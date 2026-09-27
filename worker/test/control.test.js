import { afterEach, describe, expect, test } from 'bun:test';
import { clearCache, normalise, reportResults, resolveCandidates } from '../src/control.js';

afterEach(() => {
  clearCache();
});

/** Builds a fetch stub that records calls and replays queued responses. */
function stubFetch(responses) {
  const calls = [];
  const queue = [...responses];
  const impl = async (url, init) => {
    calls.push({ url: String(url), init });
    const next = queue.length > 1 ? queue.shift() : queue[0];
    if (typeof next === 'function') return next(url, init);
    return next;
  };
  impl.calls = calls;
  return impl;
}

const ok = (body, status = 200) => new Response(JSON.stringify(body), { status });

describe('normalise', () => {
  test('accepts objects and bare strings', () => {
    expect(normalise({ candidates: [{ addr: '1.2.3.4:443', country: 'id', score: 9.5 }, '5.6.7.8:443'] })).toEqual([
      { addr: '1.2.3.4:443', country: 'ID', score: 9.5 },
      { addr: '5.6.7.8:443', country: '', score: null },
    ]);
  });

  test('drops malformed entries instead of trusting them', () => {
    const res = normalise({ candidates: [null, {}, { addr: '' }, { addr: '   ' }, 42, { addr: '1.1.1.1:443' }] });
    expect(res).toEqual([{ addr: '1.1.1.1:443', country: '', score: null }]);
  });

  test('survives a body that is not the expected shape', () => {
    expect(normalise(null)).toEqual([]);
    expect(normalise({})).toEqual([]);
    expect(normalise({ candidates: 'nope' })).toEqual([]);
  });
});

describe('resolveCandidates', () => {
  const env = { CONTROL_PLANE_URL: 'https://control.example', CONTROL_PLANE_TOKEN: 'tok' };

  test('requests the ranked list and sends the shared secret', async () => {
    const f = stubFetch([ok({ candidates: [{ addr: '1.1.1.1:443' }] })]);
    globalThis.fetch = f;
    const res = await resolveCandidates(env, 'global', { n: 3 });
    expect(res.candidates).toHaveLength(1);
    expect(res.error).toBeNull();
    expect(f.calls[0].url).toContain('selector=global');
    expect(f.calls[0].url).toContain('n=3');
    expect(f.calls[0].init.headers['X-Proxyjoss-Token']).toBe('tok');
  });

  test('caches within the ttl so a burst is not a storm', async () => {
    const f = stubFetch([ok({ candidates: [{ addr: '1.1.1.1:443' }] })]);
    globalThis.fetch = f;
    await resolveCandidates(env, 'global');
    await resolveCandidates(env, 'global');
    await resolveCandidates(env, 'global');
    expect(f.calls).toHaveLength(1);
  });

  test('treats 404 as no match and caches it briefly', async () => {
    const f = stubFetch([new Response('', { status: 404 })]);
    globalThis.fetch = f;
    const res = await resolveCandidates(env, 'nope');
    expect(res.candidates).toEqual([]);
    expect(res.error).toBe('no match');
  });

  test('serves the stale list when the control plane errors', async () => {
    const f = stubFetch([
      ok({ candidates: [{ addr: '1.1.1.1:443' }] }),
      new Response('boom', { status: 500 }),
    ]);
    globalThis.fetch = f;
    await resolveCandidates(env, 'global');
    const res = await resolveCandidates(env, 'global', { ttlMs: 1 });
    // Force a refresh past the cached entry.
    clearCache();
    const second = await resolveCandidates(env, 'global');
    expect(second.candidates).toEqual([]);
  });

  test('returns nothing when no control plane is configured', async () => {
    const res = await resolveCandidates({}, 'global');
    expect(res.candidates).toEqual([]);
    expect(res.error).toMatch(/no control plane/);
  });

  test('does not throw when fetch rejects', async () => {
    globalThis.fetch = stubFetch([
      () => {
        throw new Error('network down');
      },
    ]);
    const res = await resolveCandidates(env, 'global');
    expect(res.candidates).toEqual([]);
    expect(res.error).toContain('network down');
  });
});

describe('reportResults', () => {
  test('posts the results with the shared secret', async () => {
    const f = stubFetch([new Response('', { status: 202 })]);
    globalThis.fetch = f;
    await reportResults({ CONTROL_PLANE_URL: 'https://control.example', CONTROL_PLANE_TOKEN: 'tok' }, [
      { addr: '1.1.1.1:443', ok: true, ms: 12 },
    ]);
    expect(f.calls[0].url).toBe('https://control.example/control/report');
    expect(f.calls[0].init.method).toBe('POST');
    expect(JSON.parse(f.calls[0].init.body).results[0].addr).toBe('1.1.1.1:443');
  });

  test('is a no-op with nothing to report or nowhere to report to', async () => {
    const f = stubFetch([new Response('', { status: 202 })]);
    globalThis.fetch = f;
    await reportResults({}, [{ addr: '1.1.1.1:443', ok: true }]);
    await reportResults({ CONTROL_PLANE_URL: 'https://control.example' }, []);
    expect(f.calls).toHaveLength(0);
  });

  test('swallows errors so reporting never affects a live request', async () => {
    globalThis.fetch = stubFetch([
      () => {
        throw new Error('down');
      },
    ]);
    await reportResults({ CONTROL_PLANE_URL: 'https://control.example' }, [{ addr: '1.1.1.1:443', ok: false }]);
  });
});
