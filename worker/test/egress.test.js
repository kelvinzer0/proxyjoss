import { beforeEach, describe, expect, test } from 'bun:test';
import { connectTarget, isCloudflareHosted, parseAddr } from '../src/egress.js';
import { clearCache } from '../src/control.js';

beforeEach(() => {
  clearCache();
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ candidates: [{ addr: '146.70.37.253:2087' }, { addr: '104.16.99.52:2087' }] }), {
      status: 200,
    });
});

/** A connect() stand-in that records dials and fails the ones told to fail. */
function mockConnect({ fail = {}, delayMs = 0 } = {}) {
  const dials = [];
  const connect = ({ hostname, port }) => {
    dials.push({ hostname, port });
    const key = `${hostname}:${port}`;
    const opened = fail[key]
      ? Promise.reject(new Error(fail[key]))
      : new Promise((resolve) => setTimeout(resolve, delayMs));
    return { opened, readable: {}, writable: {} };
  };
  connect.dials = dials;
  return connect;
}

const target = { host: 'example.com', port: 443 };

describe('parseAddr', () => {
  test('parses a host and port', () => {
    expect(parseAddr('146.70.37.253:2087')).toEqual({ hostname: '146.70.37.253', port: 2087 });
  });

  test('refuses junk', () => {
    for (const bad of ['', 'nonsense', '1.2.3.4:', 'a:b:c']) {
      expect(parseAddr(bad)).toBeNull();
    }
  });
});

describe('isCloudflareHosted', () => {
  test('recognises cloudflare names', () => {
    expect(isCloudflareHosted('cloudflare.com')).toBe(true);
    expect(isCloudflareHosted('www.cloudflare.com')).toBe(true);
    expect(isCloudflareHosted('example.com')).toBe(false);
  });
});

describe('connectTarget', () => {
  test('direct connects straight to the target', async () => {
    const connect = mockConnect();
    const res = await connectTarget({}, { target, selector: 'global', egress: 'direct' }, connect);
    expect(res.socket).not.toBeNull();
    expect(res.strategy).toBe('direct');
    expect(connect.dials).toEqual([{ hostname: 'example.com', port: 443 }]);
  });

  test('auto prefers an edge entry and pins to it', async () => {
    const connect = mockConnect();
    const res = await connectTarget({ CONTROL_PLANE_URL: 'https://c' }, { target, selector: 'global', egress: 'auto' }, connect);
    expect(res.strategy).toBe('edge');
    expect(res.entry).toBe('146.70.37.253:2087');
    expect(connect.dials[0]).toEqual({ hostname: '146.70.37.253', port: 2087 });
  });

  test('auto fails over to the next entry when the first is dead', async () => {
    const connect = mockConnect({ fail: { '146.70.37.253:2087': 'connection refused' } });
    const res = await connectTarget({ CONTROL_PLANE_URL: 'https://c' }, { target, selector: 'global', egress: 'auto' }, connect);
    expect(res.strategy).toBe('edge');
    expect(res.entry).toBe('104.16.99.52:2087');
    expect(res.results[0]).toMatchObject({ addr: '146.70.37.253:2087', ok: false });
  });

  test('auto falls back to direct when every entry is dead', async () => {
    const connect = mockConnect({ fail: { '146.70.37.253:2087': 'refused', '104.16.99.52:2087': 'refused' } });
    const res = await connectTarget({ CONTROL_PLANE_URL: 'https://c' }, { target, selector: 'global', egress: 'auto' }, connect);
    expect(res.strategy).toBe('direct');
    expect(connect.dials.at(-1)).toEqual({ hostname: 'example.com', port: 443 });
    expect(res.results.every((r) => !r.ok)).toBe(true);
  });

  test('edge never silently becomes direct', async () => {
    const connect = mockConnect({ fail: { '146.70.37.253:2087': 'refused', '104.16.99.52:2087': 'refused' } });
    const res = await connectTarget({ CONTROL_PLANE_URL: 'https://c' }, { target, selector: 'global', egress: 'edge' }, connect);
    expect(res.socket).toBeNull();
    expect(res.reason).toContain('every egress entry failed');
    expect(connect.dials.some((d) => d.hostname === 'example.com')).toBe(false);
  });

  test('edge with an empty control-plane list fails instead of going direct', async () => {
    globalThis.fetch = async () => new Response(JSON.stringify({ candidates: [] }), { status: 200 });
    const connect = mockConnect();
    const res = await connectTarget({ CONTROL_PLANE_URL: 'https://c' }, { target, selector: 'nope', egress: 'edge' }, connect);
    expect(res.socket).toBeNull();
    expect(connect.dials).toHaveLength(0);
  });

  test('auto still works with no control plane at all', async () => {
    const connect = mockConnect();
    const res = await connectTarget({}, { target, selector: 'global', egress: 'auto' }, connect);
    expect(res.strategy).toBe('direct');
  });

  test('reports a direct failure with a reason', async () => {
    const connect = mockConnect({ fail: { 'example.com:443': 'DNS failure' } });
    const res = await connectTarget({}, { target, selector: 'global', egress: 'direct' }, connect);
    expect(res.socket).toBeNull();
    expect(res.reason).toContain('DNS failure');
  });

  test('stops trying entries once the time budget is spent', async () => {
    const connect = mockConnect({ fail: { '146.70.37.253:2087': 'refused', '104.16.99.52:2087': 'refused' }, delayMs: 10 });
    const res = await connectTarget({ CONTROL_PLANE_URL: 'https://c' }, { target, selector: 'global', egress: 'auto' }, connect);
    expect(res.strategy).toBe('direct');
    expect(connect.dials.filter((d) => d.hostname !== 'example.com')).toHaveLength(2);
  });
});
