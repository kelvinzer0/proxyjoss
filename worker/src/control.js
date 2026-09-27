/**
 * Control-plane client.
 *
 * proxyjoss owns the proxy list, its health and the selector rules; this Worker
 * only executes egress. It therefore asks the control plane for a ranked list of
 * egress addresses instead of fetching the feed itself, which keeps one
 * implementation of parsing, de-duplication, health and cooldown.
 *
 * Contract, served by proxyjoss on its admin listener:
 *
 *   GET  /control/resolve?selector=<name>&n=<count>
 *        200 {"selector":"global","candidates":[{"addr":"1.2.3.4:443","country":"ID","score":9.1}]}
 *        401 when the shared secret is missing or wrong
 *        404 when the selector matches nothing
 *
 *   POST /control/report   {"results":[{"addr":"1.2.3.4:443","ok":true,"ms":42}]}
 *        202 accepted, ignored if the control plane is unreachable
 *
 * The list is cached briefly so a burst of connections does not turn into a
 * burst of control-plane requests, and so the Worker keeps working when the
 * control plane is briefly down.
 */

const RESOLVE_PATH = '/control/resolve';
const REPORT_PATH = '/control/report';
const DEFAULT_TTL_MS = 30_000;
const DEFAULT_TIMEOUT_MS = 3_000;
const DEFAULT_COUNT = 4;

/** Per-isolate cache; a Worker isolate is short-lived, which is the intent. */
const cache = new Map();

function now() {
  return Date.now();
}

/**
 * Fetches a ranked candidate list for a selector.
 *
 * Always returns an array. A control-plane failure yields an empty list rather
 * than an exception, so the caller falls back to a direct connection instead of
 * failing the client's request.
 */
export async function resolveCandidates(env, selector, { n = DEFAULT_COUNT, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const base = (env?.CONTROL_PLANE_URL || '').replace(/\/+$/, '');
  if (!base) return { candidates: [], stale: false, error: 'no control plane configured' };

  const key = `${selector}|${n}`;
  const hit = cache.get(key);
  if (hit && hit.expires > now()) {
    return { candidates: hit.candidates, stale: hit.stale, error: null };
  }

  const url = `${base}${RESOLVE_PATH}?selector=${encodeURIComponent(selector)}&n=${n}`;
  try {
    const res = await fetch(url, {
      headers: {
        'X-Proxyjoss-Token': env.CONTROL_PLANE_TOKEN || '',
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (res.status === 404) {
      const empty = { selector, candidates: [] };
      cache.set(key, { ...empty, stale: false, expires: now() + 5_000 });
      return { candidates: [], stale: false, error: 'no match' };
    }
    if (!res.ok) {
      // Keep serving the previous list rather than dropping to no egress.
      if (hit) return { candidates: hit.candidates, stale: true, error: `status ${res.status}` };
      return { candidates: [], stale: false, error: `status ${res.status}` };
    }

    const body = await res.json();
    const candidates = normalise(body);
    cache.set(key, { candidates, stale: false, expires: now() + (env.CONTROL_PLANE_TTL_MS || DEFAULT_TTL_MS) });
    return { candidates, stale: false, error: null };
  } catch (err) {
    if (hit) return { candidates: hit.candidates, stale: true, error: String(err?.message || err) };
    return { candidates: [], stale: false, error: String(err?.message || err) };
  }
}

/**
 * Reduces a control-plane response to a list of { addr, country, score }.
 *
 * Anything malformed is dropped rather than trusted, because a bad address here
 * becomes a socket the Worker opens.
 */
export function normalise(body) {
  const raw = Array.isArray(body?.candidates) ? body.candidates : [];
  const out = [];
  for (const item of raw) {
    const addr = typeof item === 'string' ? item : item?.addr;
    if (typeof addr !== 'string' || !addr.trim()) continue;
    out.push({
      addr: addr.trim(),
      country: (item?.country || '').toUpperCase(),
      score: Number.isFinite(item?.score) ? item.score : null,
    });
  }
  return out;
}

/**
 * Reports egress outcomes back to the control plane so dead entries leave the
 * rotation. Fire and forget: a failure here must never affect the request that
 * is already being served.
 */
export async function reportResults(env, results) {
  const base = (env?.CONTROL_PLANE_URL || '').replace(/\/+$/, '');
  if (!base || !Array.isArray(results) || results.length === 0) return;
  try {
    await fetch(`${base}${REPORT_PATH}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Proxyjoss-Token': env.CONTROL_PLANE_TOKEN || '',
      },
      body: JSON.stringify({ results }),
      signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
    });
  } catch {
    // Reporting is best effort by design.
  }
}

/** Drops every cached selector. Used by tests and on configuration change. */
export function clearCache() {
  cache.clear();
}
