/**
 * Egress strategies.
 *
 * A Cloudflare Worker can reach anything on its own, so the honest default is a
 * direct connection. The Emilia list is not a pool of forward proxies: those
 * addresses are Cloudflare edge IPs, and a plaintext connection to one only
 * carries traffic whose TLS SNI belongs to a zone Cloudflare serves. Verified
 * against the live feed: SOCKS5 and CONNECT handshakes are answered with HTTP
 * error responses, and a TLS handshake with a non-Cloudflare SNI fails, while
 * Cloudflare-hosted targets succeed.
 *
 * So there are two egress shapes:
 *
 *   direct  connect({ hostname: target })          every destination
 *   edge    connect({ hostname: entry, port })     Cloudflare-hosted targets,
 *                                                  and a different source IP
 *
 * `edge` is attempted first only when the caller asked for it and a usable
 * entry exists, then the strategies fall back to `direct`. That ordering is
 * deliberate: an edge attempt on a non-Cloudflare target costs one TLS failure,
 * while skipping a wanted edge costs the caller the egress they selected.
 */

import { checkTarget, isIPv4, isIPv6 } from './guard.js';
import { resolveCandidates, reportResults } from './control.js';

/** How many entries one connection may try before giving up on the edge path. */
const MAX_EDGE_TRIES = 3;
/** Time budget for the whole edge attempt chain. */
const EDGE_BUDGET_MS = 4_000;

/** Reports whether a hostname looks like it is served by Cloudflare. */
export function isCloudflareHosted(host) {
  const h = String(host).toLowerCase().replace(/\.$/, '');
  if (h === 'cloudflare.com' || h.endsWith('.cloudflare.com')) return true;
  // A literal IP is ambiguous, and Cloudflare owns plenty of ranges, so the
  // edge path is allowed to try it and simply fail over if it does not work.
  return false;
}

/**
 * Parses an egress entry into connection parts, or null when it is unusable.
 *
 * The feed is IP-based, so an entry that is not a literal address is malformed
 * and is dropped here. Private ranges are allowed because the whole point of an
 * egress entry is to be a raw address chosen by the control plane, not a target
 * the caller supplied.
 */
export function parseAddr(addr) {
  const checked = checkTarget(addr, { allowPrivate: true });
  if (!checked.ok) return null;
  const { host, port } = checked;
  if (!isIPv4(host) && !isIPv6(host)) return null;
  return { hostname: host, port };
}

/** Opens a socket and resolves once it is established, or rejects. */
async function open(connect, address, port, budgetMs) {
  const socket = connect({ hostname: address, port });
  let timer;
  try {
    await Promise.race([
      socket.opened,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('connect timeout')), budgetMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
  return socket;
}

/**
 * Tries each candidate entry in turn and returns the first socket that opens.
 *
 * Entries are tried in the order the control plane ranked them, so a healthy
 * entry carries the traffic and a slow one is simply skipped.
 */
async function tryEdges(connect, candidates, results, deadline) {
  const tried = candidates.slice(0, MAX_EDGE_TRIES);
  for (const candidate of tried) {
    const parts = parseAddr(candidate.addr);
    if (!parts) {
      results.push({ addr: candidate.addr, ok: false, detail: 'unparseable' });
      continue;
    }
    const started = Date.now();
    try {
      const socket = await open(connect, parts.hostname, parts.port, Math.max(250, deadline - Date.now()));
      results.push({ addr: candidate.addr, ok: true, ms: Date.now() - started });
      return socket;
    } catch (err) {
      results.push({ addr: candidate.addr, ok: false, ms: Date.now() - started, detail: String(err?.message || err) });
      if (Date.now() >= deadline) break;
    }
  }
  return null;
}

/**
 * Establishes a stream to the target through the best available egress.
 *
 * `egress` is "auto" (edge when one is available, then direct), "edge" (edge
 * only, fail the request if none work) or "direct".
 */
export async function connectTarget(env, { target, selector, egress = 'auto' }, connect) {
  const results = [];
  const wantEdge = egress === 'auto' || egress === 'edge';

  let candidates = [];
  if (wantEdge) {
    const resolved = await resolveCandidates(env, selector || 'global');
    candidates = resolved.candidates || [];
    if (resolved.error && candidates.length === 0 && egress === 'edge') {
      return { socket: null, reason: `no egress available: ${resolved.error}`, results };
    }
  }

  if (candidates.length > 0) {
    const deadline = Date.now() + EDGE_BUDGET_MS;
    const socket = await tryEdges(connect, candidates, results, deadline);
    if (socket) {
      void reportResults(env, results);
      return { socket, strategy: 'edge', entry: results.find((r) => r.ok)?.addr || null, results };
    }
    if (egress === 'edge') {
      void reportResults(env, results);
      return { socket: null, reason: 'every egress entry failed', results };
    }
  }

  if (egress === 'edge') {
    return { socket: null, reason: 'no egress entry available', results };
  }

  try {
    const socket = await open(connect, target.host, target.port, EDGE_BUDGET_MS);
    return { socket, strategy: 'direct', entry: null, results };
  } catch (err) {
    void reportResults(env, results);
    return { socket: null, reason: `direct connect failed: ${String(err?.message || err)}`, results };
  }
}
