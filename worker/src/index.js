/**
 * proxyjoss tunnel worker — data plane.
 *
 * A Cloudflare Worker cannot accept a raw TCP listener, so this is not a
 * SOCKS5 or HTTP proxy on its own. It is the upstream hop for proxyjoss, which
 * keeps the client-facing TCP listener:
 *
 *   client -> proxyjoss (SOCKS5 / HTTP on a real port)
 *          -> WebSocket -> this worker
 *          -> cloudflare:sockets connect() -> egress
 *
 * proxyjoss is the control plane: it owns the proxy list, health, selectors and
 * the admin API, and this worker asks it for a ranked egress list. See
 * ../README.md for the contract and for how to deploy.
 */

import { authenticate } from './auth.js';
import { checkTarget } from './guard.js';
import { connectTarget } from './egress.js';
import { relay } from './relay.js';
import { clearCache } from './control.js';
import { getRuntime } from './runtime.js';

const EGRESS_MODES = new Set(['auto', 'edge', 'direct']);

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

/** Liveness and configuration echo, safe to expose because it leaks no secrets. */
function handleInfo(env) {
  return json({
    service: 'proxyjoss-tunnel',
    control_plane: Boolean(env.CONTROL_PLANE_URL),
    tunnel_configured: Boolean(env.TUNNEL_TOKEN),
    egress: 'auto',
  });
}

/**
 * Validates the request before anything is dialled.
 *
 * Everything that can be rejected without a socket is rejected here, so a
 * malformed or abusive request costs no egress and no Worker CPU.
 */
function parseTunnelRequest(env, url, headers) {
  const auth = authenticate(env, url, headers);
  if (!auth.ok) return { ok: false, response: json({ error: auth.reason }, auth.status) };

  const target = checkTarget(url.searchParams.get('target') || '', { defaultPort: 443 });
  if (!target.ok) return { ok: false, response: json({ error: target.reason }, 400) };

  const egress = (url.searchParams.get('egress') || 'auto').toLowerCase();
  if (!EGRESS_MODES.has(egress)) {
    return { ok: false, response: json({ error: `egress must be auto, edge or direct` }, 400) };
  }

  if (headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
    return { ok: false, response: json({ error: 'this endpoint requires a websocket upgrade' }, 426) };
  }

  return { ok: true, target: { host: target.host, port: target.port }, selector: auth.selector, egress };
}

async function handleTunnel(env, request, ctx) {
  const url = new URL(request.url);
  const parsed = parseTunnelRequest(env, url, request.headers);
  if (!parsed.ok) return parsed.response;

  // Resolved here rather than at module scope so the informational routes never
  // touch workerd-only modules, which lets `bun test` load this file.
  const { WebSocketPair, connect: defaultConnect } = await getRuntime();
  const connect = env.__connect || defaultConnect;

  // Dial before building the WebSocket. A 101 response is only valid when it
  // carries a socket, so a failed dial has to become a normal HTTP error. Doing
  // it in this order also means a refused target costs no upgrade.
  const outcome = await connectTarget(
    env,
    { target: parsed.target, selector: parsed.selector, egress: parsed.egress },
    connect,
  );

  if (!outcome.socket) {
    return json(
      { error: outcome.reason || 'no egress available', target: parsed.target, egress: parsed.egress },
      502,
    );
  }

  const { 0: client, 1: server } = new WebSocketPair();
  server.accept();

  const state = {};
  // The response is returned immediately so the upgrade completes; the tunnel
  // then runs for the lifetime of the connection.
  const done = relay(server, outcome.socket, state)
    .then((bytes) => {
      console.log(
        JSON.stringify({
          event: 'tunnel',
          target: `${parsed.target.host}:${parsed.target.port}`,
          selector: parsed.selector,
          strategy: outcome.strategy,
          entry: outcome.entry,
          up: bytes.toSocket,
          down: bytes.toClient,
        }),
      );
    })
    .catch((err) => {
      console.error(JSON.stringify({ event: 'tunnel_error', reason: String(err?.message || err) }));
    });

  if (ctx && typeof ctx.waitUntil === 'function') {
    ctx.waitUntil(done);
  }

  return new Response(null, { status: 101, webSocket: client });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    try {
      if (url.pathname === '/' || url.pathname === '/healthz') {
        return handleInfo(env);
      }
      if (url.pathname === '/tunnel') {
        return await handleTunnel(env, request, ctx);
      }
      if (url.pathname === '/cache/flush') {
        clearCache();
        return json({ flushed: true });
      }
      return json({ error: 'not found' }, 404);
    } catch (err) {
      // Without this the whole request surfaces as Cloudflare's "error code:
      // 1101", which names the symptom and not the cause. Anything thrown before
      // the upgrade completes is a bug here, so say what it was.
      console.error(
        JSON.stringify({
          event: 'request_failed',
          path: url.pathname,
          reason: String(err?.message || err),
          stack: String(err?.stack || '').split('\n').slice(0, 4).join(' | '),
        }),
      );
      return json({ error: 'internal error' }, 500);
    }
  },
};
