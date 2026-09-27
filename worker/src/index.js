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

const EGRESS_MODES = new Set(['auto', 'edge', 'direct']);

/** Picks the websocket pair, which differs between the module and service-worker syntax. */
function webSocketPair() {
  if (typeof WebSocketPair === 'function') return new WebSocketPair();
  const { 0: client, 1: server } = Object.getOwnPropertyDescriptors(new WebSocket()).value;
  return { 0: client, 1: server };
}

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

  // Resolved here rather than at module scope: importing cloudflare:sockets
  // statically breaks tooling that runs the worker outside of workerd, and the
  // informational routes never need it.
  const connect = env.__connect || (await import('cloudflare:sockets')).connect;

  const { 0: client, 1: server } = webSocketPair();
  server.accept();

  const outcome = await connectTarget(
    env,
    { target: parsed.target, selector: parsed.selector, egress: parsed.egress },
    connect,
  );

  if (!outcome.socket) {
    // The client is mid-handshake, so the reason goes over the socket rather
    // than into an HTTP status it will never see.
    sendError(server, outcome.reason || 'no egress available');
    try {
      client.close(1011, 'egress unavailable');
    } catch {
      // The client hung up first.
    }
    return new Response(null, { status: 101 });
  }

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

/** Tells a client, mid-handshake, why no egress could be opened. */
function sendError(ws, reason) {
  try {
    ws.send(JSON.stringify({ error: reason }));
    ws.close(1011, 'egress unavailable');
  } catch {
    // The socket is already gone.
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/' || url.pathname === '/healthz') {
      return handleInfo(env);
    }
    if (url.pathname === '/tunnel') {
      return handleTunnel(env, request, ctx);
    }
    if (url.pathname === '/cache/flush') {
      clearCache();
      return json({ flushed: true });
    }
    return json({ error: 'not found' }, 404);
  },
};
