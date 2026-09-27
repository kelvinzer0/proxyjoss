import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import worker from '../src/index.js';
import { clearCache } from '../src/control.js';

/** Minimal WebSocket stand-in that records what the worker does to it. */
function fakeSocket() {
  const sent = [];
  let closed = null;
  let pending = [];
  return {
    sent,
    get closed() {
      return closed;
    },
    get pending() {
      return pending;
    },
    accept: () => {},
    send: (data) => sent.push(typeof data === 'string' ? data : new Uint8Array(data)),
    close: (code, reason) => {
      closed = { code, reason };
      pending = [];
    },
    receive: () => {
      const next = pending.shift();
      return next === undefined ? Promise.reject(new Error('closed')) : Promise.resolve(next);
    },
  };
}

/** An egress socket with the real stream interfaces relay() expects. */
function openSocket() {
  return {
    opened: Promise.resolve(),
    readable: new ReadableStream({ start(c) { c.close(); } }),
    writable: new WritableStream(),
    close: () => {},
  };
}

function installRuntime({ connect } = {}) {
  const pair = { client: fakeSocket(), server: fakeSocket() };
  globalThis.WebSocketPair = function WebSocketPair() {
    return { 0: pair.client, 1: pair.server };
  };
  const env = { __connect: connect || openSocket, CONTROL_PLANE_URL: '', CONTROL_PLANE_TTL_MS: '1' };
  return { pair, env };
}

const req = (path, headers = {}) => new Request(`https://tunnel.example${path}`, { headers });

beforeEach(() => {
  clearCache();
  globalThis.fetch = async () => new Response(JSON.stringify({ candidates: [] }), { status: 200 });
});

afterEach(() => {
  delete globalThis.WebSocketPair;
});

describe('GET /', () => {
  test('reports configuration without leaking secrets', async () => {
    const { env } = installRuntime();
    const res = await worker.fetch(req('/'), { TUNNEL_TOKEN: 'secret', CONTROL_PLANE_URL: 'https://c' }, {});
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.service).toBe('proxyjoss-tunnel');
    expect(body.tunnel_configured).toBe(true);
    expect(body.control_plane).toBe(true);
    expect(JSON.stringify(body)).not.toContain('secret');
  });

  test('serves healthz', async () => {
    const { env } = installRuntime();
    expect((await worker.fetch(req('/healthz'), env, {})).status).toBe(200);
  });
});

describe('GET /tunnel validation', () => {
  const ctx = () => ({});

  test('rejects a missing token before touching a socket', async () => {
    let dialled = 0;
    const { env } = installRuntime({ connect: () => { dialled++; } });
    const res = await worker.fetch(req('/tunnel?target=example.com:443', { Upgrade: 'websocket' }), { TUNNEL_TOKEN: 's' }, ctx());
    expect(res.status).toBe(401);
    expect(dialled).toBe(0);
  });

  test('rejects a bad token', async () => {
    const { env } = installRuntime();
    const res = await worker.fetch(req('/tunnel?target=example.com:443&token=wrong', { Upgrade: 'websocket' }), { TUNNEL_TOKEN: 's' }, ctx());
    expect(res.status).toBe(403);
  });

  test('fails closed when the worker has no token configured', async () => {
    const { env } = installRuntime();
    const res = await worker.fetch(req('/tunnel?target=example.com:443', { Upgrade: 'websocket' }), {}, ctx());
    expect(res.status).toBe(503);
  });

  test('rejects an internal target', async () => {
    let dialled = 0;
    const { env } = installRuntime({ connect: () => { dialled++; } });
    const res = await worker.fetch(req('/tunnel?target=169.254.169.254:80&token=s', { Upgrade: 'websocket' }), { TUNNEL_TOKEN: 's' }, ctx());
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/private/);
    expect(dialled).toBe(0);
  });

  test('rejects a missing target', async () => {
    const { env } = installRuntime();
    const res = await worker.fetch(req('/tunnel?token=s', { Upgrade: 'websocket' }), { TUNNEL_TOKEN: 's' }, ctx());
    expect(res.status).toBe(400);
  });

  test('rejects an unknown egress mode', async () => {
    const { env } = installRuntime();
    const res = await worker.fetch(req('/tunnel?token=s&target=example.com:443&egress=sideways', { Upgrade: 'websocket' }), { TUNNEL_TOKEN: 's' }, ctx());
    expect(res.status).toBe(400);
  });

  test('requires a websocket upgrade', async () => {
    const { env } = installRuntime();
    const res = await worker.fetch(req('/tunnel?token=s&target=example.com:443'), { TUNNEL_TOKEN: 's' }, ctx());
    expect(res.status).toBe(426);
  });
});

describe('GET /tunnel egress', () => {
  test('upgrades and dials direct when no control plane is configured', async () => {
    const dials = [];
    const { env, pair } = installRuntime({
      connect: (addr) => {
        dials.push(addr);
        return openSocket();
      },
    });
    const ctx = { waitUntil: (p) => p.catch(() => {}) };
    const res = await worker.fetch(req('/tunnel?token=s&target=example.com:8443', { Upgrade: 'websocket' }), { TUNNEL_TOKEN: 's', ...env }, ctx);
    expect(res.status).toBe(101);
    expect(dials).toEqual([{ hostname: 'example.com', port: 8443 }]);
    expect(pair.server.closed).toBeNull();
  });

  test('tells the client why when no egress could be opened', async () => {
    const { env, pair } = installRuntime({
      connect: () => ({ opened: Promise.reject(new Error('refused')), readable: {}, writable: {}, close: () => {} }),
    });
    const ctx = { waitUntil: (p) => p.catch(() => {}) };
    const res = await worker.fetch(req('/tunnel?token=s&target=example.com:443', { Upgrade: 'websocket' }), { TUNNEL_TOKEN: 's', ...env }, ctx);
    expect(res.status).toBe(101);
    expect(pair.server.sent.join('')).toContain('refused');
    expect(pair.server.closed.code).toBe(1011);
  });
});

describe('unknown routes', () => {
  test('404', async () => {
    const { env } = installRuntime();
    expect((await worker.fetch(req('/nope'), { TUNNEL_TOKEN: 's' }, {})).status).toBe(404);
  });

  test('cache flush', async () => {
    const { env } = installRuntime();
    const res = await worker.fetch(req('/cache/flush', { 'X-Proxyjoss-Token': 's' }), { TUNNEL_TOKEN: 's' }, {});
    expect(res.status).toBe(200);
    expect((await res.json()).flushed).toBe(true);
  });
});
