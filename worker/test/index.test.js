import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import worker from '../src/index.js';
import { clearCache } from '../src/control.js';
import { setRuntime } from '../src/runtime.js';

/**
 * Minimal WebSocket stand-in that records what the worker does to it.
 *
 * The shape matches workerd, where the server half of a WebSocketPair receives
 * via `addEventListener('message')` and has no `receive()`. A fake that grew a
 * `receive()` would let relay() pass here and fail in production.
 */
function fakeSocket() {
  const sent = [];
  const listeners = new Map();
  let closed = null;
  return {
    sent,
    get closed() {
      return closed;
    },
    accept: () => {},
    send: (data) => sent.push(typeof data === 'string' ? data : new Uint8Array(data)),
    close: (code, reason) => {
      if (closed) return;
      closed = { code, reason };
      for (const fn of listeners.get('close') || []) fn({ code, reason });
    },
    addEventListener: (type, fn) => {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(fn);
    },
    /** Test hook: simulates a message arriving from the client. */
    emitMessage: (data) => {
      for (const fn of listeners.get('message') || []) fn({ data });
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

/**
 * An egress socket that stays open until the test ends the target's stream,
 * like a real target that has not answered yet. Also records what the client
 * wrote so a test can assert the request actually reached the socket.
 */
function stayOpenSocket() {
  const written = [];
  let control;
  const socket = {
    opened: Promise.resolve(),
    readable: new ReadableStream({
      start(c) {
        control = c;
      },
    }),
    writable: new WritableStream({
      write(chunk) {
        written.push(new Uint8Array(chunk));
      },
    }),
    close: () => {},
  };
  return {
    socket,
    written,
    respond: (text) => control.enqueue(new TextEncoder().encode(text)),
    end: () => control.close(),
    text: () => new TextDecoder().decode(Buffer.concat(written.map((b) => Buffer.from(b)))),
  };
}

function installRuntime({ connect } = {}) {
  const pair = { client: fakeSocket(), server: fakeSocket() };
  setRuntime({
    WebSocketPair: function WebSocketPair() {
      return { 0: pair.client, 1: pair.server };
    },
    connect: connect || openSocket,
  });
  const env = { CONTROL_PLANE_URL: '', CONTROL_PLANE_TTL_MS: '1' };
  return { pair, env };
}

const req = (path, headers = {}) => new Request(`https://tunnel.example${path}`, { headers });

beforeEach(() => {
  clearCache();
  globalThis.fetch = async () => new Response(JSON.stringify({ candidates: [] }), { status: 200 });
});

afterEach(() => {
  setRuntime(null);
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

describe('module syntax', () => {
  test('upgrades without a WebSocketPair global', async () => {
    // This worker is an ES module, where WebSocketPair is not a global and has to
    // come from cloudflare:workers. Shimming a global here is what let a broken
    // `new WebSocket()` fallback ship and throw error 1101 in production, so the
    // global is explicitly cleared and the upgrade must still happen.
    delete globalThis.WebSocketPair;
    expect(typeof globalThis.WebSocketPair).toBe('undefined');

    const dials = [];
    const { env } = installRuntime({
      connect: (addr) => {
        dials.push(addr);
        return openSocket();
      },
    });

    const ctx = { waitUntil: (p) => p.catch(() => {}) };
    const res = await worker.fetch(
      req('/tunnel?token=s&target=example.com:443', { Upgrade: 'websocket' }),
      { TUNNEL_TOKEN: 's', ...env },
      ctx,
    );

    expect(res.status).toBe(101);
    expect(dials).toEqual([{ hostname: 'example.com', port: 443 }]);
  });
});

describe('GET /tunnel egress', () => {
  test('upgrades and dials direct when no control plane is configured', async () => {
    const dials = [];
    const target = stayOpenSocket();
    const { env, pair } = installRuntime({
      connect: (addr) => {
        dials.push(addr);
        return target.socket;
      },
    });
    const ctx = { waitUntil: (p) => p.catch(() => {}) };
    const res = await worker.fetch(req('/tunnel?token=s&target=example.com:8443', { Upgrade: 'websocket' }), { TUNNEL_TOKEN: 's', ...env }, ctx);
    expect(res.status).toBe(101);
    expect(dials).toEqual([{ hostname: 'example.com', port: 8443 }]);
    // A target that has not answered yet must not be cut off by the upgrade.
    expect(pair.server.closed).toBeNull();
  });

  test('carries the request to the target and the response back', async () => {
    // This is the test that would have caught relay() calling ws.receive(), which
    // does not exist in workerd. A fake built around receive() passes happily and
    // then every real tunnel carries zero bytes.
    const target = stayOpenSocket();
    const { env, pair } = installRuntime({ connect: () => target.socket });
    const ctx = { waitUntil: (p) => p.catch(() => {}) };
    const res = await worker.fetch(
      req('/tunnel?token=s&target=example.com:80', { Upgrade: 'websocket' }),
      { TUNNEL_TOKEN: 's', ...env },
      ctx,
    );
    expect(res.status).toBe(101);

    pair.server.emitMessage('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n');
    await Bun.sleep(5);
    expect(target.text()).toContain('GET / HTTP/1.1');

    target.respond('HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc');
    target.end();
    await Bun.sleep(5);

    const toClient = new TextDecoder().decode(
      Buffer.concat(pair.server.sent.map((b) => Buffer.from(b))),
    );
    expect(toClient).toContain('HTTP/1.1 200 OK');
    expect(toClient).toContain('abc');
    expect(pair.server.closed).not.toBeNull();
  });

  test('releases the tunnel when the client disconnects', async () => {
    const target = stayOpenSocket();
    const { env, pair } = installRuntime({ connect: () => target.socket });
    const ctx = { waitUntil: (p) => p.catch(() => {}) };
    await worker.fetch(
      req('/tunnel?token=s&target=example.com:80', { Upgrade: 'websocket' }),
      { TUNNEL_TOKEN: 's', ...env },
      ctx,
    );

    pair.server.close(1000, 'client left');
    await Bun.sleep(5);
    // The socket must be torn down rather than held open until the target idles out.
    expect(pair.server.closed).not.toBeNull();
  });

  test('answers 502 with the reason when no egress could be opened', async () => {
    // A 101 response is only legal when it carries a socket, so a failed dial
    // has to surface as a normal HTTP error. Returning 101 anyway was the
    // original production failure: an unhandled RangeError that Cloudflare
    // reports as "error code: 1101" with no explanation.
    const { env, pair } = installRuntime({
      connect: () => ({ opened: Promise.reject(new Error('refused')), readable: {}, writable: {}, close: () => {} }),
    });
    const ctx = { waitUntil: (p) => p.catch(() => {}) };
    const res = await worker.fetch(req('/tunnel?token=s&target=example.com:443', { Upgrade: 'websocket' }), { TUNNEL_TOKEN: 's', ...env }, ctx);
    expect(res.status).toBe(502);
    expect((await res.json()).error).toMatch(/refused/);
    // No socket was ever handed to the client.
    expect(pair.server.closed).toBeNull();
    expect(pair.server.sent).toHaveLength(0);
  });

  test('reports a synchronous connect failure instead of throwing', async () => {
    const { env } = installRuntime({
      connect: () => {
        throw new Error('TCP sockets are not available on this plan');
      },
    });
    const res = await worker.fetch(
      req('/tunnel?token=s&target=example.com:443', { Upgrade: 'websocket' }),
      { TUNNEL_TOKEN: 's', ...env },
      { waitUntil: (p) => p.catch(() => {}) },
    );
    expect(res.status).toBe(502);
    expect((await res.json()).error).toMatch(/not available/);
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
