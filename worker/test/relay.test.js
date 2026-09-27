import { describe, expect, test } from 'bun:test';
import { relay } from '../src/relay.js';

const bytes = (...strings) => strings.map((s) => new TextEncoder().encode(s));
const decode = (chunks) => chunks.map((c) => new TextDecoder().decode(c)).join('');
const size = (s) => new TextEncoder().encode(s).length;

/**
 * A WebSocket fake with the shape workerd actually has: event listeners, send and
 * close. It deliberately has no `receive()`, so a relay written against the wrong
 * API fails here instead of in production.
 */
function wsFake() {
  const listeners = new Map();
  const sent = [];
  let closed = false;
  return {
    sent,
    get closed() {
      return closed;
    },
    addEventListener(type, fn) {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(fn);
    },
    emit(type, event) {
      for (const fn of listeners.get(type) || []) fn(event);
    },
    send(data) {
      sent.push(new Uint8Array(data));
    },
    close() {
      if (closed) return;
      closed = true;
      this.emit('close', {});
    },
  };
}

/**
 * An egress socket that stays open until the test says otherwise, which is what
 * a real target does: the client sends first, the target answers afterwards.
 */
function socketFake() {
  const written = [];
  let controller;
  let socketClosed = false;
  const readable = new ReadableStream({
    start(c) {
      controller = c;
    },
  });
  const writable = new WritableStream({
    write(chunk) {
      written.push(new Uint8Array(chunk));
    },
  });
  const socket = {
    readable,
    writable,
    close() {
      socketClosed = true;
    },
  };
  return {
    socket,
    written,
    /** Pushes target output to the client. Takes a list, matching `bytes(...)`. */
    deliver: (list) => {
      for (const chunk of list) controller.enqueue(chunk);
    },
    /** Ends the target's stream, which ends the tunnel. */
    end: () => controller.close(),
    get closed() {
      return socketClosed;
    },
  };
}

describe('relay', () => {
  test('moves bytes in both directions and counts them', async () => {
    const request = 'GET / HTTP/1.1\r\n\r\n';
    const extra = 'extra';
    const response = 'HTTP/1.1 200 OK\r\n\r\n';
    const body = 'body';

    const ws = wsFake();
    const target = socketFake();
    const running = relay(ws, target.socket, {});

    ws.emit('message', { data: new TextEncoder().encode(request).buffer });
    ws.emit('message', { data: new TextEncoder().encode(extra).buffer });
    target.deliver(bytes(response, body));
    target.end();

    const counts = await running;

    expect(decode(target.written)).toBe(request + extra);
    expect(decode(ws.sent)).toBe(response + body);
    expect(counts.toSocket).toBe(size(request + extra));
    expect(counts.toClient).toBe(size(response + body));
  });

  test('does not depend on a receive method', async () => {
    const ws = wsFake();
    expect(ws.receive).toBeUndefined();
    const target = socketFake();
    const running = relay(ws, target.socket, {});
    ws.emit('message', { data: 'ping' });
    target.end();
    await running;
    expect(decode(target.written)).toBe('ping');
  });

  test('accepts string, ArrayBuffer and typed-array messages', async () => {
    const ws = wsFake();
    const target = socketFake();
    const running = relay(ws, target.socket, {});

    ws.emit('message', { data: 'a' });
    ws.emit('message', { data: new TextEncoder().encode('b').buffer });
    ws.emit('message', { data: new TextEncoder().encode('c') });
    target.end();

    await running;
    expect(decode(target.written)).toBe('abc');
  });

  test('skips empty messages without ending the tunnel', async () => {
    const ws = wsFake();
    const target = socketFake();
    const running = relay(ws, target.socket, {});

    ws.emit('message', { data: new Uint8Array(0) });
    ws.emit('message', { data: 'after-empty' });
    target.end();

    await running;
    expect(decode(target.written)).toBe('after-empty');
  });

  test('preserves message order under many writes', async () => {
    const ws = wsFake();
    const target = socketFake();
    const running = relay(ws, target.socket, {});

    for (let i = 0; i < 25; i++) ws.emit('message', { data: `${i};` });
    target.end();

    await running;
    expect(decode(target.written)).toBe(Array.from({ length: 25 }, (_, i) => `${i};`).join(''));
  });

  test('a client that closes ends the tunnel instead of leaking the socket', async () => {
    // A WebSocket close is a full close, so a response already on its way to a
    // departed client can never arrive. The tunnel must still end here, or the
    // socket is held open for as long as the target stays silent.
    const ws = wsFake();
    const target = socketFake();
    const running = relay(ws, target.socket, {});

    ws.emit('message', { data: 'request' });
    ws.emit('close', {});

    const counts = await running;
    expect(decode(target.written)).toBe('request');
    expect(counts.toSocket).toBe(size('request'));
    expect(target.closed).toBe(true);
  });

  test('stays open while the target is slow and silent', async () => {
    // A target that has not answered yet must not be cut off.
    const ws = wsFake();
    const target = socketFake();
    const running = relay(ws, target.socket, {});

    ws.emit('message', { data: 'request' });
    let settled = false;
    void running.then(() => {
      settled = true;
    });
    await new Promise((r) => setTimeout(r, 10));
    expect(settled).toBe(false);
    expect(target.closed).toBe(false);

    target.deliver(bytes('late reply'));
    target.end();
    expect(decode(await running.then(() => ws.sent))).toBe('late reply');
  });

  test('ends when the target finishes sending and tears both sides down', async () => {
    const ws = wsFake();
    const target = socketFake();
    const running = relay(ws, target.socket, {});
    target.deliver(bytes('done'));
    target.end();

    const counts = await running;
    expect(counts.toClient).toBe(4);
    expect(ws.closed).toBe(true);
    expect(target.closed).toBe(true);
  });

  test('flushes bytes accepted from the client before tearing down', async () => {
    // The target answers and closes in the same tick as the client's request, so
    // without waiting for the pending write the request bytes would be dropped.
    const ws = wsFake();
    const target = socketFake();
    const running = relay(ws, target.socket, {});

    ws.emit('message', { data: 'request' });
    target.deliver(bytes('reply'));
    target.end();

    await running;
    expect(decode(target.written)).toBe('request');
    expect(decode(ws.sent)).toBe('reply');
  });

  test('a socket reset is a normal end of stream, not an error', async () => {
    const ws = wsFake();
    const errors = [];
    const socket = {
      readable: new ReadableStream({
        pull(c) {
          c.error(new Error('connection reset by peer'));
        },
      }),
      writable: new WritableStream(),
      close() {},
    };

    const counts = await relay(ws, socket, { onError: (e) => errors.push(e) });
    expect(errors).toHaveLength(0);
    expect(counts.toClient).toBe(0);
  });

  test('reports a genuine mid-stream fault through the state hook', async () => {
    const ws = wsFake();
    const errors = [];
    const socket = {
      readable: new ReadableStream({
        pull(c) {
          c.error(new Error('TLS handshake failed'));
        },
      }),
      writable: new WritableStream(),
      close() {},
    };

    const counts = await relay(ws, socket, { onError: (e) => errors.push(e) });
    expect(errors).toHaveLength(1);
    expect(errors[0].message).toContain('TLS handshake failed');
    expect(counts.toClient).toBe(0);
  });

  test('a failed write is surfaced and does not hang the tunnel', async () => {
    const ws = wsFake();
    const errors = [];
    const target = socketFake();
    const socket = target.socket;
    const broken = new WritableStream({
      write() {
        throw new Error('broken pipe');
      },
    });
    const failing = { readable: socket.readable, writable: broken, close: socket.close };

    const running = relay(ws, failing, { onError: (e) => errors.push(e) });
    ws.emit('message', { data: 'x' });
    target.end();

    await running;
    expect(errors.some((e) => e.message.includes('broken pipe'))).toBe(true);
  });
});
