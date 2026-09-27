import { describe, expect, test } from 'bun:test';
import { relay } from '../src/relay.js';

const bytes = (...strings) => strings.map((s) => new TextEncoder().encode(s));

/** A websocket stand-in whose incoming messages are queued up front. */
function wsWith(messages) {
  const sent = [];
  const queue = [...messages];
  return {
    sent,
    async receive() {
      const next = queue.shift();
      if (next === undefined) throw new Error('closed');
      return next;
    },
    send(data) {
      sent.push(new Uint8Array(data));
    },
    close() {},
  };
}

/** An egress socket backed by real streams, with a handle on its writer side. */
function socketWith(chunks) {
  const written = [];
  let controller;
  const readable = new ReadableStream({
    start(c) {
      controller = c;
      for (const chunk of chunks) c.enqueue(chunk);
      c.close();
    },
  });
  const writable = new WritableStream({
    write(chunk) {
      written.push(new Uint8Array(chunk));
    },
  });
  return { socket: { readable, writable, close: () => {} }, written, controller };
}

const decode = (chunks) => chunks.map((c) => new TextDecoder().decode(c)).join('');

/** Byte length of a string as it would arrive on the wire. */
const size = (s) => new TextEncoder().encode(s).length;

describe('relay', () => {
  test('moves bytes in both directions and counts them', async () => {
    const request = 'GET / HTTP/1.1\r\n\r\n';
    const extra = 'extra';
    const response = 'HTTP/1.1 200 OK\r\n\r\n';
    const body = 'body';

    const ws = wsWith(bytes(request, extra));
    const { socket, written } = socketWith(bytes(response, body));

    const counts = await relay(ws, socket, {});

    expect(decode(written)).toBe(request + extra);
    expect(decode(ws.sent)).toBe(response + body);
    expect(counts.toSocket).toBe(size(request + extra));
    expect(counts.toClient).toBe(size(response + body));
  });

  test('accepts ArrayBuffer messages, which is what a real worker delivers', async () => {
    const ws = wsWith([new TextEncoder().encode('ping').buffer]);
    const { socket, written } = socketWith([]);

    await relay(ws, socket, {});

    expect(decode(written)).toBe('ping');
  });

  test('skips empty messages without ending the tunnel', async () => {
    const ws = wsWith([new Uint8Array(0), new TextEncoder().encode('after-empty')]);
    const { socket, written } = socketWith([]);

    await relay(ws, socket, {});

    expect(decode(written)).toBe('after-empty');
  });

  test('a half-closed client still drains the download', async () => {
    // No client messages at all, but the target has a full response waiting.
    const response = 'complete response';
    const ws = wsWith([]);
    const { socket } = socketWith(bytes(response));

    const counts = await relay(ws, socket, {});

    expect(decode(ws.sent)).toBe(response);
    expect(counts.toClient).toBe(size(response));
  });

  test('closes both sides when the stream finishes', async () => {
    const ws = wsWith([]);
    let socketClosed = false;
    let wsClosed = false;
    let controller;
    const socket = {
      readable: new ReadableStream({ start(c) { controller = c; } }),
      writable: new WritableStream(),
      close: () => { socketClosed = true; },
    };
    ws.close = () => { wsClosed = true; };

    const promise = relay(ws, socket, {});
    controller.close(); // the target finished sending
    await promise;

    expect(socketClosed).toBe(true);
    expect(wsClosed).toBe(true);
  });

  test('a socket reset is a normal end of stream, not an error', async () => {
    const ws = wsWith([]);
    const errors = [];
    const socket = {
      readable: new ReadableStream({
        pull(c) {
          c.error(new Error('connection reset by peer'));
        },
      }),
      writable: new WritableStream(),
      close: () => {},
    };

    const counts = await relay(ws, socket, { onError: (e) => errors.push(e) });

    // A reset ends the tunnel quietly; the client will notice the drop.
    expect(errors).toHaveLength(0);
    expect(counts.toClient).toBe(0);
  });

  test('reports a genuine mid-stream fault through the state hook', async () => {
    const ws = wsWith([]);
    const errors = [];
    const socket = {
      readable: new ReadableStream({
        pull(c) {
          c.error(new Error('TLS handshake failed'));
        },
      }),
      writable: new WritableStream(),
      close: () => {},
    };

    const counts = await relay(ws, socket, { onError: (e) => errors.push(e) });

    expect(errors).toHaveLength(1);
    expect(errors[0].message).toContain('TLS handshake failed');
    expect(counts.toClient).toBe(0);
  });
});
