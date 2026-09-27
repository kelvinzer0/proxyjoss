/**
 * Byte pumping between the client's WebSocket and the egress socket.
 *
 * The Workers WebSocket API has no `receive()`: the server side of a
 * WebSocketPair pushes messages at `addEventListener("message", ...)` and
 * signals the client going away with a `close` event. Handshaking on a
 * `receive()` that only exists in other runtimes is the kind of thing unit tests
 * with a cooperative fake will happily pass and production will reject.
 *
 * The socket write side is acquired once and reused. Taking a new writer per
 * chunk would work but serialises on lock acquisition for no reason, and
 * holding one writer is what lets the stream apply backpressure.
 */

/** True when an error just means one side closed. */
function isClosed(err) {
  const msg = String(err?.message || err || '').toLowerCase();
  return (
    msg.includes('closed') ||
    msg.includes('reset') ||
    msg.includes('eof') ||
    msg.includes('cancel') ||
    err?.name === 'AbortError'
  );
}

/** Normalises a WebSocket message payload into bytes. */
function toBytes(data) {
  if (typeof data === 'string') return new TextEncoder().encode(data);
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return null;
}

/**
 * Runs the tunnel until the target finishes sending, then tears everything down.
 *
 * The target's read side ending is what ends the tunnel: there is nothing more
 * to deliver, and a client still writing into a dead connection gains nothing.
 * A client that closes first half-closes the socket instead, so a target that
 * still has a response to send gets to send it.
 */
export function relay(ws, socket, state = {}) {
  return new Promise((resolve) => {
    let toSocket = 0;
    let toClient = 0;
    let settled = false;
    state.wsOpen = true;

    const writer = socket.writable.getWriter();
    let writerBusy = Promise.resolve();

    const finish = async () => {
      if (settled) return;
      settled = true;
      // Let bytes already accepted from the client reach the socket before the
      // stream is torn down, or a fast target response can drop the request.
      await writerBusy;
      state.wsOpen = false;
      try {
        writer.releaseLock();
      } catch {
        // Already released or never taken.
      }
      try {
        socket.close();
      } catch {
        // Already closed.
      }
      try {
        ws.close(1000, 'tunnel closed');
      } catch {
        // The client is already gone.
      }
      resolve({ toSocket, toClient });
    };

    ws.addEventListener('message', (event) => {
      const chunk = toBytes(event.data);
      if (!chunk || chunk.length === 0) return;
      toSocket += chunk.length;
      // Writes are chained so ordering is preserved and a failed write does not
      // surface as an unhandled rejection.
      writerBusy = writerBusy.then(() => writer.write(chunk)).catch((err) => {
        if (!isClosed(err) && state.onError) state.onError(err);
      });
    });

    ws.addEventListener('close', () => {
      // A WebSocket close is not a half close: there is no way for the client to
      // signal "done sending but still listening". So a close ends the tunnel.
      // Waiting for the target to finish instead would hold a socket open for
      // as long as the target stays silent, which is a resource leak.
      state.wsOpen = false;
      void finish();
    });

    (async () => {
      const reader = socket.readable.getReader();
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          if (!value || value.length === 0) continue;
          if (state.wsOpen) {
            try {
              ws.send(value);
            } catch (err) {
              if (!isClosed(err) && state.onError) state.onError(err);
              break;
            }
          }
          toClient += value.length;
        }
        } catch (err) {
          if (!isClosed(err) && state.onError) state.onError(err);
        } finally {
          try {
            reader.releaseLock();
          } catch {
            // The stream is already gone.
          }
          void finish();
        }
    })();
  });
}
