/**
 * Byte pumping between the client's WebSocket and the egress socket.
 *
 * Both sides are half-duplex streams, so the copy has to be done in both
 * directions and neither direction may end the tunnel early. A WebSocket close
 * frame is a normal end of stream, not an error, so it must not be logged as one
 * or allowed to reject the other direction.
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

/** Reads a WebSocket message into a Uint8Array, or null at end of stream. */
async function readMessage(ws) {
  try {
    const msg = await ws.receive();
    if (typeof msg === 'string') return new TextEncoder().encode(msg);
    if (msg instanceof ArrayBuffer) return new Uint8Array(msg);
    return msg || null;
  } catch (err) {
    if (isClosed(err)) return null;
    throw err;
  }
}

/** Copies WebSocket -> socket, returning bytes moved. */
async function pumpToSocket(ws, socket, onBytes) {
  let total = 0;
  for (;;) {
    const chunk = await readMessage(ws);
    if (!chunk) break;
    if (chunk.length === 0) continue;
    const writer = socket.writable.getWriter();
    try {
      await writer.write(chunk);
    } finally {
      writer.releaseLock();
    }
    total += chunk.length;
  }
  return total;
}

/** Copies socket -> WebSocket, returning bytes moved. */
async function pumpToWebSocket(socket, ws, state) {
  const reader = socket.readable.getReader();
  let total = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (!value || value.length === 0) continue;
      if (state.wsOpen) {
        try {
          ws.send(value);
        } catch (err) {
          if (!isClosed(err)) throw err;
          break;
        }
      }
      total += value.length;
    }
  } catch (err) {
    if (!isClosed(err) && state.onError) state.onError(err);
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // The stream is already gone; nothing to release.
    }
  }
  return total;
}

/**
 * Runs the tunnel until either side ends, then tears the other one down.
 *
 * Returns once both directions are finished so a caller can report accurate
 * byte counts. A failure to close cleanly is ignored: the request is over either
 * way.
 */
export async function relay(ws, socket, state = {}) {
  state.wsOpen = true;
  let toSocket = 0;
  let toClient = 0;

  const upload = pumpToSocket(ws, socket).then((n) => {
    toSocket = n;
  });
  const download = pumpToWebSocket(socket, ws, state).then((n) => {
    toClient = n;
  });

  try {
    await Promise.all([upload, download]);
  } finally {
    state.wsOpen = false;
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
  }

  return { toSocket, toClient };
}
