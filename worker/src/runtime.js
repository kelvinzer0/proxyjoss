/**
 * Lazy access to the workerd-only globals.
 *
 * `cloudflare:sockets` only exists inside workerd, so it is imported
 * dynamically: a static import would stop `bun test` from loading this worker at
 * all.
 *
 * `WebSocketPair` is looked up on the global scope first. It is available there
 * in module syntax as well as service-worker syntax, and it is deliberately not
 * imported from `cloudflare:workers`, because that module does not export it.
 * Reading it off `new WebSocket()` is not a substitute: that throws.
 */

let cached = null;

/** Resolves the runtime bindings, caching them for the life of the isolate. */
export async function getRuntime() {
  if (!cached) {
    const sockets = await import('cloudflare:sockets');
    if (typeof sockets.connect !== 'function') {
      throw new Error('cloudflare:sockets did not provide connect');
    }
    const WebSocketPair = globalThis.WebSocketPair;
    if (typeof WebSocketPair !== 'function') {
      throw new Error('WebSocketPair is not available; this code is not running in workerd');
    }
    cached = { WebSocketPair, connect: sockets.connect };
  }
  return cached;
}

/** Replaces the cached bindings. Used by tests, which inject fakes. */
export function setRuntime(impl) {
  cached = impl;
}
