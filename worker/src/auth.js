/**
 * Shared-secret authentication for the tunnel endpoint.
 *
 * A worker that dials arbitrary destinations on request is an open proxy unless
 * it refuses anonymous callers, so this module fails closed: with no secret
 * configured every request is denied rather than allowed.
 */

const TOKEN_HEADER = 'x-proxyjoss-token';
const SELECTOR_HEADER = 'x-proxyjoss-selector';

/** Compares two strings without leaking length or content through timing. */
export function timingSafeEqual(a, b) {
  const x = String(a ?? '');
  const y = String(b ?? '');
  if (x.length !== y.length) {
    // Still do a comparison so the work does not depend on the input.
    let diff = 1;
    for (let i = 0; i < y.length; i++) diff |= x.charCodeAt(0) ^ y.charCodeAt(i);
    return diff === 0 && false;
  }
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}

/**
 * Validates the caller.
 *
 * The token may arrive as a header or a query parameter, because a browser
 * WebSocket handshake cannot set headers but a local Go client can.
 */
export function authenticate(env, url, headers) {
  const expected = env?.TUNNEL_TOKEN || '';
  if (!expected) {
    return { ok: false, status: 503, reason: 'tunnel is not configured: set TUNNEL_TOKEN' };
  }

  const provided =
    headers?.get?.(TOKEN_HEADER) || url?.searchParams?.get('token') || '';
  if (!provided) {
    return { ok: false, status: 401, reason: 'missing token' };
  }
  if (!timingSafeEqual(provided, expected)) {
    return { ok: false, status: 403, reason: 'bad token' };
  }

  const selector = headers?.get?.(SELECTOR_HEADER) || url?.searchParams?.get('selector') || 'global';
  return { ok: true, selector: String(selector).slice(0, 64) };
}
