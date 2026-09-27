// Request authentication middleware
import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated } from './http.js';

// Build request context from bearer token
export function authenticate(db, secret) {
  return function buildContext(req, params) {
    // Extract bearer token
    const authHeader = req.headers['authorization'] ?? '';
    if (!authHeader.startsWith('Bearer ')) {
      throw unauthenticated('missing or malformed Authorization header');
    }
    const token = authHeader.slice(7).trim();
    if (!token) throw unauthenticated('empty bearer token');

    // Verify token claims
    const claims = verifyAccessToken(token, secret);

    // Look up membership
    const membership = db.prepare(
      `SELECT m.id, m.org_id, m.user_id, m.role, m.status, m.perm_version
         FROM memberships m
        WHERE m.user_id = ? AND m.org_id = ?`
    ).get(claims.sub, claims.org);

    // Verify freshness
    assertFresh(claims, membership);

    // Verify membership status
    if (membership.status === 'removed') {
      throw unauthenticated('membership has been removed');
    }

    // Return context
    return {
      userId: claims.sub,
      orgId: claims.org,
      role: claims.role,
      membership,
      claims,
      suspended: membership.status === 'suspended',
    };
  };
}
