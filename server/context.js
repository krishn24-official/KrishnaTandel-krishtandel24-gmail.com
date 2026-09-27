// Per-request context: turn a bearer token into an authenticated caller.
//
// Structural org isolation: the token's `org` claim is the ONLY org this caller
// may address. A request naming a different org gets a 404 — not a 403 — because
// the other org is invisible from this token's perspective (AUTH-DATA-MODEL.md §4).
//
// authenticate(db, secret) returns a function (req, params) => caller
// where caller carries { userId, orgId, role, membership, claims }.

import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, notFound } from './http.js';

export function authenticate(db, secret) {
  return function buildContext(req, params) {
    // Extract bearer token from Authorization header
    const authHeader = req.headers['authorization'] ?? '';
    if (!authHeader.startsWith('Bearer ')) {
      throw unauthenticated('missing or malformed Authorization header');
    }
    const token = authHeader.slice(7).trim();
    if (!token) throw unauthenticated('empty bearer token');

    // Verify the token structurally (signature, exp, iss, aud, jti)
    // This throws unauthenticated() on any failure.
    const claims = verifyAccessToken(token, secret);

    // Look up the membership for (sub, org) from the token.
    // The org claim IS the only org this caller may address — structural isolation.
    const membership = db.prepare(
      `SELECT m.id, m.org_id, m.user_id, m.role, m.status, m.perm_version
         FROM memberships m
        WHERE m.user_id = ? AND m.org_id = ?`
    ).get(claims.sub, claims.org);

    // assertFresh: throws TOKEN_STALE if perm_version has changed since token was issued.
    // Also throws unauthenticated if membership doesn't exist (org was deleted, etc.).
    assertFresh(claims, membership);

    // Suspended members: token verifies, membership exists, but authority is empty.
    // Return 403 for every request (enforced by the routes); the permission set is empty.
    // Removed members: membership row still exists (users are never deleted) but the
    // token is now stale — perm_version was bumped on removal — so assertFresh above
    // would have already thrown TOKEN_STALE. But as a safety net:
    if (membership.status === 'removed') {
      throw unauthenticated('membership has been removed');
    }

    // The org in the token must match any org in the URL path. This is the structural
    // isolation: rather than filtering, the caller simply cannot address other orgs.
    // We propagate the claim's org; route handlers do: if (params.org !== ctx.orgId) notFound()
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
