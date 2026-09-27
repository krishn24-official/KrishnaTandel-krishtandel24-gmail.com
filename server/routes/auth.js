// Auth routes: login, refresh, org switch, me
import {
  verifyPassword, hashPassword, newRefreshToken, hashRefreshToken,
  issueAccessToken, assertFresh,
} from '../auth.js';
import { send, unauthenticated, notFound, badRequest } from '../http.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { orgLevelPermissions } from '../permissions.js';

const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;

// Register auth routes
export function registerAuthRoutes(router, { db, secret }) {
  // Login handler
  router.post('/v1/auth/login', (ctx, _params, res) => {
    const { email, password } = ctx.body ?? {};
    if (!email || !password) throw badRequest('email and password are required');

    // User credential check
    const user = db.prepare('SELECT id, password_hash FROM users WHERE email = lower(?)').get(email);
    if (!user || !verifyPassword(password, user.password_hash)) {
      throw unauthenticated('invalid credentials');
    }

    // Active memberships query
    const memberships = db.prepare(
      `SELECT m.org_id, m.role, m.status, m.perm_version, o.name AS orgName, o.theme
         FROM memberships m
         JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
        ORDER BY o.id ASC`
    ).all(user.id);

    if (!memberships.length) throw unauthenticated('no active organization memberships');

    const mem = memberships[0];
    const token = issueAccessToken({
      userId: user.id, orgId: mem.org_id, role: mem.role, permVersion: mem.perm_version,
    }, secret);

    // Issue refresh token
    const raw = newRefreshToken();
    const hash = hashRefreshToken(raw);
    const familyId = newId('fam');
    const expiresAt = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString();
    db.prepare(
      `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at) VALUES (?,?,?,?,?)`
    ).run(newId('rtk'), user.id, hash, familyId, expiresAt);

    const cookieFlags = [
      `remoteops_refresh=${raw}`,
      'HttpOnly', 'SameSite=Strict',
      `Expires=${new Date(expiresAt).toUTCString()}`,
      'Path=/',
    ];
    if (process.env.NODE_ENV === 'production') cookieFlags.push('Secure');
    res.setHeader('Set-Cookie', cookieFlags.join('; '));

    // Send login response
    send(res, 200, {
      token,
      orgId: mem.org_id,
      role: mem.role,
      orgs: memberships.map(m => ({ id: m.org_id, name: m.orgName, theme: m.theme, role: m.role })),
    });
  });

  // Refresh token handler
  router.post('/v1/auth/refresh', (ctx, _params, res) => {
    const cookieHeader = ctx.req?.headers['cookie'] ?? '';
    const match = cookieHeader.match(/(?:^|;\s*)remoteops_refresh=([^;]+)/);
    if (!match) throw unauthenticated('missing refresh token');

    const raw = match[1];
    const hash = hashRefreshToken(raw);
    const now = nowIso();

    const rt = db.prepare(
      `SELECT id, user_id, family_id, expires_at, revoked_at FROM refresh_tokens WHERE token_hash = ?`
    ).get(hash);

    if (!rt) throw unauthenticated('invalid refresh token');

    // Token reuse detection
    if (rt.revoked_at) {
      db.prepare(`UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ?`).run(now, rt.family_id);
      throw unauthenticated('refresh token replayed — family revoked');
    }

    if (rt.expires_at <= now) throw unauthenticated('refresh token expired');

    // Rotate refresh token
    db.prepare(`UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?`).run(now, rt.id);

    const newRaw = newRefreshToken();
    const newHash = hashRefreshToken(newRaw);
    const expiresAt = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString();
    db.prepare(
      `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at) VALUES (?,?,?,?,?)`
    ).run(newId('rtk'), rt.user_id, newHash, rt.family_id, expiresAt);

    const memberships = db.prepare(
      `SELECT m.org_id, m.role, m.status, m.perm_version, o.name AS orgName, o.theme
         FROM memberships m
         JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
        ORDER BY o.id ASC`
    ).all(rt.user_id);

    if (!memberships.length) throw unauthenticated('no active memberships');

    const mem = memberships[0];
    const token = issueAccessToken({
      userId: rt.user_id, orgId: mem.org_id, role: mem.role, permVersion: mem.perm_version,
    }, secret);

    const cookieFlags = [
      `remoteops_refresh=${newRaw}`,
      'HttpOnly', 'SameSite=Strict',
      `Expires=${new Date(expiresAt).toUTCString()}`,
      'Path=/',
    ];
    if (process.env.NODE_ENV === 'production') cookieFlags.push('Secure');
    res.setHeader('Set-Cookie', cookieFlags.join('; '));

    send(res, 200, {
      token,
      orgId: mem.org_id,
      role: mem.role,
      orgs: memberships.map(m => ({ id: m.org_id, name: m.orgName, theme: m.theme, role: m.role })),
    });
  });

  // Switch organization token handler
  router.post('/v1/auth/token', (ctx, _params, res) => {
    const { orgId } = ctx.body ?? {};
    if (!orgId) throw badRequest('orgId is required');

    const mem = db.prepare(
      `SELECT m.role, m.status, m.perm_version
         FROM memberships m
         JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.org_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
    ).get(ctx.userId, orgId);

    if (!mem) throw notFound('organization not found or no active membership');

    const token = issueAccessToken({
      userId: ctx.userId, orgId, role: mem.role, permVersion: mem.perm_version,
    }, secret);

    send(res, 200, { token, orgId, role: mem.role });
  });

  // Current user info handler
  router.get('/v1/auth/me', (ctx, _params, res) => {
    const user = db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(ctx.userId);
    if (!user) throw notFound();

    const orgs = db.prepare(
      `SELECT o.id, o.name, o.theme, m.role, m.status
         FROM memberships m
         JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.status IN ('active','suspended') AND o.deleted_at IS NULL
        ORDER BY o.name ASC`
    ).all(ctx.userId);

    const permissions = orgLevelPermissions(db, { userId: ctx.userId, orgId: ctx.orgId });
    const org = db.prepare('SELECT id, name, theme FROM organizations WHERE id = ?').get(ctx.orgId);

    send(res, 200, {
      user: { id: user.id, email: user.email, name: user.name },
      org,
      role: ctx.role,
      orgs: orgs.map(o => ({ id: o.id, name: o.name, theme: o.theme, role: o.role })),
      permissions,
    });
  });
}
