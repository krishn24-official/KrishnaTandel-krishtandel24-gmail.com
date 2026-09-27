// Public invite routes: GET /v1/invites/:token, POST /v1/invites/:token/accept
import { send, gone, conflict, badRequest, notFound } from '../http.js';
import { hashInviteToken, hashPassword, issueAccessToken, newRefreshToken, hashRefreshToken } from '../auth.js';
import { newId, nowIso } from '../db.js';
import { audit } from '../audit.js';

const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;

export function registerInviteRoutes(router, { db, secret }) {
  // GET /v1/invites/:token — public: peek at an invite without being a member
  router.get('/v1/invites/:token', (ctx, params, res) => {
    const hash = hashInviteToken(params.token);
    const invite = db.prepare(
      `SELECT i.id, i.email, i.role, i.expires_at, i.accepted_at, i.revoked_at, o.name AS orgName
         FROM invites i
         JOIN organizations o ON o.id = i.org_id
        WHERE i.token_hash = ?`
    ).get(hash);

    if (!invite) throw gone('invite not found or expired');
    if (invite.revoked_at) throw gone('invite has been revoked');
    if (invite.accepted_at) throw conflict('invite has already been accepted');
    if (invite.expires_at <= nowIso()) throw gone('invite has expired');

    // Return only what is needed to render the "You've been invited to X as Y" screen.
    // No org data, no member list — the token holder is not a member yet.
    send(res, 200, {
      orgName: invite.orgName,
      role: invite.role,
      email: invite.email,
      expiresAt: invite.expires_at,
    });
  });

  // POST /v1/invites/:token/accept — public: accept an invite
  // Does everything in one transaction: upsert user, activate membership, issue tokens.
  router.post('/v1/invites/:token/accept', (ctx, params, res) => {
    const hash = hashInviteToken(params.token);
    const invite = db.prepare(
      `SELECT i.id, i.org_id, i.email, i.role, i.expires_at, i.accepted_at, i.revoked_at
         FROM invites i
        WHERE i.token_hash = ?`
    ).get(hash);

    if (!invite) throw gone('invite not found or expired');
    if (invite.revoked_at) throw gone('invite has been revoked');
    if (invite.expired_at <= nowIso()) throw gone('invite has expired');
    if (invite.accepted_at) throw conflict('invite has already been accepted');
    if (invite.expires_at <= nowIso()) throw gone('invite has expired');

    const { name, password } = ctx.body;
    if (!name || !password) throw badRequest('name and password are required');

    let userId, perm_version;

    try {
      db.transaction(() => {
        // Upsert user: if email exists → attach, else create
        let user = db.prepare('SELECT id FROM users WHERE email = lower(?)').get(invite.email);
        if (!user) {
          const newUserId = newId('usr');
          db.prepare(
            `INSERT INTO users (id, email, name, password_hash) VALUES (?,?,?,?)`
          ).run(newUserId, invite.email.toLowerCase(), name.trim(), hashPassword(password));
          userId = newUserId;
        } else {
          userId = user.id;
        }

        // Check if already a member
        const existing = db.prepare(
          `SELECT status, perm_version FROM memberships WHERE org_id = ? AND user_id = ?`
        ).get(invite.org_id, userId);

        if (existing) {
          if (existing.status === 'active') throw conflict('already a member');
          // Reactivate
          db.prepare(
            `UPDATE memberships SET status = 'active', role = ?, perm_version = perm_version + 1, joined_at = ?
              WHERE org_id = ? AND user_id = ?`
          ).run(invite.role, nowIso(), invite.org_id, userId);
          perm_version = existing.perm_version + 1;
        } else {
          const pv = 1;
          db.prepare(
            `INSERT INTO memberships (id, org_id, user_id, role, status, perm_version, joined_at)
             VALUES (?,?,?,?,?,?,?)`
          ).run(newId('mem'), invite.org_id, userId, invite.role, 'active', pv, nowIso());
          perm_version = pv;
        }

        // Mark invite as accepted (single-use)
        db.prepare(`UPDATE invites SET accepted_at = ?, accepted_by = ? WHERE id = ?`)
          .run(nowIso(), userId, invite.id);
      })();
    } catch (err) {
      if (err.message?.includes('UNIQUE') && err.message?.includes('one_live_invite_per_email')) {
        throw conflict('a concurrent accept already succeeded');
      }
      throw err;
    }

    // Issue tokens for the new member
    const accessToken = issueAccessToken({
      userId, orgId: invite.org_id, role: invite.role, permVersion: perm_version,
    }, secret);

    const rawRefresh = newRefreshToken();
    const refreshHash = hashRefreshToken(rawRefresh);
    const familyId = newId('fam');
    const expiresAt = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString();
    db.prepare(
      `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at) VALUES (?,?,?,?,?)`
    ).run(newId('rtk'), userId, refreshHash, familyId, expiresAt);

    const cookieFlags = [
      `remoteops_refresh=${rawRefresh}`,
      'HttpOnly', 'SameSite=Strict',
      `Expires=${new Date(expiresAt).toUTCString()}`,
      'Path=/',
    ];
    if (process.env.NODE_ENV === 'production') cookieFlags.push('Secure');
    res.setHeader('Set-Cookie', cookieFlags.join('; '));

    audit(db, { orgId: invite.org_id, actorId: userId, action: 'invite.accept', targetType: 'invite', targetId: invite.id, result: 'allow', requestId: ctx.requestId ?? null });
    send(res, 200, { accessToken, orgId: invite.org_id });
  });
}
