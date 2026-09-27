// Orgs + members + invites + effective permissions + audit
import { send, badRequest, notFound, forbidden, conflict, gone, lastOwner, selfRoleChange } from '../http.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { assertCan, orgLevelPermissions, resolve } from '../permissions.js';
import {
  assertRoleExists, assertCanModify, assertCanAssignRole, assertNotLastOwner,
  endActiveSessions, roleRanks,
} from '../lifecycle.js';
import { newInviteToken, hashInviteToken } from '../auth.js';
import { audit } from '../audit.js';

const THEMES = ['cobalt', 'amber', 'moss', 'plum', 'rust', 'teal'];
const INVITE_TTL_DAYS = 7;

export function registerOrgRoutes(router, { db, secret }) {
  // ── Orgs ──────────────────────────────────────────────────────────────────

  // GET /v1/orgs — list orgs the caller belongs to
  router.get('/v1/orgs', (ctx, _params, res) => {
    const orgs = db.prepare(
      `SELECT o.id, o.name, o.theme, m.role
         FROM memberships m
         JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
        ORDER BY o.name ASC`
    ).all(ctx.userId);
    send(res, 200, { orgs });
  });

  // POST /v1/orgs — create org (creator becomes owner)
  router.post('/v1/orgs', (ctx, _params, res) => {
    const { name, theme } = ctx.body;
    if (!name || typeof name !== 'string' || name.trim().length < 1) {
      throw badRequest('name is required');
    }
    const finalTheme = THEMES.includes(theme) ? theme : THEMES[Math.floor(Math.random() * THEMES.length)];
    const orgId = newId('org');
    const memId = newId('mem');
    const at = nowIso();

    db.transaction(() => {
      db.prepare(
        `INSERT INTO organizations (id, name, theme, max_session_minutes, created_at) VALUES (?,?,?,?,?)`
      ).run(orgId, name.trim(), finalTheme, 60, at);

      db.prepare(
        `INSERT INTO memberships (id, org_id, user_id, role, status, perm_version, joined_at) VALUES (?,?,?,?,?,?,?)`
      ).run(memId, orgId, ctx.userId, 'owner', 'active', 1, at);
    })();

    audit(db, { orgId, actorId: ctx.userId, action: 'org.create', targetType: 'org', targetId: orgId, result: 'allow', requestId: ctx.requestId });
    send(res, 201, { id: orgId, name: name.trim(), theme: finalTheme });
  });

  // PATCH /v1/orgs/:org — rename/reconfigure
  router.patch('/v1/orgs/:org', (ctx, params, res) => {
    const org = requireOrgInScope(db, ctx, params.org);
    assertCan(db, ctx, 'org:update');

    const { name, theme } = ctx.body;
    const updates = [];
    const vals = [];
    if (name !== undefined) { updates.push('name = ?'); vals.push(String(name).trim()); }
    if (theme !== undefined && THEMES.includes(theme)) { updates.push('theme = ?'); vals.push(theme); }
    if (!updates.length) throw badRequest('nothing to update');
    vals.push(params.org);

    db.prepare(`UPDATE organizations SET ${updates.join(', ')} WHERE id = ?`).run(...vals);
    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'org.update', targetType: 'org', targetId: params.org, result: 'allow', requestId: ctx.requestId });
    send(res, 200, db.prepare('SELECT id, name, theme FROM organizations WHERE id = ?').get(params.org));
  });

  // DELETE /v1/orgs/:org
  router.delete('/v1/orgs/:org', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    assertCan(db, ctx, 'org:delete');
    const at = nowIso();
    db.prepare(`UPDATE organizations SET deleted_at = ? WHERE id = ?`).run(at, params.org);
    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'org.delete', targetType: 'org', targetId: params.org, result: 'allow', requestId: ctx.requestId });
    send(res, 204, undefined);
  });

  // ── Members ──────────────────────────────────────────────────────────────

  // GET /v1/orgs/:org/members
  router.get('/v1/orgs/:org/members', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    assertCan(db, ctx, 'user:read');
    const members = db.prepare(
      `SELECT u.id, u.email, u.name, m.role, m.status, m.joined_at
         FROM memberships m
         JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND m.status NOT IN ('removed')
        ORDER BY u.name ASC`
    ).all(params.org);
    send(res, 200, { members });
  });

  // PATCH /v1/orgs/:org/members/:userId — change role
  router.patch('/v1/orgs/:org/members/:userId', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    assertCan(db, ctx, 'user:role:update');

    if (params.userId === ctx.userId) throw selfRoleChange();

    const target = getActiveMember(db, params.org, params.userId);
    const { role: newRole } = ctx.body;
    if (!newRole) throw badRequest('role is required');
    assertRoleExists(db, newRole);
    assertCanModify(db, ctx.role, target.role);
    assertCanAssignRole(db, ctx.role, newRole);

    db.transaction(() => {
      db.prepare(`UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?`)
        .run(newRole, params.org, params.userId);
      bumpPermVersion(db, { orgId: params.org, userId: params.userId });
    })();

    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'member.role_change', targetType: 'user', targetId: params.userId, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { userId: params.userId, role: newRole });
  });

  // POST /v1/orgs/:org/members/:userId/suspend
  router.post('/v1/orgs/:org/members/:userId/suspend', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    assertCan(db, ctx, 'user:remove');
    const target = getActiveMember(db, params.org, params.userId);
    assertCanModify(db, ctx.role, target.role);

    db.transaction(() => {
      db.prepare(`UPDATE memberships SET status = 'suspended' WHERE org_id = ? AND user_id = ?`)
        .run(params.org, params.userId);
      bumpPermVersion(db, { orgId: params.org, userId: params.userId });
      endActiveSessions(db, { orgId: params.org, userId: params.userId, reason: 'user_suspended' });
    })();

    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'member.suspend', targetType: 'user', targetId: params.userId, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { userId: params.userId, status: 'suspended' });
  });

  // DELETE /v1/orgs/:org/members/:userId/suspend — reinstate
  router.delete('/v1/orgs/:org/members/:userId/suspend', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    assertCan(db, ctx, 'user:remove');
    const mem = db.prepare(`SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?`)
      .get(params.org, params.userId);
    if (!mem || mem.status !== 'suspended') throw notFound('no suspended member found');
    assertCanModify(db, ctx.role, mem.role);

    db.transaction(() => {
      db.prepare(`UPDATE memberships SET status = 'active' WHERE org_id = ? AND user_id = ?`)
        .run(params.org, params.userId);
      bumpPermVersion(db, { orgId: params.org, userId: params.userId });
    })();

    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'member.reinstate', targetType: 'user', targetId: params.userId, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { userId: params.userId, status: 'active' });
  });

  // DELETE /v1/orgs/:org/members/me — self-leave
  router.delete('/v1/orgs/:org/members/me', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    assertNotLastOwner(db, params.org, ctx.userId);

    db.transaction(() => {
      db.prepare(`UPDATE memberships SET status = 'removed' WHERE org_id = ? AND user_id = ?`)
        .run(params.org, ctx.userId);
      bumpPermVersion(db, { orgId: params.org, userId: ctx.userId });
      endActiveSessions(db, { orgId: params.org, userId: ctx.userId, reason: 'membership_removed' });
    })();

    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'member.leave', targetType: 'user', targetId: ctx.userId, result: 'allow', requestId: ctx.requestId });
    send(res, 204, undefined);
  });

  // DELETE /v1/orgs/:org/members/:userId — remove member
  router.delete('/v1/orgs/:org/members/:userId', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    assertCan(db, ctx, 'user:remove');
    const target = getActiveMember(db, params.org, params.userId);
    assertCanModify(db, ctx.role, target.role);
    assertNotLastOwner(db, params.org, params.userId);

    db.transaction(() => {
      db.prepare(`UPDATE memberships SET status = 'removed' WHERE org_id = ? AND user_id = ?`)
        .run(params.org, params.userId);
      bumpPermVersion(db, { orgId: params.org, userId: params.userId });
      endActiveSessions(db, { orgId: params.org, userId: params.userId, reason: 'membership_removed' });
    })();

    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'member.remove', targetType: 'user', targetId: params.userId, result: 'allow', requestId: ctx.requestId });
    send(res, 204, undefined);
  });

  // ── Invites ──────────────────────────────────────────────────────────────

  // POST /v1/orgs/:org/invites
  router.post('/v1/orgs/:org/invites', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    assertCan(db, ctx, 'user:invite');

    const { email, role } = ctx.body;
    if (!email || !role) throw badRequest('email and role are required');
    const normalizedEmail = String(email).trim().toLowerCase();
    assertRoleExists(db, role);
    assertCanAssignRole(db, ctx.role, role);

    // Check if already an active member
    const existing = db.prepare(
      `SELECT status FROM memberships WHERE org_id = ? AND user_id = (SELECT id FROM users WHERE email = ?)`
    ).get(params.org, normalizedEmail);
    if (existing?.status === 'active') throw conflict('user is already an active member');

    const rawToken = newInviteToken();
    const tokenHash = hashInviteToken(rawToken);
    const expiresAt = new Date(Date.now() + INVITE_TTL_DAYS * 24 * 60 * 60 * 1000).toISOString();
    const inviteId = newId('inv');

    try {
      db.prepare(
        `INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at) VALUES (?,?,?,?,?,?,?)`
      ).run(inviteId, params.org, normalizedEmail, role, tokenHash, ctx.userId, expiresAt);
    } catch (err) {
      if (err.message?.includes('UNIQUE')) throw conflict('a pending invite already exists for this email');
      throw err;
    }

    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'invite.create', targetType: 'invite', targetId: inviteId, result: 'allow', requestId: ctx.requestId });
    // Return raw token exactly once — never stored in plaintext
    send(res, 201, { id: inviteId, token: rawToken, email: normalizedEmail, role, expiresAt });
  });

  // GET /v1/orgs/:org/invites
  router.get('/v1/orgs/:org/invites', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    assertCan(db, ctx, 'user:invite');
    const invites = db.prepare(
      `SELECT id, email, role, expires_at, created_at FROM invites
        WHERE org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ?
        ORDER BY created_at DESC`
    ).all(params.org, nowIso());
    send(res, 200, { invites });
  });

  // DELETE /v1/orgs/:org/invites/:id — cancel invite
  router.delete('/v1/orgs/:org/invites/:id', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    assertCan(db, ctx, 'user:invite');
    const invite = db.prepare(
      `SELECT id FROM invites WHERE id = ? AND org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL`
    ).get(params.id, params.org);
    if (!invite) throw notFound('invite not found');
    db.prepare(`UPDATE invites SET revoked_at = ? WHERE id = ?`).run(nowIso(), params.id);
    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'invite.revoke', targetType: 'invite', targetId: params.id, result: 'allow', requestId: ctx.requestId });
    send(res, 204, undefined);
  });

  // ── Effective permissions ─────────────────────────────────────────────────

  // GET /v1/orgs/:org/users/:userId/effective
  router.get('/v1/orgs/:org/users/:userId/effective', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    const isSelf = params.userId === ctx.userId;
    if (!isSelf) assertCan(db, ctx, 'user:read');

    const mem = db.prepare(`SELECT role FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`)
      .get(params.org, params.userId);
    if (!mem) throw notFound();

    const permissions = orgLevelPermissions(db, { userId: params.userId, orgId: params.org });
    send(res, 200, { role: mem.role, permissions });
  });

  // ── Audit ─────────────────────────────────────────────────────────────────

  // GET /v1/orgs/:org/audit
  router.get('/v1/orgs/:org/audit', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    assertCan(db, ctx, 'audit:read');
    const events = db.prepare(
      `SELECT id, actor_id, action, target_type, target_id, result, reason_code, request_id, at
         FROM audit_events WHERE org_id = ? ORDER BY at DESC LIMIT 200`
    ).all(params.org);
    send(res, 200, { events });
  });
}

// ── Helpers ───────────────────────────────────────────────────────────────

function requireOrgInScope(db, ctx, orgId) {
  // The token's org claim is the structural isolation boundary.
  // A request to a different org is a 404 — never 403.
  if (ctx.orgId !== orgId) throw notFound('organization not found');
  const org = db.prepare('SELECT id FROM organizations WHERE id = ? AND deleted_at IS NULL').get(orgId);
  if (!org) throw notFound('organization not found');
  return org;
}

function getActiveMember(db, orgId, userId) {
  const mem = db.prepare(
    `SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`
  ).get(orgId, userId);
  if (!mem) throw notFound('member not found');
  return mem;
}


