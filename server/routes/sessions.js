// Session routes: start, list, get, terminate
import { send, badRequest, notFound, forbidden, conflict } from '../http.js';
import { newId, nowIso } from '../db.js';
import { assertCan, assertCanStartSession, resolve } from '../permissions.js';
import { endActiveSessions, snapshotAuthority, sessionExpiry } from '../lifecycle.js';
import { audit } from '../audit.js';

export function registerSessionRoutes(router, { db, secret }) {
  // POST /v1/orgs/:org/sessions — start a session (compound check)
  router.post('/v1/orgs/:org/sessions', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    if (ctx.suspended) throw forbidden('account is suspended', 'suspended');

    const { deviceId, mode } = ctx.body;
    if (!deviceId) throw badRequest('deviceId is required');
    if (!['view','control','terminal'].includes(mode)) throw badRequest("mode must be 'view', 'control', or 'terminal'");

    // Device must be in this org
    const device = db.prepare(`SELECT id FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL`)
      .get(deviceId, params.org);
    if (!device) throw notFound('device not found');

    // Compound check: session:start AND the mode permission, both on the same device.
    // assertCanStartSession distinguishes which permission was missing.
    assertCanStartSession(db, ctx, mode, deviceId);

    const sessionId = newId('ses');
    const authorizedBy = snapshotAuthority(db, { userId: ctx.userId, orgId: params.org, deviceId });
    const expiresAt = sessionExpiry(db, params.org);
    const at = nowIso();

    try {
      db.prepare(
        `INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, started_at, expires_at)
         VALUES (?,?,?,?,?,?,?,?,?)`
      ).run(sessionId, params.org, ctx.userId, deviceId, mode, 'active', authorizedBy, at, expiresAt);
    } catch (err) {
      // Partial unique index one_exclusive_session_per_device enforces exclusivity (D10)
      if (err.message?.includes('UNIQUE') || err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        const existing = db.prepare(
          `SELECT id FROM sessions WHERE device_id = ? AND state = 'active' AND mode IN ('control','terminal')`
        ).get(deviceId);
        throw Object.assign(new Error('device already has an exclusive session'), {
          status: 409, code: 'DEVICE_BUSY', reason: existing?.id ?? null,
        });
      }
      throw err;
    }

    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'session.start', targetType: 'device', targetId: deviceId, result: 'allow', requestId: ctx.requestId });
    send(res, 201, { id: sessionId, deviceId, mode, state: 'active', expiresAt });
  });

  // GET /v1/orgs/:org/sessions
  router.get('/v1/orgs/:org/sessions', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    assertCan(db, ctx, 'session:view');

    const sessions = db.prepare(
      `SELECT id, user_id, device_id, mode, state, end_reason, started_at, expires_at, ended_at
         FROM sessions WHERE org_id = ? ORDER BY started_at DESC LIMIT 100`
    ).all(params.org);

    send(res, 200, { sessions });
  });

  // GET /v1/sessions/:id — participant OR session:view
  router.get('/v1/sessions/:id', (ctx, params, res) => {
    const session = db.prepare(
      `SELECT id, org_id, user_id, device_id, mode, state, end_reason, authorized_by, started_at, expires_at, ended_at
         FROM sessions WHERE id = ?`
    ).get(params.id);

    // Must be in caller's org (structural isolation), or invisible
    if (!session || session.org_id !== ctx.orgId) throw notFound('session not found');

    const isParticipant = session.user_id === ctx.userId;
    if (!isParticipant && !can_perm(db, ctx, 'session:view')) {
      throw notFound('session not found'); // 404 not 403 — invisible
    }

    send(res, 200, session);
  });

  // DELETE /v1/sessions/:id — own session OR session:terminate
  router.delete('/v1/sessions/:id', (ctx, params, res) => {
    const session = db.prepare(
      `SELECT id, org_id, user_id, state FROM sessions WHERE id = ?`
    ).get(params.id);

    if (!session || session.org_id !== ctx.orgId) throw notFound('session not found');
    if (session.state !== 'active') throw badRequest('session is already ended');

    const isOwn = session.user_id === ctx.userId;
    const canTerminate = can_perm(db, ctx, 'session:terminate');

    if (!isOwn && !canTerminate) throw notFound('session not found');

    const reason = isOwn ? 'user_stopped' : 'admin_terminated';
    db.prepare(
      `UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ? WHERE id = ?`
    ).run(reason, nowIso(), session.id);

    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'session.end', targetType: 'session', targetId: session.id, result: 'allow', requestId: ctx.requestId });
    send(res, 204, undefined);
  });
}

function requireOrgInScope(db, ctx, orgId) {
  if (ctx.orgId !== orgId) throw notFound('organization not found');
  const org = db.prepare('SELECT id FROM organizations WHERE id = ? AND deleted_at IS NULL').get(orgId);
  if (!org) throw notFound('organization not found');
}

// Helper to check without throwing (for branching logic)
function can_perm(db, ctx, permission, deviceId = null) {
  if (ctx.suspended) return false;
  const perms = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
  return perms[permission]?.effect === 'allow';
}
