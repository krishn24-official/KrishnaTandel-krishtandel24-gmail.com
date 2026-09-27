// Device and grant routes
import { send, badRequest, notFound, forbidden, conflict } from '../http.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { assertCan, can, resolveDevices, assertMayGrant } from '../permissions.js';
import { endActiveSessions } from '../lifecycle.js';
import { audit } from '../audit.js';
import { normalizeTs } from '../http.js';

export function registerDeviceRoutes(router, { db, secret }) {
  // ── Devices ─────────────────────────────────────────────────────────────

  // GET /v1/orgs/:org/devices
  router.get('/v1/orgs/:org/devices', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    assertCan(db, ctx, 'device:list');

    const rawDevices = db.prepare(
      `SELECT id, name, kind, online FROM devices WHERE org_id = ? AND deleted_at IS NULL ORDER BY name ASC`
    ).all(params.org);

    if (!rawDevices.length) return send(res, 200, { devices: [] });

    // Batch resolve — one call for all devices, no N+1
    const deviceIds = rawDevices.map(d => d.id);
    const { byDevice } = resolveDevices(db, { userId: ctx.userId, orgId: params.org, deviceIds });

    // Filter: device:view = absent from list (not redacted, not listed at all)
    const devices = rawDevices
      .filter(d => byDevice[d.id]?.['device:view']?.effect === 'allow')
      .map(d => ({
        id: d.id,
        name: d.name,
        kind: d.kind,
        online: d.online === 1,
        permissions: byDevice[d.id],
      }));

    send(res, 200, { devices });
  });

  // GET /v1/orgs/:org/devices/:id
  router.get('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    const device = getDevice(db, params.org, params.id);
    assertCan(db, ctx, 'device:view', device.id);
    const { byDevice } = resolveDevices(db, { userId: ctx.userId, orgId: params.org, deviceIds: [device.id] });
    send(res, 200, { ...device, online: device.online === 1, permissions: byDevice[device.id] });
  });

  // POST /v1/orgs/:org/devices — provision
  router.post('/v1/orgs/:org/devices', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    assertCan(db, ctx, 'device:provision');

    const { name, kind } = ctx.body;
    if (!name) throw badRequest('name is required');
    const validKinds = ['macos','windows','linux','android','ios'];
    if (!validKinds.includes(kind)) throw badRequest(`kind must be one of: ${validKinds.join(', ')}`);

    const id = newId('dev');
    db.prepare(`INSERT INTO devices (id, org_id, name, kind, online) VALUES (?,?,?,?,?)`)
      .run(id, params.org, String(name).trim(), kind, 0);

    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'device.provision', targetType: 'device', targetId: id, result: 'allow', requestId: ctx.requestId });
    send(res, 201, { id, name: String(name).trim(), kind, online: false });
  });

  // PATCH /v1/orgs/:org/devices/:id — rename/update
  router.patch('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    const device = getDevice(db, params.org, params.id);
    assertCan(db, ctx, 'device:update', device.id);

    const { name } = ctx.body;
    if (!name) throw badRequest('name is required');
    db.prepare(`UPDATE devices SET name = ? WHERE id = ?`).run(String(name).trim(), device.id);

    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'device.update', targetType: 'device', targetId: device.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { id: device.id, name: String(name).trim() });
  });

  // DELETE /v1/orgs/:org/devices/:id — decommission (soft delete)
  router.delete('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    const device = getDevice(db, params.org, params.id);
    assertCan(db, ctx, 'device:provision', device.id);

    db.transaction(() => {
      db.prepare(`UPDATE devices SET deleted_at = ? WHERE id = ?`).run(nowIso(), device.id);
      endActiveSessions(db, { orgId: params.org, deviceId: device.id, reason: 'device_transferred' });
    })();

    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'device.decommission', targetType: 'device', targetId: device.id, result: 'allow', requestId: ctx.requestId });
    send(res, 204, undefined);
  });

  // POST /v1/orgs/:org/devices/:id/transfer — transfer to another org
  router.post('/v1/orgs/:org/devices/:id/transfer', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    const device = getDevice(db, params.org, params.id);
    assertCan(db, ctx, 'device:provision', device.id);

    const { targetOrgId } = ctx.body;
    if (!targetOrgId) throw badRequest('targetOrgId is required');

    // Must also have device:provision in the target org
    const targetMem = db.prepare(
      `SELECT role, status FROM memberships WHERE user_id = ? AND org_id = ? AND status = 'active'`
    ).get(ctx.userId, targetOrgId);
    if (!targetMem) throw notFound('target organization not found or no membership');

    // Check device:provision in target org using a temporary context
    const targetCtx = { userId: ctx.userId, orgId: targetOrgId, role: targetMem.role, suspended: false };
    if (!can(db, targetCtx, 'device:provision')) {
      throw forbidden('missing device:provision in target organization', 'missing_permission');
    }

    db.transaction(() => {
      db.prepare(`UPDATE devices SET org_id = ? WHERE id = ?`).run(targetOrgId, device.id);
      endActiveSessions(db, { orgId: params.org, deviceId: device.id, reason: 'device_transferred' });
    })();

    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'device.transfer', targetType: 'device', targetId: device.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { id: device.id, orgId: targetOrgId });
  });

  // ── Grants ──────────────────────────────────────────────────────────────

  // POST /v1/orgs/:org/grants
  router.post('/v1/orgs/:org/grants', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    assertCan(db, ctx, 'grant:create');

    const { userId, deviceId, effect, permissions, startsAt, expiresAt } = ctx.body;
    if (!userId) throw badRequest('userId is required');
    if (!effect || !['allow','deny'].includes(effect)) throw badRequest("effect must be 'allow' or 'deny'");
    if (!Array.isArray(permissions) || permissions.length === 0) throw badRequest('permissions must be a non-empty array');

    // No self-grants (D9)
    if (userId === ctx.userId) throw forbidden('cannot create a grant for yourself', 'missing_permission');

    // Target must be an active member
    const targetMem = db.prepare(
      `SELECT id FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`
    ).get(params.org, userId);
    if (!targetMem) throw notFound('user not found in this organization');

    // Device must belong to this org (cross-org is invisible → 404)
    if (deviceId) {
      const dev = db.prepare(`SELECT id FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL`).get(deviceId, params.org);
      if (!dev) throw notFound('device not found');
    }

    // Validate timestamps
    const normStarts = normalizeTs(startsAt ?? null, 'startsAt');
    const normExpires = normalizeTs(expiresAt ?? null, 'expiresAt');
    const nowStr = nowIso();
    if (normExpires && normExpires <= nowStr) {
      throw Object.assign(new Error('expiresAt is in the past'), { status: 400, code: 'GRANT_EXPIRED', reason: null });
    }

    // No privilege laundering: caller must hold every permission they're granting (D9)
    assertMayGrant(db, ctx, permissions, deviceId ?? null);

    const grantId = newId('grt');
    db.transaction(() => {
      db.prepare(
        `INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by) VALUES (?,?,?,?,?,?,?,?)`
      ).run(grantId, params.org, userId, deviceId ?? null, effect, normStarts, normExpires, ctx.userId);

      const insertPerm = db.prepare(`INSERT INTO grant_permissions (grant_id, permission) VALUES (?,?)`);
      for (const p of permissions) {
        try { insertPerm.run(grantId, p); }
        catch (err) {
          if (err.message?.includes('FOREIGN KEY')) throw badRequest(`unknown permission: ${p}`);
          throw err;
        }
      }

      bumpPermVersion(db, { orgId: params.org, userId });
    })();

    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'grant.create', targetType: 'grant', targetId: grantId, result: 'allow', requestId: ctx.requestId });
    send(res, 201, { id: grantId, userId, deviceId: deviceId ?? null, effect, permissions });
  });

  // GET /v1/orgs/:org/grants
  router.get('/v1/orgs/:org/grants', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    assertCan(db, ctx, 'user:read');

    const grants = db.prepare(
      `SELECT g.id, g.user_id, g.device_id, g.effect, g.starts_at, g.expires_at, g.created_at,
              GROUP_CONCAT(gp.permission, ',') AS perms
         FROM grants g
         JOIN grant_permissions gp ON g.id = gp.grant_id
        WHERE g.org_id = ? AND g.revoked_at IS NULL
        GROUP BY g.id
        ORDER BY g.created_at DESC`
    ).all(params.org);

    send(res, 200, { grants: grants.map(g => ({ ...g, permissions: g.perms?.split(',') ?? [] })) });
  });

  // DELETE /v1/orgs/:org/grants/:id — revoke
  router.delete('/v1/orgs/:org/grants/:id', (ctx, params, res) => {
    requireOrgInScope(db, ctx, params.org);
    assertCan(db, ctx, 'grant:revoke');

    const grant = db.prepare(
      `SELECT id, user_id FROM grants WHERE id = ? AND org_id = ? AND revoked_at IS NULL`
    ).get(params.id, params.org);
    if (!grant) throw notFound('grant not found');

    db.transaction(() => {
      db.prepare(`UPDATE grants SET revoked_at = ? WHERE id = ?`).run(nowIso(), grant.id);
      bumpPermVersion(db, { orgId: params.org, userId: grant.user_id });
    })();

    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'grant.revoke', targetType: 'grant', targetId: grant.id, result: 'allow', requestId: ctx.requestId });
    send(res, 204, undefined);
  });
}

// ── Helpers ───────────────────────────────────────────────────────────────

function requireOrgInScope(db, ctx, orgId) {
  if (ctx.orgId !== orgId) throw notFound('organization not found');
  const org = db.prepare('SELECT id FROM organizations WHERE id = ? AND deleted_at IS NULL').get(orgId);
  if (!org) throw notFound('organization not found');
  return org;
}

function getDevice(db, orgId, deviceId) {
  const d = db.prepare(`SELECT id, name, kind, online FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL`).get(deviceId, orgId);
  if (!d) throw notFound('device not found');
  return d;
}
