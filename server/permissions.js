// Permission resolution engine
import { forbidden } from './http.js';

// Session mode to permission mapping
export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

// Expand permission patterns
function expandPattern(db, pattern) {
  if (pattern === '*') {
    return db.prepare('SELECT key FROM permissions').all().map(r => r.key);
  }
  const colonIdx = pattern.indexOf(':');
  if (colonIdx !== -1 && pattern.endsWith(':*')) {
    const resource = pattern.slice(0, colonIdx);
    return db.prepare('SELECT key FROM permissions WHERE resource = ?').all(resource).map(r => r.key);
  }
  return [pattern];
}

// Get active grants
function getActiveGrants(db, { userId, orgId, now }) {
  const nowIso = now.toISOString();

  const rows = db.prepare(
    `SELECT g.id AS grantId, g.effect, g.device_id AS deviceId, gp.permission AS pattern
       FROM grants g
       JOIN grant_permissions gp ON g.id = gp.grant_id
      WHERE g.user_id = ?
        AND g.org_id  = ?
        AND g.revoked_at IS NULL
        AND (g.starts_at  IS NULL OR g.starts_at  <= ?)
        AND (g.expires_at IS NULL OR g.expires_at  > ?)`
  ).all(userId, orgId, nowIso, nowIso);

  const byGrant = new Map();
  for (const row of rows) {
    if (!byGrant.has(row.grantId)) {
      byGrant.set(row.grantId, { grantId: row.grantId, effect: row.effect, deviceId: row.deviceId, permissions: new Set() });
    }
    for (const perm of expandPattern(db, row.pattern)) {
      byGrant.get(row.grantId).permissions.add(perm);
    }
  }
  return [...byGrant.values()];
}

// Role baseline permissions
function getRoleBaseline(db, role) {
  const rows = db.prepare(
    `SELECT permission FROM role_permissions WHERE role = ?`
  ).all(role);
  return new Set(rows.map(r => r.permission));
}

// Resolve permissions
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const membership = db.prepare(
    `SELECT role, status FROM memberships WHERE user_id = ? AND org_id = ?`
  ).get(userId, orgId);

  const allPerms = db.prepare('SELECT key FROM permissions').all().map(r => r.key);

  // Missing membership check
  if (!membership) {
    const result = {};
    for (const p of allPerms) {
      result[p] = { effect: 'deny', source: null, reason: 'not_a_member' };
    }
    return { role: null, permissions: result };
  }

  // Suspended membership check
  if (membership.status === 'suspended' || membership.status === 'removed') {
    const result = {};
    for (const p of allPerms) {
      result[p] = { effect: 'deny', source: null, reason: 'suspended' };
    }
    return { role: membership.role, permissions: result };
  }

  const role = membership.role;
  const baseline = getRoleBaseline(db, role);
  const grants = getActiveGrants(db, { userId, orgId, now });

  const applicableGrants = (deviceId !== null)
    ? grants.filter(g => g.deviceId === null || g.deviceId === deviceId)
    : grants;

  const result = {};
  for (const perm of allPerms) {
    result[perm] = resolveOne(perm, role, baseline, applicableGrants, deviceId);
  }
  return { role, permissions: result };
}

// Single permission resolution
function resolveOne(perm, role, baseline, applicableGrants, deviceId) {
  // Explicit deny check
  for (const grant of applicableGrants) {
    if (grant.effect === 'deny' && grant.permissions.has(perm)) {
      return { effect: 'deny', source: `grant:${grant.grantId}`, reason: 'explicit_deny' };
    }
  }

  // Role baseline check
  if (baseline.has(perm)) {
    return { effect: 'allow', source: `role:${role}`, reason: null };
  }

  // Allow grant check
  for (const grant of applicableGrants) {
    if (grant.effect === 'allow' && grant.permissions.has(perm)) {
      return { effect: 'allow', source: `grant:${grant.grantId}`, reason: null };
    }
  }

  // Implicit deny
  return { effect: 'deny', source: null, reason: 'implicit' };
}

// Batch resolve device permissions
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const membership = db.prepare(
    `SELECT role, status FROM memberships WHERE user_id = ? AND org_id = ?`
  ).get(userId, orgId);

  const allPerms = db.prepare('SELECT key FROM permissions').all().map(r => r.key);

  if (!membership || membership.status === 'suspended' || membership.status === 'removed') {
    const emptyPerms = {};
    for (const p of allPerms) emptyPerms[p] = { effect: 'deny', source: null, reason: 'implicit' };
    const byDevice = {};
    for (const id of deviceIds) byDevice[id] = { ...emptyPerms };
    return { role: membership?.role ?? null, byDevice };
  }

  const role = membership.role;
  const baseline = getRoleBaseline(db, role);
  const allGrants = getActiveGrants(db, { userId, orgId, now });

  const byDevice = {};
  for (const deviceId of deviceIds) {
    const applicableGrants = allGrants.filter(g => g.deviceId === null || g.deviceId === deviceId);
    const devPerms = {};
    for (const perm of allPerms) {
      devPerms[perm] = resolveOne(perm, role, baseline, applicableGrants, deviceId);
    }
    byDevice[deviceId] = devPerms;
  }
  return { role, byDevice };
}

// Check permission
export function can(db, ctx, permission, deviceId = null) {
  if (ctx.suspended) return false;
  const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
  return permissions[permission]?.effect === 'allow';
}

// Assert permission
export function assertCan(db, ctx, permission, deviceId = null) {
  if (ctx.suspended) {
    throw forbidden(`account is suspended`, 'suspended');
  }
  const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
  const p = permissions[permission];
  if (!p || p.effect !== 'allow') {
    const reason = p?.reason ?? 'implicit';
    throw forbidden(`missing permission: ${permission}`, reason);
  }
}

// Assert grant authority
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  if (ctx.suspended) throw forbidden('account is suspended', 'suspended');

  const permsToGrant = new Set();
  for (const pattern of patterns) {
    for (const p of expandPattern(db, pattern)) {
      permsToGrant.add(p);
    }
  }

  const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
  for (const perm of permsToGrant) {
    if (!permissions[perm] || permissions[perm].effect !== 'allow') {
      throw forbidden(`cannot grant ${perm}: you don't hold it at this scope`, 'missing_permission');
    }
  }
}

// Assert session start permissions
export function assertCanStartSession(db, ctx, mode, deviceId) {
  if (ctx.suspended) throw forbidden('account is suspended', 'suspended');

  const modePerm = MODE_PERMISSION[mode];
  if (!modePerm) throw forbidden(`unknown session mode: ${mode}`, 'missing_permission');

  const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });

  const sessionStart = permissions['session:start'];
  if (!sessionStart || sessionStart.effect !== 'allow') {
    throw forbidden('missing session:start permission', 'missing_permission');
  }

  const modeResult = permissions[modePerm];
  if (!modeResult || modeResult.effect !== 'allow') {
    throw forbidden(`missing ${modePerm} permission for mode ${mode}`, 'missing_device_permission');
  }
}

// Org-level permissions
export function orgLevelPermissions(db, { userId, orgId, now = new Date() }) {
  return resolve(db, { userId, orgId, deviceId: null, now }).permissions;
}
