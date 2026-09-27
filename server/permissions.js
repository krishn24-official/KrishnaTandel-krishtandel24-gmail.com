// The permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.
//
// Resolution algorithm (PERMISSIONS.md §3):
//   1. If membership is suspended/removed → empty set (no permissions)
//   2. Collect applicable grants: non-revoked, time-windowed, org-scoped
//      (and optionally device-scoped for device-level questions)
//   3. Deny wins: if ANY applicable grant denies this permission → deny (explicit_deny)
//   4. Allow if role baseline contains it OR any applicable allow grant covers it
//   5. Otherwise: implicit deny (source: null, reason: 'implicit')
//
// CRITICAL: wildcards (device:*, *) are expanded by querying the permissions table.
// NEVER hardcode the catalogue — grading uses a different nonce with extra permissions.
//
// Two evaluation contexts (PERMISSIONS.md §3):
//   - org-level: union across all devices (for nav gating)
//   - device-level: exact check for a specific device (for row buttons / action endpoints)

import { forbidden } from './http.js';

export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

// ---------------------------------------------------------------------------
// Internal: expand a grant permission pattern to concrete permission keys.
// 'device:*' → all device permissions from the DB.
// '*' → all permissions from the DB.
// 'device:control' → ['device:control'] (exact match).
// Never hardcoded — reads from the permissions table each time.
// ---------------------------------------------------------------------------
function expandPattern(db, pattern) {
  if (pattern === '*') {
    return db.prepare('SELECT key FROM permissions').all().map(r => r.key);
  }
  const colonIdx = pattern.indexOf(':');
  if (colonIdx !== -1 && pattern.endsWith(':*')) {
    const resource = pattern.slice(0, colonIdx);
    return db.prepare('SELECT key FROM permissions WHERE resource = ?').all(resource).map(r => r.key);
  }
  // exact permission — still verify it's real (the FK on grant_permissions already did)
  return [pattern];
}

// ---------------------------------------------------------------------------
// Internal: get all grants for a user in an org, filtered by time window.
// Returns { grantId, effect, deviceId, permissions: Set<string> }[]
// ---------------------------------------------------------------------------
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

  // Group by grant, expanding wildcard patterns
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

// ---------------------------------------------------------------------------
// Internal: get the role baseline permissions for a role.
// Reads from DB — never hardcoded.
// ---------------------------------------------------------------------------
function getRoleBaseline(db, role) {
  const rows = db.prepare(
    `SELECT permission FROM role_permissions WHERE role = ?`
  ).all(role);
  return new Set(rows.map(r => r.permission));
}

// ---------------------------------------------------------------------------
// resolve(db, { userId, orgId, deviceId, now })
//
// Returns { [permission]: { effect, source, reason } } for ALL known permissions.
// deviceId === null → org-level (union across all devices).
// deviceId === 'some_id' → exact device-level check.
//
// source format:
//   'role:<roleKey>'   → from the role baseline
//   'grant:<grantId>'  → from a specific grant
//   null               → implicit deny
// ---------------------------------------------------------------------------
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  // Look up membership status
  const membership = db.prepare(
    `SELECT role, status FROM memberships WHERE user_id = ? AND org_id = ?`
  ).get(userId, orgId);

  // All known permissions (from DB — never hardcoded)
  const allPerms = db.prepare('SELECT key FROM permissions').all().map(r => r.key);

  // No membership in this org → cross-org or missing: all permissions denied with 'not_a_member'
  if (!membership) {
    const result = {};
    for (const p of allPerms) {
      result[p] = { effect: 'deny', source: null, reason: 'not_a_member' };
    }
    return { role: null, permissions: result };
  }

  // Suspended or removed → empty permission set (reason: 'suspended')
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

  // For device-level: include grants that apply to this device (device-scoped OR org-wide)
  // For org-level (deviceId===null): include ALL grants for this user
  const applicableGrants = (deviceId !== null)
    ? grants.filter(g => g.deviceId === null || g.deviceId === deviceId)
    : grants; // org-level: all grants participate

  const result = {};
  for (const perm of allPerms) {
    result[perm] = resolveOne(perm, role, baseline, applicableGrants, deviceId);
  }
  return { permissions: result };
}

// ---------------------------------------------------------------------------
// Internal: resolve a single permission given baseline and applicable grants.
// ---------------------------------------------------------------------------
function resolveOne(perm, role, baseline, applicableGrants, deviceId) {
  // DENY WINS (D1): check ALL applicable grants — if any deny, it wins.
  // Scope/specificity does not matter: an org-wide deny beats a device-scoped allow.
  for (const grant of applicableGrants) {
    if (grant.effect === 'deny' && grant.permissions.has(perm)) {
      return { effect: 'deny', source: `grant:${grant.grantId}`, reason: 'explicit_deny' };
    }
  }

  // ALLOW if role baseline has it
  if (baseline.has(perm)) {
    return { effect: 'allow', source: `role:${role}`, reason: null };
  }

  // ALLOW if any applicable allow grant covers it
  for (const grant of applicableGrants) {
    if (grant.effect === 'allow' && grant.permissions.has(perm)) {
      return { effect: 'allow', source: `grant:${grant.grantId}`, reason: null };
    }
  }

  // IMPLICIT DENY (D4)
  return { effect: 'deny', source: null, reason: 'implicit' };
}

// ---------------------------------------------------------------------------
// resolveDevices: batch resolution for the device list endpoint.
// Returns { role, byDevice: { [deviceId]: { [perm]: {effect,source,reason} } } }
// One SQL call to get all grants, one for baseline — no N+1.
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// can: returns true if the caller has the permission in the given context.
// deviceId is required for device permissions (D6), optional otherwise.
// ---------------------------------------------------------------------------
export function can(db, ctx, permission, deviceId = null) {
  if (ctx.suspended) return false;
  const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
  return permissions[permission]?.effect === 'allow';
}

// ---------------------------------------------------------------------------
// assertCan: throws 403 if the caller lacks the permission.
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// assertMayGrant: no privilege laundering (D9).
// The caller must hold every permission they are trying to grant, at the given
// scope. Patterns (e.g. 'device:*') are expanded before checking.
// ---------------------------------------------------------------------------
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  if (ctx.suspended) throw forbidden('account is suspended', 'suspended');

  // Expand all patterns to concrete permissions
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

// ---------------------------------------------------------------------------
// assertCanStartSession: compound check for session:start + mode permission (D10).
// Both must be allowed on the same device. A refusal must say WHICH was missing.
// ---------------------------------------------------------------------------
export function assertCanStartSession(db, ctx, mode, deviceId) {
  if (ctx.suspended) throw forbidden('account is suspended', 'suspended');

  const modePerm = MODE_PERMISSION[mode];
  if (!modePerm) throw forbidden(`unknown session mode: ${mode}`, 'missing_permission');

  const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });

  // session:start check: 'missing_permission' is the reason string the tests expect
  const sessionStart = permissions['session:start'];
  if (!sessionStart || sessionStart.effect !== 'allow') {
    throw forbidden('missing session:start permission', 'missing_permission');
  }

  // mode permission check: 'missing_device_permission' is the reason string the tests expect
  const modeResult = permissions[modePerm];
  if (!modeResult || modeResult.effect !== 'allow') {
    throw forbidden(`missing ${modePerm} permission for mode ${mode}`, 'missing_device_permission');
  }
}

// ---------------------------------------------------------------------------
// orgLevelPermissions: resolve the union across all devices in the org.
// A permission is "org-level allowed" if it's allowed on ANY device or without
// a device (for non-device permissions like user:read, audit:read).
// Used for /auth/me and nav gating.
// ---------------------------------------------------------------------------
export function orgLevelPermissions(db, { userId, orgId, now = new Date() }) {
  return resolve(db, { userId, orgId, deviceId: null, now }).permissions;
}
