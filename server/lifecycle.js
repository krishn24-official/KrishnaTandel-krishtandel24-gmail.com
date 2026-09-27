// Shared lifecycle and domain rules
import { forbidden, conflict, lastOwner, badRequest } from './http.js';
import { nowIso } from './db.js';

// Role ranks query
export function roleRanks(db) {
  const rows = db.prepare('SELECT key, rank FROM roles').all();
  const map = {};
  for (const r of rows) map[r.key] = r.rank;
  return map;
}

// Role existence check
export function assertRoleExists(db, role) {
  const row = db.prepare('SELECT key FROM roles WHERE key = ?').get(role);
  if (!row) throw badRequest(`unknown role: ${role}`);
}

// Member modification authority check
export function assertCanModify(db, callerRole, targetRole) {
  if (callerRole === 'owner') return;
  const ranks = roleRanks(db);
  const callerRank = ranks[callerRole] ?? 0;
  const targetRank = ranks[targetRole] ?? 0;

  if (callerRank <= targetRank) {
    throw forbidden(
      `you cannot modify a member of equal or higher rank (${targetRole})`,
      'missing_permission'
    );
  }
}

// Role assignment authority check
export function assertCanAssignRole(db, callerRole, newRole) {
  if (newRole === 'owner' && callerRole !== 'owner') {
    throw forbidden('only an owner may assign the owner role', 'missing_permission');
  }
  if (callerRole === 'owner') return;
  const ranks = roleRanks(db);
  const callerRank = ranks[callerRole] ?? 0;
  const newRoleRank = ranks[newRole] ?? 0;
  if (callerRank <= newRoleRank) {
    throw forbidden(`you cannot assign a role of equal or higher rank (${newRole})`, 'missing_permission');
  }
}

// Last active owner check
export function assertNotLastOwner(db, orgId, userId) {
  const ownerCount = db.prepare(
    `SELECT COUNT(*) AS n FROM memberships
      WHERE org_id = ? AND role = 'owner' AND status = 'active'`
  ).get(orgId).n;

  const isOwner = db.prepare(
    `SELECT role FROM memberships WHERE org_id = ? AND user_id = ?`
  ).get(orgId, userId);

  if (isOwner?.role === 'owner' && ownerCount <= 1) {
    throw lastOwner();
  }
}

// End active sessions
export function endActiveSessions(db, { orgId, userId = null, deviceId = null, reason, exceptSessionId = null }) {
  const at = nowIso();

  let query;
  const params = [];

  if (userId && deviceId) {
    query = `UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ?
              WHERE org_id = ? AND user_id = ? AND device_id = ? AND state = 'active'`;
    params.push(reason, at, orgId, userId, deviceId);
  } else if (userId) {
    query = `UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ?
              WHERE org_id = ? AND user_id = ? AND state = 'active'`;
    params.push(reason, at, orgId, userId);
  } else if (deviceId) {
    query = `UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ?
              WHERE org_id = ? AND device_id = ? AND state = 'active'`;
    params.push(reason, at, orgId, deviceId);
  } else {
    return;
  }

  if (exceptSessionId) {
    query += ` AND id != ?`;
    params.push(exceptSessionId);
  }

  db.prepare(query).run(...params);
}

// Authority snapshot
export function snapshotAuthority(db, { userId, orgId, deviceId }) {
  const membership = db.prepare(
    `SELECT role FROM memberships WHERE user_id = ? AND org_id = ?`
  ).get(userId, orgId);

  const now = new Date().toISOString();

  const grants = db.prepare(
    `SELECT g.id FROM grants g
      WHERE g.user_id = ? AND g.org_id = ?
        AND g.revoked_at IS NULL
        AND (g.device_id IS NULL OR g.device_id = ?)
        AND (g.starts_at IS NULL OR g.starts_at <= ?)
        AND (g.expires_at IS NULL OR g.expires_at > ?)`
  ).all(userId, orgId, deviceId, now, now);

  return JSON.stringify({
    role: membership?.role ?? null,
    grantIds: grants.map(g => g.id),
    snapshotAt: now,
  });
}

// Calculate session expiry
export function sessionExpiry(db, orgId) {
  const org = db.prepare('SELECT max_session_minutes FROM organizations WHERE id = ?').get(orgId);
  const minutes = org?.max_session_minutes ?? 60;
  const expiry = new Date(Date.now() + minutes * 60 * 1000);
  return expiry.toISOString();
}
