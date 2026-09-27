// Shared domain rules: role ranks, last-owner protection, ending sessions.
//
// IMPORTANT: roles.rank is MODIFICATION AUTHORITY ONLY (D8).
// It must NEVER answer a can() question. operator and auditor are unordered
// by permissions — ranking them as integers produces wrong answers.
//
// Session ending rules (PERMISSIONS.md §7):
//   - Permission changes do NOT end sessions in flight (grandfathering)
//   - Suspension, removal, device transfer DO cascade
//   - Every session has expires_at so grandfathering is never indefinite

import { forbidden, conflict, lastOwner, badRequest } from './http.js';
import { nowIso } from './db.js';

// ---------------------------------------------------------------------------
// roleRanks: returns { [roleKey]: rank } from the DB.
// Reads at call time — supports the undocumented extra role from personalisation.
// ---------------------------------------------------------------------------
export function roleRanks(db) {
  const rows = db.prepare('SELECT key, rank FROM roles').all();
  const map = {};
  for (const r of rows) map[r.key] = r.rank;
  return map;
}

// ---------------------------------------------------------------------------
// assertRoleExists: throws 400 if the role key isn't in the DB.
// ---------------------------------------------------------------------------
export function assertRoleExists(db, role) {
  const row = db.prepare('SELECT key FROM roles WHERE key = ?').get(role);
  if (!row) throw badRequest(`unknown role: ${role}`);
}

// ---------------------------------------------------------------------------
// assertCanModify: enforces modification authority (D8).
//   - caller must outrank target (strictly)
//   - equal rank is forbidden
//   - only owners may assign owner
// ---------------------------------------------------------------------------
export function assertCanModify(db, callerRole, targetRole) {
  if (callerRole === 'owner') return; // Owner can modify any other member (non-self)
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

// ---------------------------------------------------------------------------
// assertCanAssignRole: checks both modification authority and owner-only rule.
// ---------------------------------------------------------------------------
export function assertCanAssignRole(db, callerRole, newRole) {
  // Only an owner may confer owner
  if (newRole === 'owner' && callerRole !== 'owner') {
    throw forbidden('only an owner may assign the owner role', 'missing_permission');
  }
  if (callerRole === 'owner') return; // Owner can assign any role
  const ranks = roleRanks(db);
  // Caller must outrank the role they're assigning
  const callerRank = ranks[callerRole] ?? 0;
  const newRoleRank = ranks[newRole] ?? 0;
  if (callerRank <= newRoleRank) {
    throw forbidden(`you cannot assign a role of equal or higher rank (${newRole})`, 'missing_permission');
  }
}

// ---------------------------------------------------------------------------
// assertNotLastOwner: prevents leaving the org ownerless.
// Throws 409 LAST_OWNER if this user is the only active owner.
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// endActiveSessions: end all active sessions for a user (or device) in an org.
// Trigger: suspension, removal, or device transfer/decommission.
// Permission changes do NOT trigger this — that is intentional (D20 grandfathering).
// ---------------------------------------------------------------------------
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
    return; // nothing to do
  }

  if (exceptSessionId) {
    query += ` AND id != ?`;
    params.push(exceptSessionId);
  }

  db.prepare(query).run(...params);
}

// ---------------------------------------------------------------------------
// snapshotAuthority: create the authorized_by JSON blob stored on sessions.
// Captures role and active grant IDs at session-start time.
// ---------------------------------------------------------------------------
export function snapshotAuthority(db, { userId, orgId, deviceId }) {
  const membership = db.prepare(
    `SELECT role FROM memberships WHERE user_id = ? AND org_id = ?`
  ).get(userId, orgId);

  const now = new Date().toISOString();

  // Active grants that apply to this device (device-scoped OR org-wide)
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

// ---------------------------------------------------------------------------
// sessionExpiry: returns the ISO timestamp for a new session's expires_at.
// expires_at = now + org.max_session_minutes.
// ---------------------------------------------------------------------------
export function sessionExpiry(db, orgId) {
  const org = db.prepare('SELECT max_session_minutes FROM organizations WHERE id = ?').get(orgId);
  const minutes = org?.max_session_minutes ?? 60;
  const expiry = new Date(Date.now() + minutes * 60 * 1000);
  return expiry.toISOString();
}
