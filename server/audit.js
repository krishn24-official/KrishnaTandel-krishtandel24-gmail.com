// Append-only audit writes.
//
// audit_events has BEFORE UPDATE / BEFORE DELETE triggers, so this module
// only ever INSERTs. Two things the spec is explicit about:
//   - DENIED attempts are recorded, not just successes (PERMISSIONS.md invariant 9)
//   - a single action produces a single row; write inside the same transaction
//     as the change it describes
//
// Schema: id, org_id (NOT NULL), actor_id, action, target_type, target_id,
//         result ('allow'|'deny'), reason_code, request_id, at

import { newId, nowIso } from './db.js';

// ---------------------------------------------------------------------------
// audit: write one audit row. Never throws on audit failure — a failed audit
// write must not kill the actual response. But we do log it.
// ---------------------------------------------------------------------------
export function audit(db, { orgId, actorId, action, targetType, targetId, result, reasonCode = null, requestId = null }) {
  try {
    db.prepare(
      `INSERT INTO audit_events (id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id, at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      newId('aud'),
      orgId,
      actorId ?? null,
      action,
      targetType ?? null,
      targetId ?? null,
      result,
      reasonCode ?? null,
      requestId ?? null,
      nowIso()
    );
  } catch (err) {
    // Audit failure is logged but never propagated — the audit trigger prevents
    // UPDATE/DELETE but INSERT should always succeed.
    console.error('[audit] write failed:', err.message);
  }
}

// ---------------------------------------------------------------------------
// auditDenials: run fn(); if it refuses with a permission error, record the
// denial before rethrowing. Wraps the common pattern of "try the action, log
// the result either way".
// ---------------------------------------------------------------------------
export function auditDenials(db, ctx, meta, fn) {
  try {
    const result = fn();
    // Success — caller decides whether to write a success audit row
    return result;
  } catch (err) {
    // Only audit if it was a permission/auth failure (403/401)
    if (err.status === 403 || err.status === 401) {
      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        action: meta.action,
        targetType: meta.targetType ?? null,
        targetId: meta.targetId ?? null,
        result: 'deny',
        reasonCode: err.reason ?? err.code ?? null,
        requestId: ctx.requestId ?? null,
      });
    }
    throw err;
  }
}
