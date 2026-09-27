// Audit event logging
import { newId, nowIso } from './db.js';

// Write audit event
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
    console.error('[audit] write failed:', err.message);
  }
}

// Audit denials wrapper
export function auditDenials(db, ctx, meta, fn) {
  try {
    const result = fn();
    return result;
  } catch (err) {
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
