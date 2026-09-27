# BUILD LOG

One entry per meaningful step. Commit hash goes in when the step is committed.
Format: `## [date] [phase] — [what happened]`

---

## 2026-09-27 Phase 0 — Orient and baseline

Cloned starter, read all spec documents: README.md, BRIEF.md, AUTH-DATA-MODEL.md,
PERMISSIONS.md, WORKFLOW.md, UI-INVENTORY.md. Studied stubs in server/auth.js,
context.js, permissions.js, lifecycle.js. Inspected db/schema.sql and db/reference.sql.

Ran `node scripts/load-db.js` — failed with Windows path double-drive bug in load-db.js
line 10 (`here()` using `.pathname` instead of `fileURLToPath`). Fixed in load-db.js.
DB loaded successfully: 3 orgs, 8 users, 10 memberships, 9 devices, 6 grants, 20 permissions,
27 permission_patterns. Personalisation overlay applied (fingerprint bb339819425c,
role=reviewer, permission=device:reboot, org=Ironside Labs).

Starting state: check-jwt.js → 0/43 pass, check-permissions.js → crash, check-api.js → all 404.

Commit: c8c45ed

---

## 2026-09-27 Phase 1 — verifyAccessToken (server/auth.js)

Implemented `verifyAccessToken` with all AUTH-DATA-MODEL.md §10 failure modes:
- Structural: must have exactly 3 dot-separated segments
- Header/payload must be valid base64url-encoded JSON
- Algorithm pinning: we emit HS256 ourselves, never trust the header's `alg` field.
  This defeats `alg:none` and algorithm substitution at the structural level.
- Constant-time signature comparison via `timingSafeEqual` (avoids timing oracle)
- Half-open expiry: `exp <= now` is expired (not `<`)
- `iss` and `aud` exact match
- `jti` must be present and non-empty

Result: **43/43 JWT tests pass** (`check-jwt.js ALL PASS`)

Key decision: algorithm is pinned to HS256 before signature check, not via a denylist.
Reason: a denylist is incomplete by definition; pinning is a positive assertion.

---

## 2026-09-27 Phase 2a — context.js (authenticate)

Implemented `authenticate(db, secret)` → returns `buildContext(req, params)`:
- Extracts `Bearer` token from Authorization header
- Calls `verifyAccessToken` for structural validation
- Looks up membership for `(sub, org)` from the token (structural org isolation —
  the token's `org` claim is the ONLY org this caller can address, making wrong-org
  a 404 not a 403)
- Calls `assertFresh(claims, membership)` to check `pv !== membership.perm_version`
  (uses `!==`, not `<` — a future pv is as suspect as a stale one per AUTH-DATA-MODEL.md §3)
- Suspended members get `suspended: true` on the context; routes check this to 403

---

## 2026-09-27 Phase 2b — permissions.js (resolution engine)

Implemented full resolution engine. Key design choices:

1. Wildcard expansion reads from `permissions` table — never a hardcoded list.
   `device:*` → `SELECT key FROM permissions WHERE resource = 'device'`
   This is what makes the personalisation overlay work: `device:reboot` resolves correctly
   without being mentioned in any document.

2. Deny wins unconditionally (D1): all applicable grants are collected, any deny wins
   regardless of scope (org-wide deny beats device-scoped allow). Not "narrowest wins".

3. `resolve()` returns `{ role, permissions: { [key]: {effect, source, reason} } }`
   - No membership → `reason: 'not_a_member'`, `role: null`
   - Suspended/removed → `reason: 'suspended'`
   - Implicit deny → `reason: 'implicit'`
   - Explicit deny → `reason: 'explicit_deny'`, `source: 'grant:<id>'`

4. `resolveDevices()` batches all grants in one SQL call — no N+1 for the device list.

5. `assertCanStartSession` distinguishes missing `session:start` (`missing_permission`)
   from missing mode permission (`missing_device_permission`) — both required per D10.

Result: **35/35 permission tests pass** (`check-permissions.js ALL PASS`)

---

## 2026-09-27 Phase 2c — lifecycle.js

Implemented:
- `roleRanks()`: reads from DB at runtime (supports undocumented `reviewer` role)
- `assertCanModify()`: strict rank check — caller must outrank target, equal = forbidden
- `assertCanAssignRole()`: owner-only-assigns-owner, plus rank check on the new role
- `assertNotLastOwner()`: counts active owners, throws 409 LAST_OWNER if only one
- `endActiveSessions()`: ends sessions on suspension/removal/device transfer.
  Does NOT end on permission changes (D20 grandfathering). Only on tenancy events.
- `snapshotAuthority()`: JSON blob with role and active grant IDs at session-start time
- `sessionExpiry()`: `now + org.max_session_minutes`

---

## 2026-09-27 Phase 2d — audit.js

Implemented:
- `audit()`: INSERT-only, never throws on failure (a failed audit write must not kill the response)
- `auditDenials()`: wraps handler fn(), records denial before rethrowing 401/403

---

## 2026-09-27 Phase 3 — Routes (all)

Implemented all server-side endpoints: auth, orgs, members, invites, devices, grants, sessions.
Key choices:
- `requireOrgInScope()`: token's org claim is the 404 boundary (cross-org = invisible)
- Invite tokens returned raw exactly once (never stored in plaintext)
- Grant creation enforces no self-grants, no privilege laundering (D9)
- Device list uses `resolveDevices()` batch — no per-row permission query
- Session start: 409 DEVICE_BUSY when unique index fires for exclusive sessions
