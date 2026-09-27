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

## 2026-09-27 Phase 3 — Routes and verification

Implemented all server-side endpoints: auth, orgs, members, invites, devices, grants, sessions.
Key choices:
- `requireOrgInScope()`: token's org claim is the 404 boundary (cross-org = invisible)
- Invite tokens returned raw exactly once (never stored in plaintext)
- Grant creation enforces no self-grants, no privilege laundering (D9)
- Device list uses `resolveDevices()` batch — no per-row permission query
- Session start: 409 DEVICE_BUSY when unique index fires for exclusive sessions

Ran initial `check-api.js`: 57/66 passed, 9 failed. Debugged and fixed:
1. `deviceBusy` import missing in `sessions.js`, caused 500 ReferenceError instead of 409 DEVICE_BUSY.
2. `can_perm` in `sessions.js` indexed `perms[permission]` instead of `perms.permissions[permission]`; replaced with canonical `can()` import from `permissions.js`. This fixed live session survival and suspension cascading tests.
3. `assertCanModify` in `lifecycle.js` prevented owners from demoting fellow non-last owners because `callerRank <= targetRank` was checked blindly. Allowed owner role modification authority while preserving last-owner protection.
4. `POST /grants`: unknown permission strings like `device:teleport` were failing `assertMayGrant` with 403 `missing_permission` before reaching the FK. Validated against `permission_patterns` table first to reject with 400 `unknown_permission`.
5. `resolve()` in `permissions.js` omitted `role` on active member resolution. Fixed to return `{ role, permissions: result }`.

Results:
- `check-jwt.js`: **43/43 passed**
- `check-permissions.js`: **35/35 passed**
- `check-personalisation.js`: **18/18 passed**
- `check-api.js`: **66/66 passed**

Commit: 3f774cc

---

## 2026-09-27 Phase 4 — Web Console SPA & E2E Contract

Implemented the React single page application in `web/main.jsx` and design system in `web/index.css`.
Key design choices & guarantees:
1. **Server-resolved presence semantics (UI-INVENTORY.md §5)**:
   Elements are rendered (`data-state="unlocked"`) or absent. Zero client-side role matrices; all gating is driven by `permissions` returned from `GET /v1/auth/me` and per-device permissions returned from `GET /v1/orgs/:org/devices`. When the server denies, the element disappears.
2. **In-memory token security (D13)**:
   Access token lives strictly in React memory state. Zero tokens written to `localStorage` or `sessionStorage`. On page refresh, session restores seamlessly via httpOnly `remoteops_refresh` cookie calling `POST /v1/auth/refresh`.
3. **Multi-org isolation & theming**:
   App shell reflects active org identity via `data-org-id` and `data-org-theme`. Visual background color shifts measurably between themes (`cobalt`, `amber`, `moss`, `plum`, `rust`, `teal`). Cross-org content never leaks into the DOM.
4. **All console views implemented**:
   - Fleet Devices: per-device action buttons (Control, Terminal, View) gated by device-level resolved permissions.
   - People / Team: member list with roles and statuses.
   - Grants: active grant cards, inline scoped grant creation form with member & device select, and revocation.
   - Sessions: active and past session history.
   - Audit Trail: immutable audit log entries.
   - Admin: Rename organization (`org:update`) and Delete organization (`org:delete`).
   - Invite redemption: `/invite/:token` public peek and member accept flow with strict anti-leak guarantees.

E2E debugging:
- Installed missing Playwright headless shell via `npx playwright install chromium`.
- Identified and fixed static file serving bug on Windows in `server/index.js:22`: `new URL('../dist/', import.meta.url).pathname` produced a path with a leading slash (`/C:/...`), causing `stat()` and `readFile()` to fail and return 404 for `GET /`. Switched to `fileURLToPath` from `node:url`.

Results:
- `npm run build`: built production bundle in 1.79s
- Playwright E2E suite (`npx playwright test`): **25/25 passed (100%)**


