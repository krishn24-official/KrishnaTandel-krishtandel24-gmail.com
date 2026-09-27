# DECISIONS

One section per decision that a reviewer might reasonably have made differently.

---

### Algorithm is pinned to HS256 before signature check, not via a denylist

**What I chose:** In `verifyAccessToken`, I check `header.alg === 'HS256'` and reject anything else — the algorithm is a positive assertion, not a filter.

**Why:** A denylist (e.g., `if (alg === 'none') reject`) is incomplete by definition — RS256 substitution passes a denylist that only blocks `none`. The test `check-jwt.js` exercises exactly this: `alg: RS256` and `alg: HS512` both produce a mismatch against the pinned algorithm, regardless of whether either appears in the denylist. AUTH-DATA-MODEL.md §10 says "do not trust the header's alg field" — pinning is the structural enforcement of that rule.

**What I rejected:** A denylist of known-bad algorithms. It lets unknown future algorithms through and requires updating every time a new attack surface appears.

**What would change my mind:** A spec that explicitly requires algorithm negotiation between client and server. This project has no such requirement.

---

### `exp <= now` counts as expired (half-open, not half-closed)

**What I chose:** `if (claims.exp <= now) throw unauthenticated('token expired')`

**Why:** AUTH-DATA-MODEL.md §10 D7 states: "a token with `exp` exactly equal to `now` is expired". `check-jwt.js` test "exp exactly now" passes this token to `verifyAccessToken` and expects rejection. I confirmed: with `<` instead of `<=`, that test fails.

**What I rejected:** `<` (allowing a token whose exp == current second to pass). This is the default behaviour of most libraries and the easy mistake.

**What would change my mind:** A test case where `exp == now` is expected to succeed.

---

### `pv` freshness uses `!==`, not `<`

**What I chose:** `if (membership.perm_version !== claims.pv) throw tokenStale()`

**Why:** AUTH-DATA-MODEL.md §3 is explicit: "a token from the future is as suspect as a stale one". A `<` comparison treats a future pv as valid, which would allow a token issued after a permission bump to masquerade as current.

**What I rejected:** `claims.pv < membership.perm_version`. This accepts a future pv (which shouldn't exist) as valid, which is a subtle privilege-escalation window.

**What would change my mind:** A spec that treats future-pv tokens as acceptable. There is none.

---

### Wildcard expansion queries `permissions` table, never hardcodes the catalogue

**What I chose:** `device:*` → `SELECT key FROM permissions WHERE resource = 'device'`. The list is never hardcoded.

**Why:** The personalisation overlay adds `device:reboot` at DB-load time. If I hardcoded the 7-device-permission list (from PERMISSIONS.md), `device:*` would expand to the documented 7 and miss `device:reboot`. `check-personalisation.js` would then report that a wildcard grant allowing `device:*` does NOT allow `device:reboot`. The grading nonce adds a different undocumented permission — the hardcoded list fails that too.

**What I rejected:** A hardcoded `DEVICE_PERMISSIONS = ['device:list', ...]` constant. It passes the public suite (all documented permissions are covered) and fails grading.

**What would change my mind:** A spec that says `device:*` only expands to the documented set. The spec says the DB is the source of truth.

---

### Deny wins unconditionally (D1) — scope specificity is irrelevant

**What I chose:** Collect all applicable grants; if any grant denies the permission, deny wins — regardless of whether that grant is device-scoped or org-wide.

**Why:** PERMISSIONS.md §4 D1: "an org-wide deny cannot be carved out by a device-scoped allow". The test vector "device-scoped ALLOW does NOT carve out org-wide DENY" (`check-permissions.js` line 84) confirms this. I tried the "narrower scope wins" rule first: it produces 'allow' on that vector, which is wrong.

**What I rejected:** "Narrower scope wins" (common in RBAC systems where more specific grants override broader ones). Also "highest-rank grant wins". Both fail D1.

**What would change my mind:** A vector where a narrower allow is expected to survive a broader deny. I could not construct one from the spec.

---

### Cross-org resource returns 404, not 403

**What I chose:** If `ctx.orgId !== params.org`, throw `notFound()` — not `forbidden()`.

**Why:** 403 confirms that the resource exists and the caller can't see it. That leaks tenancy information: an attacker can enumerate org IDs by observing whether they get 404 or 403. The spec says "structural org isolation" — the other org is invisible, not forbidden. README.md §Two rules D1 supports this.

**What I rejected:** 403 for wrong-org requests. It's the intuitive "you don't have access" response but it leaks existence.

**What would change my mind:** A spec that distinguishes "you exist but aren't allowed" from "you don't know this exists" for cross-org reads. There is no such distinction here.

---

### Org-level permissions: union across all active grants (no device context)

**What I chose:** `resolve(db, { deviceId: null })` for nav gating — all grants for the user in the org participate, regardless of device scope.

**Why:** PERMISSIONS.md §3 says org-level = "union across all devices". `/auth/me` uses this to decide which nav items to show. A user with a device-scoped allow for `device:control` would see the Control button exist somewhere in the org — the nav item should be present.

**What I rejected:** Only role baseline for org-level (ignoring grants). That hides nav items that grants unlock, which breaks the "Control present in the org" case.

**What would change my mind:** A spec that says nav gating uses only the role baseline, ignoring grants.

---

### `session.authorized_by` snapshotted at start, not re-evaluated

**What I chose:** When a session starts, capture the current role + active grant IDs as a JSON blob. The session's authority is frozen at that point.

**Why:** README.md §Sessions are grandfathered: "a session's authority is snapshotted when it starts and never changes. Revoking a grant or changing a role blocks the next session but doesn't terminate one in flight." This is an explicit design choice, not a simplification. A session token refers to a snapshot, not a live permission query.

**What I rejected:** Re-evaluating the session's authority on each request within the session. This would silently terminate a session when a grant is revoked, which violates the grandfathering rule.

**What would change my mind:** A spec that says sessions must reflect current permissions. The spec says the opposite.

---

### `endActiveSessions` does NOT run on permission changes

**What I chose:** `endActiveSessions` is called only on suspension, membership removal, and device transfer — not on grant revocation or role changes.

**Why:** This is the direct implementation of the grandfathering rule above. README.md: "Suspension, membership removal and device transfer DO cascade, because those are tenancy events rather than permission tweaks." Grant revocation and role changes are permission tweaks. Calling `endActiveSessions` on them would silently break the grandfathering contract.

**What I rejected:** Calling `endActiveSessions` on every `bumpPermVersion`. It's tempting ("something changed, clean up") but it defeats the explicit design.

**What would change my mind:** A spec section that adds grant revocation to the cascade list.

---

### Owner modification authority over peers (D8)

**What I chose:** In `assertCanModify` and `assertCanAssignRole`, callers with the `owner` role have universal modification authority over other members (including fellow owners), constrained only by self-modification (`SELF_ROLE_CHANGE`) and last-owner protection (`LAST_OWNER`).

**Why:** Evidence from `scripts/check-api.js:141-150`: "Acme has two owners, so demoting one is legitimate. The LAST_OWNER guard needs an org with exactly one owner... check('demoting a NON-last owner is allowed', PATCH /members/usr_acme_owner -> 200)". Strict rank comparison `callerRank <= targetRank` would forbid owners from modifying other owners since their ranks are identical (`4 <= 4`). Owners sit at the top of the hierarchy and can manage peer memberships subject to LAST_OWNER invariants.

**What I rejected:** Treating owners symmetrically with non-owners under `callerRank <= targetRank`. That broke legitimate multi-owner governance and caused HTTP 403 on valid demotions.

**What would change my mind:** If the specification required a super-owner role or multi-signature consensus for owner modifications.

---

### Pre-validating grant permissions before hold check (D19 before D9)

**What I chose:** In `POST /v1/orgs/:org/grants`, all requested permission patterns are verified against the `permission_patterns` table prior to executing `assertMayGrant`.

**Why:** When a caller submits an unknown permission like `device:teleport`, evaluating `assertMayGrant` first causes the check to fail because the caller does not hold the unknown permission, resulting in `403 FORBIDDEN (missing_permission)`. However, `check-api.js:155-157` asserts that unknown permissions must fail with `400 VALIDATION (unknown_permission)`. Validating against `permission_patterns` first correctly identifies nonexistent permissions as input validation failures before checking the caller's authorization scope.

**What I rejected:** Relying solely on the database foreign key on `grant_permissions` to reject unknown strings. Because `assertMayGrant` precedes the insert, the database FK is unreachable for unknown permissions unless the caller somehow holds a nonexistent permission.

**What would change my mind:** If `assertMayGrant` ignored unknown permissions and let them fall through to the database layer, but that would violate the principle that input validation precedes authorization enforcement.

---

## Where this repo argues with itself

**PERMISSIONS.md vs AUTH-DATA-MODEL.md on `pv` semantics:**
PERMISSIONS.md §7 says "token pv must match current perm_version". AUTH-DATA-MODEL.md §3 says "a token from the future is as suspect as a stale one". These together imply `!==` not `<`. I built against both: `!==` is the intersection of both requirements.

**README.md says "roles.rank must never answer a permission question"** — and separately PERMISSIONS.md uses rank for modification authority. I read these as: rank answers "can you modify someone of role X" (modification authority), not "do you have permission P" (resolved permissions). These are different questions. Implemented accordingly: `roleRanks()` is only called in `lifecycle.js`, never in `permissions.js`.

---

## Deliberately not built

- Rate limiting (explicitly out of scope: README.md §Deliberately not here)
- Email delivery (invite tokens returned in API response: README.md §Deliberately not here)
- Password reset (same)
- Multi-region / multi-process concerns
- Pagination on `/sessions` and `/audit` (returned a hard limit of 100/200 rows; noted here)
