# Known divergences — kacho-iam

Deliberate, reviewed deviations from a project-wide convention that are **not**
defects. Each entry states the convention, why kacho-iam diverges, why it is
safe, and what would be required to converge.

---

## 1. mTLS config loaded via `envconfig` struct-tags, not the viper/YAML path

**Convention** (evgeniy regime): service configuration is loaded via
`viper` + `mapstructure` from YAML — no `envconfig` struct-tags.
`internal/apps/kacho/config/load.go` follows this for the bulk of the config.

**Divergence**: `MTLSConfig` (`internal/apps/kacho/config/mtls.go`) is loaded by a
**separate** `envconfig`-based path (`LoadMTLS`), using `envconfig:"…"` struct
tags, so two config-parsing mechanisms coexist in the same package.

**Why (by design, not a defect)**: the per-edge mTLS server credentials are
carried by `grpcsrv.TLSServer`, a **horizontal value-struct owned by
`kacho-corelib`**. That corelib type intentionally exposes no `mapstructure`
tags (it is a plain cross-service value type), so it cannot be populated through
the viper/`mapstructure` decoder without either (a) adding `mapstructure` tags to
a corelib type — a workspace-wide change to a shared horizontal package, owned by
corelib's release cadence, out of scope for a single service — or (b) hand-writing
a parallel tagged mirror struct in kacho-iam and copying field-by-field (its own
drift risk). `envconfig` reads the corelib fields directly from the environment
with zero corelib change, and each mTLS edge is **default-off** (`Enable=false`
→ plaintext, byte-identical to prior behaviour), so the second mechanism governs
only an opt-in security hardening surface, isolated to this one struct.

**Safety**: the two mechanisms do not overlap — viper/YAML owns all functional
config; `envconfig` owns *only* the four opt-in mTLS server edges
(`KACHO_IAM_{PUBLIC,INTERNAL,HOOKS,METRICS}_SERVER_MTLS_*`). There is no field
whose value could be silently shadowed between the two. An operator setting an
mTLS parameter uses the documented `KACHO_IAM_*_MTLS_*` env vars; these are not
expressible under a YAML `config:` section by design.

**Convergence path (deferred)**: give `grpcsrv.TLSServer` `mapstructure` tags
upstream in `kacho-corelib` and load mTLS through the same viper path. This is a
corelib-wide migration (touches every service embedding `grpcsrv.TLSServer`) and
is intentionally **not** done as part of a single-service change. Tracked as a
convergence item for the next corelib config pass; no runtime impact until then.

_Reviewed 2026-07-05 (security-hardening audit)._

---

## 2. `access_bindings.subject_id` has no within-service subject-existence enforcement

**Convention** (project hard-rule #10): every within-service reference must be
DB-enforced (FK / trigger / CAS), never left to software validation. `group_members`
follows this with the `group_members_member_exists` existence trigger, and
`access_bindings.role_id` is FK-backed (`access_bindings_role_fk`).

**Divergence**: `access_bindings.subject_id` (polymorphic `user|group|service_account`,
same `kacho_iam` DB) is validated by **nothing** — only a `CHECK` on the
`subject_type` enum and the partial `UNIQUE access_bindings_active_grant_uniq`
(duplicate-active-grant guard). `AccessBinding.Create` accepts a binding whose
subject does not (yet) exist. The `access_binding_subjects` set-table (migration
0028) likewise carries the polymorphic `subject_id` with no existence check.

**Why (by design, not a defect)**: this is the **grant-before-subject-exists /
invite** flow. A tenant admin grants a project/account role to a principal that
has not yet been provisioned in this account — e.g. an invited user who has never
logged in (a `PENDING` user row, or no row at all until first login materializes
it), or a subject managed in another account. Requiring the subject to pre-exist
would break the standard IAM pattern of pre-authorizing access ahead of first
sign-in. The `role_id` reference *is* FK-enforced because a role is always a
same-account catalog object that must exist at grant time; a *subject* is
deliberately allowed to be forward-referenced.

**Safety**: a binding to a not-yet-existent subject is inert — it grants nothing
until a matching subject id materializes, at which point the already-emitted FGA
tuples resolve. The reverse direction (deleting a subject that still has active
bindings) *is* guarded: `User.Delete` / `ServiceAccount.Delete` / `Group.Delete`
carry a `NOT EXISTS (access_bindings WHERE subject_id = …)` guard, so a live
subject cannot be removed out from under an active grant through the normal delete
path. (A concurrent create-binding-vs-delete-subject race under READ COMMITTED can
still leave a binding referencing a just-deleted subject — the same class of
polymorphic-no-FK write-skew as `group_members`; it is tolerated here for the same
reason the forward reference is: the binding is inert without a subject, and the
authoritative fix is the shared one below.)

**Convergence path (deferred)**: the only way to make a polymorphic reference
race-free is to stop it being polymorphic — split `subject_id` into typed nullable
FK columns (`subject_user_id` / `subject_group_id` / `subject_sa_id`, each a real
FK, exactly-one `CHECK`) — OR run the create/delete pair at `SERIALIZABLE`. Both
are a shared redesign that must also cover `group_members` (identical shape) and
is out of scope for a single hardening pass; tracked as a dedicated schema-redesign
item. If the typed-FK route is taken, `ON DELETE RESTRICT` would additionally make
subject-existence a hard DB invariant — but only if the invite/pre-provision flow
is first reworked to tolerate it.

_Reviewed 2026-07-05 (security-hardening audit)._
