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

## 2. `access_bindings.subject_id` subject-existence — now DB-enforced (migration 0049)

**Status (as of 2026-07-05, r3 hardening — CLOSED)**: this was previously a
documented divergence (subject_id validated by nothing). The r3 audit reversed
that decision: `access_bindings.subject_id` and `access_binding_subjects.subject_id`
are now enforced at the DB level by the `subject_ref_exists()` BEFORE INSERT/UPDATE
trigger (migration `0049_access_binding_subject_exists.sql`), restoring hard-rule
#10 parity with `group_members` and `access_bindings.role_id`.

**Convention** (project hard-rule #10): every within-service reference must be
DB-enforced (FK / trigger / CAS), never left to software validation.
`group_members` follows this via `group_members_member_exists`, and
`access_bindings.role_id` is FK-backed (`access_bindings_role_fk`).

**What the trigger does**:
- On INSERT (and on an UPDATE that *changes* the subject), it probes the referent
  table selected by `subject_type` (`users` / `service_accounts` / `groups`) with
  `SELECT … FOR KEY SHARE`. A missing subject raises `23503` →
  `ErrFailedPrecondition` (via `iamerr.WrapPgErr`), exactly like a FK-RESTRICT.
- The `FOR KEY SHARE` lock is the documented substitute for a real FK on a
  **polymorphic** reference (no single `REFERENCES` target is possible). It closes
  the create-binding-vs-delete-subject write-skew: the binding INSERT and a
  concurrent `User.Delete` guarded CAS (`… WHERE NOT EXISTS(access_bindings …)`)
  now serialize on the referenced principal's row, so whichever commits second
  observes the other's effect (delete → 0 rows; or insert → `23503`). No dangling
  binding for a just-deleted subject is left behind.
- `UPDATE`s that do not change the subject (status transition, label update,
  deletion-protection toggle) skip the probe (FK semantics: an unchanged key is
  not re-validated), so revoke/label paths on existing bindings are unaffected.
- The same trigger was applied to `group_members_member_exists()`, upgrading its
  historical snapshot `SELECT EXISTS` to a `FOR KEY SHARE` locking probe (closing
  the identical member-add-vs-subject-delete race).

**Behavioural implication (deliberate)**: a grant to a **non-existent** internal
subject id (`usr_…` / `grp_…` / `sva_…`) is now rejected with `FAILED_PRECONDITION`
instead of silently creating a phantom grant + orphaned FGA tuple. This does **not**
break the invite/pre-authorize flow: `InviteUserUseCase` mints a `PENDING` `users`
row *before* any grant, so granting to an invited-but-not-logged-in user references
an existing (PENDING) row and succeeds. Bindings carry the internal minted id
(never a raw external subject), which cannot exist before the principal is
provisioned — so "forward-referencing a subject that has no row at all" was a
phantom-grant / typo vector, not a real pre-authorization capability, and is now
closed. Cross-account subjects live in the same `kacho_iam` DB and are unaffected.

**Superseded convergence note**: the r2 doc proposed typed nullable FK columns or
`SERIALIZABLE` as the only race-free options and deferred both. The r3 trigger with
a `FOR KEY SHARE` locking probe is a third option (a locking polymorphic-existence
trigger) that closes the race without a schema redesign or a stricter isolation
level; the typed-FK split is therefore no longer required for correctness (it
remains a possible future ergonomic cleanup, not a security necessity).

_Reviewed 2026-07-05 (r2: divergence documented; r3: closed by migration 0049)._

---

## 3. Production DB-TLS gate now applies to all production variants (operational note)

**Change (r3 hardening)**: `Config.Validate()` previously required a secure
Postgres `ssl-mode` (`require|verify-ca|verify-full`) only for
`ModeProductionStrict`. It now requires it for **every** production variant
(`ModeProduction` and `ModeProductionStrict`) — all IAM rows (user/SA records,
session-revocation + token rows, and the transient SA-key `client_secret` briefly
staged in `operations.response_data` before redaction) traverse the DB link, so a
plaintext connection in production is a boot-time misconfiguration, exactly like a
missing mTLS listener (CWE-319).

**Operational implication**: a binary booted in `production` mode (the default
`authn.mode`) with `repository.postgres.ssl-mode=disable` (the default) or unset
now **fails `Validate()` at boot** instead of silently connecting in cleartext.
Dev mode is unaffected (the shipped `values.dev.yaml` carries `authn.mode: dev`,
and `InsecureDevWarnings` still emits a non-blocking warning there). A production
deployment that terminates DB TLS at a localhost sidecar/proxy must set
`ssl-mode=require` against that proxy endpoint (the connection to the sidecar is
still TLS from libpq's perspective) — there is intentionally no "encrypted at a
lower layer, so `disable` is fine" escape hatch, matching the gRPC-listener gate.

---

## 4. FGA authorization-model gates skip unless the canonical DSL is resolvable (CI residual)

**Convention** (hard-rule #12): security-relevant tests must be green, not
silently skipped. The FGA model-drift gate (`internal/authzmap/fga_model_drift_test.go`)
and the real-OpenFGA tuple-emission proof (`internal/testsupport/fgatest`) prove the
emitter/catalog match the canonical `fga_model.fga` DSL.

**Residual**: both resolve the canonical DSL by (r3) trying a sibling `kacho-proto`
checkout **then** the pinned `kacho-proto` Go-module directory
(`go list -m -f {{.Dir}}`). In the standalone Go-test CI lanes `kacho-proto` is a
module, and the `.fga` file is **not currently shipped inside that module**, so the
DSL is unresolvable and both gates still `t.Skip`. r3 added an env-gated hard-fail:
with `KACHO_IAM_REQUIRE_FGA_MODEL=1` the absence becomes `t.Fatal` (refusing to skip
a security gate) — verified locally — so CI can enforce non-skip **the moment** the
model ships in the pinned module.

**Convergence path (cross-repo, out of kacho-iam scope)**: ship
`proto/kacho/cloud/iam/v1/fga_model.fga` inside the `kacho-proto` module (so the
module-dir resolution finds it), then set `KACHO_IAM_REQUIRE_FGA_MODEL=1` (and, for
the real-FGA proof, provision the `openfga/cli` image) in the Go-test CI jobs. Until
then the gates degrade to a documented skip locally/offline rather than a silent
no-op with no way to enforce.

---

## 5. Fat authz/conditions service structs not yet split into per-RPC use-cases (deferred reorg)

**Convention** (evgeniy/godzila regime): one `UseCase` struct + one file per RPC
(as in `internal/apps/kacho/api/account`).

**Divergence**: `ConditionsCRUDService` (`conditions_crud_service.go`) and
`AuthorizeService` (`authorize_service.go`) each carry the full CRUD/authz method
set on a single struct, and some services keep their use-cases in one file
(`sa_keys/usecases.go`, `user_tokens/usecases.go`). These predate the per-RPC
regime the rest of the codebase follows.

**Why deferred (not fixed in r3)**: splitting is a pure mechanical reorganisation
with **no** runtime, wire, or security impact, but a large blast radius across the
most security-sensitive package (the authz core). Doing it inside a security
hardening pass would mix high-churn refactor noise into security-relevant diffs and
raise regression risk for zero behavioural benefit. Tracked as a dedicated
refactor-only change (its own PR), to be reviewed in isolation.

---

## 6. `access_binding_repo.go` combines row-CRUD with three outbox emitters (deferred reorg)

**Divergence**: `internal/repo/kacho/pg/access_binding_repo.go` (~1.2k LOC) holds
the access-binding reader/writer plus the subject_change / fga / audit outbox
emitters and the emitted-tuple bookkeeping in one file, with emitter logic that is
near-duplicated in `reconcile_adapter.go` / `audit_outbox_emitter.go`.

**Why deferred (not fixed in r3)**: like §5, this is a file-organisation / DRY
cleanup with no behavioural or security impact. Extracting the emitters into shared
helpers touches the write-path and the async drain-path together and is better done
as a focused, independently-reviewed refactor than folded into a hardening pass.
Tracked as a dedicated refactor-only change.
