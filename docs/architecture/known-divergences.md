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

---

## 7. Conditions domain→proto projection + required-field validation live in the service/handler, not the dto registry / a domain constructor (deferred reorg)

**Convention** (godzila/evgeniy regime): domain→proto mapping goes through the
generic `internal/dto` + `internal/dto/toproto/*` registry (`dto.Transfer` /
`RegTransfer`), and required-field/business validation lives in self-validating
domain newtypes + a `domain.X.Validate()` constructor — the pattern every core
resource (Account/Project/User/ServiceAccount/Group/Role/AccessBinding) follows.

**Divergence**: the conditions feature hand-rolls its projection
(`service.ConditionToProto` / `conditionStatusToProto` in
`conditions_crud_service.go`) instead of a registered `toproto/condition.go`, and
validates required fields (`folder_id` / `name` / `expression`, and `context` on
Evaluate) **inline in the transport handler**
(`internal/apps/kacho/api/conditions/handler.go`) rather than in a
`domain.Condition` constructor.

**Why deferred (not fixed here)**: this is the same cohesive-service area already
recorded in §5 (conditions/authorize kept as fat services). Moving the projection
into the registry would **not** by itself close the stated risk — the
`conditionStatusToProto` `switch` keeps a catch-all `STATUS_UNSPECIFIED` default,
so an unhandled future `domain.ConditionStatus` would still map silently regardless
of where the switch lives; and the `parameters_schema` JSON→structpb path
currently swallows a decode error (omit-on-bad-JSON) that a registry impl returning
`(T, error)` would surface differently. Both are behaviour-affecting nuances that
belong in a focused, independently-reviewed conditions refactor (with a domain
constructor and a loud-on-unknown status mapping), not folded into a security
hardening pass. Introducing a second entry point to condition creation before that
refactor is the only way the inline-handler validation could be bypassed; today the
gRPC handler is the sole caller, so the invariant holds for every real path.

**Convergence path (deferred)**: add `internal/dto/toproto/condition.go`
(registered via `RegTransfer`, added to the `Transferrable` type-set), introduce a
self-validating `domain.Condition` (ConditionName/Expression newtypes +
`Validate()`), make the status mapping fail loud on an unknown value, and reduce the
handler to transport parsing + delegation. Tracked as a dedicated refactor-only
change.

---

## 8. `cmd/kacho-iam/serve.go` `runServe` is a single ~780-line composition root (accepted)

**Convention** (Clean-Architecture composition-root rule): `cmd/<svc>/main.go` is
the single legitimate wiring place; but a function this long cannot be unit-covered
and forces a reviewer to hold the whole boot sequence in working memory.

**Why accepted (not split here)**: `runServe` is genuinely the composition root —
sequential wiring of pools, ops-repo, listeners, interceptor chains, hook servers
and graceful shutdown, with no branching business logic. Extracting sub-builders
(`buildListeners` / `buildInterceptorChain` / `buildHookServers` / `wireShutdown`)
is a pure readability reorganisation with no runtime, wire, or security impact, and
— like §5/§6 — carries reorder/early-return-cleanup risk in the boot path that is
better absorbed by a focused, independently-reviewed change than by a hardening
pass. No behavioural benefit; deferred as a dedicated refactor.

**Convergence path (deferred)**: extract cohesive sub-builders returning wired
components + cleanup funcs and have `runServe` call them in sequence.

_Reviewed 2026-07-05 (r5 security-hardening audit)._

---

## 9. OpenFGA peer-client port interfaces live in the `internal/clients` adapter package, imported by the use-cases (deferred reorg)

**Convention** (architecture.md dependency rule): a use-case **defines** the
narrow port-interface it needs (`<Peer>Client`), and the concrete adapter in
`internal/clients` **implements** it — the adapter depends on the use-case, never
the reverse. `cluster/ports.go` and `service/governance_ports.go` follow this
(ports declared in the consumer, adapters named only in doc-comments).

**Divergence**: the OpenFGA peer-client ports `RelationStore` / `RelationQueries`
(and the plain `RelationTuple` value type) are declared **inside** the adapter
package `internal/clients` (`openfga_client.go`, `openfga_extensions.go`). ~64
use-case files under `internal/apps/kacho/api/*` import `internal/clients` purely
to name their port type (`clients.RelationStore` / `clients.RelationQueries` /
`clients.RelationTuple`), so the use-case layer compile-time-couples to the
adapter package rather than owning its own port.

**Why (deferred, not fixed here)**: the value types the ports speak
(`ConditionalTuple` / `TupleConditionRef` and the FGA query result structs) were
**already** extracted to the neutral leaf package `internal/authztypes` in a prior
pass precisely for this dependency-rule reason; `internal/clients` re-exports them
as aliases. The remaining coupling is the two *interfaces* (a single shared peer
port used identically by ~64 use-cases, not a per-use-case narrow port). Relocating
them is a mechanical import-rewrite across ~64 of the most security-sensitive files
in the tree with **zero** runtime, wire, or security impact — exactly the kind of
high-churn reorg that §5/§6/§8 defer out of a hardening pass so refactor noise never
masks a security-relevant diff. The interface is a shared port, so the leakage is
bounded: no adapter-only concrete type (pgx, net/http, SDK) crosses into the
use-case build graph — the aliased value types already live in the leaf package —
so the practical "heavy dependency pulled into every use-case build/test graph"
failure the rule guards against is not realised today; only the *package-name*
coupling remains.

**Convergence path (deferred)**: move the `RelationStore` / `RelationQueries`
interface declarations (and `RelationTuple`) into `internal/authztypes` (the
existing neutral home for their value types), keep `clients.RelationStore =
authztypes.RelationStore` aliases for the adapter's ergonomics, and repoint the ~64
use-case imports at the leaf package. Tracked as a dedicated refactor-only change,
reviewed in isolation.

_Reviewed 2026-07-06 (r7b security-hardening audit)._

---

## 10. `ConditionsService` CRUD lives as one cohesive service, not slice-per-RPC use-cases

**Convention** (architecture.md + evgeniy/godzila regime): each CRUD resource is
implemented as slice-per-RPC `UseCase` structs under
`internal/apps/kacho/api/<resource>/` (e.g. `CreateAccountUseCase`,
`UpdateAccountUseCase`), with a thin handler as the composition target. The seven
core IAM resources (account/project/user/group/role/access_binding/
service_account) all follow this.

**Divergence**: the standalone Condition resource (`cnd_…`,
`internal/service/conditions_crud_service.go`) is implemented as a single
`ConditionsCRUDService` type that bundles every RPC (Get/List/Create/Update/
Delete/Evaluate), the folder-authz helpers, the CEL-evaluation glue, the
outbox/audit wiring, and the `doCreate`/`doUpdate`/`doDelete` Operation-worker
bodies. Its handler (`internal/apps/kacho/api/conditions/handler.go`) is a
pass-through with its own inline required-field validation and a package-local
`mapErr`, rather than a thin composition of per-RPC slices.

**Why (by design, not a defect)**: Condition is not a tenant-owned CRUD aggregate
like the seven core resources — it is an **authz-engine artefact** whose whole
lifecycle is one tightly-coupled unit: a Create/Update/Delete is only meaningful
together with CEL expression recognition (shared process-lifetime
`ConditionsEvaluator` LRU), the reference-count gate against
`access_bindings.condition_ref`, the tombstone→hard-delete Operation worker, and
the audit-atomic worker-tx (ban #10). These do not decompose into independent
per-RPC slices without threading the same evaluator + txb + audit ports through
each — the cohesion is real, mirroring the *other* `internal/service` engine
services (`authorize`, `internal_authorize`, `internal_iam`) that the regime
already treats as legitimately single-responsibility. The shape carries **zero**
proto/REST/DB contract difference; it is purely an internal code-organisation
choice on the least tenant-facing resource in the domain.

**Safety**: no runtime, wire, or security consequence — the service is exercised
by the same unit + integration + newman coverage as the sibling resources, and
the authz-critical CEL/refcount/audit paths are unchanged by the layout. The only
cost is code-organisation asymmetry (a contributor copying the account slice
pattern gets a different shape for Conditions).

**Convergence path (deferred)**: if/when a per-RPC split buys real isolation
(e.g. Conditions grows independent mutable fields with divergent CAS logic),
split `ConditionsCRUDService` into `create.go/update.go/delete.go/get.go/list.go/
evaluate.go` slices under `internal/apps/kacho/api/conditions/`, move required-
field validation into the domain constructor, and drop the package-local `mapErr`
in favour of the shared helper. Undertaken as a dedicated refactor-only change so
the diff over the authz-critical path is reviewed in isolation — not folded into a
hardening pass where refactor churn could mask a security-relevant change.

_Reviewed 2026-07-06 (r8b security-hardening audit)._

---

## 11. Scope-filter visible-set fetch is client-unbounded (`ListObjects` limit 0)

**Convention** (defense-in-depth against resource exhaustion, CWE-770): a request
should not materialise an unbounded backend result set into memory.

**Divergence**: every scope-filtered `List` (account/project/user/service_account/
group/role and the access_binding helpers) calls
`relationQueries.ListObjects(ctx, subject, relation, <type>, nil, 0)` — `0` =
no client-side cap — for both the `viewer` and `v_list` relations, then
post-filters the DB page against the resulting in-memory id set
(`internal/apps/kacho/api/account/list.go` and siblings).

**Why (by design, not a defect)**: the fetch is bounded where the data lives —
OpenFGA enforces a **server-side** `listObjectsMaxResults` (default 1000) and
`listObjectsDeadline` on `/list-objects`, so a single call returns at most that
many objects regardless of how broad the grant is; two relations bound the
per-request set to ~2× that. A **client-side** cap here would be actively wrong:
the visible-set is intersected with the DB page to decide tenant visibility, so
truncating it to N would silently drop authorised resources whose ids fall past
the first N returned — a `List` that omits resources the caller is entitled to
see (a listauthz **completeness** regression, and a worse failure than the memory
concern for this low-severity item). Failing *closed* on a large set is equally
unacceptable: a legitimately broad principal (an account-wide viewer service
account) would have its `List` return `Unavailable`. Correct visibility therefore
requires the full viewer∪v_list set, and its size bound is the authz backend's
responsibility (server-side max-results/deadline), not a client truncation.

**Safety**: the practical memory exposure is bounded by the OpenFGA server limits
above (a deployment concern, tunable at the FGA layer), and the port already
supports a `maxResults` argument for any future call-site that can tolerate
truncation — the scope-filter call-sites deliberately pass `0` because they
cannot. Both relation calls fail closed to `Unavailable` on any FGA error/timeout,
so an over-large or slow response degrades to a denied request, never to an
unfiltered/owner-only fallback.

**Convergence path (deferred)**: if per-request memory must be bounded on the
IAM side independent of the FGA backend, replace fetch-all-then-filter with a
DB-page-then-batch-`Check` strategy (Check each id on the page instead of
listing the whole visible set) — a request-path redesign of the scope filter,
not a one-line cap. Tracked as a scalability item; no correctness or security
gap exists today given the server-side FGA bounds.

_Reviewed 2026-07-06 (r8b security-hardening audit)._
