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

## 4. FGA authorization-model gates — RESOLVED (canonical DSL restored in-repo)

**Convention** (hard-rule #12): security-relevant tests must be green, not
silently skipped. The FGA model-drift gate (`internal/authzmap/fga_model_drift_test.go`)
and the real-OpenFGA tuple-emission proof (`internal/testsupport/fgatest`) prove the
emitter/catalog match the canonical `fga_model.fga` DSL.

**What was wrong**: both resolved the canonical DSL through a sibling `kacho-proto`
checkout or the pinned `kacho-proto` Go-module directory — neither of which exists
after the polyrepo→monorepo consolidation, and the `.fga` file itself was not
carried over. The DSL was therefore unresolvable **on every run**, so both gates
`t.Skip`-ed themselves while the package still reported `ok`. The only surviving
copy of the model was the DSL embedded in the openfga-bootstrap Helm ConfigMap,
which nothing compared against the Go tables. The drift this hid was real: five
compute object types (`compute_host_group`, `compute_gpu_cluster`,
`compute_placement_group`, `compute_reserved_instance_pool`, `compute_host_type`)
and one type with no service at all (`vpc_anycast_address_pool`) were declared
grantable and verb-bearing while the enforced model never declared them.

**Resolution**: the canonical model now lives in-repo at
`proto/kacho/cloud/iam/v1/fga_model.fga` (seeded byte-for-byte from the ConfigMap,
so the enforced model did not change when the file was restored). It is the single
source; the ConfigMap is GENERATED from it by `make openfga-model-json`, and
`internal/authzmap/fga_model_configmap_identity_test.go` pins both generated blocks
to it — the byte-identical DSL copy and, more importantly, the pre-transformed
`model.json` the bootstrap Job actually applies. Resolution is a plain walk-up to
the module root; **the absence of the model is now a hard failure, and there is no
environment opt-out** (`KACHO_IAM_REQUIRE_FGA_MODEL` is gone). The gate also runs
in the reverse direction: a type in the enforced model that no catalog knows about,
or one that carries `v_*` outside the grantable catalog, fails the build.

---

## 5. Fat authz service struct not yet split into per-RPC use-cases (deferred reorg)

**Convention** (evgeniy/godzila regime): one `UseCase` struct + one file per RPC
(as in `internal/apps/kacho/api/account`).

**Divergence**: `AuthorizeService` (`authorize_service.go`) carries the full authz
method set on a single struct, and some services keep their use-cases in one file
(`sa_keys/usecases.go`, `user_tokens/usecases.go`). These predate the per-RPC
regime the rest of the codebase follows.

`ConditionsCRUDService` was the third example and is no longer one: the
tenant-facing condition surface was retired, so that half of this record has no
subject left and has been struck rather than carried forward.

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

## 7. СНЯТО — расхождение по проекции условий (предмета больше нет)

Запись описывала, как ресурс условия проецировался в ответ и валидировался в
транспортном обработчике мимо общего реестра. Тенантская поверхность условного
доступа снята целиком — сервис, хранилище, наложение на привязку, — поэтому
описываемого кода не существует.

Номер сохранён намеренно: на него ссылаются снаружи, а перенумерация превратила бы
чужие ссылки в указатели на другое расхождение. Запись, которой больше нечего
описывать, — находка, а не наследство: она вычеркнута, а не оставлена «на всякий
случай».

Приёмка снятия — `services/iam/docs/acceptance/retire-tenant-condition-surface.md`.

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

## 10. СНЯТО — расхождение по компоновке сервиса условий (предмета больше нет)

Запись обосновывала, почему CRUD условий жил одним связным сервисом, а не срезами
по RPC. Сервиса нет: тенантская поверхность условного доступа снята.

Номер сохранён по той же причине, что и у §7. Приёмка снятия —
`services/iam/docs/acceptance/retire-tenant-condition-surface.md`.

---

## 11. A visibility-filtered page costs one relation question per row (up to 2000)

> **This record previously described the opposite shape and has been rewritten.**
> Until 2026-07-31 it documented, as current behaviour, a scope filter that
> enumerated the whole visible set (`ListObjects` with no client-side cap) and
> post-filtered the page against it, and it named the page-then-`Check` shape as a
> *deferred* convergence path. The enumeration was removed when that convergence
> was implemented: the surfaces below read a page from their own database and ask
> about the ids on that page. What the record called the deferred goal is the
> shipped code; what it called current behaviour no longer exists. The **batch**
> part of that goal, however, was never implemented — and that is the open item
> restated below, with its number.

**Convention**: a request's cost must be bounded by what the request asks for, and
`page_size` is part of the contract up to 1000 (`pkg/validate`); narrowing a page
to fit a budget is forbidden.

**Divergence**: visibility is resolved with one **direct relation question per
(object, relation)**, and the questions are individual HTTP round-trips to the
relation store. `authzfilter.Relations` is `{viewer, v_list}` and `v_list` is asked
only for the objects `viewer` denied, so a page costs between `page_size` and
`2 × page_size` round-trips. At the contract ceiling that is **2000 round-trips for
one `List`**. `authzfilter.DefaultParallelism = 16` bounds how many are in flight,
which makes the page **125 sequential waves** — it bounds depth, not count.

Affected surfaces — **nine** `List` RPCs over **seven** object types, all through
the one implementation (`authzfilter.VisibleSet`):
`account`, `project`, `iam_user`, `iam_service_account`, `iam_group`, `iam_role`,
and `iam_access_binding` (whose helper serves `List`, `ListByAccount`,
`ListByScope`).

**Why the shape is nonetheless right**: the alternative it replaced was worse and
was a correctness defect, not a cost one. Enumerating "every object of this type
the subject may see" is bounded SERVER-side by OpenFGA (`listObjectsMaxResults`,
default 1000) with no continuation token, and that bound applies to the type across
the whole store rather than to the tenant — so on a long-lived store a tenant's own
resource fell outside the returned prefix and became **permanently invisible** while
its row, its grant and its mutations all worked. Asking for a larger `max_results`
could not widen the answer, because that argument only trims an already-cut
response. Cost that scales with the page is the price of an answer that is correct
at any store size; see the package doc of `internal/authzfilter` for the full
argument.

**Open item (a cost, with a number)**: the count is reducible and has not been
reduced. OpenFGA exposes a batched check endpoint that iam does not use anywhere —
`services/iam/internal/clients` has no batch-check call — even though iam itself
*publishes* a batched `AuthorizeService.BatchCheck` (bounded at 100 per the
contract the sibling services split their pages against), and resolves it with a
plain per-item loop. So vpc / compute / nlb / storage each batch their pages into
≤100-id requests, and every one of those batches becomes one-question-per-id again
at the iam boundary. Converging this is a request-path change with its own
acceptance, and it is bounded by three conditions that must not be traded away:
the time budget belongs to the **request** (batches must not run one after another,
or a legitimate `page_size=1000` returns `UNAVAILABLE` on the *positive* path);
`page_size` must not be narrowed to fit; and the filter stays **fail-closed** (an
error resolving any part of a page fails the whole page — a partially-resolved set
is never returned). Whether the deployed OpenFGA build serves that endpoint is
**unverified**: `deploy/helm/umbrella/Chart.yaml` requests the openfga chart as a
floating patch range, and a chart version does not determine the binary version in
any case — so the endpoint is a hypothesis until it is read off the image, not a
plan. (The same file's neighbouring dependency carries a comment about a floating
range resolving differently on different days; this one is still floating.)

**Guards**: the ceiling is asserted as a count (not as seconds, which would measure
the test machine) by `TestVisibleSet_WorstCasePageCost`; the in-flight bound by
`TestVisibleSet_MaxPageBoundedFanOut`; and `TestRelationQuestionsStayInsideTheMeasuredPath`
keeps the number meaningful by refusing a per-row relation question written
anywhere in the use-case tree outside that one implementation — a tenth surface
asking its own questions would otherwise be measured by nothing. That gate reports
how many files it read and how many looped questions it cleared as legitimate
relation cascades, so "no findings" is distinguishable from "nothing was read".

_Rewritten 2026-07-31 (the shape it described had been replaced; the batch item is
the part that remains open)._

---

## 12. Refusal `ErrorInfo.domain` is `kacho.cloud.iam.v1`, not the `<service>.kacho.cloud` form

**Convention** (`api-conventions.md`, error-format): a machine-readable refusal
carries `google.rpc.ErrorInfo` whose `domain` is written `"<service>.kacho.cloud"`.

**Divergence**: `internal/authzguard/deny_details.go` stamps
`domain = "kacho.cloud.iam.v1"` — the value the api-gateway authz middleware has
been putting on the wire since it began emitting `AUTHZ_DENIED` / `AUTHN_REQUIRED`.

**Why (by design, not a defect)**: the two layers refuse the SAME class of request
on the same band. The gateway answers when it runs the per-RPC check; iam answers
when the row is scope-filtered and the decision is made here over the data. A
client keying on `(reason, domain)` must not have to know which of them said no —
if the two stamped different domains, that pair would stop identifying "an authz
refusal from the platform" and start identifying "which component happened to
handle it", which is not a distinction any caller can act on. Matching the
incumbent producer is therefore the only choice that keeps the token usable;
changing the gateway to the documented form is an edge-owned, cross-service wire
change (every consumer already keying on the current value), out of scope for a
service-side fix.

**Converging** would mean changing the value in `gateway/internal/middleware/
permission_denied_response.go` and here in one step, with the newman assertions
that read `details[]` updated together — and only after establishing that no
external consumer pins the current domain.

_Reviewed 2026-07-29 (contract-residue pass)._
