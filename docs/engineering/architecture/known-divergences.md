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
silently skipped. The model-drift gate (`internal/authzmap/fga_model_drift_test.go`)
proves the emitter/catalog match the canonical `fga_model.fga` DSL.

> Здесь назывался вторым доказательством харнесс, гонявший эмиссию кортежей против
> НАСТОЯЩЕГО внешнего движка. Движка нет, и харнесса в дереве нет вместе с ним;
> координата не воспроизводится, чтобы её не пошли искать. Свойство, которое он
> доказывал — «эмитируется то, что модель принимает», — теперь держится по построению:
> отношения выводятся из той же модели, а не пишутся в отдельное хранилище, способное
> их отвергнуть.

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

**Resolution**: the canonical model lives in-repo at
`proto/kacho/cloud/iam/v1/fga_model.fga`. It is the single source, and the absence of
the model is a hard failure with no environment opt-out.

> [!note] Обновлено на стадии S6: копия модели переехала вместе со своим потребителем
> До S6 второй копией модели был ConfigMap задачи подготовки хранилища внешнего движка;
> её порождала цель сборки, а идентичность обеих копий держал отдельный тест. Ни движка,
> ни его задачи подготовки, ни её чарта в дереве нет — вместе с ними снята и цель, и тот
> тест. Мёртвые имена здесь не воспроизводятся координатами: цитата несуществующей цели
> читается как исполнимая команда.
>
> **Второй экземпляр модели остался, и он другой** — вшитая копия
> `services/iam/internal/authzmodel/fga_model.fga`, из которой реляционная форма
> компилирует план вывода. Её равенство канонической держит
> `TestEmbeddedModelIsByteIdenticalToCanonical` (`services/iam/internal/authzmodel/identity_test.go`),
> и правится **только** канонический файл; копия порождается
> `make -C deploy fga-model-embed`.
>
> Довод у гейта тот же, что и был, и он усилился: разойдясь, две копии дадут не отказ, а
> **разные решения о доступе** — заметное по чужому доступу, а не по красному прогону.

Гейт по-прежнему работает в обе стороны: тип в применяемой модели, о котором не знает ни
один каталог, либо несущий `v_*` вне грантуемого каталога, роняет сборку.

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

Приёмка снятия — `services/iam/docs/engineering/acceptance/retire-tenant-condition-surface.md`.

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

## 9. Relation-store port interfaces live in the `internal/clients` adapter package, imported by the use-cases (deferred reorg)

**Convention** (architecture.md dependency rule): a use-case **defines** the
narrow port-interface it needs (`<Peer>Client`), and the concrete adapter in
`internal/clients` **implements** it — the adapter depends on the use-case, never
the reverse. `cluster/ports.go` and `service/governance_ports.go` follow this
(ports declared in the consumer, adapters named only in doc-comments).

**Divergence**: the relation ports `RelationStore` / `RelationQueries` (and the
plain `RelationTuple` value type) are declared **inside** the adapter package
`internal/clients`. **43** use-case files under `internal/apps/kacho/api/*`
(re-measured 2026-08-20; the earlier figure was ~64) import `internal/clients` purely
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
`services/iam/docs/engineering/acceptance/retire-tenant-condition-surface.md`.

---
## 11. iam's own pages ask the relation store in batches; the RPC it publishes for siblings still does not

> **Rewritten 2026-08-02. The heading and the number both changed.**
> Until this revision the record read "A visibility-filtered page costs one
> relation question per row (up to 2000)" and named the batched question as the
> open convergence path. That path has landed for iam's own read surfaces: a
> contract-sized page now costs **40 requests** to the relation store instead of
> **2000**, asking about the same 2000 tuples. What remains open is the OTHER
> half — the `BatchCheck` RPC iam publishes to sibling services, which still
> resolves its items one at a time. The number below is that half.

**Convention**: a request's cost must be bounded by what the request asks for, and
`page_size` is part of the contract up to 1000 (`pkg/validate`); narrowing a page
to fit a budget is forbidden.

### Converged: iam's own nine `List` RPCs

`authzfilter.VisibleSet` partitions a page into groups of
`MaxBatchChecksPerRequest` and asks the store one relation question per group, the
groups issued concurrently (`BatchParallelism`). The predicate is unchanged —
`viewer` for the page, then `v_list` only for what `viewer` denied — so the same
tuples are resolved; only the message count falls.

| | requests per max page | depth |
|---|---|---|
| before | 2000 | 125 waves |
| after | 40 | ≤ 6 waves |

Measured on the deployed stand (`openfga/openfga:v1.14.0`, in-cluster, idle
store, trivially-denying tuples): a single check answers in **3.0 ms** mean over
50 sequential calls; a batch of 50 answers in **19 ms** (three repeats: 19.9 /
17.8 / 19.3 ms) — **0.38 ms per check amortised**, and 50× fewer round-trips.
Time figures describe that stand and that tuple set; the request count does not.

> [!note] До стадии S6 размер партии диктовал ПОТОЛОК ЧУЖОГО ХРАНИЛИЩА — его больше нет
> Здесь стоял разбор: iam публикует `AuthorizeService.BatchCheck` с пределом 100, а
> хранилище за ним отвергало запрос длиннее **50**, поэтому деление страницы по
> опубликованному числу делало бы каждую партию отказом. Хранилища нет; предел, о
> который разбивали страницу, исчез вместе с ним, и внешнего числа, которому обязан
> подчиняться внутренний путь, не осталось. Опубликованные 100 остаются контрактом для
> вызывающих.
>
> Замеры времени в этом разделе (`openfga/openfga:v1.14.0`, 3.0 мс на проверку, 19 мс на
> партию из 50) описывали тот стенд и то хранилище и сегодня **не перемеряемы**: предмета
> замера нет. Число запросов — свойство алгоритма и остаётся верным.

The three conditions the earlier record said must not be traded away are held and
each has a test: the budget belongs to the **request** (partitions are issued
concurrently, not one after another —
`TestVisibleSet_BatchesRunConcurrently`); `page_size` is **not narrowed**
(`TestVisibleSet_PageSizeIsNotNarrowedToFitTheBudget`); the filter stays
**fail-closed** (any partition's error fails the whole page, and a refusing batch
door is never papered over by falling back to per-object questions —
`TestVisibleSet_BatchErrorFailsTheWholePage`).

Affected surfaces — **nine** `List` RPCs over **seven** object types, all through
the one implementation: `account`, `project`, `iam_user`, `iam_service_account`,
`iam_group`, `iam_role`, and `iam_access_binding` (whose helper serves `List`,
`ListByAccount`, `ListByScope`).

### Open, with a number: `AuthorizeService.BatchCheck` resolves items one at a time

`AuthorizeService.BatchCheck` is a sequential `for` loop over the single-`Check`
implementation. Nothing is shared across a pass except the cluster-administrator
verdict, and nothing runs concurrently. So a batch of the contract-maximum 100
costs **100 sequential relation-store round-trips**.

This is not internal: `services/{vpc,compute,nlb,storage}/internal/authzfilter`
each split their pages into batches of 100 and send up to 20 of them per
contract-sized page. Each batch becomes 100 sequential round-trips at the iam
boundary, so a sibling's max page still costs **up to 2000 relation-store
round-trips** — the number this record used to be about, now living one hop away.
Four services are on that path.

Converging it means routing the loop through the same batched question
(the batched relation question), which exists and is wired. It is not a mechanical substitution: the per-item path also runs the
super-access cascade and a structural fallback with contextual tuples on the deny
side, so the shape is "batch the common first question, then take the slow path
only for the items it denied". That is a request-path change to an authorization
surface and wants its own acceptance.

### Also open, with numbers: two per-row list paths

Both are declared, self-expiringly, in `declaredPerRowQuestions`
(`internal/authzfilter/pagecost_gate_test.go`):

- `access_binding/list_by_role.go: requireGrantAuthority` — a per-row scope filter
  over a list page: up to **two** relation questions per binding (a
  cluster-administrator question that is subject-scoped and therefore constant
  across the page, plus a per-scope `admin` question), i.e. up to **2000** per
  contract-sized page, plus per-row DB reads for hierarchy scopes.
- `authorize/handler.go: authorizeCaller` — per-item caller authority inside
  `BatchCheck`, bounded by that RPC's contract at **100** per call.

Both are batchable in principle — one relation over many heterogeneous objects is
exactly the shape the new client method takes — and neither was converged here.

**Guards**: the per-object ceiling is still asserted as a count by
`TestVisibleSet_WorstCasePageCost` (it describes the fallback path);
the batched ceiling and the tuple count by
`TestVisibleSet_BatchedWorstCasePageCost`; the in-flight bounds by
`TestVisibleSet_MaxPageBoundedFanOut` and `TestVisibleSet_BatchesRunConcurrently`.
Two structural gates keep those numbers meaningful:
`TestRelationQuestionsStayInsideTheMeasuredPath` refuses a per-row relation
question written anywhere in the use-case tree outside the one implementation, and
`TestVisibilityCallSitesAllHoldABatchCapableChecker` censuses the eight call sites
and refuses one holding a checker whose declared type cannot answer in batches —
which would take the fallback silently, returning correct rows at the old cost.
Both report how much they read, so "no findings" is distinguishable from "nothing
was read".

_Rewritten 2026-08-02 (the batched question landed for iam's own pages; the
published RPC and two per-row list paths remain, each with a number)._

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

---

## 13. `AccessBindingService.List` — two answers changed when the page became a page of the visible

**Convention** (project-wide, `api-conventions.md`): a list answers `200` with a
page; a caller who may see nothing gets an empty page, never an error. Existence
is never disclosed by an error code.

**Divergence**: two inputs that used to produce an empty `200` from this one RPC
now produce `UNAVAILABLE`.

1. **The relation port is not wired** (`queries == nil`). Previously the
   use-case answered an empty page — "no visibility is resolvable, so nothing is
   visible". It now refuses.
2. **The cluster-admin question fails in transport.** Previously the answer was
   folded into "not a cluster administrator" and the request continued down the
   per-object path. It now refuses.

A **nil** cluster-admin port is deliberately NOT in this list and keeps its old
meaning: an unwired super-gate does not fire, and the per-object path runs.

**Why (by design, not a defect)**: the convention above is about a caller who may
see nothing. Neither case is that caller. Both are the service saying "I could
not establish what you may see", and answering that with an empty page makes a
misconfigured or degraded deployment indistinguishable, to every tenant, from a
correctly locked-down one — the tenant reads "you have no grants" and has no way
to learn otherwise. The second case is the quieter of the two: it narrows the
page rather than emptying it, so the caller cannot tell it from a revocation.

This is not a new rule invented for this RPC. It is the rule the other six iam
list surfaces already followed; this one was the last still answering the old
way, and the divergence is recorded because the CHANGE is observable, not because
the destination is unusual.

**Safety**: no widening — nothing becomes visible that was not visible before.
Both changes turn a success into a refusal, which is the fail-closed direction.
`UNAVAILABLE` maps to HTTP 503 (`api-conventions.md` §gRPC→HTTP), which is
retryable, so a client that polls recovers on its own once the deployment is
fixed; an empty page gave it nothing to retry.

**Regression**: `services/iam/internal/apps/kacho/api/listvisibility`,
`TestList645_23b_AnUnwiredRelationPortRefusesRatherThanReportingNothing` and
`TestList645_16b_SubjectQuestionFailureIsUnavailableNotANarrowedPage` — both run
all seven surfaces against real Postgres and a real relation store, and both
carry a paired positive control in the same run (wired port → the object is
there; live store → the administrator sees it), so "it refuses" cannot be
satisfied by a build that refuses everything.

**Convergence**: none sought. The previous behaviour is the one this entry exists
to keep from being restored by someone reading the convention alone.

_Reviewed 2026-08-18 (task #645, list page is a page of the visible)._

---

## 14. СНЯТО — двери, писавшие кортёж мимо журнала, закрыты (стадия S6)

**Что было расхождением.** Два места писали кортёж во внешний движок отношений напрямую,
не кладя строку журнала `kacho_iam.fga_outbox`: административный глагол записи кортежей
внутреннего листенера и `InternalIAMService.WriteCreatorTuple`. Поставленный так кортёж
**не попадал в проекцию `relation_fact` никогда**: движок отвечал «да», своя БД — «нет»,
и такое расхождение разбирают в правах, а не в наполнении.

**Чем закрыто — предметом, а не починкой каждой двери:**

| дверь | исход | предикат |
|---|---|---|
| административная запись кортежей внутреннего листенера | **снята вместе с листенером**: ни RPC, ни его реализации в дереве нет | `grep -rn '\.WriteRaw(' --include='*.go' .` → **0** |
| `InternalIAMService.WriteCreatorTuple` | **снята с контракта**: вызывающих было ноль — все пять соседей давно ушли на `RegisterResource`, который кладёт строку журнала | `grep -rn '\.WriteCreatorTuple(' --include='*.go' .` → **0** |

Второй исход стоит отметить отдельно, потому что здесь сошлись две линии работы и обе
были правы. Линия снятия движка **перевела** эту дверь на журнал — предмет RPC никуда не
делся, изменилось то, **куда** он пишет. Линия ролевой модели независимо **пересчитала её
вызывающих** и нашла ноль: все пять соседей давно ушли на `RegisterResource`. Из двух
верных ходов побеждает второй — перевод двери, которую никто не открывает, даёт работу без
выгодоприобретателя, а сама дверь остаётся мёртвой поверхностью (ban #11, LEAN). Поэтому в
дереве осталось **снятие**, а свойство, ради которого делался перевод, живёт у
`RegisterResource`: у вызывающего «записал» означает «закоммичено», а не «поставлено в
очередь», потому что строка журнала и прямой факт ложатся одной транзакцией.

Имена обеих снятых дверей держит надгробие `retiredRPCSurface` в `internal/repohygiene` —
оно читает контракт, стабы и обе копии каталога прав, поэтому вернуть RPC под тем же именем
молча нельзя.

**Инвариант миграции `0098_relation_fact_follows_the_journal.sql` обеспечен по построению.**
Он объявлял, что состояние отношений есть свёртка ОДНОГО журнала. Пока существовало второе
хранилище, инвариант держался перечнем исключений и гейтом над ним; теперь второго
хранилища нет, писать «мимо журнала» **некуда**, и расхождение невыразимо.

> [!note] Гейт и перепись, державшие это расхождение, сняты вместе с предметом
> Прежняя редакция называла тестовый гейт мест записи в движок и скрипт переписи «движок
> против журнала» на стенде, а также приводила замер (в движке и не в журнале — 2, обратно
> — 0) и открытую задачу на снятие обоих RPC. Ни гейта, ни скрипта в дереве нет: их предмет
> — сравнение двух хранилищ — исчез. Координаты здесь не воспроизводятся, иначе читатель
> пойдёт прогонять то, чего нет.
>
> Оставшиеся два кортежа, ставившиеся посевом чарта, вопросом больше не являются: посев
> пишет туда же, куда все.

---

## 15. Снятие сессии входа у провайдера НЕ гасит уже выданный токен — измерено, не выведено

**Свойство, о котором идёт речь, принадлежит ПРОВАЙДЕРУ.** В нашем дереве оно не
выражено ничем, поэтому его нельзя ни вывести чтением кода, ни «вспомнить»: его
можно только спросить. Запись заведена, потому что от ответа зависит, чем
обеспечен наш выход из системы.

**Вопрос.** Наш выход (`gateway` `POST /oauth/logout`) и `ForceLogout` делают у
провайдера ровно одно действие — `DELETE /admin/oauth2/auth/sessions/login?subject=…`.
Делает ли оно уже выданный **токен доступа** неактивным в интроспекции?

**ОТВЕТ: НЕТ.** Измерено пробой на **той же версии**, что стоит на стенде
(`oryd/hydra:v26.2.0`), с контролями в обе стороны:

| шаг | наблюдение |
|---|---|
| контроль К1 (положительный) — свежий токен | `active=true` |
| **снятие сессии входа** | провайдер ответил **204** |
| **интроспекция того же токена после снятия** | **`active=true`** |
| следствие — обновление после снятия сессии | **чеканит НОВЫЙ токен** |
| контроль К2 (отрицательный) — штатный отзыв `POST /oauth2/revoke` | `active=false` |
| контроль К3 (отрицательный) — заведомо мусорный токен | `active=false` |

Прогнать заново, в том числе на новой версии провайдера:

```sh
IMG=oryd/hydra:<версия> bash services/iam/scripts/provider-revocation-equivalence-probe.sh
```

Проба поднимает **свой** провайдер (память вместо базы, локальные порты) и не
читает ни одной строки общего стенда. Коды возврата: `0` — не эквивалентны,
`1` — эквивалентны, `2` — **проба не выполнена** (провайдер не поднялся, токен не
выдан, контроль не сработал). Третий исход отдельный намеренно: он не вычитается
из вердикта и не зачитывается ни в одну сторону.

**Почему ответ именно такой — совпадает со схемой провайдера.** Поток ссылается на
сессию входа как `ON DELETE SET NULL`, а токен на поток — как `ON DELETE CASCADE`:
снятие сессии обнуляет ссылку, строка потока переживает снятие, а вместе с ней
переживает и токен. Схема — согласующее наблюдение, но **не** основание записи:
обработчик мог бы делать что-то сверх схемы, и именно поэтому здесь стоит проба, а
не рассуждение.

**Что из этого следует для контракта.** Запись `session_revocations` (пер-jti) —
единственное, что вообще могло бы погасить конкретный выданный токен; читателя на
пути запроса у неё нет (#797). Значит выход с `revoke_all=false` — форма без
содержания: строка пишется, никто её не читает, а сопровождающее действие у
провайдера токен не гасит. Предъявленный токен живёт до истечения, а обновление
продолжает чеканить новые.

**Отсечка субъекта — ДРУГАЯ запись, и с 2026-08-23 она читается на предъявлении
браузерной сессии (#1122).** `user_token_revocations.revoke_before` — то, что
пишут выход с `revoke_all=true` и `ForceLogout`. Её читали только хуки выдачи,
поэтому на полосе, где человек живёт в консоли, наш отзыв не действовал вовсе:
администратор получал успех, а человек продолжал работать. Теперь край
спрашивает её на каждом обращении по паре (субъект, момент аутентификации
сессии) — `InternalSessionRevocationsService.SessionCutoffOf`, — и на отвергнутой
сессии САМ заканчивает носителя. Обратимость отказа перестала зависеть от чужого
административного API: следующее обращение приходит без сессии, консоль уводит на
вход, момент аутентификации сдвигается за отсечку.

**Что этим НЕ закрыто, названо прямо.** Токен, выданный полосой кода
авторизации, эта мера не гасит — он гасится своим авторитетом отзыва
(интроспекция на крае для чужой чеканки, наш авторитет для своей). И снятие
сессии входа у провайдера здесь по-прежнему делается: полоса церемонии жива, и
пока она жива, обратимость отказа НА НЕЙ обеспечивает именно этот вызов. Обе
записи ведомости поверхностей остаются со своим предикатом снятия.

**Чем сходиться — и почему вариантов ТРИ, а не два.** #797 называл два исхода
(«эквивалентны» / «не эквивалентны ⇒ ввести читателя на путь запроса»). Проба
открыла третий, и он дешевле обоих: **звать штатный отзыв провайдера**
(`POST /oauth2/revoke`) с предъявленным токеном. Контроль К2 показал, что он гасит
токен, а отдельная проба — что он гасит и обновление (`invalid_grant`). Тогда
энфорсмент достаётся уже работающим путём — интроспекцией на краю (окно ≤5 с), —
и **новой зависимости на пути запроса не заводится вовсе**. Открытые вопросы этого
варианта, которые обязан решить его автор: отзыв требует **сам токен**, а не `jti`
(значит место вызова — край, где токен есть), и его соотношение с правилом
«iam — единый фасад к Hydra» (`security.md`) надо назвать явно, а не подразумевать.

## Быстрый путь отзыва `session_revoked` снят вместе со своим триггером (#755)

**Что было.** Триггер на `kacho_iam.session_revocations` слал уведомление в канал
`session_revoked` на каждую вставку. Производитель работал; слушателей было **ноль
с первого дня схемы**, и ноль — не «пока не написали», а по построению.

**Почему построить было нельзя.** Слушателем по замыслу назначался край. Драйвера
Postgres у края нет ни одного файла, и завести его значило бы читать чужую базу
напрямую — запрет 8, database-per-service. То есть быстрый путь **в этой форме**
неисполним, а не недоделан.

**Каким путём отзыв идёт вместо него.** Тем же, каким он шёл и раньше, и этот путь
сделан правильной формой:

| звено | чем является |
|---|---|
| очередь `subject_change_outbox` | намерение, записанное в той же транзакции, что мутация |
| её канал `kacho_iam_subject_outbox_added` | уведомление, **у которого слушатель есть** |
| дренаж iam → `InternalAuthzCacheService.InvalidateSubject` | вызов края по gRPC, без чужой базы |

**Что НЕ снято.** Таблица `session_revocations` остаётся: у неё живой писатель
(выход с края) и живые читатели (`IsRevoked`, `ListByUser`, `DeleteExpired`). Снято
ровно объявление уведомления.

**Чего эта запись не касается.** Проверка отзыва **предъявленного** токена идёт
интроспекцией у провайдера на каждом запросе и от снятого канала не зависела
никогда. Отдельный предмет — читатель пер-jti записи на пути запроса (#797), и он
разбирается выше в этом же документе.

**Урок, ради которого запись стоит здесь, а не только в миграции.** Механизм,
присутствующий и провязанный наполовину, неотличим со стороны от работающего:
«отозвано» и «не отозвано» выглядят одинаково, пока никто не спросит, есть ли у
канала слушатель. Снимать такое надо **вместе с объявлением** — иначе следующий
читатель увидит триггер, решит, что быстрый путь есть, и построит на нём вывод.

## 16. Сведение строк личности РАСШИРЯЕТ область объекта личности — окно объявлено, срок назван

**Состояние:** действует со стадии S2 перехода IAM-ID-1 (задача #472). Закрывается
стадией S3 линии #471.

**Предмет.** Цепь областей ведёт от личности к аккаунту через **членство**, и
состояние членства не читает (стадия S3, задача #944). Пока членство у человека
одно, у объекта личности ровно один аккаунт-предок. Сведение строк-дублей даёт
человеку **второе** членство — значит у объекта личности становится два предка, и
`iam_user.super_admin: admin from account` начинает выполняться администратором
обоих аккаунтов.

**Что это значит для арендатора, дословно.** Администратор второго аккаунта
получает над **живой** личностью человека те же глаголы (`v_get`/`v_list`/
`v_update`/`v_delete`), какие до сведения имел над её строкой-приглашением в своём
аккаунте. Разница не в перечне глаголов, а в предмете: строка-приглашение была
мертва — войти по ней было нельзя, — а живая личность та, которой человек входит
везде. Блокировка, поставленная вторым администратором, действует и в первом
аккаунте.

**Почему это не чинится сужением цепи.** Три поверхности дерева уже **требуют**,
чтобы у человека со вторым членством назывались оба аккаунта — это landed-решение
стадии S3, и сузить цепь здесь значило бы отменить его, а не закрыть окно.

**Почему это не закрыто тем же изменением — цена измерена.** Закрыть окно значит
завести тип `iam_membership` со своим полным набором глаголов и снять аккаунт-скоуп
с личности. Гейт дрейфа модели безусловен и двусторонен, поэтому тип без пары в
каталоге разрешений не заводится, а пара требует контракта и глаголов членства —
это отдельная стадия. Радиус по уже существующему аккаунт-скоупному типу
(`git grep -rl iam_group` по go/sql/fga/proto/yaml): **66** файлов, из них **36** не
тестов, в **20** каталогах — от общего пакета авторизации и края до посевных
миграций и наборов сквозных проб.

**Предикат снятия — механический:**

```sh
grep -c '^type iam_membership' proto/kacho/cloud/iam/v1/fga_model.fga   # сегодня 0
```

**Чем держится, что окно не шире объявленного.** Пробой
`TestIntegration_MergeWidensTheIdentityScopeExactlyAsDeclared`: она требует, чтобы
множество аккаунт-предков выжившей личности **равнялось** множеству её членств —
не шире (аккаунт, где человека нет, не появляется) и не у́же. Та же проба
**истекает сама**: её предпосылка — что типа `iam_membership` в модели ещё нет, и
появление типа роняет её с указанием переписать и снять эту запись. Описание дыры,
пережившее дыру, лжёт.

**Наблюдаемость на выкатке.** Миграция печатает число личностей, чья область
расширилась, отдельной величиной — «ноль» обязано быть отличимо от «не считали».

## 17. Состояние переехавшего членства выводится из ВЫЖИВШЕЙ строки — окно названо, срок измерен

**Состояние:** решение принято по задаче #1044. Записи-«отступления» здесь нет:
дерево ведёт себя верно, и запись существует затем, чтобы верность перестала
держаться совпадением.

**Решение — какое состояние верно.** Состояние переехавшего членства выводится из
**выжившей** строки («входил ли человек»), а не переносится со снимаемой:

| группа дублей | состояние переехавшего членства | почему |
|---|---|---|
| кто-то из строк входил | **`ACTIVE`** | выжившая строка — та, по которой входили; «приглашён» на ней ложно by construction |
| не входил никто | **`PENDING`** | приглашение никем не принято; перевод в «активно» объявил бы принятым то, чего не было |

**Почему не «взять состояние снимаемой».** Снимаемая строка — приглашение, по
которому не входили НИКОГДА (иначе она была бы активной и сводить было бы нечего).
Её состояние описывает её саму, а не человека; человека описывает выжившая.
Правило `PENDING → PENDING, иначе ACTIVE` уже трижды записано в дереве (зеркало
`470001`, его вторая половина `20260823053000`, оба пути записи строки в
`user_repo.go`) — четвёртое, своё, разошлось бы с ними молча.

**Почему не «перевести в активно всё».** Это не починка, а расширение: у группы, в
которой не входил никто, приглашение оказалось бы принятым за того, кто его не
принимал, и `ListAccountsForUser` назвал бы ему аккаунт, куда он не входил.
Приобретение доступа тише потери — потерю замечает пострадавший, приобретение не
замечает никто.

**ОКНО — измерено, а не выведено.** Миграция сведения `20260822234500` переносит
членство вместе с его состоянием, то есть на выходе ИЗ НЕЁ состояние неверное.
Догоняющая правка следующей миграции цепочки (`20260823053000`) его исправляет.
Замер на пустой базе, обе группы:

| группа | после `20260822234500` | после всей цепочки |
|---|---|---|
| вошедший + приглашённый | `accB = PENDING` | `accB = ACTIVE` |
| никто не входил | оба `PENDING` | оба `PENDING` |

Значит окно закрывается **внутри одного прогона мигратора**, и на поднятом стенде
его нет: применяется вся цепочка. Утверждение задачи «остаётся `PENDING`
НАВСЕГДА» верно ровно до следующей миграции и неверно после неё.

**Чем это держится — и почему запись понадобилась.** Верность держалась ничем:
соседние пробы сведения читают у членства ТОЛЬКО аккаунт
(`membershipAccountsOf`), поэтому состояние могло разъехаться молча. Два способа
это сделать, оба тихие: снять догоняющую правку (её `Down` возвращает зеркало без
второй половины) либо написать СЛЕДУЮЩУЮ миграцию сведения по образцу этой —
догоняющая правка одноразова и второй раз не выполнится.

Держат теперь три пробы
(`services/iam/internal/migrations/identity_merge_membership_state_integration_test.go`),
и каждая проверяет своё:

- `TestIntegration_MovedMembershipOfAPersonWhoLoggedInIsNotLeftPending` — у
  вошедшего не осталось «приглашённых» членств;
- `TestIntegration_MovedMembershipOfAPersonWhoNeverLoggedInStaysPending` —
  ЗАКОННЫЙ БЛИЗНЕЦ: у не входившего они остались. Без него первая проба зеленела
  бы на коде, переводящем в «активно» всё подряд;
- `TestIntegration_ThePendingMembershipPredicateCanSeeAViolation` — тот же
  предикат перед нарушением, внесённым в живые строки. Утверждение об ОТСУТСТВИИ
  зеленеет на предикате, не видящем ничего, поэтому его способность увидеть
  доказывается отдельно.

Способность упасть доказана возвратом дефекта: с цепочкой, остановленной на
`20260822234500`, первая проба краснеет и называет аккаунт, а близнец **молчит**.

**Кто читает состояние членства — перепись, а не память.**

```sh
git grep -nE "m\.state|memberships\.state|state[ ]*=[ ]*'(PENDING|ACTIVE)'" \
  -- 'services/**/*.go' ':!*_test.go'
```

Читатель в дереве **один**: `services/iam/internal/repo/kacho/pg/user_repo.go:273`
(`userReader.ListAccountsForUser`, отбор `m.state = 'ACTIVE' AND u.invite_status =
'ACTIVE'`), и до него доходит `WhoAmI`. Остальные попадания предиката — другая
таблица (`token_signing_keys`) и комментарии. **Его поведение не меняется**:
состояние сегодня верное, и проба это закрепляет.

Что было бы, останься членство «приглашённым», — названо, потому что это и есть
цена: аккаунт пропал бы из ответа «кто я» у самого человека, **при том что власть
администратора того аккаунта над его личностью сохраняется** (§16 выше). Цепь
областей состояние членства не читает — читает его только ответ арендатору,
поэтому расхождение было бы односторонним и в худшую сторону: невидимо для того,
кого касается.

**Отношение к §16.** Запись §16 опирается на то, что состояние членства не читает
**цепь областей**, и это по-прежнему верно (`944001`, ветвь 4a). Читатель выше —
не цепь, а ответ арендатору, поэтому размер объявленного там окна он не меняет.
