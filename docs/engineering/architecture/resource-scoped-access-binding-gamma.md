# Resource-scoped AccessBinding — label selector, containment, expiry (by-design)

By-design notes for the label selector, target-containment, and expiry of
resource-scoped AccessBinding. Builds on the per-object targets
(`resource-scoped-access-binding-alpha.md`) and the resource mirror
(`resource-mirror-source-version.md`).

> [!warning] Состояние на 2026-08-11: описанный здесь механизм СНЯТ миграцией 0030
> Заголовок обещает «by-design notes … записывают решения реализации kacho-iam», то есть
> настоящее время. По дереву это уже не так, и перепись по четырём осям это показывает:
>
> - **таблицы**: `access_binding_targets` (заводилась миграцией 0018) и
>   `access_binding_selector` (0022) **дропнуты** миграцией
>   `0030_drop_legacy_target_selector.sql`. Осталась только
>   `access_binding_target_members` — её миграция 0030 сохраняет явно, и владеет ею
>   реконсайлер правил роли, а не привязка;
> - **контракт**: имена `selector` и `target_ref` в `AccessBinding` стоят в `reserved`;
>   теги 16 и 18 — надгробия и никогда не переиспользуются как номера;
> - **RPC**: `AddTargetResources` / `RemoveTargetResources` в `access_binding_service.proto`
>   **нет**; из всей поверхности выбора объектов у сервиса не осталось ни одного метода
>   с этим предметом;
> - **место решения**: «какой объект» решает теперь **роль** (`role.rules[]`, ветви
>   `ARM_NAMES` / `ARM_LABELS`, материализуемые реконсайлером), а не привязка.
>
> Что от предмета **живо и в другой форме**: пообъектная адресация вернулась как
> `AccessTarget target = 22` (миграция `0055_access_binding_target.sql`) с **двумя** ветвями —
> `resources` и `all_in_scope`. Ветви по меткам среди них нет.
>
> Записка **сохранена как обоснование**, а не как описание кода: разбор трёх независимых
> гейтов, довод про цикл `iam→compute` и правило «эмиссия и вставка в одной транзакции»
> пережили свой механизм и применяются к нынешней форме. Имена функций и RPC внутри
> читать как имена **снятого** механизма: в дереве их нет.


## What this adds

1. **`target.selector`** — a label-based grant. `selector{types, matchLabels}`
   resolves to a DYNAMIC set of objects — a new matching object auto-joins the
   grant, a de-matched one auto-leaves.
2. **Containment** — an object must lie UNDER the binding's scope-anchor. Resolved
   SAME-DB from `resource_mirror.parent_*` (the mirror filled it) — **no
   `iam→compute/vpc` peer-call, the graph stays acyclic**.
3. **Expiry eager-revoke** — a TTL-elapsed binding has its per-object FGA tuples
   eager-revoked + `status→REVOKED` by the reconciler (not lazy Check-time).

## Design

### Storage (migrations 0020/0021/0022)
- `access_binding_selector` (0022) — the selector POLICY (`types text[]`,
  `match_labels jsonb`) — one row per binding (PK binding_id, FK CASCADE). The
  target arm is discriminated by storage: selector row ⇒ selector; rows in
  `access_binding_targets` ⇒ resources[]; neither ⇒ all_in_scope.
- `access_binding_target_members` (0020) — the MATERIALIZED membership: one row per
  (binding, object) with `verification_status` (ACTIVE | PENDING_VERIFICATION |
  REJECTED). PK (binding,type,id) ⇒ idempotent UPSERT, serializes concurrent
  reconcile on the row-lock.
- `resource_reconcile_outbox` (0021) — the event queue: RegisterResource enqueues
  a "this object changed" event atomically with the mirror UPSERT/DELETE.

### Reconciler — `internal/apps/kacho/api/access_binding/reconcile`
A use-case (ports `ReconcileStore`/`TxRunner`; pg adapter in `repo/kacho/pg/
reconcile_adapter.go`). One reconcile pass = ONE writer-tx: membership
UPSERT/DELETE + per-object `fga_outbox` emit/eager-revoke + containment audit +
event mark-sent all commit-or-rollback together (ban #10). Triggers:
- **(a)** Create / ReplaceTargetSelector → `ReconcileBinding` (post-commit, sync,
  so membership is observable when the Operation reports done).
- **(b)** mirror change → `ReconcileObject` (drained from the outbox by the
  in-process worker, `seed/reconcile_worker.go`).
- **(c)** periodic sweep (every 30s) — re-reconcile every selector binding +
  expire TTL-elapsed bindings (defense-in-depth against a lost event / restart).

### Containment predicate (single for byName + byLabel)
`MirrorObject.IsContainedIn(scope)`: `project:P ⊑ project:P`; `project:P ⊑
account:A` iff `mirror.parent_account_id==A` (backfilled); any ⊑ cluster. In
mirror + under scope → ACTIVE + tuple; in mirror + NOT under scope → REJECTED +
audit (not silent); NOT in mirror → PENDING_VERIFICATION, verified when the
mirror row lands. REJECTED is **re-verifiable**: a `mirror.parent` change
re-evaluates it both directions.

### parent_account_id backfill
RegisterResource resolves `projects.account_id` SAME-DB (IAM owns Project) when
the owner supplied only `parent_project_id`, so account-scoped selector grants
can compute containment. No peer-call.

### match_tags → match_labels
The proto carries `match_labels` (field 3); the legacy `match_tags` (field 2) is
deprecated. The use-case + storage read `match_labels` (resource labels, not the
governance "tags").

### byName tuples — non-regression
byName (`resources[]`) Create keeps the per-object tuple emission unchanged
(forward-only); the reconciler additionally materializes the `verification_status`
projection and handles the eventual PENDING→ACTIVE/REJECTED transitions. The FGA
drainer is idempotent, so a steady-state ACTIVE member's reconcile-emit is a
harmless duplicate of the Create tuple. The **byName sync containment gate**
rejects an in-mirror-foreign ref on Create (FAILED_PRECONDITION) — that part is
new (it closes the earlier containment gap).

### Selector tuples — reconciler-owned
A selector binding emits NO per-object tuple at Create — only the scope→binding
hierarchy parent-pointer (parity with resources[]). The reconciler
emits/eager-revokes per-object membership tuples as the matched set changes.

### Selectable types
Selector is activated only for `compute.instance` (the only type with a mirror
feed, via `compute→iam RegisterResource`). A selector over a non-fed type (e.g.
`vpc.subnet`) is rejected sync `INVALID_ARGUMENT` ("not selectable yet") to avoid
a member that is PENDING forever.

## Future work
Expiry is wired (eager-revoke + scan). `ReplaceTargetSelector` (CAS) and
re-verify-on-Check are not yet exposed; the storage + reconciler already support
a selector replace (`InsertSelector ON CONFLICT`), so the RPC is additive when
added.

## Acyclicity (non-negotiable)
This introduces **no** `iam→compute/vpc` edge. Containment is resolved from the
same-DB `resource_mirror` (the mirror is fed push-style over the existing
`compute→iam` edge). The graph stays acyclic.
