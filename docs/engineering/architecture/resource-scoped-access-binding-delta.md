# Resource-scoped AccessBinding — canonical contract form (by-design)

By-design notes for the canonical contract form of resource-scoped AccessBinding
(a clean-form, additive, non-breaking projection over the existing data). Builds
on the per-object targets (`resource-scoped-access-binding-alpha.md`) and the
label selector (`resource-scoped-access-binding-gamma.md`).

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


## What it adds (and explicitly does NOT)

This is a pure **form-projection** over the SAME data: NO new tables, NO
migration, NO domain change, NO behaviour change (FGA-emit / containment / expiry
/ reconciler / CAS are untouched). It cleans the contract FORM of two dimensions
to the canonical 2026 model `scope{tier,id}` + `target<all|byName|bySelector>`,
keeping the historical fields working through a two-way projection.

- **scope** — canonical nested `ScopeRef scope_ref = 17` ({tier, id}) added; the
  triple-redundant legacy `resource_type`/`resource_id`/enum `scope` is
  deprecated-in-favour-of it (comment, NOT `[deprecated=true]` — still populated
  on every response). The two forms are derived-equivalent via the existing
  `domain.Scope.ValidateAgainst` predicate (re-use, no new logic).
- **target** — canonical `AccessTargetRef target_ref = 18`
  (`all`/`by_name`/`by_selector`) added as a SEPARATE field aliasing the legacy
  `AccessTarget` arms (`all_in_scope`/`resources`/`selector`) 1:1. A separate
  field (not extra arms on the legacy oneof) so the two representations are
  wire-distinguishable and a disagreement is detectable.
- **condition** — out of scope here. UPDATE 2026-07-29: `condition_id` /
  `builtin_condition` have since been REMOVED from `CreateAccessBindingRequest`
  (tags 6/7 reserved) — nothing read them; `expires_at` is now honoured
  end-to-end (request → binding → expiry sweep).
- **subject** — NOT canonicalized here; flat `subject_type`/`subject_id` stay.

`buf breaking` stays GREEN (additive + deprecate, 0 deletions/renumber) — the
distinguishing point vs the earlier `match_tags→match_labels` rename (which was a
deliberate red). Physical removal of the deprecated fields is a future major bump.

## Design — two-way projection (handler/dto layer only)

The whole change lives in proto + the transport-adjacent layer. `domain` and
`repo` (the DB row, writer-tx, FGA emit) are NOT touched.

### Input normalization (`internal/apps/kacho/api/access_binding/delta_input.go`)
`Handler.Create` calls, FIRST (before any Operation):
- `normalizeScopeInput(resource_type, resource_id, scope_ref)` →
  single `(resource_type, resource_id)` pair the rest of the pipeline consumes.
- `normalizeTargetInput(target, target_ref)` → single validated
  `domain.AccessTarget` (parsed by the SAME existing `parseAccessTarget` validation).

Reconciliation contract:
- only legacy set → used as-is.
- only canonical set → derived to the legacy pair / parsed to the domain target.
- both set, derived-equivalent → OK (the new form is an echo of the old).
- both set, disagree → sync `INVALID_ARGUMENT` (reject, NOT silent-priority):
  - scope: `"scope conflicts with resource_type/resource_id"`.
  - target: `"target: new and deprecated arm disagree"`.
- canonical scope invalid standalone (tier unspecified / tier↔id mismatch) → sync
  `INVALID_ARGUMENT`, re-using `domain.Scope.ValidateAgainst`.

"New has priority" applies ONLY when the legacy form is absent — never as a
silent override of a present-and-conflicting legacy form.

### Output projection (`internal/dto/toproto/access_binding.go`)
`domain.AccessBinding → *iamv1.AccessBinding` fills BOTH representations of each
canonical dimension, derived-consistently from the single domain row:
- scope: `resource_type`+`resource_id`+enum `scope` AND `scope_ref{tier,id}`.
- target: legacy `target` arm AND `target_ref` arm.

A pre-existing binding (no canonical columns physically) reads identically: the
canonical form is derived read-time (NO backfill / migration). `condition` is
projected unchanged (out of scope here).

## Why these placements (clean-arch)
- Normalization is a transport concern (proto → domain), so it sits beside the
  existing `parseAccessTarget` in the use-case package, NOT in `domain` (which
  stays pure) and NOT in `repo` (the SQL/CAS path is byte-identical to the prior
  form).
- Output projection sits in `dto/toproto`, the single domain→proto mapper.
- No distributed-systems surface changes: this adds no data, no invariant, no
  cross-domain edge — only contract form.

## Future work
- A condition oneof-wrapper over the AccessBinding RESOURCE's
  `condition_id`(9)/`builtin_condition`(14)/`expires_at`(10). Note (2026-07-29):
  the Create REQUEST no longer carries condition fields at all, and its
  `expires_at` is honoured — such a wrapper would be introduced by whatever
  design actually implements conditions, not as a form over unread fields.
- A future major version may physically remove the deprecated scope/target fields
  (and condition); `buf breaking` would be deliberately red for that coordinated
  major.
