# kaname#922 — перепись порядка захвата строк выдачи, модуля и ресурса

Запись изменения задачи kaname#922: перепись писателей, берущих в одной транзакции
строки `access_bindings` (G — выдача), `catalog_module` (M — модуль) и
`catalog_resource` (R — ресурс); порядок и режим замка у каждого; пары, чьи
множества строк пересекаются; инверсии порядка и их снятие.

## Перепись — команда, ревизия, объём

Ревизия переписи — `78d5d65a2` (голова `origin/942` до правки). Места захвата —
четырьмя командами из корня клона kaname; каждое место прочитано и отнесено к
писателю вручную (таблица ниже).

```sh
# 1. явные строчные замки на G/M/R (SQL многострочный — признак ищется в 8 строках до замка)
git grep -n -B8 -E 'FOR (UPDATE|NO KEY UPDATE|SHARE|KEY SHARE)' 78d5d65a2 -- 'internal/**/*.go' ':!*_test.go' \
  | grep -cE 'FROM (kaname\.)?(access_bindings|catalog_module|catalog_resource)\b'          # → 9
# 2. запись строк G (UPDATE/DELETE берут строку FOR NO KEY UPDATE / FOR UPDATE)
git grep -nE '(UPDATE|DELETE FROM) (kaname\.)?access_bindings\b' 78d5d65a2 \
  -- 'internal/**/*.go' ':!*_test.go' ':!internal/migrations/**' | wc -l                        # → 7
# 3. вставки в проекции роли — ключ на R (`role_verb_type_fk`, `role_rule_ref_res_fk`) берёт FOR KEY SHARE
git grep -nE 'INSERT INTO kaname\.(role_verb|role_rule_ref)\b' 78d5d65a2 -- 'internal/**/*.go' ':!*_test.go' | wc -l  # → 2
# 4. advisory-замки (из 9 совпадений ключом выдачи — 3: reconcile_adapter.go:441, :473, tx.go:270)
git grep -nE 'pg_advisory_xact_lock\(hashtext' 78d5d65a2 -- 'internal/repo/**/*.go' ':!*_test.go' | wc -l         # → 9
```

Объём осмотренного: мест захвата на G/M/R — **21** (9 + 7 + 2 + 3 advisory-ключом
выдачи); писателей — **16**; пар с пересечением строк — **73** (каталог 28, выдача
45). Судятся порядком **42** пары с конфликтующими режимами; **30** совместимы
режимами, **1** (W1×W1) сериализована замком каталога — ждать в них нечего
(обоснование ниже). Инверсий — **2** (кандидат третьей опровергнут исполнением — ниже).

## Писатели

Режимы: `FU` — `FOR UPDATE`, `NKU` — `FOR NO KEY UPDATE`, `KS` — `FOR KEY SHARE`.
`adv(G)` — `pg_advisory_xact_lock(hashtext(<id выдачи>))`.

| # | писатель | координата (ревизия 78d5d65a2) | порядок захвата · режим |
|---|---|---|---|
| W1 | применитель каталога | `modulecatalog/apply.go:218`, `pg/catalog_writer.go:178`, `:228` | adv(каталог) → M (NKU, шаг 2р) → M (FU, 2а) → R модуля (FU, `ORDER BY dotted`, одним оператором) → V, проекции арендаторских ролей |
| W2 | применитель ролей модуля | `moduleroles/apply.go:341`, `pg/role_repo.go:981`, `:1019` | M своего модуля (KS) → роли (ключ на M, KS) → R ключом `role_rule_ref` (KS) в порядке ролей и сегментов — только своего модуля, то есть под уже взятой M |
| W3 | создание роли арендатора | `api/role/create.go:203`, `pg/role_repo.go:1112`, `:954`, `:1019` | строка роли (вставка) → R селекторов (KS, `ORDER BY dotted`) → R ключом `role_verb`, R+V ключом `role_rule_ref` (подмножества уже взятого) |
| W4 | правка роли арендатора | `api/role/update.go:313` | строка роли (NKU) → как W3 |
| W5 | досев проекции сегментов системных ролей | `seed/role_rule_ref_reseed.go:173`, `pg/role_repo.go:1019` | на роль транзакция: R+V ключом `role_rule_ref` (KS) **в порядке сегментов** |
| W6 | досев проекции глаголов | `seed/role_verb_reseed.go:199`, `pg/role_repo.go:954` | строка роли (FOR SHARE) → R ключом `role_verb` (KS) **в порядке пар** |
| W7 | создание выдачи | `api/access_binding/create.go:370`, `pg/access_binding_repo.go:1316` | R типов пообъектной цели (KS, `ORDER BY dotted`, первым оператором) → новая G (вставка) → строка роли (FOR SHARE, триггер) |
| W8 | отзыв выдачи | `api/access_binding/revoke.go:177`, `pg/access_binding_repo.go:189` | adv(G) → G (FU) → G UPDATE |
| W9 | удаление выдачи | `api/access_binding/delete.go:254` | adv(G) → G (FU) → G DELETE |
| W10 | истечение срока | `reconcile/reconcile.go` `ExpireBinding` | adv(G) → G (FU) → G (NKU) → G UPDATE |
| W11 | снос области (проект, аккаунт) | `shared/revoke_scope_bindings.go:111` | по выдачам в порядке id: adv(Gi) → Gi (FU) → Gi DELETE |
| W12 | полный проход сверки | `reconcile/reconcile.go` `ReconcileBinding`, `pg/reconcile_adapter.go:440` | adv(G) → G (NKU) |
| W13 | проход сверки по объекту | `reconcile/reconcile.go` `ReconcileObject`, `pg/reconcile_adapter.go:459` | adv(G1…Gn по id) → G1…Gn (NKU) в том же порядке |
| W14 | аддитивный форвард по объекту | `pg/reconcile_adapter.go:167` | G1…Gn (KS, `ORDER BY id`, одним оператором) |
| W15 | аддитивный форвард по выдаче | `pg/access_binding_repo.go:156` | G (KS) |
| W16 | правка выдачи (метки, защита) | `api/access_binding/update.go:239` | G UPDATE (NKU) |

Сверка (W12, W13) с kaname#937 читает строки каталога без замка
(`LiveCatalogTypes`) — в перепись захвата не входит.

Не писатель: `abWriter.TransitionStatus` (`UPDATE access_bindings`) — производственных
вызывающих ноль (`git grep -n '\.TransitionStatus(' -- 'internal/**/*.go' ':!*_test.go'` → 0).

## Пары

### Каталог (M, R)

Конфликтующий режим на M/R берёт только W1. Пара W1×W1 сериализована
advisory-замком каталога (`CatalogLockKey`) — в перепись пар не входит. Пары между
W2…W7 (15 пар и 6 пар «сам с собой») совместимы: KS × KS ждать не может.

| пара | инверсия | проба |
|---|---|---|
| W1×W2 | нет — M первым замком у обеих (kaname#913) | `catalog_applier_module_role_lock_order_integration_test.go` (2 пробы × 20) |
| W1×W2 (ресурсы чужого модуля) | кандидат опровергнут: правило роли модуля чужой модуль назвать не может — загрузчик `manifest.ErrRoleRuleForeignModule`, домен `ModuleSetOf(<свой модуль>)`; проба-кандидат отказала «Illegal argument module (unknown module 'probefar')» до записи | — |
| W1×W3 | нет | `TestCatalogLockOrderCensus_ApplierAgainstTenantRoleCreate` (20) |
| W1×W4 | нет | `TestCatalogLockOrderCensus_ApplierAgainstTenantRoleUpdate` (20) |
| W1×W5 | **да** — I1 | `TestCatalogProjectionWriterRuleRefsTakesCatalogRowsInTheApplierOrder` (20) |
| W1×W6 | **да** — I2 | `TestCatalogProjectionWriterRoleVerbsTakesCatalogRowsInTheApplierOrder` (20) |
| W1×W7 | нет | `TestCatalogLockOrderCensus_ApplierAgainstBindingTargetTypes` (20) |

### Выдача (G)

W7 пишет НОВУЮ строку — до фиксации её не видит никто, пересечения нет. W8…W16 —
девять писателей, 45 пар (с парами «сам с собой»): 36 конфликтуют режимами, 9
совместимы (W14, W15 с W12, W13, W16 и между собой: KS совместим с KS и NKU). W11 ×
W11 судится на ОДНОЙ области (два сноса одного проекта).

Инверсий нет: все писатели с advisory берут его ДО строки той же выдачи; писатели
нескольких выдач (W11, W13, W14) идут в порядке id; W16 держит одну строку и
ничего больше не ждёт. Каждая из 36 пар — подтестом
`TestGrantLockOrderCensusPairsDoNotDeadlock/<a>×<b>` (20 ходов, общий старт под
держателем, счётчик базы `pg_stat_database.deadlocks`). Имена писателей пробы:
revoke — W8, delete — W9, expiry — W10, scope — W11 (`RevokeBindingsInScope` в
транзакции записи — тот захват, что у сноса проекта и аккаунта), full — W12,
object — W13, objectForward — W14, bindingForward — W15, update — W16. Счётчик —
прибор пробы, и у него свой положительный контроль:
`TestDeadlockCounterSeesADeadlock` (ABBA на двух строках — ровно одна отметка).

| пара (по писателям пробы) | инверсия |
|---|---|
| revoke, delete, expiry, scope — попарно и сами с собой (10) | нет |
| {revoke, delete, expiry, scope} × {full, object, update} (12) | нет |
| {revoke, delete, expiry, scope} × {objectForward, bindingForward} (8) | нет |
| full, object, update — попарно и сами с собой (6) | нет |

## Инверсии и снятие

| | писатель | порядок до правки | против W1 | правка |
|---|---|---|---|---|
| I1 | W5 `ReplaceRuleRefs` | R ключом вставки, в порядке сегментов | W1: M → R по `dotted` | замок вперёд: R сегментов `KS`, `ORDER BY dotted`, одним оператором (`lockCatalogResourceRows`) |
| I2 | W6 `ReplaceRoleVerbs` | R ключом вставки, в порядке пар | то же | то же — по типам пар |

Строки `catalog_verb` отдельного замка не требуют: W1 трогает их только после всех
R своего модуля, а писатель проекции держит R своего сегмента раньше вставки.

## Чего перепись не судит

Цикл трёх писателей через строку роли (W1, W4, W7): W7 держит R (KS) и ждёт
строку роли (FOR SHARE), W4 держит строку роли и ждёт R (KS) за W1, W1 держит
другой R (FU) и ждёт R, взятый W7. Попарно инверсии нет; цикл возможен, когда
набор типов цели W7 не содержит раннего ресурса, который называет W4. Записано
находкой в kaname#922.
