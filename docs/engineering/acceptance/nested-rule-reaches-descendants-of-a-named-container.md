<!--
Copyright (c) PRO-Robotech
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Приёмка: вложенное правило роли манифеста достаёт до потомков названного контейнера

- **Статус:** DRAFT — вердикта нет; санкции на код нет (ban #1). Слово в этой строке —
  статическая форма: действующее одобрение выводится из записи ревью, привязанной к
  отпечатку редакции, и внешнего события, а не из шапки (`change-graph.md` §3)
- **Статическая форма:** DRAFT
- **История review:** (только дописывается строкой «дата · круг · вердикт · SHA-256
  редакции · путь записи»)
  - 2026-10-17 · круг 1 · CHANGES_REQUESTED · `492428179d619f7a0accaf2a8d2d99d0cec0ae532654ed9d76a75df82d127062` ·
    `docs/specs/reviews/nested-rule-reaches-descendants-of-a-named-container/492428179d619f7a0accaf2a8d2d99d0cec0ae532654ed9d76a75df82d127062.yaml`
  - 2026-10-17 · правка ПОСЛЕ вердикта `49242817…` · редакция 2: закрыты B1–B4 и M1–M7
    записи круга 1; B1 — решением диспетчера (б). Вердикт `49242817…` относится к
    редакции 1 и на эту редакцию не переносится. Что закрыто — раздел «Редакция 2: что
    закрыто»
  - 2026-10-17 · круг 2 · APPROVED · `f12395ae242f85e1120346123286318b3027d87e53f6973f4b8a21ac1bd6d9f6` ·
    `docs/specs/reviews/nested-rule-reaches-descendants-of-a-named-container/f12395ae242f85e1120346123286318b3027d87e53f6973f4b8a21ac1bd6d9f6.yaml`
  - 2026-10-24 · правка ПОСЛЕ вердикта `f12395ae…` · редакция 3: решение `kaname#965` —
    манифест модуля не называет конкретных объектов, загрузчик отвергает `resourceNames`
    у правила-владельца с `children` и во вложенном правиле, пустой перечень тоже. Тронуты
    только места об этой форме: «Вне объёма» п. 2, таблица ролей П1, описание П3, ND-04
    (новый пункт (з)), ND-05 (б), ND-08 «И», таблица производителей, DoD. Вердикт
    `f12395ae…` относится к редакции 2 и на эту редакцию не переносится
- **Дата:** 2026-10-17, правка 2026-10-24 · **редакция:** 3
- **Задача:** `PRO-Robotech/kaname#874` (связь: `#857` — сужение по цели, `#856` — публичное
  чтение контейнера)
- **Решения диспетчера 2026-10-17** (действует последнее): охват потомков объявляет
  **роль**, вложенными правилами `children`, и только в ролях **манифеста модуля**;
  классам субъектов — три условия, материализация через `public_reader`; объём — самый
  короткий путь. Флаг на элементе цели и поле `under` у правила отменены
- **Ревизии замера:** kaname `422d1bc6f` (ствол), kacho `a95248464` (ствол). Каждое число о
  дереве ниже — предикатом на этих ревизиях

## Обзор

После `#857` выдача с целью `target.resources: [реестр X]` даёт права только на сам X:
решение о доступе и материализатор сравнивают пару «тип, id» точно. Это записано в шапке
`internal/repo/kaname/pg/relverdict/grantarm.go` (строка 45, «Сравнение ТОЧНОЕ…») и в
`domain.AccessTarget.Contains` (`internal/domain/access_binding_target.go:94`). Требование
`#857` называло «названные объекты и их объявленных потомков», а закрыта была точная часть.

Изменение вводит в роли манифеста модуля **вложенное правило**. Правило над
типом-контейнером несёт перечень `children` — правила над типами, лежащими под ним.
Вложенное правило действует на объекты своего типа, у которых в цепи предков
(`parent_chain`) есть контейнер, выбранный выдачей: названный элементом цели либо, при цели
«вся область», любой контейнер области (решение B1 = (б)). Это касается и объектов,
созданных позже, на любой глубине. Правило верхнего уровня сравнивает точно, как сейчас.
Системным классам вложенное правило даёт потомков только через `public_reader`
объявленного контейнера.

## Вне объёма

1. **Пользовательские роли** (`RoleService.Create`/`Update` с `children` на входе) —
   следующая фаза, своей приёмкой. В этой фазе вход отвергается с именем поля, а не
   игнорируется (Р4, ND-04 (ж)).
2. **Сужение вложенного правила для человека** (`resourceNames`, `matchLabels` у самого
   вложенного правила) — входом не строится на сегодняшних типах (замер Р2). Семантика
   пересечения — следующей фазой. Охват на `allInScope` и пустой цели и сужение
   правила-владельца в объём **входят** (решение диспетчера B1 = (б), Р3, ND-08, ND-11).
   В манифесте модуля сужение **именами** (`resourceNames`) не допускается ни у
   правила-владельца, ни у вложенного правила (`kaname#965`, ND-04 (з)): правило
   манифеста сужается метками. Семантика Р3 для строки роли с именами у
   правила-владельца утверждается на уровне решения (П3, ND-08 «И»).
3. **Край, консоль, newman kacho**: пересборка края с пином kaname, показ `children` в
   консоли, сквозные кейсы — задача kacho (Р6). Манифест registry с ролями в форме
   `children` — задача `PRO-Robotech/kacho#3274`.
4. **Контейнер чужого модуля** — вложенное правило берёт модуль правила-владельца; таких
   указателей в каноне нет (Р2).

## Опора: одобренные соседи

| сосед (путь · отпечаток) | что закреплено | стык |
|---|---|---|
| `anonymous-and-authenticated-are-subject-classes.md` · `198db838d0a75b7f5b5bdbd5564bacec23a79cc00550a26e8830f3c6be61aac9` (ред. 10, APPROVED) | S5: `public_reader`, ворота SC-21, SC-24, SC-65; роль `registry.public.read`; SC-68 | **правится редакциями 11–12** (Р5): форма роли, абзац «Сужение по цели», держатели SC-68. Исходы SC-60…73 не меняются: SC-68 Б2 (`allInScope`) верен по Р3 (B1 = (б)) |
| проба `#857` — `internal/repo/kaname/pg/relverdict/target_narrows_grant_integration_test.go` | цель `resources` сужает выдачу до пар «тип, id» во всех формах вопроса | правило верхнего уровня сохраняет это дословно (ND-01, ND-07) |
| `module-manifest-roles-and-seed-grants.md` · `89c6cf6c007d3751146d3bb4f88588b1820bda2ae90eb0e0fc3666719c73c51d` (правка `kaname#965` после вердикта круга 6) | раздел `roles` манифеста, правило изоморфно `domain.Rule` | у правила роли манифеста появляется ключ `children` (Р1) |

## Решения

**Р1. Форма — `children` у правила роли манифеста.**

```yaml
roles:
  - id: registry.reader
    rules:
      - module: registry
        resources: [registries]
        classes: [get, list]
        children:               # права на объекты под реестром, названным в цели
          - resources: [repositories]
            classes: [get, list]
```

Судья формы манифеста (`manifest.Load`, `internal/manifest/roles.go`) принимает `children`,
только если:

1. правило-владелец называет **ровно один** ресурс, и это не `*`;
2. ресурс правила-владельца — **не ярус иерархии** (`account`, `project`): под ярусом
   выбирает область выдачи;
3. тип каждого вложенного правила — **потомок** типа правила-владельца по объявленным
   `parents` ресурсов того же манифеста, на любой глубине. Сам себе тип потомком не является;
4. вложенное правило **не несёт** `module` (берёт модуль правила-владельца) и своих
   `children`. Глубину выражает тип, а не структура роли;
5. ключ `children` либо отсутствует, либо непуст: `children: []` — второй способ сказать
   «вложенных нет».

Схема `schema/module-manifest.schema.json` получает ключ `children` тем же изменением:
сейчас правило закрыто для неизвестных ключей (`additionalProperties: false`). Поэтому
kaname без этого изменения манифест с `children` отвергает на загрузке.

**Р2. Что такое контейнер — по объявленному родству, измерено.** Родство объявляет
манифест ключом `parents` у ресурса (тип `Parent`, `internal/manifest/resources.go`). В
задаче стоял ключ `parent`, а ключ манифеста называется `parents`. Цепь предков объекта
шлёт владелец полем `parent_chain` регистрации. `kaname.resource_parent_edge` хранит
каждого предка цепи с глубиной (`upsertParentEdges`,
`internal/repo/kaname/pg/resource_mirror/emitter.go:354`; вставка ребра — строка 381),
поэтому проверка «контейнер
среди предков» — одно чтение рёбер объекта по ключу при любой глубине.

Канон модели @`422d1bc6f`, двумя предикатами:

- по написанию — `git grep -c 'define parent:' 422d1bc6f -- proto/kaname/cloud/iam/v1/fga_model.fga` → 1;
- по предмету — указатели на один тип, кроме ярусов и субъектов:
  `git show 422d1bc6f:proto/kaname/cloud/iam/v1/fga_model.fga | awk '/^type /{t=$2} /^    define [a-z_]+: \[[a-z_]+\]$/{n++; if ($0 !~ /\[(project|account|cluster|user|service_account|system_class)\]/) {m++; print t" "$2" "$3}} END{print "всего "n", остаток "m}'`
  → `registry_repository parent: [registry_registry]`, `всего 36, остаток 1`.

Единственный контейнер вне ярусов — `registry.registries`, ребёнок — `registry.repositories`,
внуков в каноне нет. Поэтому глубина утверждается на фикстуре трёх уровней (ND-08).
Сужение вложенного правила над репозиториями входом не строится:

- форма имени в `resourceNames` — `^[a-zA-Z0-9_-]+$`
  (`git grep -n 'ruleNameRe *=' 422d1bc6f -- internal/domain/rule.go`, строка 62), а id
  репозитория несёт `/`;
- тип `registry.repositories` в набор типов с метками не входит:
  `git show 422d1bc6f:internal/domain/feed_registry.go | grep -c '^\s*"registry.repositories": {},'` → 0.

**Р3. Семантика.** Вложенное правило N под правилом-владельцем P в выдаче B охватывает объект
o типа N, когда выполнены оба условия:

1. среди предков o (цепь регистрации, любая глубина) есть контейнер c типа P;
2. c **выбран выдачей B для правила P**: c проходит ветвь P (якорь либо имена) и входит в
   цель B — назван элементом `target.resources` точной парой «тип, id», либо цель B — вся
   область (`allInScope`, `{}`, `{"resources":[]}`) и c лежит в области выдачи.

Решение диспетчера B1 = (б), слова владельца: выдача выбирает контейнеры («все» либо по
имени), `children` действует внутри выбранных. Отсюда:

- на `allInScope` и пустой цели вложенное правило охватывает потомков **всех** контейнеров
  области, которые проходит ветвь P (ND-11, ND-08 «И»). Классам `allInScope` закрыт
  (SC-24, SC-19 соседа), и им это не расширяет ничего;

- правило верхнего уровня, сам контейнер и выдачи без `children` сравнивают точно, как после
  `#857` (ND-01, ND-07);
- соседний контейнер Y, не названный целью, не даёт ничего ни сам, ни потомками (ND-02);
- будущие потомки охвачены: правило читается при каждом вопросе и при каждой регистрации
  объекта (ND-02);
- перенос объекта под другой контейнер переносит право, когда повторная регистрация несёт
  `source_version` **строго новее** хранимого: тогда строка зеркала применяется и рёбра
  объекта заменяются целиком (`upsertParentEdges` зовётся только у применённой строки,
  `emitter.go:301-310`; сравнение версий — `emitter.go:122`, `:148`). Регистрация без более
  новой версии не применяется (last-source-state-wins, комментарий поля `source_version` в
  `proto/kaname/cloud/iam/v1/internal_iam_service.proto`), и право остаётся на месте (ND-09);
- цель, называющая объект типа, который роль покрывает **только** вложенным правилом,
  отвергается существующими воротами покрытия цели («Gate 3»,
  `internal/apps/kaname/api/access_binding/structural_gates.go`): вложенное правило действует
  на потомков названного контейнера, а не на названный объект своего типа (ND-12).

**Одна семантика во всех формах решения и в материализаторе.** Ось вложенности живёт
**внутри** единственного дома предиката ветви выдач (`grantArmPredicate`, `grantarm.go`). Тот
стоит во всех формах вопроса: `Allowed`, `AllowedMany` (`AuthorizeService.Check`,
`BatchCheck`, `InternalIAMService.Check`), `Objects`, `Subjects`
(`AuthorizeService.ListSubjects`), `Sources` (`AuthorizeService.ExpandRelations`).
Материализатор (`matchSelectorObjects`, `filterMatchedToTarget`,
`internal/apps/kaname/api/access_binding/reconcile/reconcile.go`) применяет ту же
семантику, и материализованное множество совпадает с ответом решения (ND-02).

**Р4. Чтение роли не занижает права.** Роль манифеста читается через `RoleService.Get` и
`List`. Ответ, скрывающий вложенные правила, показывал бы администратору меньше, чем роль
даёт. Поэтому в этой фазе сообщение `Rule` контракта `RoleService`
(`proto/kaname/cloud/iam/v1/role.proto`) получает поле `repeated Rule children`, в JSON —
`children`. Чтение его заполняет, а `declaredSegments` и `ruleStates` учитывают вложенные
правила. На входе `Create` и `Update` непустое `children` — синхронный
`INVALID_ARGUMENT` с именем поля, а не молчаливый пропуск (ND-04 (ж)). Вход открывает
следующая фаза. Скомпилированные `permissions` (поле снято, `deprecated`) вложенных правил
не несут — так же, как правил по меткам: строка `registry.repositories.*.get` обещала бы
чтение всех репозиториев области.

**Р5. Системные классы — только через `public_reader`, три условия.** Выдача классу
`anonymous` или `authenticated` роли с `children` допускается, только если каждое вложенное
правило:

1. стоит под типом, объявленным контейнером публичного чтения (`publicReadToChildren:
   true`), и называет его **прямого** ребёнка: ребёнок читает форму
   `public_reader from <указатель>`, и до внука она не доходит;
2. даёт **ровно** `get` и `list`. Оба нужны, потому что `public_reader` открывает ребёнку
   оба глагола сразу (`publicReadVerbsOfChild`, `internal/domain/public_read.go:50`). С одним
   `get` класс получил бы `list`, которого роль не называет. Пишущий глагол отвергают ворота
   SC-21 соседа, и они читают вложенные правила;
3. не сужено: нет `resourceNames` и `matchLabels`.

Не выполнено хоть одно условие — синхронный отказ воротами класса с текстом, называющим
условие (ND-05). Выполнены все — разворачивание выдачи пишет `public_reader` на названном
контейнере, как в S5 соседа (ND-03). **Ветвь выдач `relverdict` и материализатор
вложенное правило к выдаче классу не применяют.** Иначе у класса была бы вторая дорога к
потомкам, и снятие объявления `publicReadToChildren` (проба соседа
`TestPublicContainerRead_DeclarationWithdrawnRemovesPublicReader`) не снимало бы чтение
(ND-10).

**Роль `registry.public.read` — в форму `children`:** правило над `registries`
`[get, list]` с вложенным над `repositories` `[get, list]`. **Периода совместимости нет**
(рекомендация):

- роль не доставлена ни одним стволом: в `PRO-Robotech/kacho:services/registry/manifest.yaml`
  @`a95248464` строк `publicReadToChildren` и `registry.public.read` — 0 (`git grep -c`);
  `kacho#3274` открыта. Роль живёт только в фикстуре kaname
  `internal/manifest/testdata/registry.public-read-fixture.yaml`, и она переписывается
  этим изменением;
- прежняя форма, доставленная по ошибке, проигрывает **в сторону отказа**: класс читает
  только реестр (ND-07 (б)). Лишнего доступа она не даёт.

Порядок выкатки — Р10 соседа: сначала kaname, затем kacho. **Сосед получает редакции 11–12**
тем же изменением: Р9 п. 4 и П6 (форма роли); абзац «Сужение по цели» — `public_reader`
пишется по вложенному правилу, и человек достаёт до потомка X только вложенным правилом;
близнец SC-73 и «И (механизм общий)» SC-65. Абзац «Сужение по цели» до редакции 11
приписывал человеку поведение, которого ствол не производит. Шаблон держателя SC-68
`^Test(Ask|Batch)_SC68_` функций не имеет:
`git grep -c 'func Test\(Ask\|Batch\)_SC68_' 422d1bc6f -- internal` → пусто. Редакция 12
соседа называет держателей так же, как этот документ: часть А и Б0 — пробы `^TestTarget_`
(8 функций, `git grep -n '^func TestTarget_' 422d1bc6f -- internal/repo/kaname/pg/relverdict/`),
Б1 — ND-02, Б2 — ND-11.

**Р6. Цена и расширение поверхности.** Человек, учётка и группа получают права на
**будущие** объекты под названным контейнером — шире точной цели и уже `allInScope`. Это
объявляет роль, и это видно по её структуре (ban18-q-security). Для классов поверхность не
расширяется: условия Р5 — условия S5 соседа, вторая дорога закрыта. Узнаваемость
(ban18-q-market-recognition): права на ресурс вместе с вложенными в него ресурсами —
общепринятое свойство управления доступом. Наше отличие: вложенность видна в структуре
роли, проверяется по объявленному манифестом родству, и охват будущих потомков не требует
второй выдачи. Цена — одно чтение рёбер объекта по ключу на вложенное правило; стоимостные
пробы и отчёты R7 остаются в силе (DoD).

## Как строится «Дано»

- **П1** — мир П6 соседа (`newPCRWorld`,
  `internal/apps/kaname/api/access_binding/public_container_read_world_integration_test.go`):
  арендатор `acc-A`, проект `prj-A`, владелец `usr-A` (сессия уровня «2», предъявление
  1 минуту назад), кластерный администратор `usr-K`. В `prj-A` — реестры
  `reg00000000000000001` (X) и `reg00000000000000002` (Y); репозитории
  `reg00000000000000001/app` и `reg00000000000000001/moved` (в X),
  `reg00000000000000002/app` (в Y). Их регистрирует служба-владелец по
  `InternalIAMService.RegisterResource` (`registerRegistry`, `registerRepository`; цепь
  репозитория — `["registry_registry:<реестр>", "project:prj-A", "account:acc-A"]`).
  Люди `usr-D`, `usr-E` — члены `acc-A` без выдач. Манифест registry доставлен **новой**
  редакцией (`deliverNewEdition`); фикстура `registry.public-read-fixture.yaml`
  переписывается этим изменением и несёт роли:

  | роль · id (`domain.SystemRoleID`) | правила |
  |---|---|
  | `registry.public.read` · `rolb1325b011aa17211d` | `registries [get, list]`, `children: [repositories [get, list]]` |
  | `registry.reader` · `rolb812261cfaa239694` | то же, что `registry.public.read` |
  | `registry.viewer` · `rol2375080206e7e5e32` | `registries [get, list]`, без `children` |
  | `registry.reader_get` · `rolc36eeca826b9a8603` | как `registry.reader`, у вложенного `classes: [get]` |

  Роли `registry.reader_named` · `rolc8f851eb7a5da3d9f` (как `registry.reader`, у
  вложенного `resourceNames: [app]`) в фикстуре **нет**: манифест модуля конкретных
  объектов не называет, и загрузчик такую роль отвергает (`kaname#965`, ND-04 (з)). Для
  ND-05 (б) строку этой роли кладёт применитель манифеста **напрямую, минуя загрузчик**, —
  как строку, доставленную до запрета; контроль — строка роли с этим id в
  `kaname.roles` ровно одна.

  Id выведен формулой `'rol' || substr(md5(имя), 1, 17)` и сверен на известном
  `rolb1325b011aa17211d`. **Тело выдачи** «В(субъект, роль, цель)» —
  `{"subjects":[<субъект>],"roleId":"<роль>","scopeType":"iam.project","scopeId":"prj-A","target":<цель>}`
  от `usr-A`; цель `[X]` —
  `{"resources":{"resources":[{"type":"registry.registries","id":"reg00000000000000001"}]}}`,
  `[Y]` — то же с `reg00000000000000002`. «Вопрос `Check`» — `AuthorizeService.Check` от
  `usr-K`, как в S5 соседа. «Материализована» и «опрос доходит» — раз в 200 мс с пределом
  30 с (окно SC-13 соседа).
- **П2** — мир П1, построенный **кодом изменения**, но доставлена фикстура прежней формы:
  `registry.public.read` одним правилом `[registries, repositories]` (правило без
  `children` загрузчик принимает). Выдача В(`usr-D`, `rolb1325b011aa17211d`, `[X]`)
  материализована. «Перезапуск» — новые use-case поверх той же базы и повторная доставка
  того же манифеста, как `applyDelivered` соседа.
- **П3** — посев уровня решения, форма `tgSeedTopology`
  (`internal/repo/kaname/pg/relverdict/target_narrows_grant_integration_test.go`), с
  фикстурой манифеста `internal/manifest/testdata/probemod.children-fixture.yaml` —
  **заказана**. В ней `boxes` (`probemod_box`, `parents: [project]`,
  `publicReadToChildren: true`), `items` (указатель `box`), `tags` (указатель `item`); роль
  `probemod.reader`: `boxes [get, list]`, `children: [tags [get, list]]`. Роль-близнец
  `probemod.reader_b1` (то же, у правила над `boxes` ещё `resourceNames: [b1]`) в фикстуре
  манифеста **не объявляется** — манифест модуля конкретных объектов не называет
  (`kaname#965`); её строку пишет проба продуктовым писателем роли из правил домена, как и
  строку `probemod.reader` для ND-08. Объекты: ящики
  `b1`, `b2`; предмет `i1` в `b1`, `i3` в `b2`; ярлык `t1` в `i1` (цепь
  `["probemod_item:i1", "probemod_box:b1", "project:prj-A", "account:acc-A"]`), `t3` в `i3`.
  Выдача пишется строкой: вход API цель `probemod` не принимает, потому что
  `ValidTargetType` читает закрытый перечень `internal/domain/feed_registry.go`. Поэтому П3
  утверждает решение и материализатор, а не край.

## Сценарии

#### ND-01 — человек, `registry.viewer` на X: только X

**Дано** П1. **Когда** выдача В(`usr-D`, `rol2375080206e7e5e32`, `[X]`); опрос
`Operation` доходит до `done=true` без `error`; выдача материализована.
**Тогда** `Check` от `user:usr-D`: `v_get` на `registry_registry:reg00000000000000001` →
`allowed = true`; `v_get` и `v_list` на `registry_repository:reg00000000000000001/app` →
`allowed = false`.
**Близнец:** ND-02. Отличие — один факт: `children` у роли.

#### ND-02 — человек, `registry.reader` на X: X и его репозитории, включая будущие; Y не задет

**Дано** П1. **Когда** выдача В(`usr-D`, `rolb812261cfaa239694`, `[X]`), материализована.
**Тогда** `Check` от `user:usr-D`: `v_get` на X → `true`; `v_get` и `v_list` на `…01/app` →
`true`; `v_get` на Y и `v_get`, `v_list` на `…02/app` → `false`.
**И** служба-владелец регистрирует `reg00000000000000001/late` (цепь с X); выдача не
меняется. Опрос `v_get` от `user:usr-D` на `…01/late` доходит до `true`.
**И** `BatchCheck` (`v_get`) по X, `…01/app`, Y, `…02/app`, `…01/late` →
`[true, true, false, false, true]`; `InternalIAMService.Check` — тот же ответ по каждой
паре; `ListSubjects` по `v_get` на `…01/app` называет `user:usr-D`; `ExpandRelations` —
выдачу `usr-D` основанием; `Objects(user:usr-D, registry_repository, [v_get])` →
`{…01/app, …01/late, …01/moved}`; набор материализованных членов выдачи с `v_get` на
репозиториях равен ответу `Objects`.
**И** `GET /iam/v1/roles/rolb812261cfaa239694` отдаёт `rules[0].children[0]` =
`{"resources":["repositories"],"verbs":["get","list"]}`, `declaredSegments` = 4.
**Близнец:** ND-01.

#### ND-03 — аноним, `registry.public.read` на X: то же, только чтение

**Дано** П1. **Когда** выдача В(`{"type":"SUBJECT_TYPE_SYSTEM_CLASS","id":"anonymous"}`,
`rolb1325b011aa17211d`, `[X]`), материализована.
**Тогда** `Check` от `system_class:anonymous`: `v_get` и `v_list` на X и на `…01/app` →
`true`; после регистрации `…01/late` опрос `v_get` на нём доходит до `true`; `v_get` на
`…02/app` → `false`; `v_update` и `v_delete` на `…01/app` и X, `v_create` на X → `false`.
**И** `ExpandRelations` по `v_get` на `…01/app` называет основанием `public_reader` на X, а
не выдачу; материализованных членов `v_*` на репозиториях у выдачи нет.
**Близнец:** то же «Дано» без выдачи — каждый вопрос `v_get`/`v_list` → `false`. Отличие —
один факт: выдача.

#### ND-04 — некорректная вложенность отвергается

**Дано** документ манифеста registry новой редакции, загружаемый `manifest.Load`. В нём
правится одно место роли `registry.reader` (индекс роли `i`, правила `0`).
**Тогда** загрузка отказывает находкой судьи формы с координатой в документе и текстом:
- (а) правило-владелец над `repositories`, вложенное над `registries` —
  `roles[i].rules[0].children[0].resources: тип "registry.registries" не лежит под "registry.repositories" ни по одному объявленному указателю parents; вложенное правило действует только на потомков типа правила-владельца`;
- (б) правило-владелец над `[registries, repositories]` —
  `roles[i].rules[0].resources: правило с children называет ровно один ресурс, получено 2`;
- (в) правило-владелец над `["*"]` —
  `roles[i].rules[0].resources: правило с children называет ресурс, а не «*»`;
- (г) у вложенного правила свои `children` —
  `roles[i].rules[0].children[0].children: у вложенного правила своих children нет; более глубокий тип называется прямо под правилом-владельцем`;
- (д) у вложенного правила `module: registry` —
  `roles[i].rules[0].children[0].module: вложенное правило берёт модуль правила-владельца`;
- (е) `children: []` —
  `roles[i].rules[0].children: пустой перечень; правило без вложенных пишется без ключа`;
- (ж) **`RoleService` в этой фазе:** `POST /iam/v1/roles` с правилом, несущим непустое
  `children`, → синхронно `INVALID_ARGUMENT` (HTTP 400), текст
  `Illegal argument children (nested rules are declared by a module manifest)`,
  `BadRequest.field_violations[0].field` = `rules[0].children`; `Operation` не создана.
  **И** то же тело правил через `PATCH /iam/v1/roles/{roleId}` (`"updateMask":"rules"`) у
  роли арендатора — тот же код, текст и поле.
- (з) **`kaname#965` — ссылка на конкретный объект.** У вложенного правила
  `resourceNames: [app]` — загрузка отказывает находкой вида «манифест модуля называет
  конкретный объект» (`manifest.ErrObjectRefInManifest`), текст
  `roles[i].rules[0].children[0].resourceNames: сужение по идентификаторам объектов в роли манифеста модуля не допускается — правило называет типы (resources) и вправе сузиться метками (matchLabels); идентификатор объекта присваивает запись, и снимается он вместе с регистрацией объекта, а манифест применяется на каждом старте и вернул бы ссылку снова`.
  **И** у правила-владельца с `children` — `resourceNames: [reg00000000000000001]` под
  `resources: [registries]` — та же находка с координатой
  `roles[i].rules[0].resourceNames`. **И** пустой перечень `resourceNames: []` в любом из
  двух мест — тот же отказ: ключ судится по наличию, а не по длине. Прежняя редакция этого
  документа строила на такой роли фикстуры П1 и П3; решение `kaname#965` их снимает.

Ярус иерархии под правилом-владельцем (Р1 п. 2) — отдельная находка той же формы. Она
строится на манифесте службы, где ярусы объявлены (`manifest.yaml` kaname): правило над
`project` с `children` —
`roles[i].rules[0].resources: "project" — ярус иерархии; под ярусом выбирает область выдачи, children у него нет`.
**Близнец:** немодифицированная фикстура — загрузка успешна, роль `registry.reader`
применяется (ND-02). Для (ж) — то же тело без `children` (и `POST`, и `PATCH`) →
`done=true`. Для (з) — немодифицированная фикстура: вложенное правило над типом, без
`resourceNames`, — загрузка успешна. Отличие в каждой
паре — один факт.

#### ND-05 — классу не выдаётся вложенное правило, не выполняющее условий

**Дано** П1. **Когда** выдача анониму, как в ND-03, но:
- (а) роль `rolc36eeca826b9a8603` (вложенное `[get]`) → синхронно `FAILED_PRECONDITION`
  (HTTP 400), текст
  `Role rolc36eeca826b9a8603 nests a rule over registry.repositories that does not read it whole (get and list, without resourceNames or matchLabels); a system class reads children only whole`;
- (б) роль `rolc8f851eb7a5da3d9f` (вложенное с `resourceNames`; строка роли положена
  применителем в обход загрузчика, как доставленная до запрета `kaname#965` — П1) → тот
  же текст с `rolc8f851eb7a5da3d9f`;
- (в) роль `rolb812261cfaa239694`, «Дано» — П1, **затем** `deliverPriorEdition`: прежняя
  редакция раздела `roles` не объявляет, поэтому роль остаётся живой
  (`internal/apps/kaname/moduleroles/retire.go:91`), а объявление контейнера снято. С одной
  прежней редакцией роли не было бы, и отказ был бы `Role … not found`. → текст SC-65 соседа
  `Type registry.registries does not pass public read to its children; role rolb812261cfaa239694 covers its child type registry.repositories`;
- (г) unit ворот на фикстуре П3: роль с вложенным над `tags` (внук), выдача анониму на
  `b1` → `Type probemod.boxes passes public read to its direct children only; role rol533113283eb982de5 nests a rule over probemod.tags`.

`Operation` не создана ни в одном случае.
**Близнец:** ND-03 (вложенное `[get, list]` без сужения, объявленный контейнер, прямой
ребёнок) — принято. **И** человеку отказа нет: (а) и (б) с субъектом `usr-D` →
`done=true`.

#### ND-06 — снятие выдачи снимает право со всех потомков

**Дано** ND-02 и ND-03 целиком (`…01/late` зарегистрирован).
**Когда** `usr-A` удаляет обе выдачи (`DELETE /iam/v1/accessBindings/{id}`), опрос каждой
`Operation` доходит до `done=true`.
**Тогда** опрос `Check` от `user:usr-D` и от `system_class:anonymous` доходит до
`allowed = false` по `v_get` на X, `…01/app` и `…01/late`.
**Близнец:** те же вопросы до удаления — `true`. Отличие — один факт: выдача снята.

#### ND-07 — старая роль без `children` смысла не меняет

- (а) **Дано** П2. **Когда** «перезапуск» П2. **Тогда** `GET` роли
  `rolb1325b011aa17211d` отдаёт `rules` дословно как до перезапуска, без `children`;
  `materializedAt` выдачи не изменился; `Check` от `user:usr-D`: `v_get` на X → `true`, на
  `…01/app` → `false` — как до перезапуска. **Близнец:** те же вопросы до перезапуска.
- (б) **Дано** П1, но роль `registry.public.read` доставлена прежней формой (одно правило
  `[registries, repositories]`). **Когда** выдача анониму, как в ND-03. **Тогда** `v_get` на X
  → `true`; `v_get` и `v_list` на `…01/app` → `false`; кортежа `public_reader` на X нет.
  **Близнец:** ND-03. Отличие — один факт: форма роли.

#### ND-08 — внук охватывается на любой глубине

**Дано** П3, выдача `usr-D` роли `probemod.reader` с целью `[probemod.boxes b1]`.
**Тогда** `Allowed(user:usr-D, probemod_tag, t1, v_get)` → `true` (предок `b1` на глубине 2);
`t3` → `false` (предок `b2`); `Allowed(…, probemod_item, i1, v_get)` → `false` (правила над
`items` нет). Материализатор (unit, фикстура каталога П3) даёт член `v_get` на `t1` и ни
одного на `t3`, `i1`.
**И** (B1 = (б)) выдача `usr-D` роли `probemod.reader` с целью `allInScope` → `t1` и `t3`
→ `true`; роли-близнеца `probemod.reader_b1` (строка роли из правил домена, П3; манифестом
не объявляется — `kaname#965`) с целью `allInScope` → `t1` → `true`, `t3` → `false`:
ветвь правила-владельца выбирает только `b1`.
**Близнец:** цель `[probemod.boxes b2]` → `t1` → `false`, `t3` → `true`. Отличие — один факт:
названный контейнер. Для «И» близнецы — пара ролей, отличие — `resourceNames` у
правила-владельца.

#### ND-09 — перенос объекта под другой контейнер переносит право

**Дано** ND-02 и выдача В(`usr-E`, `rolb812261cfaa239694`, `[Y]`), обе материализованы.
`…01/moved` зарегистрирован в X с `source_version` = T1 (часы фикстуры; оба вызова —
`parent` и `owner`). `v_get` на `…01/moved`: от `user:usr-D` → `true`, от `user:usr-E` →
`false`.
**Когда** служба-владелец повторно регистрирует `…01/moved` с цепью
`["registry_registry:reg00000000000000002", "project:prj-A", "account:acc-A"]` и
`source_version` = T2 > T1 — оба вызова, `parent` на Y и `owner`.
**Тогда** опрос `Check` на `…01/moved` доходит до `false` от `user:usr-D` и до `true` от
`user:usr-E`.
**Близнец:** та же повторная регистрация с `source_version` = T1 (не новее) — регистрация
не применяется, рёбра прежние, ответы прежние. Отличие — один факт: новизна версии.
Перенос — свойство механизма: registry сам так не переносит (id репозитория несёт id
реестра), но `parent_chain` — состояние, и право следует за ним.

#### ND-10 — у класса нет второй дороги к потомкам

Сценарий утверждается для обоих классов (Р5 говорит о двух).
- (а) **Дано** ND-03 материализована; выдача В(`usr-D`, `rolb1325b011aa17211d`, `[X]`)
  материализована. **Когда** манифест registry доставлен прежней редакцией
  (`deliverPriorEdition`: объявление `publicReadToChildren` снято), затем полный проход
  материализатора `ReconcileBinding` по каждой выдаче — как в пробе соседа
  `TestPublicContainerRead_DeclarationWithdrawnRemovesPublicReader`. **Тогда** `Check` от
  `system_class:anonymous` на `…01/app` → `false`; от `user:usr-D` на `…01/app` → `true`.
- (б) **Дано** П1 без выдачи анониму; выдача
  В(`{"type":"SUBJECT_TYPE_SYSTEM_CLASS","id":"authenticated"}`, `rolb1325b011aa17211d`, `[X]`)
  и В(`usr-D`, `rolb1325b011aa17211d`, `[X]`) материализованы; `usr-E` выдач не имеет и
  несёт класс `authenticated` как вошедший. **Когда** то же снятие и тот же проход.
  **Тогда** `Check` от `user:usr-E` на `…01/app` → `false`; от `user:usr-D` → `true`.

**Близнец:** в (а) и (б) до снятия — все вопросы `true`. Отличие — один факт: объявление
контейнера.

#### ND-11 — вся область: вложенное правило внутри всех контейнеров области

Решение диспетчера B1 = (б).
- (а) **Дано** П1. **Когда** выдача В(`usr-E`, `rolb812261cfaa239694`, `{"allInScope":{}}`),
  материализована. **Тогда** `BatchCheck` от `user:usr-E` (`v_get`) по X, `…01/app`, Y,
  `…02/app` → `[true, true, true, true]`; после регистрации `…01/late` опрос `v_get` на нём
  доходит до `true`.
- (б) **Дано** П3, переложенный на типы registry (форма `tgSeedTopology`, как близнецы
  пробы `#857`): выдача `usr-E` роли `rolb812261cfaa239694` строкой с целью `{}`, затем с
  целью `{"resources":[]}` — входом `Create` пустая цель отвергается, хранимые формы
  остаются. **Тогда** `Allowed` и `AllowedMany` дают тот же ответ, что (а).

**Близнец:** та же выдача ролью `rol2375080206e7e5e32` (без `children`) →
`[true, false, true, false]`. Отличие — один факт: `children`. Этим же показано, что Y и
`…02/app` живы и достижимы, — ровно исход SC-68 Б2 соседа.

#### ND-12 — цель не называет объект типа, покрытого только вложенным правилом

**Дано** П1. **Когда** выдача В(`usr-D`, `rolb812261cfaa239694`,
`{"resources":{"resources":[{"type":"registry.repositories","id":"reg00000000000000001/app"}]}}`).
**Тогда** синхронно `FAILED_PRECONDITION` (HTTP 400), текст ворот 3 дословно
`role rolb812261cfaa239694 does not grant verbs on registry.repositories; target type must be covered by role.rules`;
`Operation` не создана.
**Близнец:** ND-02 — та же роль, цель `[X]`. Отличие — один факт: тип элемента цели.

## Сценарий → производитель

«Уже производит» — координата на `422d1bc6f`, прочитана; «заказан» — производителя нет, его
заводит полоса.

| ID | что производит «Тогда» | координата | чем измерено |
|---|---|---|---|
| ND-01, 07 (а) | точная ось цели в решении и материализаторе | `grantArmPredicate` (`internal/repo/kaname/pg/relverdict/grantarm.go`), `filterMatchedToTarget` (`reconcile.go:1048`) — уже производят | проба `#857`: `go test ./internal/repo/kaname/pg/relverdict/ -run '^TestTarget_' -count=1` |
| ND-02, 06, 08, 09, 11 | ось вложенности (включая всю область): решение во всех формах и материализатор | там же — **заказана**; рёбра предков — `upsertParentEdges` (`emitter.go:354`) уже производит, у применённой строки (`emitter.go:301-310`) | прочитано; посев рецензента ND-09 без новой версии — рёбра прежние (запись `49242817…`, B4) |
| ND-12 | ворота 3 | `CoversType` (`internal/domain/access_binding_target.go`) в «Gate 3» `internal/apps/kaname/api/access_binding/structural_gates.go` — уже производит по правилам верхнего уровня; неизменность при правке домена `Rule` под `children` — **заказана** пробой | прочитано |
| ND-02 «И» `GET` | `Rule.children` и проекции чтения роли | `internal/apps/kaname/api/role/get.go`, `proto/kaname/cloud/iam/v1/role.proto` — поле **заказано** | `awk '/^message Rule \{/,/^\}/' proto/kaname/cloud/iam/v1/role.proto` — полей 5, `children` нет |
| ND-03, 07 (б), 10 | `public_reader` по вложенному правилу; исключение класса из оси вложенности | `publicReaderMember`, `withPublicReaders` (`internal/apps/kaname/api/access_binding/reconcile/public_reader.go`) — производят по правилу верхнего уровня; условие «вложенное правило» и исключение — **заказаны** | прочитано |
| ND-04 (а)–(е) | судья формы манифеста | `internal/manifest/roles.go` (`Rule`, `DomainRule`), `schema/module-manifest.schema.json` — ключ **заказан**; родство — `parents` ресурсов (`internal/manifest/resources.go`) уже есть | прочитано |
| ND-04 (ж) | отказ входа `RoleService` | `internal/apps/kaname/api/role/handler.go` (`InvalidArg`) — **заказан** | прочитано |
| ND-04 (з) | отказ загрузчика по ссылке на конкретный объект (`kaname#965`) | `internal/manifest/object_refs.go` (`refuseObjectRefs`, `ErrObjectRefInManifest`); схема — `not: {required: [resourceNames]}` у элемента правила и у вложенного правила (`schema/module-manifest.schema.json`) — **уже производит** | прочитано @`abbcb5558`; пробы `TestObjectRefs_NestedRuleResourceNamesIsRefused`, `TestObjectRefs_OwnerRuleWithChildrenResourceNamesIsRefused`, близнец `TestObjectRefs_NestedRuleOverATypeLoads` (`internal/manifest/object_refs_test.go`); пустой перечень во вложенном правиле и у правила-владельца — подтесты `internal/manifest/object_refs_test.go` (**заказаны** решением диспетчера 2026-10-24); у правила верхнего уровня — `TestObjectRefs_RoleRuleResourceNamesIsRefused` |
| ND-05, ND-10 | ворота класса и «только чтение» | `systemClassContainerGate` (`internal/apps/kaname/api/access_binding/system_class_gates.go`) и текст `domain.UndeclaredContainerText` — текст (в) уже производят. Условие — нет: `PublicReadContainer.CoveredChild` (`internal/domain/public_read.go:37-45`) и `Role.GrantsReadsOnly` (`internal/domain/system_class.go:182`) перебирают только правила верхнего уровня. Чтение вложенных правил в них и в стражах базы `kaname.role_grants_reads_only`, `kaname.access_binding_subject_class_reads_only`, тексты (а), (б), (г) — **заказаны** | прочитано |
| ND-08 | глубина | фикстура `probemod.children-fixture.yaml` — **заказана**; роль-близнец «И» с `resourceNames: [b1]` — строкой роли из правил домена, не фикстурой манифеста (`kaname#965`) | прочитано |

## DoD

Пробы ещё не написаны, поэтому они названы командой с шаблоном `-run`, а не координатой.
Красные пробы сдаются одним изменением с реализацией; полный хук отправки не обходится.

- `schema/module-manifest.schema.json`, `internal/manifest/roles.go`: ключ `children`;
  описание ключа в схеме называет глубину — «любая по цепи предков» (В5);
  `go test ./internal/manifest/ -run '^Test\w*_ND04_' -count=1` — находки ND-04 (а)–(е)
  дословно, близнец зелёный;
- `proto/kaname/cloud/iam/v1/role.proto`: `Rule.children` (вывод) и вложенная форма
  `RuleState`; `buf lint`, `buf breaking` против ствола зелёные; порождённое перегенерировано;
- `go test ./internal/repo/kaname/pg/relverdict/ -run '^Test\w*_ND(0[1-9]|1[0-2])_' -count=1`
  — все формы вопроса;
- `go test ./internal/apps/kaname/api/access_binding/... ./internal/apps/kaname/api/role/ -run '^Test\w*_ND(0[1-9]|1[0-2])_' -count=1`
  — integration на П1 и П2, unit материализатора и ворот;
- **проба падает на стволе:** ND-02 на `422d1bc6f` красная (`…01/app` → `false`), на
  голове — зелёная; оба вывода — в `DoD-proof`;
- проба `#857` и пробы S5 соседа зелёные без правки утверждений:
  `go test ./internal/repo/kaname/pg/relverdict/ -run '^TestTarget_' -count=1`,
  `go test ./internal/apps/kaname/api/access_binding/ -run '^TestPublicContainerRead_' -count=1`;
- **стоимость — требование к реализации:**
  - `TestR7_1_13_EarlyExitIsObservable` зелёная, строк не больше прежнего (26 при трёх
    основаниях, 24 при трёхстах — `DoD-proof @91b216f3c` задачи `#857`);
  - проба той же формы для выдачи с вложенным правилом,
    `go test ./internal/repo/kaname/pg/relverdict/ -run '^TestNestedEarlyExit' -count=1 -v`:
    на разрешающем вопросе строк при трёхстах основаниях не больше, чем при трёх;
  - отчёты `TestMatrixVolume_Report`, `TestScaleGrid_FullGridReport`,
    `TestStrengthGrid_Report` (под `KACHO_MATRIX_VOLUME=1`, `KACHO_SCALEGRID_FULL=1`,
    `KACHO_STRENGTH_FULL=1`) — код 0; несущие строки, отброшенное и тронутое во всех точках
    равны прежнему отчёту; при сдвиге отпечатка отчёт переснят, и
    `TestMatrixVolumeReportIsFreshAndItsSubjectHasNotMoved` зелёная;
  - `TestGrantArmPredicateHasASingleHome` и `TestEveryAssembledQueryCarriesTheGrantPredicateOnce`
    зелёные: ось вложенности — внутри единственного предиката;
- фикстура `registry.public-read-fixture.yaml` — роли таблицы П1; соседу — редакция 11 (Р5)
  и её ревью дельты до вливания кода;
- `kaname#965`: `go test ./internal/manifest/ -run '^TestObjectRefs_' -count=1` — находки
  ND-04 (з) дословно, близнецы зелёные; ND-05 (б) зелёная на строке роли, положенной
  применителем в обход загрузчика;
- `make lint` и полный хук отправки зелёные; комментарий `DoD-proof @<sha>` в задаче `#874`.

## Решения диспетчера 2026-10-17 по вопросам В1–В5

Все пять вопросов решены рекомендацией автора. Открытых вопросов у документа нет.

| № | решение | где действует |
|---|---|---|
| В1 | условие 2 для класса — вложенное правило даёт **ровно** `get` и `list`; «входят в {get, list}» отклонено: роль с одним `get` получила бы `list` через `public_reader` | Р5 п. 2, ND-05 (а) |
| В2 | `RoleService` в этой фазе **показывает** `children` на чтении (`Get`, `List`, `declaredSegments`, `ruleStates`) и **отвергает** непустое `children` на входе `Create`/`Update` с именем поля | Р4, ND-02 «И», ND-04 (ж) |
| В3 | периода совместимости для `registry.public.read` **нет**: роль не доставлена ни одним стволом, прежняя форма проигрывает в сторону отказа | Р5, ND-07 (б) |
| В4 | редакция 11 соседа `anonymous-and-authenticated-are-subject-classes.md` — **тем же изменением, до кода**: форма роли, абзац «Сужение по цели», близнец SC-73 | Р5, DoD |
| В5 | имя ключа — `children`; глубина — **любая** по цепи предков объекта (для класса — только прямой ребёнок, Р5 п. 1). Описание ключа в `schema/module-manifest.schema.json` называет глубину прямо, потому что `publicReadToChildren` в том же манифесте значит один шаг | Р1, Р3, ND-08, DoD |
| В6 · B1 круга 1 | **вариант (б)**: выдача выбирает контейнеры («все» либо по имени), `children` действует внутри выбранных; на `allInScope` и пустой цели вложенное правило охватывает потомков всех контейнеров области, которые проходит ветвь правила-владельца. Классам `allInScope` закрыт (SC-24, SC-19). SC-68 Б2 соседа верен без правки | Вне объёма п. 2, Р3, ND-08 «И», ND-11 |

## Редакция 2: что закрыто

Запись круга 1 —
`docs/specs/reviews/nested-rule-reaches-descendants-of-a-named-container/492428179d619f7a0accaf2a8d2d99d0cec0ae532654ed9d76a75df82d127062.yaml`.
Сценариев 12: добавлены ND-11, ND-12.

| пункт | как закрыт | где |
|---|---|---|
| B1 · SCOPE | решение диспетчера (б): охват на `allInScope` и пустой цели — потомки всех выбранных контейнеров области; SC-68 Б2 соседа верен | Вне объёма п. 2; Р3; решения, строка В6 |
| B2 · COVERAGE | (1) ND-11 — `allInScope` и пустая цель с близнецом без `children`; (2) ND-12 — отказ воротами 3; (3) ND-04 (ж) — и `PATCH`; (4) ND-10 — оба класса | ND-04, ND-10, ND-11, ND-12 |
| B3 · PRODUCER | держатели SC-68 согласованы с редакцией 12 соседа: `^TestTarget_` (8 функций) — часть А и Б0, ND-02 — Б1, ND-11 — Б2 | Р5 |
| B4 · CONSTRUCTIBILITY | ND-09: регистрации с `source_version`, повторная — строго новее; близнец — не новее; Р3 — то же условие словами | Р3; ND-09 |
| M1 | производитель ND-05: условие ворот и «только чтение» читают лишь правила верхнего уровня — заказ назван, со стражами базы | таблица производителей |
| M2 | ND-05 (в): «П1, затем `deliverPriorEdition`», роль жива по `retire.go:91` | ND-05 |
| M3 | отпечаток `module-manifest-roles-and-seed-grants.md` — `fc75beed…` | «Опора» |
| M4 | `upsertParentEdges` — `emitter.go:354`, вставка — строка 381 | Р2; таблица производителей |
| M5 | П2 строится кодом изменения с фикстурой прежней формы; «перезапуск» — новые use-case поверх той же базы | П2; ND-07 (а) |
| M6 | ND-10: полный проход `ReconcileBinding` после доставки назван | ND-10 |
| M7 | ND-04 (ж): `field_violations[0].field` = `rules[0].children` | ND-04 |
