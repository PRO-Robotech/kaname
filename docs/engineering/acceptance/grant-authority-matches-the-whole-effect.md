<!--
Copyright (c) PRO-Robotech
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Приёмка: выдача роли ограничена полным выдаваемым эффектом

- **Статическая форма:** DRAFT, редакция 1 от 2026-11-12. Полный контракт этой редакции ещё не получил одобрения по отпечатку. Слово DRAFT после ревью не меняется; действующий вердикт выводится из отдельной записи и события ревью.
- **Задачи:** Kaname #1034, #1035; взаимодействие с поставленными узкими исправлениями #1036/#1037/#1039 и с общими доверенностями #986/#1032.
- **Область:** Kaname и общие доверенности. Kachō, Terraform, Registry-потребитель и svc-registry не участвуют.
- **Предыдущая приёмка:** `role-rights-stay-within-what-is-named.md`, r4, SHA-256 `3131d7ddfffa9b66857b94c70138b6ebfe7bdb77c7ca07f5333db88aefaae690` покрывает прежний узкий срез. Её одобрение не переносится на полный bind/escalate, Role.Create и этот документ.
- **Основание исходников:** каноническая рабочая база `8455a9a2c997d16b3c026ac2c9fbc01457e68fba`, дерево `83fca3cbe39bf0e5780736cf4c1f6b6a43cb0744`. Ни одна описанная ниже новая проба на этой базе ещё не исполнена; требуемые новые производители перечислены отдельно.
- **История полного ревью:** записей с одобрением этой редакции пока нет. Будущая запись размещается в `docs/specs/reviews/grant-authority-matches-the-whole-effect/<sha256>.yaml`; исторические записи не переписываются.

## 1. Контракт выдачи

**D1. Правило выдачи: CreateBinding AND (explicit bind OR coverage).** Обычная выдача требует отдельное handler-owned scoped право создания выдачи и затем `explicitBind(actor, roleID, scope)` **ИЛИ** полное семантическое покрытие выдаваемых полномочий эффективным объединением прав actor. Это предложение публичного контракта, не утверждение об уже выполненной реализации. Use само по себе не даёт Create. Текущий RPC `<exempt>` и `requireGrantAuthority` (cluster-admin/owner/scope-admin) ещё не являются производителем нового ordinary Create.

**Производитель ordinary Create в этом срезе:** существующая поверхность Role.Create/Update принимает явное правило `{module:"iam",resources:["accessBinding"],verbs:["create"]}` без resourceNames/matchLabels/children/createdBySubject; существующий AccessBinding.Create выдаёт такую управляющую роль с `allInScope` на anchor S. Это специальная scoped operation-capability `CreateBinding(actor,scopeType,scopeID)`, а не `v_update` существующего binding и не требование старого admin-gate. Только действующая управляющая выдача на точно том же S производит ordinary Create; конечный target.resources для её носителя — InvalidArgument. Не вводится новый RPC. Синтаксис и каталог становятся обязательной частью новой приёмки; сейчас это определённый контракт, ещё не работающий producer. `verbs:*` обычного leaf-типа не создаёт эту новую capability случайно; прежние admin-источники сохраняются отдельно по D3. Если управляющая роль содержит иные правила, запрет target.resources относится к выдаче всего такого носителя. Создание/передача управляющей роли подчиняется D1/D3, включая её meta-эффект; proposed binding не может обосновывать собственную авторизацию.

**Ответ treska/osetr при D1:** да, actor с treska и правом AccessBinding.Create выдаёт osetr, если *весь фактический эффект* osetr на выбранных области/целях покрыт объединением его эффективных прав. Совпадения module/resources/verbs мало при разных resourceNames, matchLabels, target, scope, children, creator-селекторах, условиях и дополнительных отношениях. RoleID при coverage не сравнивается. Без coverage отдельный bind(osetr) может разрешить выдачу; bind(treska) не эквивалентен bind(osetr).

**D2. Explicit bind — scoped capability конкретной роли, без нового RPC.** Публичный носитель в исправленном контракте: существующие Role.Create/Update + Rule `{module:"iam",resources:["role"],verbs:["bind"],resourceNames:[roleID]}` и существующий AccessBinding.Create этой управляющей роли на нужном anchor с `allInScope`. Это НОВАЯ семантика правила, а не уже работающий payload. Названная роль здесь — ссылка на допустимую к выдаче роль, включая system/module роль; её home-anchor не переносит право bind за anchor управляющей выдачи. Поэтому нельзя реализовать это простым `v_bind` на глобальном объекте iam_role: нужны координаты **(roleID, scopeType, scopeID)** в модели и материальном представлении. На первом этапе bind-правило требует конечный непустой resourceNames, запрещает matchLabels, children, createdBySubject и `verbs:*` как способ получить bind. Для bind-управляющей выдачи target.resources отвергается INVALID_ARGUMENT; `allInScope` задаёт потолок всей области, а привязка управляемой роли к конечным объектам допускается как сужение. Так поддерживаются разные system roleID в разных аккаунтах без новой публичной ручки. На первом срезе anchor совпадает точно: bind на A не даёт bind в P внутри A и тем более в B. `allInScope` здесь не включает наследование capability. Это явное исключение из обычной объектной семантики iam.role/resourceNames: system/module roleID может быть определён вне A, но capability выдачи действует только в A. Assignability самой выдаваемой роли сохраняется отдельно: account-role допускается в своём вложенном project; project-role — только в своём project. При отзыве/истечении/удалении управляющей выдачи дальнейший bind исчезает. Передача её самой требует D1 для полного meta-эффекта. Имена `bind` и представление в Rule входят в новую приёмку и каталог. Не смешивать это с output-only `AccessBinding.grantedRelation`.

**D3. Escalate означает ограничение содержимого, без нового публичного bypass.** Role.Create/Update требуют обычного create/update плюс coverage полного proposed содержимого; bind роли не разрешает расширять rules. Сохранить ровно существующие административные источники: cluster-admin, владелец owning account, FGA scope-admin на проверяемом scope и существующий каскад модели. Их разрешённый потолок и обычные create-права воспроизводятся в тех же границах, с зависимостью от исходной выдачи, членства, срока и отзыва. Account admin, project admin и leaf admin не взаимозаменяемы; leaf admin не становится scope admin; account admin не приобретает CRUD самого account. Отзыв исходного admin прекращает будущую выдачу, обычные уже созданные bindings сохраняются. Прежнее wildcard-поведение сохраняется ровно там, где модель уже производит административное отношение; wildcard произвольного leaf-типа не становится bind. Для `iam.role verbs:*` явно объявлено исключение из «всех действий типа»: новый meta-bind требует явного `bind` с конечными ID и не добавляется старым wildcard при обновлении каталога. Не переносить authority в независимый бессрочный tuple/backfill.

**D4. Используемая роль — реальные выдачи; новая/неиспользуемая — fallback.** Если есть действующие bindings, Role.Update проверяет весь proposed эффект на **всех** их scope/target/recipient, включая все страницы и групповых получателей. Дополнительного accountwide definitionTier/allInScope cap нет: роль A, выданная только на P/Q, достижимо меняется actor с полным покрытием P/Q. Только Role.Create и Update без действующих выдач проверяют proposed rules на собственной definitionTier account/project области с `allInScope`. Это явный новый fallback full-контракта и намеренное изменение ESC-11 «нет выдач — разрешено»; narrow r4 его не принимал. Изменения name/description/labels без rules не требуют повторного coverage; обычные права и OCC сохраняются.

**D5. Authority проверяется в момент авторизуемой мутации.** Не вводится наследование срока actor в обычную выдачу или потолок «самый ранний expiresAt». Сохраняются собственный expiresAt binding, текущие проверки формы/нижней границы, штатные expiry/revoke. Потеря полномочий grantor запрещает новые мутации и не отзывает созданные bindings. По #986 ранее созданные delegated bindings также остаются после утраты creator authority; следующий delegated Create отказывает. Явный отзыв самого GrantDelegation сохраняет предусмотренный #986 каскад. Условие внутри права нельзя снять успешным Check сейчас: покрытие сохраняет весь смысл условий/creator-relative эффекта, но lifetime actor не превращается в новый TTL-контракт выдачи.

## 2. Публичный контракт покрытия и мутаций

`E(actor,S,T)` — объединение реально действующих разрешений actor: прямые и групповые выдачи, все страницы, scope-каскад по модели, target, ограничения правил и именованные отношения. Не `effectiveVerbs` из ответа Role: это preview без координат объектов. `G(role,S,T,recipient)` — весь эффект предлагаемой выдачи, включая выдаваемые управляющие права. Проверяется `G ⊆ E` для каждого recipient. Сам создаваемый binding и proposed rules не участвуют в обосновании actor: нельзя выдать самому себе право и этим объяснить выдачу.

* Правила сопоставляются по module + ресурсному типу + действию/отношению + множеству объектов. Разбиение на Rule и roleID несущественно: два правила/две роли вместе покрывают третью. Учитывать действительный смысл ярусов: например, сохранить принятый delete без update, а не сравнивать строки глаголов по рангу.
* `scopeType/scopeId` — cluster/account/project; definitionTier роли и scope binding различны. Account-права покрывают project только когда модель реально даёт соответствующее действие внутри этого account; project не покрывает account/соседний project. Обычное admin на конкретном объекте не становится admin всей области. Assignability из `role_scope.go` остаётся дополнительным обязательным условием.
* `target.resources` — конечное множество; покрытие проверяется на каждом объекте. `allInScope` включает будущие объекты; покрыть его перечислением сегодняшних объектов нельзя. resourceNames — subset; отсутствие селектора — универсум. Для equality labels `Ltarget ⇒ Lactor`: все пары ключ/значение actor должны содержаться у target. Union разных label-правил допустим только при доказанной полной импликации, не по сегодняшнему совпадению объектов. Одного более широкого покрывающего label-правила достаточно; недоказанное покрытие даёт отказ, а не эвристику.
* `verbs:*` — символическое право на все объявляемые действия типа; конечный текущий список не покрывает `*` и будущие действия. Wildcard actor покрывает конечный список в своей области. Custom role по-прежнему не получает `module:*` или `resources:*`. Meta-bind не приобретается wildcard автоматически при обновлении каталога. Новые типы/отношения не делают вчерашнее неполное доказательство достаточным.
* Модель может давать custom relations, вложенные права, creator-relative права и условия. Они входят в эффект при наличии доказуемого отображения. Creator actor=A не покрывает creator recipient=B: множества различны. Правило для A нельзя молча переименовать в B. Для неподдержанного отношения/условия/интерпретации coverage-ветка не доказана. Известный explicit bind и сохранённый administrative authority остаются независимыми разрешающими ветками; неизвестность coverage не запрещает их глобально. Если ни одна ветка не разрешает — PermissionDenied; недоступность требуемого authority backend/каталога/движка — Unavailable, не fallback allow. Нельзя выбросить неизвестный компонент и получить пустое покрываемое множество. Некорректный новый ввод остаётся InvalidArgument; валидное, но недоказуемое наследуемое состояние — отказ авторизации.

AccessBinding.Create требует обычное право мутации и D1; multi-subject проверяется целиком, частичного успеха нет. Group.AddMember требует обычное право изменения группы плюс D1 для каждой действующей выдачи группы с новым получателем; новые права не выводятся из членства, которое ещё только добавляется. Другой account участника запрещён независимо от bind/admin. Проверять последние страницы и одновременно добавляемые binding. RemoveMember уменьшает доступ и новых проверок выдачи не требует.

Role.Update с rules проверяет **весь** результат, не только добавленные строки, одновременно с фиксацией версии. Это намеренно означает: actor, утративший покрытие старой части роли, не может даже сузить rules без администратора; удаление binding/роли остаётся штатным путём отзыва. GrantDelegation.Create/Update сохраняют текущие actor/creator gates и три прежних административных источника account grant authority (`grant_delegation/authority.go:24–58`), текущие account/module/role/target/subject ограничения и installation-authority. Ни один ordinary CreateBinding, bind(role) или D1-coverage сам по себе не открывает создание delegation. Полный semantic coverage декартова произведения roleIDs × targetTypes × subjectTypes не вводится. Делегат использует прежнее исключение #986 без собственных use-прав; текущий creator authority проверяется на очередном Create. Потеря creator authority запрещает новые grants, существующие delegated bindings сохраняются, explicit delegation revoke каскадирует. D1 не встраивается в общий read/removal helper; чтение и удаление не получают новый gate, removal делегата сохраняет исключение из проверки creator.

**Два независимых оракула успеха.** Первый: Operation.done без error означает **DURABLE** — целостная запись committed, Get/List отражают durable изменение. API не ждёт FGA, reconcile выполняется отдельно; `materialized_at` остаётся отдельным индикатором. Второй: после reconcile ограниченный таймаутом eventual FGA Check подтверждает ожидаемый доступ и отрицательный контроль за границей. Таймаут второго фиксирует проблему эффекта, но не превращает уже committed Operation в error. Для metadata-only Update и создания невыданной роли второй oracle — отсутствие изменения доступа; искусственная выдача для Check не требуется.

Отказ до принятия — синхронный PermissionDenied `permission denied`; если authority утрачено к согласованному решению writer после принятия, Operation.error содержит отказ без полезного изменения. Backend outage — Unavailable `authz backend unavailable`; исчерпанный сериализационный retry — Aborted. Сохраняются текущие стадии/тексты структурных отказов и запрет existence oracle. Decision и запись на обычных Create, Role.Update и Group.AddMember читают authority и affected bindings/membership из согласованного writer snapshot/порядка; отдельный Reader внутри helper не считается такой проверкой. Фиксируется версия модели/каталога, использованная решением. Для конфликтующих revoke/rules/group/binding допустим один из реальных последовательных порядков с согласованным результатом; недопустим commit по устаревшему authority после победившего revoke. Online-атомарность произвольной смены модели/каталога без конкретного протокола не обещается; это не заказ глобальной платформы ревизий.

## 3. Исправленная GWT-матрица

Каждая строка с одинаковым When задаёт пару самостоятельных GWT с одной сменой Given; строки с разными методами/масками и гонки явно разделены ниже и не объявляются такими twins. Фикстуры: account A/B, project P/Q внутри A; U — non-admin, V — допустимый получатель. Для ordinary Create-пар одинаковое отдельное CreateBinding-authority, кроме FB01. FB23–24 сохраняют delegated exception без этого ordinary gate. Для FB05 оба actor имеют одинаковый CreateBinding, но лишь один — bind; иначе это не однофактная пара. При смене источника покрытия запрос, roleID, scope, target и recipient неизменны. Treska/osetr имеют разные roleID. Роли/выдачи/группы сеются администратором существующих API; children/createdBySubject/custom relation — только зарегистрированным generic module-manifest fixture Kaname (без consumer), а не запрещённым custom Role.Create. Положительный Then — durable oracle и отдельно eventual oracle по §2; отрицательный — отсутствие частичного изменения, сохранение API-стадии/ошибки. Не утверждается исполнение этих проверок.

| ID | Given / When | Δ единственного факта (+ / −) | Then − |
|---|---|---|---|
| 01 | Non-admin U покрывает osetr через treska; неизменный Create osetr | только явный scoped CreateBinding действует / отсутствует | PermissionDenied |
| 02 | U имеет Create; Create osetr | полное coverage / отсутствует один verb | PermissionDenied |
| 03 | Права разбиты на две роли U; Create их union | обе действуют / одна отозвана | PermissionDenied |
| 04 | U имеет отдельный CreateBinding, не имеет use; неизменный Create osetr | bind(osetr,S) / bind(treska,S) | PermissionDenied |
| 05 | Bind(osetr) на A; Create в A | actor=держатель / другой actor | PermissionDenied |
| 06 | Одна system/module роль структурно допустима A/B; одинаковый CreateBinding на обоих; неизменный запрос Create в B | носитель bind(role,B) / bind(role,A) | PermissionDenied; home-tier не расширяет anchor |
| 07 | Одна system/module роль допустима P/Q; CreateBinding на обоих; неизменный запрос Create в Q | coverage U на Q / лишь на P | PermissionDenied |
| 08 | Неизменный Create с target={x,y} | источник U покрывает x,y / только x | PermissionDenied |
| 09 | Неизменный Create с allInScope | источник U символически покрывает всю область / лишь все нынешние объекты | PermissionDenied |
| 10 | Одна выдаваемая роль names={x}; одинаковый Create/target | источник покрытия U names={x,y} / names={z} | PermissionDenied |
| 11 | Одна выдаваемая роль labels env=prod,team=a; одинаковый Create/target | источник U env=prod / env=dev | PermissionDenied |
| 12 | Неизменный AccessBinding.Create роли с verb=* | U имеет * / U имеет только все нынешние verbs | PermissionDenied |
| 13 | Existing generic module-manifest роль с children/custom relation; неизменный Create | источник покрывает весь компонент / одного компонента нет | PermissionDenied |
| 14 | Actor S1 — service account, получатель S2 — другая direct service account в A; неизменный Create manifest-роли iam.service_account.creator для S2 на A/allInScope; в обеих половинах S1 уже имеет creator-role и отдельный CreateBinding(A) | дополнительный unconditional source iam.service_account.admin для S1 действует / отсутствует | PermissionDenied: собственный creator=S1 не покрывает creator=S2; исходная выдача S1 и новая S2 не дублируют active-grant key |
| 15 | U может Role.Create, binding ещё нет | proposed покрыт на definitionTier / не покрыт | PermissionDenied |
| 16 | Role.Update rules, выдач нет | proposed покрыт / не покрыт | PermissionDenied |
| 17 | Роль definitionTier=A выдана только в P/Q; неизменный Role.Update | U покрывает оба P/Q / лишь P | PermissionDenied; в + accountwide coverage A не требуется |
| 18 | U имеет bind и Role.Update, расширяет rules | новое содержимое покрыто / не покрыто | PermissionDenied |
| 19a/19b | Rules не покрыты; U имеет update; отдельные сценарии: metadata-only / rules в mask | разные When, не twin | 19a durable success без изменения доступа; 19b PermissionDenied |
| 20 | Role.Update rules | актуальная resourceVersion / устаревшая | FailedPrecondition (Role was modified concurrently, retry) |
| 21 | AddMember, группа имеет несколько страниц выдач | покрыты все / не покрыта последняя | PermissionDenied |
| 22 | AddMember, все права выдавать есть | V из A / V из B | FailedPrecondition, reference missing (как отсутствующий member) |
| 23 | Делегат без use-прав; Create по #986 | разрешённые role/target/subject / одна ось вне delegation | PermissionDenied |
| 24 | Та же delegation; Create | creator authority действует / отозвано | PermissionDenied, permission denied |
| 25a/25b/25c | Отдельные неизменные методы: GrantDelegation.Create actor-gate; Update actor-gate; Update saved-creator-gate | соответствующий прежний administrative authority действует / утрачен | прежний отказ соответствующей стадии; без нового semantic axes coverage |
| 26 | Mutation и revoke одного источника; два барьера до writer decision/commit | см. порядок ниже | согласованный serial исход, не устаревший grant |
| 27 | Role.Update и новый binding этой роли в Q | два заданных interleavings ниже | согласованный serial исход полного proposed эффекта |
| 28 | AddMember и новый binding роли группе | два заданных interleavings ниже | согласованный serial исход, нет непроверенного усиления |
| 29 | Все shape/security inputs одинаковы; Create | backend отвечает / outage | Unavailable, не fallback allow |
| 30 | Неизменный Create, нет explicit bind/admin; нужен custom effect | семантика coverage известна / неизвестна | PermissionDenied; отдельный контроль известного bind при неизвестном coverage — success |
| 31 | Неизменный Create с тем же собственным валидным expiresAt либо бессрочно | источник authority действует в writer decision / уже истёк | PermissionDenied; TTL actor не наследуется |
| 32a/32b | Отдельные shape-сценарии Role.Create bind-rule D2 | разные payload: конечные roleIDs / label selector вместо IDs; не twin | 32a проходит shape при обычных правах и coverage; 32b InvalidArgument |
| 33a/33b | После выдачи отозван creator/grantor authority; отдельные ordinary/delegated fixtures | оба ранее созданных binding остаются; следующий Create до/после потери authority | новый Create после потери — отказ; explicit delegation revoke отдельно каскадирует |
| 34 | Actor — service-account V; неизменный Create manifest-роли iam.service_account.creator для direct SA V/W, account A, allInScope; исходная C→[Z,V] даёт V creator=V без duplicate-key нового C→[V,W] | дополнительный unconditional source iam.service_account.admin для V действует / отсутствует | PermissionDenied всего запроса из-за creator=W; никакой частичной записи; прежняя C→[Z,V] сохраняется |

Число «68 исходов» снято: разделённые сценарии и гонки не являются 34 однофактными парами. Наследуются GD и ESC, кроме явно изменённого D4 fallback/ESC-11; narrow-r4 approval остаётся историческим и не покрывает full #1034/#1035.

**Обязательные дополнительные пары D2/D3:** одинаковый Create в A с bind(role1,A) разрешён, с bind(role2,A) запрещён; тот же binding-carrier действует/отозван; scope-admin с сохранённым исходным источником разрешён, CRUD-only не разрешает; тот же admin до/после отзыва источника прекращает новые grants и сохраняет прежние bindings. Home-tier управляемой system/module роли не меняет bind anchor. bind не открывает Role.Update rules вне coverage. Coverage проверяет meta-права при передаче управляющей роли.

**Конкретные гонки writer/storage, без обязательной сети:**

* FB26: (I) mutation decision+commit раньше revoke — grant допустим и остаётся после revoke; (II) revoke commit раньше writer decision — grant отвергнут, частичной записи нет. Проверка на старом Reader при II не разрешает commit.
* FB27: R уже имеет действующую выдачу только в P. Задать U с Role.Update на R и coverage только P, R до изменения даёт x, proposed — x+y; U покрывает y в P, не Q. Соперник B имеет CreateBinding и покрывает старый x в Q, не y. (I) новый binding R→Q commit раньше Update — Update обязан увидеть Q и отказать; (II) Update commit раньше Create→Q — Create обязан увидеть x+y и отказать. Итог не может содержать одновременно расширенную роль и новый непроверенный binding. Оба API имеют обычное право своего метода, поэтому отказ достигает именно full-effect gate.
* FB28: изолированный generic fixture probemod.boxes (manifest.Load → modelcompose.Compose/admission → production modulecatalog.Applier → InternalIAMService.RegisterResource), объект b в P аккаунта A. H={U}, U/V/A1/A2 из A; H уже имеет X=get на b. A1 имеет AddMember, CreateBinding(P) и coverage X, но не Y=update на b. A2 имеет CreateBinding(P) и coverage Y; explicit bind/admin у обоих нет. Запросы неизменны: A1 AddMember(V,H), A2 Create Y→H на P с target.resources={b}. (I) binding commit раньше AddMember decision — binding success, AddMember PermissionDenied; H={U}, lower v_update(U,b)=allow, v_update(V,b)=deny. (II) AddMember commit раньше binding decision — оба success: второй writer проверяет актуальную H={U,V}, а A2 покрывает Y для обоих; lower v_update(U,b)=allow и v_update(V,b)=allow. Это допустимый проверенный serial исход. Creator-relative роль группе не сеется: production creator-gates запрещают group subject. Последовательность II является положительным serial контролем, но не доказательством recipient-sensitive Create race, для которого достижимый producer отсутствует. Оба порядка проверяют committed строки/Operation отдельно от реального lower-port результата; error/Unknown не засчитывается как deny.

Для FB25 actor-denial — прежний PermissionDenied; утрата saved creator authority при Update — прежний FailedPrecondition. Это не новые ошибки. FB28 использует существующую generic безусловную семантику и допускает оба успешных commit во втором serial порядке; новая recipient policy не вводится. Для FB14 creator-relative Given берётся отдельно из manifest iam.service_account.creator: direct service-account recipient, account scope, allInScope; группа и generic mirror creator запрещены текущими production gates. FB22 и FB23 с разными recipient/axis — отдельные инвариантные сценарии с изменённым payload, не однофактные twins одного запроса.

## 4. Карта реализации, совместимость и следующий шаг

| Существующий держатель (в W) | Необходимое изменение / производитель Then |
|---|---|
| `internal/apps/kaname/api/access_binding/create.go`, `helpers.go`, `scope_grant_authority.go` | отдельный role+scope+target+recipient aware decision; старый общий admin-helper не превращать в универсальное исключение #986; FB01–14,26,29–34 |
| `role/iface.go:RulesGrantAuthority.RequireForRole(ctx,id)`, `role/create.go`, `role/update.go` | порт принимает proposed rules, definitionTier и действующие binding/targets; проверка в writer snapshot, версия и фан-аут; FB15–20,27 |
| `group/iface.go:MembersGrantAuthority.RequireForGroup(ctx,id)`, `group/add_member.go` | учитывать нового member и весь эффект, транзакционную смену binding/членства; FB21–22,28 |
| `grant_delegation/authority.go`, `create.go`, `update.go`, `access_binding/delegated_path*` | сохранённые actor/creator administrative gates, GD исключения, installation path; без нового полного axes coverage; FB23–25,33 |
| `internal/domain/rule.go`, `rule_verbs.go`, `role_scope.go`, `role_rule_state.go`; `internal/authzmodel/*`, `internal/authzmap/*`, `internal/reconcile/*` | единый семантический coverage над plans; явные scoped CreateBinding и bind; не вычислять авторизацию по UI-preview; символический wildcard/selector/условия |
| `internal/repo/kaname/pg/`, `internal/clients/relations.go`, `cmd/kaname/wiring.go` | reader/writer порты полного snapshot; pg writer уже имеет TransactionRelationChecker у delegation.Update; согласованные writer snapshot/decision, fanout и outbox без TOCTOU; без новой глобальной платформы ревизий |
| `proto/kaname/cloud/iam/v1/role*.proto`, permission catalog/model generated surfaces | описать новый verb/Rule restrictions; публичный RPC не добавляется; разъяснить definitionTier против binding scope |
| `docs/engineering/acceptance/`, tests integration/newman | отдельная новая принятая приёмка по fingerprint; держатели всех FB-пар и полный прежний домен на одном SHA |

**Миграция:** существующие binding и roleID сохраняются; ordinary use-rights не переписываются. Новые мутации начинают проходить полный контракт. Сохранённые administrative grant-capabilities воспроизвести из доказуемых текущих cluster-admin/owner/scope-admin источников с живыми зависимостями; не backfill из «когда-то создал binding» и не из любого CRUD-tier. Creator authority действующих delegation сохранить в том же атомарном шаге, с сохранением границ account/module/roles/targets/subjects, без бессрочного сохранения уже отозванного полномочия. Не делать rollout, при котором новая модель уже допускает bind, а старый writer ещё его не проверяет: capability/version gate до переключения write-пути; несовместимый старый writer fail-closed. Reconcile не расширяет bind от добавления глагола в wildcard-каталог. Старые broad unused roles читаются, их будущие изменения/выдачи проверяются; blanket revoke или silent rewrite не предлагаются.

Точная модель scoped bind, доказуемое coverage всех поддерживаемых custom relations и атомарность snapshot — обязательные design-review предметы, не «потом добавим тест». При невозможности доказательства допустим отказ, но ни один ранее обещанный поддерживаемый тип не должен незаметно стать недоступным: перед кодом перечислить supporting/unsupported class и утвердить границу. Этот SOURCE-пакет не заменяет такую перепись и review.

**Основание Kubernetes:** официальные правила позволяют привязку роли при владении всем её содержимым в нужной области либо при explicit bind. Создание и правка роли требуют владения содержимым либо explicit escalate; право изменения самого RoleBinding проверяется отдельно. Документация сверена 2026-11-12. D1 использует этот принцип. Отсутствие публичного escalate-bypass, ограничения future/creator/label и D2 — собственные решения Kaname. [Kubernetes RBAC: privilege escalation prevention](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping).

**Решение ROOT 2026-11-12:** приняты архитектурное направление D1–D5 и исправленные serial исходы FB27/FB28 после критического SOURCE review r2. Требование обязательного отказа во втором порядке FB28 снято как добавляющее отсутствующую recipient policy; generic fixture и direct creator fixture разделены. Новый цикл review этой поправки не требуется. Следующий конечный шаг — точное представление scoped capability, перечень поддерживаемых coverage-классов и протокол writer serialization, затем реализация и реальные проверки. Этот draft ещё не является опубликованной принятой приёмкой: точные запросы/держатели/ошибки и проверяемая конструируемость каждого Then должны быть зафиксированы в реализации и приёмке. Narrow-r4 approval не переносится; runtime/CI успеха, готовности закрыть #1034/#1035 и срока закрытия этот пакет не даёт.

## 5. Конкретные запросы и производители мира проб

Обозначения A/B, P/Q, U/V/W/H и R — идентификаторы, возвращённые настоящими
API/фикстурами IAM, а не заранее угаданные ID. U/V состоят в A; P/Q принадлежат A.
Администратор создаёт мир, обычный actor исполняет исследуемый запрос.
У отрицательного близнеца сохраняются actor, payload, scope, target, recipient и
модель; меняется только названный в §3 источник права. Исключения с разными When
и двумя порядками commit уже перечислены отдельно.

Базовый запрос FB01–04, 07–12, 29–31 — `CreateAccessBindingRequest`:

```json
{
  "subjectType": "user",
  "subjectId": "<V>",
  "roleId": "<osetr>",
  "scopeType": "iam.project",
  "scopeId": "<P>",
  "target": {"allInScope": {}}
}
```

Для конечной цели FB08 используется настоящая protobuf-форма
`target.resources.resources=[{type:"probemod.boxes",id:x},{type:"probemod.boxes",id:y}]`.
Массив непосредственно в `target.resources` неправильный и не является
проверкой полномочий. Для FB34 legacy-пара subjectType/subjectId не задаётся;
запрос: `subjects=[{type:"SUBJECT_TYPE_SERVICE_ACCOUNT",id:V},{type:"SUBJECT_TYPE_SERVICE_ACCOUNT",id:W}]`,
`roleId=C`, `scopeType="iam.account"`, `scopeId=A`, `target={allInScope:{}}`.
C — ID manifest-роли `iam.service_account.creator`; actor=V. В обеих половинах
администратор заранее выдаёт C субъектам `[Z,V]`, где Z — третья service account
в A, и выдаёт V отдельный CreateBinding(A). Первый субъект исходной выдачи Z
не совпадает с первым субъектом новой V: иначе active-grant UNIQUE дал бы
AlreadyExists вместо положительного coverage исхода. V/W/Z — прямые SA одной A.
Положительная половина отличается одним дополнительным source:
`iam.service_account.admin` для V на A/allInScope; отрицательная его не имеет.
Обе личности V/W заранее создают по дочерней SA настоящим API, чтобы lower oracle
наблюдал creator=V и creator=W; запрос и model фиксированы. Фикстура проверяет
protobuf-преобразование, отсутствие новой записи при отказе и сохранение C→[Z,V].

`treska` и `osetr` создаются разными вызовами `RoleService.Create` с разными
возвращёнными ID. Правила обычного примера:
`{module:"probemod",resources:["boxes"],verbs:["create"]}`.
Носитель ordinary Create имеет правило D1, выданное U на P с allInScope.
Создание такого носителя требует нового производителя из §1; его отсутствие
на исходной базе не маскируется административной выдачей от имени U.

Role.Create передаёт `name`, `rules` и
`definitionTier={tierType:"iam.account",tierId:A}` либо project-вариант.
Role.Update передаёт `roleId`, неизменный `resourceVersion` из Get, маску
`rules` и весь proposed rules; metadata-only использует отдельную маску.
Для AddMember запрос равен
`AddGroupMemberRequest{groupId:H,memberType:"user",memberId:V}`.
Фикстуры сохраняют фактическую стадию отказа: ошибка до выдачи Operation и
терминальная `Operation.error` учитываются раздельно, не превращаются в
одинаковый HTTP-статус тестовым адаптером.

| Мир | Настоящий производитель | Обязательное подтверждение до исследования |
|---|---|---|
| Обычные generic effects, FB02–12/27/28 | `internal/manifest/testdata/probemod.public-read-fixture.yaml`: `manifest.Load` → `modelcompose.Compose`/admission → `modulecatalog.Applier.Apply`; объект через `InternalIAMService.RegisterResource` | Каталог и admitted plans содержат probemod_box; родительский project/account создан; RegisterResource завершён; lower-port видит ровно ожидаемый объект и отсутствие доступа у постороннего |
| Children, FB13 | `internal/manifest/testdata/probemod.children-fixture.yaml`, manifest-роль `probemod.reader`, boxes → items → tags; каждый объект регистрируется настоящим RegisterResource с проверяемой parentChain | Нижний запрос для tags доказывает эффект children от выбранного boxes; при отсутствии компонента нет разрешения. Это отдельный мир, не одновременная загрузка двух разных manifest одного module |
| Labels, FB11 | IAM-direct объекты `iam.role` с метками, созданные Role.Create/Update; тип поддержан `domain.IsLabelSelectableType` | Реальный feed/reconcile довёл метки; обе фикстуры отличаются только источником покрывающего label-правила. probemod fixture без feed не используется для этой пробы |
| Creator, FB14 | Каноническая manifest-роль `iam.service_account.creator`; actor S1 и recipient S2 — разные service accounts, account/allInScope | S1 имеет исходную creator-role и отдельный CreateBinding(A); обе личности создают дочерние SA настоящим API. Позитив добавляет только unconditional iam.service_account.admin для S1. Общий USER actor U здесь не используется; group и mirror исключены |
| Административные источники D3 | Действующие cluster-admin grant, account owner и scope-admin binding из штатных писателей | Положительная выдача до изменения источника; отказ нового grant после revoke/expiry; прежний grant остаётся |
| Делегирование FB23–25/33 | Прежние GD/ESC фикстуры, после поставки #1032 — также GDU | Создание и чтение delegation через настоящие API; actor и сохранённый creator различаются; сохранены прежние bound module/role/target/subject gates |

Регистрация строки каталога без admitted model и реального объекта не создаёт
этот мир. Прямая запись разрешающих tuples вместо перечисленных API не является
производителем положительного Then. Ошибка создания мира — «не выполнилось»,
не ожидаемый отказ исследуемого API. Наличие этих производителей в исходниках
не является утверждением об исполнении нового FB-сценария.

## 6. Полнота эффекта и нормализация

Внутреннее ядро сравнения принимает нормализованные эффекты одного фиксированного
admitted model/catalog. Оно не извлекает эффективные права из ответа Role,
не получает флаг «actor достаточно широк» и не подменяет writer-снимок.
Роль/выдача/группа, parent anchors, срок действия, actual subject membership,
targets и все страницы читаются будущим normalizer на том же writer, на котором
принимается решение. Предлагаемая мутация исключена из разрешающих источников.

| Класс | Что обязано сохранить отображение |
|---|---|
| Обычное действие типа | module, реальный resource type, действие/отношение и область; семантика из admitted plans, без ранжирования строк глаголов |
| Конечные ID | Полный набор суженных объектов; допускается покрытие объединением нескольких источников |
| Вся область | Символическое множество нынешних и будущих объектов; конечная выборка не равна этому множеству |
| Равенства меток | Импликация ограничений; неизвестные метки конкретного объекта не объявляются подходящими |
| Creator | Разрешённый production selector и явная личность создателя; actor и recipient не переименовываются друг в друга |
| Children | Область потомков конкретного контейнера по admitted parent paths, включая будущих потомков; без потери ограничения родителя |
| Custom relation/условие | Весь admitted смысл, его зависимости и границы; неполученное доказательство не исчезает из списка |
| CreateBinding | Отдельное управляющее право точного anchor; обычный resource wildcard его не создаёт |
| BindRole | Отдельное управляющее право конкретного roleID × anchor; home-tier роли не переносит его в другой account/project |

Каждый предложенный эффект должен попасть в проверяемый набор либо явно сделать
покрытие недоказанным. Ошибка чтения страницы, обрезанный список, незнакомая
семантика, другая ревизия модели и превышение внутреннего предела не дают пустой
успешный набор. Полнота не доказывается одним булевым полем входа: её обязан
доказывать производственный normalizer и его отдельные интеграционные пробы.
Неизвестность coverage не отменяет независимо доказанный D2/D3.
Внутренний structural/work limit означает неполученное доказательство, а не
отсутствующее право и не malformed пользовательский payload. Если ни одна
независимая ветка не разрешила мутацию, такой исход возвращает Unavailable
(incomplete evaluation), не PermissionDenied/InvalidArgument. Нельзя усекать
страницы или эффекты ради обхода предела. Различный порядок равносильных атомов
может менять достижение рабочего лимита; до полного вычисления это не
утверждение о различии полномочий. Это решение ROOT для интеграции компонента.

Первый внутренний компонент может реализовать часть нормализованных классов,
пока публичные двери не переключены. Сам по себе он не доказывает full D1 и
не разрешает закрыть #1034/#1035. До переключения должны быть реализованы и
проверены перечисленные производители нормализации, управляющие capabilities,
writer serialization и совместимость D3/D5/#986. Удаление неподдержанного
компонента из нормализованного входа запрещено.

## 7. Наблюдаемые оракулы, держатели и завершение

Планируемый держатель обычных FB-сценариев:
`internal/apps/kaname/api/access_binding/full_bind_contract_integration_test.go`,
семейство `TestFullBind_FBxx`; Role и Group вызываются через реальные use-cases
того же мира. Сквозные проверки входного admission и формы отказа идут через
настоящий gRPC/HTTP listener. Эти держатели пока заказаны, не объявлены готовыми.
Прежние GD/GDU/ESC остаются самостоятельными держателями.

Для положительного исхода сначала проверяются сохранённые строки binding,
role rules или membership и терминальный Operation без error. Для отрицательного
исхода проверяются код/сообщение соответствующей стадии, отсутствие новой записи
и неизменность ранее действовавшего доступа. Затем отдельно спрашивается реальный
нижний порт: `relverdict.Ask`/`NewTransactionAsker` над PG с admitted plans.
Ожидаются точные Allow/Deny и nil error. Unknown/error не засчитываются как Deny.
Проверка последующего reconcile отделена от DURABLE-успеха API.

Гонки FB26–28 удерживаются детерминированными барьерами между decision и commit
двух настоящих writer-транзакций. Проверяются оба заданных порядка и выигравший
commit. Sleeps, поддельный authorizer и чтение на отдельном Reader не являются
свидетельством сериализации. Для FB28 второй порядок с обоими success допустим
по §3; он не объявляется пробой недостижимой recipient-sensitive политики.

Полный результат задачи требует одновременно:

1. Одобренного точного отпечатка этой полной приёмки и замысла нормализации,
   capabilities, writer serialization и совместимой миграции.
2. Всех FB-исходов с подтверждённым миром и названным настоящим оракулом, включая
   контролируемые ошибки backend и последние страницы. Разделённые сценарии
   и гонки не выдаются за 34 пары с одной сменой факта.
3. Прежнего домена доступа, GD/GDU/ESC на том же содержимом; намеренное изменение
   unused-role fallback ограничено D4, остальные утверждения не ослабляются.
4. Проверки mixed-version/migration: старый writer не может принять mutation
   по устаревшему правилу после включения нового контракта; чтение существующих
   выдач и разрешённые #986 lifetime/revoke свойства сохраняются.
5. Полного обычного хука публикации, канонического CI на точном SHA, слияния,
   успешного CI ветки main и собственного DoD каждой дочерней задачи. Локальный
   компонент, его unit tests или наличие PR этот результат не заменяют.
