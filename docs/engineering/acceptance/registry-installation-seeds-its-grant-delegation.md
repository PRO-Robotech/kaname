<!-- Copyright (c) PRO-Robotech; SPDX-License-Identifier: AGPL-3.0-or-later -->

# Приёмка: установка registry засевает доверенность выпускающему

> **Статус:** DRAFT
> **Статическая форма:** DRAFT; действующий вердикт задаёт внешнее ревью точного SHA-256.
> **История review:** первая редакция, вердикта нет.
> **Дата:** 2026-10-30
> **Правлено ПОСЛЕ объявления состояния/вердикта (2026-11-04, #1030):**
> добавлен абзац RID11 об удалении и отзыве ключа. Историческое exact-source
> одобрение редакции `09013f` и review `ca8a` не покрывают новые байты.
> Дополнительное ревью точного SHA-256 текущей редакции и current runtime pending;
> прежняя review-запись сохранена и не переобозначена.
> **Задачи:** PRO-Robotech/kaname#1038 (S1), #1030 (S2).
> **База переписи:** `092bee4fb3220215da255258dfa6fe0da9214f34`.

## Предмет и граница

S1 (#1038) — штатный installation seed производит одну доверенность выпускающему
registry в единственном аккаунте арендаторов. S2 (#1030) — объявление в манифесте
применяется к полному снимку всех аккаунтов арендаторов. Успех S1 не доказывает S2.
Это редакция 3 для нового fingerprint review, не реализация и не runtime proof.
База пересверки производителей: `f6e5856b416541603f88dfc93ccef3a05e0cf333`.
История дополнена: редакция 1 возвращена независимым ревью по восьми замечаниям;
редакция 2 также возвращена по B1/B3/B7. Редакция 3 исполняет принятое
диспетчером архитектурное решение; новый fingerprint требует отдельного одобрения.
Статическая шапка прежней редакции сохранена.

Не входят Update (#1032), Publish, новые потолки seed grants (#979), изменение
module writer (#1031), operator и Kacho. Не меняются миграция делегирований и #986
`delegated-grants-stay-within-the-delegation.md`: неизменные оси, авторитет creator,
отзыв delegation и сохранение уже выданных grants после потери авторитета creator.
Нормативные соседи: `module-manifest-seed-contract.md`,
`module-manifest-roles-and-seed-grants.md`, `service-manifest-seeds-its-own-groups.md`,
`module-manifest-relation-grant.md`. Новый публичный RPC не заказывается.

## Принятые решения и заказанная дельта startup

Q2/Q3 сохраняются: полный canonical snapshot в начале delegation stage,
исключение канонического system account, будущие аккаунты — следующий apply;
обычный reinstall не отменяет Revoke, новое намерение — явный Create от C.
C — отдельная долговременная cloud-admin SA; I никогда не получает cloud-admin.
Эти решения зафиксированы первичным независимым возвратом редакции 1.

Диспетчер принял для редакции 3 следующий порядок #1038/#1030. Это **заказанная
реализация**, а не утверждение, что нынешний startup уже умеет аутентифицировать C:

1. Чистый standalone base БЕЗ registry delivery становится ready. Он применяет
   только обычный own seed; I/registry model/delegation отсутствуют. Уполномоченный
   независимый O штатными API создаёт C, выдаёт cloud-admin и KEYPAIR. Это явное
   исходное provisioning установки, не действие повторного seed.
2. Установка останавливает base и повторно входит в СУЩЕСТВУЮЩИЙ `kaname serve`
   с полной доставкой и защищённым credential C. Нового CLI или публичного RPC нет;
   новый live Publish, post-ready подмена модели и GD-only сокращение не вводятся.
3. До ЛЮБОЙ записи ПРИМЕНЕНИЯ доставки загрузить и strict-validate все manifests,
   форму, linkage, оси и принадлежность модулю по полной in-memory доставке.
   Чистые Compose/Admit допустимы здесь. Затем настоящая authentication C и её
   текущая authority через заранее подготовленные общие production dependencies.
   До успеха этой границы нельзя мутировать/install модель доставки, каталог,
   роли, own/delivered seed, SA/groups/joins/grants/delegation.
4. После успешного preflight установить admitted model до первого её рабочего
   читателя, применить existing catalog/roles/own+delivered seed механизм и общий
   delegation stage с существующими Create/authority usecases и normal operations.
   I впервые создаётся именно этим full startup. На каждой паре authority C
   проверяется снова, в том числе на уже точной ACTIVE паре.
5. Production readiness/success только после обязательного stage. Ошибка stage
   завершает startup неуспешно. Следующий startup повторяет весь preflight с тем
   же standing credential, без создания C/key/admin grant заново.

Далее «apply», «повтор установки» и «повтор run» означают этот full startup
/re-entry существующего serve с полной доставкой, а не live mutation работающей
модели. Идемпотентные повторы/другой manifest проверяются на следующем startup.

Защищённый input добавляется в СУЩЕСТВУЮЩУЮ конфигурацию Kaname
(`KANAME_CONFIG_PATH`): секция `moduleSeedInstaller` содержит `credentialFile`,
для S1 один `tenantAccountId`, для S2 — canonical census вместо входного списка.
Файл содержит только `clientId` и `privateKeyPem` из однократного Issue C;
доступ — installation process, 0600 либо эквивалентный ограниченный Secret mount.
Principal/creator ID не задаётся конфигурацией; C определяется проверенной строкой
реестра. Ключи/токены не попадают в argv, manifest, отчёты или диагностику.

Нужный startup authentication adapter — заказ #1038. Он переиспользует общую
сборку `clienttokenwire.New/FromPool`, `clientassertion.Verifier.Verify`, настоящий
client-token issuer и штатный собственный authn front door над подготовленными
production dependencies. Adapter формирует свежее assertion по F5, получает
проверенный Result.Client, проходит настоящий issuer/обычную проверку выпущенного
credential и получает principal из этой проверки; затем существующий authority
judge проверяет C. Источник principal — проверенное удостоверение, не config ID.
Прямой `operations.WithPrincipal(C)` из config, копия verifier, новый authn bypass
и замена KEYPAIR на module mTLS запрещены. Слушатель этого процесса пока не поднят:
для renewal нельзя обращаться по сети к собственному ещё выключенному endpoint.
Вынесение общей prepared-service сборки раньше — явная требуемая дельта композиции,
а не новый verifier/новый token endpoint. Сетевой public token flow остаётся для
обычных клиентов после ready; правила assertion/issuance в обоих входах одни.

KEYPAIR — существующий SA flow; долгоживущая C не означает вечный access token.
Истёкший access token при действующем standing key обновляется тем же shared
production путём без повторных Create/GrantAdmin/Issue. Module mTLS W остаётся
существующим транспортным/registration credential и не становится C.

Provisioning O использует разрешённый gateway-fronted маршрут действующего admin
API: O предъявляет свой проверенный credential, api-gateway выполняет authn/ReBAC
и вызывает internal admin RPC как разрешённая gateway SA. Произвольный module cert
напрямую к internal GrantAdmin не является этим путём. Internal RPC не появляются
на external listener Kaname; адреса/CA/SAN берутся из существующей установки.

Гарантия «ничего не записано» относится к persistent DELIVERY writes перечисленных
сущностей, включая persistent model state, если такое есть. Штатное погашение jti,
authentication replay/rate/audit bookkeeping и проверенный authn/operations след
не объявляются отсутствующими DB writes. Их разрешённое отдельное изменение не
разрешает catalog/roles/seed/delegation до успешного preflight и не скрывает
частичную мутацию доставки. Новая публичная модель или storage policy не вводятся.

Опоры пересверки: `cmd/kaname/model_compose.go:installComposedModel`,
`cmd/kaname/client_token.go:clientTokenBuildConfig` (ExpectedAudience=signer.Issuer),
`internal/clienttokenwire/build.go:New/FromPool`,
`internal/clientassertion/verifier.go:Verify/admit`,
`cmd/kaname/wiring.go` (существующие delegation usecases),
`cmd/kaname/serve.go` (GatewayFrontedInternalRPCs). Координаты — существующие seams;
сам startup adapter ещё не реализован. До fingerprint APPROVED кода не писать.

## Производители

| ID | Существующий производитель на базе пересверки (api = internal/apps/kaname/api) | Заказанная дельта |
|---|---|---|
| P1 | `cmd/kaname/module_seed_apply.go:applyModuleSeed`, `internal/apps/kaname/moduleseed/apply.go:Apply` | existing serve: full-delivery preflight и prepared authentication перед install/write, общий seed/delegation stage #1038 |
| P2 | `internal/manifest/manifest.go:Seed`, `internal/manifest/linkage.go`; каталог/роли в startup | форма D2 и preflight ВСЕЙ доставки до её записей #1030 |
| P3 | `api/grant_delegation/create.go:Execute`, `authority.go:requireAccountGrantAuthority`, pg delegation repo | вызвать существующие authn/authority/write пути, не синтезировать creator |
| P4 | ServiceAccountService, SAKeyService, InternalClusterService, существующий client token endpoint | защищённый input C и prepared shared startup adapter; provisioning через existing gateway-fronted admin; RPC не меняются |
| P5 | Account.Create и pg account reader; system identity из общего seed resolver | canonical snapshot с полным обходом страниц #1030; не публичный scope-filtered List |
| P6 | GrantDelegation.Get/List/Create/Revoke; AccessBinding.Create/Get; Operation.Get | публичные наблюдатели остаются существующими |

Ни P1, ни Writer на этой базе пока не производят install delegation. Имена будущих
проб ниже являются заказом, а не утверждением, что такие функции уже существуют.

## Договор D1–D6

**D1. Личности и authority.** O — независимый действующий system-admin пользователь,
не C/I/bootstrap, сохраняющий authority и доступ к чтениям после retirement C.
C — новая SA `registry-installer` в каноническом system account, cloud-admin;
I — посеянная SA `svc-registry`, только issuer; W — штатная module identity registry,
имеющая уже принятый module registration path. O один раз provision C через API.
Обычный apply только аутентифицирует C и проверяет её текущее право, в том числе
когда точная ACTIVE пара уже есть. Он не вызывает GrantAdmin и не создаёт C заново.
Потеря C права запрещает новые делегированные выдачи, но не меняет ACTIVE старых
выдач и delegation (#986 GD-20). O не получает права из C и не исчезает вместе с ней.

Здесь «cloud-admin C» имеет конкретный существующий смысл: GrantAdmin с
`subjectType=SERVICE_ACCOUNT, subjectId=C` пишет через `systemAdminTuples` факт
`service_account:C` / `system_admin` / `cluster:cluster_root` в том же transaction
journal, что grant. После материализации **реальный** `authzguard.IsClusterAdminE`
на проверенном C спрашивает ровно этот flat relation через production store.
F3 требует не только Operation/ListAdmins, но и true этого guard. Создание GD
пользуется тем же вопросом (`grant_delegation/authority.go`), а не новым названием
права. RevokeAdmin отзывает тот же typed subject; после материализации guard C
false и новая выдача запрещена по #986. O при GrantAdmin/RevokeAdmin также должен
пройти действующий system_admin gate; gateway SA — разрешённый transport caller,
она не подменяет principal O и не является creator C. Это existing production
эффект, не добавление permissions/отношений. Опоры: `api/cluster/helpers.go:77`,
`grant_admin.go:doGrant`, `admin_authz.go:requireClusterSystemAdmin`,
`internal/authzguard/cluster_admin_shortcircuit.go:IsClusterAdminE`,
`api/grant_delegation/authority.go:requireAccountGrantAuthority`.

**D2. Закрытая форма S2.** Новый `seed.grantDelegations` — массив. Каждый элемент:
`delegate: {account: system, name: <имя собственной seed.serviceAccounts>}`,
`roleIds`, `targetTypes`, `subjectTypes`. Иных полей нет: accountId, delegatedBy,
module, status, allInScope и произвольный scope не принимаются.
Модуль — содержащий manifest, роли — его объявленные role IDs, типы — его dotted
catalog types, не iam. Role IDs разрешаются по объявленным именам доставленных ролей,
проверяются по полному доставленному каталогу, не подменяются константой пробы.
`roleIds` и `targetTypes`: 1…16, `subjectTypes`: 1…4. Порядок несемантичен;
дубликат в ЛЮБОЙ оси отвергается до записей, не нормализуется.
Допустимы ровно `SUBJECT_TYPE_USER`, `SUBJECT_TYPE_SERVICE_ACCOUNT`,
`SUBJECT_TYPE_GROUP`, `SUBJECT_TYPE_SYSTEM_CLASS`; UNSPECIFIED/неизвестное запрещены.
SYSTEM_CLASS в делегированной выдаче означает только `anonymous` по #986, не
`authenticated`. Отсутствие grantDelegations и `[]` — два законных варианта без
delegation stage. Пустая ось, неизвестное поле, чужие роль/тип/delegate — отказ.
S1 принимает тот же закрытый элемент из явно доставленного registry manifest
посредством installation input; S2 делает его общей формой seed всех manifests.

**D3. Порядок и census.** На re-entry существующего serve сначала загрузить и проверить ВСЮ доставку: own manifest,
все delivered manifests, все оси и связи. Невалидность любого позднего manifest
запрещает любые новые записи применения всей доставки: каталог, роли, own seed,
SA, группы, joins, grants, delegation. Ранее существовавшие ресурсы остаются.
До любых новых DELIVERY записей также проверяются input, настоящая authentication C и её
текущая authority через подготовленный shared production путь; после этого install
admitted model, каталог/роли, own seed, SA модулей и delegation. Authn bookkeeping
отделён от delivery guarantee как описано выше.
Перед каждой парой authority проверяется снова, включая точную существующую пару. S1 требует один явный ID
существующего tenant account: ноль, несколько или canonical system — отказ input;
несуществующий ID — отказ до первой записи.
S2 фиксирует membership snapshot в начале delegation stage из канонического pg
источника, обходит все страницы по ID. System ID получается тем же seed identity
resolver, что обслуживает `domain.SystemAccountName` и его действующее окно имён;
исключается ровно этот ID. Неоднозначный/отсутствующий system resolver — ошибка,
не произвольный выбор. Tenant `system-tenant` остаётся tenant. Полный census не
строится из публичного Account.List, видимость которого зависит от caller.
N=0 допустим лишь после успешного полного snapshot, включая все страницы.

**D4. Идемпотентность и Revoke.** Точная ACTIVE пара (account,I) от C с теми же осями
сохраняет id/createdAt, в том числе при перестановке осей. Другие оси или creator
дают конфликт без Update/Revoke/замены. Только REVOKED история не реактивируется
и не заменяется обычным apply; он даёт конфликт. После явного Create от C новая
точная ACTIVE пара может быть принята apply; старая история/старые grants остаются
REVOKED. Apply, начавшийся до явного Revoke, также не создаёт replacement после него.

**D5. Конкуренция и сбой.** Для валидной доставки runtime fault может оставить уже
committed пары; весь запуск неуспешен. Повтор при восстановленном input доводит
snapshot до N, сохраняя ID завершённых пар. Два apply на одной отсутствующей паре
сходятся к одной ACTIVE записи; конфликт уникальности проигравший перечитывает:
точное ACTIVE совпадение — успех, другое/REVOKED — конфликт. Существующий DB invariant
unique active pair обязателен. Потеря authority C между парами запрещает последующие
записи, не отзывая старые delegation/grants. Полномочия не кэшируются на весь apply.

**D6. Будущие accounts.** Account, созданный после фиксации snapshot, не включается
в текущий run; следующий apply включает его и сохраняет прежние IDs. Account.Create
не запускает watcher. Это принятая граница Q2, не обещание непрерывного provisioning.

## Воспроизводимый мир F-RID

F-RID — заказываемая fixture последовательность на отдельной установке Kaname,
с настоящими production API/клиентами и доставкой Kaname fixture manifest.
O — собственный аутентифицированный пользователь isolated stand с действующим
system_admin (штатный bootstrap/setup установки), A/B/D принадлежат O: он вызывает
Account.Create сам, `ownerUserId` не подставляется. Проверка bootstrap/system-admin
O — обязательный precondition receipt, не подмена principal. После старта fixture
нет прямых SQL insert C/I/delegation/grants и нет fake authz. Динамические IDs берутся
из ответов. Все Operation поллятся до done=true без error; затем делается Get.

| Шаг / principal | Точный вызов или input | Полученный ID / проверка |
|---|---|---|
| F0 / installation | чистая standalone base-ready установка без registry delivery; собственный own seed штатно применён; сохранить system account ID общего resolver; проверить независимого O через разрешённый gateway-fronted InternalCluster.ListAdmins | SYS, O; C/I/registry model/delegations ещё нет; bootstrap и действующий credential O — явные исходные inputs собственной установки |
| F1 / O | Account.Create `{"name":"rid-a"}`; для S2 также `rid-b`, `system-tenant` | A,B,T из response; O owner каждого |
| F2 / O | ServiceAccount.Create `{"accountId":"${SYS}","name":"registry-installer"}` | C=response.id, C≠bootstrap и C≠I |
| F3 / O через gateway-fronted admin, затем internal gateway SA | InternalClusterService.GrantAdmin `{"subjectType":"SERVICE_ACCOUNT","subjectId":"${C}"}`; Operation/Get/ListAdmins до материализации | C active system_admin на singleton; отдельный реальный IsClusterAdminE под проверенным principal C даёт true после материализации; O остаётся независимым admin |
| F4 / O | SAKeyService.Issue `{"serviceAccountId":"${C}","credentialKind":"CREDENTIAL_KIND_KEYPAIR","ttlSeconds":"${K}","name":"rid-c"}` | одноразовые clientId/privateKeyPem/key.id в защищённый fixture store; не отчёт |
| F5 / C standing key, prepared startup path | остановить standalone base; re-enter existing serve с полной delivery/config C; startup adapter предъявляет shared Verifier/issuer то же стандартное assertion F5a ниже, без HTTP к выключенному собственному listener | настоящий проверенный principal C из shared production flow, текущая authority подтверждена; до этого нет delivery writes и нет I; authn bookkeeping отдельно |
| F6 / аутентифицированная C, тот же full serve startup | после successful wholebatch+authn+authority preflight: install model, existing catalog/roles/own+delivered seed, shared GD stage; S1 один A + registry declaration, S2 полный snapshot; готовых I/delegation в setup нет | впервые создан I; readiness только после stage; после ready O Get/List SA в SYS и P6 подтверждают I/delegation IDs |
| F7 / O | ServiceAccount.Create `{"accountId":"${A}","name":"rid-u"}`, Project.Create `{"accountId":"${A}","name":"rid-project"}` | U, P; не I/C; для denial выдачи отдельные U2/U3 тем же Create |
| F8 / O | SAKey.Issue для I тем же KEYPAIR payload, serviceAccountId=I, name=rid-i; получить token через public endpoint по F5a после ready | credential I без GrantAdmin I |
| F9 / W, internal | InternalIAMService.RegisterResource `{"subjectId":"user:${O}","relation":"owner","object":"registry_registry:rid-registry","parentProjectId":"${P}","parentAccountId":"${A}","parentChain":["project:${P}","account:${A}"]}` | registration X через существующий W module mTLS path; O читает зеркало/проверяет разрешённый объект перед RID-03 |
| F10 / I, public | AccessBinding.Create `{"subjectType":"service_account","subjectId":"${U}","roleId":"${Rpull}","scopeType":"iam.account","scopeId":"${A}","target":{"resources":{"resources":[{"type":"registry.registries","id":"rid-registry"}]}}}` | G=Operation.response.id; Get G: ACTIVE, delegationId=созданный install delegation ID |

**F5a — точный существующий assertion/issuance контракт для F5 и F8.**
F4/F8 задают `CREDENTIAL_KIND_KEYPAIR` по `credential_kind.proto`; сохраняются
clientId/privateKeyPem/keyId из Issue. Подписанное ES256 assertion имеет header
`alg=ES256`, `kid=keyId`, обязательный `typ=client-authentication+jwt`
(`tokenpolicy.TokenTypeClientAssertion`). Claims: `iss=clientId`, `sub=clientId`,
`aud=signer.Issuer()` установки — НЕ URL token endpoint; обязательные NumericDate
`iat=now`, `exp=iat+min(60s, tokenpolicy.MaxAssertionLifetime)` при положительном
остатке standing key; свежий `jti`, непустой и не длиннее
`domain.MaxAssertionIDLength=256`, никогда не повторяется для этого client.
Реальный verifier проверяет подпись, owner/key state, время/clock skew, replay,
revocation и остальную production policy; fixture их не выключает.

Стандартный form для public `/iam/v1/token` после ready:
`grant_type=client_credentials`,
`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
(`tokenpolicy.ClientAssertionType`), `client_assertion=<F5a assertion>`.
Request `audience` отдельно выбирается из разрешённых key/installation audiences
для получаемого access token и фиксируется как несекретное значение fixture;
он НЕ assertion aud и не переносится из assertion. F5 prepared adapter использует
те же поля и shared pipeline до подъёма listener, F8 — настоящий public endpoint.
При обновлении token новые iat/exp/jti, тот же standing key; не повтор F2/F3/F4.
В fixture срок standing key K выбирается разрешённым и больше срока access token,
чтобы вариант expired access/live key был достижим, а не двумя одновременно
истёкшими credentials; числовой K фиксируется в несекретном input receipt.

Source anchors: `cmd/kaname/client_token.go:108–117`;
`internal/clientassertion/verifier.go:427–458,597–675`;
`internal/domain/client_assertion.go:ValidateAssertionID`;
`corelib/tokenpolicy` закреплённой go.mod версии (typ/assertion type/max lifetime).
Никакого нового формата assertion или guessed endpoint audience не заказывается.

Registry declaration F6 берётся из Kaname
`internal/manifest/testdata/registry.delegation-fixture.yaml` (роли `registry.puller`,
`registry.pusher`, `registry.admin`, типы `registry.registries/repositories`).
К исходному Kaname документу применяется существующий adapter
`internal/testsupport/publicreadfixture.WithWrites`: на registries/repositories
`writes: [{relation: owner, subjects: [user, service_account]}]`. Это тот же
законный owner-registration input, что у #986; raw fixture без writes не
засчитывается как мир F9. Затем в fixture delivery добавляются `seed.serviceAccounts: [{account: system, name: svc-registry}]`
и закрытый элемент D2: delegate system/svc-registry, roleIds=[Rpull],
targetTypes=[registry.registries], subjectTypes=[SUBJECT_TYPE_SERVICE_ACCOUNT].
Rpull/Rpush/Radmin — фактические Role.Get IDs по именам доставленного manifest,
не выдуманные ID. Registry writer W берётся из действующей isolated stand module
roster/credential fixture #986; установка без этого законного production input
не считается исполненным RID-03. Модуль W не получает новых прав в #1038.
Пробы authn/registration не ослабляются ради install proof.

Для RID-09 доставляются M1=эта registry fixture с отсутствующими seed SA `svc-registry`,
группой `registry-rid-readers`, join SA в СУЩЕСТВУЮЩУЮ чужую группу
Kaname `module-relation-writers` и собственным role grant группе (точная форма ниже); M2 — отдельный fixture module `ridaux` с собственными
catalog resource/role/SA/group/grant и D2. Полные manifests являются fixture входом
пробы и проходят общий loader; их снимки и bytes SHA обязательны. Ошибка M2 —
единственная замена собственного roleId на Rpull registry. Близнец возвращает
собственный roleId M2; проверяются оба порядка M1/M2. Fixture конструктор
`RIDDeliveryFixture` заказывается в #1030; непредъявленные manifests не считаются
доказанной конструируемостью или исполненным прогоном.

Точный seed M1 (roleId — объявленное имя роли, обычный seed resolver):

```yaml
seed:
  serviceAccounts:
    - {account: system, name: svc-registry}
  groups:
    - {account: system, name: registry-rid-readers}
  accessBindings:
    - subjects: [{type: group, name: registry-rid-readers}]
      roleId: registry.puller
      scopeType: iam.cluster
      scopeId: cluster_root
      target: allInScope
  joins:
    - serviceAccount: {account: system, name: svc-registry}
      group: {account: system, name: module-relation-writers}
      why: Existing registry registration path of the isolated fixture
  grantDelegations:
    - delegate: {account: system, name: svc-registry}
      roleIds: [registry.puller]
      targetTypes: [registry.registries]
      subjectTypes: [SUBJECT_TYPE_SERVICE_ACCOUNT]
```

M2 — полный самостоятельный manifest; legal bytes ниже, invalid twin меняет
ТОЛЬКО `seed.grantDelegations[0].roleIds[0]` с `ridaux.reader` на `registry.puller`.
Для иных осей RID-09 тот же принцип одной замены. Системная группа вступления
принадлежит own manifest Kaname и уже существует в F0; M1/M2 её не создают.

```yaml
apiVersion: iam/v1
module: ridaux
resources:
  - name: objects
    objectType: ridaux_object
    parents: [project]
    producer: derived
    verbs:
      - {name: get, from: [super_admin]}
      - {name: list, from: [super_admin]}
roles:
  - id: ridaux.reader
    tier: {tierType: iam.cluster, tierId: cluster_root}
    rules:
      - module: ridaux
        resources: [objects]
        classes: [get, list]
seed:
  serviceAccounts:
    - {account: system, name: svc-ridaux}
  groups:
    - {account: system, name: ridaux-readers}
  accessBindings:
    - subjects: [{type: group, name: ridaux-readers}]
      roleId: ridaux.reader
      scopeType: iam.cluster
      scopeId: cluster_root
      target: allInScope
  joins:
    - serviceAccount: {account: system, name: svc-ridaux}
      group: {account: system, name: module-relation-writers}
      why: Fixture joins the existing module writer mechanism
  grantDelegations:
    - delegate: {account: system, name: svc-ridaux}
      roleIds: [ridaux.reader]
      targetTypes: [ridaux.objects]
      subjectTypes: [SUBJECT_TYPE_SERVICE_ACCOUNT]
```

Форма нового элемента D2 сохраняет объявленные имена roleIds; adapter разрешает
их в IDs P6 по ролям именно загруженного manifest. Другой способ интерпретации
roleIds не выбирается незаметно. Для нормальной пары payload существующего RPC:
`GrantDelegation.Create {accountId:A,delegate:{type:SUBJECT_TYPE_SERVICE_ACCOUNT,id:I},
roleIds:[Rpull],targetTypes:[registry.registries],subjectTypes:[SUBJECT_TYPE_SERVICE_ACCOUNT]}`.
У I тот же credential, что в F8; у C — F4/F5, у O — независимый начальный credential.
Явные Revoke в RID-05/06: `{grantDelegationId:<P6.id>}`; читается Get с тем же ID.
Для проверки creator conflict C-other создаётся как F2/F3/F4 с другим name;
C меняется на C-other только в caller Create, остальные поля совпадают.

O читает все страницы P6 (pageSize=2 в пробах census), затем Get каждой записи;
также SA/groups/joins/grants/catalog/roles через штатные чтения, internal consequence
без публичного API — через read-only integration snapshot. ACTIVE считается по
каждой паре, REVOKED история отдельно. Mutation RPC refusal проверяет synchronous
status без Operation либо done Operation.error — ровно тот слой, который обещает
существующий RPC; installer ошибки не объявляются новыми RPC ошибками.

## Наблюдаемый результат installation apply

Installation input исполняет existing `kaname serve`. Успех run означает
production readiness после полного обязательного stage; в пробе процесс затем
штатно останавливается и имеет exit0. Обозначение «run exit0» ниже включает ОБА
утверждения, а не выход долгоживущего server сразу после apply. Startup refusal
даёт exit1 и отсутствие readiness. Concurrent runs имеют разные собственные
listener addresses, общую проверяемую DB и обязательный startup stage каждый.
Безопасный структурный результат имеет `stage`, `code`, `field` либо `accountId` и
`delegateId`, `completedPairs`. Код — существующее имя статуса или названный ниже
input class; секреты/токены/SQL/driver text отсутствуют. Это заказанный структурный startup result, не
новая команда или RPC; raw startup refusal также сохраняется в evidence. Failure никогда не превращается в success с N=0.

| Вариант | До запуска / единственный изменённый факт | code / координата / отсутствие дельты |
|---|---|---|
| RID-06 | только REVOKED история пары | FAILED_PRECONDITION, stage=delegation, pair; нет replacement/реактивации |
| RID-07 | ACTIVE с иной одной осью или creator | FAILED_PRECONDITION, stage=delegation, pair; ID/оси/grants неизменны |
| RID-09 | неверная ось M2 | INVALID_ARGUMENT, stage=preflight, field=manifests[1].seed.grantDelegations[0].roleIds; ноль записей всей доставки; при перестановке field указывает новый индекс |
| RID-11.input | credentialFile отсутствует/нечитабелен | INSTALL_INPUT_INVALID, stage=input, field=credentialFile; ноль writes и auth RPC |
| RID-11.authn | C удалён, ключ отозван, либо неверна подпись (отдельные варианты) | UNAUTHENTICATED, stage=authentication; shared verifier/issuer refusal не раскрывает причину C; публичный token twin после ready даёт штатно HTTP401 `invalid_client`; 0 delivery writes, replay/audit bookkeeping не приравнивается к delivery |
| RID-11.authz | действующий credential C, но authority отозвана до delivery writes | PERMISSION_DENIED `permission denied`, stage=preflight-authority, field=moduleSeedInstaller.credentialFile; 0 delivery writes; I ещё не создаётся и выдуманный delegateId не печатается |
| RID-11.account | S1 A отсутствует при действующем C | NOT_FOUND от Account.Get, stage=input, field=tenantAccountId; нет writes |
| RID-11.backend | production authz check C недоступен на общей prewrite границе | UNAVAILABLE `authz backend unavailable`, stage=preflight-authority, field=moduleSeedInstaller.credentialFile; completedPairs=0, 0 delivery writes; новый I отсутствует |
| RID-11.census | Reader BeginTx второй страницы возвращает свежий unknown non-sentinel error при живом контексте; не timeout/cancellation | INTERNAL `internal error`, stage=census, field=accounts; completedPairs=0, нет writes delegation; это не N=0 и не выдуманный UNAVAILABLE |
| RID-10.storage | после успешной первой пары и создания Operation второй пары Writer BeginTx возвращает тот же unknown non-sentinel error при живом контексте | INTERNAL `internal error` в Operation.error второй пары, stage=delegation, completedPairs=1; первая сохранена, вторая не создана |
| RID-12 | invalid shape/axes | INVALID_ARGUMENT, stage=preflight, точный field элемента/оси; ноль записей всей доставки |

Для RID-10.storage производитель текущего исхода: Create.Execute сначала
`opsRepo.Create`, затем normal `operations.Run` вызывает doCreate;
`shared.DoWithWriteTx` маппит unknown Writer/BeginTx error при живом контексте
через `MapRepoErrAt` в INTERNAL `internal error`. Поэтому Create возвращает
Operation, а failure наблюдается в её error, не как synchronous RPC refusal.
RID-11.census инъецирует unknown error в чтение snapshot до delegation Create:
startup result INTERNAL, delegation Operation ещё нет. Fault не несёт секретов
и не сериализуется на провод; сырой driver text не появляется. Это конкретная
fixture-инъекция текущего mapping, не новая классификация всех storage failures.
Authz backend fault по-прежнему отдельный UNAVAILABLE `authz backend unavailable`
через существующий authority judge. Остальные реальные storage failures нельзя
молча переименовать в UNAVAILABLE. Нельзя применять rollback к committed первой
паре только потому, что вторая завершилась INTERNAL.

Для отказа пер-парной authority ПОСЛЕ successful preflight (RID-10 retirement)
координата уже существующей пары — accountId/delegateId, stage=authority.
Для общей границы до создания I используется field, а не выдуманный ID.

RID-11 authority/authn/backend повторяются и на пустой паре, и на уже точной ACTIVE;
совпавший ID не разрешает обойти текущую authentication/authority C.
Нуль writes означает отсутствие новой DELIVERY дельты относительно указанного снимка;
погашение jti/authn replay/audit и normal operations bookkeeping считаются отдельно;
не означает удаление ранее существовавших пар/seed. Mid-run fault относится к RID-10,
не к обещанию rollback уже committed валидной доставки.

## Сценарии

### RID-01 — чистая установка и standing credential (S1)
**Given** чистая F0 без C/I/delegation, O действует независимо.
**When** выполнить F1…F4 через настоящие API, остановить standalone base и пройти
F5/F6 существующим full serve startup с полной delivery и protected C key.
**Then** ровно одна ACTIVE пара (A,I), delegatedBy={type:service_account,id:C},
точные D2 оси; C/I/A существуют и разные, I не cloud-admin.
**And** перезапустить Kaname, дождаться истечения access token C при ещё действующем
standing key, повторить F5/F6: новый токен, прежние C/I/A/delegation ID и createdAt,
число SA/admin grants/key credentials не выросло. Истёкший standing key — отказ,
близнец с действующим ключом отличается только его сроком, не новым admin grant.

### RID-02 — повтор и настоящая конкуренция (S1/S2)
**Given** F-RID, отдельно свежий мир без пары и без REVOKED истории.
**When** повторить F6 последовательно с перестановкой осей; затем на свежем мире два
apply довести управляемым barrier до попытки одной отсутствующей пары, подтвердить
прибытие ОБОИХ, освободить barrier и дождаться обоих результатов.
**Then** оба run exit0; ровно одна ACTIVE пара от C; повтор сохраняет id/createdAt.
Реальная DB uniqueness и перечитывание проигравшего обязательны, sleeps не заменяют
barrier. Контроль fixture без overlap не засчитывается как concurrency.

### RID-03 — выдача через production listener, issuer не администратор (S1/S2)
**Given** F0…F9; I без cloud-admin, account admin и самостоятельного права выдавать.
**When** выполнить F10, затем тот же payload для U2 с roleId=Rpush вне roleIds;
отдельно I пытается GrantDelegation.Create на другом существующем account.
**Then** F10 Operation done без error, Get G ACTIVE/delegationId=install ID;
выдача Rpush — PERMISSION_DENIED `permission denied`, нового binding нет;
Create от I — такой же отказ без Operation. Близнец role denial меняет только
roleId на Rpull (для того же U2); близнец Create меняет только caller I на C.
Вариант SYSTEM_CLASS: при разрешённой оси `anonymous` успешен, `authenticated`
отвергается #986; это не новые system classes. Credentials/registration failure
не засчитываются как ожидаемый authorization refusal.

### RID-04 — retirement creator (S1/S2)
**Given** RID-03 с ACTIVE G; C не owner tenant и не account admin, O независим.
**When** O через разрешённый gateway-fronted admin маршрут вызывает InternalCluster.RevokeAdmin `{subjectType:SERVICE_ACCOUNT,subjectId:C}`,
поллит Operation/ListAdmins до наблюдаемого отзыва; I делает новую выдачу U2,
затем повторить apply с действующим ключом C.
**Then** новая выдача и apply — PERMISSION_DENIED `permission denied`; G/delegation
остаются ACTIVE по #986 GD-20; admin C не восстановлен, replacement отсутствует.
Близнец: только O через тот же gateway-fronted маршрут явно восстанавливает GrantAdmin C; после материализации тот же
запрос U2 успешен и delegationId прежний.

### RID-05 — удаление C и новый ID (S1/S2)
**Given** RID-04, O остаётся действующим admin. O отзывает ВСЕ ключи C через
SAKey.Revoke `{serviceAccountId:C,keyId:<каждый List.id>}` и поллит операции;
проверяет отсутствие иных ACTIVE ссылок C как delegate/subject/group member
(полный SAKey.List, P6 List/Get, AccessBinding.List с subject C, GroupService.ListMembers
по группам fixture); никаких дополнительных выдач/членства C эта fixture не создаёт.
У C только revoked admin grant и исторический delegatedBy; I жив.
**When** O ServiceAccount.Delete `{serviceAccountId:C}`, поллит done/Get NOT_FOUND;
I пытается новую выдачу, apply использует прежний credential C; затем O создаёт
C2 с тем же name и новым ID, но без переноса authority/delegation.
**Then** новая выдача PERMISSION_DENIED, apply UNAUTHENTICATED; G остаётся ACTIVE,
delegatedBy=старый C; C2 не оживляет старую доверенность. Не требуется отзывать
старую delegation ради Delete creator. Отдельный deletion negative: одна ACTIVE
ссылка C как delegate блокирует Delete: возвращённая Operation завершается
FAILED_PRECONDITION с `service account ${C} holds an active grant delegation ${D}; revoke it first`;
законный близнец отзывает только D штатным Revoke и затем Delete успешен.
Близнец восстановления: O через gateway-fronted admin выполняет GrantAdmin C2,
затем Issue C2, Revoke старой delegation,
явный Create от C2, затем I делает новую успешную выдачу; старая история REVOKED.
Это явное новое намерение, а не автоматическое следствие совпадения name.

### RID-06 — Revoke и уже начавшийся reinstall (S1/S2)
**Given** RID-03 с G; apply остановлен barrier непосредственно перед create/re-read
пары. O завершает GrantDelegation.Revoke старого ID до освобождения apply.
**When** освободить barrier и закончить run; отдельно обычный sequential reinstall.
**Then** оба отказывают как таблица результатов; старые delegation/G REVOKED,
G.reason=REVOCATION_REASON_DELEGATION_REVOKED, новых ACTIVE нет. Близнец overlap
убирает только Revoke и сохраняет ID. Отдельный recovery twin: C явно Create
новую пару, apply принимает новый ID, новая выдача I проходит, старая история
не меняется. Начало apply до Revoke не считается согласием на replacement.

### RID-07 — конфликт существующей пары (S1/S2)
**Given** F-RID с ACTIVE парой, отдельные варианты: изменён ровно roleIds,
targetTypes, subjectTypes либо delegatedBy другого уполномоченного C-other;
состав каждого варианта сам по себе законен #986.
**When** apply исходной D2.
**Then** FAILED_PRECONDITION/exit1 на паре, прежние ID/createdAt/оси/creator/grants
сохранены. Близнец каждого меняет только отличавшуюся ось/creator в fixture
исходной пары и получает точное совпадение RID-02. Update/Revoke для сходимости нет.

### RID-08 — полный snapshot и граница будущего account (S2)
**Given** A,B,T=system-tenant, отдельно canonical SYS; pageSize=2, N=3.
**When** canonical snapshot полностью зафиксирован; barrier до первой delegation;
O создаёт D=`rid-d`, освобождает apply. Повторить apply после его завершения.
**Then** первый run ровно N=3 ACTIVE, включая T, исключая SYS/D; второй N+1=4,
все прежние id/createdAt сохранены. Все страницы P6 сверены. Отдельные варианты:
полный успешный census N=0 даёт exit0/0; точный unknown-error отказ
Reader BeginTx второй страницы snapshot до delegation записи даёт INTERNAL/exit1 и 0 новых delegation, а не success/N=0. Близнец late-page
fault убирает только fault; после восстановления повтор сходится к N без дублей.
Публичный List с ограниченной видимостью C не подменяет canonical census.

### RID-09 — вся доставка атомарно отвергается до записей (S2)
**Given** RIDDeliveryFixture: M1 полностью законный с отсутствующими ресурсами,
M2 с одной неверной осью. O фиксирует полный снимок catalog/roles/own seed/
SA/groups/joins/grants/delegation во всех accounts, не только P6.
**When** apply [M1,M2], затем на свежем идентичном мире [M2,M1]. Отдельные неверные
оси: чужая роль, чужой targetType, запрещённый subjectType, чужой delegate.
**Then** exit1 INVALID_ARGUMENT с конкретным field; ВСЕ перечисленные снимки
неизменны в обоих порядках, включая каталог/роли/own seed; нет частичного M1.
Близнец каждой ошибки исправляет только её одну в M2, остальной payload побайтово
тот же: exit0, ресурсы обоих manifests и все N пары доступны O. Это preflight
заказанной дельты, не новая глобальная транзакция runtime apply.

### RID-10 — fault и retirement между парами (S2)
**Given** N=3, валидная доставка; barrier: первая пара committed и наблюдаема O,
следующая попытка ещё не началась, completedPairs=1.
**When** отдельно (a) после создания normal Operation второй пары вернуть из
Writer BeginTx свежий unknown non-sentinel error с ещё живым контекстом,
без cancellation/deadline/ErrUnavailable; (b) O через gateway-fronted маршрут
завершает RevokeAdmin C и материализацию до второй пары; освободить barrier.
**Then** run exit1, (a) INTERNAL `internal error` в done Operation.error второй
пары; (b) PERMISSION_DENIED `permission denied` синхронно без новой Operation; после восстановления
источников ровно первая пара сохранена, следующих нет; прежние G не отозваны.
Для (a) убрать только fault и повторить; для (b) O явно восстанавливает только
admin C, затем повторить: N пар, первая id/createdAt прежние. Близнец каждого
варианта убирает только fault/revoke и за один run получает те же N. Barrier и
read receipts доказывают границу, ожидание по времени не заменяет её.

### RID-11 — input, authn, authority и backend (S1/S2)
**Given** F-RID, каждый вариант таблицы результатов на отдельном мире; для
input/authn/authz/backend — и отсутствующая пара, и уже точная ACTIVE.
**When** изменить ровно один input/состояние по таблице и выполнить apply.
**Then** точные exit/code/stage/field или pair по таблице, нет новой дельты,
нет C/admin self-provisioning и bootstrap/I fallback; прежние пары не отозваны.
Близнец каждого возвращает только изменённый факт к законному: тот же payload
успешен и сходится к одной паре. Missing A — отдельный S1 input до writes;
backend до первой пары не смешивается с mid-run частичностью RID-10.

В RID11 единственный изменённый факт означает наблюдаемое input/lifecycle-state из таблицы результатов, а не одну физическую запись БД. Состояние «C удалён» создаётся штатной последовательностью обязательных предпосылок и Delete; связанные Operation/audit/replay effects фиксируются отдельно. После Revoke ключа обязательно доказать, что тот же C ещё существует; только после normal Delete — его public NOT_FOUND и primary absence. В обоих состояниях отдельно проверяются startup UNAUTHENTICATED и public token HTTP401 invalid_client. Независимый lawful twin сохраняет исходный действующий C/ключ и тот же delivery payload, опуская только эту retirement intervention. Отдельный revoked-key сценарий сохраняется и обязан доказать живого C. Эти пробы не утверждают, что отказ deleted-C вызван исключительно отсутствием строки C при всё ещё действующем ключе.

### RID-12 — закрытая форма, лимиты и близнецы (S2)
**Given** полная доставка F-RID; каждый вариант на отдельной чистой копии мира.
**When** применить: (a) поле отсутствует; (b) `grantDelegations: []`;
(c) неизвестное поле; (d) пустая каждая ось; (e) дубликат каждой оси;
(f) 17 различных ролей; (g) 17 различных типов; (h) 5 subjectTypes;
(i) UNSPECIFIED; (j) неизвестное enum значение; (k) модуль/роль/тип iam;
(l) legal boundary 16 ролей/16 типов/4 разрешённых subjectTypes.
**Then** (a)/(b) exit0, обычный seed, 0 delegation; (c)…(k) exit1 INVALID_ARGUMENT,
точный field и 0 записей ВСЕЙ доставки. Близнец каждого меняет только плохое поле:
удалить неизвестное поле, заполнить пустую ось одним разрешённым значением,
удалить второе повторение, уменьшить 17→16, убрать пятое значение, заменить
UNSPECIFIED/unknown на отсутствовавший законный тип, заменить iam собственной
ролью/типом. (l) exit0, N делегирований. Чтобы лимит не маскировался чужой ролью
или типом, fixture boundary manifest объявляет все 17 собственных валидных
ролей/типов; 5 subjectTypes неизбежно включает unknown/duplicate, отказ принимается
по конкретной первой проверке #986, не выдуманному пятому допустимому типу.
Порядок массивов меняется отдельно: повтор остаётся идемпотентным по RID-02.

## Сценарий → держатели, которые заказываются

Каждая названная integration функция содержит все буквенные варианты данного RID
как именованные subtests, negative + lawful twin; отчёт перечисляет каждый. Newman
кейс исполняет те же public последствия. Table — обязательный заказ, не inventory
существующих тестов. Держатель сверяет ровно названное утверждение, не только exit.

| ID | Integration функция | Newman case / граница | Producer и обязательное утверждение |
|---|---|---|---|
| RID-01 | TestRID_01_CleanInstallAndRenewal | registry-installation-rid01 | P1/P4: clean→C/I→delegation, restart/renewal сохраняют IDs |
| RID-02 | TestRID_02_ConcurrentAndRepeat | registry-installation-rid02: repeat; overlap integration-only (barrier/real DB) | P1/P3: оба run0, ровно одна ACTIVE, IDs/createdAt |
| RID-03 | TestRID_03_DelegatedGrantAndIssuerBounds | registry-installation-rid03 | P6: реальные Operation/Get delegationId, denied + twin |
| RID-04 | TestRID_04_CreatorRetirement | registry-installation-rid04 | P4/P6: отказ новых, старые ACTIVE, recovery |
| RID-05 | TestRID_05_CreatorDeletionAndNewID | registry-installation-rid05 | P4/P6: key cleanup, Delete/Get, C2 не оживляет C |
| RID-06 | TestRID_06_RevokeDuringApply | registry-installation-rid06: sequential/recovery; race integration-only | P1/P6: REVOKED сохранён, replacement0 |
| RID-07 | TestRID_07_ExistingPairConflict | registry-installation-rid07 | P1/P3: четыре отдельные оси/creator, zero delta + twins |
| RID-08 | TestRID_08_SnapshotPagesAndFutureAccount | registry-installation-rid08: public N/IDs; canonical pages/barrier/fault integration-only | P5/P1: N3→4, SYS исключён/T включён, late-page fault ≠ N0 |
| RID-09 | TestRID_09_WholeDeliveryPreflight | registry-installation-rid09: public snapshot/twin; own/catalog snapshot integration-only | P2: оба порядка M1/M2, ни одной записи, lawful twin |
| RID-10 | TestRID_10_MidRunFaultAndRetirement | registry-installation-rid10: public сохранение/retry; boundary/fault integration-only | P1/P3: committed1/next0, recovery→N |
| RID-11 | TestRID_11_InputAuthnAuthorityBackend | registry-installation-rid11 | P1/P3/P4/P5: точные outcomes на empty и ACTIVE, no self-grant |
| RID-12 | TestRID_12_ClosedShapeAndBounds | registry-installation-rid12: public snapshots/twins; preflight границы integration-only | P2: absent/[], 3duplicate оси, bounds/enum/iam, zero whole-delivery delta |

Barriers/faults — только fixture управления integration пробой; нового production
watcher/RPC/административной двери для них не появляется. Край не выдаёт внутренний
snapshot как публичный API; internal RPC проверяются на штатном internal listener.

## DoD

1. APPROVED относится к точному SHA-256 этой редакции; принятое startup решение
B1/input/shared credential flow рассмотрено явно. Ни один draft не объявлен implementation.
2. S1: RID-01…07 и RID-11, включая все их варианты и близнецы; настоящие API,
одна пара после install/reinstall, реальный delegated grant, creator retire/delete,
Revoke/conflict; security review разделения C/I/O и текущей authority.
3. S2: все 12 RID и их варианты, census 0/3/4/pageSize2, 16/17 bounds, absent/[],
двухmanifestный whole-delivery reject/twin, overlap/retry/retirement.
4. На одной exact implementation head отдельные результаты S1, S2 и полного
regression #986; S1 не засчитывается за S2, integration не заменяется mock seed.
5. Обязательный внешний smoke: clean standalone base-ready без registry/I →
provisioning C через API и разрешённый gateway-fronted admin → остановка base →
re-entry existing serve с полной delivery и protected C key → реальная shared
preflight authentication/authority без обращения к выключенному listener →
existing model/catalog/roles/own+delivered seed/GD stage → readiness →
Issue credential I → настоящий AccessBinding.Create I →
Operation/Get с ожидаемым delegationId → reinstall с тем же ID. Authn/registration
ошибки не засчитываются как успех install или ожидаемый authorization negative.
6. В evidence каждый RID/вариант→integration/newman результат, сырые exit/status,
непустое число фактических проверок; установочные manifests bytes SHA, source SHA,
снимки before/after и cleanup собственных namespaces/resources. Секретов нет.
7. После локальной авторской правки документа runtime не заявляется. Для кода —
внешние обязательные hook/CI на exact source, отдельный DoD-proof в #1038 и #1030.
8. Документация Kaname описывает D1–D6, защищённые входы, provisioning/renewal/retry,
границу будущих accounts; ссылка на страницу в DoD-proof #1030. Полный scope issues
не закрывается по одному подмножеству этих пунктов.
