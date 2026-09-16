# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set: PermissionCatalogService.ListPermissionCatalog.

Витрина грантуемого каталога правил роли — ПУБЛИЧНОЕ синхронное чтение
`GET /iam/v1/permissionCatalog`. Это метаданные платформы (модули → ресурсы +
признаки редактора, закрытый набор глаголов, политика подстановок, перечень
снятого с преемниками), а не данные арендатора и не инфраструктурные сведения:
читает любой аутентифицированный вызывающий, безымянный получает отказ.

ПОВЕРХНОСТЬ — СОБСТВЕННЫЙ ПУБЛИЧНЫЙ REST-ФРОНТ СЛУЖБЫ (`{{ownRestBaseUrl}}`),
А НЕ КРАЙ ПЛАТФОРМЫ. Решение владельца (e2e-flow.md §7а): сущности службы
доступа проверяются в её репозитории на её собственном фронте. Каждый шаг
адресуется `require_env_url("ownRestBaseUrl", …)`; переменная края `baseUrl`
не переопределяется (гейт `scripts/own_front_env_test.py`).

Прежде коллекция стучалась к краю через `{{baseUrl}}`, которого на автономном
стенде нет: прогон там давал три запроса из трёх без ответа
(`ECONNREFUSED 127.0.0.1:18080`), то есть «не выполнилось», а не вердикт. Ни
один конвейер службы её не гонял, поэтому кейс `CONF-G-03` (приёмка
`docs/engineering/acceptance/retired-resource-names-its-successor.md`,
`IAM-SUC-10`) был объявлен и не исполнялся нигде.

ЧЕЙ ПРОИЗВОДИТЕЛЬ ОТВЕЧАЕТ НА КАЖДОЕ УТВЕРЖДЕНИЕ — по таблице e2e-flow.md §7а
«что производит край». Край добавлял три вещи: разбор доступа с извлечением
области до валидации тела, скрытие существования побайтово равным промахом и
таблицу «внутренний тип → форма ответа». Витрина не принимает ни области, ни
идентификатора объекта, поэтому ни одна из трёх до её утверждений не доходит:

  * тело ответа (`modules[]`, `closedVerbs`, `wildcardPolicy`,
    `retiredResources[]`) производит use-case витрины
    (`internal/apps/kaname/api/permission_catalog/list_catalog.go`) из живых
    строк каталога; в camelCase его кодирует `grpc-gateway` собственного
    фронта (`internal/restfront/mux.go`), и ложные признаки
    (`hasListEndpoint: false`, `labelSelectable: false`) на проводе есть — это
    замерено ответом стенда, а не выведено. Утверждения не менялись;
  * отказ безымянному — `401` + код 16 — на этой поверхности производит рубеж
    самой службы (`internal/authzguard/public_caller_policy.go`,
    `UnnamedCallerMessage`), а не перехватчик края. Утверждение то же;
    переписано только, КТО его производит.

Живые строки каталога — `kaname.catalog_resource` / `catalog_verb`, читаемые
через снимок `catalog.Snapshot`. Строку заводит ПРИМЕНЕНИЕ МАНИФЕСТА модуля в
работающем процессе, снятие (#1861) делает её неживой. За сборкой остался ОДИН
факт, и это законно: `hasListEndpoint` — свойство КРАЯ (публичный ли у типа
отфильтрованный список), живой строкой оно не объявляется ни одной колонкой.
Значение этого признака на проводе всё равно производит служба — край его не
вычисляет, — поэтому утверждение о нём остаётся здесь.

  ⚠️ ЗДЕСЬ СТОЯЛО «authzmap.objectTypes + TypeHasVerbRelations +
  authzmap.CommonVerbVocabulary() + curated hasListEndpoint table. No DB, no
  migration» — перечень, порождённый СБОРКОЙ. Все четыре утверждения были верны
  в день записи и перестали им быть: витрина переехала на живые строки задачей
  #1976, и прод-код снял свою прежнюю редакцию с разбором
  (`internal/apps/kaname/api/permission_catalog/list_catalog.go`, §«ВИТРИНА
  ОТВЕЧАЕТ ЖИВЫМИ СТРОКАМИ КАТАЛОГА»), а этот кейс унаследовал её дословно.

  Почему правка не косметическая (#2646): «базы нет, миграции нет» означает
  «расхождения живого и снятого не бывает by construction» — ровно того класса,
  который #1976 и закрывал. Автор, пишущий сюда соседний кейс по прежней шапке,
  не стал бы проверять ни снятые строки, ни тип, заведённый применением
  манифеста в работающем процессе.

Предъявитель — `{{jwtBootstrap}}`: на автономном стенде его чеканит бутстрап-
контур нашего подписанта (`tests/authz-fixtures/seed_own_stand.py`). Витрина
требует только аутентифицированного яруса и по арендатору не сужается, поэтому
выбор предъявителя на ответ не влияет. Здесь прежде стояла ссылка на пробу
паритета предъявителей `TestListPermissionCatalog_AuthenticatedFloor` — такой
пробы в дереве нет; отказ безымянному на слое use-case держит
`TestListPermissionCatalog_AnonymousFailClosed`.

TLS: шаги НЕ снимают проверку цепочки (`insecure_tls` не ставится), в отличие
от соседней коллекции `kaname-own-rest-front`. Её довод — туннель в кластер, где
лист сервера выписан на имя Service, — здесь предмета не имеет: коллекцию гоняет
задание автономного стенда, прогонщику передаётся УЦ стенда
(`--ssl-extra-ca-certs`), а лист стенда называет `localhost` и `127.0.0.1`.

Covered scenarios:
  - authenticated GET → 200, modules[]/resources[]/closedVerbs/wildcardPolicy
    present, camelCase on the wire.
  - closedVerbs — ПЕРЕСЕЧЕНИЕ наборов `resources[].verbs` того же тела, в
    каноническом порядке; литерального состава кейс не утверждает (его пинит
    проба слоя use-case `TestListPermissionCatalog_ClosedVerbsAreTheCommonSetInCanonicalOrder`).
  - anonymous → 401 UNAUTHENTICATED (no taxonomy leaks pre-auth, no-leak body).
  - each resource carries labelSelectable (camelCase); vpc.subnet=true
    (mirror-fed), vpc.addressPool=false (not fed) — the ARM_LABELS feed-gate flag
    (domain.IsLabelSelectableType).
  - retiredResources[] names each retired type with its successor, and the
    grantable half of the SAME body does not contain it (`IAM-SUC-10`).

Test-design techniques:
  - CONF (conformance): response shape vs the ListPermissionCatalogResponse
    contract — camelCase modules/resources/closedVerbs/wildcardPolicy; resources
    carry hasVerbRelations + hasListEndpoint booleans.
  - ECP (equivalence): authenticated (valid) vs anonymous (invalid) input class.
  - error-guessing: anonymous must be refused before the catalog is read and must
    NOT leak any module/resource taxonomy in the error body.
  - state-transition is N/A — sync read, no Operation envelope.
"""

# ДОМ МОДУЛЯ — репозиторий его ПРЕДМЕТА (e2e-flow.md §7а, решение владельца
# 2026-09-12). Сверяется с деревом гейтом `scripts/case_home_test.py`: домены
# выводятся из REST-путей этого же модуля, и объявление обязано с ними сходиться.
HOME = "kaname"

CASES = []

_OWN_WHY = ("собственный публичный REST-фронт службы; без него у витрины нет "
            "адреса на автономном стенде, и кейс проверял бы край платформы "
            "вместо предмета")


def _own(path):
    """Шаг адресуется к СОБСТВЕННОМУ фронту службы; пропавший адрес — отказ с именем
    переменной и меткой «условие не создано», а не молчаливый пропуск."""
    return require_env_url("ownRestBaseUrl", path, _OWN_WHY)


# ---------------------------------------------------------------------------
# CONF-G-01-catalog-happy — authenticated GET /iam/v1/permissionCatalog → 200
# with the grantable taxonomy.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="CONF-G-01-catalog-happy",
    title="GET /iam/v1/permissionCatalog as jwtBootstrap → 200, modules[]/closedVerbs/wildcardPolicy (camelCase)",
    classes=["CONF", "CRUD"],
    priority="P0",
    steps=[
        Step(
            name="list-permission-catalog-auth",
            method="GET",
            path="/iam/v1/permissionCatalog",
            pre_script=_own("/iam/v1/permissionCatalog"),
            auth="jwtBootstrap",
            test_script=[
                *assert_status(200),
                "pm.test('modules is a non-empty array', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.modules, JSON.stringify(j)).to.be.an('array');",
                "  pm.expect(j.modules.length, 'modules non-empty').to.be.greaterThan(0);",
                "});",
                "pm.test('modules include iam/vpc/compute/loadbalancer', () => {",
                "  const j = pm.response.json();",
                "  const names = (j.modules || []).map(m => m.module);",
                "  ['iam','vpc','compute','loadbalancer'].forEach(want => {",
                "    pm.expect(names, 'module ' + want + ' present in ' + JSON.stringify(names)).to.include(want);",
                "  });",
                "});",
                "pm.test('each resource carries camelCase hasVerbRelations + hasListEndpoint', () => {",
                "  const j = pm.response.json();",
                "  const iam = (j.modules || []).find(m => m.module === 'iam');",
                "  pm.expect(iam, 'iam module present').to.be.an('object');",
                "  pm.expect(iam.resources, 'iam.resources array').to.be.an('array');",
                "  const role = iam.resources.find(r => r.resource === 'role');",
                "  pm.expect(role, 'iam.role present in catalog').to.be.an('object');",
                "  pm.expect(role).to.have.property('hasVerbRelations');",
                "  pm.expect(role).to.have.property('hasListEndpoint');",
                "  pm.expect(role.hasVerbRelations, 'iam.role is verb-bearing').to.equal(true);",
                "});",
                "pm.test('closedVerbs — ПЕРЕСЕЧЕНИЕ наборов типов, а не выписанный список', () => {",
                "  const j = pm.response.json();",
                "  // Литеральный перечень здесь пережил бы своё изменение молча: он был",
                "  // [get,list,create,update,delete] и остался бы им после того, как глагол",
                "  // создания перестал быть общим (снят с 23 носителей из 24 — у реестра",
                "  // читатель есть). Поэтому утверждается СВОЙСТВО поля, а не его состав.",
                "  pm.expect(j.closedVerbs, JSON.stringify(j)).to.be.an('array').that.is.not.empty;",
                "  // Порядок фиксирован — это часть контракта: клиент вправе сравнивать",
                "  // побайтово, поэтому набор обязан приходить отсортированным по канону.",
                "  const canon = ['get','list','create','update','delete'];",
                "  const seen = j.closedVerbs.slice();",
                "  const ordered = canon.filter(v => seen.indexOf(v) !== -1);",
                "  pm.expect(seen, 'порядок закрытого набора — канонический').to.eql(ordered);",
                "  // СОСТАВ сверяется с наборами `resources[].verbs` ТОГО ЖЕ тела: контракт",
                "  // `closed_verbs` — «пересечение наборов всех типов». Здесь стояло «get и",
                "  // list — общие для всех типов by construction», и это ложно с тех пор, как",
                "  // `v_get` снят с `iam_role` (kacho#1922): пересечение сузилось до `[list]`.",
                "  // Не краснело потому, что коллекцию не гоняет ни один конвейер, — а не",
                "  // потому, что было верно.",
                "  const verbBearing = (j.modules || []).flatMap(m => (m.resources || [])",
                "    .filter(r => r.hasVerbRelations)",
                "    .map(r => ({ key: m.module + '.' + r.resource, verbs: r.verbs })));",
                "  pm.expect(verbBearing.length, 'глагол-несущих типов в каталоге').to.be.above(1);",
                "  // Набор каждого глагол-несущего типа обязан быть на проводе: край, чьи",
                "  // стабы поля не знают, отбрасывает его молча, и пересечение отсутствующих",
                "  // наборов было бы пустым — отказ ниже назвал бы не ту причину.",
                "  verbBearing.forEach(t => pm.expect(t.verbs, t.key + ': набор глаголов типа на проводе')",
                "    .to.be.an('array').that.is.not.empty);",
                "  const inter = verbBearing.reduce((acc, t) => acc.filter(v => t.verbs.indexOf(v) !== -1),",
                "    verbBearing[0].verbs.slice());",
                "  pm.expect(seen.slice().sort(), 'closedVerbs = пересечение наборов показанных типов')",
                "    .to.eql(inter.slice().sort());",
                "  // Положительный контроль: наборы типов на этом теле РАЗЛИЧАЮТСЯ. Без него",
                "  // равенство выше не отличало бы пересечение от объединения — на теле, где",
                "  // все наборы совпали, они равны, и ни один дефект поля не наблюдаем.",
                "  const union = verbBearing.reduce((acc, t) => acc.concat(t.verbs.filter(v => acc.indexOf(v) === -1)), []);",
                "  pm.expect(union.length, 'объединение наборов шире пересечения: ' + JSON.stringify(union) +",
                "    ' против ' + JSON.stringify(inter)).to.be.above(inter.length);",
                "});",
                "pm.test('wildcardPolicy flags present (verb-* allowed; module/resource-* system-only)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.wildcardPolicy, JSON.stringify(j)).to.be.an('object');",
                "  pm.expect(j.wildcardPolicy.verbWildcardAllowedCustom, 'verb-* allowed in custom').to.equal(true);",
                "  pm.expect(j.wildcardPolicy.moduleResourceWildcardSystemOnly, 'module/resource-* system-only').to.equal(true);",
                "});",
                "pm.test('vpc.addressPool grantable+verb-bearing but hasListEndpoint=false (Internal-only List)', () => {",
                "  const j = pm.response.json();",
                "  const vpc = (j.modules || []).find(m => m.module === 'vpc');",
                "  pm.expect(vpc, 'vpc module present').to.be.an('object');",
                "  const ap = (vpc.resources || []).find(r => r.resource === 'addressPool');",
                "  pm.expect(ap, 'vpc.addressPool present in catalog').to.be.an('object');",
                "  pm.expect(ap.hasVerbRelations, 'addressPool verb-bearing').to.equal(true);",
                "  pm.expect(ap.hasListEndpoint, 'addressPool List is Internal-only → false').to.equal(false);",
                "});",
                "pm.test('labelSelectable present + vpc.subnet=true, vpc.addressPool=false (ARM_LABELS feed-gate)', () => {",
                "  const j = pm.response.json();",
                "  const vpc = (j.modules || []).find(m => m.module === 'vpc');",
                "  pm.expect(vpc, 'vpc module present').to.be.an('object');",
                "  const subnet = (vpc.resources || []).find(r => r.resource === 'subnet');",
                "  pm.expect(subnet, 'vpc.subnet present').to.be.an('object');",
                "  pm.expect(subnet).to.have.property('labelSelectable');",
                "  pm.expect(subnet.labelSelectable, 'vpc.subnet is mirror-fed → label-selectable').to.equal(true);",
                "  const ap = (vpc.resources || []).find(r => r.resource === 'addressPool');",
                "  pm.expect(ap, 'vpc.addressPool present').to.be.an('object');",
                "  pm.expect(ap).to.have.property('labelSelectable');",
                "  pm.expect(ap.labelSelectable, 'vpc.addressPool NOT fed → not label-selectable').to.equal(false);",
                "});",
                "pm.test('no `geo` module (geo.* not grantable)', () => {",
                "  const j = pm.response.json();",
                "  const names = (j.modules || []).map(m => m.module);",
                "  pm.expect(names, 'geo NOT in modules: ' + JSON.stringify(names)).to.not.include('geo');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# NEG-G-02-catalog-anonymous-unauthenticated — anonymous GET → 401, no leak.
# Matched negative for CONF-G-01-catalog-happy.
#
# ПРОИЗВОДИТЕЛЬ ОТКАЗА на этой поверхности — рубеж самой службы
# (`internal/authzguard/public_caller_policy.go`, `UnnamedCallerMessage`), а не
# перехватчик края: край здесь не стоит. Пара «401 + код 16» у обоих
# производителей одна, поэтому утверждение не менялось.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="NEG-G-02-catalog-anonymous-unauthenticated",
    title="GET /iam/v1/permissionCatalog as anonymous (no Bearer) → 401 Unauthenticated, no taxonomy leak",
    classes=["AUTHZ", "NEG", "SEC"],
    priority="P1",
    steps=[
        Step(
            name="list-permission-catalog-anon",
            method="GET",
            path="/iam/v1/permissionCatalog",
            pre_script=_own("/iam/v1/permissionCatalog"),
            auth="anonymous",
            test_script=[
                "pm.test('status 401', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(401));",
                "let j; try { j = pm.response.json(); } catch (e) { j = null; }",
                "pm.test('grpc code 16 (UNAUTHENTICATED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(16));",
                "pm.test('no taxonomy leaks pre-auth (no modules in error body)', () => {",
                "  pm.expect(j, JSON.stringify(j)).to.not.have.property('modules');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# CONF-G-03-catalog-retired-successor — СНЯТЫЙ ресурс назван своим перечнем и
# несёт преемника; перечень ГРАНТУЕМОГО того же тела его не содержит.
#
# Предмет (kacho#1814, приёмка
# `docs/engineering/acceptance/retired-resource-names-its-successor.md`,
# `IAM-SUC-10`): преемник снятого ресурса существовал ДАННЫМИ и не доезжал до
# арендатора ни одним путём чтения. Клиент, чьё правило отвергнуто на
# `compute.disk`, узнать `storage.volumes` мог только чтением исходников —
# догадка по имени неверна ровно там, где нужна: имена намеренно не
# единообразны (`compute.instance` единственного числа, `storage.volumes`
# множественного).
#
# ПОЧЕМУ КЕЙС КРАЯ, а не проба слоя use-case. Предикат задачи звучит «арендатор
# узнаёт преемника ОДНИМ вызовом» — это утверждение о теле ответа ПО ПРОВОДУ.
# Проба слоя use-case зовёт хендлер напрямую, и мимо неё проходят край,
# перекодирование в camelCase и пересборка потребителя: неизвестное краю поле он
# отбрасывает МОЛЧА.
#
# ОБЕ половины утверждаются ОДНИМ телом, а не двумя прогонами: состояние
# «ресурс в обоих перечнях сразу» и «ни в одном» наблюдаемо только так.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="CONF-G-03-catalog-retired-successor",
    title="GET /iam/v1/permissionCatalog as jwtBootstrap → 200, retiredResources[] несёт supersededBy, и грантуемое снятого не содержит",
    classes=["CONF", "CRUD"],
    priority="P1",
    steps=[
        Step(
            name="list-permission-catalog-retired",
            method="GET",
            path="/iam/v1/permissionCatalog",
            pre_script=_own("/iam/v1/permissionCatalog"),
            auth="jwtBootstrap",
            test_script=[
                *assert_status(200),
                "pm.test('retiredResources — непустой массив в camelCase на проводе', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.retiredResources, JSON.stringify(j)).to.be.an('array');",
                "  pm.expect(j.retiredResources.length, 'снятых записей').to.be.greaterThan(0);",
                "});",
                "pm.test('compute.disk назван снятым и его преемник — storage.volumes', () => {",
                "  const j = pm.response.json();",
                "  const disk = (j.retiredResources || []).find(r => r.resource === 'compute.disk');",
                "  pm.expect(disk, 'compute.disk в перечне снятого: ' + JSON.stringify(j.retiredResources))",
                "    .to.be.an('object');",
                "  pm.expect(disk).to.have.property('supersededBy');",
                "  pm.expect(disk.supersededBy, 'преемник compute.disk').to.equal('storage.volumes');",
                "});",
                "pm.test('преемник КАЖДОЙ названной записи — живой ключ ТОГО ЖЕ тела', () => {",
                "  const j = pm.response.json();",
                "  const grantable = (j.modules || []).reduce((acc, m) => acc.concat(",
                "    (m.resources || []).map(r => m.module + '.' + r.resource)), []);",
                "  // Положительный контроль: перечень грантуемого непуст, иначе",
                "  // членство преемника проверялось бы в пустом множестве.",
                "  pm.expect(grantable.length, 'грантуемых пар в теле').to.be.greaterThan(0);",
                "  let named = 0;",
                "  (j.retiredResources || []).forEach(r => {",
                "    if (!r.supersededBy) { return; }",
                "    named += 1;",
                "    pm.expect(grantable, 'преемник ' + r.supersededBy + ' снятого ' + r.resource +",
                "      ' — живой ключ того же ответа').to.include(r.supersededBy);",
                "  });",
                "  pm.expect(named, 'записей с названным преемником').to.be.greaterThan(0);",
                "});",
                "pm.test('снятое НЕ попало в перечень ГРАНТУЕМОГО того же тела', () => {",
                "  const j = pm.response.json();",
                "  const grantable = (j.modules || []).reduce((acc, m) => acc.concat(",
                "    (m.resources || []).map(r => m.module + '.' + r.resource)), []);",
                "  pm.expect(grantable.length, 'грантуемых пар в теле').to.be.greaterThan(0);",
                "  (j.retiredResources || []).forEach(r => {",
                "    pm.expect(grantable, 'снятый ' + r.resource + ' НЕ предлагается к выдаче')",
                "      .to.not.include(r.resource);",
                "  });",
                "});",
                "pm.test('положительный контроль: три прежних поля на месте и непусты', () => {",
                "  const j = pm.response.json();",
                "  // Без него «снятого нет в грантуемом» зеленело бы на пустом ответе.",
                "  pm.expect(j.modules, 'modules').to.be.an('array').that.is.not.empty;",
                "  pm.expect(j.closedVerbs, 'closedVerbs').to.be.an('array').that.is.not.empty;",
                "  pm.expect(j.wildcardPolicy, 'wildcardPolicy').to.be.an('object');",
                "});",
            ],
        ),
    ],
))
