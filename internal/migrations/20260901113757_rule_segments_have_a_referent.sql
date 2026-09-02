-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 20260901113757_rule_segments_have_a_referent — у сегментов правила роли появляется
-- РЕФЕРЕНТ: каталог модуля становится строками, а ссылка на него — ключом.
--
-- Приёмка: services/iam/docs/engineering/acceptance/rule-segments-have-a-referent.md
-- (APPROVED круга 3). Сценарии IAM-CT-1-01 … IAM-CT-1-16. Задача продукта #1030.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧТО НЕВЕРНО СЕГОДНЯ
--
-- Правило роли адресует объект тремя сегментами — модуль, ресурс, глагол.
-- Референт есть у ОДНОГО из трёх: модуль сверяется с закрытым набором Go, ресурс
-- и глагол — только с грамматикой токена. Правило, называющее `vpc.nonesuch` или
-- глагол `frobnicate`, принимается успешно, а дальше не отвергается, а ИСЧЕЗАЕТ:
-- писатель проекции пропускает неизвестный тип молча, и роль получает проекцию
-- из нуля строк. Для арендатора привязка создаётся, читается, выглядит
-- действующей и не даёт ничего — пустое соединение неотличимо от честного
-- «права нет». Дерево уже платило за этот класс дважды (513001 — двенадцать
-- доменных ролей без единого пообъектного права; 0089 — комментарий колонки,
-- обманувший читателя о словаре).
--
-- Симметричная половина: СНЯТЬ ресурс или глагол с платформы некому. Снятие
-- выражено запретительным списком в Go, то есть решением, которое нельзя ни
-- выдать, ни отозвать, ни увидеть в аудите, и которое ничего не говорит об уже
-- выданных правах на снимаемое.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ КЛЮЧЕЙ ДВА, А НЕ ОДИН — ИЗМЕРЕНО, А НЕ ВЫБРАНО
--
-- Правило-якорь (глаголы не сужены) даёт строку с `verb IS NULL`. Под ОДНИМ
-- составным ключом `(module, resource, verb, live)` умолчание `MATCH SIMPLE`
-- пропускает проверку ЦЕЛИКОМ, если NULL стоит в любом столбце ключа, — то есть
-- правило, называющее ресурс вне каталога, принимается успешно. Проверено
-- прогоном на PostgreSQL 16.15 (приёмка §0.2 Н1). Поэтому ключа два: ключ
-- РЕСУРСА проверяется при любом значении глагола, ключ ГЛАГОЛА пропускается на
-- якоре — и это правильно, потому что ресурс уже проверен первым.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ФОРМА `DEFERRABLE INITIALLY IMMEDIATE`, А НЕ `INITIALLY DEFERRED`
--
-- У формы две обязанности, и они тянут в разные стороны.
--
-- На пути запроса отказ обязан НАЗЫВАТЬ сегмент и токен (сценарии -05/-06/-07).
-- Это даёт немедленность: нарушение приходит ИЗ ОПЕРАТОРА, и писатель держит тот
-- самый сегмент, который сейчас вставляет. При `INITIALLY DEFERRED` отказ
-- всплывает на коммите, где подсказка одна на транзакцию, а сегментов в правиле
-- много, — назвать виновника нечем by construction.
--
-- В административном пути снятие и переселение обязаны помещаться в одну
-- транзакцию в естественном порядке. Это даёт `SET CONSTRAINTS … DEFERRED` в том
-- пути, которому отложенность нужна. Отложенность ОТКЛАДЫВАЕТ проверку, а не
-- отменяет: та же транзакция без переселения отказывает на коммите, и строка
-- каталога остаётся живой (сценарий -14, контроль).
--
-- `RESTRICT … DEFERRABLE` здесь ЗАПРЕЩЁН: форма принимается DDL и молча инертна —
-- проверка остаётся немедленной (приёмка §0.2 Н2, проба C4). Без `DEFERRABLE`
-- `NO ACTION` и `RESTRICT` тождественны, и выбор между ними доводов не несёт.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ `live` — ОБЫЧНАЯ КОЛОНКА, А НЕ ГЕНЕРИРУЕМАЯ
--
-- Не потому, что поведение движка непроверено — оно проверено, и обе формы дают
-- побайтово одинаковый исход. Потому что генерируемая колонка при добавлении в
-- ЖИВУЮ таблицу переписывает кучу под ACCESS EXCLUSIVE (0067: 344 МБ на
-- замеренном стенде). К новым пустым `catalog_*` довод неприменим, но форма
-- обязана быть ОДНА на все таблицы и на `role_verb.live`, иначе заводится вторая
-- ось, о которой никто не решал.
--
-- Цена решения названа: писатель обязан менять `retired_at` и `live` ОДНИМ
-- оператором. Молчаливого расхождения не будет — его отвергает проверка кодом
-- 23514 (сценарий -11), — но ось существует.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ПРОЕКЦИЯ `role_rule_ref`, А НЕ КЛЮЧ НА `roles.rules`
--
-- Ключ на значение jsonb невыразим by construction: проверка значения не умеет
-- спрашивать другую таблицу, и подзапрос в CHECK отвергается DDL
-- («cannot use subquery in check constraint»). Поэтому объявление проецируется
-- строками, и пишет их ТОТ ЖЕ оператор и та же транзакция, что и само правило.
--
-- Строка кладётся на КАЖДЫЙ объявленный сегмент, а не на резолвящийся: молчаливый
-- пропуск и есть тот дефект, который эта миграция закрывает, и воспроизводить его
-- в новом писателе значило бы завести ключ, которому нечего отвергать.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ВСЁ В ОДНОЙ МИГРАЦИИ
--
-- Применённую миграцию не правят (запрет #5), и ошибка, разложенная на две,
-- становится неисправимой посередине: между ними существует состояние, где ключ
-- уже объявлен, а переселение ещё нет, — и стенд в нём отказывает арендатору в
-- создании роли. Порядок: завести таблицы → посеять → завести проекцию правила и
-- заполнить из `roles.rules` → переселить непокрытые пары → добавить колонки
-- `live` → ADD CONSTRAINT → ПРОВЕРИТЬ СВОЙ ИСХОД и RAISE EXCEPTION при
-- недостижении. Форма взята у 732001, самопроверка — у 513001.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ИСТОЧНИК ПОСЕВА НАЗВАН ПОИМЁННО, И ОН НЕ ОДИН НА ВСЕ ТРИ ТАБЛИЦЫ
--
--   catalog_module   ← domain.KnownModules()          (6 строк)
--   catalog_resource ← authzmap.objectTypes           (27 живых)
--   catalog_verb     ← authzmap.typeVerbRelations     (109 пар)
--   снятые строки    ← domain.retiredTypes            (3, с преемником)
--
-- Перечень ВЫВОДИТСЯ одним производителем — `authzmap.CatalogSeedResources()` /
-- `CatalogSeedVerbs()`, — и им же его сверяет гейт дерева
-- (internal/repohygiene, TestIAMCT114_CatalogSeedMatchesTheLiteral) и страж
-- старта. Разойдясь, три места дали бы худший из исходов: посев, согласный с
-- гейтом, и оба неверные относительно того, что судит ключ.
--
-- Аннотации контрактов источником НЕ являются: они говорят ТРЕТЬИМ словарём
-- (`vpc.networks.get` против `vpc.network`), и пересечение множеств «как есть» —
-- 8 из 27. Таблица, посеянная из них, не соединилась бы с `role_verb.object_type`
-- и не соединилась бы МОЛЧА — ровно класс 513001.

-- +goose Up

-- ── КАТАЛОГ МОДУЛЕЙ ────────────────────────────────────────────────────────────

CREATE TABLE kacho_iam.catalog_module (
  module         text        NOT NULL,
  retired_at     timestamptz,
  retired_reason text,
  -- live — ОБЫЧНАЯ колонка под проверкой согласия, см. шапку. Она же даёт
  -- ключам их референт: уникальность `(module, live)` позволяет сослаться на
  -- «эту строку И она жива» одним ключом.
  live           boolean     NOT NULL DEFAULT true,

  CONSTRAINT catalog_module_pkey PRIMARY KEY (module),
  CONSTRAINT catalog_module_live_matches_retired CHECK (live = (retired_at IS NULL)),
  CONSTRAINT catalog_module_nonempty CHECK (module <> ''),
  -- Третье написание не заводится: имя модуля точки не содержит. Симметрия с
  -- пятью такими же проверками у колонок словаря МОДЕЛИ (0091, 0098), которых у
  -- колонок словаря КАТАЛОГА до этой миграции было ноль.
  CONSTRAINT catalog_module_undotted CHECK (module NOT LIKE '%.%'),
  CONSTRAINT catalog_module_live_uk UNIQUE (module, live)
);

COMMENT ON TABLE kacho_iam.catalog_module IS
  'Каталог модулей платформы. Источник посева — domain.KnownModules(). Строка живёт, пока retired_at IS NULL; согласие держит проверка, а не писатель.';

INSERT INTO kacho_iam.catalog_module (module) VALUES
  ('iam'),
  ('vpc'),
  ('compute'),
  ('loadbalancer'),
  ('registry'),
  ('storage');

-- ── КАТАЛОГ РЕСУРСОВ ──────────────────────────────────────────────────────────

CREATE TABLE kacho_iam.catalog_resource (
  module         text        NOT NULL,
  resource       text        NOT NULL,
  -- dotted — ПРОИЗВОДНАЯ форма того же имени, та, какой говорят
  -- `role_verb.object_type` и `role_rule_selectors.object_types`. Хранится
  -- колонкой под проверкой согласия, а не собирается читателем: словарей имени
  -- типа в дереве ровно два (модель ↔ каталог), и третьего здесь НЕ заводится
  -- (authzmap/type_dictionaries.go: «Второго переходника в дереве не заводится»).
  dotted         text        NOT NULL,
  retired_at     timestamptz,
  retired_reason text,
  -- superseded_by — точечное имя ЖИВОГО ресурса, которым пользуется арендатор
  -- вместо снятого. МЕСТО У ПРЕЕМНИКА РОВНО ОДНО — эта колонка: литерал, знающий
  -- преемника, покрывал бы только посеянные снятия и молчал бы о тех, что
  -- заводит административный путь. Читается ПУТЁМ ЧТЕНИЯ каталога, а не текстом
  -- отказа: в прерванной транзакции чтения нет by construction.
  superseded_by  text,
  live           boolean     NOT NULL DEFAULT true,

  CONSTRAINT catalog_resource_pkey PRIMARY KEY (module, resource),
  CONSTRAINT catalog_resource_module_fk FOREIGN KEY (module)
    REFERENCES kacho_iam.catalog_module (module)
    ON DELETE NO ACTION ON UPDATE NO ACTION,
  CONSTRAINT catalog_resource_live_matches_retired CHECK (live = (retired_at IS NULL)),
  CONSTRAINT catalog_resource_dotted_form CHECK (dotted = module || '.' || resource),
  CONSTRAINT catalog_resource_module_undotted CHECK (module NOT LIKE '%.%'),
  CONSTRAINT catalog_resource_resource_undotted CHECK (resource NOT LIKE '%.%'),
  CONSTRAINT catalog_resource_nonempty CHECK (module <> '' AND resource <> ''),
  -- Преемник указывается ТОЛЬКО у снятого: у живого ресурса ему нечего значить,
  -- и непустое значение там читалось бы как «этот ресурс тоже отзывают».
  CONSTRAINT catalog_resource_successor_only_when_retired
    CHECK (superseded_by IS NULL OR NOT live),
  -- Референт ключа РЕСУРСА проекции правила.
  CONSTRAINT catalog_resource_live_uk UNIQUE (module, resource, live),
  -- Референт ключа проекции ГЛАГОЛОВ (`role_verb.object_type`), который говорит
  -- точечной формой.
  CONSTRAINT catalog_resource_dotted_live_uk UNIQUE (dotted, live)
);

COMMENT ON TABLE kacho_iam.catalog_resource IS
  'Каталог грантуемых типов. Источник посева — authzmap.objectTypes (27 живых) плюс domain.retiredTypes (3 снятых с преемником). Ключ role_rule_ref_res_fk ссылается на (module, resource, live), ключ role_verb_type_fk — на (dotted, live).';

COMMENT ON COLUMN kacho_iam.catalog_resource.superseded_by IS
  'Точечное имя ЖИВОГО ресурса взамен снятого. Читается путём чтения каталога: в прерванной транзакции отказа чтения нет by construction, поэтому текст отказа преемника не называет и не обещает.';

INSERT INTO kacho_iam.catalog_resource (module, resource, dotted) VALUES
  ('compute', 'guestAccessKey', 'compute.guestAccessKey'),
  ('compute', 'instance', 'compute.instance'),
  ('compute', 'placementGroup', 'compute.placementGroup'),
  ('iam', 'accessBinding', 'iam.accessBinding'),
  ('iam', 'account', 'iam.account'),
  ('iam', 'group', 'iam.group'),
  ('iam', 'project', 'iam.project'),
  ('iam', 'role', 'iam.role'),
  ('iam', 'serviceAccount', 'iam.serviceAccount'),
  ('iam', 'user', 'iam.user'),
  ('loadbalancer', 'listeners', 'loadbalancer.listeners'),
  ('loadbalancer', 'networkLoadBalancers', 'loadbalancer.networkLoadBalancers'),
  ('loadbalancer', 'targetGroups', 'loadbalancer.targetGroups'),
  ('registry', 'registries', 'registry.registries'),
  ('registry', 'repositories', 'registry.repositories'),
  ('storage', 'images', 'storage.images'),
  ('storage', 'snapshots', 'storage.snapshots'),
  ('storage', 'volumes', 'storage.volumes'),
  ('vpc', 'address', 'vpc.address'),
  ('vpc', 'addressPool', 'vpc.addressPool'),
  ('vpc', 'cidrGroup', 'vpc.cidrGroup'),
  ('vpc', 'gateway', 'vpc.gateway'),
  ('vpc', 'network', 'vpc.network'),
  ('vpc', 'networkInterface', 'vpc.networkInterface'),
  ('vpc', 'routeTable', 'vpc.routeTable'),
  ('vpc', 'securityGroup', 'vpc.securityGroup'),
  ('vpc', 'subnet', 'vpc.subnet');

-- Снятые типы переезжают СТРОКАМИ, а не остаются запретительным списком в Go.
-- Преемники названы в комментарии `domain/retired_types.go`, который
-- производителем не является; здесь они становятся ДАННЫМИ. Каждое значение —
-- живой ключ каталога выше, и это утверждается пробой IAM-CT-1-10.
INSERT INTO kacho_iam.catalog_resource
  (module, resource, dotted, retired_at, retired_reason, superseded_by, live) VALUES
  ('compute', 'disk',     'compute.disk',     now(),
   'блочное хранение принадлежит kacho-storage; вторая копия ресурса снята', 'storage.volumes',   false),
  ('compute', 'image',    'compute.image',    now(),
   'блочное хранение принадлежит kacho-storage; вторая копия ресурса снята', 'storage.images',    false),
  ('compute', 'snapshot', 'compute.snapshot', now(),
   'блочное хранение принадлежит kacho-storage; вторая копия ресурса снята', 'storage.snapshots', false);

-- ── КАТАЛОГ ГЛАГОЛОВ ──────────────────────────────────────────────────────────

CREATE TABLE kacho_iam.catalog_verb (
  module         text        NOT NULL,
  resource       text        NOT NULL,
  -- verb — каноническая форма БЕЗ приставки отношения, та же, какой говорит
  -- `role_verb.verb`. Приставку знает компилятор модели, и дублировать её здесь
  -- значило бы завести второе место, где она может смениться.
  verb           text        NOT NULL,
  retired_at     timestamptz,
  retired_reason text,
  live           boolean     NOT NULL DEFAULT true,

  CONSTRAINT catalog_verb_pkey PRIMARY KEY (module, resource, verb),
  -- Ключ на ПЕРВИЧНЫЙ ключ ресурса, а не на его живость: живость ресурса судит
  -- ключ РЕСУРСА проекции правила, и второе место о том же предмете разошлось бы
  -- с первым молча. Строка глагола у снятого ресурса недостижима by
  -- construction: до неё дело не доходит — правило отвергается ключом ресурса.
  CONSTRAINT catalog_verb_resource_fk FOREIGN KEY (module, resource)
    REFERENCES kacho_iam.catalog_resource (module, resource)
    ON DELETE NO ACTION ON UPDATE NO ACTION,
  CONSTRAINT catalog_verb_live_matches_retired CHECK (live = (retired_at IS NULL)),
  CONSTRAINT catalog_verb_undotted CHECK (verb NOT LIKE '%.%'),
  CONSTRAINT catalog_verb_nonempty CHECK (verb <> ''),
  -- Приведённость — свойство хранимого, а не надежда на писателя: строка,
  -- отличающаяся от своей канонической формы, не будет найдена ключом, и
  -- отличить это от «глагола нет» станет нечем (тот же довод, что у
  -- role_verb_verb_canonical, 0085).
  CONSTRAINT catalog_verb_canonical CHECK (verb = lower(btrim(verb))),
  CONSTRAINT catalog_verb_live_uk UNIQUE (module, resource, verb, live)
);

COMMENT ON TABLE kacho_iam.catalog_verb IS
  'Каталог глаголов, объявленных типом. Источник посева — authzmap.typeVerbRelations (109 пар), переведённых в словарь каталога единственным переходником.';

INSERT INTO kacho_iam.catalog_verb (module, resource, verb) VALUES
  ('compute', 'guestAccessKey', 'delete'),
  ('compute', 'guestAccessKey', 'get'),
  ('compute', 'guestAccessKey', 'list'),
  ('compute', 'guestAccessKey', 'update'),
  ('compute', 'instance', 'delete'),
  ('compute', 'instance', 'get'),
  ('compute', 'instance', 'list'),
  ('compute', 'instance', 'update'),
  ('compute', 'placementGroup', 'delete'),
  ('compute', 'placementGroup', 'get'),
  ('compute', 'placementGroup', 'list'),
  ('compute', 'placementGroup', 'update'),
  ('iam', 'accessBinding', 'delete'),
  ('iam', 'accessBinding', 'get'),
  ('iam', 'accessBinding', 'list'),
  ('iam', 'accessBinding', 'update'),
  ('iam', 'account', 'delete'),
  ('iam', 'account', 'get'),
  ('iam', 'account', 'list'),
  ('iam', 'account', 'update'),
  ('iam', 'group', 'delete'),
  ('iam', 'group', 'get'),
  ('iam', 'group', 'list'),
  ('iam', 'group', 'update'),
  ('iam', 'project', 'delete'),
  ('iam', 'project', 'get'),
  ('iam', 'project', 'list'),
  ('iam', 'project', 'update'),
  ('iam', 'role', 'delete'),
  ('iam', 'role', 'get'),
  ('iam', 'role', 'list'),
  ('iam', 'role', 'update'),
  ('iam', 'serviceAccount', 'delete'),
  ('iam', 'serviceAccount', 'get'),
  ('iam', 'serviceAccount', 'list'),
  ('iam', 'serviceAccount', 'update'),
  ('iam', 'user', 'get'),
  ('iam', 'user', 'list'),
  ('loadbalancer', 'listeners', 'delete'),
  ('loadbalancer', 'listeners', 'get'),
  ('loadbalancer', 'listeners', 'list'),
  ('loadbalancer', 'listeners', 'update'),
  ('loadbalancer', 'networkLoadBalancers', 'delete'),
  ('loadbalancer', 'networkLoadBalancers', 'get'),
  ('loadbalancer', 'networkLoadBalancers', 'list'),
  ('loadbalancer', 'networkLoadBalancers', 'update'),
  ('loadbalancer', 'targetGroups', 'addtargets'),
  ('loadbalancer', 'targetGroups', 'delete'),
  ('loadbalancer', 'targetGroups', 'get'),
  ('loadbalancer', 'targetGroups', 'list'),
  ('loadbalancer', 'targetGroups', 'removetargets'),
  ('loadbalancer', 'targetGroups', 'update'),
  ('registry', 'registries', 'create'),
  ('registry', 'registries', 'delete'),
  ('registry', 'registries', 'get'),
  ('registry', 'registries', 'list'),
  ('registry', 'registries', 'update'),
  ('registry', 'repositories', 'delete'),
  ('registry', 'repositories', 'get'),
  ('registry', 'repositories', 'list'),
  ('registry', 'repositories', 'update'),
  ('storage', 'images', 'delete'),
  ('storage', 'images', 'get'),
  ('storage', 'images', 'list'),
  ('storage', 'images', 'update'),
  ('storage', 'snapshots', 'delete'),
  ('storage', 'snapshots', 'get'),
  ('storage', 'snapshots', 'list'),
  ('storage', 'snapshots', 'update'),
  ('storage', 'volumes', 'delete'),
  ('storage', 'volumes', 'get'),
  ('storage', 'volumes', 'list'),
  ('storage', 'volumes', 'update'),
  ('vpc', 'address', 'delete'),
  ('vpc', 'address', 'get'),
  ('vpc', 'address', 'list'),
  ('vpc', 'address', 'update'),
  ('vpc', 'addressPool', 'delete'),
  ('vpc', 'addressPool', 'get'),
  ('vpc', 'addressPool', 'list'),
  ('vpc', 'addressPool', 'update'),
  ('vpc', 'cidrGroup', 'delete'),
  ('vpc', 'cidrGroup', 'get'),
  ('vpc', 'cidrGroup', 'list'),
  ('vpc', 'cidrGroup', 'update'),
  ('vpc', 'gateway', 'delete'),
  ('vpc', 'gateway', 'get'),
  ('vpc', 'gateway', 'list'),
  ('vpc', 'gateway', 'update'),
  ('vpc', 'network', 'delete'),
  ('vpc', 'network', 'get'),
  ('vpc', 'network', 'list'),
  ('vpc', 'network', 'update'),
  ('vpc', 'networkInterface', 'delete'),
  ('vpc', 'networkInterface', 'get'),
  ('vpc', 'networkInterface', 'list'),
  ('vpc', 'networkInterface', 'update'),
  ('vpc', 'routeTable', 'delete'),
  ('vpc', 'routeTable', 'get'),
  ('vpc', 'routeTable', 'list'),
  ('vpc', 'routeTable', 'update'),
  ('vpc', 'securityGroup', 'delete'),
  ('vpc', 'securityGroup', 'get'),
  ('vpc', 'securityGroup', 'list'),
  ('vpc', 'securityGroup', 'update'),
  ('vpc', 'subnet', 'delete'),
  ('vpc', 'subnet', 'get'),
  ('vpc', 'subnet', 'list'),
  ('vpc', 'subnet', 'update');

-- ── ПРОЕКЦИЯ ОБЪЯВЛЕННЫХ СЕГМЕНТОВ ПРАВИЛА ───────────────────────────────────

CREATE TABLE kacho_iam.role_rule_ref (
  role_id  text    NOT NULL
    REFERENCES kacho_iam.roles (id) ON DELETE CASCADE,
  module   text    NOT NULL,
  resource text    NOT NULL,
  -- verb IS NULL — ЯКОРЬ: правило не сузило глаголы. Не «значение не задано»:
  -- ключ ГЛАГОЛА на такой строке пропускается `MATCH SIMPLE`, и это ровно то
  -- поведение, ради которого ключей два.
  verb     text,
  -- live — константа `true`: строка проекции существует, пока правило её
  -- называет, и ссылается только на ЖИВУЮ строку каталога. Колонка нужна ключам:
  -- без неё сослаться на «эту строку И она жива» нечем.
  live     boolean NOT NULL DEFAULT true,

  CONSTRAINT role_rule_ref_live_true CHECK (live),
  CONSTRAINT role_rule_ref_nonempty CHECK (module <> '' AND resource <> ''),
  CONSTRAINT role_rule_ref_verb_nonempty CHECK (verb IS NULL OR verb <> ''),
  CONSTRAINT role_rule_ref_module_undotted CHECK (module NOT LIKE '%.%'),
  CONSTRAINT role_rule_ref_resource_undotted CHECK (resource NOT LIKE '%.%'),
  CONSTRAINT role_rule_ref_verb_undotted CHECK (verb IS NULL OR verb NOT LIKE '%.%')
);

-- Первичного ключа нет: столбец `verb` допускает NULL, и в первичный ключ он
-- не входит by construction. Уникальность выражена индексом по выражению —
-- якорь и названный глагол различаются, а два одинаковых якоря не заводятся.
CREATE UNIQUE INDEX role_rule_ref_uk
  ON kacho_iam.role_rule_ref (role_id, module, resource, COALESCE(verb, ''));

-- Ключ на пару каталога читается снятием: административный путь спрашивает
-- «есть ли живая ссылка на эту строку», и без индекса это был бы обход таблицы.
CREATE INDEX role_rule_ref_pair_idx ON kacho_iam.role_rule_ref (module, resource);

COMMENT ON TABLE kacho_iam.role_rule_ref IS
  'Проекция ОБЪЯВЛЕННЫХ сегментов правила роли — то, на чём внешний ключ в каталог ВОЗМОЖЕН (на roles.rules jsonb он невыразим: подзапрос в CHECK отвергается DDL). Строка кладётся на КАЖДЫЙ объявленный сегмент, а не на резолвящийся. Писатель один — role_repo.ReplaceRuleRefs.';

COMMENT ON COLUMN kacho_iam.role_rule_ref.verb IS
  'NULL — ЯКОРЬ (правило не сузило глаголы). Ключ ресурса на такой строке проверяется, ключ глагола пропускается MATCH SIMPLE — ресурс уже проверен первым.';

-- ── СИРОТЫ ВЫДАЧИ ─────────────────────────────────────────────────────────────

CREATE TABLE kacho_iam.role_grant_orphan (
  role_id     text        NOT NULL
    REFERENCES kacho_iam.roles (id) ON DELETE CASCADE,
  object_type text        NOT NULL,
  -- verb — пустая строка означает ЯКОРЬ у строки, пришедшей из объявления
  -- правила. Здесь `''`, а не NULL, намеренно и по другой причине, чем в
  -- role_rule_ref: там NULL ТРЕБУЕТСЯ семантикой ключа, здесь ключа нет, и
  -- пустая строка оставляет первичный ключ простым.
  verb        text        NOT NULL,
  -- source — откуда переселена строка. Две популяции: выдача (`role_verb`) и
  -- объявление (`role_rule_ref`). Смешать их значило бы потерять различие между
  -- «право отобрано» и «правило перестало резолвиться».
  source      text        NOT NULL,
  reason      text        NOT NULL,
  orphaned_at timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT role_grant_orphan_pkey PRIMARY KEY (role_id, object_type, verb, source),
  CONSTRAINT role_grant_orphan_source_known CHECK (source IN ('role_verb', 'rule_ref')),
  CONSTRAINT role_grant_orphan_reason_nonempty CHECK (reason <> ''),
  CONSTRAINT role_grant_orphan_type_nonempty CHECK (object_type <> '')
);

COMMENT ON TABLE kacho_iam.role_grant_orphan IS
  'Выдачи и объявления, потерявшие референт при снятии строки каталога. Снятие ПЕРЕСЕЛЯЕТ, а не отбирает молча: без этой таблицы отобранное право было бы неотличимо от никогда не выданного.';

-- ── ОБРАТНОЕ ЗАПОЛНЕНИЕ ПРОЕКЦИИ ПРАВИЛА ─────────────────────────────────────
--
-- Подстановка `*` в модуле и ресурсе сегмента НЕ даёт: она называет не имя, а
-- «все», и адресовать ею строку каталога нечего. Подстановка в глаголе даёт
-- ЯКОРЬ — одну строку с NULL.
--
-- Кладётся только то, что резолвится в живой каталог. Непокрытое НЕ пропускается
-- молча — оно переселяется в сироты ниже, вместе с непокрытыми парами выдачи:
-- иначе `ADD CONSTRAINT` был бы сюрпризом, а расхождение — невидимым.
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb)
SELECT DISTINCT
       r.id,
       rule ->> 'module'                                        AS module,
       res.value #>> '{}'                                       AS resource,
       CASE WHEN EXISTS (
              SELECT 1 FROM jsonb_array_elements_text(rule -> 'verbs') w
               WHERE w = '*')
            THEN NULL
            ELSE lower(btrim(vrb.value #>> '{}'))
       END                                                      AS verb
  FROM kacho_iam.roles r,
       LATERAL jsonb_array_elements(COALESCE(r.rules, '[]'::jsonb)) rule,
       LATERAL jsonb_array_elements(rule -> 'resources') res,
       LATERAL jsonb_array_elements(rule -> 'verbs') vrb
 WHERE rule ->> 'module' <> '*'
   AND res.value #>> '{}' <> '*'
   AND EXISTS (
         SELECT 1 FROM kacho_iam.catalog_resource cr
          WHERE cr.module = rule ->> 'module'
            AND cr.resource = res.value #>> '{}'
            AND cr.live)
   AND (
         EXISTS (SELECT 1 FROM jsonb_array_elements_text(rule -> 'verbs') w WHERE w = '*')
         OR EXISTS (
              SELECT 1 FROM kacho_iam.catalog_verb cv
               WHERE cv.module = rule ->> 'module'
                 AND cv.resource = res.value #>> '{}'
                 AND cv.verb = lower(btrim(vrb.value #>> '{}'))
                 AND cv.live)
       )
ON CONFLICT DO NOTHING;

-- Объявленные сегменты, которым в каталоге нечего адресовать, — в сироты.
-- Это НЕ находка миграции и не отказ: правило, называющее снятый или
-- несуществующий ресурс, уже сегодня не даёт ничего, и переселение делает это
-- состояние ВИДИМЫМ вместо того, чтобы оставить его молчаливым.
INSERT INTO kacho_iam.role_grant_orphan (role_id, object_type, verb, source, reason)
SELECT DISTINCT
       r.id,
       (rule ->> 'module') || '.' || (res.value #>> '{}'),
       CASE WHEN EXISTS (
              SELECT 1 FROM jsonb_array_elements_text(rule -> 'verbs') w WHERE w = '*')
            THEN ''
            ELSE lower(btrim(vrb.value #>> '{}'))
       END,
       'rule_ref',
       'сегмент правила не имеет живой строки каталога на момент 20260901113757 (kacho#1030)'
  FROM kacho_iam.roles r,
       LATERAL jsonb_array_elements(COALESCE(r.rules, '[]'::jsonb)) rule,
       LATERAL jsonb_array_elements(rule -> 'resources') res,
       LATERAL jsonb_array_elements(rule -> 'verbs') vrb
 WHERE rule ->> 'module' <> '*'
   AND res.value #>> '{}' <> '*'
   AND NOT EXISTS (
         SELECT 1 FROM kacho_iam.role_rule_ref rr
          WHERE rr.role_id = r.id
            AND rr.module = rule ->> 'module'
            AND rr.resource = res.value #>> '{}'
            AND COALESCE(rr.verb, '') = CASE WHEN EXISTS (
                  SELECT 1 FROM jsonb_array_elements_text(rule -> 'verbs') w WHERE w = '*')
                THEN '' ELSE lower(btrim(vrb.value #>> '{}')) END)
ON CONFLICT DO NOTHING;

-- ── ПЕРЕСЕЛЕНИЕ НЕПОКРЫТЫХ ПАР ВЫДАЧИ ────────────────────────────────────────
--
-- Разность «пары role_verb минус посеянный каталог» — это данные к переселению,
-- а не сюрприз. Её производители названы и все из дерева: три снятых точечных
-- типа; снятие `v_create` у 24 типов; снятие `v_update` и `v_delete` у
-- `iam_user`. Пустая разность тоже законна — тогда переселится ноль строк.
INSERT INTO kacho_iam.role_grant_orphan (role_id, object_type, verb, source, reason)
SELECT rv.role_id, rv.object_type, rv.verb, 'role_verb',
       'пара выдачи не покрыта живым каталогом на момент 20260901113757 (kacho#1030)'
  FROM kacho_iam.role_verb rv
 WHERE NOT EXISTS (
         SELECT 1 FROM kacho_iam.catalog_verb cv
          WHERE cv.module || '.' || cv.resource = rv.object_type
            AND cv.verb = rv.verb
            AND cv.live)
    OR NOT EXISTS (
         SELECT 1 FROM kacho_iam.catalog_resource cr
          WHERE cr.dotted = rv.object_type AND cr.live)
ON CONFLICT DO NOTHING;

-- Удаляется РОВНО то, что переселено, и по ТОМУ ЖЕ предикату. Асимметрия здесь
-- была бы хуже отсутствия переселения: строка сирот утверждала бы «право
-- отобрано», а строка выдачи продолжала бы его давать.
--
-- Предикат — на ТРОЙКУ (модуль, ресурс, глагол), а не на ресурс: разность,
-- которую требует предикат готовности приёмки (§8.1), считается тройками, и
-- пара, чей ресурс жив, а глагол каталогом не объявлен, в неё входит.
DELETE FROM kacho_iam.role_verb rv
 WHERE NOT EXISTS (
         SELECT 1 FROM kacho_iam.catalog_resource cr
          WHERE cr.dotted = rv.object_type AND cr.live)
    OR NOT EXISTS (
         SELECT 1 FROM kacho_iam.catalog_verb cv
          WHERE cv.module || '.' || cv.resource = rv.object_type
            AND cv.verb = rv.verb
            AND cv.live);

-- ── КОЛОНКА ЖИВОСТИ У ПРОЕКЦИИ ГЛАГОЛОВ ──────────────────────────────────────
--
-- Колонка ОБЫЧНАЯ, а не генерируемая, — и здесь довод из шапки применим прямо:
-- `role_verb` таблица ЖИВАЯ, и генерируемая колонка переписала бы её кучу под
-- ACCESS EXCLUSIVE.
ALTER TABLE kacho_iam.role_verb
  ADD COLUMN live boolean NOT NULL DEFAULT true;

ALTER TABLE kacho_iam.role_verb
  ADD CONSTRAINT role_verb_live_true CHECK (live);

COMMENT ON COLUMN kacho_iam.role_verb.live IS
  'Константа true. Колонка существует ради ключа role_verb_type_fk: сослаться на «эту строку каталога И она жива» без неё нечем.';

-- ── КЛЮЧИ ────────────────────────────────────────────────────────────────────

ALTER TABLE kacho_iam.role_rule_ref
  ADD CONSTRAINT role_rule_ref_res_fk
  FOREIGN KEY (module, resource, live)
  REFERENCES kacho_iam.catalog_resource (module, resource, live)
  ON DELETE NO ACTION ON UPDATE NO ACTION
  DEFERRABLE INITIALLY IMMEDIATE;

ALTER TABLE kacho_iam.role_rule_ref
  ADD CONSTRAINT role_rule_ref_verb_fk
  FOREIGN KEY (module, resource, verb, live)
  REFERENCES kacho_iam.catalog_verb (module, resource, verb, live)
  ON DELETE NO ACTION ON UPDATE NO ACTION
  DEFERRABLE INITIALLY IMMEDIATE;

ALTER TABLE kacho_iam.role_verb
  ADD CONSTRAINT role_verb_type_fk
  FOREIGN KEY (object_type, live)
  REFERENCES kacho_iam.catalog_resource (dotted, live)
  ON DELETE NO ACTION ON UPDATE NO ACTION
  DEFERRABLE INITIALLY IMMEDIATE;

-- ── САМОПРОВЕРКА ИСХОДА ───────────────────────────────────────────────────────
--
-- Миграция проверяет СВОЙ результат и роняет применение при недостижении.
-- Посев не в полном объёме означает, что ADD CONSTRAINT отобрал у арендатора
-- живой доступ, а это необратимо на месте (запрет #5). Образец — 513001.
-- +goose StatementBegin
DO $$
DECLARE
    live_modules   int;
    live_resources int;
    live_verbs     int;
    retired_res    int;
    dangling_ref   int;
    dangling_verb  int;
BEGIN
    SELECT count(*) INTO live_modules   FROM kacho_iam.catalog_module   WHERE live;
    SELECT count(*) INTO live_resources FROM kacho_iam.catalog_resource WHERE live;
    SELECT count(*) INTO live_verbs     FROM kacho_iam.catalog_verb     WHERE live;
    SELECT count(*) INTO retired_res    FROM kacho_iam.catalog_resource WHERE NOT live;

    IF live_modules <> 6 OR live_resources <> 27 OR live_verbs <> 109 OR retired_res <> 3 THEN
        RAISE EXCEPTION
            'посев каталога не в полном объёме: модулей % (ждали 6), живых ресурсов % '
            '(ждали 27), пар глаголов % (ждали 109), снятых ресурсов % (ждали 3) — '
            'ADD CONSTRAINT на неполном каталоге отбирает у арендатора живой доступ '
            '(kacho#1030, IAM-CT-1-04)',
            live_modules, live_resources, live_verbs, retired_res;
    END IF;

    -- Разность ПОСЛЕ переселения обязана быть пуста в обе стороны.
    SELECT count(*) INTO dangling_ref
      FROM kacho_iam.role_rule_ref rr
     WHERE NOT EXISTS (SELECT 1 FROM kacho_iam.catalog_resource cr
                        WHERE cr.module = rr.module AND cr.resource = rr.resource AND cr.live);
    -- Разность §8.1 приёмки: тройка (модуль, ресурс, глагол) выдачи минус
    -- живой каталог. Считать её по РЕСУРСУ было бы слабее объявленного — пара с
    -- живым ресурсом и неизвестным глаголом прошла бы незамеченной.
    SELECT count(*) INTO dangling_verb
      FROM kacho_iam.role_verb rv
     WHERE NOT EXISTS (SELECT 1 FROM kacho_iam.catalog_resource cr
                        WHERE cr.dotted = rv.object_type AND cr.live)
        OR NOT EXISTS (SELECT 1 FROM kacho_iam.catalog_verb cv
                        WHERE cv.module || '.' || cv.resource = rv.object_type
                          AND cv.verb = rv.verb AND cv.live);

    IF dangling_ref <> 0 OR dangling_verb <> 0 THEN
        RAISE EXCEPTION
            'после переселения остались висячие строки: проекции правила %, выдачи % '
            '— ключ бы их отверг, и миграция не применилась бы молча (kacho#1030, IAM-CT-1-09)',
            dangling_ref, dangling_verb;
    END IF;

    -- Перепись печатается ВСЕГДА: «ноль переселённых» обязано быть отличимо от
    -- «ноль прочитанных».
    RAISE NOTICE 'каталог посеян: модулей %, живых ресурсов %, пар глаголов %, снятых ресурсов %',
        live_modules, live_resources, live_verbs, retired_res;
    RAISE NOTICE 'переселено в сироты: % строк',
        (SELECT count(*) FROM kacho_iam.role_grant_orphan);
    RAISE NOTICE 'проекция объявленных сегментов: % строк',
        (SELECT count(*) FROM kacho_iam.role_rule_ref);
END;
$$;
-- +goose StatementEnd

-- +goose Down
--
-- ОТКАТ НЕ ВОССТАНАВЛИВАЕТ ПЕРЕСЕЛЁННОЕ, и это сказано прямо, а не умолчано.
--
-- Строки выдачи, у которых на момент применения не было живого референта, здесь
-- УДАЛЕНЫ, а их след перенесён в `role_grant_orphan`; откат снимает и таблицу
-- следа. Восстановить их можно только пересчётом проекции — досевом на старте
-- для системных ролей и правкой роли для арендаторских, — то есть тем же путём,
-- каким они появились. Обратной вставки здесь НЕТ намеренно: она вернула бы
-- строки, которые уже тогда не давали ни одного права, и сделала бы откат
-- источником состояния, которого не было ни до, ни после.
--
-- Снять след ДО того, как снят его предмет: `role_grant_orphan` ссылается на
-- роли, а не на каталог, поэтому порядок здесь — от зависящего к тому, от чего
-- зависят.

ALTER TABLE kacho_iam.role_verb DROP CONSTRAINT role_verb_type_fk;
ALTER TABLE kacho_iam.role_verb DROP CONSTRAINT role_verb_live_true;
ALTER TABLE kacho_iam.role_verb DROP COLUMN live;
DROP TABLE kacho_iam.role_grant_orphan;
DROP TABLE kacho_iam.role_rule_ref;
DROP TABLE kacho_iam.catalog_verb;
DROP TABLE kacho_iam.catalog_resource;
DROP TABLE kacho_iam.catalog_module;
