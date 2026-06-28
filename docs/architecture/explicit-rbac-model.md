# Explicit RBAC model — kacho-iam authz

Нормативное описание модели авторизации `kacho-iam` в том виде, в каком она
работает в проде. Это **источник истины** по тому, как грант превращается в
доступ; остальные документы (`19-authorize.md`, `29-openfga-check.md`,
`08-access-binding.md`, `07-role.md`) ссылаются сюда, а не дублируют модель.

Аудитория — архитектор / оператор / интегратор, которому нужно понять, **почему**
у субъекта есть (или нет) доступ к ресурсу и как это аудировать.

## Зачем именно так

Раньше доступ выводился каскадом в графе OpenFGA: «есть отношение на родителя
(account/project/cluster) ⇒ есть доступ ко всему содержимому» плюс отдельный
escalation-движок (`scope_grant`). Каскад было трудно объяснить и аудировать:
один факт доступа складывался из нескольких вычисляемых правил, и «почему у X
есть доступ» нельзя было свести к перечню строк.

Модель переведена на **явную RBAC с per-object материализацией**. Принцип:

> Каждый факт доступа — это явный relation-tuple на конкретном объекте, который
> можно **перечислить**, **объяснить** (`ExpandAccess`) и **снять** (revoke), без
> «магического» каскада.

OpenFGA в этой модели — **плоский индекс** (storage-слой): прямые tuple на
объектах, без вычисляемых иерархических каскадов доступа. Единственное
исключение — cluster super-admin (один флаг + short-circuit, см. ниже).

## Три кита модели

| Понятие | Что это |
|---|---|
| **Роль** | неизменная единица: `rules[]`, каждое правило `{module, resources[], verbs[], selector}` |
| **Грант (AccessBinding)** | `(subjects[], role, scope)` — кому, какая роль, в какой **границе** |
| **Материализация** | reconciler разворачивает грант в прямые per-object tuple внутри границы |

### 1. Роль = набор правил (rules)

Роль — `{id, name, is_system, scope, rules[]}`. Каждое правило:

```
{ module: "<module>", resources: ["<r>", …], verbs: ["<v>", …], selector }
```

Селектор правила — одна из трех форм (выводится из формы правила, не хранится
отдельным enum-полем):

| Форма | Когда | Что материализуется |
|---|---|---|
| **all** (anchor) | нет ни `resource_names`, ни `match_labels` | все объекты матчащих типов внутри границы |
| **names** | задан `resource_names[]` | объекты с перечисленными именами/id |
| **labels** | задан `match_labels{}` | объекты, чьи labels содержат match-набор (`@>`) |

`names` и `labels` взаимоисключающи. Wildcard `*` в `module`/`resources`/`verbs`
разрешен **только** системным ролям и только как единственный элемент.

Семантика ролей и селекторов **не менялась** при переходе на explicit-модель —
изменился только способ энфорса (явные tuple вместо каскада).

### 2. Грант = (subjects, role, scope)

`AccessBinding` связывает `subjects[]` (1..32 субъекта: `user` / `service_account`
/ `group`) с ролью в пределах **scope**. Scope несет `scope_ref {tier, id}`:

| tier (proto enum `Scope`) | Граница материализации |
|---|---|
| `CLUSTER` (концептуально «GLOBAL») | весь кластер |
| `ACCOUNT` | один account и все его содержимое (все его project'ы) |
| `PROJECT` | один project и его содержимое |

**Ключевая идея:** `scope` — это **граница материализации, а не корень
наследования**. Сам по себе scope не дает доступа к содержимому. Он лишь
ограничивает область, внутри которой селектор правила ищет объекты для
материализации.

> Иерархия владения в Kachō — **Account → Project** (двухуровневая). Сущностей
> `folder` / `organization` нет — они полностью удалены из модели авторизации.

### 3. Материализация — единый reconciler

Грант разворачивается в доступ **единым reconciler'ом** (binding-time эмиссии
`scope_grant` больше нет — это единственный путь материализации). Для каждого
активного гранта reconciler вычисляет пересечение:

```
scope ⊇ местоположение(объект)   И   selector матчит(объект)
   →  эмитируется прямой tuple  <objType>:<id> # v_<verb> @ <subject>
```

Verb-relation на объекте — `v_get` / `v_list` / `v_create` / `v_update` /
`v_delete` (+ tier `admin` для admin-набора). Снятые/измененные гранты
снимают tuple **по сохраненному ledger** (`access_binding_emitted_tuples`), не
пере-выводя из роли.

#### Forward-materialization

Ресурс, появившийся в границе гранта **после** его создания (включая ресурсы в
account'е, созданном владельцем «на пустом месте»), материализуется тем же
reconciler-путем на своем `RegisterResource`/Create — грант не «протухает» на
поздних ресурсах. Forward-path — нормативная часть движка, а не отдельный
механизм.

#### Eventually-consistent на grant→access

Мутации (`Create`/`Delete`/`Update` гранта) — async `Operation`; клиент поллит
`OperationService.Get(id)` до `done=true`. Материализация доступа —
eventually-consistent: на create-пути выполняется sync-write tuple для
собственного объекта, а полный охват границы досходится async-реконсиляцией
(backstop через transactional-outbox). Watch-RPC нет.

## owner — системная роль аккаунта

`owner` — системная (cluster-scoped, `is_system=true`) роль с правилом-wildcard:

```json
rules = [{ "module": "*", "resources": ["*"], "verbs": ["*"] }]
```

Она всегда биндится **@ ACCOUNT** (граница = именно этот account, не весь
кластер):

- На `Account.Create` сервис **авто-создает** `AccessBinding(subject=creator,
  role=owner, scope=ACCOUNT:<A>)` в той же writer-транзакции, что и сам account
  (атомарный co-commit: account-строка + binding + ledger + fga-outbox).
- Авто-binding несет `deletion_protection=true` (см. ниже).

**Как owner достает содержимое (per-object, не каскад):** в границе ACCOUNT
wildcard-правило `*.*.*` **разворачивается per-object** — reconciler перечисляет
все материализуемые типы внутри account'а и эмитирует на каждый объект прямые
`v_*` + `admin` tuple. На момент `Account.Create` account пуст → материализуется
только self-tuple на `account:<A>`; содержимое досоздается **forward** на Create
каждого ресурса в account'е. Так owner доступ остается **явным набором tuple**,
а не вычисляемым каскадом, и не протухает на ресурсах, созданных позже.

> На границе CLUSTER тот же wildcard НЕ разворачивается per-object (это был бы
> неограниченный churn) — cluster-wide super-grant обслуживает short-circuit
> (см. cluster super-admin). Per-object материализация owner ограничена именно
> тем, что owner биндится @ ACCOUNT, а не @ CLUSTER.

## cluster super-admin — единственное исключение из per-object

Материализовать per-object «на весь кластер» — анти-паттерн (миллионы tuple,
churn на каждом Create). Поэтому cluster-admin — это:

1. **Одно плоское cluster-relation** `cluster:cluster_kacho_root # system_admin @ <subject>`.
2. **Check short-circuit**: «является ли subject cluster-admin?» → ALLOW, минуя
   обычный per-object резолв.

Это **плоский супер-гейт**, а не иерархический каскад (`from cluster` в модели
нет). Один факт = один tuple = одна строка в `cluster_admin_grants` — остается
явным и аудируемым.

Short-circuit применяется **не только** к read-Check (`AuthorizeService.Check` /
`InternalIAMService.Check`), но и ко **всем write-authz-проверкам** выдачи грантов
(`requireGrantAuthority`, `fgaHoldsAdmin`). После удаления каскада cluster-admin
теряет implicit account/project-tier admin — поэтому его право выдавать гранты на
**любой** account и управлять самими `AccessBinding`-объектами обеспечивается тем
же short-circuit, а не каскадом.

### Bootstrap (chicken-egg + separation of duties)

Первый cluster-admin сидится на инсталле через internal-only
`InternalClusterService` (env `KACHO_IAM_BOOTSTRAP_ROOT_EMAIL`): в одной tx —
строка `cluster_admin_grants` + fga-outbox tuple `system_admin` + audit-событие.
Идемпотентно: повторный рестарт ловит partial-unique (SQLSTATE 23505) и тихо
пропускает. **Self-grant через публичный API невозможен** — нет публичного пути к
cluster super-admin до bootstrap.

Дальше существующий cluster-admin выдает его другим публичным
`AccessBindingService/Create(role=cluster-admin, scope=GLOBAL)` — этот binding
эмитирует **то самое cluster-relation** (спец-случай, не per-object). Вызов от
не-cluster-admin → `PERMISSION_DENIED`.

**Защита cluster-admin'а** — функциональная (без отдельного флага): нельзя
ревокнуть последнего активного (`"cannot revoke last active cluster admin"`) и
нельзя ревокнуть себя (`"cannot revoke own cluster admin grant"`) — атомарный
CAS-guard в `RevokeAdmin`.

`InternalClusterService` живет **только** на cluster-internal listener (:9091) и
никогда не публикуется на external TLS endpoint.

## account/project — verb-bearing ресурсы

`account` и `project` теперь несут собственный замкнутый набор verb-relations
(`v_get/v_list/v_create/v_update/v_delete`), как листовые ресурсы. Следствие:

- Грант роли `iam.account.get` @ ACCOUNT материализует `account:<A> # v_get @
  subj` — доступ к **самому** account-объекту, без доступа к его содержимому.
- «Видеть account/project в селекторе/списке, но не иметь доступа к контенту»
  выпадает само: `Check(subj, get, account:A)` → allowed, при этом
  `Check(subj, get, vpc_network:N ∈ A)` → denied (каскада нет).

Tier `admin`/`editor`/`viewer` на account/project **остается**, но только как
write-authz-якорь (кто вправе выдавать гранты на этот scope), **без** down-cascade
в семантику доступа. То есть `account:<A> # admin @ subj` означает «subj вправе
администрировать гранты на этом account'е», а не «subj имеет admin на все внутри».

## GLOBAL-граница: что легально

| Селектор | Обычная роль @ GLOBAL | cluster-admin роль @ GLOBAL |
|---|---|---|
| **all** | **запрещен** — sync `INVALID_ARGUMENT` | разрешен → cluster-relation (short-circuit) |
| **names** / **labels** | разрешен → per-object кластер-wide по матч-объектам | — |

`GLOBAL + all` для обычной (не-cluster-admin) роли отклоняется синхронно с
текстом:

```
GLOBAL scope requires names or labels selector for non-cluster-admin roles
```

Причина: per-object материализация «на весь кластер» для обычной роли — это
неограниченный ledger + churn на каждом Create. Обычная роль на GLOBAL легальна
только с `names`/`labels` (конечный, явный набор матч-объектов). Единственное
исключение — системная cluster-admin роль (`*.*.*`), которой `GLOBAL+all` легален
и обслуживается short-circuit'ом.

## Check: плоский резолв

`AuthorizeService.Check` / `InternalIAMService.Check`:

1. Прямой FGA-Check по материализованному per-object tuple (плоский, без каскада).
2. На отказе — short-circuit cluster-admin (если subject — cluster-admin → ALLOW).
3. `resource.id == "*"` (unscoped List) → чистый DENY (не ошибка).
4. verb не резолвится в relation → fail-closed DENY.

`ExpandAccess(object, relation)` перечисляет явных принципалов по прямым tuple
(группы развернуты до членов) — после удаления каскадного indirection это
тривиальный обход графа.

Публичный `List<Resource>` каждого сервиса фильтрует результат по
материализованным per-object tuple владельца (CI-гейт `make audit-list-filter`).

## Снятие доступа (revoke / label-change / scope-exit)

Доступ снимается **по сохраненному ledger**, а не пере-выводится из роли:

- **revoke гранта** (`AccessBindingService/Delete`) → сняты все материализованные
  tuple в той же writer-tx, что и удаление binding-строк.
- **смена метки** объекта, выводящая его из-под labels-селектора → consumer
  эмитирует `RegisterResource`, reconciler видит «больше не матчится» → revoke
  tuple.
- **объект покинул scope / удален** → consumer эмитирует `UnregisterResource` →
  revoke tuple. IAM грациозно переживает dangling-ref (не паникует).
- **`Role.Update` изменил rules** → для каждого активного гранта роли реконсиляция
  диффа желаемое-vs-ledger (добавить/снять), идемпотентно.

## deletion_protection на гранте

`AccessBinding.deletion_protection` (`bool`, default false). owner-auto-binding
ставит `true`. `Delete` protected-гранта:

- sync pre-check → `FAILED_PRECONDITION` `"access binding <id> has
  deletion_protection enabled; clear it via Update before Delete"`;
- атомарный CAS-backstop `DELETE … WHERE deletion_protection=false` против TOCTOU.

Снять защиту — `Update(update_mask=["deletion_protection"], deletion_protection=
false)`, затем `Delete`.

## RPC-поверхность (где живет)

| RPC | Listener | Sync/Async |
|---|---|---|
| `AccessBindingService.{Create,Update,Delete}` | public :443 | async `Operation` |
| `AccessBindingService.{Get,ListByScope,ListBySubject,ListByRole,ListByAccount,ExpandAccess,ListSubjectPrivileges,ListAssignableRoles}` | public :443 | sync |
| `AuthorizeService.Check` | public :443 (+ internal для service→service) | sync |
| `InternalIAMService.Check` | internal :9091 | sync |
| `InternalClusterService.{GrantAdmin,RevokeAdmin}` | internal :9091 | async `Operation` |
| `InternalClusterService.{Get,ListAdmins}` | internal :9091 | sync |

## Системные роли

Системных ролей в каталоге — **64** (58 catalog + 5 module-SA + net-new `owner`).
Сидятся миграциями с детерминированными id (`'rol' || substr(md5(name),1,17)`),
идемпотентно (`ON CONFLICT (id) DO NOTHING`). Их `rules[]` — единственный источник
авторизационного смысла роли (legacy `permissions`-проекция — deprecated, остается
на чтении для совместимости).

## Канонические объекты модели (FGA)

- **subject-типы**: `user`, `service_account`, `group#member`, `federated_subject`.
- **leaf-объекты**: прямые `v_*` relation-tuple (+ tier для write-authz-якоря).
- **`account` / `project`**: verb-bearing + tier (admin/editor/viewer) как
  write-authz-якорь.
- **`cluster:cluster_kacho_root`**: `system_admin` — плоский cluster super-admin.
- **`type organization` / любые `… from organization` / `… from account|project|
  cluster` каскады доступа / `scope_grant`** — **удалены**.

## Связанные документы

- [`08-access-binding.md`](../components/08-access-binding.md) — AccessBinding-ресурс, поля, RPC.
- [`07-role.md`](../components/07-role.md) — Role-ресурс, rules, system seed.
- [`19-authorize.md`](../components/19-authorize.md) — `AuthorizeService.Check` pipeline.
- [`29-openfga-check.md`](../components/29-openfga-check.md) — выполнение Check в OpenFGA.
- [`assignable-roles-scope-enforcement.md`](assignable-roles-scope-enforcement.md) — какие роли назначаемы в каком scope.
