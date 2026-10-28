<!--
Copyright (c) PRO-Robotech
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Приёмка: отказ снятия личности и аккаунта называет остаток и следующий шаг (kaname#725)

> **Статус:** DRAFT
> **Статическая форма:** DRAFT; действующий вердикт выводится из внешнего события и записи ревью,
> каталог `docs/specs/reviews/deletion-refusals-name-the-remainder-and-the-step/`
> **История review:** строки только дописываются; прежние не правятся и не удаляются
> - редакция 1 — 2026-10-15 — кругов ноль; отпечаток считает `sha256sum` этого файла
> - редакция 1 — 2026-10-15 — круг 1 — CHANGES_REQUESTED — `32177117…ae160faf` —
>   `docs/specs/reviews/deletion-refusals-name-the-remainder-and-the-step/3217711702358047275c3f7c588011e80d55704e9b1d589487733d42ae160faf.yaml`
> - редакция 2 — 2026-10-15 — правка по B1–B4 и замечаниям круга 1 (раздел «Дельта к редакции 1»);
>   отпечаток считает `sha256sum` этого файла
> - редакция 2 — 2026-10-15 — круг 2 — APPROVED — `b7a49bb0…846d5f0` —
>   `docs/specs/reviews/deletion-refusals-name-the-remainder-and-the-step/b7a49bb043e611e774b689c800391dd9cfc42c37bdb09b37e50bae535846d5f0.yaml`
> - редакция 3 — 2026-10-16 — правка ПОСЛЕ вердикта круга 2: вердикт `b7a49bb0…` на неё не переносится; только §0.4: предикат потребителей в `PRO-Robotech/kacho` записан формой
>   названного дома с ревизией `a95248464` (гейт `TestAcceptancePathCoordinateResolves`); вывод тот же,
>   утверждения не меняются; отпечаток считает `sha256sum` этого файла
> **Дата:** 2026-10-15
> **Эпик/issue:** PRO-Robotech/kaname#725 (P2), волна 8 линии identity-own (`PRO-Robotech/kacho#3162`),
> источник — `PRO-Robotech/kacho#3127`
> **Дом:** `docs/engineering/acceptance/` службы — предмет внутри одного сервиса (`UserService`,
> `AccountService`); потребители текста в `PRO-Robotech/kacho` названы в DoD п. 6 ребром, не предметом
> **Ревизия измерения:** код — `ede94db30` (голова ветки `725-w9-kn-acc-proto-b` = `f8021ad84`;
> `git diff --stat ede94db30 HEAD -- internal proto tests` пуст — между ними только документы приёмки);
> `PRO-Robotech/kacho` `origin/main` = `a95248464`
> **Опора (fa-b7):** `own-account-and-identity-are-removed-in-order.md` — одобренная редакция 5,
> отпечаток `f10f3e8693f26763b1658b351c1fa3891922ae9b987e1a62f6c125bde05a31b4`, запись
> `docs/specs/reviews/own-account-and-identity-are-removed-in-order/f10f3e8693f26763b1658b351c1fa3891922ae9b987e1a62f6c125bde05a31b4.yaml`
> (`verdict: APPROVED`). Этот документ **меняет** её утверждения о тексте отказов KN664-11, KN664-31,
> KN664-36 (Р1–Р3 ниже) и ничего больше: порядок «аккаунт → личность», коды, пороги уровня, состав
> транзакции снятия остаются её предметом. Сменится редакция опоры — опора перепроверяется до захода.
> **Тип изменения:** меняет **тексты и признак** отказов двух существующих глаголов —
> `UserService.Delete` и `AccountService.Delete`. Кодов, полей, RPC, порогов уровня и схемы не меняет.
> Отказ `UserService.RemoveFromAccount` **не** меняется (редакция 2, B1): он уже называет держащие
> выдачи, их число и шаг своей формой (§0.1, «Что НЕ входит»).

## §0 Перепись производителей — до сценариев

Каждая строка — что в дереве **уже** производит факт, на котором стоит сценарий, и команда, которой
получено. Пути — от корня репозитория службы, ревизия `ede94db30`.

### 0.1. Тексты отказов по содержимому — все производители

```sh
git grep -n -e 'owns accounts and cannot be deleted' -e 'has active access bindings and cannot be deleted' \
  -e 'is a member of one or more groups and cannot' -e 'cannot be removed from it' \
  -- internal/repo/kaname/pg/user_repo.go internal/repo/kaname/pg/pgmaperr.go
git grep -n 'cannot be deleted' -- internal/repo/kaname/pg/account_repo.go
# по признаку и по месту, где к тексту дописывается хвост (редакция 2, B1):
git grep -n -E 'Message\(\) *\+|st\.Message\(\)|WithDetails\(' -- 'internal/apps/kaname/**/*.go' ':!*_test.go'
git grep -n -E 'reason[A-Za-z]* *= *"[A-Z_]+"' -- 'internal/**/*.go' ':!*_test.go'
git grep -n -E 'MapRepoErr|Refusal|Message' -- internal/apps/kaname/api/user/delete.go internal/apps/kaname/api/account/delete.go
```

| глагол | отказ | рубеж | координата | полоса (`iamerr`) | признак наружу |
|---|---|---|---|---|---|
| `UserService.Delete` | `User %s owns accounts and cannot be deleted` | охрана оператора | `user_repo.go`:834 | `ErrReferenceInUse` | `REFERENCE_IN_USE` |
| то же | то же | ключ `accounts_owner_fk` на фиксации (гонка) | `pgmaperr.go`:496 | `ErrReferenceInUse` | `REFERENCE_IN_USE` |
| то же | `User %s has active access bindings and cannot be deleted` | охрана оператора | `user_repo.go`:837 | `ErrFailedPrecondition` | **нет** |
| то же | `%s %s has active access bindings and cannot be deleted` | триггер схемы (гонка) | `pgmaperr.go`:618 | `ErrReferenceInUse` | `REFERENCE_IN_USE` |
| то же | `User %s is a member of one or more groups and cannot be deleted` | охрана оператора | `user_repo.go`:840 | `ErrFailedPrecondition` | **нет** |
| `AccountService.Delete` | `Account %s contains projects` · `service accounts` · `groups` · `custom roles` `and cannot be deleted` | охрана оператора | `account_repo.go`:404, 406, 408, 410 | `ErrFailedPrecondition` | **нет** |
| то же | те же тексты | ключи `*_account_fk` (гонка) | `pgmaperr.go`:505, 510, 515, 520 | `ErrReferenceInUse` | `REFERENCE_IN_USE` |
| `UserService.RemoveFromAccount` — **не предмет** | `User %s still has active access bindings in Account %s and cannot be removed from it` + хвост `: <acb…>[, …][ and N more] (N total); revoke them before removing the membership` | отложенный триггер `membership_carrying_rights_is_kept` на фиксации; хвост дописывает use-case отдельным чтением после отказа | основа — `pgmaperr.go`:722 (запасной — :724); хвост — `internal/apps/kaname/shared/membership_refusal.go`:120, :131, дочитывание — `internal/apps/kaname/api/user/remove_from_account.go`:213 | `ErrMembershipCarriesRights` | `MEMBERSHIP_CARRIES_RIGHTS`, `metadata` `blocking_binding_ids` (до 5), `blocking_binding_count` (`membership_refusal.go`:45, :51–52) |

Признак у полосы «ещё ссылаются» ставит один производитель — `referenceRefusal`
(`internal/apps/kaname/shared/reference_refusal.go`:50): `REFERENCE_IN_USE` получает только ошибка,
вложенная в `ErrReferenceInUse`. Отсюда измеренное расхождение: **один и тот же отказ несёт признак
на рубеже гонки и не несёт его на рубеже охраны** — у выдач, у групп и у всех четырёх отказов
`AccountService.Delete`. Клиент, ветвящийся по `reason`, видит два разных отказа там, где отказ один.

Ни один текст `UserService.Delete` и `AccountService.Delete` не называет **какой** ресурс держит
снятие и **что сделать**; у этих двух глаголов второго производителя текста нет — их use-case
отдают отказ репозитория через `shared.MapRepoErr` как есть (`internal/apps/kaname/api/user/delete.go`:64,
:69; `internal/apps/kaname/api/account/delete.go`:60, :65), хвоста не дописывает никто (перепись по
месту дописывания выше: `Message()+` есть только у `membership_refusal.go`:120). Метаданных у
`ErrorInfo` (`resource_type`, `resource_id`) у них нет (`reference_refusal.go`:67–70 — только
`Reason` и `Domain`).

Отказ `UserService.RemoveFromAccount` — исключение из «не называет»: с `kacho#1686` он называет
держащие выдачи (до пяти), их полное число и шаг, и несёт **свой** признак
`MEMBERSHIP_CARRIES_RIGHTS` с `metadata` `blocking_binding_ids` / `blocking_binding_count`.
Держатели — `tests/newman/cases/iam-user.py`:2630–2636 (`IAM-USR-EXCL-NEG-LIVE-GRANT`, текст
регекспом целиком, признак) и `internal/apps/kaname/api/user/remove_from_account_names_grants_test.go`:190.
Этот документ его **не меняет** (редакция 2, B1).

### 0.2. Пороги уровня глаголов, которые называет шаг

```sh
git grep -n 'required_acr_min' -- proto/kaname/cloud/iam/v1/user_service.proto proto/kaname/cloud/iam/v1/account_service.proto
for s in project service_account group role; do awk '/rpc Delete /{d=1} d&&/required_acr_min/{print FILENAME": "$0; d=0}' proto/kaname/cloud/iam/v1/${s}_service.proto; done
awk '/rpc (Revoke|RemoveMember) /{d=1} d&&/required_acr_min/{print FILENAME": "$0; d=0}' proto/kaname/cloud/iam/v1/access_binding_service.proto proto/kaname/cloud/iam/v1/group_service.proto
```

`UserService.Delete` (`user_service.proto`:242), `AccountService.Delete` (`account_service.proto`:130), `ProjectService.Delete`,
`ServiceAccountService.Delete`, `GroupService.Delete`, `RoleService.Delete`,
`AccessBindingService.Revoke`, `GroupService.RemoveMember` — **все** `"2"`. Следствие: вызывающий,
дошедший до отказа по содержимому, уже на уровне `2`, и ни один названный шагом глагол уровня не
поднимает. Посылка задачи «`owns accounts` отправляет на глагол уровня `2`, не говоря о втором
факторе» была верна до `kaname#720`, когда `UserService.Delete` стоял на `"1"` (опора, редакция 4,
Р12); сегодня **опровергнута** этой командой: на `"1"` отказа по содержимому не видит никто.

Человек на уровне `1` получает от обоих глаголов указание повысить уровень — `401`, код `16`,
`authentication level is insufficient: step up with a second factor, or present a credential of
another kind` (`internal/errors/step_up.go`:29; форма — `docs/content/api/rest-surface.mdx`, раздел
`#step-up`). Способы повышения своей сессии он читает в `GET /iam/v1/auth/second-factor`, поле
`stepUpMethods`; пусто — `[]` (`docs/content/api/auth-lane.mdx`, раздел «Второй фактор»).

### 0.3. Кто вызывает и что ему видно

`UserService.Delete` — отношение `identity_remover` = `subject or super_admin from account`
(`user_service.proto`:237–241): сам человек либо надзор облака. Оба читают выдачи человека целиком
глаголом `AccessBindingService.ListSubjectPrivileges`
(`GET /iam/v1/accessBindings:listSubjectPrivileges?subjectType=user&subjectId=<id>`,
`access_binding_service.proto`:255–260): допуск — общий предикат `subjectReadAuthority`
(`internal/apps/kaname/api/access_binding/subject_read_authority.go`:136), полоса своего —
`subjectReadSelf` (:181), полоса надзора облака — `subjectReadClusterAdmin` (:194); построчно
сужается **только** полоса распорядителя аккаунта (`narrowsPage`, :105), поэтому субъекту и надзору
страница отдаётся без сужения (`list_subject_privileges.go`:213). Строка ответа несёт `bindingId`,
`scopeType`, `scopeId` (`SubjectPrivilege`, `access_binding_service.proto`:812, поля 12–13) — ровно то,
что называет отказ Р1. Держатель полосы своего сегодня —
`tests/newman/cases/iam-subject-privileges-read.py`:194 («ПОЛОСА СВОЕГО»). Называть в отказе
выдачу, её область и группу человека вызывающему **не** открывает ничего, чего он не читает сам.

`AccessBindingService.List` с `filter=subject=` для этого довода **не** годится (редакция 2, B3):
его страница сужается построчно по `v_get` на `iam_access_binding:<id>` (`access_binding_service.proto`:119–125),
а что субъект держит `v_get` на выдаче, выданной администратором чужого аккаунта, не измерено.

У `AccountService.Delete` вызывающий держит `v_delete` на аккаунте — его проекты, сервисные аккаунты,
группы и роли он перечисляет теми же правами.

Своего глагола снять чужую выдачу у человека **нет**: `AccessBindingService.Revoke` — `v_delete` на
выдаче (`access_binding_service.proto`:411–421), то есть у администратора области выдачи.
`GroupService.RemoveMember` — `v_update` на группе. Шаг поэтому называет, **кто** его делает.

### 0.4. Где тексты утверждаются сегодня (потребители правки)

```sh
git grep -l -e 'owns accounts and cannot be deleted' -e 'has active access bindings and cannot be deleted' \
  -e 'is a member of one or more groups and cannot be deleted' -e 'contains projects and cannot be deleted' \
  -e 'contains service accounts and cannot be deleted' -e 'contains groups and cannot be deleted' \
  -e 'contains custom roles and cannot be deleted' -- ':!docs/specs/reviews' | sort -u | wc -l
# → 26 файлов @ede94db30 (кроме записей ревью)
# в рабочей копии PRO-Robotech/kacho, origin/main = a95248464:
git grep -l -e "contains projects and cannot" a95248464 -- 'PRO-Robotech/kacho@a95248464:tests' 'PRO-Robotech/kacho@a95248464:ui-future'
# → tests/newman/kacholib/gen_shared.py (пример в шапке функции, :860)
```

Второй предикат, по предмету (разбор того же вывода по путям): из 26 — прод-код 6 (`user_repo.go`,
`account_repo.go`, `pgmaperr.go`, `maperr.go`, `group_repo.go`, `service_account_repo.go`), документация 5
(`docs/content/api/user.mdx`, `account.mdx`, `docs/engineering/components/04-service-account.md`, две
приёмки), пробы 15 (9 Go-проб, 3 описания newman `tests/newman/cases/*.py` и 3 собранные коллекции). Тексты `GroupService.Delete` и `ServiceAccountService.Delete`
(`group_repo.go`:416, `service_account_repo.go`:320, :323) и Group/ServiceAccount-половина общей
ветви `pgmaperr.go`:612–618 — **не предмет** («Что НЕ входит»).

Потребители отказа `RemoveFromAccount` — по признаку и хвосту, не по префиксу:

```sh
git grep -n 'revoke them before removing the membership\|MEMBERSHIP_CARRIES_RIGHTS' -- \
  ':!docs/specs/reviews' ':!tests/newman/collections'
# → membership_refusal.go:45, :131 · remove_from_account_names_grants_test.go:190 ·
#   internal/errors/errors.go:142 (комментарий) · tests/newman/cases/iam-user.py:2632, :2636, :2668
```

Они **не** потребители правки: форма этого отказа не меняется (DoD п. 10 держит это).

## Обзор

Человек, который снимает себя, и владелец, который снимает аккаунт, получают отказ «ещё что-то
держит» — и сегодня отказ не говорит, что именно и кто это снимет. Человек с выдачей в чужом
аккаунте не узнаёт ни выдачи, ни аккаунта и не знает, что снять её может только чужой
администратор. Документ утверждает: каждый отказ снятия по содержимому у двух глаголов —
`UserService.Delete` и `AccountService.Delete` — называет
**первый** держащий ресурс, **число** держащих этого вида и **следующий шаг** с тем, кто его
делает; один отказ несёт одну форму и один признак, каким бы рубежом он ни пришёл.

## Что НЕ входит

- указание повысить уровень (`401`/`16`) — его текст один на три поверхности, включая край
  `PRO-Robotech/kacho`, и принадлежит приёмке `assurance-level-is-declared-by-our-session.md`
  (APPROVED, `b39219bc…`); здесь он только наблюдается (DRS-01, DRS-02), см. Д1 и вопрос В1;
- порядок снятия, коды, пороги уровня, состав транзакции — опора (KN664-*); здесь не
  переутверждаются;
- отказы `GroupService.Delete` и `ServiceAccountService.Delete` «has active access bindings» —
  тот же класс у других глаголов; вызывающий их — администратор аккаунта, перечисляющий выдачи
  своими правами; вынесено вопросом В2;
- отказ снятия непустого проекта — `non-empty-project-is-not-deleted.md` (APPROVED), не меняется;
- отказ `UserService.RemoveFromAccount` «still has active access bindings in Account … and cannot be
  removed from it» — **не меняется** ни текстом, ни признаком, ни `metadata` (редакция 2, B1): он уже
  называет держащие выдачи (до пяти), их полное число и шаг (`kacho#1686`, §0.1), а замена его
  признака `MEMBERSHIP_CARRIES_RIGHTS` на `REFERENCE_IN_USE` и `blocking_*` на `resource_*` была бы
  ломающим изменением для клиента, ветвящегося по `reason`. Две формы — «перечень до пяти» у
  исключения и «первый + счёт» у снятия — сосуществуют намеренно: у исключения шаг один на все
  выдачи (отозвать их тем, кто исключает), у снятия шаг зависит от вида держащего;
- глагол «снять свою выдачу самому» — новой возможности нет, шаг называет того, у кого право есть.

## Решения (наблюдаемое)

**Р1. Форма текста.** Каждый отказ по содержимому — прежний текст **дословно**, затем `: `, затем
шаг и счёт. Прежний текст сохраняется как префикс, поэтому потребитель, сверяющий начало строки,
не ломается; сверка целой строки — ломается, и это объявлено (DoD п. 6). Тексты — контракт
(`api-conventions.md` §«Error-format», `api-error-tone`), меняются этим тикетом:

| глагол · что держит | текст отказа |
|---|---|
| `UserService.Delete` · владение аккаунтами | `User <U> owns accounts and cannot be deleted: delete Account <A> first (accounts owned: <N>)` |
| `UserService.Delete` · действующие выдачи | `User <U> has active access bindings and cannot be deleted: AccessBinding <B> on <type> <id> is revoked by an administrator of that <type> (active bindings: <N>)` |
| `UserService.Delete` · членство в группах | `User <U> is a member of one or more groups and cannot be deleted: Group <G> removes the member by its administrator (groups: <N>)` |
| `AccountService.Delete` · проекты | `Account <A> contains projects and cannot be deleted: delete Project <P> first (projects: <N>)` |
| `AccountService.Delete` · сервисные аккаунты | `Account <A> contains service accounts and cannot be deleted: delete ServiceAccount <S> first (service accounts: <N>)` |
| `AccountService.Delete` · группы | `Account <A> contains groups and cannot be deleted: delete Group <G> first (groups: <N>)` |
| `AccountService.Delete` · свои роли | `Account <A> contains custom roles and cannot be deleted: delete Role <R> first (custom roles: <N>)` |

`<type> <id>` — область выдачи **в написании текста**: `<type>` — вид области без префикса
(`account`, `project`, `cluster`), `<id>` — её `id`. Это не имя поля: на проводе у `AccessBinding`
и `SubjectPrivilege` та же область — `scopeType` в точечной форме (`iam.account`, `iam.project`,
`iam.cluster`) и `scopeId` (`access_binding.proto`, поля 5, 6; `access_binding_service.proto`,
`SubjectPrivilege` поля 12, 13); текст `account F` соответствует `scopeType = iam.account`,
`scopeId = F`. Машинно область не передаётся — `metadata` Р3 называет выдачу, а не область. **Первый** — наименьший `id` среди держащих этого вида;
`<N>` — их число в момент чтения, `<N> ≥ 1`. Порядок видов — прежний (владение → выдачи → группы;
проекты → сервисные аккаунты → группы → роли): отказ называет один вид — первый держащий.

**Р2. Один отказ — одна форма на любом рубеже.** Отказ, пришедший с рубежа гонки (ключ или
триггер схемы на фиксации), несёт ту же форму Р1: держащий ресурс и счёт читаются после отказа. Если
к моменту этого чтения держащих этого вида уже нет (гонка разрешилась), текст —
`<прежний текст>: nothing holds it now, retry the deletion`, без счёта и без ресурса.

**Р3. Признак и метаданные.** Все отказы Р1 и Р2 (только глаголы `UserService.Delete` и
`AccountService.Delete`) — `FAILED_PRECONDITION` (код `9`, HTTP `400`, как
сегодня) с `ErrorInfo`: `reason` = `REFERENCE_IN_USE`, `domain` — объявленный домен службы
(`refusaldomain.For(ServiceIAM)`), `metadata` = `{resource_type, resource_id, remaining}` —
вид и `id` первого держащего (`account` · `access_binding` · `group` · `project` ·
`service_account` · `role`) и `<N>` десятичной строкой. На тексте Р2 «nothing holds it now»
`metadata` **пуст** — отсутствие держащего представлено отсутствием ключей, а не пустой строкой.
Клиент решает по `reason` и `metadata`, а не по тексту.

**Р4. Отказ — синхронно у операции как сегодня.** Где отказ сегодня приходит исходом операции
(`done=true`, `error`), он там и остаётся; где синхронно — синхронно. Меняются только `message` и
`details`.

## Сценарии

Общее «Дано» (Г0): `U` зарегистрирован самостоятельно — личный аккаунт `A` с проектом по
умолчанию `P` (опора, §0.4); `U` вошёл паролем. Аккаунт `F` — чужой, его владелец `O`; в `F` на `U`
выдана роль на уровне аккаунта — выдача `B` (`scopeType = iam.account`, `scopeId = F`; членства `U`
в `F` нет — так ставит выдачу фикстура KN664-36, `tests/newman/cases/iam-user.py`:1680–1700).

### DRS-01: человек на уровне `1` — указание повысить уровень · E

**Given** Г0; у `U` заведён код по времени; сессия `U` уровня `1`
**When** `U` вызывает `DELETE /iam/v1/users/{U}`, затем `DELETE /iam/v1/accounts/{A}`
**Then** оба — `401`, тело `{"code": 16, "message": "authentication level is insufficient: step up
with a second factor, or present a credential of another kind", "details": []}`,
`WWW-Authenticate` с `error="insufficient_user_authentication"` и `acr_values="2"`
**And** строка `U` и аккаунт `A` на месте

### DRS-02: тот же человек на уровне `2` — отказ называет аккаунт · E

**ID:** DRS-02 (близнец DRS-01; отличающий факт один — уровень сессии `2` после
`POST /iam/v1/auth/step-up` кодом)

**Given** как DRS-01, сессия повышена до `2`
**When** `U` вызывает `DELETE /iam/v1/users/{U}` и опрашивает операцию до `done=true`
**Then** `error.code` = 9, `error.message` = `User U owns accounts and cannot be deleted: delete
Account A first (accounts owned: 1)`
**And** `error.details` содержит `ErrorInfo` с `reason` = `REFERENCE_IN_USE`, `metadata` =
`{"resource_type": "account", "resource_id": "A", "remaining": "1"}`

### DRS-03: человек без второго фактора видит, что повыситься ему нечем · E

**ID:** DRS-03 (близнец DRS-01; отличающий факт один — кода по времени нет)

**Given** Г0; у `U` нет ни кода по времени, ни ключа доступа; сессия уровня `1`
**When** `U` вызывает `DELETE /iam/v1/users/{U}`, затем `GET /iam/v1/auth/second-factor`
**Then** первое — тот же ответ, что в DRS-01, побайтово
**And** второе — `200`, `stepUpMethods` = `[]`, `totp.enrolled` = `false`

### DRS-04: два своих аккаунта — назван наименьший, счёт два · I

**Given** как DRS-02, и `U` владеет вторым аккаунтом `A2`, `id` `A2` больше `id` `A` (integration-посев
явными `id`: `id` выдаются из случайного источника, порядок в newman не построить)
**When** `U` вызывает `DELETE /iam/v1/users/{U}`
**Then** `error.message` = `User U owns accounts and cannot be deleted: delete Account A first
(accounts owned: 2)`; `metadata.remaining` = `"2"`

### DRS-05: свои аккаунты сняты — отказ называет выдачу в чужом аккаунте · E

**Given** как DRS-02; проект `P` и аккаунт `A` сняты (опора, KN664-10)
**When** `U` вызывает `DELETE /iam/v1/users/{U}`
**Then** `error.code` = 9, `error.message` = `User U has active access bindings and cannot be
deleted: AccessBinding B on account F is revoked by an administrator of that account (active
bindings: 1)`
**And** `ErrorInfo.reason` = `REFERENCE_IN_USE`, `metadata` = `{"resource_type": "access_binding",
"resource_id": "B", "remaining": "1"}` — признак есть и на рубеже охраны (§0.1: сегодня его нет)
**And** `GET /iam/v1/accessBindings:listSubjectPrivileges?subjectType=user&subjectId=U` от `U` —
`200`, `privileges` содержит строку с `bindingId` = `B`, `scopeType` = `"iam.account"`, `scopeId` = `F`:
названное в отказе вызывающий читает сам (полоса своего, без сужения — §0.3)

### DRS-06: выдачу отозвал администратор чужого аккаунта — снятие проходит · E

**ID:** DRS-06 (близнец DRS-05; отличающий факт один — `B` отозвана)

**Given** как DRS-05, и `O` вызвал `POST /iam/v1/accessBindings/{B}:revoke`, операция `done=true`
без ошибки
**When** `U` вызывает `DELETE /iam/v1/users/{U}`
**Then** операция завершилась без ошибки; `GET /iam/v1/users/{U}` от администратора облака —
`404`, «User U not found»

### DRS-07: две выдачи в двух областях — названа наименьшая · I

**Given** как DRS-05, и в аккаунте `F` на `U` выдана вторая роль на проекте `Q` аккаунта `F` —
выдача `B2`, `id` `B2` меньше `id` `B`
**When** `U` снимает себя
**Then** `error.message` = `User U has active access bindings and cannot be deleted: AccessBinding
B2 on project Q is revoked by an administrator of that project (active bindings: 2)`

### DRS-08: членство в группе — названа группа · E

**Given** состояние DRS-06 до его «Когда» (`B` отозвана, `U` не снят), и `O` добавил `U` в группу
`G` аккаунта `F`
(`POST /iam/v1/groups/{G}:addMember`)
**When** `U` снимает себя
**Then** `error.message` = `User U is a member of one or more groups and cannot be deleted: Group G
removes the member by its administrator (groups: 1)`
**And** `ErrorInfo.reason` = `REFERENCE_IN_USE`, `metadata.resource_type` = `"group"`,
`metadata.resource_id` = `"G"`
**And** близнец: после `POST /iam/v1/groups/{G}:removeMember` от `O` снятие `U` проходит

### DRS-09: облако снимает человека — та же форма · E

**ID:** DRS-09 (близнец DRS-05; отличающий факт один — вызывающий — администратор облака на
уровне `2`)

**Given** как DRS-05
**When** администратор облака вызывает `DELETE /iam/v1/users/{U}`
**Then** `error.message` и `ErrorInfo` побайтово те же, что в DRS-05: текст от вызывающего не
зависит

### DRS-10: аккаунт с проектом по умолчанию — назван проект · E

**Given** как DRS-02
**When** `U` вызывает `DELETE /iam/v1/accounts/{A}`
**Then** `error.code` = 9, `error.message` = `Account A contains projects and cannot be deleted:
delete Project P first (projects: 1)`
**And** `ErrorInfo.reason` = `REFERENCE_IN_USE`, `metadata` = `{"resource_type": "project",
"resource_id": "P", "remaining": "1"}`
**And** близнец — опора KN664-10: проект снят, снятие аккаунта проходит

### DRS-11: прочие виды держащих — по одному отказу на вид · I

**Given** как DRS-02, проект `P` снят, и в `A` есть ровно один держащий одного вида из таблицы
**When** `U` вызывает `AccountService.Delete(A)`
**Then** исход по строке:

| в `A` есть | `error.message` | `metadata.resource_type` |
|---|---|---|
| сервисный аккаунт `S` | `Account A contains service accounts and cannot be deleted: delete ServiceAccount S first (service accounts: 1)` | `service_account` |
| группа `G` | `Account A contains groups and cannot be deleted: delete Group G first (groups: 1)` | `group` |
| своя роль `R` | `Account A contains custom roles and cannot be deleted: delete Role R first (custom roles: 1)` | `role` |

**And** при проекте и сервисном аккаунте вместе назван проект (порядок видов Р1)

### DRS-12: снят в редакции 2

Сценарий исключения человека из аккаунта снят вместе с глаголом `UserService.RemoveFromAccount`
с предмета (B1; «Что НЕ входит»). Его «Дано» на Г0 к тому же не строился (B2): исключение
не-участника — успех без действия (`remove_from_account.go`:145–151). Существующий контракт
исключения держат `IAM-USR-EXCL-NEG-LIVE-GRANT` и `remove_from_account_names_grants_test.go`
(DoD п. 10). `ID` DRS-12 повторно не выдаётся.

### DRS-13: держащий появился после снимка охраны — та же форма · I

**ID:** DRS-13 (рубеж гонки, Р2)

**Given** состояние DRS-06 до его «Когда» (`B` отозвана, `U` не снят); снятие `U` задержано после снимка охраны и до
фиксации (однократная задержка на операторе снятия строки `users`), и в это окно `O` выдаёт `U`
новую роль в `F` — выдача `B3`, зафиксирована
**When** задержка отпущена
**Then** снятие отвергнуто рубежом схемы (триггер), `error.message` = `User U has active access
bindings and cannot be deleted: AccessBinding B3 on account F is revoked by an administrator of that
account (active bindings: 1)`, `ErrorInfo.reason` = `REFERENCE_IN_USE`, `metadata.resource_id` =
`"B3"` — побайтово та же форма, что у рубежа охраны

### DRS-14: держащий исчез до чтения остатка — «повторите» · U

**ID:** DRS-14 (близнец DRS-13; отличающий факт один — чтение остатка после отказа не нашло
держащих)

**Given** use-case снятия получает от порта отказ «действующие выдачи» рубежа гонки, а чтение
остатка возвращает ноль
**When** отказ формируется
**Then** `message` = `User U has active access bindings and cannot be deleted: nothing holds it now,
retry the deletion`; `ErrorInfo.reason` = `REFERENCE_IN_USE`; `metadata` пуст

## Сценарий → производитель

| ID | что производит «Тогда» | координата в дереве (`ede94db30`) | чем измерено |
|---|---|---|---|
| DRS-01, DRS-03 (первое «Тогда») | указание повысить уровень | `internal/errors/step_up.go`:29 (`TextStepUpRequired`); пол — опция `required_acr_min` (`user_service.proto`:242, `account_service.proto`:130), REST — `stepUpErrorHandler` (`internal/restfront/mux.go`:38) | `git grep -n TextStepUpRequired -- internal/errors/step_up.go`; §0.2 |
| DRS-03 (второе «Тогда») | `stepUpMethods: []` | набор — `SecondFactorStatusUseCase.stepUpMethods` (`internal/apps/kaname/api/humansession/sf_status.go`:131, в ответ — :94); поле ответа — `internal/handler/loginlanehttp/handler.go`:961 | `git grep -n 'StepUpMethods' -- 'internal/**/*.go' ':!*_test.go'` |
| DRS-02, DRS-04 | текст владения, счёт, признак | охрана — `userWriter.Delete` (`user_repo.go`:793–842, `ownsAccounts`); новый текст и чтение первого аккаунта и счёта — **заказ полосе `kaname#725`**; признак — `referenceRefusal` (`reference_refusal.go`:50), `metadata` — **заказ** | §0.1 |
| DRS-05, DRS-07, DRS-09 | текст выдачи, область, признак на охране | `userWriter.Delete`, ветвь `hasBindings` (`user_repo.go`:836) — полоса `ErrFailedPrecondition`, признака нет; перевод в `ErrReferenceInUse`, чтение первой выдачи (`access_bindings` и `access_binding_subjects`, `revoked_at IS NULL`, наименьший `id`), область — колонки `resource_type`, `resource_id` — **заказ** | §0.1; колонки — `awk '/CREATE TABLE kaname.access_bindings/,/\);/' internal/migrations/0001_initial.sql` |
| DRS-05 (последнее «Тогда») | выдача чужого аккаунта видна субъекту | `AccessBindingService.ListSubjectPrivileges` (`access_binding_service.proto`:255); полоса своего — `subject_read_authority.go`:181, без сужения — `list_subject_privileges.go`:213 (`narrowsPage`, `subject_read_authority.go`:105) | `git grep -n 'narrowsPage' -- internal/apps/kaname/api/access_binding ':!*_test.go'`; полоса своего держится `iam-subject-privileges-read.py`:194 на выдачах своего аккаунта; выдачу **чужого** аккаунта на этой полосе кейс DRS-05 утверждает впервые |
| DRS-06 | снятие после отзыва | опора KN664-46 — тот же производитель (`revoked_at IS NULL` в охране) | `git grep -n 'revoked_at IS NULL' -- internal/repo/kaname/pg/user_repo.go` |
| DRS-08 | текст группы | `user_repo.go`:839 (`hasGroupMems`) — **заказ** нового текста и чтения первой группы (`group_members`, `member_type = 'user'`) | §0.1 |
| DRS-10, DRS-11 | тексты аккаунта, признак | `accountWriter.Delete` (`account_repo.go`:367–413) — полоса `ErrFailedPrecondition`; перевод в `ErrReferenceInUse`, чтение первого держащего вида — **заказ** | §0.1 |
| DRS-13 | форма на рубеже гонки | триггер `principal_not_referenced_as_subject` (миграция 0050) → `pgmaperr.go`:618; задержка — фикстура `installOneShotHold` (`internal/apps/kaname/api/internal_iam/force_logout_concurrent_teardown_integration_test.go`); сборка текста после отказа — **заказ** | `git grep -n 'func installOneShotHold' -- internal/apps/kaname/api/internal_iam` |
| DRS-14 | текст «повторите», пустой `metadata` | **нет в дереве** — заказ полосе `kaname#725` (Р2) | — |

Посев «Дано»: регистрация, выдача в чужом аккаунте и группа — глаголами API в newman (как
`tests/newman/cases/iam-user.py`:1680–1700 сегодня ставит KN664-36); второй аккаунт с порядком `id`,
вторая выдача, сервисный аккаунт, роль — integration-посевом в `internal/repo/kaname/pg` (`id` выдаются `ids.NewID`, порядок
задаётся явными `id` посева, а не временем). Повышение кодом — существующими шагами
`tests/newman/cases/kaname-second-factor.py`.

## DoD

1. Integration-пробы DRS-04, DRS-07, DRS-11, DRS-13 (testcontainers) — **красные** на `ede94db30`
   до правки (текст без шага, у охраны нет признака), зелёные после, каждая 3 из 3.
2. Unit-проба DRS-14 — красная до правки, зелёная после.
3. Newman-кейсы DRS-01, DRS-02, DRS-03, DRS-05, DRS-06, DRS-08, DRS-09, DRS-10 — в
   `tests/newman/cases/iam-user.py` и `iam-account.py`, текст утверждается **целиком** (не
   «содержит»), признак и `metadata` — парой с кодом (`api-case-asserts-pair`); новая коллекция,
   если заводится, — со строкой ведомости производителя.
4. Файлы §0.4 приведены к новым текстам там, где утверждают тексты предмета. Два предиката, оба
   с выводом в `DoD-proof`:
   - (а) у производителей предмета прежнего текста без хвоста нет —
     `git grep -n -E '(User %s (owns accounts|has active access bindings|is a member of one or more groups)|Account %s contains (projects|service accounts|groups|custom roles)) and cannot be deleted"' -- internal/repo/kaname/pg/user_repo.go internal/repo/kaname/pg/account_repo.go internal/repo/kaname/pg/pgmaperr.go | wc -l`
     → **0** (на `ede94db30` — **13**: 12 строк кода — `user_repo.go`:834, 837, 840,
     `account_repo.go`:404, 406, 408, 410, `pgmaperr.go`:496, 505, 510, 515, 520 — и комментарий
     `pgmaperr.go`:51); User-половина общей ветви `pgmaperr.go`:612–618 (`kindHint = "User.Delete"`)
     даёт форму Р1/Р2 — держит DRS-13;
   - (б) не-предмет побайтово прежний: `git grep -c -F` каждого из
     `"Group %s has active access bindings and cannot be deleted"` (`group_repo.go`),
     `"ServiceAccount %s has active access bindings and cannot be deleted"`,
     `"ServiceAccount %s is a member of one or more groups and cannot be deleted"`
     (`service_account_repo.go`) → по **1**, как на `ede94db30`; Group/ServiceAccount-половина ветви
     `pgmaperr.go`:612–618 — строки `pgmaperr_test.go`:203–204 проходят **без правки** ожидаемого
     текста.
5. Опора правится **тем же изменением** новой редакцией: тексты KN664-11, KN664-31, KN664-36 —
   ссылкой на этот документ; её одобрение на новую редакцию не переносится — нужен круг ревью
   опоры по дельте.
6. Потребители в `PRO-Robotech/kacho` (`tests/newman/kacholib/gen_shared.py`:860 — пример в шапке, не
   проба; ещё раз `git grep` по `origin/main` перед посадкой) — заказ задачей в `PRO-Robotech/kacho`,
   посадка после закрепления новой головы службы.
7. `docs/content/api/user.mdx` и `account.mdx` — тексты Р1, признак и `metadata` Р3, случай Р2.
8. `go test -race` пакетов `internal/repo/kaname/pg`, `internal/apps/kaname/api/user`,
   `internal/apps/kaname/api/account`, `internal/apps/kaname/shared` — зелёный.
9. Комментарий `DoD-proof @<sha>` в `kaname#725`.
10. Отказ `UserService.RemoveFromAccount` не тронут: `IAM-USR-EXCL-NEG-LIVE-GRANT`
    (`tests/newman/cases/iam-user.py`:2630–2636) и
    `internal/apps/kaname/api/user/remove_from_account_names_grants_test.go` зелёные **без правки**;
    `git diff ede94db30 -- internal/apps/kaname/shared/membership_refusal.go` пуст.

## Дельта к редакции 1

| замечание круга 1 | где закрыто в редакции 2 |
|---|---|
| B1 (PRODUCER) — `RemoveFromAccount` уже называет остаток | глагол снят с предмета: шапка «Тип изменения», §0.1 (строка «не предмет», перепись по признаку и месту дописывания), §0.4 (потребители по признаку), «Что НЕ входит», Р1 (строка снята), Р3, DRS-12 снят, DoD п. 3 и новый п. 10 |
| B2 (CONSTRUCTIBILITY) — «Дано» DRS-12 не строится | снято вместе с DRS-12 (B1) |
| B3 (PRODUCER) — видимость выдачи через `List` | DRS-05 утверждает её через `:listSubjectPrivileges` (полоса своего, без сужения); §0.3 и строка производителя переписаны |
| B4 (DoD) — п. 4 невыполним | п. 4 — два предиката (а) счёт 13 → 0 у производителей предмета, (б) не-предмет побайтово прежний |
| minor: DRS-04 «· E» | DRS-04 — «· I», порядок `id` integration-посевом |
| minor: производитель `stepUpMethods` | строка DRS-03 — `sf_status.go`:131, `loginlanehttp/handler.go`:961 |
| minor: написание области в Р1 | Р1 объявляет написание текста и его соответствие `scopeType`/`scopeId`; Г0 — проводные поля |
| minor: ссылки «§2», «как DRS-06» | ссылки — на «Что НЕ входит»; DRS-08, DRS-13 — «состояние DRS-06 до его «Когда»» |
| minor: близнецы DRS-04, DRS-07, DRS-11 | не меняется: текст утверждается целиком, снятие держащего проходит в DRS-06 и DRS-10 |

## Допущения

- **Д1.** Указание повысить уровень не меняется: человек без второго фактора узнаёт, что
  повыситься нечем, из `stepUpMethods: []` (DRS-03), а не из текста указания. Текст указания один
  на три поверхности, и его правка — ребро с краем `PRO-Robotech/kacho` (вопрос В1).
- **Д2.** Называется **первый** держащий, а не все: перечень неограничен по длине, и полный
  перечень вызывающий читает глаголом перечня своими правами (§0.3); счёт говорит, сколько шагов.
  Отказ `RemoveFromAccount` с перечнем до пяти остаётся своей формой («Что НЕ входит»).
- **Д3.** Чтение остатка после отказа (Р2) — отдельное чтение с правами того же вызывающего; оно
  не меняет исхода (отказ уже решён) и не держит замков.

## Вопросы диспетчеру

Оба вопроса решены диспетчером вариантом (а) после круга 1; документ стоит на (а) — Д1 и
«Что НЕ входит». Текст вопросов сохранён как основание решения.

- **В1.** Указание повысить уровень человеку без заведённого способа. Варианты: (а) оставить, путь
  — `stepUpMethods: []` (Д1; цена — человек делает лишний запрос); (б) второй текст указания «enrol
  a second factor first» при пустом наборе (цена — правка трёх поверхностей и края, новая приёмка
  ребра, плюс различимость «у человека нет фактора» в ответе на любой глагол уровня `2`). Рекомендация
  — (а).
- **В2.** Тот же класс у `GroupService.Delete` и `ServiceAccountService.Delete`. Варианты: (а)
  отдельной задачей того же вида (цена — ещё одна приёмка размера S); (б) расширить этот документ
  (цена — ещё два глагола и посевы в этом круге). Рекомендация — (а).
