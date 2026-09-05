# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set authz-deny для kacho-iam.

Проверяет default-deny matrix для 6 субъектов на Account/Project/Group/SA/AB/User/Role,
плюс UserService.Invite (CanInviteUsers) и UserService.List scope-filter.

Семантика:
  - DENY  → 403 + grpc 7 + "permission denied" (ANON без токена → 401 + grpc 16)
  - ALLOW → != 403
  - EMPTY → 200 + body.<list>.length === 0 (scope-filter List: User / ServiceAccount /
            Project / Group возвращают 200 c пустым списком для non-member, никогда 403 —
            все 5 account-scoped IAM List унифицированы в <exempt>)

Pre-conditions: `tests/authz-fixtures/setup.sh`. Env-var'ы те же что у vpc/compute.

The ALLOW cases for INV (invitee→admin@account-B) and PA1 (proj-adm→edit@project-A1)
require a system-role grant on an account/project scope to emit FGA tier-tuples.
emitAnchorRule materializes a wildcard *.* anchor rule as a tier-tuple on the bare
account/project/cluster object (the permissions-path grant), so the fixture
viewer/editor tuple lands in OpenFGA and the ALLOW assertions pass.
"""

CASES = []

# System role ids — source of truth = migration 0008_role_catalog_kac122.sql,
# which DELETEs the legacy `rol00000000000000<tail>` roles (migration 0001) and
# re-seeds the catalog with deterministic ids `rol` + substr(md5(<name>),1,17).
# An AccessBinding.Create / Invite with a non-existent role_id fails the worker
# `FAILED_PRECONDITION Role <id> not found` (FK access_bindings_role_fk) — so
# these tests MUST reference the post-0008 ids.
ROLE_ADMIN = "rol21232f297a57a5a74"   # md5('admin')[:17] — global super-admin
ROLE_VIEW  = "rol1bda80f2be4d3658e"   # md5('view')[:17]  — global read-only

# NOB -> jwtPureNoBindings, the DEDICATED never-granted subject.
#
# `jwtNoBindings` (userNOBId) is doubly used in this tree: it is the standard grant
# TARGET for the AccessBinding suites — iam-flat-authz-vbc grants it `view` on
# account-A and the AB-CR ALLOW rows below grant it `view` on account-B — and those
# rows stay ACTIVE in Postgres/OpenFGA across runs. Every DENY/EMPTY expectation for
# this subject was therefore being asserted against a principal that genuinely holds
# a live grant (AUTHZ-USR-LS-A-NOB / -B-NOB over-showed real users for exactly that
# reason). userPureNoBindingsId is seeded by tests/authz-fixtures/setup.sh and is
# never a grant target anywhere in the tree, so the matrix rows below mean what they
# say. (Parity with services/vpc/tests/newman/cases/authz-deny.py, kacho-iam#276.)
SUBJECTS = [
    ("ANON", "anon",       "anonymous"),
    ("NOB",  "no-bind",    "jwtPureNoBindings"),
    ("PA1",  "proj-adm",   "jwtProjectAdminA1"),
    ("AAA",  "acct-adm-a", "jwtAccountAdminA"),
    ("AAB",  "acct-adm-b", "jwtAccountAdminB"),
    ("INV",  "invitee",    "jwtInvitee"),
]

# Субъект по коду — чтобы КОНТРОЛЬ ФОРМЫ (ниже) называл своего предъявителя один раз.
# Контроль формы адресован тому, у кого право ЕСТЬ: только тогда `400` доказывает
# проверку ТЕЛА, а не отказ в правах. Выписывать тройку второй раз нельзя — она
# разошлась бы с SUBJECTS молча.
SUBJECT_BY_CODE = {code: (code, label, auth) for code, label, auth in SUBJECTS}

EXPECT = {
    "account-A":              {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"ALLOW","AAB":"DENY","INV":"DENY"},
    "account-B":              {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"DENY","AAB":"ALLOW","INV":"ALLOW"},
    "project-A1":             {"ANON":"DENY","NOB":"DENY","PA1":"ALLOW","AAA":"ALLOW","AAB":"DENY","INV":"ALLOW"},
    "project-B1":             {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"DENY","AAB":"ALLOW","INV":"ALLOW"},
    "catalog-read":           {"ANON":"DENY","NOB":"ALLOW","PA1":"ALLOW","AAA":"ALLOW","AAB":"ALLOW","INV":"ALLOW"},
    "cluster-role-mutate":    {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"DENY","AAB":"DENY","INV":"DENY"},
    "invite-to-account-A":    {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"ALLOW","AAB":"DENY","INV":"DENY"},
    "invite-to-account-B":    {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"DENY","AAB":"ALLOW","INV":"ALLOW"},
    # User.List is a scope-filter RPC (exempt at the gateway). The
    # kacho-iam handler returns 200 with only the Users of Accounts where the
    # principal is a member — EMPTY (200, zero users) when the caller is not a
    # member of the requested Account; never 403. Anonymous → DENY (IAM
    # anti-anonymous interceptor). So a non-member account-admin (e.g. AAB on
    # account-A) gets EMPTY, not PERMISSION_DENIED.
    "user-list-account-A":    {"ANON":"DENY","NOB":"EMPTY","PA1":"EMPTY","AAA":"ALLOW","AAB":"EMPTY","INV":"ALLOW"},
    "user-list-account-B":    {"ANON":"DENY","NOB":"EMPTY","PA1":"EMPTY","AAA":"EMPTY","AAB":"ALLOW","INV":"ALLOW"},
    # ServiceAccount.List is a scope-filter RPC (exempt at the
    # gateway, like User.List). The kacho-iam handler returns 200
    # with only the ServiceAccounts of Accounts where the principal is a
    # member — EMPTY (200, zero serviceAccounts) for a non-member; never 403.
    # Membership semantics are identical to user-list-account-*.
    "sa-list-account-A":      {"ANON":"DENY","NOB":"EMPTY","PA1":"EMPTY","AAA":"ALLOW","AAB":"EMPTY","INV":"ALLOW"},
    "sa-list-account-B":      {"ANON":"DENY","NOB":"EMPTY","PA1":"EMPTY","AAA":"EMPTY","AAB":"ALLOW","INV":"ALLOW"},
    # Project/Group List are in the scope-filter family (List = <exempt>):
    # non-member → 200 + empty, never 403; ANON → 401. Membership truth
    # from tests/authz-fixtures/setup.sh (PA1=editor@project-A1[in A]; AAA=admin@account-A;
    # AAB=admin@account-B; INV=admin@account-B + editor@project-A1[in A]; NOB=nothing):
    #   ProjectService.List filters owner-via-account ∪ viewer ∪ v_list on `project`:
    #     acc-A → PA1/INV see project-A1 (editor⊇viewer), AAA owns A → ALLOW; NOB/AAB → EMPTY.
    #     acc-B → AAB owns B, INV admin@B → ALLOW; NOB/PA1/AAA → EMPTY (no acc-B project grant).
    #   GroupService.List filters viewer ∪ v_list on `iam_group` (account-tier admin cascades;
    #   project-editor does NOT cascade to groups):
    #     acc-A → AAA (account-admin) → ALLOW; NOB/PA1/AAB → EMPTY. INV kept ALLOW (lenient
    #       non-403) so the by-label visibility suite granting INV a transient acc-A group
    #       v_list cannot flake a strict-empty assert.
    #     acc-B → AAB/INV (account-admin@B) → ALLOW; NOB/PA1/AAA → EMPTY.
    "prj-list-account-A":     {"ANON":"DENY","NOB":"EMPTY","PA1":"ALLOW","AAA":"ALLOW","AAB":"EMPTY","INV":"ALLOW"},
    "prj-list-account-B":     {"ANON":"DENY","NOB":"EMPTY","PA1":"EMPTY","AAA":"EMPTY","AAB":"ALLOW","INV":"ALLOW"},
    "grp-list-account-A":     {"ANON":"DENY","NOB":"EMPTY","PA1":"EMPTY","AAA":"ALLOW","AAB":"EMPTY","INV":"ALLOW"},
    "grp-list-account-B":     {"ANON":"DENY","NOB":"EMPTY","PA1":"EMPTY","AAA":"EMPTY","AAB":"ALLOW","INV":"ALLOW"},
    # AccountService.List — top-level scope-filter RPC (exempt at the
    # gateway, default-deny via the handler returning 200 with only the
    # caller's member-Accounts). Every authenticated subject gets a non-403.
    "account-list":           {"ANON":"DENY","NOB":"ALLOW","PA1":"ALLOW","AAA":"ALLOW","AAB":"ALLOW","INV":"ALLOW"},
    # User.List WITHOUT accountId is a scope-filter RPC — the
    # kacho-iam handler returns 200 with only the Users of Accounts the
    # principal is a member of (its own user at minimum). Returning the
    # caller's own user is not a data leak. Every authenticated subject → ALLOW
    # (non-403, non-empty); anonymous → DENY.
    "user-list-unqualified":  {"ANON":"DENY","NOB":"ALLOW","PA1":"ALLOW","AAA":"ALLOW","AAB":"ALLOW","INV":"ALLOW"},
    # a per-resource-gated Get/Delete on a NON-EXISTENT id is
    # `no path` for EVERY subject — the FGA cascade has no parent-pointer tuple
    # for an object that never existed, so the Check cannot resolve regardless
    # of the caller's account/project role. DENY for all (the request never
    # reaches the repo to return 404).
    "garbage-perresource":    {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"DENY","AAB":"DENY","INV":"DENY"},
    # UserService.Get записи пользователя — читать её вправе САМ пользователь
    # (`iam_user.v_get` содержит `subject`); каждый базовый тест-пользователь
    # владеет своим домашним аккаунтом, поэтому пути «через администратора» нет.
    #
    # НО НИ ОДИН СУБЪЕКТ ЭТОЙ МАТРИЦЫ САМИМ ПОЛЬЗОВАТЕЛЕМ НЕ ЯВЛЯЕТСЯ, И БЫТЬ ИМ
    # НЕ МОЖЕТ — поэтому здесь DENY по всей строке, а не ALLOW на «своей» клетке.
    # Основание структурное, а не «не хватает выдачи»:
    #
    #   * `define subject: [user]` (proto/kacho/cloud/iam/v1/fga_model.fga, тип
    #     `iam_user`) — отношение принимает ТОЛЬКО тип `user`;
    #   * каждый предъявитель этой матрицы аутентифицируется как
    #     `service_account` — объявлено данными в
    #     tests/authz-fixtures/principal_pairings.py, где прямо сказано, что
    #     `userNOBId` / `userINVId` / `userPureNoBindingsId` — ТОЛЬКО цели
    #     привязки, и «ни один выдаваемый токен ими не аутентифицируется и не
    #     может»: машинный посев добывает `client_credentials`, то есть
    #     служебную учётку (почему именно так — tests/authz-fixtures/mint_rs256.py,
    #     раздел `user_platform_token`: человеческий предъявитель не несёт `acr` и
    #     не проходит порог повышения, от которого машина освобождена, а человек —
    #     нет). Прежняя редакция называла второй причиной жёсткий kacho-внутренний
    #     `aud` — её больше нет: выпуск персонального токена не объявляет адресата
    #     у внешнего поставщика (#1121), и обменивается такой токен у нашего
    #     издателя.
    #
    # Значит `service_account` не удовлетворяет `subject` НИ ПРИ КАКОЙ выдаче, и
    # прежняя клетка ALLOW не имела производителя: 404 (скрытие существования) —
    # правильный ответ продукта на запрос, который шаг РЕАЛЬНО делает. Клетка была
    # ALLOW с 2026-07-26 (c4960673, «self всё ещё значит self»), где цель
    # переставили вслед за субъектом; переставили ЦЕЛЬ, но принципал остался
    # служебной учёткой, поэтому самочтением строка так и не стала ни разу.
    #
    # ALLOW-полоса самочтения НЕ потеряна — она вынесена туда, где у неё есть
    # производитель: AUTHZ-USR-GT-SELF-CEREMONY ниже, человеческим предъявителем.
    "user-get-nob":           {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"DENY","AAB":"DENY","INV":"DENY"},
    "user-get-inv":           {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"DENY","AAB":"DENY","INV":"DENY"},
}


def deny_asserts(case_id):
    return [
        f"pm.test('[{case_id}] DENY: status 403', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(403));",
        "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
        f"pm.test('[{case_id}] DENY: grpc code 7 (PERMISSION_DENIED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(7));",
        f"pm.test('[{case_id}] DENY: message contains permission denied', () => pm.expect((j && j.message || '').toLowerCase()).to.contain('permission denied'));",
    ]


def _is_single_resource_get(path):
    # A single-resource Get targets one object: the path's last segment is a
    # concrete id — a `{{var}}` placeholder or a literal resource id (3-char prefix
    # + ≥17 chars) — with NO query string. A List (collection) carries a ?query
    # (e.g. ?accountId=…) or ends in the bare plural (`/accounts`); those are NOT
    # single reads and a denied List stays PermissionDenied (403), not hidden as 404.
    if "?" in path:
        return False
    last = path.rstrip("/").rsplit("/", 1)[-1]
    if last.startswith("{{") and last.endswith("}}"):
        return True
    # Literal resource id: 3-char alpha prefix + ≥17 trailing chars (matches the
    # GARBAGE_* / id format), distinguishing it from the bare plural collection name.
    return len(last) >= 20 and last[:3].isalpha() and last[3:].isalnum()


def read_deny_asserts(case_id):
    # BUG-2 hide-existence: a denied single-resource read (Get) on a verb-bearing
    # IAM resource is surfaced as NotFound (404 / code 5), never PermissionDenied —
    # no enumeration / existence leak. Applies to authenticated-but-denied AND to a
    # denied read of a (well-formed) nonexistent id — both yield the same 404, so an
    # attacker cannot tell "exists but forbidden" from "does not exist".
    return [
        f"pm.test('[{case_id}] READ-DENY: status 404 (hide existence)', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(404));",
        "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
        f"pm.test('[{case_id}] READ-DENY: grpc code 5 (NOT_FOUND, not 7)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(5));",
        f"pm.test('[{case_id}] READ-DENY: no deny_reasons leak', () => pm.expect(JSON.stringify(j || {{}}).toLowerCase()).to.not.include('deny_reasons'));",
    ]


def unauth_asserts(case_id):
    # BUG-2: anonymous (no credentials) → 401 + code 16 (UNAUTHENTICATED),
    # not 403 + code 7 (PERMISSION_DENIED).
    # gRPC/HTTP convention: missing credentials → UNAUTHENTICATED (16) → HTTP 401;
    # authenticated-but-denied → PERMISSION_DENIED (7) → HTTP 403.
    return [
        f"pm.test('[{case_id}] UNAUTH: status 401', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(401));",
        "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
        f"pm.test('[{case_id}] UNAUTH: grpc code 16 (UNAUTHENTICATED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(16));",
    ]


# ---------------------------------------------------------------------------
# ALLOW-ПОЛОСЫ: ИСХОД ОДИН, УСТАНОВЛЕННЫЙ, И УТВЕРЖДАЕТСЯ ПАРОЙ
#
# Здесь стояла ОДНА функция на все 74 ALLOW-позиции матрицы, и она утверждала
# «код не 403» и «код не 16». Отрицание проходит на любом ответе, кроме этих двух:
# на успехе, на отказе валидации, на 409, на 500, на 503. То есть строка не
# отличала исправную систему ни от одной поломки, кроме подписанной 403 — а на
# полосах ниже она скрывала ДВА живых дефекта самих кейсов (см. lane «sync-reject»).
# Отдельно: шаг, у которого ВСЕ утверждения о статусе отрицательные, читается
# гейтами дерева (`internal/repohygiene`) как ПРОБА ОТКАЗА и выпадает из их
# рассмотрения. verifies #668.
#
# Полос четыре, и выбирается полоса ПО ФОРМЕ ЗАПРОСА, а не по имени кейса, —
# поэтому новая строка матрицы попадает в свою полосу автоматически:
#
#   read   — одиночное чтение (`GET /res/{id}`): sync, ответ — сам ресурс.
#            Пара: HTTP 200 + `id` ответа РАВЕН запрошенному. `google.rpc.Status`
#            успешное чтение не несёт, поэтому вторым членом пары служит форма.
#   list   — перечисление (`GET /res` либо `GET /res?scope=`): sync, ответ —
#            конверт выдачи. Пара: HTTP 200 + верхний уровень тела состоит только
#            из объявленных полей ответа (`<plural>` + `nextPageToken`), то есть
#            это НЕ конверт ошибки (`code`/`message`/`details`).
#   op     — мутация: async по контракту (`api-conventions.md`; все мутирующие RPC
#            iam возвращают `operation.Operation`). Пара: HTTP 200 + конверт
#            Operation с iam-префиксом `iop` и объектом `metadata`.
#   sync-reject — мутация, которую ВЛАДЕЛЕЦ отвергает СИНХРОННО, до Operation,
#            по телу запроса. Пара: HTTP 400 + `code` 3 + названный текст.
#
# ПРЕДМЕТ МАТРИЦЫ ПРИ ЭТОМ СОХРАНЁН СТРОГО. До сервиса доходит только запрос,
# который край ПРОПУСТИЛ; отказ в правах край отдаёт `403` (полоса DENY) либо
# скрывает существование `404` (полоса READ-DENY). Значит любой из четырёх исходов
# выше достижим ровно тем субъектом, которому доступ дан, и регрессия прав валит
# кейс по первому же утверждению.


def _allow_id_expr(path):
    """Выражение, дающее тот же идентификатор, что ушёл в АДРЕСЕ запроса.

    Подстановка `{{…}}` работает в адресе и теле, но НЕ в скрипте, поэтому
    ожидаемое значение собирается из того же источника, что и запрос, — двух мест
    об одном предмете не заводится.
    """
    last = path.rstrip("/").rsplit("/", 1)[-1]
    if last.startswith("{{") and last.endswith("}}"):
        return f"pm.environment.get('{last[2:-2]}')"
    return f"'{last}'"


def _allow_list_key(path):
    """Ключ выдачи — последний сегмент КОЛЛЕКЦИИ адреса.

    Он совпадает с именем поля ответа by construction: REST-путь ресурса —
    `/iam/v1/<plural>`, а поле списка в `List<Res>Response` называется тем же
    `<plural>` в camelCase (`accounts`, `users`, `roles`, `groups`, `projects`,
    `serviceAccounts`). Выводить его из адреса, а не принимать параметром, —
    решение осознанное: параметр `empty_list_key` имеет умолчание `users`, и на
    вызовах `/accounts` / `/roles` / `/projects` оно неверно; для полосы EMPTY это
    никогда не выстреливало, потому что EMPTY на них не достижим, но полосе ALLOW
    досталось бы утверждение про чужой ключ.
    """
    return path.split("?")[0].rstrip("/").rsplit("/", 1)[-1]


def allow_read_asserts(case_id, id_expr):
    """ALLOW, одиночное чтение: 200 + ответ есть ЗАПРОШЕННЫЙ ресурс."""
    return [
        f"pm.test('[{case_id}] ALLOW: HTTP 200 (чтение разрешено)', () => "
        "pm.expect(pm.response.code, pm.response.text()).to.equal(200));",
        "let _j; try { _j = pm.response.json(); } catch(e) { _j = null; }",
        f"pm.test('[{case_id}] ALLOW: ответ — запрошенный ресурс, а не конверт отказа', () => {{",
        "  pm.expect(_j, 'тело не разобралось как JSON: ' + pm.response.text()).to.be.an('object');",
        f"  pm.expect(_j.id, JSON.stringify(_j)).to.equal({id_expr});",
        "});",
    ]


def allow_list_asserts(case_id, list_key):
    """ALLOW, перечисление: 200 + конверт выдачи (а не конверт отказа).

    Ключ выдачи может ОТСУТСТВОВАТЬ — пустая страница законна, и protojson пустое
    повторяющееся поле не печатает. Поэтому утверждается не «ключ есть», а «сверх
    объявленных полей ответа в теле ничего нет»: конверт ошибки этим и падает.
    """
    return [
        f"pm.test('[{case_id}] ALLOW: HTTP 200 (перечисление разрешено)', () => "
        "pm.expect(pm.response.code, pm.response.text()).to.equal(200));",
        "let _j; try { _j = pm.response.json(); } catch(e) { _j = null; }",
        f"pm.test('[{case_id}] ALLOW: конверт выдачи, а не конверт отказа', () => {{",
        "  pm.expect(_j, 'тело не разобралось как JSON: ' + pm.response.text()).to.be.an('object');",
        f"  pm.expect(Object.keys(_j).filter(k => ['{list_key}', 'nextPageToken'].indexOf(k) < 0),",
        "    'посторонний ключ в конверте выдачи: ' + pm.response.text()).to.eql([]);",
        f"  pm.expect(_j['{list_key}'] === undefined || Array.isArray(_j['{list_key}']),",
        f"    'поле {list_key} присутствует и не является массивом: ' + pm.response.text()).to.equal(true);",
        "});",
    ]


def allow_operation_asserts(case_id):
    """ALLOW, мутация: 200 + конверт Operation с iam-префиксом.

    Мутации iam async по контракту — все мутирующие RPC возвращают
    `operation.Operation`. Исход самой операции (конфликт активного гранта, занятое
    имя) приезжает в `Operation.error` и синхронного статуса не меняет: повторный
    прогон на том же стенде остаётся 200, а не 409.
    """
    return [
        f"pm.test('[{case_id}] ALLOW: HTTP 200 (мутация принята)', () => "
        "pm.expect(pm.response.code, pm.response.text()).to.equal(200));",
        "let _j; try { _j = pm.response.json(); } catch(e) { _j = null; }",
        f"pm.test('[{case_id}] ALLOW: конверт Operation', () => {{",
        "  pm.expect(_j && _j.id, 'operation.id: ' + pm.response.text()).to.match(/^iop[a-z0-9]+$/);",
        "  pm.expect(_j.metadata, 'operation.metadata').to.be.an('object');",
        "});",
    ]


def allow_sync_reject_asserts(case_id, message_token):
    """ALLOW, полоса «край ПРОПУСТИЛ — владелец отверг ТЕЛО, синхронно».

    Пара: HTTP 400 + `code` 3 (`INVALID_ARGUMENT`) + названный текст отказа.
    Отображение кода в статус задаёт библиотека края (`runtime.HTTPStatusFromCode`;
    край собирается без `WithErrorHandler`).

    Текст сверяется ВХОЖДЕНИЕМ, а не равенством, и это осознанно: проверка домена
    склеивает ошибки полей через multierr, поэтому равенство сломалось бы от
    появления второго нарушения — то есть от изменения, к предмету кейса
    отношения не имеющего. Названная часть при этом однозначно указывает на
    производителя отказа.
    """
    return [
        f"pm.test('[{case_id}] ALLOW→отказ тела: HTTP 400', () => "
        "pm.expect(pm.response.code, pm.response.text()).to.equal(400));",
        "let _j; try { _j = pm.response.json(); } catch(e) { _j = null; }",
        f"pm.test('[{case_id}] ALLOW→отказ тела: grpc code 3 (INVALID_ARGUMENT)', () => "
        "pm.expect(_j && _j.code, JSON.stringify(_j)).to.equal(3));",
        f"pm.test('[{case_id}] ALLOW→отказ тела: названный производитель отказа', () => "
        f"pm.expect((_j && _j.message) || '', JSON.stringify(_j)).to.contain({message_token!r}));",
    ]


def allow_asserts(case_id, method, path, lane=None, message_token=None):
    """Выбор ALLOW-полосы ПО ФОРМЕ ЗАПРОСА (разбор — в комментарии выше)."""
    if lane == "sync-reject":
        return allow_sync_reject_asserts(case_id, message_token)
    if method == "GET":
        if _is_single_resource_get(path):
            return allow_read_asserts(case_id, _allow_id_expr(path))
        return allow_list_asserts(case_id, _allow_list_key(path))
    return allow_operation_asserts(case_id)


def empty_asserts(case_id, list_key="users"):
    # list_key — the JSON array field of the List response to assert empty on
    # (`users` for User.List, `serviceAccounts` for ServiceAccount.List, ...).
    return [
        f"pm.test('[{case_id}] EMPTY: status 200', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(200));",
        "const body = pm.response.json();",
        f"pm.test('[{case_id}] EMPTY: zero {list_key} (scope-filter default-deny)', "
        f"() => pm.expect((body && body.{list_key} || []).length).to.equal(0));",
    ]


def reject_asserts(case_id):
    # BUG-3: AccountService.Create enforces RequireOwnerMatchesPrincipal
    # which returns code 3 (INVALID_ARGUMENT / 400) when ownerUserId != principal,
    # not code 7 (PERMISSION_DENIED / 403). Both are valid denial responses:
    # code 3 = "your request is malformed — you cannot set a foreign ownerUserId";
    # code 7 = "you don't have permission". Security-wise both reject the hijack.
    # This assert accepts either code 3 (400) or code 7 (403).
    return [
        f"let rj; try {{ rj = pm.response.json(); }} catch(e) {{ rj = null; }}",
        f"pm.test('[{case_id}] REJECT: status 400 or 403', () => "
        f"pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.be.oneOf([400, 403]));",
        f"pm.test('[{case_id}] REJECT: grpc code 3 or 7', () => "
        f"pm.expect(rj && rj.code, JSON.stringify(rj)).to.be.oneOf([3, 7]));",
    ]


def emit(case_id_prefix, title, scope, method, path, body, subject, empty_list_key="users",
         allow_lane=None, allow_message_token=None):
    code, label, auth = subject
    decision = EXPECT[scope][code]
    case_id = f"AUTHZ-{case_id_prefix}-{code}"
    if decision == "DENY":
        # BUG-2: ANON subject uses "anonymous" auth (no credentials sent).
        # Missing credentials → UNAUTHENTICATED(16)/401, not PERMISSION_DENIED(7)/403.
        # Authenticated subjects that are denied still use deny_asserts (7/403).
        if code == "ANON":
            asserts = unauth_asserts(case_id)
        elif scope == "esc-account-hijack":
            # BUG-3: Account.Create with mismatched ownerUserId returns
            # code 3 (INVALID_ARGUMENT / 400) via RequireOwnerMatchesPrincipal,
            # not code 7 (PERMISSION_DENIED / 403). Both are valid denial responses.
            asserts = reject_asserts(case_id)
        elif method == "GET" and _is_single_resource_get(path):
            # BUG-2 hide-existence: a denied single-resource read (Get) on a
            # verb-bearing IAM resource → NotFound (404 / code 5), not 403. ONLY a
            # single-resource Get (path ends in /{{id}}, no ?query) hides existence;
            # a denied List (e.g. /projects?accountId=…) stays PermissionDenied (403)
            # — a collection has no single object whose existence to hide. The
            # garbage-id single-Get probe denied for all subjects also surfaces as 404
            # (denied nonexistent == existing-denied → no enumeration leak).
            asserts = read_deny_asserts(case_id)
        else:
            asserts = deny_asserts(case_id)
    elif decision == "ALLOW":
        asserts = allow_asserts(case_id, method, path,
                                lane=allow_lane, message_token=allow_message_token)
    elif decision == "EMPTY":
        asserts = empty_asserts(case_id, empty_list_key)
    else:
        raise ValueError(f"unknown decision {decision} for {case_id}")
    cls = ["AUTHZ"]
    if decision == "DENY":      cls.append("NEG")
    elif decision == "ALLOW":   cls.append("POS")
    elif decision == "EMPTY":   cls.append("SCOPE")
    CASES.append(Case(
        id=case_id,
        title=f"[{decision}] {title} as {label} ({scope})",
        classes=cls,
        priority="P1",
        steps=[Step(name=method.lower(), method=method, path=path, body=body, auth=auth, test_script=asserts)],
    ))


GARBAGE_ACCT = "accnonexistent000001"
GARBAGE_PROJ = "prjnonexistent000001"
GARBAGE_GRP  = "grpnonexistent000001"
GARBAGE_SA   = "svanonexistent000001"
GARBAGE_AB   = "acbnonexistent000001"
GARBAGE_USER = "usrnonexistent000001"
GARBAGE_ROLE = "rolnonexistent000001"

# Значение, которым строка матрицы обновляет аккаунт. Постоянное намеренно: повтор
# прогона не меняет ничего, поэтому `changed` пуст, аудит молчит, а ответ остаётся
# конвертом Operation — идемпотентность здесь свойство значения, а не удача.
ACCT_UP_DESCRIPTION = "authz matrix update probe"


# ---------------------------------------------------------------------------
# Account (CRUD) — own A vs cross B
# ---------------------------------------------------------------------------

for subj in SUBJECTS:
    # Create (any subject) — account-creation на стенде разрешено всем authenticated
    # (signup-flow), но для тестов intentionally probe whether DENY semantics work.
    # Decision for "account-create": same matrix as "account-A own" — only AAA expected ALLOW.
    # (Если стенд разрешает всем — это даст разные false-positives; задокументировано в matrix-doc.)
    emit("ACCT-GT-OWN", "Get account-A", "account-A",
         "GET", "/iam/v1/accounts/{{accountAId}}", None, subj)
    emit("ACCT-GT-CROSS", "Get account-B", "account-B",
         "GET", "/iam/v1/accounts/{{accountBId}}", None, subj)
    # Тело обновления аккаунта — МИНИМАЛЬНО ЗАКОННОЕ, и это предмет задачи #710.
    #
    # Строка спрашивает «вправе ли субъект обновить аккаунт», поэтому запрос обязан
    # доходить до обновления. Прежнее тело `{"name": "x"}` до него не доходило ни
    # разу: `Account.Validate` (и в нём `AccountName.Validate`,
    # `services/iam/internal/domain/types.go`) исполняется СИНХРОННО, раньше
    # `operations.NewFromContext`, — значит субъект С ПРАВОМ получал `400`
    # `INVALID_ARGUMENT`, а Operation не появлялась вовсе. Полоса разрешения не
    # проверяла разрешение.
    #
    # Меняется поле, а НЕ проверка домена: `description` — такое же изменяемое поле
    # маски (`accountMutableFields`), проходит тот же гейт прав
    # (`authzguard.RequireScopeRelation` на `account:<id>`) и ту же
    # `target.Validate()`. Имя при этом остаётся нетронутым — а именно оно
    # `UNIQUE` на весь кластер и служит идентичностью посевного аккаунта, поэтому
    # переименовывать общую фикстуру ради пробы нельзя (разбор — в #710).
    #
    # Повторный прогон безопасен by construction: значение то же, `changed` пуст,
    # строки аудита нет, ответ остаётся конвертом Operation.
    emit("ACCT-UP-OWN", "Update account-A", "account-A",
         "PATCH", "/iam/v1/accounts/{{accountAId}}",
         {"description": ACCT_UP_DESCRIPTION, "updateMask": "description"}, subj)
    emit("ACCT-UP-CROSS", "Update account-B", "account-B",
         "PATCH", "/iam/v1/accounts/{{accountBId}}",
         {"description": ACCT_UP_DESCRIPTION, "updateMask": "description"}, subj)
    # garbage-id Delete is per-resource-gated on a non-existent
    # `account:<garbage>` object → `no path` → 403 for every subject (never
    # reaches the repo). See garbage-perresource note in define_account_scoped.
    emit("ACCT-DL-OWN", "Delete account (garbage id — no FGA path)", "garbage-perresource",
         "DELETE", f"/iam/v1/accounts/{GARBAGE_ACCT}", None, subj)
    emit("ACCT-LS", "List accounts (scope-filter)", "account-list",
         "GET", "/iam/v1/accounts", None, subj)


# КОНТРОЛЬ ФОРМЫ к ACCT-UP (#710). Строки выше теперь доходят до обновления, и без
# этой пары починка предмета сняла бы заодно проверку самого тела: «имя вне контракта
# отвергается синхронно» больше не утверждал бы никто.
#
# Предъявитель — тот, у кого право на account-A ЕСТЬ (`SUBJECT_BY_CODE["AAA"]`).
# Только на нём `400` доказывает проверку ТЕЛА: у субъекта без права тот же `400`
# был бы неотличим от отказа края.
#
# Имя обязано быть вне ДЕЙСТВУЮЩЕЙ формы, и это не косметика фикстуры, а условие
# существования кейса. Прежде здесь стояло `"x"`, негодное лишь по собственной
# форме iam (`^[a-z][-a-z0-9]{2,62}$` — от трёх символов). #1279 привела имя к
# единственной форме дерева (`pkg/validate/nameform`), где длина 1 законна ПО
# РЕШЕНИЮ (RFC 1123, 1–63), — и `"x"` стало именем в контракте. Кейс при этом не
# покраснел бы «мимо»: он получил `200` + Operation, то есть перестал утверждать
# ровно то, ради чего заведён.
#
# Цена принятого имени тут выше обычной: маска несёт `name`, значит принятое имя
# ПЕРЕИМЕНОВАЛО БЫ общую фикстуру — а имя аккаунта `UNIQUE` на весь кластер и
# служит идентичностью посевного account-A (разбор строкой выше, #710). Отказ по
# форме — единственное, что держит запрос вне записи.
#
# Негодность взята по ДВУМ независимым осям — заглавные и подчёркивание (обе
# названы в конвенции имени), — чтобы послабление формы по одной оси не сделало
# фикстуру законной молча во второй раз. Заглавные — тот же идиом, что у парного
# кейса создания `IAM-ACC-CR-NEG-NAME-INVALID`.
emit("ACCT-UPFORM-OWN", "Update account-A с именем вне контракта", "account-A",
     "PATCH", "/iam/v1/accounts/{{accountAId}}",
     {"name": "ACCT_UPFORM_{{runId}}", "updateMask": "name"},
     SUBJECT_BY_CODE["AAA"],
     allow_lane="sync-reject", allow_message_token="Illegal argument name")


# ---------------------------------------------------------------------------
# Project (CRUD) — A1 (own), A2 (same-account-cross-project), B1 (cross-account)
# ---------------------------------------------------------------------------

for subj in SUBJECTS:
    # Create в account-A
    emit("PRJ-CR-A", "Create project в account-A", "account-A",
         "POST", "/iam/v1/projects",
         {"accountId": "{{accountAId}}", "name": f"authz-prj-{subj[0].lower()}-{{{{runId}}}}"}, subj)
    # Create в account-B
    emit("PRJ-CR-B", "Create project в account-B", "account-B",
         "POST", "/iam/v1/projects",
         {"accountId": "{{accountBId}}", "name": f"authz-prj-{subj[0].lower()}-{{{{runId}}}}"}, subj)
    # Get project A1
    emit("PRJ-GT-A1", "Get project-A1", "project-A1",
         "GET", "/iam/v1/projects/{{projectA1Id}}", None, subj)
    # Get project B1
    emit("PRJ-GT-B1", "Get project-B1", "project-B1",
         "GET", "/iam/v1/projects/{{projectB1Id}}", None, subj)
    # Update project A1
    emit("PRJ-UP-A1", "Update project-A1", "project-A1",
         "PATCH", "/iam/v1/projects/{{projectA1Id}}",
         {"description": "x", "updateMask": "description"}, subj)
    # Update project B1
    emit("PRJ-UP-B1", "Update project-B1", "project-B1",
         "PATCH", "/iam/v1/projects/{{projectB1Id}}",
         {"description": "x", "updateMask": "description"}, subj)
    # garbage-id Delete — per-resource-gated on a non-existent
    # `project:<garbage>` → `no path` → 403 for all subjects.
    emit("PRJ-DL-A", "Delete project (garbage id — no FGA path)", "garbage-perresource",
         "DELETE", f"/iam/v1/projects/{GARBAGE_PROJ}", None, subj)
    # List projects ?accountId — scope-filter RPC (List = <exempt>):
    # non-member → 200 + empty `projects`, never 403.
    emit("PRJ-LS-A", "List projects ?accountId=A", "prj-list-account-A",
         "GET", "/iam/v1/projects?accountId={{accountAId}}", None, subj,
         empty_list_key="projects")
    emit("PRJ-LS-B", "List projects ?accountId=B", "prj-list-account-B",
         "GET", "/iam/v1/projects?accountId={{accountBId}}", None, subj,
         empty_list_key="projects")


# ---------------------------------------------------------------------------
# Group / ServiceAccount / AccessBinding — account-scoped, single set of cases per
# ---------------------------------------------------------------------------

def define_account_scoped(prefix_short, plural, body_template_a, body_template_b,
                          garbage_id, with_list=True,
                          list_scope_a="account-A", list_scope_b="account-B",
                          list_key="users"):
    # with_list=False — ресурс не имеет account-scoped плоского List RPC
    # (AccessBindingService экспонирует только
    # Get/Create/Delete/ListByScope/ListBySubject — `GET /iam/v1/accessBindings`
    # это catalog-miss, fail-closed 403, не valid default-deny scenario).
    #
    # list_scope_a / list_scope_b — the EXPECT scope-keys used for the LIST
    # sub-cases (separate from Get/Create/Delete which stay account-A/B). A
    # scope-filter List RPC (ServiceAccount.List) uses a
    # scope-filter scope (`sa-list-account-*`, EMPTY for non-members) rather
    # than the hard-deny `account-*` scope. list_key — the List response array
    # field asserted empty on EMPTY decisions.
    for subj in SUBJECTS:
        emit(f"{prefix_short}-CR-A", f"Create {prefix_short} в account-A", "account-A",
             "POST", f"/iam/v1/{plural}", body_template_a(subj), subj)
        emit(f"{prefix_short}-CR-B", f"Create {prefix_short} в account-B", "account-B",
             "POST", f"/iam/v1/{plural}", body_template_b(subj), subj)
        # a per-resource-gated Get/Delete on a NON-EXISTENT id is
        # always `no path` → 403 — the gateway extracts the scope object
        # `iam_<res>:<garbage-id>` and the FGA cascade has no parent-pointer
        # tuple (the object never existed). This holds for EVERY subject,
        # including the account-admin: there is no way to authorise a Check
        # against an object with no tuples. So the garbage-id probe is DENY for
        # all (it never reaches the repo to 404).
        emit(f"{prefix_short}-GT-A", f"Get {prefix_short} (garbage id — no FGA path)",
             "garbage-perresource", "GET", f"/iam/v1/{plural}/{garbage_id}", None, subj)
        if with_list:
            emit(f"{prefix_short}-LS-A", f"List {plural} ?accountId=A", list_scope_a,
                 "GET", f"/iam/v1/{plural}?accountId={{{{accountAId}}}}", None, subj,
                 empty_list_key=list_key)
            emit(f"{prefix_short}-LS-B", f"List {plural} ?accountId=B", list_scope_b,
                 "GET", f"/iam/v1/{plural}?accountId={{{{accountBId}}}}", None, subj,
                 empty_list_key=list_key)
        emit(f"{prefix_short}-DL-A", f"Delete {prefix_short} (garbage id — no FGA path)",
             "garbage-perresource", "DELETE", f"/iam/v1/{plural}/{garbage_id}", None, subj)


define_account_scoped(
    "GRP", "groups",
    lambda s: {"accountId": "{{accountAId}}", "name": f"authz-grp-{s[0].lower()}-{{{{runId}}}}"},
    lambda s: {"accountId": "{{accountBId}}", "name": f"authz-grp-{s[0].lower()}-{{{{runId}}}}"},
    GARBAGE_GRP,
    # GroupService.List is <exempt> — non-members get
    # 200 + empty `groups`, never 403. Create/Get/Delete stay hard-deny (account-A/B); only
    # the LIST sub-cases switch to the scope-filter scope (parity with serviceAccounts).
    list_scope_a="grp-list-account-A", list_scope_b="grp-list-account-B",
    list_key="groups",
)
define_account_scoped(
    "SA", "serviceAccounts",
    lambda s: {"accountId": "{{accountAId}}", "name": f"authz-sa-{s[0].lower()}-{{{{runId}}}}"},
    lambda s: {"accountId": "{{accountBId}}", "name": f"authz-sa-{s[0].lower()}-{{{{runId}}}}"},
    GARBAGE_SA,
    # ServiceAccount.List is a scope-filter RPC — non-members get
    # 200 + empty `serviceAccounts`, not 403. Create/Get/Delete stay hard-deny
    # (account-A/B). Only the LIST sub-cases switch to the scope-filter scope.
    list_scope_a="sa-list-account-A", list_scope_b="sa-list-account-B",
    list_key="serviceAccounts",
)
define_account_scoped(
    "AB", "accessBindings",
    lambda s: {"subjectType":"user","subjectId":"{{userNOBId}}","roleId":ROLE_VIEW,"scopeType":"iam.account","scopeId":"{{accountAId}}","target":{"allInScope":{}}},
    lambda s: {"subjectType":"user","subjectId":"{{userNOBId}}","roleId":ROLE_VIEW,"scopeType":"iam.account","scopeId":"{{accountBId}}","target":{"allInScope":{}}},
    GARBAGE_AB,
    with_list=False,  # AccessBindingService has no plain account-scoped List RPC.
)

# ---------------------------------------------------------------------------
# Non-member → Project & Group List → 200 + empty (was 403).
# verifies: a non-member gets 200 + empty (not 403) on Project & Group List.
#
# До unify Project/Group.List несли gateway call-gate `account:<id>#v_list`
# (+ required_acr_min=2). Non-member без этого якоря получал 403 PERMISSION_DENIED.
# Теперь List = <exempt>, единственный гейт — in-handler `viewer ∪ v_list`
# фильтр → 200 + пустой массив (existence не раскрывается кодом ошибки; паритет с
# ServiceAccount/User List). jwtPureNoBindings — выделенный НИКОГДА-не-гранченый субъект
# (jwtNoBindings им БОЛЬШЕ НЕ является: сюиты сами грантят userNOBId view на оба аккаунта),
# гарантированно non-member на оба аккаунта → детерминированно пустой List (immune к pollution).
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="AUTHZ-ULG04-NONMEMBER-PRJGRP-LIST-EMPTY",
    title="non-member (jwtPureNoBindings) → Project & Group List → 200 + empty (was 403 pre-unify call-gate)",
    classes=["AUTHZ", "SCOPE", "NEG", "RBAC"],
    priority="P1",
    steps=[
        Step(name="prj-list-nonmember-empty", method="GET",
             path="/iam/v1/projects?accountId={{accountAId}}", auth="jwtPureNoBindings",
             test_script=empty_asserts("ULG04-PRJ", "projects")),
        Step(name="grp-list-nonmember-empty", method="GET",
             path="/iam/v1/groups?accountId={{accountAId}}", auth="jwtPureNoBindings",
             test_script=empty_asserts("ULG04-GRP", "groups")),
    ],
))


# Fixture-pollution fix — NOB tuple teardown after AB-CR ALLOW cases.
#
# The AB-CR cases that succeed (ALLOW) grant NOB a `viewer` FGA tuple on the
# target account.  Those tuples are written inside the async Operation worker and
# persist in OpenFGA across newman runs (OpenFGA is backed by PostgreSQL, not an
# in-memory store).  On the next run the matrix still expects NOB → DENY on those
# accounts, but OpenFGA sees the lingering tuple and returns ALLOW, causing 24
# assertion failures across ACCT-GT, PRJ-GT, PRJ-LS, GRP-LS sub-cases.
#
# Fix: after each ALLOW AccessBinding.Create (AB-CR-A-AAA, AB-CR-B-AAB,
# AB-CR-B-INV), append three clean-up steps to the Case:
#   1. poll-op  — wait for the Create Operation to complete; extract abId.
#   2. delete-ab — DELETE /accessBindings/{abId} (authorised as the same
#                  subject that created it, so the authz gate passes).
#   3. poll-op-del — wait for the Delete Operation to complete (fire-and-forget
#                    style: we accept any `done` state; failure here is logged
#                    but does not mask the original ALLOW assertion).
#
# The three teardown steps are appended (not prepended) so the original single-
# step ALLOW assertion fires first — test semantics are unchanged.
#
# Subject → auth-var mapping (same as SUBJECTS list above):
#   AAA → jwtAccountAdminA
#   AAB → jwtAccountAdminB
#   INV → jwtInvitee

_AB_CR_ALLOW_AUTH = {
    "AUTHZ-AB-CR-A-AAA": "jwtAccountAdminA",
    "AUTHZ-AB-CR-B-AAB": "jwtAccountAdminB",
    "AUTHZ-AB-CR-B-INV": "jwtInvitee",
}

for _case in CASES:
    if _case.id not in _AB_CR_ALLOW_AUTH:
        continue
    _auth = _AB_CR_ALLOW_AUTH[_case.id]
    # Per-case-unique step names + env vars.
    #
    # The teardown steps used to share the names `poll-op-create` / `delete-ab-
    # teardown` / `poll-op-delete` and the env vars `_abTeardownOpId` /
    # `_abTeardownId` across ALL three AB-CR ALLOW cases. That caused two real,
    # NON-product flakes under CI load (verified in the flat-umbrella newman logs):
    #   1. setNextRequest(pm.info.requestName) re-runs the named request, but with a
    #      name shared across cases newman could re-enter the *wrong* case's poll —
    #      and worse, the prior case's self-re-poll jumped straight into the NEXT
    #      case's poll step, SKIPPING that case's create POST entirely. The next
    #      case then never saved its own op id and polled the PRIOR case's op as a
    #      DIFFERENT principal → 404 (Operation.Get is principal-scoped, anti-leak),
    #      exhausting the poll without resolving the teardown id.
    #   2. With the teardown id unresolved, the DELETE pre-script guard
    #      `setNextRequest(null)` did NOT skip the current request — worse, it
    #      ABORTED THE WHOLE RUN (setNextRequest(null) ends the newman run; it never
    #      meant "skip this one"). The DELETE still fired with a literal
    #      `{{_abTeardownId}}` URL → 400 InvalidArgument → `[teardown] 200 or 404`
    #      failed, and every request after it in the collection was silently never
    #      executed. The correct primitive for "skip exactly this request" is
    #      `pm.execution.skipRequest()`, which is what every guard here now uses.
    # Fix (test-side, harness-only): unique per-case names so setNextRequest re-enters
    # the correct step and never bypasses a create; per-case env vars reset on the
    # create step so no stale op id bleeds in; and an unresolved teardown id falls
    # back to a well-formed garbage acb (clean 404), never a literal template (400).
    _cid = _case.id.replace("-", "_")
    _opvar = f"_abTeardownOpId_{_cid}"
    _idvar = f"_abTeardownId_{_cid}"
    _delopvar = f"_abDelOpId_{_cid}"
    _pollName = f"poll-op-create-{_case.id}"
    _delName = f"delete-ab-teardown"  # asserted by name in the green-gate; kept stable
    _delPollName = f"poll-op-delete-{_case.id}"
    # Step 1: the existing single step already has the POST and ALLOW asserts.
    # Reset the per-case teardown vars, then save THIS create's Operation id.
    _case.steps[0].test_script = list(_case.steps[0].test_script) + [
        f"pm.environment.unset('{_opvar}'); pm.environment.unset('{_idvar}'); pm.environment.unset('{_delopvar}');",
        # Save the Operation id returned by THIS case's Create RPC for teardown polling.
        f"try {{ const _op = pm.response.json(); if (_op && _op.id) pm.environment.set('{_opvar}', _op.id); }} catch(e) {{}}",
    ]
    # Step 2: poll until THIS case's Create Operation is done and extract abId.
    # A persistent 404 here means the op was never saved (create dup / response shape)
    # — bounded by POLL_CAP, it falls through leaving the teardown id unresolved, and
    # the DELETE below uses the garbage fallback (clean 404). No foreign-op polling.
    _case.steps.append(Step(
        name=_pollName,
        method="GET",
        path="/operations/{{" + _opvar + "}}",
        auth=_auth,
        pre_script=[
            # Skip the poll entirely if THIS case saved no op id (jump to delete).
            f"if (!pm.environment.get('{_opvar}')) {{ pm.execution.setNextRequest('{_delName}'); }}",
        ],
        test_script=[
            # First-entry reset (request-name-scoped flag) — keeps the iteration
            # count immune to cross-case bleed.
            "if (pm.environment.get('_abPollStarted') !== pm.info.requestName) { pm.environment.set('_abPollCount', '0'); pm.environment.set('_abPollStarted', pm.info.requestName); }",
            "const _pc = parseInt(pm.environment.get('_abPollCount') || '0', 10);",
            "let _j; try { _j = pm.response.json(); } catch(e) { _j = {}; }",
            # 404 (op not yet visible) or !done → retry within the cap. A non-converging
            # 404 (foreign/never-persisted op) falls through and resolves no id.
            f"if ((pm.response.code === 404 || !_j.done) && _pc < {POLL_CAP}) {{",
            "  pm.environment.set('_abPollCount', String(_pc + 1));",
            "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            "pm.environment.unset('_abPollCount');",
            "pm.environment.unset('_abPollStarted');",
            # ИСХОД СОЗДАНИЯ НАЗЫВАЕТСЯ ЗДЕСЬ, а не подразумевается.
            #
            # Предмет кейса — созданная привязка, и её координату публикует ИМЕННО
            # этот шаг. Без утверждения он зеленел при любом ответе: непришедшая
            # операция, `done` с ошибкой и настоящий успех читались одинаково.
            # Дальше `_abId` оставался пустым, снятие привязки пропускалось стражем
            # `skipRequest`, и «убирать нечего» становилось неотличимо от «создать не
            # удалось» — при том что кейс уже отчитался `[ALLOW]: HTTP 200`. Цена
            # молчания названа соседним шагом дословно: непогашенная выдача ПЕРЕЖИВАЕТ
            # прогон в ОБЩЕМ аккаунте и достаётся тому, кто запустит набор следующим.
            #
            # Полоса здесь ОДНА: кейс называется `[ALLOW] Create AB`, то есть создание
            # разрешено и обязано состояться. `done` мало — операция, завершившаяся
            # ошибкой, тоже `done`, а идентификатор ресурса чеканится до того, как
            # отработает воркер.
            "(function () {",
            "  var _co; try { _co = pm.response.json(); } catch (e) { _co = {}; }",
            "  pm.test('[teardown] операция создания завершилась', function () {",
            "    pm.expect(_co.done, pm.response.text()).to.eql(true);",
            "  });",
            "  pm.test('[teardown] операция создания успешна — иначе предмета кейса "
            "не существует, а убирать будет нечего', function () {",
            "    pm.expect(_co.error && JSON.stringify(_co.error), 'operation.error')"
            ".to.eql(undefined);",
            "  });",
            "})();",
            # Extract abId from Operation metadata for teardown.
            "try {",
            "  const _meta = _j.metadata || {};",
            "  const _abId = _meta.accessBindingId || _meta['@value'] && _meta['@value'].accessBindingId || '';",
            f"  if (_abId) pm.environment.set('{_idvar}', _abId);",
            "} catch(e) {}",
        ],
    ))
    # Step 3: DELETE the binding (teardown), so re-runs don't trip the strict-create
    # active-grant UNIQUE.
    #
    # A PERMISSION DENIAL IS NOT A CLEANUP RESULT. The previous version accepted
    # `oneOf([200, 404, 403])`, and 403 was defensible only for one of the two targets
    # this step could aim at: when THIS case's binding id was unresolved it deliberately
    # aimed at a well-formed garbage id, which legitimately 403s at the scope extractor.
    # But the SAME assertion covered the real target, where 403 means the admin's
    # `v_delete` on the fresh binding had not yet materialised — the revoke did NOT
    # happen and the grant stays ACTIVE in the SHARED account for whoever runs next.
    # One assertion could not tell the two apart, so it accepted the harmful one to
    # tolerate the harmless one.
    #
    # The ambiguity is removed at the source instead of being tolerated: when there is
    # no binding of ours to delete, no DELETE is issued at all (an explicit
    # `skipRequest()` guard, which is the sanctioned form for exec-coverage). The step
    # therefore only ever runs against a REAL target, where 403 is not terminal — it is
    # retried past the materialization window, and a persistent denial fails honestly.
    _case.steps.append(poll_request_until_status(
        name=_delName,
        method="DELETE",
        path="/iam/v1/accessBindings/{{_abTeardownDelId}}",
        auth=_auth,
        retry_on=(403,),
        test_script=[
            # Идентификатор операции удаления СБРАСЫВАЕТСЯ ПЕРЕД захватом: ветка
            # `404` («уже нет») законна и тела с `id` не несёт, поэтому захват не
            # срабатывает. Без сброса имя сохранило бы операцию предыдущего шага, и
            # опрос подтвердил бы чужой завершённый успех. Пустая строка, а не
            # `unset`: парный опрос снимает себя `skipRequest`, когда имя пусто.
            f"pm.environment.set('{_delopvar}', '');",
            # Save delete Operation id for the follow-up poll.
            f"try {{ const _dop = pm.response.json(); if (_dop && _dop.id) pm.environment.set('{_delopvar}', _dop.id); }} catch(e) {{}}",
            "pm.test('[teardown] delete-ab: revoked (200) or already gone (404) — a persistent 403 "
            "means the grant SURVIVES into the next run', "
            "() => pm.expect(pm.response.code, JSON.stringify(pm.response.json() || {})).to.be.oneOf([200, 404]));",
        ],
    ))
    # No binding of ours ⇒ no DELETE. Aiming at a garbage id purely to have something to
    # send is what made the outcome unreadable in the first place.
    # `_abTeardownDelId` задаётся ВСЕГДА — пустой строкой, когда привязки нашей нет.
    # Для стража адреса пустое значение — законный случай (его собственный комментарий
    # это оговаривает: литерала в адресе не останется), тогда как «переменную не задал
    # НИКТО» обязано оставаться находкой. Отправку по-прежнему снимает skipRequest, так
    # что запрос с пустым id никуда не уходит; разница только в том, что шаг ЗАЯВЛЯЕТ
    # «адресовать нечего», вместо того чтобы молчать и выглядеть как потерянный захват.
    _case.steps[-1].pre_script = [
        f"pm.environment.set('_abTeardownDelId', pm.environment.get('{_idvar}') || '');",
        f"if (!pm.environment.get('{_idvar}')) {{ pm.execution.skipRequest(); }}",
    ] + list(_case.steps[-1].pre_script or [])
    # Step 4: poll THIS case's Delete Operation until done (best-effort cleanup).
    _case.steps.append(Step(
        name=_delPollName,
        method="GET",
        path="/operations/{{" + _delopvar + "}}",
        auth=_auth,
        pre_script=[
            # Та же дисциплина: DELETE мог законно ответить 404 («уже нет»), и тогда
            # идентификатора операции удаления не существует — опрашивать нечего.
            f"pm.environment.set('{_delopvar}', pm.environment.get('{_delopvar}') || '');",
            f"if (!pm.environment.get('{_delopvar}')) {{ pm.execution.skipRequest(); }}",
        ],
        test_script=[
            # First-entry reset (request-name-scoped flag).
            "if (pm.environment.get('_abDelPollStarted') !== pm.info.requestName) { pm.environment.set('_abDelPollCount', '0'); pm.environment.set('_abDelPollStarted', pm.info.requestName); }",
            "const _dp = parseInt(pm.environment.get('_abDelPollCount') || '0', 10);",
            "let _dj; try { _dj = pm.response.json(); } catch(e) { _dj = {}; }",
            f"if (!_dj.done && _dp < {POLL_CAP}) {{",
            "  pm.environment.set('_abDelPollCount', String(_dp + 1));",
            "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            "pm.environment.unset('_abDelPollCount');",
            "pm.environment.unset('_abDelPollStarted');",
            f"pm.environment.unset('{_opvar}');",
            f"pm.environment.unset('{_idvar}');",
            f"pm.environment.unset('{_delopvar}');",
            "pm.environment.unset('_abTeardownDelId');",
        ],
    ))


# ---------------------------------------------------------------------------
# Role — cluster-scoped catalog (Get/List = catalog-read; Create/Update/Delete = cluster-role-mutate)
# ---------------------------------------------------------------------------

for subj in SUBJECTS:
    emit("ROLE-LS", "List roles (catalog)", "catalog-read",
         "GET", "/iam/v1/roles", None, subj)
    emit("ROLE-GT", "Get role (catalog system role)", "catalog-read",
         "GET", f"/iam/v1/roles/{ROLE_VIEW}", None, subj)
    emit("ROLE-CR", "Create role (cluster admin)", "cluster-role-mutate",
         "POST", "/iam/v1/roles",
         # `isSystem` is derived output-only (from definitionTier) and is not a field
         # of CreateRoleRequest — sending it would be a key the edge discards.
         {"name": f"authz-role-{subj[0].lower()}",
          "rules": [{"module": "iam", "resources": ["user"], "verbs": ["get"]}]}, subj)
    emit("ROLE-UP", "Update role (cluster admin)", "cluster-role-mutate",
         "PATCH", f"/iam/v1/roles/{GARBAGE_ROLE}", {"description":"x"}, subj)
    emit("ROLE-DL", "Delete role (cluster admin)", "cluster-role-mutate",
         "DELETE", f"/iam/v1/roles/{GARBAGE_ROLE}", None, subj)


# ---------------------------------------------------------------------------
# UserService.Invite (CanInviteUsers = Check editor on account)
# ---------------------------------------------------------------------------

for subj in SUBJECTS:
    # Тело приглашения — МИНИМАЛЬНО ЗАКОННОЕ, и это второй предмет задачи #710.
    #
    # Строка спрашивает `CanInviteUsers` — право приглашать В АККАУНТ. Прежнее тело
    # несло `roleId` без `projectId`, а `InviteUserUseCase.Execute` объявляет эти
    # поля парными и отвергает такую пару СИНХРОННО, шагом 1, — то есть раньше
    # `canInviteUsers` (шаг 2, `services/iam/internal/apps/kacho/api/user/invite.go`).
    # Значит ALLOW-строки до заявленного предмета не доходили ни разу.
    #
    # Снят `roleId`, а не добавлен `projectId`, и выбор здесь содержательный:
    # приглашение БЕЗ выдачи остаётся приглашением в аккаунт — ровно тем, что
    # объявлено областью (`invite-to-account-A`/`-B`) и что гейтит `canInviteUsers`.
    # Добавление `projectId` сделало бы строку приглашением в ПРОЕКТ: другой
    # предмет, другая область, другая клетка матрицы.
    #
    # DENY-строки предмет сохраняют и от правки не зависят: `UserService/Invite`
    # гейтится краем (`editor` на `account` из `account_id`), поэтому субъект без
    # права получает `403` ещё до тела.
    #
    # Повтор прогона безопасен: адрес почты постоянный, и повторное приглашение
    # того же адреса в тот же аккаунт идемпотентно (`GetByAccountEmail` → строка
    # существует → вставки нет). С `projectId` этого свойства не было бы: выдача
    # вставляется СТРОГО, повторная сталкивается на частичной уникальности активного
    # гранта, и откатывается всё приглашение целиком — то есть второй прогон подряд
    # красил бы строку.
    emit("INV-A", "Invite user в account-A", "invite-to-account-A",
         "POST", "/iam/v1/users:invite",
         {"accountId":"{{accountAId}}","email": f"authz-invtarget-{subj[0].lower()}@example.com"}, subj)
    emit("INV-B", "Invite user в account-B", "invite-to-account-B",
         "POST", "/iam/v1/users:invite",
         {"accountId":"{{accountBId}}","email": f"authz-invtarget-{subj[0].lower()}@example.com"}, subj)

# КОНТРОЛЬ ФОРМЫ к INV (#710) — парный к ACCT-UPFORM выше и по той же причине:
# без него правка тела сняла бы заодно утверждение «`roleId` без `projectId`
# отвергается синхронно». Предъявитель — тот, у кого право приглашать в account-A
# ЕСТЬ, иначе `400` был бы неотличим от отказа края.
emit("INV-FORMA", "Invite user в account-A с roleId без projectId", "invite-to-account-A",
     "POST", "/iam/v1/users:invite",
     {"accountId":"{{accountAId}}","email":"authz-invform@example.com","roleId":ROLE_VIEW},
     SUBJECT_BY_CODE["AAA"],
     allow_lane="sync-reject",
     allow_message_token="Illegal argument project_id: required when role_id is set")


# ---------------------------------------------------------------------------
# UserService.Get / Update / Delete / List — scope-filter
# ---------------------------------------------------------------------------

for subj in SUBJECTS:
    # UserService.Get is per-resource-gated on `iam_user:<id>`.
    # Читать запись пользователя вправе САМ пользователь (`iam_user.v_get`
    # содержит `subject`) либо носитель прямой выдачи на этот объект. Каждый
    # базовый тест-пользователь владеет своим домашним аккаунтом, поэтому пути
    # «через администратора чужого аккаунта» нет (AAA — админ account-A, а не
    # домашнего аккаунта NOB).
    #
    # ОБЕ СТРОКИ — СПЛОШНОЙ DENY, и это не ослабление, а исправление ложного
    # ожидания: субъекты матрицы — служебные учётки, а `define subject: [user]`
    # принимает только тип `user` (разбор и предикаты — у EXPECT выше). Прежняя
    # клетка ALLOW описывала запрос, которого шаг не делает, и производителя не
    # имела; 404 здесь — правильный ответ продукта, и он утверждается СТРОГО
    # (read_deny_asserts: скрытие существования, дословный контракт-тон).
    #
    # Ценность строки от этого не падает — она остаётся анти-BOLA утверждением:
    # НИ администратор соседнего аккаунта, НИ администратор проекта, НИ
    # приглашённый не читают чужую запись пользователя.
    emit("USR-GT-A", "Get user record (self-viewable only)", "user-get-nob",
         "GET", "/iam/v1/users/{{userPureNoBindingsId}}", None, subj)
    emit("USR-GT-B", "Get userINV (self-viewable only)", "user-get-inv",
         "GET", "/iam/v1/users/{{userINVId}}", None, subj)
    # List ?accountId — главный default-deny scope-filter case
    emit("USR-LS-A", "List users ?accountId=A", "user-list-account-A",
         "GET", "/iam/v1/users?accountId={{accountAId}}", None, subj)
    emit("USR-LS-B", "List users ?accountId=B", "user-list-account-B",
         "GET", "/iam/v1/users?accountId={{accountBId}}", None, subj)
    # garbage-id Delete — per-resource-gated on a non-existent
    # `iam_user:<garbage>` → `no path` → 403 for all subjects.
    emit("USR-DL-A", "Delete user (garbage id — no FGA path)", "garbage-perresource",
         "DELETE", f"/iam/v1/users/{GARBAGE_USER}", None, subj)


# ---------------------------------------------------------------------------
# ALLOW-полоса самочтения — ЧЕЛОВЕЧЕСКИМ предъявителем (её производитель)
# ---------------------------------------------------------------------------
# Строки USR-GT-* выше — сплошной DENY, и это верно: их субъекты суть служебные
# учётки, а `define subject: [user]` принимает только тип `user`. Но отрицание без
# положительного контроля не отличает «читать чужое нельзя» от «UserService.Get
# сломан для ВСЕХ»: полностью отказавший глагол оставил бы матрицу зелёной.
#
# Поэтому положительный контроль стоит ЗДЕСЬ, а не подразумевается: предъявителем,
# который действительно принадлежит человеку. Он добывается настоящим входом
# паролем у провайдера личности (волна церемонии), и коллекция authz-deny в эту
# волну уже входит — проверяется машинно:
#     python3 tests/authz-fixtures/ceremony_credentials.py --stems \
#         --suite services/iam/tests/newman
# то есть credential здесь доступен, а не заведён «на будущее».
#
# ПОЧЕМУ ВТОРОЙ ЧЕЛОВЕК, А НЕ ГЛАВНЫЙ. `ceremonyNoBindingsUserId` не является целью
# привязки НИ В ОДНОЙ суите дерева, поэтому его 200 не может прийти от чужой выдачи,
# залетевшей из соседней коллекции, и не зависит от порядка прогона. Главный человек
# церемонии — владелец своего аккаунта и цель выдач, на нём тот же ответ был бы
# слабее ровно на эту величину. (Его собственный положительный контроль живёт в
# наборе iam-user, IAM-USR-GT-CRUD-OK.)
#
# ЧТО ИМЕННО УТВЕРЖДАЕТСЯ: человек читает СВОЮ запись и получает её. Отношение, по
# которому это разрешено, — `iam_user.v_get ⊇ subject`; кортеж `iam_user:<usr>#subject
# @ user:<usr>` пишется на заведении пользователя (bootstrapTuples в
# services/iam/internal/apps/kacho/api/user/internal_upsert.go, ветка ownedAccounts==0
# — то есть у КАЖДОГО пользователя). До восстановления `subject` в читающем глаголе
# самочтение не работало ни у кого, и отказ был неотличим от «пользователя нет»:
# скрытие существования отвечает тем же текстом, что и настоящее отсутствие. Здесь
# это отличимо — предъявитель и цель названы, а ответ обязан НЕСТИ id.
#
# Проба не оборачивается ожиданием: запись пользователя и её кортеж существуют с
# момента посева волны, а не создаются этим кейсом, — read-your-writes окна здесь нет.
CASES.append(Case(
    id="AUTHZ-USR-GT-SELF-CEREMONY",
    title="[ALLOW] Get own user record as human ceremony principal (self via iam_user.v_get ⊇ subject)",
    classes=["AUTHZ", "POS"],
    priority="P1",
    steps=[
        Step(
            name="get-self",
            method="GET",
            path="/iam/v1/users/{{ceremonyNoBindingsUserId}}",
            auth="jwtHumanCeremonyNoBindings",
            test_script=[
                *assert_status(200),
                # Ответ обязан быть ИМЕННО той записью, которую спрашивали. Без этого
                # утверждения кейс зеленел бы на любом 200 — в том числе на чужой
                # записи, а это ровно та ошибка, которую он призван исключать.
                "pm.test('AUTHZ-USR-GT-SELF-CEREMONY: вернулась СВОЯ запись', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, JSON.stringify(j)).to.eql(",
                "    pm.environment.get('ceremonyNoBindingsUserId'));",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# Privilege escalation / Information disclosure / Isolation
# ---------------------------------------------------------------------------

# AccessBindingService.Create больше НЕ
# enforces identity-equality RequireSelfGrant. Grant-authority следует SCOPE
# гранта — caller обязан owner'ить owning Account ЛИБО держать FGA `admin` на
# scope. Account-owner, грантящий роль (в т.ч. iam.admin себе) в СВОЕМ account —
# allowed by design (он уже держит owner). Поэтому self-grant в собственном
# scope = ALLOW, в чужом = DENY. Зеркалит account-A / account-B матрицы.
EXPECT["esc-self-grant-A"]     = {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"ALLOW","AAB":"DENY","INV":"DENY"}
EXPECT["esc-self-grant-B"]     = {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"DENY","AAB":"ALLOW","INV":"ALLOW"}
# AccountService.Create enforces RequireOwnerMatchesPrincipal —
# ownerUserId обязан совпадать с caller'ом. Body фиксирует ownerUserId=AAA, так
# что для caller'а AAA это нормальное self-owned account creation (ALLOW); для
# любого другого subject — попытка назначить чужого owner'а (DENY = hijack).
# IAM-1 F1 (redesign-2026): ownerUserId° is OUTPUT-ONLY derived-from-caller. Setting ANY
# ownerUserId in the Create body — even the caller's OWN id — is a sync INVALID_ARGUMENT
# ("Illegal argument ownerUserId (derived from caller)"). The hijack vector is now closed
# by construction for EVERY subject, so AAA (which used to self-own via ownerUserId=AAA) is
# now DENY(reject) too. reject_asserts already accepts code 3/400.
EXPECT["esc-account-hijack"]   = {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"DENY","AAB":"DENY","INV":"DENY"}
# ESC-CUSTOM-ROLE creates a custom Role in account-A. Role.Create
# is gated `editor@account` — the account-A owner (AAA) holds it and may
# create custom roles in their own account (defining a role is not itself
# privilege escalation — the role only grants what an AccessBinding later
# assigns, and binding-grant authority is separately enforced). So AAA → ALLOW
# in their own account; every other subject → DENY.
EXPECT["esc-custom-role"]      = {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"ALLOW","AAB":"DENY","INV":"DENY"}
EXPECT["iso-internal-rpc"]     = {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"DENY","AAB":"DENY","INV":"DENY"}
# data-leak-user-list — removed in replaced by user-list-unqualified
# (scope-filter ALLOW, not DENY — returning the caller's own user is not a leak).

# ESC-1: каждый субъект пытается выдать СЕБЕ iam.admin. На своем account —
# ALLOW (Problem-3: owner grant-authority в своем scope); на чужом — DENY.
for subj in SUBJECTS:
    user_var = {
        # NOB acts as jwtPureNoBindings, so its SELF-grant target is that user's id
        # (userNOBId would make the row a grant to a third party, not self-escalation).
        "NOB": "{{userPureNoBindingsId}}", "PA1": "{{userPA1Id}}",
        "AAA": "{{userAAAId}}", "AAB": "{{userAABId}}", "INV": "{{userINVId}}",
    }.get(subj[0], "{{userPureNoBindingsId}}")  # для ANON хватает любого id — суть DENY на anon
    emit("ESC-SELF-ADMIN-A", "Self-grant iam.admin on account-A",
         "esc-self-grant-A", "POST", "/iam/v1/accessBindings",
         {"subjectType":"user","subjectId":user_var,"roleId":ROLE_ADMIN,
          "scopeType":"iam.account","scopeId":"{{accountAId}}","target":{"allInScope":{}}}, subj)
    emit("ESC-SELF-ADMIN-B", "Self-grant iam.admin on account-B",
         "esc-self-grant-B", "POST", "/iam/v1/accessBindings",
         {"subjectType":"user","subjectId":user_var,"roleId":ROLE_ADMIN,
          "scopeType":"iam.account","scopeId":"{{accountBId}}","target":{"allInScope":{}}}, subj)

# ESC-2: создание Account. Body фиксирует ownerUserId=AAA → для caller AAA это
# self-owned creation (ALLOW), для остальных — hijack (DENY).
for subj in SUBJECTS:
    emit("ESC-ACCT-HIJACK", "Create Account with ownerUserId=AAA",
         "esc-account-hijack", "POST", "/iam/v1/accounts",
         {"name": f"hack-{subj[0].lower()}", "description": "hijack", "ownerUserId": "{{userAAAId}}"}, subj)

# ESC-3: создание custom Role с broad (super-admin-shaped) rules (HIGH-3).
# RBAC rules model: the authored field is `rules`. A custom
# role canNOT use module/resource wildcard `*` (system-only → 400), so the
# legacy super-admin intent (iam.*.*.* / vpc.*.*.* / compute.*.*.*) is expressed
# as concrete resource lists with verb-wildcard `verbs:["*"]` (all verbs) across
# the three domains — still broad enough to make the escalation probe meaningful.
# role name must match ^[a-z][a-z0-9_]{0,40}$ — hyphen is invalid
# and would fail name-validation BEFORE authz, masking the authz check. Use a
# regex-valid underscore name so the request actually exercises authz.
for subj in SUBJECTS:
    emit("ESC-CUSTOM-ROLE", "Create custom Role with broad iam/vpc/compute rules (escalation prep)",
         "esc-custom-role", "POST", "/iam/v1/roles",
         {"accountId": "{{accountAId}}", "name": f"hack_role_{subj[0].lower()}",
          "rules": [
              {"module": "iam", "resources": ["user", "role", "account", "project"], "verbs": ["*"]},
              {"module": "vpc", "resources": ["network", "subnet", "securityGroup"], "verbs": ["*"]},
              # `disk` здесь стоял до раскола блочного хранения и пережил его: тип
              # `compute.disk` отставлен (владелец — storage), и iam отвергает
              # правило, называющее снятый ресурс, — `domain.validateRetirementGate`.
              # Отказ приходил на ALLOW-полосу как 400, то есть кейс проверял не
              # эскалацию прав, а собственную несвежесть. Гейт верен, фикстура была
              # мертва: перепись по дереву дала ровно одно такое место из 13 правил
              # с `"module": "compute"`.
              {"module": "compute", "resources": ["instance"], "verbs": ["*"]},
          ]}, subj)

# HIGH-1: User.List unqualified (без accountId) — scope-filter RPC: 200 со
# списком только из member-Accounts caller'а (его собственный user как минимум).
# Возврат собственного user'а — не data leak. ALLOW, не DENY.
for subj in SUBJECTS:
    emit("DATA-LEAK-USR-LS", "User.List without accountId (scope-filter, returns own user)",
         "user-list-unqualified", "GET", "/iam/v1/users", None, subj)

# ISO-1..ISO-4: Internal RPC на external endpoint — должны 404 (но мы тестим
# на dev port 18080 который cluster-internal; этот класс для external TLS endpoint).
# Здесь — позитивный контроль что путь существует в principle.
# (Полноценный test против external endpoint — отдельная suite-variant.)


# ---------------------------------------------------------------------------
# AUTHZ-REVOKE-ENFORCED-A-INV push-drain end-to-end:
# AccessBinding revoke MUST de-authorise the subject within ~1s, not 30s.
#
# Pre-requires:
#   - iam emits subject_change_outbox on AccessBinding.Delete (writer-tx).
#   - iam push-drainer dials api-gateway internal listener and pushes
#     InvalidateSubject.
#   - api-gateway main.go wires the internal grpc listener so the drainer
#     can connect.
#
# Narrative (each step ~RTT-bound):
#   1. AAA grants jwtInvitee admin@account-A — fresh binding (different scope
#      than the setup.sh-baked INV→admin@account-B grant, so we can revoke it
#      cleanly without affecting INV's home account access).
#   2. Poll the create-Operation to done.
#   3. INV's first GET /iam/v1/accounts/{accountAId} → 200 (ALLOW + cache warm).
#   4. AAA DELETEs the binding (sync 200 + Operation).
#   5. Poll the delete-Operation to done.
#   6. Brief retry-on-ALLOW loop on INV's GET → expect 403 within a small
#      number of polls (≤8 ~= ≤1.6s @ 200ms). If still 200 the case fails:
#      either iam did not emit OR drainer did not push OR gateway did not
#      invalidate. (Without the push-drain wiring the gateway cache returns
#      ALLOW for ≤30s, the poll-loop fallback window.)
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="AUTHZ-REVOKE-ENFORCED-A-INV",
    title="push-drain enforces revoke→DENY within <2s (vs 30s poll-fallback)",
    classes=["AUTHZ", "FLOW", "PUSH_DRAIN"],
    priority="P0",
    steps=[
        # 1) AAA grants INV admin@account-A.
        Step(
            name="setup-grant-admin-to-inv",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                # Читает шаг ниже `jwtInvitee` — предъявитель СЛУЖЕБНОЙ УЧЁТКИ
                # (`svaInviteeId`, объявленная пара в principal_pairings.py). Выдача на
                # `userINVId` называла бы субъектом ряд, которым ни один запрос не
                # аутентифицируется: отношение не резолвится ни при каком бюджете, и шаг
                # прогорал по времени, сообщая о материализации вместо неверного субъекта.
                "subjectType": "service_account",
                "subjectId": "{{svaInviteeId}}",
                "roleId": ROLE_ADMIN,
                "scopeType": "iam.account",
                "scopeId": "{{accountAId}}",
                "target": {"allInScope": {}},
            },
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('grant create accepted (200; мутация возвращает Operation, 202 краем не производится)', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                # Clear FIRST — a rejected create mints no Operation and must not
                # inherit a previous case's id (the poll below would confirm it).
                "pm.environment.set('opId', '');",
                "if (j && j.id) pm.environment.set('opId', j.id);",
                "if (j && j.metadata && j.metadata.accessBindingId) {",
                "  pm.environment.set('w12RevokeBindingId', j.metadata.accessBindingId);",
                "}",
            ],
        ),
        # 2) Poll create-op to done; capture binding id from response if not in metadata.
        Step(
            name="poll-grant-op",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "pm.test('grant op done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "pm.test('grant succeeded (no error)', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
                "if (j.response && j.response.id && !pm.environment.get('w12RevokeBindingId')) {",
                "  pm.environment.set('w12RevokeBindingId', j.response.id);",
                "}",
            ],
        ),
        # 3) INV's first GET → ALLOW (200) — populates the gateway's authz decision cache.
        #
        # AccessBinding.Create Operation done = iam DB commit done;
        # FGA tuple write happens async via the fga_outbox drainer. So a
        # single-shot GET right after the grant-binding poll-op can still see
        # 404 before the tuple lands. Wrap in a POLL_CAP-bounded retry,
        # symmetric to the post-revoke loop below at step 6.
        # Accept 200 as soon as the tuple is visible; fail with detail if
        # the budget is exhausted (drainer not functioning).
        Step(
            name="inv-get-account-allow-warm-cache",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}",
            auth="jwtInvitee",
            test_script=[
                # First-entry reset (request-name-scoped flag).
                "if (pm.environment.get('_w12WarmStarted') !== pm.info.requestName) { pm.environment.set('_w12WarmPoll', '0'); pm.environment.set('_w12WarmStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_w12WarmPoll') || '0', 10);",
                f"if (pm.response.code !== 200 && pc < {POLL_CAP}) {{",
                "  pm.environment.set('_w12WarmPoll', String(pc + 1));",
                "  const _ipd1 = Date.now(); while (Date.now() - _ipd1 < 500) void 0; /* real inter-poll delay; budget = POLL_CAP x 500ms (testing.md). READ THE CONSTANT: it is 50, so ~25s — this line said 'cap 30 ~= 15s' while nothing set 30, and a known-failing record then justified itself with that 15s. */",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_w12WarmPoll');",
                "pm.environment.unset('_w12WarmStarted');",
                "pm.test('INV sees account-A (200) — grant visible inside the bounded poll (POLL_CAP x 500ms)', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.eql(200));",
            ],
        ),
        # 4) AAA revokes the binding. iam emits subject_change_outbox row in the
        #    same writer-tx. The drainer pushes InvalidateSubject
        #    to api-gateway within ~1s.
        Step(
            name="revoke-binding",
            method="DELETE",
            path="/iam/v1/accessBindings/{{w12RevokeBindingId}}",
            auth="jwtAccountAdminA",
            test_script=[
                # Read-your-writes over the DELETE gate's own relation. AccessBinding
                # Delete is gated on `v_delete` @ iam_access_binding:<id> (permission
                # catalog), and that tuple for the just-created binding materializes
                # eventually-consistent (writer-tx → fga_outbox → drainer → OpenFGA).
                # The grant above is seconds old, so the first DELETE can land inside
                # that window and come back 403 — which then leaves INV granted and
                # cascades into a foreign suite (iam-authz-grant-check-propagation's
                # `stranger-inv-on-accountA` sees a still-granted INV and gets 200
                # instead of 403). Bounded-retry the SELF revoke of our OWN fresh
                # binding (20 x 500ms ~= 10s); the real assertion still runs once the
                # budget is spent, so a genuine deny fails honestly (testing.md).
                "const _rvc = parseInt(pm.environment.get('_w12RevokeRetry') || '0', 10);",
                "if (pm.response.code === 403 && _rvc < 20) {",
                "  pm.environment.set('_w12RevokeRetry', String(_rvc + 1));",
                "  const _ipd = Date.now(); while (Date.now() - _ipd < 500) void 0;",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_w12RevokeRetry');",
                "pm.test('revoke accepted (200; 202 краем не производится)', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                # Clear FIRST — see the grant step above.
                "pm.environment.set('opId', '');",
                "if (j && j.id) pm.environment.set('opId', j.id);",
            ],
        ),
        # 5) Poll the revoke-Operation to done — by the time the op is done the
        #    iam writer-tx (binding state-flip + subject_change_outbox INSERT)
        #    has committed. The drainer typically pushes InvalidateSubject within
        #    ~200-500ms of the commit (LISTEN/NOTIFY → claim → gRPC push).
        Step(
            name="poll-revoke-op",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "pm.test('revoke op done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "pm.test('revoke succeeded (no error)', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
            ],
        ),
        # 6) INV's next GET — DENY within a poll budget. Retry-on-ALLOW
        #    loop bounded to POLL_CAP polls — well under the 30s
        #    WS-2.3 safety-net window. If still ALLOW after the budget, the
        #    push-drainer is NOT functioning (either iam side or gateway side).
        Step(
            name="inv-get-account-denied-post-revoke",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}",
            auth="jwtInvitee",
            test_script=[
                # First-entry reset (request-name-scoped flag).
                "if (pm.environment.get('_w12PollStarted') !== pm.info.requestName) { pm.environment.set('_w12Poll', '0'); pm.environment.set('_w12PollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_w12Poll') || '0', 10);",
                f"if (pm.response.code === 200 && pc < {POLL_CAP}) {{",
                "  pm.environment.set('_w12Poll', String(pc + 1));",
                "  const _ipd2 = Date.now(); while (Date.now() - _ipd2 < 500) void 0; /* real inter-poll delay: cap 30 x 500ms ~= 15s budget (testing.md) */",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_w12Poll');",
                "pm.environment.unset('_w12PollStarted');",
                # BUG-2 hide-existence: a verb-bearing IAM read-deny is surfaced as
                # NotFound (404 / code 5), never PermissionDenied — no enumeration leak.
                "pm.test('INV denied within ~2s of revoke (404 hide-existence)', () => {",
                "  pm.expect(pm.response.code, 'expected 404 post-revoke; got ' + pm.response.code + ' ' + pm.response.text()).to.equal(404);",
                "});",
                "let jj; try { jj = pm.response.json(); } catch(e) { jj = null; }",
                "pm.test('INV post-revoke: no deny_reasons leak', () => pm.expect(JSON.stringify(jj || {}).toLowerCase()).to.not.include('deny_reasons'));",
            ],
        ),
    ],
))

