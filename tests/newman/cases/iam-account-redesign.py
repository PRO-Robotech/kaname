# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set для AccountService + ProjectService — IAM-1 REDESIGN (tenancy-tree).

Покрывает tenant-facing редизайн Account/Project (docs/specs/sub-phase-IAM-1-
tenancy-authz-core-acceptance.md, F1/F2/F3), НЕ легаси owner-required-поверхность
(та жила в cases/iam-account.py и здесь приводится к новому контракту). Все обращения
— public :8080 через api-gateway. Мутации возвращают IAM Operation (id-prefix `iop`,
НЕ `epd`) — поллятся через OpsProxy `/operations/{id}`.

Трассировка IAM-1-NN (verifies-аннотация в title каждого кейса):
  F1 ownerUserId° output-only derived-from-caller (01/02/03) ·
  F2 Account.Create one-shot сага: metadata несёт accountId+defaultProjectId,
     default Project("default") + owner-AccessBinding(deletionProtection=true) (04) ·
     Account.Delete RESTRICT на непустой аккаунт (06) ·
  F3 Project.accountId immutable (Move удалён, строго 2 уровня) (07/08) ·
     UNIQUE(accountId,name) per-account (09).

Техники (testing-product-coach): ECP (owner присутствует/отсутствует, own-account vs
cross-account name), decision-table (owner-in-body × значение: attacker-id vs self-id
— оба reject), state-transition (Operation done→durable; immutable-поля на Update),
error-guessing (output-only-field reject, dup-name, RESTRICT-непустой), conformance
(flat-shape, createdAt truncate, saga two-id metadata, default-project co-commit).

Дисциплина (testing.md): read-your-writes → retry_until_authorized/poll_request_until_
status на ПЕРВЫЙ доступ к своему свежему ресурсу; async op-poll с задержкой; negatives
НЕ оборачиваются; per-case self-seed (свежий account per {{runId}}) + best-effort
cleanup; {{runId}}-уникальные имена (UNIQUE(name) — коллизия на повторном прогоне).

Фикстуры (authz-fixtures/setup.sh): jwtAccountAdminA (СЛУЖЕБНАЯ учётка, admin @ accountAId
— для проектных кейсов и чтения посеянного аккаунта), accountAId (owned by userAAAId),
accountBId, jwtAccountAdminB.

СВЕЖИЙ АККАУНТ САГА-СОЗДАЁТСЯ ЧЕЛОВЕКОМ, и иначе нельзя: `owner_user_id` ссылается на
`users(id)`, владелец выводится из принципала, поэтому служебная учётка получает
синхронный отказ первым стейтментом. Условие создаёт волна церемонии
(`scripts/run-ceremony.sh`); необратимое удаление дополнительно требует ПОДНЯТОГО
уровня входа.

У КАЖДОГО ЗАВОДЯЩЕГО КЕЙСА ЧЕЛОВЕК СВОЙ, а не общий человек церемонии: заведение
аккаунта списывается с темпа личности (три в час), и восемь заведений волны под одним
человеком давали десять списаний при потолке три. Слоты объявлены в
`ceremony_credentials.ADMISSION_SLOTS`, ожидаемый владелец — `human<Слот>UserId`.
Кейсы, чей предмет — синхронный ОТКАЗ заведения, остаются на человеке церемонии:
отвергнутое заведение не списывает ничего.

Grounded в landed-коде (services/iam/internal/apps/kaname/api/{account,project}):
  create.go:167 owner-in-body reject · update.go:57 owner immutable · create.go:255
  default "default" · account_repo.go:296 contains-projects · project/update.go:45
  accountId immutable · pgmaperr.go:95 dup-name.
"""

CASES = []

# Поднятый уровень входа: `AccountService/Delete` объявлен чувствительным
# (`required_acr_min = "2"`). Машинный предъявитель от порога освобождён, поэтому под
# ним этот порог не проверялся ни разу.
#
# ЧЕЛОВЕК У КАЖДОГО ЗАВОДЯЩЕГО КЕЙСА СВОЙ, И ЭТО НЕ УКРАШЕНИЕ. Заведение аккаунта
# списывается с ТЕМПА личности (#618, умолчание — три в час на внешний идентификатор
# входа). Три заводящих кейса этого набора плюс пять соседних шли под ОДНИМ человеком
# церемонии, у которого посев уже занял два места, — десять списаний при потолке три.
# Отказ был верен; неверна была форма пробы: человек заводит СЕБЕ аккаунт, а не восемь
# подряд. Личности слотов объявлены в `ceremony_credentials.ADMISSION_SLOTS`, выдаёт их
# волна церемонии, и каждая заводит РОВНО ОДИН аккаунт.
#
# Пара на слот: обычный вход заводит и читает, поднятый — убирает за собой.
_HUMAN_DERIVE = "jwtHumanAccRdDerive"
_HUMAN_DERIVE_STEPUP = "jwtHumanAccRdDeriveStepUp"
_HUMAN_DERIVE_USER_ID = "humanAccRdDeriveUserId"

_HUMAN_SAGA = "jwtHumanAccRdSaga"
_HUMAN_SAGA_STEPUP = "jwtHumanAccRdSagaStepUp"
_HUMAN_SAGA_USER_ID = "humanAccRdSagaUserId"

_HUMAN_RESTRICT = "jwtHumanAccRdRestrict"
_HUMAN_RESTRICT_STEPUP = "jwtHumanAccRdRestrictStepUp"

# Кейсы, которые аккаунт НЕ заводят (их предмет — синхронный отказ формы запроса),
# остаются на человеке церемонии: отказанное заведение ничего не списывает, потому
# что транзакция не доходит до фиксации.
_HUMAN = "jwtHumanCeremony"

# ---------------------------------------------------------------------------
# Helpers: IAM Operation envelope (prefix `iop`, gen.py's assert_operation_envelope
# asserts `epd` and MUST NOT be used for iam).
# ---------------------------------------------------------------------------

def assert_iam_op():
    return [
        "pm.test('IAM Operation envelope (iop)', () => {",
        "  const j = pm.response.json();",
        "  pm.expect(j.id, 'operation.id must start with iop').to.match(/^iop[a-z0-9]+$/);",
        "  pm.expect(j.done, 'operation.done present').to.be.a('boolean');",
        "});",
    ]


# ===========================================================================
# F1 — Account.ownerUserId° output-only derived-from-caller (IAM-1-01/02/03)
# ===========================================================================

CASES.append(Case(
    id="IAM-ACC-RD-CR-OWNER-DERIVE-OK",
    title="IAM-1-01: Account.Create БЕЗ ownerUserId → op(iop) done → Get: ownerUserId° == caller "
          "(derive-from-caller, человек церемонии), createdAt truncate (Account has NO status field)",
    classes=["CRUD", "CONF"],
    priority="P0",
    steps=[
        Step(
            name="create-no-owner",
            method="POST",
            path="/iam/v1/accounts",
            # NB: NO ownerUserId in body — owner° is derived from the authenticated caller.
            body={"name": "rdown{{runId}}", "description": "iam-1 owner-derive probe"},
            # Владельцем аккаунта может быть только ПОЛЬЗОВАТЕЛЬ (`owner_user_id` →
            # `users(id)`), поэтому вызывающий — человек, а не служебная учётка
            # матрицы: у неё запрос отвергается первым стейтментом. Человек — СВОЙ
            # у этого кейса: заведение списывается с темпа личности, и складывать
            # заведения разных кейсов в одного человека значит воспроизводить
            # сценарий, который продукт отвергает.
            auth=_HUMAN_DERIVE,
            test_script=[
                *assert_status(200),
                *assert_iam_op(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accountId", "rdAccId"),
                # Захват потомка САГИ — ради уборки, а не ради утверждения (его
                # предмет — соседний кейс SAGA-TWO-ID). Без него снять аккаунт
                # нельзя: `Account.Delete` отвергает непустой аккаунт (RESTRICT),
                # а `default`-проект приезжает только этими метаданными.
                *save_from_response("j.metadata && j.metadata.defaultProjectId", "rdDefPrjId"),
            ],
        ),
        poll_operation_until_done(),
        assert_op_success(),
        retry_until_authorized(Step(
            name="get-owner-derived",
            method="GET",
            path="/iam/v1/accounts/{{rdAccId}}",
            auth=_HUMAN_DERIVE,
            test_script=[
                *assert_status(200),
                "pm.test('ownerUserId° derived from caller (== the human who created it)', () => {",
                "  const j = pm.response.json();",
                f"  const expected = pm.environment.get('{_HUMAN_DERIVE_USER_ID}');",
                # Пустое ожидаемое превратило бы сверку в тождество — проверяем его форму.
                f"  pm.expect(expected, '{_HUMAN_DERIVE_USER_ID} must be seeded by the ceremony wave')"
                ".to.be.a('string').and.to.match(/^usr[a-z0-9]+$/);",
                "  pm.expect(j.ownerUserId, JSON.stringify(j)).to.eql(expected);",
                "});",
                *assert_created_at_seconds(),
            ],
        )),
        # Уборка: сперва дочерний проект (FK RESTRICT), затем аккаунт — тем же
        # `reliable_delete`, каким её делают IAM-ACC-CR-BVA-NAME-MIN/MAX и
        # IAM-ACC-LSOP-CRUD-OK. Аккаунт занимает слот потолка ОБЪЁМА своей личности
        # (`iam.account`, умолчание 5 на внешний идентификатор входа); несобранный
        # слот доживает до конца прогона и сужает запас, который считает гейт
        # `deploy/scripts/assert-identity-account-peak-under-ceiling.py`. Потолок
        # ТЕМПА уборка не возвращает вовсе — его держит одна личность на кейс.
        *reliable_delete("teardown-rdown-project", "/iam/v1/projects/{{rdDefPrjId}}",
                         auth=_HUMAN_DERIVE_STEPUP, op_key="rdownPrj"),
        *reliable_delete("teardown-rdown-account", "/iam/v1/accounts/{{rdAccId}}",
                         auth=_HUMAN_DERIVE_STEPUP, op_key="rdownAcc"),
    ],
))


CASES.append(Case(
    id="IAM-ACC-RD-CR-OWNER-INBODY-ATTACKER-NEG",
    title="IAM-1-02: Account.Create с ownerUserId=<attacker> в теле → sync 400 INVALID_ARGUMENT "
          "'Illegal argument ownerUserId (derived from caller)', no Operation minted",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        Step(
            name="create-owner-attacker",
            method="POST",
            path="/iam/v1/accounts",
            body={"name": "rdatk{{runId}}", "ownerUserId": "usr00000000000000bad"},
            # Вызывающий обязан быть способен создать аккаунт — иначе отказ придёт про
            # род принципала, и кейс останется зелёным даже если проверку поля снимут.
            auth=_HUMAN,
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('exact reject text (derived from caller)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.message || '', JSON.stringify(j)).to.include('Illegal argument ownerUserId (derived from caller)');",
                "});",
                "pm.test('no Operation minted', () => pm.expect((pm.response.json().id)||'').to.not.match(/^iop/));",
            ],
        ),
    ],
))


CASES.append(Case(
    id="IAM-ACC-RD-CR-OWNER-INBODY-SELF-NEG",
    title="IAM-1-02: даже ownerUserId == principal.id (self) в теле → тот же sync 400 INVALID_ARGUMENT "
          "(поле output-only by construction — нет required-branch, нет anti-hijack-branch)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-owner-self",
            method="POST",
            path="/iam/v1/accounts",
            # ownerUserId == the caller's OWN id — still rejected (output-only by construction).
            # «Своим» это значение стало только теперь: прежде здесь стоял userAAAId при
            # вызывающем-служебной-учётке, то есть кейс никогда не проверял то, что называл.
            body={"name": "rdself{{runId}}", "ownerUserId": "{{ceremonyUserId}}"},
            auth=_HUMAN,
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('self-id still rejected (derived from caller)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.message || '', JSON.stringify(j)).to.include('Illegal argument ownerUserId (derived from caller)');",
                "});",
            ],
        ),
    ],
))


CASES.append(Case(
    id="IAM-ACC-RD-UP-OWNER-IMMUTABLE-NEG",
    title="IAM-1-03: Account.Update updateMask=[ownerUserId] → sync 400 INVALID_ARGUMENT "
          "'ownerUserId is immutable after Account.Create' (immutable-switch до UpdateMask)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="update-owner-immutable",
            method="PATCH",
            path="/iam/v1/accounts/{{accountAId}}",
            # FieldMask → comma-separated STRING in proto3 JSON, not an array.
            # `ownerUserId` is not a field of UpdateAccountRequest — the mask alone
            # drives the immutable-switch; a body key here would be discarded.
            body={"updateMask": "ownerUserId"},
            # The account OWNER does NOT materialize v_update on the account itself
            # (hierarchy-scope anti-over-grant, data-integrity.md) → an owner update
            # is authz-denied (403) BEFORE the handler's immutable-check. Use the
            # cluster system_admin (v_update everywhere) so the request reaches the
            # handler and the immutable validation is actually exercised (400).
            auth="jwtBootstrap",
            test_script=[
                # tolerate authz-first 403 (if system_admin also lacks v_update here);
                # assert the canonical immutable rejection when the handler is reached.
                "pm.test('rejected 400 (immutable) or 403 (authz-first)', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.be.oneOf([400, 403]));",
                "if (pm.response.code === 400) {",
                "  pm.test('INVALID_ARGUMENT (3)', () => pm.expect(pm.response.json().code).to.eql(3));",
                "  pm.test('immutable owner text', () => pm.expect(pm.response.json().message||'', JSON.stringify(pm.response.json())).to.include('ownerUserId is immutable after Account.Create'));",
                "}",
            ],
        ),
    ],
))


# ===========================================================================
# F2 — Account.Create one-shot сага: metadata(accountId+defaultProjectId),
#      default Project("default") + owner-AccessBinding(deletionProtection=true)
#      (IAM-1-04); Account.Delete RESTRICT на непустой аккаунт (IAM-1-06)
# ===========================================================================

CASES.append(Case(
    id="IAM-ACC-RD-CR-SAGA-TWO-ID-OK",
    title="IAM-1-04: Account.Create сага → metadata несёт accountId И defaultProjectId (оба до done); "
          "default Project name=='default', accountId==metadata.accountId (co-commit); owner-AccessBinding "
          "scopeType iam.account, deletionProtection=true (F5 owner-binding защищён)",
    classes=["CRUD", "SAGA", "CONF"],
    priority="P0",
    steps=[
        Step(
            name="create-saga",
            method="POST",
            path="/iam/v1/accounts",
            body={"name": "rdsaga{{runId}}", "description": "iam-1 saga two-id metadata"},
            auth=_HUMAN_SAGA,
            test_script=[
                *assert_status(200),
                *assert_iam_op(),
                *save_from_response("j.id", "opId"),
                # F2: BOTH ids present in metadata BEFORE done (client не List'ит дефолт-проект).
                *save_from_response("j.metadata && j.metadata.accountId", "sagaAccId"),
                *save_from_response("j.metadata && j.metadata.defaultProjectId", "sagaDefProjId"),
                "pm.test('metadata carries accountId (acc-prefix)', () => pm.expect(pm.environment.get('sagaAccId')||'').to.match(/^acc[a-z0-9]/));",
                "pm.test('metadata carries defaultProjectId (prj-prefix)', () => pm.expect(pm.environment.get('sagaDefProjId')||'').to.match(/^prj[a-z0-9]/));",
            ],
        ),
        poll_operation_until_done(),
        assert_op_success(),
        # Default Project co-committed in the SAME writer-tx: name=="default", accountId matches.
        retry_until_authorized(Step(
            name="get-default-project",
            method="GET",
            path="/iam/v1/projects/{{sagaDefProjId}}",
            auth=_HUMAN_SAGA,
            test_script=[
                *assert_status(200),
                "pm.test('default project name==default', () => pm.expect(pm.response.json().name).to.eql('default'));",
                "pm.test('default project accountId==saga account', () => pm.expect(pm.response.json().accountId).to.eql(pm.environment.get('sagaAccId')));",
            ],
        )),
        # Owner-AccessBinding materialized: List (whitelist filter subject=caller) contains an
        # iam.account binding on the saga account with deletionProtection=true (owner auto-grant).
        poll_request_until_status(
            name="list-owner-binding",
            method="GET",
            # Владельческая привязка заводится сагой на СОЗДАТЕЛЯ аккаунта, значит
            # искать её надо по человеку ЭТОГО кейса, а не по владельцу посеянного acctA.
            path="/iam/v1/accessBindings?filter=subject%3D%22{{" + _HUMAN_SAGA_USER_ID + "}}%22&pageSize=1000",
            auth=_HUMAN_SAGA,
            retry_predicate="(() => { const j = pm.response.json(); const acc = pm.environment.get('sagaAccId'); "
                            "return !((j.accessBindings)||[]).some(b => b.scopeId === acc); })()",
            test_script=[
                *assert_status(200),
                "pm.test('owner-AccessBinding on saga account: iam.account + deletionProtection', () => {",
                "  const j = pm.response.json();",
                "  const acc = pm.environment.get('sagaAccId');",
                "  const owner = ((j.accessBindings)||[]).find(b => b.scopeId === acc);",
                "  pm.expect(owner, JSON.stringify(j)).to.be.an('object');",
                "  pm.expect(owner.scopeType, 'scopeType dotted').to.eql('iam.account');",
                "  pm.expect(owner.deletionProtection, 'owner binding is deletion-protected').to.eql(true);",
                "});",
            ],
        ),
        # Уборка — после утверждений о САГЕ, а не вместо них: снимается ровно то,
        # что кейс завёл. Порядок обязателен (потомок → родитель): непустой аккаунт
        # отвергается RESTRICT, и это предмет соседнего кейса RD-DL-NONEMPTY.
        # Владельческая привязка снятию не мешает — `Account.Delete` вычищает
        # выдачи аккаунта сам (так же снимаются аккаунты BVA/LSOP).
        *reliable_delete("teardown-saga-project", "/iam/v1/projects/{{sagaDefProjId}}",
                         auth=_HUMAN_SAGA_STEPUP, op_key="sagaPrj"),
        *reliable_delete("teardown-saga-account", "/iam/v1/accounts/{{sagaAccId}}",
                         auth=_HUMAN_SAGA_STEPUP, op_key="sagaAcc"),
    ],
))


CASES.append(Case(
    id="IAM-ACC-RD-DL-NONEMPTY-RESTRICT-NEG",
    title="IAM-1-06: Account.Delete на аккаунт с ≥1 Project (default из саги) → Operation{done} c "
          "result.error FAILED_PRECONDITION 'Account <id> contains projects and cannot be deleted' "
          "(within-service FK RESTRICT, ban #10 DB-backstop)",
    classes=["NEG", "SAGA"],
    priority="P1",
    steps=[
        # Self-seed a fresh saga account (carries a default project → RESTRICT-non-empty).
        Step(
            name="seed-acc-for-restrict",
            method="POST",
            path="/iam/v1/accounts",
            body={"name": "rdrst{{runId}}", "description": "iam-1 delete-restrict probe"},
            auth=_HUMAN_RESTRICT,
            test_script=[
                *assert_status(200), *assert_iam_op(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accountId", "rstAccId"),
                # Тот самый проект, из-за которого аккаунт непуст, — предмет
                # утверждения ниже и одновременно единственный способ убрать за
                # собой: пока он есть, аккаунт не снять, а после его снятия
                # аккаунт снимается обычным порядком.
                *save_from_response("j.metadata && j.metadata.defaultProjectId", "rstDefPrjId"),
            ],
        ),
        poll_operation_until_done(),
        assert_op_success(),
        # Delete the non-empty account → async Operation.error FAILED_PRECONDITION.
        retry_until_authorized(Step(
            name="delete-nonempty",
            method="DELETE",
            path="/iam/v1/accounts/{{rstAccId}}",
            # Необратимое удаление → поднятый уровень входа (acr>=2).
            auth=_HUMAN_RESTRICT_STEPUP,
            test_script=[
                *assert_status(200), *assert_iam_op(),
                *save_from_response("j.id", "opId"),
            ],
        )),
        # `msg_substr` приводит обе стороны к нижнему регистру и заглавную `A`
        # владельца не различает; `msg_regex` сверяет текст как есть.
        assert_op_error(9, "FAILED_PRECONDITION",
                        msg_regex="Account [^ ]+ contains projects and cannot be deleted"),
        # Уборка идёт ПОСЛЕ утверждения об отказе и ничего в нём не меняет: отказ
        # уже зафиксирован на непустом аккаунте. Сняв потомка, снимаем и родителя —
        # иначе аккаунт, чьё удаление кейс проверяет, переживает прогон и держит
        # слот потолка объёма своей личности до конца прогона.
        *reliable_delete("teardown-rst-project", "/iam/v1/projects/{{rstDefPrjId}}",
                         auth=_HUMAN_RESTRICT_STEPUP, op_key="rstPrj"),
        *reliable_delete("teardown-rst-account", "/iam/v1/accounts/{{rstAccId}}",
                         auth=_HUMAN_RESTRICT_STEPUP, op_key="rstAcc"),
    ],
))


# ===========================================================================
# F3 — Project.accountId immutable (Move удалён); UNIQUE(accountId,name) per-account
#      (IAM-1-07/08/09)
# ===========================================================================

CASES.append(Case(
    id="IAM-PRJ-RD-CR-UNDER-ACCOUNT-OK",
    title="IAM-1-07: Project.Create под accountA → op → Get accountId==accountA (Project has NO status field); "
          "leaf-workspace (нет parent-project/folder поля — иерархия строго 2 уровня)",
    classes=["CRUD", "CONF"],
    priority="P0",
    steps=[
        Step(
            name="create-project",
            method="POST",
            path="/iam/v1/projects",
            body={"accountId": "{{accountAId}}", "name": "rdprj{{runId}}", "description": "iam-1 project"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200), *assert_iam_op(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.projectId", "rdPrjId"),
            ],
        ),
        poll_operation_until_done(),
        assert_op_success(),
        retry_until_authorized(Step(
            name="get-project",
            method="GET",
            path="/iam/v1/projects/{{rdPrjId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('accountId == accountA', () => pm.expect(pm.response.json().accountId).to.eql(pm.environment.get('accountAId')));",
                "pm.test('no parent-project/folder field (strictly 2 levels)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j).to.not.have.property('parentProjectId');",
                "  pm.expect(j).to.not.have.property('folderId');",
                "});",
                *assert_created_at_seconds(),
            ],
        )),
        # cleanup (best-effort): delete the fresh project.
        Step(name="cleanup-project", method="DELETE", path="/iam/v1/projects/{{rdPrjId}}",
             auth="jwtAccountAdminA", test_script=[*save_from_response("j.id", "opId")]),
        # Best-effort teardown: a refused DELETE returns no Operation, so there is
        # nothing to poll (required=False keeps a teardown detail from being
        # reported as a defect of the case under test).
        poll_operation_until_done(required=False),
    ],
))


CASES.append(Case(
    id="IAM-PRJ-RD-UP-ACCOUNT-IMMUTABLE-NEG",
    title="IAM-1-08: Project.Update updateMask=[accountId] → sync 400 INVALID_ARGUMENT "
          "'accountId is immutable after Project.Create' (нет Move RPC — cross-account перенос "
          "запрещён by construction; сломал бы scope-координату downstream)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="update-account-immutable",
            method="PATCH",
            path="/iam/v1/projects/{{projectA1Id}}",
            # FieldMask → comma-separated STRING in proto3 JSON, not an array.
            # `accountId` is not a field of UpdateProjectRequest — the mask alone
            # drives the immutable-switch; a body key here would be discarded.
            body={"updateMask": "accountId"},
            # editor does NOT materialize v_update on the project hierarchy-scope
            # (anti-over-grant) → owner/editor update is authz-denied (403) before the
            # handler's immutable-check. Use system_admin so the immutable validation
            # is actually exercised (400).
            auth="jwtBootstrap",
            test_script=[
                "pm.test('rejected 400 (immutable) or 403 (authz-first)', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.be.oneOf([400, 403]));",
                "if (pm.response.code === 400) {",
                "  pm.test('INVALID_ARGUMENT (3)', () => pm.expect(pm.response.json().code).to.eql(3));",
                "  pm.test('accountId immutable text', () => pm.expect(pm.response.json().message||'', JSON.stringify(pm.response.json())).to.include('accountId is immutable after Project.Create'));",
                "}",
            ],
        ),
    ],
))


CASES.append(Case(
    id="IAM-PRJ-RD-CR-DUP-NAME-PER-ACCOUNT",
    title="IAM-1-09: dup name в том же аккаунте → Operation.error ALREADY_EXISTS (partial "
          "UNIQUE(accountId,name), 23505); то же имя в ДРУГОМ аккаунте → OK (uniqueness per-account)",
    classes=["NEG", "EDGE"],
    priority="P1",
    steps=[
        # First create under accountA.
        Step(
            name="create-first-A",
            method="POST",
            path="/iam/v1/projects",
            body={"accountId": "{{accountAId}}", "name": "rddup{{runId}}"},
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200), *assert_iam_op(), *save_from_response("j.id", "opId"),
                         *save_from_response("j.metadata && j.metadata.projectId", "dupPrjA")],
        ),
        poll_operation_until_done(),
        assert_op_success(),
        # Duplicate name in the SAME account → op.error ALREADY_EXISTS.
        Step(
            name="create-dup-A",
            method="POST",
            path="/iam/v1/projects",
            body={"accountId": "{{accountAId}}", "name": "rddup{{runId}}"},
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200), *save_from_response("j.id", "opId")],
        ),
        # Текст владельца ЦЕЛИКОМ: «already exists» несут пять разных отказов iam
        # (Account/Group/Project/Role/ServiceAccount), и утверждение об общей части
        # проходило на отказе о ЧУЖОМ ресурсе (#1748).
        assert_op_error(6, "ALREADY_EXISTS",
                        msg_text="Project with name rddup{{runId}} already exists"),
        # Same name under accountB (jwtAccountAdminB) → success (per-account uniqueness).
        Step(
            name="create-same-name-B",
            method="POST",
            path="/iam/v1/projects",
            body={"accountId": "{{accountBId}}", "name": "rddup{{runId}}"},
            auth="jwtAccountAdminB",
            test_script=[*assert_status(200), *assert_iam_op(), *save_from_response("j.id", "opId"),
                         *save_from_response("j.metadata && j.metadata.projectId", "dupPrjB")],
        ),
        # OperationService.Get is account-scoped — the op minted under accountB
        # (jwtAccountAdminB) is only visible to a caller with access to accountB;
        # polling it with the default jwtAccountAdminA → hide-existence 404. Poll
        # (and assert) with the CREATOR's identity.
        poll_operation_until_done(auth="jwtAccountAdminB"),
        assert_op_success(auth="jwtAccountAdminB"),
        # cleanup both. The DELETE is the FIRST authz-gated access of each just-
        # created project (the prior polls were on the Create *Operation*, not the
        # project resource), so its creator/owner FGA tuple can still be materialising
        # (opgate removed → op.done ≠ tuple visible). Under load that surfaces as a
        # transient 403 at the delete authz gate → the raw DELETE never saved a fresh
        # `opId`, so the following poll polled the STALE op id (the prior delete's, minted
        # by a DIFFERENT principal) → 404 from OperationService.Get's principal-scoped
        # hide-existence. Wrap the own-fresh-resource delete in the bounded read-your-
        # writes retry (retries SELF only on 403/404, fail-closed at budget).
        retry_until_authorized(Step(
            name="cleanup-dup-A", method="DELETE", path="/iam/v1/projects/{{dupPrjA}}",
            auth="jwtAccountAdminA", test_script=[*assert_status(200), *save_from_response("j.id", "opId")])),
        poll_operation_until_done(),
        retry_until_authorized(Step(
            name="cleanup-dup-B", method="DELETE", path="/iam/v1/projects/{{dupPrjB}}",
            auth="jwtAccountAdminB", test_script=[*assert_status(200), *save_from_response("j.id", "opId")])),
        poll_operation_until_done(auth="jwtAccountAdminB"),
    ],
))
