# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

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

Фикстуры (authz-fixtures/setup.sh): jwtAccountAdminA (principal == userAAAId),
accountAId (owned by userAAAId), accountBId, jwtAccountAdminB. Свежий account сага-
создаётся jwtAccountAdminA → caller становится owner° (derive-from-caller).

Grounded в landed-коде (services/iam/internal/apps/kacho/api/{account,project}):
  create.go:167 owner-in-body reject · update.go:57 owner immutable · create.go:255
  default "default" · account_repo.go:296 contains-projects · project/update.go:45
  accountId immutable · pgmaperr.go:95 dup-name.
"""

CASES = []

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
          "(derive-from-caller, principal userAAAId), status ACTIVE, createdAt truncate",
    classes=["CRUD", "CONF"],
    priority="P0",
    steps=[
        Step(
            name="create-no-owner",
            method="POST",
            path="/iam/v1/accounts",
            # NB: NO ownerUserId in body — owner° is derived from the authenticated caller.
            body={"name": "rdown{{runId}}", "description": "iam-1 owner-derive probe"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_op(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accountId", "rdAccId"),
            ],
        ),
        poll_operation_until_done(),
        assert_op_success(),
        retry_until_authorized(Step(
            name="get-owner-derived",
            method="GET",
            path="/iam/v1/accounts/{{rdAccId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('ownerUserId° derived from caller (== userAAAId)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.ownerUserId, JSON.stringify(j)).to.eql(pm.environment.get('userAAAId'));",
                "});",
                "pm.test('status ACTIVE', () => pm.expect(pm.response.json().status).to.eql('ACTIVE'));",
                *assert_created_at_seconds(),
            ],
        )),
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
            auth="jwtAccountAdminA",
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
            body={"name": "rdself{{runId}}", "ownerUserId": "{{userAAAId}}"},
            auth="jwtAccountAdminA",
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
            body={"updateMask": ["ownerUserId"], "ownerUserId": "usr00000000000000bad"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('immutable owner text', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.message || '', JSON.stringify(j)).to.include('ownerUserId is immutable after Account.Create');",
                "});",
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
            auth="jwtAccountAdminA",
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
            auth="jwtAccountAdminA",
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
            path="/iam/v1/accessBindings?filter=subject%3D%22{{userAAAId}}%22&pageSize=1000",
            auth="jwtAccountAdminA",
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
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200), *assert_iam_op(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accountId", "rstAccId"),
            ],
        ),
        poll_operation_until_done(),
        assert_op_success(),
        # Delete the non-empty account → async Operation.error FAILED_PRECONDITION.
        retry_until_authorized(Step(
            name="delete-nonempty",
            method="DELETE",
            path="/iam/v1/accounts/{{rstAccId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200), *assert_iam_op(),
                *save_from_response("j.id", "opId"),
            ],
        )),
        assert_op_error(9, "FAILED_PRECONDITION", msg_substr="contains projects"),
    ],
))


# ===========================================================================
# F3 — Project.accountId immutable (Move удалён); UNIQUE(accountId,name) per-account
#      (IAM-1-07/08/09)
# ===========================================================================

CASES.append(Case(
    id="IAM-PRJ-RD-CR-UNDER-ACCOUNT-OK",
    title="IAM-1-07: Project.Create под accountA → op → Get accountId==accountA, status ACTIVE; "
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
                "pm.test('status ACTIVE', () => pm.expect(pm.response.json().status).to.eql('ACTIVE'));",
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
        poll_operation_until_done(),
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
            body={"updateMask": ["accountId"], "accountId": "{{accountBId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('accountId immutable text', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.message || '', JSON.stringify(j)).to.include('accountId is immutable after Project.Create');",
                "});",
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
        assert_op_error(6, "ALREADY_EXISTS", msg_substr="already exists"),
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
        poll_operation_until_done(),
        assert_op_success(),
        # cleanup both.
        Step(name="cleanup-dup-A", method="DELETE", path="/iam/v1/projects/{{dupPrjA}}",
             auth="jwtAccountAdminA", test_script=[*save_from_response("j.id", "opId")]),
        poll_operation_until_done(),
        Step(name="cleanup-dup-B", method="DELETE", path="/iam/v1/projects/{{dupPrjB}}",
             auth="jwtAccountAdminB", test_script=[*save_from_response("j.id", "opId")]),
        poll_operation_until_done(),
    ],
))
