# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set для RoleService — IAM-1 REDESIGN (authz-core: definitionTier + catalog).

Покрывает tenant-facing редизайн Role (docs/specs/sub-phase-IAM-1-tenancy-authz-core-
acceptance.md, F4/F5/F6). Public :8080 через api-gateway; мутации → IAM Operation
(id-prefix `iop`). Compiled `permissions` — Internal-only (:9091 GetRoleCompiled, вне
black-box reach) → здесь проверяется public field-ABSENCE (two-projection tenant-side).

Трассировка IAM-1-NN (verifies-аннотация в title):
  F4 definitionTier{tierType,tierId} dotted; isSystem° derived (10) · XOR/empty-tierType
     neg (11) · [IAM-1-12 tierType prefix-derivation — PHASE-0-GATED B3, tierType сейчас
     ОБЯЗАТЕЛЕН → см. RESULTS] ·
  F5 compiled permissions[] НЕ на public Get/List (13); client-sent permissions[] reject +
     пустой rules[] reject (14) ·
  F6 canonical system-catalog view→edit→admin→owner first-in-order; edit.effectiveVerbs°
     включает delete* + verbNotes (15); system-роль Update/Delete → FAILED_PRECONDITION
     (16) · [IAM-1-17 hyphen-id — PHASE-0-GATED B3, seed non-hyphen md5-id → см. RESULTS].

Техники (testing-product-coach): ECP (system vs custom tier; assignable-anchor класс),
decision-table (verbs×tier → editorTier delete*-qualifier), state-transition (Operation
done; system-role immutable), error-guessing (output-only permissions reject, empty rules,
malformed tier), conformance (definitionTier dotted проекция, isSystem derived, catalog
order/effectiveVerbs честный, field-absence compiled permissions).

Дисциплина (testing.md): read-your-writes → retry на ПЕРВЫЙ Get своей свежей роли;
negatives НЕ оборачиваются; per-case self-seed + cleanup; {{runId}}-имена.

Grounded в landed-коде: role/handler.go:49 permissions reject · create.go:102 rules
non-empty · handler.go:182 Illegal argument definitionTier · role_definition_tier.go:52
isSystem derived · list.go:111 catalog rank view<edit<admin<owner · role_effective_verbs.go
delete*/note · update.go:124 System role read-only · role_repo.go:472 cannot be deleted.
Seed (migrations 0001/0031/0040/0035): edit rules verbs=[get,list,update] (editor-tier),
view=[read,list,get], admin=[*], owner=[*.*].
"""

CASES = []

# System-role seeded ids (deterministic 'rol'||substr(md5(name),1,17); migrations
# 0001 + 0035). Hyphen-id form (rol-viewer/…) is PHASE-0-GATED B3.
SYS_VIEW = "rol1bda80f2be4d3658e"
SYS_EDIT = "rolde95b43bceeb4b998"
SYS_ADMIN = "rol21232f297a57a5a74"
SYS_OWNER = "rol72122ce96bfec66e2"

# Exact editor delete*-qualifier note (domain.EditorDeleteNote).
EDITOR_DELETE_NOTE = "co-materialized on in-scope leaf objects, NOT on the account/project anchor itself"


def assert_iam_op():
    return [
        "pm.test('IAM Operation envelope (iop)', () => {",
        "  const j = pm.response.json();",
        "  pm.expect(j.id, 'operation.id must start with iop').to.match(/^iop[a-z0-9]+$/);",
        "  pm.expect(j.done, 'operation.done present').to.be.a('boolean');",
        "});",
    ]


# ===========================================================================
# F4 — Role.definitionTier{tierType,tierId} dotted; isSystem° derived (IAM-1-10/11)
# ===========================================================================

CASES.append(Case(
    id="IAM-ROL-RD-CR-DEFINITIONTIER-OK",
    title="IAM-1-10: Role.Create с definitionTier{iam.account,accountA}+rules → Get: definitionTier."
          "tierType=='iam.account', tierId==accountA, isSystem°==false (derived tier!=iam.cluster); "
          "ответ НЕ несёт поля scope/scopeType/scopeId (зарезервировано за AccessBinding); rules roundtrip",
    classes=["CRUD", "CONF"],
    priority="P0",
    steps=[
        Step(
            name="create-role-tier",
            method="POST",
            path="/iam/v1/roles",
            body={
                "name": "rdtier{{runId}}",
                "definitionTier": {"tierType": "iam.account", "tierId": "{{accountAId}}"},
                "rules": [{"module": "compute", "resources": ["instance", "disk"],
                           "verbs": ["get", "list", "create", "update"]}],
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200), *assert_iam_op(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.roleId", "rdRoleId"),
            ],
        ),
        poll_operation_until_done(),
        assert_op_success(),
        retry_until_authorized(Step(
            name="get-role-tier",
            method="GET",
            path="/iam/v1/roles/{{rdRoleId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('definitionTier dotted projection', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.definitionTier, JSON.stringify(j)).to.be.an('object');",
                "  pm.expect(j.definitionTier.tierType).to.eql('iam.account');",
                "  pm.expect(j.definitionTier.tierId).to.eql(pm.environment.get('accountAId'));",
                "});",
                "pm.test('isSystem° derived false (custom account-tier)', () => pm.expect(pm.response.json().isSystem).to.eql(false));",
                "pm.test('no scope/scopeType/scopeId field on Role (reserved for AccessBinding)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j).to.not.have.property('scope');",
                "  pm.expect(j).to.not.have.property('scopeType');",
                "  pm.expect(j).to.not.have.property('scopeId');",
                "});",
                "pm.test('rules roundtrip (public surface)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect((j.rules||[]).length, JSON.stringify(j)).to.be.above(0);",
                "  pm.expect(j.rules[0].module).to.eql('compute');",
                "  pm.expect(j.rules[0].resources).to.include('instance');",
                "});",
            ],
        )),
        Step(name="cleanup-role-tier", method="DELETE", path="/iam/v1/roles/{{rdRoleId}}",
             auth="jwtAccountAdminA", test_script=[*save_from_response("j.id", "opId")]),
        poll_operation_until_done(),
    ],
))


CASES.append(Case(
    id="IAM-ROL-RD-CR-DEFINITIONTIER-EMPTY-TIERTYPE-NEG",
    title="IAM-1-11/12: definitionTier с tierId но БЕЗ tierType → sync 400 INVALID_ARGUMENT "
          "'Illegal argument definitionTier' (pre-Phase-0 tierType ОБЯЗАТЕЛЕН — prefix-derivation "
          "B3-gated; ровно один валидный anchor)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-role-empty-tiertype",
            method="POST",
            path="/iam/v1/roles",
            body={"name": "rdbadtier{{runId}}",
                  "definitionTier": {"tierId": "{{accountAId}}"},
                  "rules": [{"module": "compute", "resources": ["instance"], "verbs": ["get"]}]},
            auth="jwtAccountAdminA",
            test_script=[
                # authz-first: an empty tierType is UNSCOPEABLE at the gateway (no
                # object type to derive from the anchor; pre-Phase-0 prefix-derivation
                # is B3-gated) → the scope_extractor cannot resolve account|project and
                # fail-closes 403 BEFORE the iam handler's sync 400 'Illegal argument
                # definitionTier'. Both are correct rejections of a malformed anchor —
                # tolerate 400|403 (testing.md authz-first). Assert the canonical text
                # only when the request reached the handler (400).
                "pm.test('rejected 400 (validation) or 403 (authz-first unscoped)', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.be.oneOf([400, 403]));",
                "if (pm.response.code === 400) {",
                "  pm.test('INVALID_ARGUMENT (3)', () => pm.expect(pm.response.json().code).to.eql(3));",
                "  pm.test('Illegal argument definitionTier text', () => pm.expect(pm.response.json().message||'', JSON.stringify(pm.response.json())).to.include('Illegal argument definitionTier'));",
                "}",
            ],
        ),
    ],
))


CASES.append(Case(
    id="IAM-ROL-RD-CR-LEGACY-BOTH-SCOPES-XOR-NEG",
    title="IAM-1-11: legacy accountId И projectId оба непустые → sync 400 INVALID_ARGUMENT XOR "
          "('exactly one of account_id / project_id') — ровно один anchor",
    classes=["NEG"],
    priority="P2",
    steps=[
        Step(
            name="create-role-both-scopes",
            method="POST",
            path="/iam/v1/roles",
            body={"name": "rdxor{{runId}}", "accountId": "{{accountAId}}", "projectId": "{{projectA1Id}}",
                  "rules": [{"module": "compute", "resources": ["instance"], "verbs": ["get"]}]},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('XOR scope text', () => pm.expect((pm.response.json().message||'').toLowerCase(), JSON.stringify(pm.response.json())).to.include('exactly one of account_id'));",
            ],
        ),
    ],
))


# ===========================================================================
# F5 — compiled permissions[] Internal-only (two-projection) (IAM-1-13/14)
# ===========================================================================

CASES.append(Case(
    id="IAM-ROL-RD-GT-NO-COMPILED-PERMISSIONS",
    title="IAM-1-13: public Role.Get несёт rules[] (authored), НЕ несёт compiled permissions[] "
          "(two-projection — compiled M.R.rn.V только Internal GetRoleCompiled :9091, field-absence на public)",
    classes=["CONF", "SEC"],
    priority="P0",
    steps=[
        Step(
            name="seed-role-for-projection",
            method="POST",
            path="/iam/v1/roles",
            body={"name": "rdproj{{runId}}", "accountId": "{{accountAId}}",
                  "rules": [{"module": "compute", "resources": ["instance"], "verbs": ["get", "list"]}]},
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200), *assert_iam_op(), *save_from_response("j.id", "opId"),
                         *save_from_response("j.metadata && j.metadata.roleId", "projRoleId")],
        ),
        poll_operation_until_done(),
        assert_op_success(),
        retry_until_authorized(Step(
            name="get-role-no-compiled",
            method="GET",
            path="/iam/v1/roles/{{projRoleId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('rules[] present (authored public surface)', () => pm.expect((pm.response.json().rules||[]).length).to.be.above(0));",
                "pm.test('compiled permissions[] absent/empty on public Get', () => {",
                "  const j = pm.response.json();",
                "  pm.expect((j.permissions||[]).length, JSON.stringify(j)).to.eql(0);",
                "});",
            ],
        )),
        Step(name="cleanup-role-proj", method="DELETE", path="/iam/v1/roles/{{projRoleId}}",
             auth="jwtAccountAdminA", test_script=[*save_from_response("j.id", "opId")]),
        poll_operation_until_done(),
    ],
))


CASES.append(Case(
    id="IAM-ROL-RD-CR-PERMISSIONS-INPUT-REJECT-NEG",
    title="IAM-1-14: client-sent compiled permissions[] в Create-body → sync 400 INVALID_ARGUMENT "
          "'Illegal argument permissions' (output-only compiled-проекция; политика только через rules[])",
    classes=["NEG", "SEC"],
    priority="P1",
    steps=[
        Step(
            name="create-role-with-permissions",
            method="POST",
            path="/iam/v1/roles",
            body={"name": "rdperm{{runId}}", "accountId": "{{accountAId}}",
                  "permissions": ["compute.instance.*.get"],
                  "rules": [{"module": "compute", "resources": ["instance"], "verbs": ["get"]}]},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('Illegal argument permissions text', () => pm.expect((pm.response.json().message||'').toLowerCase(), JSON.stringify(pm.response.json())).to.include('illegal argument permissions'));",
            ],
        ),
    ],
))


CASES.append(Case(
    id="IAM-ROL-RD-CR-EMPTY-RULES-REJECT-NEG",
    title="IAM-1-14: Create БЕЗ rules[] (пустой) → sync 400 INVALID_ARGUMENT "
          "'Illegal argument rules (must be non-empty)' — legacy permissions-only отклоняется",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-role-empty-rules",
            method="POST",
            path="/iam/v1/roles",
            body={"name": "rdnorules{{runId}}", "accountId": "{{accountAId}}", "rules": []},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('rules must be non-empty text', () => pm.expect((pm.response.json().message||'').toLowerCase(), JSON.stringify(pm.response.json())).to.include('rules'));",
            ],
        ),
    ],
))


# ===========================================================================
# F6 — canonical system-role catalog + effectiveVerbs° (IAM-1-15/16)
# ===========================================================================

CASES.append(Case(
    id="IAM-ROL-RD-LS-CANONICAL-CATALOG-OK",
    title="IAM-1-15: RoleService.List → system-роли первыми в порядке view→edit→admin→owner "
          "(first-in-order rank); каждая isSystem°==true; edit.authoredVerbs°==[get,list,update], "
          "effectiveVerbs°==[get,list,update,delete*] (честный editor delete*-qualifier), "
          "verbNotes[delete*] дословно; view НЕ несёт delete*",
    classes=["CONF"],
    priority="P0",
    steps=[
        Step(
            name="list-catalog",
            method="GET",
            path="/iam/v1/roles?pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "const roles = j.roles || [];",
                "const names = roles.map(r => r.name);",
                "pm.test('catalog leads with view→edit→admin→owner (first-in-order)', () => {",
                "  pm.expect(names.slice(0,4), JSON.stringify(names)).to.eql(['view','edit','admin','owner']);",
                "});",
                "pm.test('canonical four are isSystem° true (derived cluster-tier)', () => {",
                "  for (const n of ['view','edit','admin','owner']) {",
                "    const r = roles.find(x => x.name === n);",
                "    pm.expect(r && r.isSystem, n).to.eql(true);",
                "  }",
                "});",
                "pm.test('edit.authoredVerbs° == [get,list,update]', () => {",
                "  const e = roles.find(x => x.name === 'edit');",
                "  pm.expect(e.authoredVerbs, JSON.stringify(e)).to.eql(['get','list','update']);",
                "});",
                "pm.test('edit.effectiveVerbs° includes delete* (honest editor co-materialization)', () => {",
                "  const e = roles.find(x => x.name === 'edit');",
                "  pm.expect(e.effectiveVerbs, JSON.stringify(e)).to.eql(['get','list','update','delete*']);",
                "});",
                f"pm.test('edit.verbNotes[delete*] verbatim', () => {{",
                "  const e = roles.find(x => x.name === 'edit');",
                f"  pm.expect((e.verbNotes||{{}})['delete*'], JSON.stringify(e)).to.eql('{EDITOR_DELETE_NOTE}');",
                "});",
                "pm.test('view.effectiveVerbs° does NOT include delete* (not editor-tier)', () => {",
                "  const v = roles.find(x => x.name === 'view');",
                "  pm.expect(v.effectiveVerbs||[], JSON.stringify(v)).to.not.include('delete*');",
                "});",
            ],
        ),
    ],
))


CASES.append(Case(
    id="IAM-ROL-RD-UP-SYSTEM-IMMUTABLE-NEG",
    title="IAM-1-16: Update system-роли (cluster-tier 'edit') → sync FAILED_PRECONDITION "
          "'System role is read-only and cannot be updated' (seed/system immutable)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="update-system-role",
            method="PATCH",
            path=f"/iam/v1/roles/{SYS_EDIT}",
            # google.protobuf.FieldMask serialises to a COMMA-SEPARATED STRING in
            # proto3 JSON, not an array — `["description"]` → grpc-gateway
            # "proto: syntax error unexpected token [".
            body={"updateMask": "description", "description": "hacked-{{runId}}"},
            auth="jwtBootstrap",
            test_script=[
                # System-role read-only fires SYNC (FAILED_PRECONDITION) before the Operation is minted.
                "pm.test('sync FAILED_PRECONDITION (9)', () => {",
                "  pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.eql(400);",
                "  pm.expect(pm.response.json().code).to.eql(9);",
                "});",
                "pm.test('read-only system role text', () => pm.expect((pm.response.json().message||'').toLowerCase(), JSON.stringify(pm.response.json())).to.include('system role is read-only'));",
            ],
        ),
    ],
))


CASES.append(Case(
    id="IAM-ROL-RD-DL-SYSTEM-NEG",
    title="IAM-1-16: Delete system-роли (cluster-tier 'view') → Operation.error FAILED_PRECONDITION "
          "'System role <id> cannot be deleted'",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="delete-system-role",
            method="DELETE",
            path=f"/iam/v1/roles/{SYS_VIEW}",
            auth="jwtBootstrap",
            test_script=[
                # Delete → async Operation; system-role guard surfaces as op.error (repo, worker path).
                # Tolerant of a sync-reject too (some guards fire pre-mint) — either way FAILED_PRECONDITION.
                "let j; try { j = pm.response.json(); } catch(e) { j = {}; }",
                "if (pm.response.code === 200 && (j.id||'').match(/^iop/)) {",
                "  pm.environment.set('opId', j.id);",
                "  pm.test('async Delete accepted (op minted)', () => pm.expect(true).to.eql(true));",
                "} else {",
                "  pm.environment.unset('opId');",
                "  pm.test('sync FAILED_PRECONDITION', () => pm.expect(pm.response.code).to.eql(400));",
                "  pm.test('sync code 9', () => pm.expect(j.code).to.eql(9));",
                "}",
            ],
        ),
        # If an Operation was minted, assert it terminates with FAILED_PRECONDITION.
        Step(
            name="assert-system-delete-op-error",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtBootstrap",
            pre_script=["if (!pm.environment.get('opId')) { pm.execution.setNextRequest(null); }"],
            test_script=[
                "if (pm.environment.get('opId')) {",
                "  const j = pm.response.json();",
                "  if (pm.environment.get('_sysDelStarted') !== pm.info.requestName) { pm.environment.set('_sysDelCount','0'); pm.environment.set('_sysDelStarted', pm.info.requestName); }",
                "  const pc = parseInt(pm.environment.get('_sysDelCount')||'0',10);",
                f"  if (!j.done && pc < {POLL_CAP}) {{ pm.environment.set('_sysDelCount', String(pc+1)); const _d=Date.now(); while(Date.now()-_d<500){{}} pm.execution.setNextRequest(pm.info.requestName); return; }}",
                "  pm.environment.unset('_sysDelCount'); pm.environment.unset('_sysDelStarted');",
                "  pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "  pm.test('op.error FAILED_PRECONDITION (9)', () => pm.expect(j.error && j.error.code, JSON.stringify(j)).to.eql(9));",
                "  pm.test('cannot be deleted text', () => pm.expect(((j.error&&j.error.message)||'').toLowerCase(), JSON.stringify(j)).to.include('cannot be deleted'));",
                "}",
            ],
        ),
    ],
))
