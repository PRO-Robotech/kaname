# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set для AccessBindingService — IAM-1 REDESIGN (authz-core: scope+target+revoke).

Покрывает tenant-facing редизайн AccessBinding (docs/specs/sub-phase-IAM-1-tenancy-
authz-core-acceptance.md, F7/F8/F9/F10/F11). Public :8080 через api-gateway; мутации →
IAM Operation (id-prefix `iop`).

Трассировка IAM-1-NN (verifies-аннотация в title):
  F7 scope-anchor rename resourceType/Id→scopeType(dotted)/scopeId; immutable (18/19) ·
     [scopeType prefix-derivation IAM-1-18/20 — PHASE-0-GATED B3, scopeType сейчас ОБЯЗАТЕЛЕН] ·
  F8 target REQUIRED (allInScope{} | resources[ResourceRef{type,id}] closed-table, без name);
     no-target → INVALID_ARGUMENT; unknown type → INVALID_ARGUMENT; RoleCoversType (21/22/23/24) ·
  F9 3 sync-гейта (scope-XOR/IsRoleAssignable/RoleCoversType) первыми стейтментами до Operation;
     malformed scopeId; missing anchor (24/25/26) ·
  F10 Delete=hard (Get→existence-hide 403/404) / :revoke=soft (status REVOKED, revokedAt);
      re-grant после revoke → новая ACTIVE-строка; идентичный при ACTIVE → ALREADY_EXISTS (27/28/29) ·
  F11 List format-validate ДО authz (garbage token/pageSize>1000 → 400); whitelist-filter
      subject/role/scope/scopeId; unknown key → 400 (32).

Техники (testing-product-coach): ECP (scope-tier класс; target allInScope vs per-object),
decision-table (roleTier×scopeAnchor → assignable; roleRules×targetType → covers), BVA
(pageSize 1000/1001, pageToken garbage), state-transition (Operation done; ACTIVE→REVOKED
terminal; immutable-scope на Update; hard-delete gone), error-guessing (no-target, unknown
resource-type, malformed scopeId, re-grant race), conformance (scopeType dotted, target
двойная вложенность resources.resources[], ResourceRef без name, existence-hide byte-parity).

Дисциплина (testing.md): read-your-writes → retry_until_authorized / get_until_gone на
ПЕРВЫЙ доступ к своему свежему binding; async op-poll с задержкой; negatives (no-target,
unknown-type, gate-FP, malformed) НЕ оборачиваются; authz-first → oneOf([400,403,404]) где
gateway scope_extractor короткозамыкает недоступный/absent target; per-case self-seed
свежей custom-роли (run-unique tuple → нет UNIQUE-коллизии на повторном прогоне) + cleanup.

Grounded в landed-коде (services/iam/internal/apps/kacho/api/access_binding):
  delta_input.go:27 target required · :47 unknown target type · :63 scopeType required ·
  structural_gates.go:73 IsRoleAssignable · :100 RoleCoversType · :144 invalid scope id ·
  update.go:56-75 immutable per-field · revoke.go status REVOKED+revokedAt · get.go:63
  existence-hide 403 on Delete-gone · handler.go:236/240/259 List format-before-authz + whitelist.
"""

CASES = []

# System-role ids (deterministic seed). SYS_ADMIN rules cover `*.*.*` (covers any
# target type); SYS_VIEW is read-only. Custom roles are self-seeded per-case for
# tier control + run-unique grant tuples.
SYS_VIEW = "rol1bda80f2be4d3658e"
SYS_ADMIN = "rol21232f297a57a5a74"

# A well-formed compute.instance target id (existence is NOT checked by IAM — target
# ResourceRef is a graceful-dangling cross-DB soft-ref; only the closed type-registry
# is validated). {{runId}} keeps the (subject,role,scope,target) tuple run-unique.
_TGT_INSTANCE = {"type": "compute.instance", "id": "ins-rdacb{{runId}}"}


def assert_iam_op():
    return [
        "pm.test('IAM Operation envelope (iop)', () => {",
        "  const j = pm.response.json();",
        "  pm.expect(j.id, 'operation.id must start with iop').to.match(/^iop[a-z0-9]+$/);",
        "  pm.expect(j.done, 'operation.done present').to.be.a('boolean');",
        "});",
    ]


def _seed_role(suffix, save_var, tier_type="iam.account", tier_id="{{accountAId}}",
               rules=None):
    """Self-seed a custom Role (run-unique name) at the given definitionTier; saves its
    id into save_var. Default rules cover compute.instance (assignable+covers for target
    positives). Returns [create, poll, assert_op_success]."""
    if rules is None:
        rules = [{"module": "compute", "resources": ["instance"], "verbs": ["get", "list", "update"]}]
    return [
        Step(name=f"seed-role-{suffix}", method="POST", path="/iam/v1/roles",
             body={"name": f"rdacbr{suffix}{{{{runId}}}}",
                   "definitionTier": {"tierType": tier_type, "tierId": tier_id},
                   "rules": rules},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200), *assert_iam_op(), *save_from_response("j.id", "opId"),
                          *save_from_response("j.metadata && j.metadata.roleId", save_var)]),
        poll_operation_until_done(),
        assert_op_success(),
    ]


def _cleanup_role(save_var, name="cleanup-role"):
    return [Step(name=name, method="DELETE", path="/iam/v1/roles/{{" + save_var + "}}",
                 auth="jwtAccountAdminA", test_script=[*save_from_response("j.id", "opId")]),
            poll_operation_until_done()]


def _acb_body(role_var, target, scope_type="iam.account", scope_id="{{accountAId}}",
              subj="{{userNOBId}}"):
    b = {"subjectType": "user", "subjectId": subj, "roleId": "{{" + role_var + "}}"}
    if scope_type is not None:
        b["scopeType"] = scope_type
    b["scopeId"] = scope_id
    if target is not None:
        b["target"] = target
    return b


def _create_binding(name, body, save_var):
    return [
        Step(name=name, method="POST", path="/iam/v1/accessBindings", body=body,
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200), *assert_iam_op(), *save_from_response("j.id", "opId"),
                          *save_from_response("j.metadata && j.metadata.accessBindingId", save_var)]),
        poll_operation_until_done(),
        assert_op_success(),
    ]


def _cleanup_binding(save_var, name="cleanup-binding"):
    return [Step(name=name, method="DELETE", path="/iam/v1/accessBindings/{{" + save_var + "}}",
                 auth="jwtAccountAdminA", test_script=[*save_from_response("j.id", "opId")]),
            poll_operation_until_done()]


# ===========================================================================
# F7 + F8 — scopeType/scopeId + target.allInScope (IAM-1-18/21)
# ===========================================================================

CASES.append(Case(
    id="IAM-ACB-RD-CR-SCOPE-ALLINSCOPE-OK",
    title="IAM-1-18/21: Create scopeType=iam.account, scopeId=accountA, target.allInScope{} → op → "
          "Get: scopeType=='iam.account', scopeId==accountA, target.allInScope задан; ответ НЕ несёт "
          "resourceType/resourceId (имя 'resource' отдано target'у — единственная scope-проекция)",
    classes=["CRUD", "CONF"],
    priority="P0",
    steps=[
        *_seed_role("as", "rdRoleAs"),
        *_create_binding("cr-allinscope", _acb_body("rdRoleAs", {"allInScope": {}}), "rdAcbAs"),
        retry_until_authorized(Step(
            name="get-allinscope",
            method="GET",
            path="/iam/v1/accessBindings/{{rdAcbAs}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('scopeType dotted iam.account', () => pm.expect(pm.response.json().scopeType).to.eql('iam.account'));",
                "pm.test('scopeId == accountA', () => pm.expect(pm.response.json().scopeId).to.eql(pm.environment.get('accountAId')));",
                "pm.test('target.allInScope present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.target, JSON.stringify(j)).to.be.an('object');",
                "  pm.expect(j.target.allInScope, JSON.stringify(j.target)).to.be.an('object');",
                "});",
                "pm.test('no resourceType/resourceId on wire (F7 rename)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j).to.not.have.property('resourceType');",
                "  pm.expect(j).to.not.have.property('resourceId');",
                "});",
            ],
        )),
        *_cleanup_binding("rdAcbAs"),
        *_cleanup_role("rdRoleAs"),
    ],
))


CASES.append(Case(
    id="IAM-ACB-RD-CR-TARGET-RESOURCES-OK",
    title="IAM-1-21/23: Create target.resources=[ResourceRef{compute.instance, ins-…}] (per-object, "
          "role covers *) → op → Get target.resources.resources[0].type=='compute.instance', id совпал, "
          "БЕЗ поля name (ResourceRef closed-table {type,id})",
    classes=["CRUD", "CONF"],
    priority="P1",
    steps=[
        # Self-seed a custom account-tier role that COVERS compute.instance (so RoleCoversType
        # gate-3 passes) and is grantable by jwtAccountAdminA on accountA.
        *_seed_role("po", "rdRolePo"),
        *_create_binding(
            "cr-perobj",
            _acb_body("rdRolePo", {"resources": {"resources": [dict(_TGT_INSTANCE)]}}),
            "rdAcbPo",
        ),
        retry_until_authorized(Step(
            name="get-perobj",
            method="GET",
            path="/iam/v1/accessBindings/{{rdAcbPo}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('target.resources.resources[0] is compute.instance ResourceRef', () => {",
                "  const j = pm.response.json();",
                "  const refs = ((j.target||{}).resources||{}).resources||[];",
                "  pm.expect(refs.length, JSON.stringify(j.target)).to.be.above(0);",
                "  pm.expect(refs[0].type).to.eql('compute.instance');",
                "  pm.expect(refs[0].id, JSON.stringify(refs[0])).to.include('ins-rdacb');",
                "  pm.expect(refs[0]).to.not.have.property('name');",
                "});",
            ],
        )),
        *_cleanup_binding("rdAcbPo"),
        *_cleanup_role("rdRolePo"),
    ],
))


# ===========================================================================
# F8 — target REQUIRED + closed-table (IAM-1-22/23)
# ===========================================================================

CASES.append(Case(
    id="IAM-ACB-RD-CR-NO-TARGET-NEG",
    title="IAM-1-22: Create БЕЗ target (ни resources, ни allInScope) → sync 400 INVALID_ARGUMENT "
          "'target is required; use target.allInScope{} to grant all objects under the anchor' "
          "(least-privilege spine — самый широкий грант только явным allInScope opt-in)",
    classes=["NEG"],
    priority="P0",
    steps=[
        *_seed_role("nt", "rdRoleNt"),
        Step(
            name="cr-no-target",
            method="POST",
            path="/iam/v1/accessBindings",
            body=_acb_body("rdRoleNt", None),  # target omitted
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('target required text', () => pm.expect(pm.response.json().message||'', JSON.stringify(pm.response.json())).to.include('target is required; use target.allInScope{}'));",
            ],
        ),
        *_cleanup_role("rdRoleNt"),
    ],
))


CASES.append(Case(
    id="IAM-ACB-RD-CR-TARGET-UNKNOWN-TYPE-NEG",
    title="IAM-1-23: target.resources=[{type:'unknown.thing',id}] (тип вне закрытого type-registry) → "
          "sync 400 INVALID_ARGUMENT 'Illegal argument target.resources[].type' (closed-table валидируется)",
    classes=["NEG"],
    priority="P1",
    steps=[
        # targetFromProto validates the closed target type-registry in the HANDLER, before the
        # use-case reads the role or checks authority — so a plain existing roleId (SYS_VIEW) and
        # a valid dotted scopeType suffice to reach the target-type check.
        Step(
            name="cr-unknown-type",
            method="POST",
            path="/iam/v1/accessBindings",
            body={"subjectType": "user", "subjectId": "{{userNOBId}}", "roleId": SYS_VIEW,
                  "scopeType": "iam.account", "scopeId": "{{accountAId}}",
                  "target": {"resources": {"resources": [{"type": "unknown.thing", "id": "x"}]}}},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('unknown target type text', () => pm.expect(pm.response.json().message||'', JSON.stringify(pm.response.json())).to.include('Illegal argument target.resources[].type'));",
            ],
        ),
    ],
))


# ===========================================================================
# F7 — scopeType required (pre-Phase-0; prefix-derivation B3-gated) (IAM-1-18/26)
# ===========================================================================

CASES.append(Case(
    id="IAM-ACB-RD-CR-SCOPETYPE-REQUIRED-NEG",
    title="IAM-1-18: scopeType опущен → sync 400 'scopeType is required'; bare 'account' (не dotted) → "
          "sync 400 'Illegal argument scopeType' (pre-Phase-0 scopeType ОБЯЗАТЕЛЕН и dotted — "
          "prefix-derivation B3-gated)",
    classes=["NEG"],
    priority="P1",
    steps=[
        *_seed_role("st", "rdRoleSt"),
        Step(
            name="cr-scopetype-missing",
            method="POST",
            path="/iam/v1/accessBindings",
            body=_acb_body("rdRoleSt", {"allInScope": {}}, scope_type=None),  # scopeType omitted
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('scopeType required text', () => pm.expect((pm.response.json().message||'').toLowerCase(), JSON.stringify(pm.response.json())).to.include('scopetype is required'));",
            ],
        ),
        Step(
            name="cr-scopetype-bare",
            method="POST",
            path="/iam/v1/accessBindings",
            body=_acb_body("rdRoleSt", {"allInScope": {}}, scope_type="account"),  # bare, not dotted
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('Illegal argument scopeType text', () => pm.expect(pm.response.json().message||'', JSON.stringify(pm.response.json())).to.include('Illegal argument scopeType'));",
            ],
        ),
        *_cleanup_role("rdRoleSt"),
    ],
))


# ===========================================================================
# F7 — scope/subjects immutable via Update (IAM-1-19)
# ===========================================================================

CASES.append(Case(
    id="IAM-ACB-RD-UP-SCOPE-IMMUTABLE-NEG",
    title="IAM-1-19: Update updateMask=[scopeId] → sync 400 'scopeId is immutable after AccessBinding."
          "Create'; updateMask=[subjects] → 'subjects is immutable…' (mutable-set = {deletionProtection,labels})",
    classes=["NEG"],
    priority="P1",
    steps=[
        *_seed_role("im", "rdRoleIm"),
        *_create_binding("cr-for-immutable", _acb_body("rdRoleIm", {"allInScope": {}}), "rdAcbIm"),
        retry_until_authorized(Step(
            name="up-scopeid-immutable",
            method="PATCH",
            path="/iam/v1/accessBindings/{{rdAcbIm}}",
            body={"updateMask": ["scopeId"], "scopeId": "{{accountBId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('scopeId immutable text', () => pm.expect(pm.response.json().message||'', JSON.stringify(pm.response.json())).to.include('scopeId is immutable after AccessBinding.Create'));",
            ],
        )),
        Step(
            name="up-subjects-immutable",
            method="PATCH",
            path="/iam/v1/accessBindings/{{rdAcbIm}}",
            body={"updateMask": ["subjects"], "subjects": [{"type": "USER", "id": "{{userAAAId}}"}]},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('subjects immutable text', () => pm.expect(pm.response.json().message||'', JSON.stringify(pm.response.json())).to.include('subjects is immutable after AccessBinding.Create'));",
            ],
        ),
        *_cleanup_binding("rdAcbIm"),
        *_cleanup_role("rdRoleIm"),
    ],
))


# ===========================================================================
# F9 — 3 sync structural gates first-statement (IAM-1-24/25/26)
# ===========================================================================

CASES.append(Case(
    id="IAM-ACB-RD-CR-ROLECOVERSTYPE-NEG",
    title="IAM-1-24: role покрывает только vpc.*, target.resources=[compute.instance] → sync "
          "FAILED_PRECONDITION 'role <id> does not grant verbs on compute.instance; target type must be "
          "covered by role.rules' (3-й sync-гейт RoleCoversType, ДО Operation)",
    classes=["NEG"],
    priority="P1",
    steps=[
        # vpc-only role (account-tier, assignable on accountA — gate-2 passes; gate-3 fails on compute type).
        *_seed_role("rc", "rdRoleRc",
                    rules=[{"module": "vpc", "resources": ["network"], "verbs": ["get", "list", "update"]}]),
        Step(
            name="cr-rolecoverstype",
            method="POST",
            path="/iam/v1/accessBindings",
            body=_acb_body("rdRoleRc", {"resources": {"resources": [dict(_TGT_INSTANCE)]}}),
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(9, "FAILED_PRECONDITION"),
                "pm.test('RoleCoversType text', () => pm.expect(pm.response.json().message||'', JSON.stringify(pm.response.json())).to.include('does not grant verbs on compute.instance'));",
                "pm.test('actionable tail', () => pm.expect(pm.response.json().message||'').to.include('target type must be covered by role.rules'));",
            ],
        ),
        *_cleanup_role("rdRoleRc"),
    ],
))


CASES.append(Case(
    id="IAM-ACB-RD-CR-ROLE-NOTASSIGNABLE-NEG",
    title="IAM-1-25: project-tier роль (на projectA1) назначаемая на account-anchor accountA → sync "
          "FAILED_PRECONDITION 'is not assignable on iam.account:…; assign at … tier of this account' "
          "(2-й sync-гейт IsRoleAssignable — project-роль assignable только на своём проекте)",
    classes=["NEG"],
    priority="P1",
    steps=[
        # project-tier role → assignable ONLY on its own project; on the account anchor → not-assignable.
        *_seed_role("na", "rdRoleNa", tier_type="iam.project", tier_id="{{projectA1Id}}"),
        Step(
            name="cr-notassignable",
            method="POST",
            path="/iam/v1/accessBindings",
            body=_acb_body("rdRoleNa", {"allInScope": {}}, scope_type="iam.account", scope_id="{{accountAId}}"),
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(9, "FAILED_PRECONDITION"),
                "pm.test('IsRoleAssignable text', () => pm.expect(pm.response.json().message||'', JSON.stringify(pm.response.json())).to.include('is not assignable on iam.account'));",
            ],
        ),
        *_cleanup_role("rdRoleNa"),
    ],
))


CASES.append(Case(
    id="IAM-ACB-RD-CR-SCOPEID-MALFORMED-NEG",
    title="IAM-1-26: malformed scopeId '!!!' → sync 400 INVALID_ARGUMENT 'invalid access binding scope "
          "id' (1-й sync-гейт corevalidate.ResourceID первым стейтментом); well-formed-но-нет anchor → "
          "NOT_FOUND/authz-first (tolerant 400|403|404)",
    classes=["NEG"],
    priority="P1",
    steps=[
        *_seed_role("mf", "rdRoleMf"),
        Step(
            name="cr-scopeid-malformed",
            method="POST",
            path="/iam/v1/accessBindings",
            body=_acb_body("rdRoleMf", {"allInScope": {}}, scope_type="iam.project", scope_id="!!!"),
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('invalid scope id text', () => pm.expect((pm.response.json().message||'').toLowerCase(), JSON.stringify(pm.response.json())).to.include('invalid access binding scope id'));",
            ],
        ),
        # Well-formed-but-nonexistent project anchor. NOT_FOUND per direct-read lane; but the
        # gateway scope_extractor can fail-closed 403 on an unresolvable target → authz-first
        # tolerance (never 200). NOT wrapped in a retry (negative).
        Step(
            name="cr-scopeid-missing-anchor",
            method="POST",
            path="/iam/v1/accessBindings",
            body=_acb_body("rdRoleMf", {"allInScope": {}}, scope_type="iam.project",
                           scope_id="prj00000000000missng"),
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('missing anchor rejected (authz-first tolerant), never 200', () => "
                "pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.be.oneOf([400, 403, 404]));",
            ],
        ),
        *_cleanup_role("rdRoleMf"),
    ],
))


# ===========================================================================
# F10 — Delete=hard / :revoke=soft; re-grant (IAM-1-27/28/29)
# ===========================================================================

CASES.append(Case(
    id="IAM-ACB-RD-DL-HARD-OK",
    title="IAM-1-27: Delete = физическое удаление → Get → gone (existence-hide 403 или 404). "
          "product-parity hard-delete (тот же смысл, что compute/vpc/nlb)",
    classes=["CRUD"],
    priority="P0",
    steps=[
        *_seed_role("dh", "rdRoleDh"),
        *_create_binding("cr-for-delete", _acb_body("rdRoleDh", {"allInScope": {}}), "rdAcbDh"),
        retry_until_authorized(Step(
            name="delete-hard",
            method="DELETE",
            path="/iam/v1/accessBindings/{{rdAcbDh}}",
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200), *assert_iam_op(), *save_from_response("j.id", "opId")],
        )),
        poll_operation_until_done(),
        # Get after hard-delete → gone. get.go hides existence → 403 (or 404) — both accepted.
        get_until_gone("/iam/v1/accessBindings/{{rdAcbDh}}", "AccessBinding hard-deleted"),
        *_cleanup_role("rdRoleDh"),
    ],
))


CASES.append(Case(
    id="IAM-ACB-RD-REVOKE-SOFT-OK",
    title="IAM-1-28: :revoke = soft-revoke (POST …:revoke → Operation) → Get ВСЁ ЕЩЁ возвращает row "
          "со status=='REVOKED' (terminal), revokedAt° set (audit-retention — в отличие от Delete)",
    classes=["CRUD", "CONF"],
    priority="P0",
    steps=[
        *_seed_role("rv", "rdRoleRv"),
        *_create_binding("cr-for-revoke", _acb_body("rdRoleRv", {"allInScope": {}}), "rdAcbRv"),
        retry_until_authorized(Step(
            name="revoke-soft",
            method="POST",
            path="/iam/v1/accessBindings/{{rdAcbRv}}:revoke",
            body={},
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200), *assert_iam_op(), *save_from_response("j.id", "opId")],
        )),
        poll_operation_until_done(),
        assert_op_success(),
        # Row RETAINED with status REVOKED + revokedAt set (Get still returns it, unlike hard-delete).
        retry_until_authorized(Step(
            name="get-revoked-row",
            method="GET",
            path="/iam/v1/accessBindings/{{rdAcbRv}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('status == REVOKED (terminal)', () => pm.expect(pm.response.json().status, JSON.stringify(pm.response.json())).to.eql('REVOKED'));",
                "pm.test('revokedAt° set (audit-retention)', () => pm.expect(pm.response.json().revokedAt, JSON.stringify(pm.response.json())).to.be.a('string').and.not.empty);",
            ],
        )),
        *_cleanup_binding("rdAcbRv"),
        *_cleanup_role("rdRoleRv"),
    ],
))


CASES.append(Case(
    id="IAM-ACB-RD-REGRANT-AFTER-REVOKE-OK",
    title="IAM-1-29: после :revoke идентичный Create → новая ACTIVE-строка (новый acb-id; REVOKED слот "
          "не занимает — partial UNIQUE WHERE revoked_at IS NULL); тот же Create при уже-ACTIVE → "
          "Operation.error ALREADY_EXISTS (идемпотентность grant)",
    classes=["IDM", "EDGE"],
    priority="P1",
    steps=[
        *_seed_role("rg", "rdRoleRg"),
        *_create_binding("rg-cr1", _acb_body("rdRoleRg", {"allInScope": {}}), "rdAcbRg1"),
        # revoke the first grant → frees the active-grant UNIQUE slot.
        retry_until_authorized(Step(
            name="rg-revoke",
            method="POST",
            path="/iam/v1/accessBindings/{{rdAcbRg1}}:revoke",
            body={},
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200), *save_from_response("j.id", "opId")],
        )),
        poll_operation_until_done(),
        assert_op_success(),
        # re-grant identical (subject,role,scope,target) → NEW ACTIVE row, new id.
        *_create_binding("rg-cr2", _acb_body("rdRoleRg", {"allInScope": {}}), "rdAcbRg2"),
        Step(
            name="rg-assert-new-id",
            method="GET",
            path="/iam/v1/accessBindings/{{rdAcbRg2}}",
            auth="jwtAccountAdminA",
            pre_script=[
                "// self-retry over read-your-writes (owner-tuple) window; assert distinct id.",
                "if (pm.environment.get('_rgStarted') !== pm.info.requestName) { pm.environment.set('_rgCount','0'); pm.environment.set('_rgStarted', pm.info.requestName); }",
            ],
            test_script=[
                "const _rc = parseInt(pm.environment.get('_rgCount')||'0',10);",
                f"if ([403,404].includes(pm.response.code) && _rc < 15) {{ pm.environment.set('_rgCount', String(_rc+1)); const _d=Date.now(); while(Date.now()-_d<400){{}} pm.execution.setNextRequest(pm.info.requestName); return; }}",
                "pm.environment.unset('_rgCount'); pm.environment.unset('_rgStarted');",
                *assert_status(200),
                "pm.test('re-grant is a NEW ACTIVE row (distinct id, ACTIVE)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id).to.not.eql(pm.environment.get('rdAcbRg1'));",
                "  pm.expect(j.status).to.eql('ACTIVE');",
                "});",
            ],
        ),
        # identical Create while an ACTIVE row exists → op.error ALREADY_EXISTS.
        Step(
            name="rg-cr-dup-active",
            method="POST",
            path="/iam/v1/accessBindings",
            body=_acb_body("rdRoleRg", {"allInScope": {}}),
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200), *save_from_response("j.id", "opId")],
        ),
        assert_op_error(6, "ALREADY_EXISTS", msg_substr="already granted"),
        *_cleanup_binding("rdAcbRg2"),
        *_cleanup_role("rdRoleRg"),
    ],
))


# ===========================================================================
# F11 — List format-validate BEFORE authz + whitelist-filter (IAM-1-32)
# ===========================================================================

CASES.append(Case(
    id="IAM-ACB-RD-LS-PAGETOKEN-GARBAGE-NEG",
    title="IAM-1-32: List ?pageToken=<garbage> → 400 INVALID_ARGUMENT (format-validate ДО listauthz "
          "empty-grant short-circuit — единый порядок format-validate → authz → repo)",
    classes=["NEG", "PAGE"],
    priority="P1",
    steps=[
        Step(
            name="ls-garbage-token",
            method="GET",
            path="/iam/v1/accessBindings?pageToken=%25%25%25not-base64%25%25%25",
            auth="jwtAccountAdminA",
            test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT")],
        ),
    ],
))


CASES.append(Case(
    id="IAM-ACB-RD-LS-PAGESIZE-OVER-NEG",
    title="IAM-1-32: List ?pageSize=2000 (>1000) → 400 INVALID_ARGUMENT 'page_size must be in [0..1000]' "
          "(отвергается, НЕ clamp'ится)",
    classes=["NEG", "BVA", "PAGE"],
    priority="P1",
    steps=[
        Step(
            name="ls-pagesize-over",
            method="GET",
            path="/iam/v1/accessBindings?pageSize=2000",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('page_size range text', () => pm.expect((pm.response.json().message||'').toLowerCase(), JSON.stringify(pm.response.json())).to.include('page_size must be in [0..1000]'));",
            ],
        ),
    ],
))


CASES.append(Case(
    id="IAM-ACB-RD-LS-FILTER-UNKNOWN-KEY-NEG",
    title="IAM-1-32: List ?filter=bogus=\"x\" (ключ вне whitelist subject/role/scope/scopeId) → 400 "
          "INVALID_ARGUMENT (closed whitelist)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="ls-filter-unknown-key",
            method="GET",
            path="/iam/v1/accessBindings?filter=bogus%3D%22x%22",
            auth="jwtAccountAdminA",
            test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT")],
        ),
    ],
))


CASES.append(Case(
    id="IAM-ACB-RD-LS-FILTER-WHITELIST-OK",
    title="IAM-1-32: List whitelist-filter — ?filter=scopeId=\"accountA\" (retry-until-present) содержит "
          "свой свежий binding; ?filter=scope=\"iam.account\" → 200 (whitelist принимается)",
    classes=["CRUD", "CONF"],
    priority="P1",
    steps=[
        *_seed_role("lf", "rdRoleLf"),
        *_create_binding("cr-for-list", _acb_body("rdRoleLf", {"allInScope": {}}), "rdAcbLf"),
        poll_request_until_status(
            name="ls-filter-scopeid",
            method="GET",
            path="/iam/v1/accessBindings?filter=scopeId%3D%22{{accountAId}}%22&pageSize=1000",
            auth="jwtAccountAdminA",
            retry_predicate="(() => { const j = pm.response.json(); const id = pm.environment.get('rdAcbLf'); "
                            "return id && !((j.accessBindings)||[]).some(b => b.id === id); })()",
            test_script=[
                *assert_status(200),
                "pm.test('filter scopeId returns own fresh binding', () => {",
                "  const j = pm.response.json();",
                "  const id = pm.environment.get('rdAcbLf');",
                "  pm.expect(((j.accessBindings)||[]).some(b => b.id === id), JSON.stringify(j)).to.eql(true);",
                "});",
                "pm.test('all returned bindings match the scopeId filter', () => {",
                "  const j = pm.response.json();",
                "  const acc = pm.environment.get('accountAId');",
                "  for (const b of (j.accessBindings)||[]) pm.expect(b.scopeId).to.eql(acc);",
                "});",
            ],
        ),
        Step(
            name="ls-filter-scope-dotted",
            method="GET",
            path="/iam/v1/accessBindings?filter=scope%3D%22iam.account%22&pageSize=100",
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200)],
        ),
        *_cleanup_binding("rdAcbLf"),
        *_cleanup_role("rdRoleLf"),
    ],
))
