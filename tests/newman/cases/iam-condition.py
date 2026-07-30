# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set for ConditionsService — the reusable project-scoped Condition resource.

Covered RPCs:
  ConditionsService.Create (POST   /iam/v1/conditions)
  ConditionsService.Get    (GET    /iam/v1/conditions/{condition_id})
  ConditionsService.List   (GET    /iam/v1/conditions?projectId=…)
  ConditionsService.Delete (DELETE /iam/v1/conditions/{condition_id})

CRUD fixture dependency:
  jwtAccountAdminA — owner of accountAId, so admin (⊇ editor) on projectA1Id
  jwtNoBindings    — authenticated, no membership anywhere
  projectA1Id      — the project the conditions are created in

Why this suite exists
  The Condition resource was the one public resource the seven-domain redesign
  never reached. It named its scope `folderId` — a pre-redesign word for a
  Project that no other resource in any service still uses — while the platform
  convention, and every client written against it, sends `projectId`. The REST
  bridge silently drops an unknown JSON key, so a conventional request left the
  required scope empty and the gateway refused it. Underneath that, the service
  was never mounted on the external mux at all and its id prefix was missing
  from the platform id catalog, so the surface answered 404 and 400 no matter
  which spelling was used.

  These cases assert the resource is reachable BY THE CONVENTION: `projectId` in
  the request, `projectId` in the response, the created row readable and
  listable, and the whole thing scoped — a caller with no bindings sees none of
  it.

Acceptance scenarios:
  Happy:    Create with projectId → Operation → done+success → Get → 200 with
            projectId echoed; List by projectId contains it; Delete → gone.
  Negative: Create WITHOUT a project anchor → rejected (authz-first 403 or 400).
  Negative: a caller with no bindings cannot read the condition, and its List is
            empty.

verifies: Condition Create/Get/List/Delete over the conventional `projectId`
scope field; project-scoped authz on all four.
"""

CASES = []


# ---------------------------------------------------------------------------
# IAM-CND-CR-CRUD-OK — full lifecycle over the conventional scope field.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-CND-CR-CRUD-OK",
    title="POST /iam/v1/conditions with projectId → Operation → Get/List → Delete → gone",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="create-condition",
            method="POST",
            path="/iam/v1/conditions",
            auth="jwtAccountAdminA",
            body={
                "projectId": "{{projectA1Id}}",
                "name": "cnd-{{runId}}",
                "description": "conventional scope field",
                "expression": "non_expired",
            },
            test_script=[
                *assert_status(200),
                *assert_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata.conditionId", "cndId"),
                "pm.test('Operation metadata carries the condition id', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.metadata.conditionId, JSON.stringify(j)).to.match(/^cnd[a-z0-9]+$/);",
                "});",
            ],
        ),
        poll_operation_until_done(),
        assert_op_success(),
        retry_until_authorized(Step(
            name="get-condition",
            method="GET",
            path="/iam/v1/conditions/{{cndId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('the scope field is projectId and it echoes the request', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.projectId, JSON.stringify(j)).to.eql(pm.environment.get('projectA1Id'));",
                "});",
                "pm.test('no pre-redesign folderId is served', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(Object.keys(j), JSON.stringify(j)).to.not.include('folderId');",
                "});",
                "pm.test('id / name / status returned', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id).to.eql(pm.environment.get('cndId'));",
                "  pm.expect(j.name).to.eql('cnd-' + pm.environment.get('runId'));",
                "  pm.expect(j.status, JSON.stringify(j)).to.eql('ACTIVE');",
                "});",
                *assert_created_at_seconds(),
            ],
        )),
        # No retry wrapper: List is a plain project-scoped read of this service's
        # own table — it applies no per-object filter, and the row is already
        # committed (the Operation was asserted done+success above).
        Step(
            name="list-conditions",
            method="GET",
            path="/iam/v1/conditions?projectId={{projectA1Id}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('List is scoped by projectId and contains the fresh condition', () => {",
                "  const j = pm.response.json();",
                "  const want = pm.environment.get('cndId');",
                "  pm.expect((j.conditions || []).map(c => c.id), JSON.stringify(j)).to.include(want);",
                "});",
            ],
        ),
        Step(
            name="delete-condition",
            method="DELETE",
            path="/iam/v1/conditions/{{cndId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        assert_op_success(),
        get_until_gone("/iam/v1/conditions/{{cndId}}", "condition", auth="jwtAccountAdminA"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-CND-CR-VAL-UNSCOPED — Create with no project anchor is refused.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-CND-CR-VAL-UNSCOPED",
    title="POST /iam/v1/conditions without projectId → rejected (authz-first 403 or 400)",
    classes=["VAL", "NEG"],
    priority="P0",
    steps=[
        Step(
            name="create-unscoped",
            method="POST",
            path="/iam/v1/conditions",
            auth="jwtAccountAdminA",
            body={
                "name": "cnd-unscoped-{{runId}}",
                "expression": "non_expired",
            },
            test_script=assert_unscoped_rejected("iam.conditions.create"),
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-CND-LS-AUTHZ-NOBINDINGS-DENY — a caller with no bindings sees nothing.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# IAM-CND-UP-CRUD-OK — Update mutates description, refuses the immutable scope,
# and Evaluate answers. These two RPCs were unreachable over REST along with the
# rest of the service, so neither had ever been exercised black-box.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-CND-UP-CRUD-OK",
    title="PATCH /iam/v1/conditions/{id} applies description, rejects project_id in the mask; :evaluate answers",
    classes=["CRUD", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="create-for-update",
            method="POST",
            path="/iam/v1/conditions",
            auth="jwtAccountAdminA",
            body={
                "projectId": "{{projectA1Id}}",
                "name": "cnd-upd-{{runId}}",
                "expression": "non_expired",
            },
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata.conditionId", "cndUpdId"),
            ],
        ),
        poll_operation_until_done(),
        assert_op_success(),
        retry_until_authorized(Step(
            name="update-description",
            method="PATCH",
            path="/iam/v1/conditions/{{cndUpdId}}",
            auth="jwtAccountAdminA",
            body={"updateMask": "description", "description": "patched by newman"},
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "opId"),
            ],
        )),
        poll_operation_until_done(),
        assert_op_success(),
        Step(
            name="get-after-update",
            method="GET",
            path="/iam/v1/conditions/{{cndUpdId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('the description actually changed', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.description, JSON.stringify(j)).to.eql('patched by newman');",
                "});",
                "pm.test('projectId is unchanged by the patch', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.projectId, JSON.stringify(j)).to.eql(pm.environment.get('projectA1Id'));",
                "});",
            ],
        ),
        Step(
            name="update-immutable-scope-rejected",
            method="PATCH",
            path="/iam/v1/conditions/{{cndUpdId}}",
            auth="jwtAccountAdminA",
            body={"updateMask": "project_id", "description": "should not apply"},
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                # Over REST the scope can never travel in the mask: UpdateConditionRequest
                # carries no project_id field, so the FieldMask unmarshaller rejects the
                # path before the use-case's immutability check is reached. The refusal is
                # therefore real but its wording is grpc-gateway's, not the Kacho contract
                # tone ("<field> is immutable after <Resource>.Create") -- the in-service
                # check still owns that wording on the gRPC path, where a client can put
                # arbitrary strings in `paths`. Asserting the tone here would assert a
                # message this surface does not produce.
                "pm.test('the refusal is about the path project_id', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.message, JSON.stringify(j)).to.match(/project_id/);",
                "});",
            ],
        ),
        # The scope really did not move -- the assertion above proves a refusal, this
        # proves the refusal had the intended effect.
        Step(
            name="get-after-immutable-attempt",
            method="GET",
            path="/iam/v1/conditions/{{cndUpdId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('projectId is still the original project', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.projectId, JSON.stringify(j)).to.eql(pm.environment.get('projectA1Id'));",
                "});",
                "pm.test('and the rejected patch did not apply its description either', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.description, JSON.stringify(j)).to.eql('patched by newman');",
                "});",
            ],
        ),
        Step(
            name="evaluate-condition",
            method="POST",
            path="/iam/v1/conditions/{{cndUpdId}}:evaluate",
            auth="jwtAccountAdminA",
            body={"context": {}},
            test_script=[
                *assert_status(200),
                "pm.test('Evaluate answers with a boolean and a trace', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.allowed, JSON.stringify(j)).to.be.a('boolean');",
                "  pm.expect(j.trace, JSON.stringify(j)).to.be.a('string');",
                "});",
                *assert_created_at_seconds("pm.response.json().evaluatedAt"),
            ],
        ),
        Step(
            name="cleanup-update-condition",
            method="DELETE",
            path="/iam/v1/conditions/{{cndUpdId}}",
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200), *save_from_response("j.id", "opId")],
        ),
        poll_operation_until_done(),
        assert_op_success(),
    ],
))


# The case seeds its OWN condition and asserts the owner CAN see it in the same
# run. Without that, "the stranger sees nothing" is trivially true — the happy-path
# case above deletes its condition, so a bare deny-step would pass against an empty
# project and prove nothing about authorization.
CASES.append(Case(
    id="IAM-CND-LS-AUTHZ-NOBINDINGS-DENY",
    title="GET /iam/v1/conditions?projectId=projectA1Id — owner sees its condition, jwtPureNoBindings does not",
    classes=["AUTHZ", "NEG"],
    priority="P0",
    steps=[
        Step(
            name="seed-visible-condition",
            method="POST",
            path="/iam/v1/conditions",
            auth="jwtAccountAdminA",
            body={
                "projectId": "{{projectA1Id}}",
                "name": "cnd-deny-{{runId}}",
                "expression": "non_expired",
            },
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata.conditionId", "cndDenyId"),
            ],
        ),
        poll_operation_until_done(),
        assert_op_success(),
        # Positive control: the row IS listable by someone entitled to it, so the
        # negative below cannot pass merely because the project is empty.
        Step(
            name="list-as-owner-control",
            method="GET",
            path="/iam/v1/conditions?projectId={{projectA1Id}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('control: the seeded condition IS visible to the entitled caller', () => {",
                "  const j = pm.response.json();",
                "  const want = pm.environment.get('cndDenyId');",
                "  pm.expect((j.conditions || []).map(c => c.id), JSON.stringify(j)).to.include(want);",
                "});",
            ],
        ),
        Step(
            name="list-as-nobindings",
            method="GET",
            path="/iam/v1/conditions?projectId={{projectA1Id}}",
            auth="jwtPureNoBindings",
            test_script=[
                # Полоса одна: запись каталога прав для этого перечисления требует
                # `viewer` на объекте проекта из запроса и НЕ объявлена
                # scope-filtered — значит вопрос задаётся краем один раз, до чтения
                # данных, и «пустая страница» на этом пути не рождается. У типа
                # `project` отношение `viewer` подстановочным туплом не выполняется
                # (только editor/admin/super_admin), а у никогда-не-гранченого
                # субъекта нет ни одного из них. Отказ терминальный.
                #
                # Прежнее `oneOf([200, 403])` принимало и отказ, и пустую страницу;
                # утверждение об отсутствии утечки при этом стояло ВНУТРИ ветки 200
                # (`if (code !== 200) return`), поэтому на реально происходящем 403
                # оно не выполнялось вовсе — то есть страж утечки был немым в
                # единственном достижимом исходе.
                *assert_status(403),
                *assert_grpc_code(7, "PERMISSION_DENIED"),
                # Тело отказа обязано быть пустым по существу: ни id условия,
                # которое владелец только что видел, ни его содержимого.
                "pm.test('в теле отказа нет условия, которое видел владелец', () => "
                "  pm.expect(pm.response.text()).to.not.contain(pm.environment.get('cndDenyId')));",
            ],
        ),
        Step(
            name="get-as-nobindings",
            method="GET",
            path="/iam/v1/conditions/{{cndDenyId}}",
            auth="jwtPureNoBindings",
            test_script=[
                "pm.test('direct Get of a foreign condition is refused (403) or hidden (404)', () => {",
                "  pm.expect(pm.response.code, pm.response.text()).to.be.oneOf([403, 404]);",
                "});",
            ],
        ),
        # Cleanup — the suite must be idempotent across runs (UNIQUE(project,name)).
        Step(
            name="cleanup-deny-condition",
            method="DELETE",
            path="/iam/v1/conditions/{{cndDenyId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        assert_op_success(),
    ],
))
