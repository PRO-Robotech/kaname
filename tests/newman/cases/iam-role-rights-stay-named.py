# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ESC-E1…E4, accepted r4 3131d7ddfffa9b66857b94c70138b6ebfe7bdb77c7ca07f5333db88aefaae690.

HTTP black box of the service's own REST front. Techniques: paired controls,
state transition, negative authorization and byte-exact refusal privacy.
H is a separate ceremony person, with level 1 and level 2 credentials. Each
case first proves ListBySubject(H) empty; fixtures never replace human auth.
The delegation seed owns gdRegistryId/gdRegistryProjectId. Mutations are polled
and their errors checked before a resource is used. No deployed verdict is
inferred from collection generation.
"""
HOME = "kaname"
CASES = []
OWNER = "jwtAccountAdminAStepUp"
HUMAN = "jwtHumanEscStepUp"


def var(key):
    return "{{" + key + "}}"


def done():
    return [poll_operation_until_done(), assert_op_success()]


def mutation(name, path, body, auth=OWNER, capture=None, method="POST"):
    tests = [*assert_status(200), *save_from_response("j.id", "opId")]
    request = Step(name=name, method=method, path=path, body=body, auth=auth,
                   test_script=tests)
    if name in ("description-control", "empty-group-control", "wildcard-holder-grants"):
        request = retry_until_authorized(request)
    steps = [request, *done()]
    if capture:
        # Capture only after successful completion, from the completed operation.
        steps[-1].test_script.extend(save_from_response(
            "j.response && j.response.id", capture))
    return steps


def role(key, module, resource, verbs):
    return mutation("create-" + key, "/iam/v1/roles", {
        "name": key.lower() + "-{{runId}}",
        "definitionTier": {"tierType": "iam.account", "tierId": var("accountAId")},
        "rules": [{"module": module, "resources": [resource], "verbs": verbs}]}, capture=key)


def grant(key, role_id, subject="humanEscUserId", kind="USER", account=False):
    return mutation("grant-" + key, "/iam/v1/accessBindings", {
        "subjects": [{"type": "SUBJECT_TYPE_" + kind, "id": var(subject)}],
        "roleId": var(role_id), "scopeType": "iam.account" if account else "iam.project",
        "scopeId": var("accountAId" if account else "gdRegistryProjectId"),
        "target": {"allInScope": {}}}, capture=key)


def remove(path, key):
    return mutation("delete-" + key, path + "/" + var(key), None, method="DELETE")


def empty():
    return [Step(name="H-has-no-bindings", method="GET",
        path="/iam/v1/accessBindings:listBySubject?subjectType=user&subjectId={{humanEscUserId}}&pageSize=1000",
        auth=HUMAN, pre_script=[
            "['jwtHumanEsc', 'jwtHumanEscStepUp', 'humanEscUserId', 'gdRegistryId', 'gdRegistryProjectId'].forEach(k => {",
            "  pm.test('seed present: ' + k, () => pm.expect(pm.environment.get(k)).to.be.a('string').and.not.empty);",
            "});",
            "['role', 'group'].forEach(r => pm.environment.set('esc' + r.charAt(0).toUpperCase() + r.slice(1) + 'Edit', 'rol' + CryptoJS.MD5('iam.' + r + '.edit').toString().substring(0, 17)));"], test_script=[*assert_status(200),
            "pm.test('H has no bindings: fixture precondition', () => {",
            "  const j = pm.response.json(); pm.expect(j.accessBindings || []).to.eql([]);",
            "  pm.expect(j.nextPageToken || '').to.eql('');",
            "});"])]


def sa(key, account="A"):
    return mutation("create-" + key, "/iam/v1/serviceAccounts", {
        "name": key.lower() + "-{{runId}}", "accountId": var("account" + account + "Id")},
        auth="jwtAccountAdmin" + account, capture=key)


def denied(saved=None, same=None):
    lines = [*assert_status(403), *assert_grpc_code(7, "PERMISSION_DENIED")]
    if saved:
        lines.append("pm.environment.set(" + js_str(saved) + ", pm.response.text());")
    if same:
        lines.append("pm.test('refusal bytes equal same-method door refusal', () => pm.expect(pm.response.text()).to.eql(pm.environment.get(" + js_str(same) + ")));")
    return lines


def check(action, allowed, name, module="registry", resource_type="registry_registry", resource_var="gdRegistryId", resource="registries"):
    step = Step(name=name, method="POST", path="/iam/v1/authorize:check",
        auth="jwtHumanEsc", body={"subject": "user:{{humanEscUserId}}",
            "resource": {"type": resource_type, "id": var(resource_var)},
            "action": module + "." + resource + "." + action},
        test_script=[*assert_status(200),
            "pm.test('exact authorization decision', () => pm.expect(pm.response.json().allowed).to.eql(" + str(allowed).lower() + "));"])
    if allowed:
        step.test_script = [
            "const decision = pm.response.code === 200 && pm.response.json().allowed === true;",
            "const key = 'escDecision:' + pm.info.requestName;",
            "const tries = Number(pm.environment.get(key) || 0);",
            "if (!decision && tries < 30) {",
            "  pm.environment.set(key, String(tries + 1));",
            "  setTimeout(() => {}, 400); pm.execution.setNextRequest(pm.info.requestName); return;",
            "}",
            "pm.environment.unset(key);",
            *step.test_script]
    return step


def case(number, title, steps):
    CASES.append(Case(id="IAM-ESC-E" + str(number), title="ESC-E" + str(number) + ": " + title,
                     classes=["SEC", "NEG"], priority="P0", steps=steps))


# E1: one changed fact: delete -> wildcard on the same project and same human.
ve = {"subjects": [{"type": "SUBJECT_TYPE_SERVICE_ACCOUNT", "id": var("escSa")}],
      "roleId": var("escGrantRole"), "scopeType": "iam.project",
      "scopeId": var("gdRegistryProjectId"), "target": {"allInScope": {}}}
case(1, "delete cannot grant; wildcard twin can", [
    *empty(), *sa("escSa"), *role("escGrantRole", "registry", "registries", ["get"]),
    *role("escDelete", "iam", "project", ["delete"]), *grant("escHold", "escDelete"),
    check("delete", True, "delete-binding-is-visible", "iam", "iam_project", "gdRegistryProjectId", "project"),
    Step(name="delete-holder-cannot-grant", method="POST", path="/iam/v1/accessBindings",
         body=ve, auth=HUMAN, test_script=denied()),
    *remove("/iam/v1/accessBindings", "escHold"),
    *role("escWildcard", "iam", "project", ["*"]), *grant("escTwinHold", "escWildcard"),
    *mutation("wildcard-holder-grants", "/iam/v1/accessBindings", ve, HUMAN, "escGranted"),
    *remove("/iam/v1/accessBindings", "escGranted"), *remove("/iam/v1/accessBindings", "escTwinHold"),
    *remove("/iam/v1/roles", "escWildcard"), *remove("/iam/v1/roles", "escDelete"),
    *remove("/iam/v1/roles", "escGrantRole"), *remove("/iam/v1/serviceAccounts", "escSa")])

case(2, "delete-only and update/delete twin", [
    *empty(), *role("escDelete", "registry", "registries", ["delete"]), *grant("escHold", "escDelete"),
    check("delete", True, "delete-binding-is-visible"),
    check("update", False, "delete-does-not-update"), check("delete", True, "delete-is-allowed"),
    *remove("/iam/v1/accessBindings", "escHold"),
    *role("escBoth", "registry", "registries", ["update", "delete"]), *grant("escTwinHold", "escBoth"),
    check("update", True, "twin-can-update"),
    *remove("/iam/v1/accessBindings", "escTwinHold"),
    *remove("/iam/v1/roles", "escBoth"), *remove("/iam/v1/roles", "escDelete")])

ur = {"updateMask": "rules", "rules": [{"module": "registry", "resources": ["registries"], "verbs": ["*"]}]}
case(3, "role editing has no grant authority; refusal privacy", [
    *empty(), *role("escRole", "registry", "registries", ["get"]), *grant("escHold", "escRole"),
    Step(name="door-refusal", method="PATCH", path="/iam/v1/roles/{{escRole}}", body=ur,
         auth=HUMAN, test_script=denied(saved="escT0")),
    *grant("escEditHold", "escRoleEdit", account=True),
    *mutation("description-control", "/iam/v1/roles/{{escRole}}",
              {"updateMask": "description", "description": "ESC-E3 control"}, HUMAN, method="PATCH"),
    Step(name="rules-refusal", method="PATCH", path="/iam/v1/roles/{{escRole}}", body=ur,
         auth=HUMAN, test_script=denied(same="escT0")),
    *mutation("admin-rules-twin", "/iam/v1/roles/{{escRole}}", ur, method="PATCH"),
    *remove("/iam/v1/accessBindings", "escEditHold"), *remove("/iam/v1/accessBindings", "escHold"),
    *remove("/iam/v1/roles", "escRole")])


def group(key):
    return mutation("create-" + key, "/iam/v1/groups", {
        "accountId": var("accountAId"), "name": key.lower() + "-{{runId}}"}, capture=key)


def am(group_id, member_id):
    return "/iam/v1/groups/" + var(group_id) + ":addMember", {
        "memberType": "service_account", "memberId": var(member_id)}


am_path, am_body = am("escGroup", "escSa")
control_path, control_body = am("escEmptyGroup", "escSa")
missing_message = "referenced resource does not exist; create it or correct the reference before retrying"
foreign_steps = []
for label, member in [("foreign", var("escSb")), ("missing", "sva0000000000000ghst")]:
    foreign_steps.extend([
        Step(name=label + "-member", method="POST", path=am_path,
             body={"memberType": "service_account", "memberId": member}, auth=OWNER,
             test_script=[*assert_status(200), *save_from_response("j.id", "opId")]),
        poll_operation_until_done(),
        assert_op_error(9, "FAILED_PRECONDITION"),
        Step(name=label + "-exact-error", method="GET", path="/operations/{{opId}}", auth=OWNER,
             test_script=[*assert_status(200),
                "pm.test('done with exact missing-reference refusal', () => {",
                "  const j = pm.response.json(); pm.expect(j.done).to.eql(true);",
                "  pm.expect(j.error.code).to.eql(9);",
                "  pm.expect(j.error.message).to.eql(" + js_str(missing_message) + ");",
                "});",
                "pm.environment.set('escMissingForm', JSON.stringify(pm.response.json().error));"
                if label == "foreign" else
                "pm.test('foreign and absent members have identical error form', () => pm.expect(JSON.stringify(pm.response.json().error)).to.eql(pm.environment.get('escMissingForm')));"])
    ])

case(4, "group grant authority and foreign-member privacy", [
    *empty(), *group("escGroup"), *group("escEmptyGroup"), *sa("escSa"), *sa("escSb", "B"),
    *role("escRole", "registry", "registries", ["get"]),
    *grant("escHold", "escRole", "escGroup", "GROUP"),
    Step(name="door-refusal", method="POST", path=am_path, body=am_body,
         auth=HUMAN, test_script=denied(saved="escT1")),
    *grant("escEditHold", "escGroupEdit", account=True),
    *mutation("empty-group-control", control_path, control_body, HUMAN),
    Step(name="grant-authority-refusal", method="POST", path=am_path, body=am_body,
         auth=HUMAN, test_script=denied(same="escT1")),
    *mutation("admin-group-twin", am_path, am_body), *foreign_steps,
    *remove("/iam/v1/accessBindings", "escEditHold"), *remove("/iam/v1/accessBindings", "escHold"),
    *remove("/iam/v1/groups", "escGroup"), *remove("/iam/v1/groups", "escEmptyGroup"),
    *remove("/iam/v1/roles", "escRole"), *remove("/iam/v1/serviceAccounts", "escSa"),
    *mutation("delete-escSb", "/iam/v1/serviceAccounts/{{escSb}}", None,
              "jwtAccountAdminB", method="DELETE")])

CASES = address_own_front(CASES, "S2 r4: own public REST front of kaname")
