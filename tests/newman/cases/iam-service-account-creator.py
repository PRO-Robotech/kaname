# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""SAC-E1…E5 (kaname#1003), own public REST, S2 approved acceptance.

Source: docs/engineering/acceptance/service-account-creation-is-its-own-right.md.
Techniques: decision table, positive controls, one-fact scope/target twins.
Ordered world: E1 grants; E2 lifecycle; E3 admin controls; E4/E5 denies.
Seed: saCreatorId/jwtSaCreator (client_credentials, separate account, no grant),
accountAId/accountBId, jwtAccountAdminA, svaAId. Scenario cleanup is in this
collection; namespace teardown covers interrupted runs and seed resources.
Live response probe and RED/GREEN evidence require an assigned own stand.
"""
HOME = "kaname"
CASES = []
CREATOR = "jwtSaCreator"
ADMIN = "jwtAccountAdminA"
KEY_BODY = {"credentialKind": "CREDENTIAL_KIND_SECRET", "ttlSeconds": 3600}


def mutation(name, method, path, body=None, auth=ADMIN, capture=None, first=False):
    """Захват ресурса только после успешного исхода операции."""
    request = Step(name=name, method=method, path=path, body=body, auth=auth,
                   test_script=[*assert_status(200),
                                "pm.test('operation id', () => pm.expect(pm.response.json().id).to.match(/^iop[a-z0-9-]+$/));",
                                *save_from_response("j.id", "opId")])
    if first:
        request = retry_until_authorized(request)
    result = assert_op_success(auth=auth)
    result.name = name + "-done"
    result.test_script.extend(assert_status(200))
    if capture:
        field, var = capture
        result.test_script.extend([
            "pm.test('completed operation names resource', () => {",
            f"  const value = pm.response.json().response.{field};",
            "  pm.expect(value).to.be.a('string').and.not.empty;",
            "});",
            *save_from_response(f"!j.error && j.done && j.response && j.response.{field}", var),
        ])
    return [request, result]


def denied(name, path, body):
    return Step(name=name, method="POST", path=path, body=body, auth=CREATOR,
                test_script=[*assert_status(403), *assert_grpc_code(7, "PERMISSION_DENIED"),
                             *assert_refusal_message("permission denied")])


CASES.append(Case(
    id="IAM-SAC-GR-AUTHZ-E1", title="SAC-E1: admin grants creator role through REST",
    classes=["AUTHZ"], priority="P0", steps=[
        Step(name="discover-creator-role", method="GET", path="/iam/v1/roles?pageSize=1000", auth=ADMIN,
             test_script=[*assert_status(200),
                          "const roles = (pm.response.json().roles || []).filter(r => r.name === 'iam.service_account.creator' && !r.accountId);",
                          "pm.test('one built-in creator role', () => pm.expect(roles.length).to.eql(1));",
                          "pm.environment.unset('sacRoleId');",
                          "if (roles.length === 1) pm.environment.set('sacRoleId', roles[0].id);"]),
        *mutation("grant-creator", "POST", "/iam/v1/accessBindings", {
            "subjectType": "service_account", "subjectId": "{{saCreatorId}}",
            "roleId": "{{sacRoleId}}", "scopeType": "iam.account", "scopeId": "{{accountAId}}",
            "target": {"allInScope": {}}}, capture=("id", "sacBindingId")),
    ]))
CASES.append(Case(
    id="IAM-SAC-CR-CRUD-E2", title="SAC-E2: creator creates SA, issues/revokes key, deletes own SA",
    classes=["CRUD", "AUTHZ"], priority="P0", steps=[
        *mutation("create-own-sa", "POST", "/iam/v1/serviceAccounts",
                  {"accountId": "{{accountAId}}", "name": "cr-{{runId}}"}, CREATOR,
                  ("id", "sacOwnId"), first=True),
        *mutation("issue-own-key", "POST", "/iam/v1/serviceAccounts/{{sacOwnId}}/keys",
                  KEY_BODY, CREATOR, ("keyId", "sacKeyId"), first=True),
        *mutation("revoke-own-key", "DELETE", "/iam/v1/serviceAccounts/{{sacOwnId}}/keys/{{sacKeyId}}", auth=CREATOR),
        *mutation("delete-own-sa", "DELETE", "/iam/v1/serviceAccounts/{{sacOwnId}}", auth=CREATOR),
    ]))
_controls = []
for resource, prefix, var, extra in (
    ("projects", "p", "sacProjectId", {}),
    ("groups", "g", "sacGroupId", {}),
    ("roles", "r", "sacCustomRoleId", {"rules": [{"module": "iam", "resources": ["project"], "verbs": ["get"]}]}),
):
    body = {"accountId": "{{accountAId}}",
            "name": prefix + ("" if resource == "roles" else "-") + "{{runId}}", **extra}
    path = "/iam/v1/" + resource
    _controls.extend([
        denied("creator-denied-" + resource, path, body),
        *mutation("admin-create-" + resource, "POST", path, body, capture=("id", var)),
        *mutation("admin-cleanup-" + resource, "DELETE", path + "/{{" + var + "}}"),
    ])
CASES.append(Case(
    id="IAM-SAC-CR-AUTHZ-E3", title="SAC-E3: project/group/role denied; same request by admin succeeds",
    classes=["AUTHZ", "NEG"], priority="P0", steps=_controls))
CASES.append(Case(
    id="IAM-SAC-KEY-AUTHZ-E4", title="SAC-E4: foreign SA key denied (positive twin E2)",
    classes=["AUTHZ", "NEG"], priority="P0", steps=[
        denied("foreign-sa-key-denied", "/iam/v1/serviceAccounts/{{svaAId}}/keys", KEY_BODY),
    ]))
CASES.append(Case(
    id="IAM-SAC-CR-AUTHZ-E5", title="SAC-E5: foreign account create denied (positive twin E2)",
    classes=["AUTHZ", "NEG"], priority="P0", steps=[
        denied("foreign-account-denied", "/iam/v1/serviceAccounts",
               {"accountId": "{{accountBId}}", "name": "cr-{{runId}}"}),
        *mutation("cleanup-creator-binding", "DELETE", "/iam/v1/accessBindings/{{sacBindingId}}"),
    ]))
CASES = address_own_front(CASES, "SAC-E1…E5 assert the service's own public REST front")
