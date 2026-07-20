# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set for the flat verb-bearing authz model (iam) — black-box
через api-gateway.

Covered scenarios (iam-native subset):

  AccessBinding.Create with a LOWERCASE subject type (`"type":"user"`).
    protojson DiscardUnknown drops the lowercase JSON value to the zero enum
    (SUBJECT_TYPE_UNSPECIFIED), so subjectsFromProto derives the subject type from
    the id PREFIX (usr→user, sva→service_account, grp→group). The UI sends this
    shape; before the derive fix it failed validation. Happy: usr-prefixed id →
    Operation(iop). Negative: an unrecognized prefix with no type → sync 400
    INVALID_ARGUMENT (validation NOT weakened).

  Foreign-account iam.user GET → 403 is already covered by
    iam-user.py::IAM-USR-GT-AUTHZ-FOREIGN-DENY (no implicit cross-account access);
    not duplicated here.

CRUD fixture dependency (crud-fixture/setup.sh):
  jwtAccountAdminA — JWT with grant authority on accountAId.
  userNOBId        — a real `usr…`-prefixed User.id used as the derived subject.
  accountAId       — the binding scope (ACCOUNT tier).

System role id: ROLE_VIEW (md5('view')[:17]) — assignable on any scope.

Test-first note (strict TDD):
  These cases are written RED-first against the subject id-prefix derive. They
  fail until subjectsFromProto derives the type from the prefix. Do NOT weaken
  the negative (bad-prefix → 400) — fix the implementation instead.
"""

CASES = []

ROLE_VIEW = "rol1bda80f2be4d3658e"  # md5('view')[:17] — system viewer, any-scope


def assert_iam_operation_envelope():
    """IAM Operation envelope (id prefix `iop`)."""
    return [
        "pm.test('IAM Operation envelope returned', () => {",
        "  const j = pm.response.json();",
        "  pm.expect(j.id, 'operation.id must start with iop').to.match(/^iop[a-z0-9]+$/);",
        "  pm.expect(j.done, 'operation.done present').to.be.a('boolean');",
        "});",
    ]


def _revoke_teardown(name, acb_var):
    """Best-effort revoke so re-runs do not trip strict-create (active-grant
    UNIQUE). Accepts 200/404/403."""
    return Step(
        name=name,
        method="DELETE",
        path="/iam/v1/accessBindings/{{" + acb_var + "}}",
        auth="jwtAccountAdminA",
        test_script=[
            "pm.test('teardown: status acceptable', () => pm.expect(pm.response.code).to.be.oneOf([200, 404, 403]));",
        ],
    )


# ---------------------------------------------------------------------------
# IAM-VBC-ACB-LOWERCASE-SUBJECT-DERIVE — happy: lowercase type → derive from prefix
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-VBC-ACB-LOWERCASE-SUBJECT-DERIVE",
    title="AccessBinding.Create with lowercase subject type (`user`) + usr-prefixed id → derive → Operation(iop) done",
    classes=["VAL", "CRUD"],
    priority="P1",
    steps=[
        # Pre-clean any prior active (userNOBId, ROLE_VIEW, account/accountAId) binding so
        # strict-create always materializes a fresh one (DB persists across runs).
        Step(
            name="pre-clean-revoke",
            method="GET",
            path="/iam/v1/accessBindings:listBySubject?subjectType=user&subjectId={{userNOBId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('pre-clean list acceptable', () => pm.expect(pm.response.code).to.be.oneOf([200, 403]));",
                "pm.environment.unset('vbcDupAcbId');",
                "if (pm.response.code === 200) {",
                "  const arr = (pm.response.json() || {}).accessBindings || [];",
                f"  const dup = arr.find(b => b.roleId === '{ROLE_VIEW}' && b.scopeType === 'iam.account'",
                "       && b.scopeId === pm.environment.get('accountAId'));",
                "  if (dup && dup.id) pm.environment.set('vbcDupAcbId', dup.id);",
                "}",
                "if (!pm.environment.get('vbcDupAcbId')) { pm.execution.setNextRequest('create-derive'); }",
            ],
        ),
        Step(
            name="del-dup",
            method="DELETE",
            path="/iam/v1/accessBindings/{{vbcDupAcbId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('del-dup acceptable', () => pm.expect(pm.response.code).to.be.oneOf([200, 404, 403]));",
                # AccessBinding.Delete is ASYNC (returns Operation). Save its id so the
                # next step AWAITS the revoke (revoked_at set) BEFORE create-derive — else
                # the strict-create races the still-active grant → AlreadyExists (the
                # active-grant partial UNIQUE). Skip the await when delete didn't yield an
                # Operation (404/403).
                "pm.environment.unset('vbcDelOpId');",
                "if (pm.response.code === 200) {",
                "  const dj = pm.response.json() || {};",
                "  if (dj.id) pm.environment.set('vbcDelOpId', dj.id);",
                "}",
                "if (!pm.environment.get('vbcDelOpId')) { pm.execution.setNextRequest('create-derive'); }",
            ],
        ),
        Step(
            name="await-del-dup",
            method="GET",
            path="/operations/{{vbcDelOpId}}",
            auth="jwtAccountAdminA",
            pre_script=[
                "if (pm.environment.get('_vbcDelStarted') !== pm.info.requestName) {",
                "  pm.environment.set('_vbcDelCount', '0');",
                "  pm.environment.set('_vbcDelStarted', pm.info.requestName);",
                "}",
            ],
            test_script=[
                "pm.test('await-del-dup status 200', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                "const pc = parseInt(pm.environment.get('_vbcDelCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_vbcDelCount', String(pc + 1));",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_vbcDelCount');",
                "pm.environment.unset('_vbcDelStarted');",
                "pm.test('dup-revoke operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
            ],
        ),
        Step(
            name="create-derive",
            method="POST",
            path="/iam/v1/accessBindings",
            # Lowercase "user" — protojson DiscardUnknown → SUBJECT_TYPE_UNSPECIFIED;
            # subjectsFromProto derives `user` from the `usr` id-prefix.
            body={
                "subjects": [{"type": "user", "id": "{{userNOBId}}"}],
                "roleId": ROLE_VIEW,
                "scopeRef": {"tier": "ACCOUNT", "id": "{{accountAId}}"},
            },
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "pm.test('lowercase subject derive accepted (200)', () => pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200));",
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accessBindingId", "vbcAcbId"),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="op-success",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                # This asserts the LOWERCASE subject type was DERIVED from the id-prefix
                # (usr→user) and the binding-create proceeded — i.e. the subject resolved
                # to a real `user`, NOT rejected as UNSPECIFIED. The operation is `done`;
                # the create either succeeded (no error) OR — when a concurrent/prior suite
                # left an active view@accountA grant on NOB that the best-effort pre-clean
                # could not revoke (listBySubject 403 for non-self) — returned ALREADY_EXISTS
                # (code 6). BOTH prove the derive worked (a derive FAILURE would be sync 400
                # / INVALID_ARGUMENT code 3, never an Operation). The hard fail is a derive
                # rejection: error code 3.",
                "pm.test('derive-create Operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "pm.test('subject derived (no INVALID_ARGUMENT — lowercase type resolved)', () => {",
                "  const code = j.error && j.error.code;",
                "  pm.expect(code, 'derive must NOT be rejected as INVALID_ARGUMENT: ' + JSON.stringify(j.error)).to.not.eql(3);",
                "});",
            ],
        ),
        _revoke_teardown("teardown-vbc16", "vbcAcbId"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-VBC-ACB-BAD-PREFIX-SUBJECT — negative: unknown prefix + no type → sync 400
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-VBC-ACB-BAD-PREFIX-SUBJECT",
    title="AccessBinding.Create with empty type + unrecognized id prefix (`rol-bad`) → sync 400 INVALID_ARGUMENT (validation not weakened)",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="create-bad-prefix",
            method="POST",
            path="/iam/v1/accessBindings",
            # Empty type + a prefix the derive does not recognize (`rol`) → the type
            # stays "" → the domain validator rejects it SYNC (before any Operation).
            body={
                "subjects": [{"type": "", "id": "rol-not-a-subject"}],
                "roleId": ROLE_VIEW,
                "scopeRef": {"tier": "ACCOUNT", "id": "{{accountAId}}"},
            },
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "pm.test('unrecognized prefix rejected sync 400', () => pm.expect(pm.response.code, JSON.stringify(j)).to.eql(400));",
                "pm.test('error code INVALID_ARGUMENT (3)', () => pm.expect(j.code, JSON.stringify(j)).to.eql(3));",
            ],
        ),
    ],
))
