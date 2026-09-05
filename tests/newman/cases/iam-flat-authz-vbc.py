# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set for the flat verb-bearing authz model (iam) — black-box
через api-gateway.

Covered scenarios (iam-native subset):

  AccessBinding.Create with NO subject type (SUBJECT_TYPE_UNSPECIFIED).
    subjectsFromProto derives the subject type from the id PREFIX (usr→user,
    sva→service_account, grp→group). Happy: usr-prefixed id → Operation(iop).
    Negative: an unrecognized prefix with no type → sync 400 INVALID_ARGUMENT
    (validation NOT weakened).

    This case used to send `"type":"user"` and lean on the edge dropping the
    lowercase name to the zero enum, on the stated grounds that "the UI sends this
    shape". Both halves stopped being true: the console maps its internal lowercase
    type through SUBJECT_TYPE_ENUM to the wire name (`SUBJECT_TYPE_USER`), and the
    edge now REFUSES an enum value outside the dictionary instead of swallowing it.
    Sending garbage also made the case assert the wrong thing — the swallow rather
    than the derive; it would have stayed green with the derive deleted.

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
    """RELIABLE revoke — общий помощник gen.py.

    Прежняя редакция принимала 403 («отказано в правах») как успешную уборку и
    ехала дальше. Отзыв при этом НЕ происходил: грант оставался ACTIVE в ОБЩЕМ
    аккаунте после конца прогона, и следующий прогон видел субъекта, у которого
    «нет ни одной выдачи», но которому тем не менее разрешено. Реализация была
    исправлена в соседнем файле (iam-rbac-subjects), а здесь класс остался жив —
    ровно потому, что помощник скопирован, а не общий. Теперь он один.
    """
    return reliable_delete(name, "/iam/v1/accessBindings/{{" + acb_var + "}}")


# ---------------------------------------------------------------------------
# IAM-VBC-ACB-UNSPECIFIED-SUBJECT-DERIVE — happy: no type → derive from id prefix
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-VBC-ACB-UNSPECIFIED-SUBJECT-DERIVE",
    title="AccessBinding.Create with no subject type + usr-prefixed id → derive → Operation(iop) done",
    classes=["VAL", "CRUD"],
    priority="P1",
    steps=[
        # Pre-clean any prior active (userNOBId, ROLE_VIEW, account/accountAId) binding so
        # strict-create always materializes a fresh one (DB persists across runs).
        Step(
            name="pre-clean-revoke",
            method="GET",
            path="/iam/v1/accessBindings:listByScope?resourceType=account&resourceId={{accountAId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[
                # РАЗВЕДКА ИДЁТ АВТОРИЗОВАННЫМ ЧТЕНИЕМ, И ИСХОД У НЕГО ОДИН — 200.
                #
                # Прежде здесь стоял `:listBySubject` для ЧУЖОГО субъекта. Это не
                # «известный продуктовый предел», как утверждал прежний текст, и не
                # kacho-iam#276 (тот про другое — про материализацию дочерних туплов у
                # не-владельца с глобальной ролью просмотра). Это был ОБЪЯВЛЕННЫЙ контракт
                # метода: строгий список только про себя, административного обхода нет.
                # Значит для админа исход был ровно один — отказ, — предочистка не
                # выполнялась НИКОГДА, а утверждение `oneOf([200, 403])` это скрывало,
                # принимая и недостижимый успех.
                #
                # Контракт с тех пор изменён (#1352): чтение допускает и распорядителя
                # домашнего аккаунта субъекта, сужая ответ границами этого аккаунта.
                # Замена ниже от этого не устарела — предочистке нужны ВСЕ субъекты
                # области, а на этот вопрос отвечает перечисление по области.
                #
                # Рабочая замена уже была в дереве, в соседнем наборе: перечисление по
                # ОБЛАСТИ аккаунта (владелец аккаунта видит выдачи ВСЕХ субъектов), а
                # нужный субъект выбирается фильтром. Его шапка прямо говорит, что
                # `listBySubject` «корректно отдаёт 403 и давал ЛОЖНУЮ чистоту слота».
                # Здесь та же замена — и предочистка наконец работает.
                *assert_status(200),
                "pm.environment.unset('vbcDupAcbId');",
                "const arr = (pm.response.json() || {}).accessBindings || [];",
                f"const dup = arr.find(b => b.subjectId === pm.environment.get('userNOBId')",
                f"       && b.roleId === '{ROLE_VIEW}' && b.scopeType === 'iam.account'",
                "       && b.scopeId === pm.environment.get('accountAId'));",
                "if (dup && dup.id) pm.environment.set('vbcDupAcbId', dup.id);",
                "if (!pm.environment.get('vbcDupAcbId')) { pm.execution.setNextRequest('create-derive'); }",
            ],
        ),
        poll_request_until_status(
            retry_on=(403,),
            
            name="del-dup",
            method="DELETE",
            path="/iam/v1/accessBindings/{{vbcDupAcbId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('pre-clean: слот освобождён (200) или его и не было (404) — устойчивый 403 значит, что прежняя выдача ОСТАЛАСЬ активной и strict-create упрётся в UNIQUE', () => pm.expect(pm.response.code, JSON.stringify(pm.response.json() || {})).to.be.oneOf([200, 404]));",
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
                "  const _ipd1 = Date.now(); while (Date.now() - _ipd1 < 500) void 0; /* real inter-poll delay: cap 30 x 500ms ~= 15s budget (testing.md) */",
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
            # `type` OMITTED — that is what SUBJECT_TYPE_UNSPECIFIED looks like on
            # the wire, and it is the actual precondition of the derive:
            # subjectsFromProto reads `user` off the `usr` id-prefix.
            #
            # It used to say `"type":"user"` and lean on the edge dropping the
            # lowercase name to the zero enum. That prop is gone: an enum value
            # outside the dictionary is now refused (INVALID_ARGUMENT), because
            # accepting it meant answering 200 for a setting the server never made.
            # Leaning on it also made this case test the WRONG thing — it asserted
            # the edge's swallow, not the service's derive, and it would have stayed
            # green if the derive were deleted.
            body={
                "subjects": [{"id": "{{userNOBId}}"}],
                "roleId": ROLE_VIEW,
                "scopeType": "iam.account",
                "scopeId": "{{accountAId}}",
                "target": {"allInScope": {}},
            },
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "pm.test('subject type derived from id prefix (200)', () => pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200));",
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
                # the create either succeeded (no error) OR — when a CONCURRENT suite
                # granted the same 5-tuple between this pre-clean and this create — returned
                # ALREADY_EXISTS
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
        *_revoke_teardown("teardown-vbc16", "vbcAcbId"),
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
                "scopeType": "iam.account",
                "scopeId": "{{accountAId}}",
                "target": {"allInScope": {}},
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
