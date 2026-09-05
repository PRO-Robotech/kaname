# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Unit tests for the two HARNESS invariants that decide whether an
Operation-shaped case checks anything at all.

Both classes below produced GREEN cases that verified nothing, and neither was
visible to the assertion count or to exec-coverage.py (the request ran, the
assertions ran, they passed — against the wrong subject / the wrong object):

1. WHO POLLS THE OPERATION.  `OperationService.Get` is principal-scoped and
   hides a foreign operation as 404.  A poll step that hard-codes a default
   principal instead of the one that MINTED the operation therefore 404s on
   every case whose mutation runs as anybody else (IAM-USR-DL-CRUD-OK: 52
   failing assertions, all one root).  The poll must inherit the auth of the
   step that captured the operation id.

2. WHICH OPERATION IS POLLED.  `opId` is a single shared environment variable.
   A mutation that is REJECTED (4xx) writes no id — so the variable keeps the
   PREVIOUS case's operation, the poll fetches a stale, unrelated, already-done
   operation and `done === true` passes.  The negative silently degrades into a
   no-op (IAM-USR-INV-IDEM-REINVITE, IAM-ROL-DL-NEG-SYSTEM).  The capture must
   clear the variable BEFORE it tries to write it, so a rejected mutation leaves
   it empty and the poll fails loudly instead of passing on a foreign object.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gen  # noqa: E402


def _items(case):
    """Generated collection items of a case, keyed by bare step name."""
    col = gen._RUN.case_item(case)
    return {it["name"].split(" :: ", 1)[1]: it for it in col["item"]}


def _script(item, listen):
    for ev in item.get("event", []) or []:
        if ev.get("listen") == listen:
            return "\n".join(ev["script"]["exec"])
    return ""


# ---------------------------------------------------------------------------
# 1. Operation-poll principal inheritance
# ---------------------------------------------------------------------------

def test_poll_op_inherits_auth_of_the_step_that_minted_the_operation():
    case = gen.Case(
        id="T-INHERIT", title="t", classes=["CRUD"], priority="P0",
        steps=[
            gen.Step(name="delete-user", method="DELETE", path="/iam/v1/users/{{u}}",
                     auth="jwtInvitee",
                     test_script=[*gen.save_from_response("j.id", "opId")]),
            gen.poll_operation_until_done(),
        ],
    )
    poll = _items(case)["poll-op"]
    pre = _script(poll, "prerequest")
    assert "pm.environment.get('jwtInvitee')" in pre, (
        "poll-op must poll as the principal that minted the operation "
        "(OperationService.Get hides a foreign operation as 404)"
    )
    assert "jwtAccountAdminA" not in pre


def test_assert_op_success_and_error_inherit_the_minting_principal():
    case = gen.Case(
        id="T-INHERIT2", title="t", classes=["CRUD"], priority="P0",
        steps=[
            gen.Step(name="create", method="POST", path="/iam/v1/x", auth="jwtAccountAdminB",
                     test_script=[*gen.save_from_response("j.id", "opId")]),
            gen.poll_operation_until_done(),
            gen.assert_op_success(),
        ],
    )
    items = _items(case)
    for nm in ("poll-op", "assert-op-success"):
        assert "pm.environment.get('jwtAccountAdminB')" in _script(items[nm], "prerequest"), nm


def test_explicit_auth_on_the_poll_is_never_overridden_by_inheritance():
    case = gen.Case(
        id="T-EXPLICIT", title="t", classes=["CRUD"], priority="P0",
        steps=[
            gen.Step(name="create", method="POST", path="/iam/v1/x", auth="jwtInvitee",
                     test_script=[*gen.save_from_response("j.id", "opId")]),
            gen.poll_operation_until_done("jwtBootstrap"),
        ],
    )
    pre = _script(_items(case)["poll-op"], "prerequest")
    assert "pm.environment.get('jwtBootstrap')" in pre
    assert "jwtInvitee" not in pre


def test_inheritance_falls_back_to_the_default_when_nothing_minted_the_op():
    """A case that polls an id seeded by an EARLIER case has no local producer —
    the historical default must still apply rather than producing an unauthenticated
    (or template-literal) step."""
    case = gen.Case(
        id="T-NOPROD", title="t", classes=["CRUD"], priority="P0",
        steps=[gen.poll_operation_until_done()],
    )
    pre = _script(_items(case)["poll-op"], "prerequest")
    assert "pm.environment.get('jwtAccountAdminA')" in pre


def test_inheritance_never_makes_the_poll_anonymous():
    """An anonymous mutation is a 401 negative: it mints nothing. Inheriting
    `anonymous` would strip the Authorization header and turn the poll into a
    second 401 probe that passes for the wrong reason."""
    case = gen.Case(
        id="T-ANON", title="t", classes=["NEG"], priority="P1",
        steps=[
            gen.Step(name="create-anon", method="POST", path="/iam/v1/x", auth="anonymous",
                     test_script=[*gen.save_from_response("j.id", "opId")]),
            gen.poll_operation_until_done(),
        ],
    )
    pre = _script(_items(case)["poll-op"], "prerequest")
    assert "pm.environment.get('jwtAccountAdminA')" in pre
    assert "per-step auth: anonymous step" not in pre


def test_poll_of_a_named_op_var_inherits_from_that_vars_producer():
    """`assert_op_error(op_var=...)` reads a per-case variable; inheritance must
    follow the step that captured THAT variable, not the shared `opId`."""
    case = gen.Case(
        id="T-OPVAR", title="t", classes=["NEG"], priority="P1",
        steps=[
            gen.Step(name="unrelated", method="POST", path="/iam/v1/y", auth="jwtAccountAdminA",
                     test_script=[*gen.save_from_response("j.id", "opId")]),
            gen.Step(name="add", method="POST", path="/iam/v1/x", auth="jwtInvitee",
                     test_script=[*gen.save_from_response("j.id", "myOpId")]),
            gen.assert_op_error(9, "FAILED_PRECONDITION", op_var="myOpId"),
        ],
    )
    pre = _script(_items(case)["assert-op-error"], "prerequest")
    assert "pm.environment.get('jwtInvitee')" in pre


# ---------------------------------------------------------------------------
# 2. Operation-id reset before capture
# ---------------------------------------------------------------------------

def test_op_id_is_cleared_before_the_capture_attempt():
    js = "\n".join(gen.save_from_response("j.id", "opId"))
    assert "pm.environment.unset('opId')" in js, (
        "a rejected mutation writes no id — without a reset the variable keeps the "
        "PREVIOUS case's operation and the poll passes on a foreign object"
    )
    # The clear must precede the write, otherwise it erases the value it just saved.
    assert js.index("unset('opId')") < js.index("set('opId'")


def test_every_operation_id_variable_is_cleared_not_only_the_shared_one():
    for var in ("badRoleInvOpId", "vbcDelOpId", "rmOpId", "addAisOpId"):
        js = "\n".join(gen.save_from_response("j.id", var))
        assert f"pm.environment.unset('{var}')" in js, var


def test_non_operation_variables_are_left_alone():
    """Resource-id captures are deliberately NOT reset here: several cases save a
    resource id in one step and read it many steps later, across requests that do
    not re-return it. Widening the reset would break those; the stale-poll class is
    specific to operation ids, which are consumed immediately by the next step."""
    js = "\n".join(gen.save_from_response("j.metadata.roleId", "crudRoleId"))
    assert "unset(" not in js


def test_rejected_mutation_leaves_the_op_id_empty_end_to_end():
    """End-to-end shape check on generated JS: the capture block, evaluated against
    a 4xx body that carries no `id`, must leave `opId` unset."""
    case = gen.Case(
        id="T-RESET", title="t", classes=["NEG"], priority="P1",
        steps=[gen.Step(name="reject", method="POST", path="/iam/v1/x", auth="jwtAccountAdminA",
                        test_script=[*gen.save_from_response("j.id", "opId")])],
    )
    js = _script(_items(case)["reject"], "test")
    # unset unconditionally, then set only when the response actually carries one
    assert "unset('opId')" in js
    assert "if (v !== undefined && v !== null)" in js


# ---------------------------------------------------------------------------
# 3. What the poll does when there is no operation id at all
# ---------------------------------------------------------------------------
#
# Clearing the id (2) turns "poll the previous case's operation" into "poll an
# unresolved {{opId}} template". Left alone that is POLL_CAP wasted round-trips
# against the gateway ending in a confusing `invalid operation id "{{opId}}"`.
# The absence must be reported once, by name, at the guard.

def test_missing_op_id_fails_once_by_name_instead_of_polling_a_template():
    step = gen.poll_operation_until_done()
    pre = "\n".join(step.pre_script)
    assert "pm.environment.get('opId')" in pre
    assert "pm.test(" in pre, "the missing id must be REPORTED, not silently skipped"
    assert "opId" in pre
    assert "skipRequest()" in pre, "and the request must not be sent with an unresolved template"


def test_best_effort_cleanup_poll_skips_silently():
    """A `cleanup-*` delete is allowed to be refused (403/404 on a resource another
    suite already removed): there is genuinely no operation to poll, and failing
    would report a teardown detail as a defect of the case under test."""
    step = gen.poll_operation_until_done(required=False)
    pre = "\n".join(step.pre_script)
    assert "skipRequest()" in pre
    assert "pm.test(" not in pre


def test_assert_op_helpers_also_guard_the_missing_id():
    for step in (gen.assert_op_success(), gen.assert_op_error(9, "FAILED_PRECONDITION")):
        pre = "\n".join(step.pre_script)
        assert "skipRequest()" in pre, step.name
        assert "pm.test(" in pre, step.name


# ---------------------------------------------------------------------------
# 4. Tolerant negatives must still say WHICH refusal they accept
# ---------------------------------------------------------------------------

def test_unscoped_helper_tolerates_both_defensible_refusals():
    js = "\n".join(gen.assert_unscoped_rejected())
    assert "oneOf([400, 403])" in js
    assert "oneOf([3, 7])" in js


def test_unscoped_helper_pins_the_refusal_when_an_action_is_given():
    """Without this the negative passes on ANY 403 — including a permission-catalog
    miss, which denies every subject for an unrelated reason."""
    js = "\n".join(gen.assert_unscoped_rejected("iam.roles.create", "account:*"))
    assert "AUTHZ_DENIED" in js
    assert "iam.roles.create" in js
    assert "account:*" in js
    assert "empty action = permission-catalog miss" in js


# ---------------------------------------------------------------------------
# Regression guard for the collection-wide invariants these tests rely on
# ---------------------------------------------------------------------------

def test_generated_poll_step_is_valid_json_serialisable():
    case = gen.Case(
        id="T-JSON", title="t", classes=["CRUD"], priority="P0",
        steps=[
            gen.Step(name="create", method="POST", path="/iam/v1/x", auth="jwtInvitee",
                     test_script=[*gen.save_from_response("j.id", "opId")]),
            gen.poll_operation_until_done(),
        ],
    )
    json.dumps(gen._RUN.case_item(case))


# ---------------------------------------------------------------------------
# 5. Страж неразрешённой подстановки обязан смотреть и в ТЕЛО запроса
# ---------------------------------------------------------------------------
#
# Страж читал ТОЛЬКО адрес (`pm.request.url`). Идентификатор, названный в ТЕЛЕ,
# уезжал литералом `{{имя}}` — и класс, ради которого страж написан, оставался
# открытым ровно для тех шагов, которые называют предмет телом, а не путём.
#
# Замер прогона 31951162447 (шард iam, коллекция `label-revoke-nlb`): 63 запроса
# ушли с литералом `{{_t31nLsn}}` в теле, потому что создание слушателя было
# отвергнуто и переменную никто не захватил. Два из них ОТЧИТАЛИСЬ ПРОЙДЕННЫМИ:
# оба — отрицательные (`lsn-pre-grant-deny`, `lsn-post-revoke-deny`), которые
# ждут отказа в доступе. Несуществующий объект отказывает и сам, поэтому запрет
# «нечего проверять» неотличим от запрета работающего — фикстура оказалась
# СНИСХОДИТЕЛЬНЕЕ продукта.
#
# Шаги того же кейса, называющие слушателя ПУТЁМ, страж поймал — отсюда и
# асимметрия: три отказа стража против двух ложных зеленей в одном кейсе.


def _prerequest(step: gen.Step) -> str:
    item = gen._RUN.step_item(step)
    for ev in item.get("event", []):
        if ev["listen"] == "prerequest":
            return "\n".join(ev["script"]["exec"])
    return ""


def test_guard_catches_an_unresolved_placeholder_named_in_the_body():
    """Тело называет предмет — страж обязан отказать до отправки."""
    step = gen.Step(
        name="check-listener",
        method="POST",
        path="/iam/v1/internal/iam:check",
        body={"object": "nlb_listener:{{_t31nLsn}}", "relation": "v_list"},
    )
    pre = _prerequest(step)
    assert "pm.request.body" in pre, (
        "страж читает только адрес: идентификатор, названный телом, уезжает литералом"
    )
    assert "skipRequest()" in pre
    assert "pm.test(" in pre, "отсутствие обязано быть НАЗВАНО, а не тихо пропущено"


def test_guard_stays_silent_when_the_body_placeholder_is_resolvable():
    """Законный близнец: та же форма, но переменная задана — страж молчит.

    Без этой пары страж ловил бы ФОРМУ (`{{`) вместо существа и краснел бы на
    каждом шаге, который сам готовит своё тело.
    """
    step = gen.Step(
        name="check-listener",
        method="POST",
        path="/iam/v1/internal/iam:check",
        body={"object": "nlb_listener:{{_t31nLsn}}", "relation": "v_list"},
        pre_script=["pm.variables.set('_t31nLsn', 'lsn-real');"],
    )
    pre = _prerequest(step)
    assert "pm.variables.has" in pre, (
        "решение обязано зависеть от того, ЗАДАНА ли переменная, а не от наличия скобок"
    )
    assert pre.index("pm.variables.set('_t31nLsn'") < pre.index("pm.request.body"), (
        "страж обязан стоять ПОСЛЕ законных производителей тела этого шага"
    )
