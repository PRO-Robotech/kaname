# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Regression lock for exec-coverage.py — the execution-coverage gate.

The defect this gate exists for: newman only reports failures for requests it
EXECUTED, so a run that stopped early is indistinguishable from a clean full run
(both read `assertions.failed == 0`). A pre-request guard using
`setNextRequest(null)` — which ENDS THE RUN rather than skipping one request —
silently dropped 325 of 1502 iam requests while every collection gated GREEN.

These tests lock the OBSERVABLE behaviour of the gate, not its internals:
  * a truncated run must RED (this is the artificially-skipped-request proof),
  * a legitimately skipped request must stay GREEN (so the gate is usable),
  * `setNextRequest(null)` must RED on sight, even if nothing was truncated.
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
GATE = HERE / "exec-coverage.py"


def _item(name, prereq=None, test=None):
    ev = []
    if prereq:
        ev.append({"listen": "prerequest", "script": {"exec": prereq}})
    if test:
        ev.append({"listen": "test", "script": {"exec": test}})
    it = {"name": name, "request": {"method": "GET", "url": "http://x/y"}}
    if ev:
        it["event"] = ev
    return it


def _collection(tmp, name, items):
    d = tmp / "collections"
    d.mkdir(exist_ok=True)
    p = d / f"{name}.postman_collection.json"
    p.write_text(json.dumps({"info": {"name": name}, "item": items}))
    return p


def _report(tmp, name, positions, total, assertions_failed=0, unanswered=()):
    """Synthesise a newman JSON report where only `positions` executed.

    `unanswered` — positions that newman ATTEMPTED but that never produced a
    response (DNS failure, refused connection, TLS error, timeout). newman still
    records an execution for these, at their cursor position, with `response:
    null` and a `requestError` — which is precisely why they used to read as
    "executed". They are listed in `positions` too, exactly as newman does it.
    """
    d = tmp / "out"
    d.mkdir(exist_ok=True)
    execs = []
    for p in positions:
        ex = {"cursor": {"position": p, "length": total, "iteration": 0},
              "item": {"name": f"i{p}"}, "response": {"code": 200}}
        if p in unanswered:
            ex["response"] = None
            ex["requestError"] = {"code": "ENOTFOUND", "syscall": "getaddrinfo",
                                  "hostname": "api.kacho.local"}
        execs.append(ex)
    (d / f"{name}.json").write_text(json.dumps({
        "run": {"executions": execs,
                "stats": {"assertions": {"total": len(execs), "failed": assertions_failed},
                          "requests": {"total": len(execs), "failed": len(unanswered)}},
                "failures": []},
    }))


def _run(tmp):
    return subprocess.run(
        [sys.executable, str(GATE), "--collections-glob",
         str(tmp / "collections" / "*.postman_collection.json"),
         "--out-dir", str(tmp / "out")],
        capture_output=True, text=True, timeout=60,
    )


def test_full_run_is_green(tmp_path):
    _collection(tmp_path, "c", [_item(f"i{i}") for i in range(5)])
    _report(tmp_path, "c", range(5), 5)
    r = _run(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "executed 5/5 (100%)" in r.stdout


def test_truncated_run_is_red(tmp_path):
    """THE PROOF: a request that never executed reddens the gate even though the
    report carries zero failed assertions — the exact blindness that let a suite
    drop 22% of itself and still be called GREEN."""
    _collection(tmp_path, "c", [_item(f"i{i}") for i in range(5)])
    _report(tmp_path, "c", [0, 1], 5, assertions_failed=0)  # aborted after 2 of 5
    r = _run(tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "3 UNEXPLAINED" in r.stdout
    assert "execution-coverage gaps in: c" in r.stderr
    for missing in ("i2", "i3", "i4"):
        assert missing in r.stdout


def test_single_artificially_skipped_request_is_red(tmp_path):
    """One request removed from the middle — no truncation, no failed assertion,
    no guard explaining it. Must still RED."""
    _collection(tmp_path, "c", [_item(f"i{i}") for i in range(5)])
    _report(tmp_path, "c", [0, 1, 3, 4], 5)
    r = _run(tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "1 UNEXPLAINED" in r.stdout
    assert "i2" in r.stdout


def test_explicit_skipRequest_guard_is_explained(tmp_path):
    """The sanctioned replacement primitive: a conditional poll guard that skips
    exactly one request keeps the suite GREEN."""
    items = [_item("i0"),
             _item("poll", prereq=["if (!pm.environment.get('opId')) { pm.execution.skipRequest(); }"]),
             _item("i2")]
    _collection(tmp_path, "c", items)
    _report(tmp_path, "c", [0, 2], 3)
    r = _run(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "1 explained-skip" in r.stdout


def test_forward_setNextRequest_jump_is_explained(tmp_path):
    """Branch jumps (pre-clean / retry-from paths) legitimately step over items."""
    items = [_item("start", test=["pm.execution.setNextRequest('landing');"]),
             _item("stepped-over-a"), _item("stepped-over-b"), _item("landing")]
    _collection(tmp_path, "c", items)
    _report(tmp_path, "c", [0, 3], 4)
    r = _run(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "2 explained-skip" in r.stdout


def test_setNextRequest_null_is_banned_even_when_nothing_truncated(tmp_path):
    """Static ban: the idiom is never correct inside a guard, and its damage is
    invisible to assertion counts — so it fails on sight, not only on effect."""
    items = [_item("i0"),
             _item("guard", prereq=["if (!pm.environment.get('opId')) { pm.execution.setNextRequest(null); }"]),
             _item("i2")]
    _collection(tmp_path, "c", items)
    _report(tmp_path, "c", [0, 1, 2], 3)  # full execution, zero failures
    r = _run(tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "BANNED setNextRequest(null)" in r.stdout
    assert "skipRequest()" in r.stdout


def test_legacy_postman_alias_is_banned_too(tmp_path):
    items = [_item("guard", prereq=["postman.setNextRequest( null )"])]
    _collection(tmp_path, "c", items)
    _report(tmp_path, "c", [0], 1)
    r = _run(tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "BANNED setNextRequest(null)" in r.stdout


def test_environment_guard_without_an_assertion_is_banned(tmp_path):
    """THE SECOND-ORDER BLIND SPOT.

    An operation guard and an environment guard are the same three lines of
    JavaScript and mean opposite things:

      if (!opId)            skipRequest()  → legal: the create was rejected on
                                             purpose, there is nothing to poll.
      if (!internalBaseUrl) skipRequest()  → BROKEN HARNESS: the check is still
                                             expected to run; the runner simply
                                             did not inject the variable.

    newman leaves NO trace of a skipped request, so the second kind passes by
    never running — and the coverage gate cannot tell them apart, because both
    are an explicit `skipRequest()` and both are therefore "explained". Losing
    one variable would silently delete 31 authorization checks from a single
    collection and the suite would still be GREEN.

    So an environment guard must FAIL, not merely skip: it has to carry an
    assertion. This locks that statically."""
    items = [_item("probe", prereq=[
        "const b = pm.environment.get('internalBaseUrl') || '';",
        "if (!b) { console.warn('not set — skipping'); pm.execution.skipRequest(); }",
        "else { pm.request.url = b + '/iam/v1/internal/iam:check'; }",
    ])]
    _collection(tmp_path, "c", items)
    _report(tmp_path, "c", [0], 1)  # it ran; nothing truncated, zero failures
    r = _run(tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "SILENT environment guard" in r.stdout
    assert "internalBaseUrl" in r.stdout


def test_environment_guard_that_asserts_is_accepted(tmp_path):
    """The sanctioned shape: fail (naming the variable), then skip."""
    items = [_item("probe", prereq=[
        "const b = pm.environment.get('internalBaseUrl') || '';",
        "if (b) { pm.request.url = b + '/iam/v1/internal/iam:check'; }",
        "else {",
        "  pm.test('harness config: internalBaseUrl is set', () => { pm.expect.fail('internalBaseUrl is not set'); });",
        "  pm.execution.skipRequest();",
        "}",
    ])]
    _collection(tmp_path, "c", items)
    _report(tmp_path, "c", [], 1)  # the variable was missing → skipped, and RED elsewhere
    r = _run(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "1 explained-skip" in r.stdout


def test_operation_guard_stays_a_legal_silent_skip(tmp_path):
    """The environment rule must NOT bleed onto operation guards: a rejected
    create genuinely has no operation to poll, and demanding an assertion there
    would turn every negative case red."""
    items = [_item("create-rejected"),
             _item("poll", prereq=[
                 "// no operation id → the create was refused on purpose.",
                 "if (!pm.environment.get('opId')) { pm.execution.skipRequest(); }",
             ]),
             _item("after")]
    _collection(tmp_path, "c", items)
    _report(tmp_path, "c", [0, 2], 3)
    r = _run(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "1 explained-skip" in r.stdout


def test_request_that_never_got_an_answer_is_not_executed(tmp_path):
    """THE THIRD STATE.

    A request can end three ways, and only two of them were ever counted:

      answered      — a response arrived, whatever its status;
      failed        — an assertion said no;
      NOT EXECUTED  — no response arrived at all.

    The third one had no home. A request that dies at transport level (DNS,
    refused connection, TLS, timeout) still gets an execution record at its
    cursor position, so this gate called it executed; its assertions run against
    an empty response and can trivially be written to pass; and the one honest
    signal left — `requests.failed` — was being SUBTRACTED by the suite gate as
    "DNS noise". Eight ban-#6 negatives (Internal* must not be reachable on the
    advertised external endpoint) rode on that for an unknown length of time: the
    checks never ran and the numbers read "0 failed".

    A check that did not happen is not a check that passed. Position present is
    not evidence of execution — an ANSWER is."""
    _collection(tmp_path, "c", [_item(f"i{i}") for i in range(4)])
    _report(tmp_path, "c", [0, 1, 2, 3], 4, assertions_failed=0, unanswered=[2, 3])
    r = _run(tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "2 UNANSWERED" in r.stdout
    assert "execution-coverage gaps in: c" in r.stderr
    for named in ("i2", "i3"):
        assert named in r.stdout
    # The transport cause must be named, or the reader cannot act on it.
    assert "ENOTFOUND" in r.stdout


def test_unanswered_request_is_not_absorbed_by_a_skip_guard(tmp_path):
    """A `skipRequest()` guard explains a request that did NOT run. It must not
    also excuse one that ran and got no answer — otherwise any step carrying a
    conditional guard becomes a place where transport failure is invisible."""
    items = [_item("i0"),
             _item("guarded", prereq=["if (!pm.environment.get('opId')) { pm.execution.skipRequest(); }"])]
    _collection(tmp_path, "c", items)
    _report(tmp_path, "c", [0, 1], 2, unanswered=[1])
    r = _run(tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "1 UNANSWERED" in r.stdout


def test_answered_requests_stay_green(tmp_path):
    """The new state must not redden a healthy run: a response with any status
    code — including the 4xx that negative cases assert — is an answer."""
    _collection(tmp_path, "c", [_item(f"i{i}") for i in range(3)])
    _report(tmp_path, "c", [0, 1, 2], 3)
    r = _run(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "UNANSWERED" not in r.stdout


def test_report_for_a_different_collection_is_red(tmp_path):
    """A stale report cannot be silently paired with a regenerated collection."""
    _collection(tmp_path, "c", [_item(f"i{i}") for i in range(5)])
    _report(tmp_path, "c", [0, 1, 2], 3)  # report says the collection had 3 items
    r = _run(tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "report/collection mismatch" in r.stdout


def test_missing_report_is_left_to_the_assertion_gate(tmp_path):
    """No report is already the existing gate's `(no-report)` failure — this gate
    reports it but does not double-count it as an execution gap."""
    _collection(tmp_path, "c", [_item("i0")])
    (tmp_path / "out").mkdir(exist_ok=True)
    r = _run(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "NO REPORT" in r.stdout
