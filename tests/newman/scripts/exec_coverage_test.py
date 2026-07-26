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


def _report(tmp, name, positions, total, assertions_failed=0):
    """Synthesise a newman JSON report where only `positions` executed."""
    d = tmp / "out"
    d.mkdir(exist_ok=True)
    execs = [
        {"cursor": {"position": p, "length": total, "iteration": 0}, "item": {"name": f"i{p}"}}
        for p in positions
    ]
    (d / f"{name}.json").write_text(json.dumps({
        "run": {"executions": execs,
                "stats": {"assertions": {"total": len(execs), "failed": assertions_failed}},
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
