# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

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


def _collection(tmp, name, items, root_pre=None):
    """`root_pre` — пре-скрипт КОРНЯ коллекции (`collection.event`).

    Postman исполняет его перед КАЖДЫМ запросом наравне с элементным. Пока гейт
    читал только элементные скрипты, эта область не проверялась вовсе: замер по
    дереву на `dfd2c027` — 57 коллекций из 89 держат стража именно здесь, и iam
    (где гейт писался) не держит его ни в одной из 32.
    """
    d = tmp / "collections"
    d.mkdir(exist_ok=True)
    p = d / f"{name}.postman_collection.json"
    doc = {"info": {"name": name}, "item": items}
    if root_pre is not None:
        doc["event"] = [{"listen": "prerequest", "script": {"exec": root_pre}}]
    p.write_text(json.dumps(doc))
    return p


def _report(tmp, name, positions, total, assertions_failed=0, unanswered=(), failures=(),
            embed=True, foreign_items=None):
    """Synthesise a newman JSON report where only `positions` executed.

    `unanswered` — positions that newman ATTEMPTED but that never produced a
    response (DNS failure, refused connection, TLS error, timeout). newman still
    records an execution for these, at their cursor position, with `response:
    null` and a `requestError` — which is precisely why they used to read as
    "executed". They are listed in `positions` too, exactly as newman does it.

    `embed` — newman's JSON reporter writes the collection it executed alongside
    the run; a real report's top-level keys are `collection`, `environment`,
    `globals`, `run`. The gate reads that copy to answer "is this report about the
    collection on disk?", so embedding is the default here because it is what
    newman does. `embed=False` models an older reporter and exercises the
    count-only fallback.

    `foreign_items` — embed a DIFFERENT collection than the one on disk. That is
    what a leftover `out/` from another branch of the same suite looks like, and
    it is the input the gate must refuse to draw a product verdict from.
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
    fails = [{"error": {"test": f"assertion on {n}", "message": "boom"},
              "source": {"name": n}, "parent": {"name": "F"}} for n in failures]
    doc = {
        "run": {"executions": execs,
                "stats": {"assertions": {"total": len(execs) + len(fails),
                                         "failed": assertions_failed or len(fails)},
                          "requests": {"total": len(execs), "failed": len(unanswered)}},
                "failures": fails},
    }
    if embed:
        if foreign_items is not None:
            doc["collection"] = {"info": {"name": name}, "item": foreign_items}
        else:
            on_disk = json.loads(
                (tmp / "collections" / f"{name}.postman_collection.json").read_text())
            doc["collection"] = on_disk
    (d / f"{name}.json").write_text(json.dumps(doc))


def _run(tmp):
    return subprocess.run(
        [sys.executable, str(GATE), "--collections-glob",
         str(tmp / "collections" / "*.postman_collection.json"),
         "--out-dir", str(tmp / "out")],
        capture_output=True, text=True, timeout=60,
    )


def _coverage_line(stdout, name="c"):
    """Строка ПРО КОЛЛЕКЦИЮ, а не весь вывод гейта.

    Утверждения о классификации шага обязаны читать именно её. Гейт печатает ещё
    и итоговую перепись пропусков, в которой имена категорий стоят ВСЕГДА — в том
    числе нулями, потому что «объяснённых пропусков ноль» обязано быть отличимо
    от «их никто не считал». Проверка подстроки по всему выводу подхватывает эту
    строку и с тех пор утверждает не то, что написано в её имени: её исход
    определяется текстом переписи, а не классификацией шага.

    Это СУЖЕНИЕ проверки, а не ослабление: раньше она могла быть удовлетворена
    посторонней строкой, теперь — только той, о которой говорит.
    """
    for line in stdout.splitlines():
        if line.startswith(f"{name}: "):
            return line
    return ""


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


def test_report_whose_cursors_do_not_describe_this_collection_is_not_judged(tmp_path):
    """A stale report cannot be silently paired with a regenerated collection.

    This test previously demanded exit 1 and the words "report/collection
    mismatch" — i.e. it pinned the misclassification. The detection is unchanged
    and still fires; what changed is the SIDE it lands on. Positions that
    disagree with the collection cannot be read as coverage of it, so the answer
    is "not judged". Calling it a product failure is how another tree's artifact
    directory came to name twelve collections as failing here.
    """
    _collection(tmp_path, "c", [_item(f"i{i}") for i in range(5)])
    _report(tmp_path, "c", [0, 1, 2], 3)  # report says the collection had 3 items
    r = _run(tmp_path)
    assert r.returncode == 3, r.stdout + r.stderr
    assert "REPORT DOES NOT DESCRIBE THIS COLLECTION" in r.stdout
    assert "FAIL: execution-coverage gaps" not in r.stderr


def test_guard_that_asserted_and_failed_is_not_filed_as_a_silent_skip(tmp_path):
    """THE FOURTH STATE — a step whose script ASSERTED but whose request never ran.

    Measured on the production-posture run of 2026-07-30: newman's JSON reporter does
    NOT put an execution record in `run.executions` for an item that skips its own
    request from the pre-request script. Its assertions still count in `run.stats` and
    still appear in `run.failures` — so walking the array alone UNDERCOUNTS. In
    `iam-user.json` the array accounted for 121 failed assertions where the summary
    said 137; sixteen belonged to items with NO execution entry at all, across four
    iam collections.

    For this gate the consequence is worse than a wrong number. The very items that
    vanish are the guarded ones, and a guard is exactly what this gate accepts as an
    explanation. So a guard that fired, asserted and FAILED was filed as
    "explained-skip — nothing was lost", which is the opposite of what happened.

    The verdict must come from the summary and the failure list, not from the array.
    """
    items = [_item("create-rejected"),
             _item("poll", prereq=[
                 "if (!pm.environment.get('opId')) {",
                 "  pm.test('operation id was captured', () => pm.expect.fail('opId is empty'));",
                 "  pm.execution.skipRequest();",
                 "}",
             ]),
             _item("after")]
    _collection(tmp_path, "c", items)
    _report(tmp_path, "c", [0, 2], 3, failures=["poll"])
    r = _run(tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr
    line = _coverage_line(r.stdout)
    assert line, "no per-collection coverage line — the gate said nothing about 'c'"
    assert "explained-skip" not in line, "a failed assertion was filed as a legal skip"
    # RECORDED-SKIP is the OTHER legal outcome for a step that asserted and did not
    # run, and it must not apply here: the failure booked against `poll` is not the
    # guard's own assertion, so the step's checks ran and its execution record is
    # what went missing. Naming it explicitly keeps the new category from becoming
    # a second door out of this finding.
    assert "RECORDED-SKIP" not in line, "a failure that is not the guard's own was excused"
    assert "ASSERTED" in line
    assert "poll" in r.stdout


def test_a_guard_that_skipped_quietly_is_still_explained(tmp_path):
    """The other direction — the gate must stay usable.

    Same shape, same guard, same missing execution; the only difference is that the
    report names no failure for it. That is the sanctioned conditional poll: a create
    refused on purpose has nothing to poll. It must remain GREEN, or every negative
    case in the tree reddens and the gate is switched off within a day.
    """
    items = [_item("create-rejected"),
             _item("poll", prereq=[
                 "if (!pm.environment.get('opId')) { pm.execution.skipRequest(); }",
             ]),
             _item("after")]
    _collection(tmp_path, "c", items)
    _report(tmp_path, "c", [0, 2], 3, failures=[])
    r = _run(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    line = _coverage_line(r.stdout)
    assert line, "no per-collection coverage line — the gate said nothing about 'c'"
    assert "1 explained-skip" in line
    assert "ASSERTED" not in line


def test_the_gate_reconciles_its_own_count_with_the_summary(tmp_path):
    """The gate must state the volume it read and where the number came from.

    "Zero findings" has to be distinguishable from "zero read" — and the array this
    gate walks is known not to be complete, so the line it prints says which side the
    numbers come from.
    """
    _collection(tmp_path, "c", [_item(f"i{i}") for i in range(3)])
    _report(tmp_path, "c", [0, 1, 2], 3)
    r = _run(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "summary" in r.stdout, "the reconciliation against run.stats is not reported"


# ── WHOSE REPORTS THESE ARE ──────────────────────────────────────────────────
#
# The gate's coverage half is computed from `out/<name>.json`, a run artifact it
# does not produce and git does not track. Until these tests existed, both an
# EMPTY directory and a directory full of ANOTHER tree's reports reached the exit
# code as if they were evidence: empty printed "OK: every request either executed
# or is an explained skip." over 1658 requests nobody had looked at, and foreign
# leftovers printed a product FAILURE naming collections from a tree the reports
# do not describe.
#
# The test that used to stand here, `test_missing_report_is_left_to_the_assertion_gate`,
# asserted `returncode == 0` on a missing report — it pinned that behaviour as
# intended. It is replaced rather than amended: the pass it demanded is the defect.


def test_missing_report_is_not_a_pass(tmp_path):
    """No report means the coverage question was not answered.

    Not a pass — nothing here says the requests ran. Not a failure — nothing here
    says they did not. A third exit code, so a caller cannot spend it on either
    side by accident.
    """
    _collection(tmp_path, "c", [_item("i0")])
    (tmp_path / "out").mkdir(exist_ok=True)
    r = _run(tmp_path)
    assert r.returncode == 3, r.stdout + r.stderr
    assert "NO REPORT (not judged)" in r.stdout
    assert "DID NOT RUN" in r.stderr
    assert not r.stdout.startswith("OK:") and "\nOK:" not in r.stdout, (
        "an affirmative was printed about a collection nobody looked at:\n" + r.stdout)


def test_census_names_how_many_were_judged(tmp_path):
    """"Zero findings" must not read the same as "zero examined", so the count of
    judged collections prints on every path — including the affirmative one."""
    _collection(tmp_path, "c", [_item(f"i{i}") for i in range(3)])
    _report(tmp_path, "c", [0, 1, 2], 3)
    r = _run(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "CENSUS: 1 collection(s) matched; judged 1; not judged 0" in r.stdout


def test_report_of_another_collection_abstains_instead_of_reddening(tmp_path):
    """A leftover report from another branch of the same suite.

    Same file name, same leaf COUNT — which is all the previous cross-check
    compared, and why 18 of 29 stale reports were consumed as current in a live
    measurement while the 11 it did catch were filed as product failures. The
    verdict must be about the INPUT: not judged, not failed.
    """
    _collection(tmp_path, "c", [_item("alpha"), _item("beta"), _item("gamma")])
    _report(tmp_path, "c", [0], 3,
            foreign_items=[_item("alpha"), _item("BETA-renamed"), _item("gamma")])
    r = _run(tmp_path)
    assert r.returncode == 3, r.stdout + r.stderr
    assert "REPORT IS NOT OF THIS COLLECTION" in r.stdout
    assert "FAIL: execution-coverage gaps" not in r.stderr, (
        "a report from another tree was turned into a verdict about this one:\n"
        + r.stdout + r.stderr)


def test_report_of_this_collection_is_judged(tmp_path):
    """The paired positive: the same shape, legitimately produced.

    Without this twin the provenance check would be indistinguishable from one
    that refuses every report — and a gate that never judges anything is the same
    blindness with the sign flipped.
    """
    items = [_item("alpha"), _item("beta"), _item("gamma")]
    _collection(tmp_path, "c", items)
    _report(tmp_path, "c", [0, 1, 2], 3)
    r = _run(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "REPORT IS NOT OF THIS COLLECTION" not in r.stdout
    assert "judged 1" in r.stdout


def test_provenance_survives_a_report_without_an_embedded_collection(tmp_path):
    """Older reporter: no `collection` key. The leaf-count fallback still answers
    the provenance question — and still answers it as provenance, not as a gap."""
    _collection(tmp_path, "c", [_item(f"i{i}") for i in range(3)])
    _report(tmp_path, "c", [0], 9, embed=False)  # cursors describe a 9-leaf collection
    r = _run(tmp_path)
    assert r.returncode == 3, r.stdout + r.stderr
    assert "REPORT IS NOT OF THIS COLLECTION" in r.stdout
    assert "FAIL: execution-coverage gaps" not in r.stderr


def test_static_ban_still_reds_without_any_report(tmp_path):
    """The bans read the tracked collection, which IS this tree, so they need no
    run to be true. Abstaining on coverage must not swallow them: a red outranks
    a did-not-run."""
    _collection(tmp_path, "c", [_item("i0", prereq=["pm.execution.setNextRequest(null);"])])
    (tmp_path / "out").mkdir(exist_ok=True)
    r = _run(tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "BANNED setNextRequest(null)" in r.stdout


# ─────────────────────────────────────────────────────────────────────────────
# СТРАЖ В КОРНЕ КОЛЛЕКЦИИ — область, которой гейт не читал (#661)
# ─────────────────────────────────────────────────────────────────────────────
#
# Форма, стоящая в 57 коллекциях дерева из 89: имя утверждения СОБИРАЕТСЯ
# конкатенацией, потому что называет переменную, которой не оказалось.
_ROOT_GUARD = [
    "(function () {",
    "  var _u = pm.request.url.toString();",
    "  var _all = _u.match(/\\{\\{[A-Za-z0-9_]+\\}\\}/g);",
    "  if (!_all) { return; }",
    "  var _n = _all[0].slice(2, -2);",
    "  if (pm.variables.has(_n)) { return; }",
    "  pm.test('предусловие: {{' + _n + '}} не было захвачено — запрос не отправлен', function () {",
    "    pm.expect.fail(_n + ' не определена ни в одной области.');",
    "  });",
    "  pm.execution.skipRequest();",
    "})();",
]
_ROOT_GUARD_FAILED = "предусловие: {{lbId}} не было захвачено — запрос не отправлен"


def _report_named_failures(tmp, name, positions, total, failures):
    """Как `_report`, но имена упавших утверждений задаются дословно.

    `_report` подставляет `assertion on <шаг>`; здесь нужен ТОТ ЖЕ текст, что
    печатает страж, иначе проба утверждала бы не о том — сверка идёт по имени.
    """
    d = tmp / "out"
    d.mkdir(exist_ok=True)
    execs = [{"cursor": {"position": p, "length": total, "iteration": 0},
              "item": {"name": f"i{p}"}, "response": {"code": 200}} for p in positions]
    fails = [{"error": {"test": t, "message": m}, "source": {"name": n},
              "parent": {"name": "F"}} for n, t, m in failures]
    on_disk = json.loads((tmp / "collections" / f"{name}.postman_collection.json").read_text())
    (d / f"{name}.json").write_text(json.dumps({
        "collection": on_disk,
        "run": {"executions": execs,
                "stats": {"assertions": {"total": len(execs) + len(fails), "failed": len(fails)},
                          "requests": {"total": len(execs), "failed": 0}},
                "failures": fails},
    }))


def test_root_level_guard_records_the_skip(tmp_path):
    """Пропуск корневым стражем — ЗАПИСАННЫЙ, а не находка.

    На прогоне 32077150454 (шард nlb) гейт объявил 157 таких пропусков находкой
    `ASSERTED-NOT-EXECUTED` и в той же сводке напечатал `SKIPS: 0 RECORDED-SKIP` —
    то есть о записанных пропусках отчитался нулём, имея их все 157. Причина
    механическая: читались скрипты только самого шага.
    """
    _collection(tmp_path, "c", [_item("i0"), _item("i1"), _item("i2")], root_pre=_ROOT_GUARD)
    _report_named_failures(tmp_path, "c", [0, 2], 3,
                           [("i1", _ROOT_GUARD_FAILED, "lbId не определена ни в одной области.")])
    r = _run(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    line = _coverage_line(r.stdout)
    assert "RECORDED-SKIP" in line, line
    assert "ASSERTED" not in line, line


def test_root_level_guard_does_not_amnesty_a_failed_test_script(tmp_path):
    """Положительный контроль к предыдущей: «корень прочитан» не значит «извинено».

    Тот же корневой страж, тот же отсутствующий шаг — но упало утверждение
    ТЕСТ-скрипта, значит запрос ушёл и ответ пришёл. Это находка, ради которой
    гейт и заведён, и корневой страж её не покрывает.
    """
    _collection(tmp_path, "c", [_item("i0"), _item("i1"), _item("i2")], root_pre=_ROOT_GUARD)
    _report_named_failures(tmp_path, "c", [0, 2], 3,
                           [("i1", "status 200", "expected 403 to equal 200")])
    r = _run(tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr
    line = _coverage_line(r.stdout)
    assert "ASSERTED-NOT-EXECUTED" in line, line
    assert "RECORDED-SKIP" not in line, line


def test_setNextRequest_null_in_the_root_script_is_banned(tmp_path):
    """Запрет читает КАЖДУЮ область скриптов, а не только элементную.

    Иначе маска, внесённая в корневой скрипт, гейтом не ловится — а маски
    запрещены директивой владельца. Область молчания была не гипотетической:
    57 коллекций из 89.
    """
    _collection(tmp_path, "c", [_item("i0")],
                root_pre=["if (!pm.environment.get('opId')) { pm.execution.setNextRequest(null); }"])
    _report(tmp_path, "c", [0], 1)
    r = _run(tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "BANNED setNextRequest(null)" in r.stdout
    assert "корень коллекции" in r.stdout, "находка обязана назвать координату"


def test_the_same_ban_written_as_a_comment_stays_silent(tmp_path):
    """Законный близнец той же внешности: объяснение рядом с запретом — не вызов.

    Без разбора на код/строку/комментарий запрет краснел бы на тексте о самом
    себе, и первым же ложным срабатыванием его бы сняли.
    """
    _collection(tmp_path, "c", [_item("i0")], root_pre=[
        "// НИКОГДА не пиши pm.execution.setNextRequest(null): он завершает ПРОГОН.",
        "/* и в блочном комментарии тоже: setNextRequest(null) */",
        "pm.environment.set('_ok', '1');",
    ])
    _report(tmp_path, "c", [0], 1)
    r = _run(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "BANNED" not in r.stdout


def test_a_mute_root_skip_does_not_explain_a_truncated_tail(tmp_path):
    """АНТИ-МАСКИРОВКА: корневой `skipRequest()` не объясняет пропавший хвост.

    Корневой пре-скрипт исполняется перед КАЖДЫМ запросом, поэтому засчитать его
    в «объяснённые пропуски» значило бы объявить объяснённым любое усечение — то
    есть убить ровно тот класс, ради которого перепись заведена, и убить его
    разом в 57 коллекциях из 89. Корень читается там, где вывод делается по
    ОТЧЁТУ (упало ли утверждение стража), а не по форме кода.
    """
    _collection(tmp_path, "c", [_item(f"i{i}") for i in range(4)],
                root_pre=["if (!pm.variables.has('zzz')) { pm.execution.skipRequest(); }"])
    _report(tmp_path, "c", [0], 4)  # хвост исчез, отчёт о нём молчит
    r = _run(tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr
    line = _coverage_line(r.stdout)
    assert "UNEXPLAINED" in line, line


def test_the_census_names_which_script_scopes_were_read(tmp_path):
    """Объём осмотренного печатается по ОБЛАСТЯМ, включая нули.

    «Ноль находок» обязано быть отличимо от «ноль прочитанного» — и слепота к
    корневым скриптам выглядела именно как первое, будучи вторым.
    """
    _collection(tmp_path, "c", [_item("i0")], root_pre=["pm.environment.set('_ok', '1');"])
    _report(tmp_path, "c", [0], 1)
    r = _run(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SCOPES:" in r.stdout
    assert "корней 1/1" in r.stdout, r.stdout
    assert "элементов" in r.stdout
