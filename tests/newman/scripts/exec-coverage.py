#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""exec-coverage.py — EXECUTION coverage gate: did every request in the collection
actually run?

WHY (the blindness this closes)
-------------------------------
newman reports failures only for requests it EXECUTED. A request that never ran
contributes zero assertions and zero failures, so a suite that silently stopped
after 6 of its 46 requests is indistinguishable — to `.run.stats.assertions.failed`
— from a suite that ran all 46 cleanly. Both read "0 failed" and both were gated
GREEN.

That is exactly what happened: a poll pre-request guard used

    if (!pm.environment.get('<opId>')) { pm.execution.setNextRequest(null); }

intending "skip this poll when the create was rejected and no operation exists".
But `setNextRequest(null)` does not skip a request — it ENDS THE RUN. The guard
fires deterministically on negative cases (create rejected 403/400 → no op id), so
the whole remainder of the collection was dropped. The iam suite executed 1177 of
1502 requests (78.4%) while reporting every collection GREEN; the 325 dropped
requests were the authz-deny leak matrix, the ROLE/INV/USR/ESC deny matrices and
the fail-closed OpenFGA-outage case — i.e. the reason the suite exists.

`pm.execution.skipRequest()` is the primitive that skips exactly one request.

WHAT THIS CHECKS
----------------
Per collection, two independent things:

1. STATIC BANS
   a. no script may contain `setNextRequest(null)`. It is never the right
      primitive inside a per-request guard, and its damage is invisible to the
      assertion-based verdict, so it is banned outright rather than merely
      detected through its effects.
   b. no ENVIRONMENT guard may skip SILENTLY. A guard that skips because a
      harness variable is missing must carry an assertion, so the missing
      variable is reported instead of quietly deleting checks. See below.

   THE SECOND-ORDER BLIND SPOT (why 1b exists). Skipping is the sanctioned fix
   for 1a — but a skip leaves NO trace either: no execution record, no assertion,
   no failure. So a guard that fires for the WRONG REASON still passes, and this
   gate cannot see it, because "explained by a skipRequest() guard" is exactly
   what it was taught to accept. Two guards, three identical lines, opposite
   meanings:

     if (!opId)            skipRequest()  → LEGAL. The create under test was
                                            refused on purpose; there is no
                                            operation to poll and nothing to
                                            assert. Nothing is lost.
     if (!internalBaseUrl) skipRequest()  → BROKEN HARNESS. The check is still
                                            meaningful and still expected to run;
                                            the runner merely failed to inject
                                            the variable (--env-var).

   Losing one variable would silently remove 31 authorization checks from a
   single collection (label-revoke-vpc) and the suite would still report GREEN —
   the same blindness as the truncation above, one level down. Hence: an
   environment guard must FAIL, not merely skip. The sanctioned shape is
   gen.py::require_env_url — assert (naming the variable), then skip.

2. EXECUTION COVERAGE — every leaf request must either have EXECUTED or be
   statically EXPLAINED as skippable. A request is explained when:
     a. its pre-request script calls `pm.execution.skipRequest()` (an explicit,
        reviewable opt-out — the conditional-poll guards), or
     b. some earlier request can jump over it via a literal
        `pm.execution.setNextRequest('<name>')` targeting a later request (the
        pre-clean / branch jumps in rbac-visibility-set, iam-flat-authz-vbc, ...).

   Anything else that did not run is UNEXPLAINED and fails the suite. Truncation
   (the whole tail vanishing) can never be explained, so this catches the entire
   class, not just the one idiom that caused it.

3. ANSWERED — a request that newman attempted but that got NO RESPONSE did not
   execute, whatever its cursor says.

   THE THIRD STATE (why 2 alone was not enough). A request ends one of three
   ways: it is ANSWERED (a response arrived, any status), an assertion FAILED,
   or it is UNANSWERED — nothing came back. Only the first two had a home.
   newman records an execution for a transport failure too — same cursor
   position, but `response: null` and a `requestError` (DNS, refused connection,
   TLS, timeout) — so check 2 above counted it as executed. Meanwhile its test
   script still runs, against an empty response, where `pm.response.code` is
   `undefined` and an assertion phrased "if the code is undefined, return" PASSES.
   And the last honest signal, `.run.stats.requests.failed`, was being SUBTRACTED
   by the suite gate as DNS noise.

   All three layers agreed that nothing was wrong. Eight ban-#6 negatives — the
   ones asserting that Internal* RPCs are not reachable on the advertised
   external endpoint — never ran, and the verdict read "0 failed requests".

   So: an ANSWER is the evidence of execution, not a cursor position. A skip
   guard explains a request that did not run; it does not excuse one that ran
   and got nothing back.

Matching is POSITIONAL: generated collections carry no item `id` (newman mints one
per run), but every execution records `cursor.position` — the index of the item in
the flattened collection order. `cursor.length` is cross-checked against the leaf
count so a report can never be silently paired with a different collection.

Self-loop retries (`setNextRequest(pm.info.requestName)`) inflate
`.run.stats.requests.total` far beyond the item count, which is why raw request
totals are NOT a usable signal here — distinct executed positions are.

Usage:
    python3 exec-coverage.py [--collections-glob GLOB] [--out-dir DIR]
Exit: 0 = every collection fully accounted for; 1 = ban hit or unexplained gaps.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

# `setNextRequest(null)` / `setNextRequest( null )`, on pm.execution or the legacy
# `postman.` alias. Banned: it ends the run instead of skipping a request.
_BAN_RE = re.compile(r"setNextRequest\(\s*null\s*\)")

# Explicit single-request skip — the sanctioned opt-out.
_SKIP_RE = re.compile(r"skipRequest\s*\(")

# A read of a harness-supplied endpoint variable: pm.environment.get('internalBaseUrl'),
# pm.variables.get('externalBaseUrl'), ... A guard keyed on one of these is an
# ENVIRONMENT guard (misconfigured harness), not an operation guard (legal skip).
_ENV_URL_VAR_RE = re.compile(r"""(?:environment|variables|globals)\.get\(\s*['"](\w*[Bb]aseUrl)['"]\s*\)""")

# Any assertion at all in the same script — that is what makes a skip audible.
_ASSERT_RE = re.compile(r"pm\.test\s*\(")

# Literal forward jump: setNextRequest('name') / setNextRequest("name").
# The dynamic self-loop form setNextRequest(pm.info.requestName) has no quotes and
# is deliberately not matched (it re-runs the SAME request, skipping nothing).
_JUMP_RE = re.compile(r"setNextRequest\(\s*(['\"])(.*?)\1\s*\)")

_MAX_REPORTED = 12  # cap the per-collection offender list in the output


def _iter_leaves(items):
    """Postman items nest (folders). Yield leaf items (those with `.request`) in
    the same depth-first order newman executes them."""
    for it in items:
        if "request" in it:
            yield it
        if "item" in it:
            yield from _iter_leaves(it["item"])


def _iter_leaf_parents(items, parent=""):
    """The enclosing folder name of each leaf, in the SAME order as `_iter_leaves`.

    newman's failure records identify a step by the pair (`parent.name`,
    `source.name`) — folder and item — because item names repeat across folders.
    Positional matching needs the same pair, so the folder is tracked separately
    rather than changing what `_iter_leaves` yields.
    """
    for it in items:
        if "request" in it:
            yield parent
        if "item" in it:
            yield from _iter_leaf_parents(it["item"], it.get("name", ""))


def _scripts(item, listen=None):
    """Concatenated script source of an item, optionally only for one event type
    ('prerequest' | 'test')."""
    out = []
    for ev in item.get("event", []) or []:
        if listen is not None and ev.get("listen") != listen:
            continue
        exec_ = (ev.get("script") or {}).get("exec") or []
        if isinstance(exec_, str):
            out.append(exec_)
        else:
            out.extend(str(x) for x in exec_)
    return "\n".join(out)


def _transport_error(ex):
    """Return a short description of why this execution got no response, or None
    if a response arrived.

    newman's JSON reporter writes, for a request that died before an HTTP
    exchange completed, `response: null` plus a `requestError` object carrying the
    Node-level cause, e.g.

        {"errno": -3008, "code": "ENOTFOUND", "syscall": "getaddrinfo",
         "hostname": "api.kacho.local"}

    Both signals are checked: `requestError` is the explicit one, and a null
    response is the invariant it implies. Either is enough — an execution without
    a response did not answer, whatever else the report says about it.
    """
    err = ex.get("requestError")
    if err is None and ex.get("response") is not None:
        return None
    if isinstance(err, dict):
        code = err.get("code") or err.get("errno") or "request error"
        host = err.get("hostname") or err.get("address") or ""
        syscall = err.get("syscall") or ""
        detail = " ".join(x for x in (str(code), syscall, host) if x)
        return detail or "request error"
    if isinstance(err, str) and err:
        return err
    return "no response"


def _explained_skippable(leaves):
    """Indices that are allowed to not execute, with the reason.

    (a) explicit `skipRequest()` in the item's own pre-request script;
    (b) jumped over by a literal forward `setNextRequest('<later item>')`.
    Both are static over-approximations of newman's runtime control flow — they
    never mask a truncation, because a truncated tail has no jump pointing past
    it and no skip guard of its own.
    """
    by_name = {}
    for i, it in enumerate(leaves):
        by_name.setdefault(it.get("name", ""), i)  # newman resolves to the FIRST match

    reasons = {}
    for i, it in enumerate(leaves):
        if _SKIP_RE.search(_scripts(it, "prerequest")):
            reasons[i] = "skipRequest() guard"

    for i, it in enumerate(leaves):
        for _q, target in _JUMP_RE.findall(_scripts(it)):
            j = by_name.get(target)
            if j is None or j <= i + 1:
                continue  # unknown target, self, or adjacent → nothing skipped
            for k in range(i + 1, j):
                reasons.setdefault(k, f"jumped over by {it.get('name','?')!r} → {target!r}")
    return reasons


def check_collection(col_path, out_dir):
    """Returns (ok, coverage_line, [problem lines])."""
    name = os.path.basename(col_path).replace(".postman_collection.json", "")
    problems = []
    with open(col_path, encoding="utf-8") as fh:
        col = json.load(fh)
    leaves = list(_iter_leaves(col.get("item", [])))
    parents = list(_iter_leaf_parents(col.get("item", [])))
    total = len(leaves)

    # (1a) static ban — setNextRequest(null) ends the run
    for it in leaves:
        if _BAN_RE.search(_scripts(it)):
            problems.append(
                f"  BANNED setNextRequest(null) in {it.get('name','?')!r} — it ENDS THE RUN, "
                f"it does not skip a request. Use pm.execution.skipRequest()."
            )

    # (1b) static ban — an environment guard that skips without saying so
    silent = []
    for it in leaves:
        src = _scripts(it, "prerequest")
        if not _SKIP_RE.search(src):
            continue
        env_vars = sorted(set(_ENV_URL_VAR_RE.findall(src)))
        if env_vars and not _ASSERT_RE.search(src):
            silent.append((it.get("name", "?"), "/".join(env_vars)))
    if silent:
        problems.append(
            f"  {len(silent)} SILENT environment guard(s) — skip when a harness variable is "
            f"missing and assert NOTHING. A missing variable is a misconfigured runner, not a "
            f"legal mode: newman leaves no trace of a skipped request, so the check would "
            f"vanish and the suite would still read GREEN. Use gen.py::require_env_url — fail "
            f"naming the variable, then skip. (Operation guards `if (!opId)` are unaffected: a "
            f"create refused on purpose genuinely has nothing to poll.)"
        )
        for nm, vs in silent[:_MAX_REPORTED]:
            problems.append(f"    {nm}  [{vs}]")
        if len(silent) > _MAX_REPORTED:
            problems.append(f"    ... and {len(silent) - _MAX_REPORTED} more")

    report = os.path.join(out_dir, f"{name}.json")
    if not os.path.isfile(report):
        # Absence of a report is already the existing gate's business; say so and
        # do not double-count it as an execution gap.
        return (not problems, f"{name}: {total} items, NO REPORT", problems)

    with open(report, encoding="utf-8") as fh:
        run = json.load(fh).get("run", {})
    executions = run.get("executions", []) or []
    stats = run.get("stats", {}) or {}
    failures = run.get("failures", []) or []

    executed = set()
    lengths = set()
    # position -> transport error, for requests newman attempted but that never
    # produced a response. These carry a cursor position like any other execution,
    # which is exactly why "position seen" cannot stand for "request executed".
    unanswered = {}
    for ex in executions:
        cur = ex.get("cursor") or {}
        pos = cur.get("position")
        if isinstance(cur.get("length"), int):
            lengths.add(cur["length"])
        if not isinstance(pos, int):
            continue
        err = _transport_error(ex)
        if err is None:
            executed.add(pos)
        else:
            # A later retry of the same position CAN succeed (self-loop polls);
            # one answered attempt is enough to call the position executed.
            unanswered.setdefault(pos, err)
    for pos in list(unanswered):
        if pos in executed:
            del unanswered[pos]

    # Cross-check: the report must describe THIS collection.
    if lengths and total not in lengths:
        problems.append(
            f"  report/collection mismatch: collection has {total} leaf items, "
            f"report cursors say {sorted(lengths)} — stale or mismatched report"
        )

    # ── THE FOURTH STATE: asserted, but never executed ───────────────────────
    #
    # `run.executions` is NOT the complete record of what ran, and this gate walked
    # only that array. Measured on the production-posture run of 2026-07-30: an item
    # that skips its own request from the pre-request script gets NO execution record
    # at all, while its assertions still count in `run.stats` and still appear in
    # `run.failures`. In `iam-user.json` the array accounted for 121 failed assertions
    # against a summary of 137; the missing sixteen belonged to items with zero
    # execution entries. Four iam collections carried the same shape.
    #
    # For THIS gate the wrong number is the smaller half of the problem. The items
    # that disappear are precisely the guarded ones — and a guard is what this gate
    # accepts as the explanation "nothing was lost here". So a guard that fired,
    # asserted and FAILED was being filed as a legal silent skip: the gate reported
    # the opposite of what happened, in the one place it was least able to notice.
    #
    # Hence the failure list is consulted as evidence of execution. A step named there
    # RAN — whatever the array says — and it is a finding, not a skip.
    asserted_names = set()
    for f in failures:
        src = ((f.get("source") or {}).get("name") or "").strip()
        par = ((f.get("parent") or {}).get("name") or "").strip()
        if src:
            asserted_names.add((par, src))
            asserted_names.add(("", src))
    asserted = set()
    if asserted_names:
        for i, (it, par) in enumerate(zip(leaves, parents)):
            nm = (it.get("name") or "").strip()
            if (par, nm) in asserted_names or ("", nm) in asserted_names:
                asserted.add(i)

    reasons = _explained_skippable(leaves)
    # An unanswered request is NOT explained by a skip guard: the guard says "this
    # request did not run", the transport error says "it ran and got nothing back".
    # Folding the second into the first is how the class hid in the first place.
    # An ASSERTED-but-unexecuted step is not explained by one either — its script ran.
    asserted_gap = sorted(i for i in range(total)
                          if i not in executed and i not in unanswered and i in asserted)
    unexplained = [i for i in range(total)
                   if i not in executed and i not in reasons and i not in unanswered
                   and i not in asserted]
    skipped_ok = [i for i in range(total)
                  if i not in executed and i in reasons and i not in unanswered
                  and i not in asserted]

    pct = (100.0 * len(executed) / total) if total else 100.0
    # Where the numbers come from is part of the report: the left-hand ones are walked
    # from the executions array (which is incomplete by construction), the right-hand
    # ones are the run summary, which is authoritative. Printing both makes "zero
    # findings" distinguishable from "zero read", and makes a future divergence visible
    # instead of silently halving a count.
    s_assert = (stats.get("assertions") or {})
    walked_assertions = sum(len(ex.get("assertions") or []) for ex in executions)
    line = (
        f"{name}: executed {len(executed)}/{total} ({pct:.0f}%)"
        f"{f', {len(skipped_ok)} explained-skip' if skipped_ok else ''}"
        f"{f', {len(asserted_gap)} ASSERTED-NOT-EXECUTED' if asserted_gap else ''}"
        f"{f', {len(unanswered)} UNANSWERED' if unanswered else ''}"
        f"{f', {len(unexplained)} UNEXPLAINED' if unexplained else ''}"
        f"  [summary: {s_assert.get('total', 0)} assertions,"
        f" {s_assert.get('failed', 0)} failed, {len(failures)} listed;"
        f" array walked {walked_assertions}]"
    )

    if asserted_gap:
        problems.append(
            f"  {len(asserted_gap)} step(s) ASSERTED but have no execution record — their "
            f"script ran and the run summary counts their assertions, while the executions "
            f"array does not contain them. A skip guard cannot explain a step that asserted: "
            f"read the verdict from run.stats / run.failures, and fix the step so its check "
            f"either runs or is not written:"
        )
        for i in asserted_gap[:_MAX_REPORTED]:
            problems.append(f"    [{i}] {leaves[i].get('name','?')}")
        if len(asserted_gap) > _MAX_REPORTED:
            problems.append(f"    ... and {len(asserted_gap) - _MAX_REPORTED} more")

    if unanswered:
        problems.append(
            f"  {len(unanswered)} request(s) got NO RESPONSE — attempted, but nothing came "
            f"back (DNS / refused connection / TLS / timeout). This is not a passing check "
            f"and not a skip: the check did not happen. Fix the harness so it can reach the "
            f"endpoint, or delete the check — do not let it read as green:"
        )
        for i in sorted(unanswered)[:_MAX_REPORTED]:
            problems.append(f"    [{i}] {leaves[i].get('name','?')}  <- {unanswered[i]}")
        if len(unanswered) > _MAX_REPORTED:
            problems.append(f"    ... and {len(unanswered) - _MAX_REPORTED} more")

    if unexplained:
        problems.append(
            f"  {len(unexplained)} request(s) never executed and not explained by a "
            f"skipRequest() guard or a forward setNextRequest() jump:"
        )
        for i in unexplained[:_MAX_REPORTED]:
            problems.append(f"    [{i}] {leaves[i].get('name','?')}")
        if len(unexplained) > _MAX_REPORTED:
            problems.append(f"    ... and {len(unexplained) - _MAX_REPORTED} more")

    return (not problems, line, problems)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--collections-glob", default="collections/*.postman_collection.json")
    ap.add_argument("--out-dir", default="out")
    args = ap.parse_args(argv)

    cols = sorted(glob.glob(args.collections_glob))
    if not cols:
        print(f"exec-coverage: no collections matched {args.collections_glob}", file=sys.stderr)
        return 2

    bad = []
    tot_items = tot_exec = 0
    print("===== execution coverage (did every request actually run?) =====")
    for col in cols:
        ok, line, problems = check_collection(col, args.out_dir)
        print(line)
        for p in problems:
            print(p)
        if not ok:
            bad.append(os.path.basename(col).replace(".postman_collection.json", ""))
        # totals for the headline number
        m = re.search(r"executed (\d+)/(\d+)", line)
        if m:
            tot_exec += int(m.group(1))
            tot_items += int(m.group(2))

    if tot_items:
        print(f"TOTAL executed {tot_exec}/{tot_items} ({100.0 * tot_exec / tot_items:.1f}%)")
    if bad:
        print(f"FAIL: execution-coverage gaps in: {' '.join(bad)}", file=sys.stderr)
        return 1
    print("OK: every request either executed or is an explained skip.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
