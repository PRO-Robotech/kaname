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

    executed = set()
    lengths = set()
    for ex in executions:
        cur = ex.get("cursor") or {}
        pos = cur.get("position")
        if isinstance(pos, int):
            executed.add(pos)
        if isinstance(cur.get("length"), int):
            lengths.add(cur["length"])

    # Cross-check: the report must describe THIS collection.
    if lengths and total not in lengths:
        problems.append(
            f"  report/collection mismatch: collection has {total} leaf items, "
            f"report cursors say {sorted(lengths)} — stale or mismatched report"
        )

    reasons = _explained_skippable(leaves)
    unexplained = [i for i in range(total) if i not in executed and i not in reasons]
    skipped_ok = [i for i in range(total) if i not in executed and i in reasons]

    pct = (100.0 * len(executed) / total) if total else 100.0
    line = (
        f"{name}: executed {len(executed)}/{total} ({pct:.0f}%)"
        f"{f', {len(skipped_ok)} explained-skip' if skipped_ok else ''}"
        f"{f', {len(unexplained)} UNEXPLAINED' if unexplained else ''}"
    )

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
