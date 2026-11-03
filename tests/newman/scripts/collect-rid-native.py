#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Combine actual phase reports from one owned RID invocation.

The native producer must pass every required phase, with the same exact generated
collection and test executable. No request/assertion is manufactured here.
Normalized cursor indexes are an explicit projection of actual executed unique
item names onto the complete source collection. The original Newman cursor and
each source-report/record reference remain alongside that projection.
"""
import argparse
import copy
import hashlib
import json
import os
import re
import sys
from pathlib import Path


class InvalidEvidence(Exception):
    pass


def need(value, message):
    if not value:
        raise InvalidEvidence(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def flatten(items):
    for item in items:
        if "request" in item:
            yield item
        else:
            yield from flatten(item.get("item", []))


def combine(collection_path, reports, run_id, executable_sha, expected):
    required = {"nodeSHA256", "runnerSHA256", "toolTreeSHA256", "collectionSHA256", "testExecutableSHA256"}
    need(isinstance(expected, dict) and set(expected) == required and
         all(isinstance(v, str) and re.fullmatch(r"[a-f0-9]{64}", v) for v in expected.values()),
         "external exact tool/source identities required")
    need(expected["testExecutableSHA256"] == executable_sha, "external test executable mismatch")
    raw = collection_path.read_bytes()
    need(digest(raw) == expected["collectionSHA256"], "external collection identity mismatch")
    collection = json.loads(raw)
    stem = collection_path.name.removesuffix(".postman_collection.json")
    need(re.fullmatch(r"registry-installation-rid(?:0[1-9]|1[012])", stem), "invalid RID collection name")
    leaves = list(flatten(collection.get("item", [])))
    names = [x.get("name") for x in leaves]
    need(names and all(isinstance(x, str) and x for x in names) and len(set(names)) == len(names),
         "empty or ambiguous complete source leaf census")
    source_index = {name: i for i, name in enumerate(names)}
    phases = {}
    for folder in collection.get("item", []):
        need("request" not in folder and " — " in folder.get("name", ""), "unnamed source phase")
        case_id = folder["name"].split(" — ", 1)[0]
        need(case_id.startswith(stem + "-") and case_id not in phases, "ambiguous source phase ID")
        phase_names = {x["name"] for x in flatten(folder.get("item", []))}
        need(phase_names, "source phase has no requests")
        phases[case_id] = phase_names
    need(set().union(*phases.values()) == set(names), "incomplete source phase membership")
    seen_phases = set()
    executions, sources = [], []
    assertions = 0
    package_sha = None
    for report in reports:
        report_raw = report.read_bytes()
        doc = json.loads(report_raw)
        case_id = doc.get("caseId")
        need(case_id in phases and case_id not in seen_phases, "unknown or duplicated phase report")
        need(doc.get("ok") is True and doc.get("schemaVersion") == 1, "phase did not succeed")
        need(doc.get("producer") == {"runId": run_id, "testExecutableSHA256": executable_sha},
             "different owned invocation or test executable")
        need(doc.get("collectionSHA256") == digest(raw) and doc.get("collection") == collection,
             "report is not about the exact complete generated collection")
        need(doc.get("newmanVersion") == "6.2.2", "unexpected actual Newman version")
        for identity in ("nodeSHA256", "runnerSHA256", "toolTreeSHA256"):
            need(doc.get(identity) == expected[identity], "phase toolchain differs from external expected identity")
        tree = doc.get("toolTree", {})
        need(tree.get("algorithm") == "rid-tool-tree-v1" and tree.get("requireCacheAttested") is True and
             tree.get("beforeSHA256") == expected["toolTreeSHA256"] and tree.get("afterSHA256") == expected["toolTreeSHA256"] and
             type(tree.get("files")) is int and 0 < tree["files"] <= 32768 and
             type(tree.get("bytes")) is int and 0 < tree["bytes"] <= 256 * 1048576,
             "complete bounded tool tree before/after proof missing")
        current_package = doc.get("newmanPackageSHA256")
        need(isinstance(current_package, str) and re.fullmatch(r"[a-f0-9]{64}", current_package), "invalid package identity")
        if package_sha is None:
            package_sha = current_package
        need(current_package == package_sha, "phases report different Newman package identities")
        counts = doc.get("counts", {})
        need(counts.get("missing") == [] and counts.get("failureCount") == 0, "phase missing/failing outcomes")
        for key in ("unanswered", "failed", "skipped", "wrongOrigin", "unexpectedItems", "emptyAssertionRequests"):
            need(counts.get(key) == 0, "phase census has failures")
        actual = doc.get("run", {}).get("executions", [])
        need(actual, "phase contains no actual executions")
        seen, phase_assertions = set(), 0
        for record_index, ex in enumerate(actual):
            name = ex.get("item", {}).get("name")
            need(name in phases[case_id], "execution belongs to a different phase")
            need(ex.get("sourceLeafIndex") == source_index[name], "wrong source leaf identity")
            need(ex.get("request") and ex.get("response") and not ex.get("requestError"),
                 "request did not produce an answer")
            need(ex.get("actualExpectedOrigin") is True, "request used a different origin")
            checks = ex.get("assertions", [])
            need(checks and all(not a.get("error") and not a.get("skipped") for a in checks),
                 "execution has missing, failed or skipped assertions")
            seen.add(name)
            phase_assertions += len(checks)
            projected = copy.deepcopy(ex)
            projected["cursor"] = {"position": source_index[name], "length": len(leaves), "iteration": 0}
            projected["cursorProjection"] = {
                "kind": "actual-unique-item-name-to-complete-source-index",
                "phase": case_id, "sourceReportSHA256": digest(report_raw), "sourceRecord": record_index,
            }
            executions.append(projected)
        need(seen == phases[case_id], "phase did not execute every declared request")
        need(counts.get("declaredRequests") == len(seen) and counts.get("uniqueRequests") == len(seen)
             and counts.get("requests") == len(actual) and counts.get("assertions") == phase_assertions,
             "reported phase counts disagree with actual executions")
        seen_phases.add(case_id)
        assertions += phase_assertions
        sources.append({"phase": case_id, "reportSHA256": digest(report_raw),
                        "requests": len(actual), "uniqueRequests": len(seen), "assertions": phase_assertions})
    need(seen_phases == set(phases), "not every required phase report is present")
    need({ex["item"]["name"] for ex in executions} == set(names), "whole collection has missing execution")
    return {
        "schemaVersion": 1, "ok": True,
        "producer": {"runId": run_id, "testExecutableSHA256": executable_sha},
        "collectionSHA256": digest(raw), "collection": collection, "expectedIdentities": expected,
        "normalization": "Actual execution records only; cursor is the named source-index projection; nativeCursor retained",
        "sources": sources,
        "run": {"stats": {"requests": {"total": len(executions), "failed": 0},
                          "assertions": {"total": assertions, "failed": 0, "skipped": 0}},
                "failures": [], "executions": executions},
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--collection", type=Path, required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--test-executable-sha256", required=True)
    ap.add_argument("--expected-identities", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("reports", nargs="+", type=Path)
    args = ap.parse_args()
    need(re.fullmatch(r"[A-Za-z0-9-]{16,80}", args.run_id), "invalid owned invocation ID")
    need(re.fullmatch(r"[a-f0-9]{64}", args.test_executable_sha256), "invalid executable identity")
    result = combine(args.collection, args.reports, args.run_id, args.test_executable_sha256, json.loads(args.expected_identities.read_bytes()))
    # Exclusive fresh output: stale reports are never silently replaced/reused.
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(result, out, ensure_ascii=False)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    print(json.dumps({"ok": True, "phases": len(result["sources"]),
                      "requests": result["run"]["stats"]["requests"]["total"],
                      "assertions": result["run"]["stats"]["assertions"]["total"]}))


if __name__ == "__main__":
    try:
        main()
    except (InvalidEvidence, ValueError, OSError, TypeError, KeyError, AttributeError):
        # Never expose raw report data, paths, body content or arbitrary exceptions.
        print(json.dumps({"ok": False, "kind": "incomplete-or-incompatible-actual-RID-evidence"}))
        sys.exit(1)
