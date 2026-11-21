#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Проверка четырёх сводок RID11 по текущему дереву исходников."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SUITE = "registry-installation-rid11"
GROUPS = ("input", "identity", "proof-authority", "availability")
WORLDS = dict(zip(GROUPS, (16, 16, 16, 14)))
PREDICATES = frozenset({
    "every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair",
    "exact_exit_stage_field_pair_completedPairs;_no_bootstrap_I_fallback_or_self-provision",
    "each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes",
    "real_structured_stdout_stderr_and_absence_of_raw_or_JSON-escaped_credential_key_token_values",
})
TOP_KEYS = frozenset({
    "schemaVersion", "ok", "suite", "status", "sourceRevision", "sourceTree",
    "expectedIdentities", "artifactSHA256", "collectorSHA256", "producerSHA256",
    "runIdSHA256", "testDeadlineSeconds", "outerDeadlineSeconds", "nativeProcessScope",
    "testElapsedMilliseconds", "testExitCode", "test", "phases", "counts", "cleanup", "rid11Group",
})
IDENTITY_KEYS = frozenset({"nodeSHA256", "runnerSHA256", "toolTreeSHA256", "collectionSHA256", "testExecutableSHA256"})
CLEANUP_ZERO = ("processesRemaining", "forcedProcesses", "containersRemaining", "volumesRemaining", "fallbackContainers")
MAX_INPUT_BYTES = 1024 * 1024


class InvalidEvidence(Exception):
    pass


def need(value):
    if not value:
        raise InvalidEvidence()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def hex_value(value, size=64):
    return type(value) is str and re.fullmatch(r"[a-f0-9]{%d}" % size, value) is not None


def integer(value, minimum=0, maximum=10**12):
    return type(value) is int and minimum <= value <= maximum


def exact_keys(value, keys):
    need(type(value) is dict and set(value) == set(keys))


def unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value)
        value[key] = item
    return value


def decode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_INPUT_BYTES)
    return json.loads(raw, object_pairs_hook=unique_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(InvalidEvidence()))


def read_regular(path, maximum=MAX_INPUT_BYTES):
    need(not path.is_symlink() and path.is_file() and 0 < path.stat().st_size <= maximum)
    raw = path.read_bytes()
    need(0 < len(raw) <= maximum)
    return raw


def load_contract(root, collection_path):
    canonical = root / "tests/newman/collections/registry-installation-rid11.postman_collection.json"
    need(collection_path.resolve(strict=True) == canonical.resolve(strict=True))
    raw = read_regular(canonical, 16 * 1024 * 1024)
    collection = json.loads(raw, object_pairs_hook=unique_pairs)
    collector = root / "tests/newman/scripts/collect-rid-native.py"
    spec = importlib.util.spec_from_file_location("rid11_aggregate_collector", collector)
    impl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(impl)
    groups = impl.rid11_phase_groups(collection)
    need(set(groups) == set(GROUPS))
    hashes = {group: frozenset(digest(phase.encode()) for phase in groups[group]) for group in GROUPS}
    need([len(hashes[group]) for group in GROUPS] == [32, 36, 32, 28])
    need(len(set().union(*hashes.values())) == sum(map(len, hashes.values())) == 128)
    unique_requests = {}
    for folder in collection["item"]:
        phase = folder["name"].split(" — ", 1)[0]
        leaves = list(impl.flatten(folder["item"]))
        names = [leaf["name"] for leaf in leaves]
        need(names and len(names) == len(set(names)))
        unique_requests[digest(phase.encode())] = len(names)
    need(set(unique_requests) == set().union(*hashes.values()))
    return {
        "phaseHashes": hashes, "uniqueRequests": unique_requests,
        "collectionSHA256": digest(raw),
        "runnerSHA256": digest(read_regular(root / "tests/newman/scripts/run-rid-native.cjs")),
        "collectorSHA256": digest(read_regular(collector)),
        "producerSHA256": digest(read_regular(root / ".github/scripts/run-rid-native.py")),
    }


def aggregate(receipts, revision, tree, contract):
    need(hex_value(revision, 40) and hex_value(tree, 40))
    exact_keys(receipts, GROUPS)
    common = None
    run_ids, reports, phase_ids = set(), set(), set()
    totals = {"phases": 0, "requests": 0, "assertions": 0}
    groups = []
    merged_phases = []
    for group in GROUPS:
        raw = receipts[group]
        doc = decode(raw)
        exact_keys(doc, TOP_KEYS)
        need(type(doc["schemaVersion"]) is int and doc["schemaVersion"] == 1)
        need(doc["ok"] is True and doc["suite"] == SUITE and doc["status"] == "passed")
        need(doc["rid11Group"] == group and doc["sourceRevision"] == revision and doc["sourceTree"] == tree)
        for name in ("collectorSHA256", "producerSHA256"):
            need(hex_value(doc[name]) and doc[name] == contract[name])
        identities = doc["expectedIdentities"]
        exact_keys(identities, IDENTITY_KEYS)
        need(all(hex_value(value) for value in identities.values()))
        for name in ("collectionSHA256", "runnerSHA256"):
            need(identities[name] == contract[name])
        shared = {key: identities[key] for key in sorted(IDENTITY_KEYS - {"testExecutableSHA256"})}
        if common is None:
            common = shared
        need(shared == common)
        artifacts = doc["artifactSHA256"]
        exact_keys(artifacts, ("kaname", "kaname-migrator", "rid-tests"))
        need(all(hex_value(value) for value in artifacts.values()))
        need(artifacts["rid-tests"] == identities["testExecutableSHA256"])
        run_id = doc["runIdSHA256"]
        need(hex_value(run_id) and run_id not in run_ids)
        run_ids.add(run_id)
        for name, expected in (("testDeadlineSeconds", 1200), ("outerDeadlineSeconds", 1320), ("testExitCode", 0)):
            need(type(doc[name]) is int and doc[name] == expected)
        need(integer(doc["testElapsedMilliseconds"], 1, 1320000))
        scope = doc["nativeProcessScope"]
        exact_keys(scope, ("memoryMaxBytes", "memorySwapMaxBytes", "unprivileged"))
        need(type(scope["memoryMaxBytes"]) is int and scope["memoryMaxBytes"] == 4294967296)
        need(type(scope["memorySwapMaxBytes"]) is int and scope["memorySwapMaxBytes"] == 0 and scope["unprivileged"] is True)
        verdict = doc["test"]
        exact_keys(verdict, ("ok", "passedTests", "skippedTests", "failedTests", "directPredicates"))
        need(verdict["ok"] is True)
        for name, expected in (("passedTests", WORLDS[group] + 5), ("skippedTests", 0), ("failedTests", 0)):
            need(type(verdict[name]) is int and verdict[name] == expected)
        predicates = verdict["directPredicates"]
        need(type(predicates) is list and len(predicates) == 4 and all(type(item) is str for item in predicates))
        need(set(predicates) == PREDICATES)
        cleanup = doc["cleanup"]
        exact_keys(cleanup, (*CLEANUP_ZERO, "ok", "containers", "volumes"))
        need(cleanup["ok"] is True)
        need(all(type(cleanup[name]) is int and cleanup[name] == 0 for name in CLEANUP_ZERO))
        for name in ("containers", "volumes"):
            need(type(cleanup[name]) is int and cleanup[name] == WORLDS[group])
        counts = doc["counts"]
        exact_keys(counts, ("phases", "requests", "assertions"))
        need(all(integer(value, 1) for value in counts.values()))
        phases = doc["phases"]
        need(type(phases) is list and len(phases) == len(contract["phaseHashes"][group]) == counts["phases"])
        observed = set()
        actual_counts = {"phases": len(phases), "requests": 0, "assertions": 0}
        for phase in phases:
            exact_keys(phase, ("phaseSHA256", "reportSHA256", "requests", "uniqueRequests", "assertions"))
            phase_id, report_id = phase["phaseSHA256"], phase["reportSHA256"]
            need(hex_value(phase_id) and phase_id in contract["phaseHashes"][group])
            need(phase_id not in observed and phase_id not in phase_ids)
            need(hex_value(report_id) and report_id not in reports)
            need(all(integer(phase[name], 1) for name in ("requests", "uniqueRequests", "assertions")))
            need(phase["uniqueRequests"] == contract["uniqueRequests"][phase_id])
            need(phase["assertions"] >= phase["requests"] >= phase["uniqueRequests"])
            observed.add(phase_id)
            reports.add(report_id)
            actual_counts["requests"] += phase["requests"]
            actual_counts["assertions"] += phase["assertions"]
        need(observed == contract["phaseHashes"][group] and counts == actual_counts)
        phase_ids.update(observed)
        for name in totals:
            totals[name] += actual_counts[name]
        merged_phases.extend(dict(phase) for phase in phases)
        groups.append({"rid11Group": group, "receiptSHA256": digest(raw), "runIdSHA256": run_id,
                       "artifactSHA256": dict(artifacts), "testExecutableSHA256": identities["testExecutableSHA256"],
                       "counts": dict(counts), "worlds": WORLDS[group], "passedTests": verdict["passedTests"],
                       "testElapsedMilliseconds": doc["testElapsedMilliseconds"]})
    need(len(phase_ids) == totals["phases"] == 128 and len(reports) == 128 and len(run_ids) == 4)
    return {"schemaVersion": 1, "ok": True, "status": "passed", "suite": SUITE,
            "sourceRevision": revision, "sourceTree": tree, "counts": totals, "worlds": 62,
            "sharedIdentities": common, "collectorSHA256": contract["collectorSHA256"],
            "producerSHA256": contract["producerSHA256"], "groups": groups,
            "phases": sorted(merged_phases, key=lambda phase: phase["phaseSHA256"]),
            "test": {"ok": True, "passedTests": sum(WORLDS.values()) + 5 * len(GROUPS),
                     "skippedTests": 0, "failedTests": 0, "directPredicates": sorted(PREDICATES)},
            "perGroupDeadlines": {"testSeconds": 1200, "outerSeconds": 1320},
            "perGroupNativeProcessScope": {"memoryMaxBytes": 4294967296, "memorySwapMaxBytes": 0, "unprivileged": True},
            "cleanup": {"ok": True, "containers": 62, "volumes": 62, **dict.fromkeys(CLEANUP_ZERO, 0)}}


def checkout_identity(root, revision, tree):
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.DEVNULL, timeout=15).decode().strip()
    need(hex_value(revision, 40) and hex_value(tree, 40))
    need(git("rev-parse", "HEAD") == revision and git("rev-parse", "HEAD^{tree}") == tree)
    need(not git("status", "--porcelain", "--untracked-files=all"))


def input_receipts(input_dir):
    need(input_dir.is_dir() and not input_dir.is_symlink())
    folders = {SUITE + "-" + group for group in GROUPS}
    need({item.name for item in input_dir.iterdir()} == folders)
    receipts = {}
    for group in GROUPS:
        folder = input_dir / (SUITE + "-" + group)
        need(folder.is_dir() and not folder.is_symlink())
        need({item.name for item in folder.iterdir()} == {"rid11-summary.json"})
        receipts[group] = read_regular(folder / "rid11-summary.json")
    return receipts


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise InvalidEvidence()


def main():
    failure = {"schemaVersion": 1, "ok": False, "suite": SUITE, "status": "aggregate-evidence-rejected"}
    result = failure
    output = None
    try:
        parser = SafeParser(description=__doc__)
        parser.add_argument("--source-revision", required=True)
        parser.add_argument("--source-tree", required=True)
        parser.add_argument("--collection", type=Path, required=True)
        parser.add_argument("--input-dir", type=Path, required=True)
        parser.add_argument("--out", type=Path, required=True)
        args = parser.parse_args()
        need(args.out.is_absolute() and args.input_dir.is_absolute() and args.collection.is_absolute())
        need(not args.out.exists() and not args.out.is_symlink())
        candidate = args.out.resolve()
        need(candidate != ROOT and ROOT not in candidate.parents)
        need(candidate != args.input_dir.resolve() and args.input_dir.resolve() not in candidate.parents)
        output = candidate
        checkout_identity(ROOT, args.source_revision, args.source_tree)
        contract = load_contract(ROOT, args.collection)
        result = aggregate(input_receipts(args.input_dir), args.source_revision, args.source_tree, contract)
        checkout_identity(ROOT, args.source_revision, args.source_tree)
        need(load_contract(ROOT, args.collection) == contract)
    except Exception:
        result = failure
    if output is not None:
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("x", encoding="utf-8") as stream:
                json.dump(result, stream, sort_keys=True)
                stream.write("\n")
        except Exception:
            result = failure
    print(json.dumps({"ok": result["ok"], "status": result["status"]}, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
