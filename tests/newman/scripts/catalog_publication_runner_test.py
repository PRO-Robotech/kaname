#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Проверки чтения квитанций приёмки на синтетических данных."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "catalog_publication_runner", Path(__file__).resolve().parents[3] / ".github/scripts/run-rid-native.py")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class PublicationReceiptControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.evidence = Path(temporary.name)
        self.root = self.evidence / ("case-" + hashlib.sha256(RUNNER.CATALOG_PUBLICATION_TEST.encode()).hexdigest())
        self.root.mkdir()
        self.artifacts = {"kaname": "a" * 64, "kaname-migrator": "b" * 64}
        self.observed = {
            "test": RUNNER.CATALOG_PUBLICATION_TEST, "replicaPIDs": [101, 102],
            "binarySHA256": self.artifacts["kaname"], "migratorSHA256": self.artifacts["kaname-migrator"],
            "firstRevision": "2", "finalRevision": "3", "finalDigest": "sha256:" + "c" * 64,
            "firstConvergenceMs": 501, "secondConvergenceMs": 502, "configuredWindowMs": 15000,
            "unchangedMigrationHead": 20261122000000, "migrationLedgerSHA256": "d" * 64,
            "transport": "production REST TLS presented Bearer", "owner": "migrator follow-publications",
        }
        self.write("test-identity.json", {"testIdentity": RUNNER.CATALOG_PUBLICATION_TEST})
        self.pg_caps = {"containerId": "e" * 64, "memory": 1 << 30, "memorySwap": 1 << 30, "nanoCPUs": 10**9}
        self.write("pg-resource-caps.json", self.pg_caps)
        self.write("pg-ownership.json", {"containerId": self.pg_caps["containerId"], "mounts": []})
        for ordinal, pid in enumerate(self.observed["replicaPIDs"], 1):
            replica = self.root / f"publication-replica-{ordinal}"
            (replica / "process").mkdir(parents=True)
            config = replica / "config.yaml"
            config.write_text("{}\n")
            self.write(f"publication-replica-{ordinal}/process/process.json",
                       {"pid": pid, "binarySHA256": self.artifacts["kaname"], "configSHA256": RUNNER.sha(config)})
            self.write(f"publication-replica-{ordinal}/process/terminal.json", {"pid": pid, "exited": True, "exitCode": 0})
        self.write("publication-native-observations.json", self.observed)

    def write(self, name, value):
        (self.root / name).write_text(json.dumps(value))

    def judge(self):
        return RUNNER.judge_publication_receipt(self.evidence, self.artifacts)

    def test_valid_complete_receipt_is_bound_to_binaries_and_processes(self):
        result = self.judge()
        self.assertTrue(result["ok"])
        self.assertEqual(result["receiptSHA256"], RUNNER.sha(self.root / "publication-native-observations.json"))

    def test_refuses_wrong_identity_hash_revision_window_and_extra_fields(self):
        changes = ({"test": "Other"}, {"binarySHA256": "e" * 64}, {"migratorSHA256": "e" * 64},
                   {"firstRevision": "1"}, {"finalRevision": "2"}, {"replicaPIDs": [101, 101]},
                   {"replicaPIDs": [True, 102]}, {"configuredWindowMs": 30000},
                   {"firstConvergenceMs": 15001}, {"secondConvergenceMs": -1},
                   {"unchangedMigrationHead": True}, {"migrationLedgerSHA256": "unbounded text"},
                   {"transport": "bufconn"}, {"owner": "direct activation"}, {"secret": "must-not-be-projected"})
        for change in changes:
            with self.subTest(change=change):
                self.write("publication-native-observations.json", dict(self.observed, **change))
                with self.assertRaises(RUNNER.Rejected):
                    self.judge()

    def test_refuses_missing_or_failed_replica_terminal_and_changed_config(self):
        terminal = self.root / "publication-replica-2/process/terminal.json"
        original = terminal.read_bytes()
        terminal.unlink()
        with self.assertRaises(RUNNER.Rejected):
            self.judge()
        terminal.write_text(json.dumps({"pid": 102, "exited": True, "exitCode": 1}))
        with self.assertRaises(RUNNER.Rejected):
            self.judge()
        terminal.write_bytes(original)
        (self.root / "publication-replica-2/config.yaml").write_text("different: true\n")
        with self.assertRaises(RUNNER.Rejected):
            self.judge()

    def test_refuses_resource_caps_for_other_container_or_higher_limits(self):
        for change in ({"containerId": "f" * 64}, {"memory": 0}, {"memorySwap": 2 << 30}, {"nanoCPUs": 2 * 10**9}):
            with self.subTest(change=change):
                self.write("pg-resource-caps.json", dict(self.pg_caps, **change))
                with self.assertRaises(RUNNER.Rejected):
                    self.judge()

    def test_refuses_symlink_duplicate_fields_and_oversized_receipt(self):
        receipt = self.root / "publication-native-observations.json"
        original = receipt.read_bytes()
        other = self.evidence / "outside.json"
        other.write_bytes(original)
        receipt.unlink()
        receipt.symlink_to(other)
        with self.assertRaises(RUNNER.Rejected):
            self.judge()
        receipt.unlink()
        receipt.write_bytes(original[:-1] + b',"test":"duplicate"}')
        with self.assertRaises(RUNNER.Rejected):
            self.judge()
        receipt.write_bytes(original + b" " * 16384)
        with self.assertRaises(RUNNER.Rejected):
            self.judge()

    def test_test_judge_requires_all_six_refusals_and_package_terminal(self):
        root, predicates, _ = RUNNER.CASES[RUNNER.CATALOG_PUBLICATION_SUITE]
        rows = [{"Package": RUNNER.PACKAGE, "Test": name, "Action": action}
                for name in [root, *(root + "/" + predicate for predicate in sorted(predicates))]
                for action in ("run", "pass")]
        rows.append({"Package": RUNNER.PACKAGE, "Action": "pass"})
        path = self.evidence / "test.jsonl"
        def judge(values):
            path.write_text("".join(json.dumps(value) + "\n" for value in values))
            return RUNNER.judge_test(path, root, predicates)
        self.assertEqual(judge(rows)["passedTests"], 7)
        skipped = copy.deepcopy(rows)
        skipped[3]["Action"] = "skip"
        extra = rows[:-1] + [{"Package": RUNNER.PACKAGE, "Test": root + "/anonymous/extra", "Action": action}
                             for action in ("run", "pass")] + rows[-1:]
        for invalid in (rows[:-1], rows[:2] + rows[4:], skipped, extra):
            with self.subTest(invalid=invalid):
                with self.assertRaises(RUNNER.Rejected):
                    judge(invalid)


if __name__ == "__main__":
    unittest.main()
