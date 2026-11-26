#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Offline artifact validation controls. These fixtures do not run the Go witness."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import subprocess
from unittest.mock import patch
import tempfile
import unittest

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("registered_check_pair", Path(__file__).with_name("registered-check-pair.py"))
pairing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pairing)


def go_event(pkg, action, name="", **fields):
    return {"Package": pkg, "Action": action, **({"Test": name} if name else {}), **fields}


def control(pkg, parent, children=()):
    pkg = pairing.MODULE + "/internal/" + pkg
    events = [go_event(pkg, "start"), go_event(pkg, "run", parent)]
    for child in children:
        name = parent + "/" + child
        events.extend([go_event(pkg, "run", name), go_event(pkg, "pass", name)])
    return [*events, go_event(pkg, "pass", parent), go_event(pkg, "pass")]


class PairTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.out = Path(self.temp.name)
        self.pair = {"id": "a" * 32, "schema": 1, "ci": {},
                     "source": {"head": "b" * 40, "tree": "c" * 40, "coordinate": "handler.go:20:3",
                                "fixture_sha256": dict(zip(pairing.PHASES, ("d"*64, "e"*64))),
                                "table_sha256": dict(zip(pairing.PHASES, ("f"*64, "0"*64)))}}
        self.handler = {"RPC": pairing.RPC, "Producer": pairing.PRODUCER, "Site": pairing.HANDLER,
                        "Coordinate": self.pair["source"]["coordinate"]}
        self.finding = (self.handler["Coordinate"] + ": чтение личности без объявления " + pairing.RPC
                        + " -> " + pairing.PRODUCER + " @ " + pairing.HANDLER)

    def leg(self, phase, mutate=lambda report: None, front_cases=pairing.FRONT_CASES,
            rc=0, pair=None, terminal="pass", duplicate=False):
        pair = pair or self.pair
        src = pair["source"]
        report = {"Phase": phase, "Pair": pair["id"], "Schema": 1, "RPC": pairing.RPC,
                  "Producer": pairing.PRODUCER, "Coordinate": src["coordinate"],
                  "TableSHA256": src["table_sha256"][phase], "FixtureSHA256": src["fixture_sha256"][phase],
                  "Reads": [self.handler, self.handler], "Findings": [] if phase == "lawful" else [self.finding]*2}
        mutate(report)
        name = pairing.TOP + "/" + phase
        pkg = pairing.PACKAGE
        events = [go_event(pkg, "start"), go_event(pkg, "run", pairing.TOP), go_event(pkg, "run", name)]
        if phase == "lawful":
            for nested in [*control("authzguard", pairing.ADMISSION),
                           *control("restfront", pairing.FRONT, front_cases)]:
                events.append(go_event(pkg, "output", name, Output="        " + json.dumps(nested) + "\n"))
        rendered = "    test.go:42: " + pairing.MARKER + json.dumps(report) + "\n"
        for i in range(0, len(rendered), 101):
            events.append(go_event(pkg, "output", name, Output=rendered[i:i+101]))
        events.append(go_event(pkg, terminal, name))
        if duplicate:
            events.extend([go_event(pkg, "run", name), go_event(pkg, "pass", name)])
        events.extend([go_event(pkg, "pass", pairing.TOP), go_event(pkg, "pass")])
        log = b"".join(json.dumps(event).encode() + b"\n" for event in events)
        folder = self.out / phase
        folder.mkdir()
        (folder / "go.jsonl").write_bytes(log)
        pairing.write(folder / "completed.json", {"phase": phase, "command": pairing.command(phase),
                      "go_exit": rc, "pair": pair, "go_environment": dict.fromkeys(pairing.GO_KEYS), "log_sha256": pairing.sha(log)})

    def check(self):
        return pairing.compare(self.out, self.pair)

    def test_complete_pair_keeps_multiplicity(self):
        self.leg("missing_row")
        self.leg("lawful")
        self.assertEqual(self.check()["expected_findings"], [self.finding]*2)

    def test_missing_leg(self):
        self.leg("lawful")
        with self.assertRaises(FileNotFoundError):
            self.check()

    def test_false_green(self):
        self.leg("lawful")
        self.leg("missing_row", lambda r: r.update(Findings=[]))
        with self.assertRaisesRegex(ValueError, "findings differ"):
            self.check()

    def test_missing_multiplicity(self):
        self.leg("lawful")
        self.leg("missing_row", lambda r: r.update(Findings=[self.finding]))
        with self.assertRaisesRegex(ValueError, "findings differ"):
            self.check()

    def test_extra_finding(self):
        self.leg("lawful")
        self.leg("missing_row", lambda r: r["Findings"].append("other"))
        with self.assertRaisesRegex(ValueError, "findings differ"):
            self.check()

    def test_other_head_or_tree_or_run(self):
        for key in ("head", "tree", "id", "ci"):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temp:
                self.out = Path(temp)
                other = copy.deepcopy(self.pair)
                if key in {"head", "tree"}:
                    other["source"][key] = "a" * 40
                else:
                    other[key] = {"GITHUB_RUN_ATTEMPT": "2"} if key == "ci" else "b"*32
                self.leg("lawful")
                self.leg("missing_row", pair=other)
                with self.assertRaisesRegex(ValueError, "identity"):
                    self.check()

    def test_extra_fixture_edit_or_wrong_table(self):
        for field in ("FixtureSHA256", "TableSHA256", "Phase", "Coordinate"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp:
                self.out = Path(temp)
                self.leg("lawful")
                self.leg("missing_row", lambda r: r.update({field: "wrong"}))
                with self.assertRaisesRegex(ValueError, "fixture mismatch"):
                    self.check()

    def test_missing_handler_read(self):
        self.leg("lawful", lambda r: r.update(Reads=[]))
        self.leg("missing_row")
        with self.assertRaisesRegex(ValueError, "missing actual handler"):
            self.check()

    def test_required_mtls_case_absent(self):
        self.leg("lawful", front_cases=pairing.FRONT_CASES[1:])
        self.leg("missing_row")
        with self.assertRaisesRegex(ValueError, "lifecycle"):
            self.check()

    def test_skipped_timed_out_or_duplicate(self):
        for args in ({"terminal": "skip"}, {"rc": 1}, {"duplicate": True}):
            with self.subTest(args=args), tempfile.TemporaryDirectory() as temp:
                self.out = Path(temp)
                self.leg("lawful")
                self.leg("missing_row", **args)
                with self.assertRaises(ValueError):
                    self.check()

    def test_source_detects_ignored_files_and_hidden_checkout_edits(self):
        root = self.out
        for name, data in [(pairing.TABLE, pairing.ROW), (pairing.HANDLER_SOURCE, pairing.CALL),
                           (".gitignore", b"ignored-file\n")]:
            file = root / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(data)
        def git(*args):
            subprocess.run(["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid",
                            "-c", "commit.gpgsign=false", *args], cwd=root, check=True, capture_output=True)
        git("init", "-q")
        git("add", ".")
        git("commit", "-qm", "offline fixture")
        with patch.object(pairing, "ROOT", root):
            src = pairing.source()
            self.assertNotEqual(src["fixture_sha256"]["lawful"], src["fixture_sha256"]["missing_row"])
            self.assertEqual(src["coordinate"], pairing.HANDLER_SOURCE + ":1:1")
            (root / "ignored-file").touch()
            with self.assertRaisesRegex(ValueError, "untracked"):
                pairing.source()
            (root / "ignored-file").unlink()
            git("update-index", "--assume-unchanged", pairing.TABLE)
            (root / pairing.TABLE).write_bytes(pairing.ROW + b"extra edit")
            with self.assertRaisesRegex(ValueError, "differs from HEAD"):
                pairing.source()

    def test_modified_log(self):
        self.leg("lawful")
        self.leg("missing_row")
        with (self.out / "missing_row" / "go.jsonl").open("ab") as f:
            f.write(b"{}\n")
        with self.assertRaisesRegex(ValueError, "log digest"):
            self.check()


if __name__ == "__main__":
    unittest.main()
