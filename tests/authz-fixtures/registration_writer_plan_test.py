#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fixture protocol tests; no Docker daemon, PostgreSQL, or product imports."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).with_name("registration_writer_plan.py")
SPEC = importlib.util.spec_from_file_location("registration_writer_plan", SOURCE)
PLAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PLAN)
ROOT = SOURCE.parents[2]
ACCOUNT = "acc" + "1" * 17


class GenerationProtocol(unittest.TestCase):
    def test_recreate_resets_but_service_restart_retains_exact_assignment(self):
        for prefix, first, second in (
            ("docker:", "a" * 64, "b" * 64),
            ("pod:", "11111111-1111-4111-8111-111111111111",
             "22222222-2222-4222-8222-222222222222"),
        ):
            with self.subTest(route=prefix), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                run, binary = root / "run", root / "bin"
                identity, replacement = prefix + first, prefix + second
                PLAN.generation(run, binary, identity, begin=True)
                config = binary / "registration-writers.json"
                self.assertEqual(PLAN.owned_json(config)["registration-account-writers"]["assignments"], [])
                environment = root / "environment.json"
                environment.write_text(json.dumps({"values": [{"key": "accountAId", "value": ACCOUNT}]}))
                next_config = binary / "registration-writers.next.json"
                result = subprocess.run([sys.executable, str(SOURCE), "--env-file", str(environment),
                                         "--output", str(next_config)], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                assigned = next_config.read_bytes()
                os.replace(next_config, config)
                assignment = PLAN.owned_json(config)["registration-account-writers"]["assignments"]
                self.assertEqual(assignment, [{"account_id": ACCOUNT, "module": "registry",
                                               "assignment_id": "stand-registry-" + ACCOUNT}])
                evidence = {
                    "registration-plan.attempt": b"attempt1\n",
                    "registration-stop.rc": b"0\n",
                    "registration-stop.stderr": b"original stderr\n",
                    "kaname.bootstrap.log": b"bootstrap history\n",
                    "kaname.bootstrap.cid": b"c" * 64,
                }
                for name, body in evidence.items():
                    (run / name).write_bytes(body)
                original_state = (run / "registration-generation.json").read_bytes()
                # The service-only path verifies and retains the same generation;
                # even repeated up preparation cannot reset a still-live identity.
                PLAN.generation(run, binary, identity)
                PLAN.generation(run, binary, identity, begin=True)
                self.assertEqual(config.read_bytes(), assigned)
                self.assertEqual((run / "registration-generation.json").read_bytes(), original_state)
                for name, body in evidence.items():
                    self.assertEqual((run / name).read_bytes(), body)
                with self.assertRaises(ValueError):
                    PLAN.generation(run, binary, replacement)
                self.assertEqual(config.read_bytes(), assigned)
                # A confirmed new PG CID/pod UID is a different stand database.
                PLAN.generation(run, binary, replacement, begin=True)
                self.assertEqual(PLAN.owned_json(config)["registration-account-writers"]["assignments"], [])
                self.assertEqual(PLAN.owned_json(run / "registration-generation.json")["identity"], replacement)
                archives = list(run.glob("registration-history-*"))
                self.assertEqual(len(archives), 1)
                archived = archives[0]
                self.assertEqual((archived / "registration-writers.json").read_bytes(), assigned)
                self.assertEqual((archived / "registration-generation.json").read_bytes(), original_state)
                for name, body in evidence.items():
                    self.assertFalse((run / name).exists())
                    self.assertEqual((archived / name).read_bytes(), body)
                # A new one-use transition marker can be created, with old proof intact.
                with (run / "registration-plan.attempt").open("xb") as output:
                    output.write(b"attempt2\n")
                self.assertEqual((archived / "registration-plan.attempt").read_bytes(), b"attempt1\n")

    def test_foreign_evidence_fails_before_archive_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run, binary = root / "run", root / "bin"
            PLAN.generation(run, binary, "docker:" + "a" * 64, begin=True)
            before = (binary / "registration-writers.json").read_bytes()
            state = (run / "registration-generation.json").read_bytes()
            foreign = root / "foreign"
            foreign.write_bytes(b"keep foreign evidence")
            (run / "registration-stop.rc").symlink_to(foreign)
            with self.assertRaises(ValueError):
                PLAN.generation(run, binary, "docker:" + "b" * 64, begin=True)
            self.assertEqual(foreign.read_bytes(), b"keep foreign evidence")
            self.assertEqual((binary / "registration-writers.json").read_bytes(), before)
            self.assertEqual((run / "registration-generation.json").read_bytes(), state)
            self.assertEqual(list(run.glob("registration-history-*")), [])
            self.assertFalse((run / "registration-generation.lock").exists())

    def test_cli_refuses_missing_duplicate_wildcard_and_foreign_accounts(self):
        for accounts in ([], [ACCOUNT, ACCOUNT], ["*"], ["unknown"]):
            with self.subTest(accounts=accounts), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source, output = root / "environment.json", root / "plan.json"
                source.write_text(json.dumps({"values": [{"key": "accountAId", "value": value}
                                                          for value in accounts]}))
                result = subprocess.run([sys.executable, str(SOURCE), "--env-file", str(source),
                                         "--output", str(output)], capture_output=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())


class LocalReplacementOwnership(unittest.TestCase):
    def test_foreign_name_replacement_is_preserved(self):
        # Execute the exact current shell function with only Docker's external
        # boundary replaced. Sourcing the complete stand would run its CLI.
        script = (ROOT / ".github/scripts/stand-own.sh").read_text()
        begin = script.index("start_service() {")
        end = script.index("\n# Порты собственных слушателей", begin)
        function = script[begin:end]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run, commands = root / "run", root / "commands"
            run.mkdir()
            commands.mkdir()
            foreign = root / "foreign-container"
            foreign.write_text("foreign-immutable-id")
            docker = commands / "docker"
            docker.write_text("""#!/bin/sh
printf '%s\\n' "$*" >> "$TEST_DOCKER_CALLS"
case "$1" in
  rm) rm -f "$TEST_FOREIGN_CONTAINER"; exit 0 ;;
  run) echo 'Conflict: name belongs to foreign-immutable-id' >&2; exit 125 ;;
  *) exit 99 ;;
esac
""")
            docker.chmod(0o755)
            runner = root / "replacement.sh"
            runner.write_text(function + """
fail() { printf '%s\\n' "$*" >&2; }
say() { :; }
listeners_up() { return 1; }
listeners_report() { :; }
ports_count() { printf 8; }
sleep() { command sleep 0.02; }
start_service replacement
""")
            calls = root / "docker-calls"
            env = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ["PATH"],
                       RUNDIR=str(run), BIN=str(root / "bin"), PKI=str(root / "pki"),
                       SERVICE_NAME="fixture-owned-name", SERVICE_MEMORY="1280m",
                       SERVICE_IMAGE="existing-image", SERVICE_TRIES="100",
                       TEST_DOCKER_CALLS=str(calls), TEST_FOREIGN_CONTAINER=str(foreign))
            result = subprocess.run(["bash", str(runner)], env=env, capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(foreign.read_text(), "foreign-immutable-id")
            actual = calls.read_text().splitlines()
            self.assertEqual(len(actual), 1)
            self.assertTrue(actual[0].startswith("run "), actual)
            self.assertIn("--name fixture-owned-name", actual[0])
            self.assertFalse((run / "kaname.cid").exists())


if __name__ == "__main__":
    unittest.main()
