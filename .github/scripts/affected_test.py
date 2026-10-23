# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Пробы выбора затронутого (kaname#707): инъекция настоящим входом дерева — карта и
процессы те же, что исполняет конвейер, — и законный близнец рядом с каждым дефектом.

Исполняются шагом задания `suite` в `e2e-newman.yml` и локально:
`python3 .github/scripts/affected_test.py`.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load(file: str, name: str):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


affected = _load("affected.py", "affected")

MAP = affected.load_map()
WORKFLOWS = HERE.parent / "workflows"
NEWMAN_CASE = "tests/newman/cases/account.py"
GO_FILE = "internal/check/catalog_copy_parity.go"


def _local_titles(sel) -> list[str]:
    real = affected.go_packages
    affected.go_packages = lambda files, with_dependents: (
        {affected.ROOT: ["./internal/check"]}
        if any(f.endswith(".go") for f in files) else {})
    try:
        steps, stands = affected.plan_local(sel, "origin/1266")
    finally:
        affected.go_packages = real
    return [" ".join(s.argv) for s in steps] + [f"STAND {x}" for x in stands]


class Selection(unittest.TestCase):
    def test_newman_case_selects_only_newman_and_its_tree_gates(self):
        sel = affected.select(MAP, [NEWMAN_CASE])
        self.assertFalse(sel.full)
        self.assertEqual({g.id for g in sel.groups},
                         {"go-unit", "tree-gates-newman", "newman-suite", "stand"})
        for job in ("ci.yml:build", "ci.yml:lint", "ci.yml:integration", "ci.yml:proto",
                    "ci.yml:gosec", "ci.yml:standalone", "ci.yml:govulncheck",
                    "docker-build.yml:image"):
            self.assertNotIn(job, sel.jobs, job)
        local = _local_titles(sel)
        self.assertTrue(any("newman-suite-debt.py" in t for t in local), local)
        self.assertTrue(any("vendor_provenance_test.py" in t for t in local), local)
        for alien in ("go vet", "golangci-lint", "proto-lint", "govulncheck", "go test -race"):
            self.assertFalse(any(alien in t for t in local), (alien, local))

    def test_go_package_selects_its_tests_and_linter(self):
        sel = affected.select(MAP, [GO_FILE])
        self.assertFalse(sel.full)
        self.assertIn("go-build", {g.id for g in sel.groups})
        self.assertIn("ci.yml:lint", sel.jobs)
        local = _local_titles(sel)
        self.assertIn("go test -race -count=1 ./internal/check", local)
        self.assertIn("golangci-lint run --timeout=10m ./internal/check/", local)
        self.assertNotIn("e2e-newman.yml:suite", sel.jobs)
        self.assertFalse(any("newman-suite-debt" in t for t in local), local)

    def test_empty_diff_is_void_not_green(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt") as empty, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(affected.main(["--files-from", empty.name]), affected.VOID)
            self.assertEqual(affected.main(["--files-from", empty.name, "--run"]), affected.VOID)

    def test_selection_map_change_selects_everything(self):
        sel = affected.select(MAP, [".github/ci-paths.json"])
        self.assertTrue(sel.full)
        self.assertEqual(sorted(MAP.all_jobs()), sel.jobs)

    def test_unclaimed_path_selects_everything(self):
        m = affected.PathMap(full_bases=["main"], full_on=[], always=[], detectors={},
                             groups=[affected.Group("g", "", ["a.yml:x"], ["src/**"])])
        self.assertTrue(affected.select(m, ["elsewhere/file"]).full)
        self.assertFalse(affected.select(m, ["src/file"]).full)  # законный близнец

    def test_catch_all_pattern_is_not_coverage(self):
        # Дефект приёмки kaname#707: группа с `**` «заявляла» любой путь, и запасной ход к
        # полному прогону не срабатывал никогда.
        m = affected.PathMap(full_bases=["main"], full_on=[], always=[], detectors={},
                             groups=[affected.Group("any", "", ["a.yml:u"], ["**"]),
                                     affected.Group("src", "", ["a.yml:x"], ["src/**"])])
        sel = affected.select(m, ["elsewhere/file"])
        self.assertTrue(sel.full)
        self.assertIn("elsewhere/file", sel.reason)
        twin = affected.select(m, ["src/file"])  # законный близнец: путь опознан узким образцом
        self.assertFalse(twin.full)
        self.assertEqual(twin.jobs, ["a.yml:u", "a.yml:x"])

    def test_universal_pattern_forms(self):
        for p in ("**", "**/*", "**/**"):
            self.assertTrue(affected._universal(p), p)
        for p in ("*", "**/*.go", "tests/**", "*.mk", "**/go.mod", "tests/newman/**"):
            self.assertFalse(affected._universal(p), p)

    def test_path_outside_the_map_selects_everything(self):
        for f in ("brand-new-top-level-dir/file.txt", "README.md"):
            sel = affected.select(MAP, [f])
            self.assertTrue(sel.full, f)
            self.assertEqual(sorted(MAP.all_jobs()), sel.jobs, f)
            self.assertIn(f, sel.reason)
        # законный близнец: путь известного класса выбирает только своё
        sel = affected.select(MAP, [NEWMAN_CASE])
        self.assertFalse(sel.full)
        self.assertLess(len(sel.jobs), len(MAP.all_jobs()))

    def test_workflow_file_selects_its_own_jobs(self):
        sel = affected.select(MAP, [".github/workflows/docker-build.yml"])
        self.assertIn("docker-build.yml:image", sel.jobs)
        self.assertNotIn("e2e-newman.yml:chart-own", sel.jobs)
        self.assertNotIn("docker-build.yml:image", affected.select(MAP, [NEWMAN_CASE]).jobs)

    def test_glob(self):
        self.assertTrue(affected.matches("a.go", ["**/*.go"]))
        self.assertTrue(affected.matches("x/y/a.go", ["**/*.go"]))
        self.assertFalse(affected.matches("x/a.gox", ["**/*.go"]))
        self.assertTrue(affected.matches("services/vpc/deploy/a", ["services/*/deploy/**"]))
        self.assertFalse(affected.matches("services/vpc/x/deploy/a", ["services/*/deploy/**"]))


class EventMode(unittest.TestCase):
    def test_only_draft_into_epic_branch_is_targeted(self):
        self.assertFalse(affected.event_mode(MAP, "pull_request", "true", "1266")[0])
        self.assertTrue(affected.event_mode(MAP, "pull_request", "false", "1266")[0])
        self.assertTrue(affected.event_mode(MAP, "pull_request", "true", "main")[0])
        self.assertTrue(affected.event_mode(MAP, "push", "", "")[0])
        self.assertTrue(affected.event_mode(MAP, "workflow_dispatch", "", "")[0])

    def test_detector_on_ready_request_writes_full_without_network(self):
        with tempfile.NamedTemporaryFile("r", suffix=".out") as out:
            env = {"EVENT": "pull_request", "DRAFT": "false", "BASE": "1266",
                   "GITHUB_OUTPUT": out.name}
            old = {k: os.environ.get(k) for k in env}
            os.environ.update(env)
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(affected.detector(MAP, "ci.yml"), affected.GREEN)
            finally:
                for k, v in old.items():
                    os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
            self.assertIn("full=true", Path(out.name).read_text())


class Wiring(unittest.TestCase):
    def test_tree_wiring_matches_the_map(self):
        self.assertEqual(affected.check_wiring(MAP, WORKFLOWS), [])

    def _copy(self) -> Path:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        shutil.copytree(WORKFLOWS, tmp / "wf")
        return tmp / "wf"

    def test_job_without_selection_condition_is_found(self):
        wf = self._copy()
        p = wf / "ci.yml"
        text = p.read_text(encoding="utf-8")
        line = ("    if: ${{ needs.changes.outputs.full == 'true' || contains(fromJSON("
                "needs.changes.outputs.jobs || '[]'), 'lint') }}\n")
        self.assertIn(line, text)
        p.write_text(text.replace(line, ""), encoding="utf-8")
        found = affected.check_wiring(MAP, wf)
        self.assertEqual(len(found), 1, found)
        self.assertIn("ci.yml:lint", found[0])

    def test_job_missing_from_map_is_found(self):
        m = affected.load_map()
        for g in m.groups:
            g.jobs = [j for j in g.jobs if j != "ci.yml:govulncheck"]
        m.groups = [g for g in m.groups if g.jobs]
        found = affected.check_wiring(m, WORKFLOWS)
        self.assertTrue(any("ci.yml:govulncheck" in f and "ни в одной группе" in f
                            for f in found), found)

    def test_map_entry_without_job_is_found(self):
        m = affected.load_map()
        m.groups[0].jobs.append("ci.yml:no-such-job")
        found = affected.check_wiring(m, WORKFLOWS)
        self.assertTrue(any("ci.yml:no-such-job" in f and "без предмета" in f for f in found),
                        found)


class PrAggregate(unittest.TestCase):
    def _call(self, needs: dict, draft: str) -> tuple[int, str]:
        env = {"EVENT": "pull_request", "DRAFT": draft, "NEEDS": json.dumps(needs)}
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                rc = affected.pr_aggregate(MAP, "ci.yml")
        finally:
            for k, v in old.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        return rc, buf.getvalue()

    def _needs(self, result_of=lambda j: "success"):
        jobs = sorted({j.split(":")[1] for j in MAP.all_jobs() if j.startswith("ci.yml:")})
        out = {j: {"result": result_of(j)} for j in jobs}
        out["changes"] = {"result": "success"}
        return out

    def test_draft_with_green_selection_is_red_and_says_n_of_m(self):
        needs = self._needs(lambda j: "success" if j == "unit" else "skipped")
        rc, out = self._call(needs, "true")
        self.assertEqual(rc, affected.RED)
        # знаменатель — задания процесса из карты, а не выписанное число
        total = len(needs) - 1
        self.assertGreater(total, 1)
        self.assertIn(f"целевой прогон: 1 заданий из {total}", out)
        self.assertIn("целевой зелёный", out)

    def test_full_run_all_green_is_green(self):
        rc, _ = self._call(self._needs(), "false")
        self.assertEqual(rc, affected.GREEN)

    def test_full_run_with_a_skip_is_red(self):
        rc, out = self._call(self._needs(lambda j: "skipped" if j == "lint" else "success"),
                             "false")
        self.assertEqual(rc, affected.RED)
        self.assertIn("не исполнено: lint", out)

    def test_needs_not_matching_the_map_is_void(self):
        needs = self._needs()
        needs.pop("lint")
        rc, _ = self._call(needs, "false")
        self.assertEqual(rc, affected.VOID)


if __name__ == "__main__":
    unittest.main()
