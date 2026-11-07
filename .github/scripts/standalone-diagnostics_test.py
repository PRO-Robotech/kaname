#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Поведенческие пробы границы публикации; сырые фикстуры только синтетические."""
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock
import shutil
import subprocess
import sys

spec = importlib.util.spec_from_file_location("standalone_export", pathlib.Path(__file__).with_name("standalone-diagnostics.py"))
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)
root = pathlib.Path(__file__).resolve().parents[2]
capture_spec = importlib.util.spec_from_file_location("standalone_capture", root / "scripts/standalone-capture.py")
producer = importlib.util.module_from_spec(capture_spec)
capture_spec.loader.exec_module(producer)


class ExportControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = pathlib.Path(self.tmp.name).resolve()
        self.src, self.dst = self.base / "private", self.base / "public"
        self.src.mkdir()

    def capture(self):
        directory = self.src / "producer-test"
        directory.mkdir()
        # Короткий секрет проверяется по имени JSON, Bearer — по форме.
        self.secret = "секрет-по-имени"
        self.bearer = "Bearer AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
        event = {"Action": "output", "Package": "example.test/diagnostics", "Test": "TestContext",
                 "Output": json.dumps({"password": self.secret, "cause": "первичная причина"}, ensure_ascii=False)+"\n"}
        terminal = {"Action": "fail", "Package": "example.test/diagnostics", "Test": "TestContext"}
        package = {"Action": "fail", "Package": "example.test/diagnostics"}
        raw = "".join(json.dumps(e, ensure_ascii=False)+"\n" for e in (event, terminal, package)).encode()
        (directory / "stdout.jsonl").write_bytes(raw)
        (directory / "stderr.log").write_text("контекст stderr " + self.bearer + "\n", encoding="utf-8")
        (directory / "go.rc").write_text("1\n")
        (directory / "census.json").write_text(json.dumps(producer.census(directory / "stdout.jsonl")))
        m = {"version": 1, "kind": "producer", "complete": True, "goRC": 1, "parseRC": 0, "captureRC": 0, "helperRC": 1, "captureStatus": "complete", "censusStatus": "complete", "outcome": "named", "source": {"commit": "a"*40, "tree": "b"*40}, "files": {}}
        for name in exporter.PRODUCER_FILES - {"manifest.json"}:
            m["files"][name] = exporter.digest((directory / name).read_bytes())
        (directory / "manifest.json").write_text(json.dumps(m))
        return directory

    def published(self):
        return "\n".join(p.read_text() for p in self.dst.rglob("*") if p.is_file())

    def rejected(self, limit=exporter.MAX_BYTES):
        self.assertEqual(exporter.export(self.src, self.dst, limit), 1)
        self.assertEqual([p.name for p in self.dst.iterdir()], ["export.json"])
        self.assertFalse(json.loads((self.dst / "export.json").read_text())["complete"])
        self.assertNotIn(self.secret, self.published())
        self.assertNotIn(self.bearer, self.published())

    def test_clean_copy_preserves_context_and_accounts_every_event(self):
        self.capture()
        self.assertEqual(exporter.export(self.src, self.dst), 0)
        published = self.published()
        self.assertNotIn(self.secret, published)
        self.assertNotIn(self.bearer, published)
        self.assertIn("example.test/diagnostics", published)
        self.assertIn("TestContext", published)
        self.assertIn("первичная причина", published)
        self.assertIn("контекст stderr", published)
        stream = next(self.dst.glob("capture-*/stdout.jsonl"))
        self.assertEqual(len([json.loads(line) for line in stream.read_text().splitlines()]), 3)
        report = json.loads((self.dst / "export.json").read_text())
        self.assertTrue(report["complete"])
        entry = report["captures"][0]["files"]["stdout.jsonl"]
        self.assertNotEqual(entry["raw"]["sha256"], entry["public"]["sha256"])
        self.assertEqual(entry["public"], exporter.digest(stream.read_bytes()))

    def test_bad_inputs_never_publish_raw(self):
        for mode in ("missing", "malformed", "symlink", "incomplete", "changed", "unknown", "mismatch"):
            with self.subTest(mode=mode):
                if self.dst.exists():
                    shutil.rmtree(self.dst)
                shutil.rmtree(self.src)
                self.src.mkdir()
                directory = self.capture()
                if mode == "missing":
                    (directory / "stderr.log").unlink()
                elif mode == "malformed":
                    (directory / "manifest.json").write_text("{сломано")
                elif mode == "symlink":
                    (directory / "stderr.log").unlink()
                    (directory / "stderr.log").symlink_to(directory / "stdout.jsonl")
                elif mode == "incomplete":
                    m = json.loads((directory / "manifest.json").read_text())
                    m["complete"] = False
                    (directory / "manifest.json").write_text(json.dumps(m))
                elif mode == "changed":
                    (directory / "stderr.log").write_text(self.secret)
                elif mode == "unknown":
                    (directory / "private.env").write_text(self.secret)
                elif mode == "mismatch":
                    m = json.loads((directory / "manifest.json").read_text())
                    c = json.loads((directory / "census.json").read_text())
                    c["events"] = 4
                    (directory / "census.json").write_text(json.dumps(c))
                    m["files"]["census.json"] = exporter.digest((directory / "census.json").read_bytes())
                    (directory / "manifest.json").write_text(json.dumps(m))
                self.rejected()

    def test_size_boundary_has_positive_twin(self):
        self.capture()
        size = sum(p.stat().st_size for p in self.src.rglob("*") if p.is_file())
        self.rejected(size - 1)
        shutil.rmtree(self.dst)
        # Достаточный предел того же входа разрешает именно очищенный payload.
        self.assertEqual(exporter.export(self.src, self.dst, size * 4), 0)

    def test_empty_capture_cannot_be_complete(self):
        self.secret, self.bearer = "не должно быть", "нет секрета"
        self.rejected()

    def test_runner_log_is_cleaned_and_cleanup_failure_has_no_raw_fallback(self):
        directory = self.capture()
        runner = self.src / "target-test"
        runner.mkdir()
        (runner / "runner.json").write_text(json.dumps({"version": 1, "kind": "runner", "complete": True, "rc": 2, "target": "test-standalone"}))
        (runner / "target.log").write_text("контекст runner " + self.bearer + "\n")
        self.assertEqual(exporter.export(self.src, self.dst), 0)
        self.assertIn("контекст runner", self.published())
        self.assertNotIn(self.bearer, self.published())
        shutil.rmtree(self.dst)
        with mock.patch.object(exporter, "text_clean", side_effect=ValueError("синтетический отказ очистки")):
            self.rejected()

    def test_path_escape_is_refused(self):
        self.capture()
        link = self.base / "linked"
        link.symlink_to(self.src, target_is_directory=True)
        with self.assertRaises(ValueError):
            exporter.export(link, self.dst)
        self.assertFalse(self.dst.exists())

    def critical_fixture(self, events, rc=1, stderr=""):
        # Каждый подслучай получает отдельный capture; hashes всегда пересчитываются.
        for path in (self.src, self.dst):
            if path.exists():
                shutil.rmtree(path)
        self.src.mkdir()
        directory = self.capture()
        (directory / "stdout.jsonl").write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events))
        (directory / "stderr.log").write_text(stderr)
        (directory / "go.rc").write_text(str(rc) + "\n")
        census = producer.census(directory / "stdout.jsonl")
        (directory / "census.json").write_text(json.dumps(census))
        manifest = json.loads((directory / "manifest.json").read_text())
        manifest["goRC"] = rc
        manifest["helperRC"] = 1 if rc or census["namedFailures"] or census["failedPackages"] else 0
        manifest["outcome"] = ("mixed" if census["namedFailures"] and census["packageOnlyFailures"] else
                               "named" if census["namedFailures"] else "package" if census["failedPackages"] else
                               "pass" if rc == 0 else "unknown")
        self.critical_rehash(directory, manifest)
        return directory

    def critical_rehash(self, directory, manifest=None):
        if manifest is None:
            manifest = json.loads((directory / "manifest.json").read_text())
        for name in exporter.PRODUCER_FILES - {"manifest.json"}:
            manifest["files"][name] = exporter.digest((directory / name).read_bytes())
        (directory / "manifest.json").write_text(json.dumps(manifest))

    @staticmethod
    def critical_events(outputs=(), package="example.test/diagnostics", test="TestContext", action="fail"):
        return ([{"Action": "output", "Package": package, "Test": test, "Output": text} for text in outputs] +
                [{"Action": action, "Package": package, "Test": test}, {"Action": action, "Package": package}])

    def test_critical_multiline_secret_boundaries_all_channels(self):
        forms = {
            "json": ('{"password":\n"s3cr",\n"cause":"безопасная причина"\n}\n', ["s3cr"], False),
            "pem": ("-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n", ["c2VjcmV0"], False),
            "pem_tail": ("-----BEGIN PRIVATE KEY-----\n" + "QmFzZTY0" * 12 + "\ndGFpbA==\n-----END PRIVATE KEY-----\n", ["QmFzZTY0", "dGFpbA=="], False),
            "unfinished_json": ('{"password":\n"s3cr"\n', ["s3cr"], True),
            "unfinished_pem": ("-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n", ["c2VjcmV0"], True),
        }
        for channel in ("stderr", "runner", "one_output", "split_output"):
            with self.subTest(channel=channel, form="законный близнец"):
                benign = '{"cause":\n"безопасная причина",\n"detail":"вторая строка"\n}\n'
                events = self.critical_events([benign])
                directory = self.critical_fixture(events, stderr=benign if channel == "stderr" else "")
                if channel == "runner":
                    self.critical_runner(benign)
                if channel == "split_output":
                    events = self.critical_interleaved(benign)
                    directory = self.critical_fixture(events)
                self.assertEqual(exporter.export(self.src, self.dst), 0)
                self.assertIn("безопасная причина", self.published())
                self.assertIn("вторая строка", self.published())
                self.assertEqual(len(next(self.dst.glob("capture-*/stdout.jsonl")).read_text().splitlines()), len(events))
            for form, (body, fragments, unfinished) in forms.items():
                with self.subTest(channel=channel, form=form):
                    events = self.critical_events([body] if channel == "one_output" else ["безопасная причина\n"])
                    if channel == "split_output":
                        events = self.critical_interleaved(body)
                    self.critical_fixture(events, stderr=body if channel == "stderr" else "")
                    if channel == "runner":
                        self.critical_runner(body)
                    code = exporter.export(self.src, self.dst)
                    if not unfinished:
                        self.assertEqual(code, 0, "завершённая поддерживаемая форма должна очищаться")
                    else:
                        self.assertIn(code, (0, 1), "оборванная форма очищается целиком либо закрывает экспорт")
                    for fragment in fragments:
                        self.assertNotIn(fragment, self.published(), "публикация раскрыла часть многострочного секрета")
                    if code == 0:
                        stream = next(self.dst.glob("capture-*/stdout.jsonl"))
                        self.assertEqual(len(stream.read_text().splitlines()), len(events))
                        self.assertIn("TestContext", self.published())

    def critical_runner(self, text):
        runner = self.src / "runner-test"
        runner.mkdir()
        (runner / "runner.json").write_text(json.dumps({"version": 1, "kind": "runner", "complete": True, "rc": 1, "target": "test-standalone"}))
        (runner / "target.log").write_text(text)

    def critical_interleaved(self, text):
        events = []
        for line in text.splitlines(keepends=True):
            events.extend([
                {"Action": "output", "Package": "example.test/diagnostics", "Test": "TestContext", "Output": line},
                {"Action": "output", "Package": "example.test/diagnostics", "Test": "TestNeighbor", "Output": "безопасная причина соседней пробы\n"},
            ])
        return events + [{"Action": "pass", "Package": "example.test/diagnostics", "Test": "TestNeighbor"}] + self.critical_events()

    def test_critical_build_events_use_import_path_without_phantom_test_packages(self):
        package, build = "example.test/diagnostics", "example.test/diagnostics [example.test/diagnostics.test]"
        for failed in (False, True):
            with self.subTest(failed=failed):
                events = [{"Action": "build-output", "ImportPath": build if failed else "example.test/dependency", "Output": "контекст сборки\n"}]
                if failed:
                    events += [{"Action": "build-output", "ImportPath": build, "Output": "первичный отказ сборки\n"}, {"Action": "build-fail", "ImportPath": build}]
                events += [{"Action": "start", "Package": package}, {"Action": "output", "Package": package, "Output": "контекст пакета\n"},
                           {"Action": "fail" if failed else "pass", "Package": package, **({"FailedBuild": build} if failed else {})}]
                directory = self.critical_fixture(events, rc=int(failed))
                census = json.loads((directory / "census.json").read_text())
                with self.subTest(boundary="producer"):
                    self.assertEqual(census["unterminatedPackages"], [], "у build-output нет обязательного build-pass")
                    self.assertEqual(census["failedPackages"], [package] if failed else [], "build identity ошибочно посчитана тестовым пакетом")
                with self.subTest(boundary="exporter"):
                    # Независимое ожидание не наследует ошибочное слияние BuildEvent/TestEvent.
                    census.update(unterminatedPackages=[], packages={package: "fail" if failed else "pass"},
                                  failedPackages=[package] if failed else [], packageOnlyFailures=[package] if failed else [],
                                  passedPackages=0 if failed else 1)
                    (directory / "census.json").write_text(json.dumps(census))
                    self.critical_rehash(directory)
                    self.assertEqual(exporter.export(self.src, self.dst), 0)
                    public_events = [json.loads(line) for line in next(self.dst.glob("capture-*/stdout.jsonl")).read_text().splitlines()]
                    self.assertEqual(public_events[-1].get("FailedBuild"), build if failed else None)
                    self.assertIn("контекст сборки", self.published())

    def test_critical_repeated_executions_keep_failures_and_counts(self):
        package, test = "example.test/repeated", "TestRepeated"
        for actions, expected_passes, expected_failures in ((["pass"], 1, []), (["pass", "pass"], 2, []), (["fail", "pass"], 1, [{"package": package, "test": test}])):
            for boundary in ("producer", "exporter"):
                with self.subTest(actions=actions, boundary=boundary):
                    events = []
                    for action in actions:
                        events += [{"Action": "run", "Package": package, "Test": test}, {"Action": action, "Package": package, "Test": test}]
                    events.append({"Action": "fail" if expected_failures else "pass", "Package": package})
                    directory = self.critical_fixture(events, rc=int(bool(expected_failures)))
                    census = json.loads((directory / "census.json").read_text())
                    if boundary == "producer":
                        self.assertEqual(census["passedTests"], expected_passes, "считаются исполнения, включая повторные")
                        self.assertEqual(census["namedFailures"], expected_failures, "последующий pass стёр наблюдённый fail")
                    else:
                        census.update(passedTests=expected_passes, namedFailures=expected_failures, packageOnlyFailures=[])
                        (directory / "census.json").write_text(json.dumps(census))
                        manifest = json.loads((directory / "manifest.json").read_text())
                        manifest["outcome"] = "named" if expected_failures else "pass"
                        self.critical_rehash(directory, manifest)
                        self.assertEqual(exporter.export(self.src, self.dst), 0, "экспорт не согласован с переписью повторных исполнений")
                        public = json.loads(next(self.dst.glob("capture-*/census.json")).read_text())
                        self.assertEqual(public["passedTests"], expected_passes)
                        self.assertEqual(public["namedFailures"], expected_failures)

    def test_critical_new_run_after_terminal_remains_unfinished(self):
        package, test = "example.test/repeated", "TestRepeated"
        events = [{"Action": "run", "Package": package, "Test": test}, {"Action": "pass", "Package": package, "Test": test},
                  {"Action": "run", "Package": package, "Test": test}, {"Action": "pass", "Package": package}]
        directory = self.critical_fixture(events, rc=0)
        self.assertEqual(producer.census(directory / "stdout.jsonl")["unterminatedTests"], [{"package": package, "test": test}])

    def test_critical_typed_census_keeps_static_names_and_cleans_dynamic_subtests(self):
        package = "github.com/PRO-Robotech/kaname/internal/clienttokenwire"
        static = "TestF2_22_CompositionRefusesADegenerateDeclaredNumber"
        credential = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
        for action in ("pass", "fail"):
            with self.subTest(action=action):
                dynamic = static + "/token=" + credential
                events = self.critical_events(package=package, test=static, action=action)[:-1]
                events += self.critical_events(package=package, test=dynamic, action=action)
                directory = self.critical_fixture(events, rc=int(action == "fail"))
                self.assertEqual(exporter.export(self.src, self.dst), 0)
                census = json.loads(next(self.dst.glob("capture-*/census.json")).read_text())
                self.assertEqual(census["packages"], {package: action}, "ключ с token не превращает enum-статус в секрет")
                public_events = [json.loads(line) for line in next(self.dst.glob("capture-*/stdout.jsonl")).read_text().splitlines()]
                self.assertEqual(public_events[0]["Test"], static, "статическое имя пробы потеряло идентичность")
                self.assertNotIn(credential, self.published())
                self.assertTrue(public_events[1]["Test"].startswith(static + "/"))
                self.assertNotEqual(public_events[1]["Test"], static, "динамическая проба слилась с родителем")
                if action == "fail":
                    self.assertEqual([e["test"] for e in census["namedFailures"]], [public_events[0]["Test"], public_events[1]["Test"]])
                report = json.loads((self.dst / "export.json").read_text())
                self.assertEqual(report["captures"][0]["files"]["stdout.jsonl"]["raw"], exporter.digest((directory / "stdout.jsonl").read_bytes()))

    def test_critical_refused_second_export_cannot_publish_previous_complete_capture(self):
        directory = self.capture()
        self.assertEqual(exporter.export(self.src, self.dst), 0)
        first = (self.dst / "export.json").read_bytes()
        (directory / "stderr.log").write_text("состав нового запуска изменён\n")
        command = [sys.executable, str(root / ".github/scripts/standalone-diagnostics.py"), str(self.src), str(self.dst)]
        readiness = self.base / "current-output"
        refused = subprocess.run(command, capture_output=True, text=True, timeout=15,
                                 env=dict(os.environ, GITHUB_OUTPUT=str(readiness)))
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(readiness.read_text(), "ready=false\n", "отказ не разрешает upload предыдущего результата")
        if self.dst.exists():
            self.assertNotEqual((self.dst / "export.json").read_bytes(), first, "отказ B оставил опубликованный complete-A по тому же upload path")
            self.assertFalse(json.loads((self.dst / "export.json").read_text())["complete"])
            self.assertEqual([p.name for p in self.dst.iterdir()], ["export.json"])

    def test_critical_fresh_second_export_has_its_own_bytes(self):
        directory = self.capture()
        self.assertEqual(exporter.export(self.src, self.dst), 0)
        (directory / "stderr.log").write_text("безопасная причина второго запуска\n")
        self.critical_rehash(directory)
        second = self.base / "public-second"
        self.assertEqual(exporter.export(self.src, second), 0)
        self.assertIn("второго запуска", next(second.glob("capture-*/stderr.log")).read_text())

    def test_critical_cli_readiness_names_only_current_success_and_preserves_foreign_directory(self):
        self.capture()
        readiness = self.base / "current-output"
        command = [sys.executable, str(root / ".github/scripts/standalone-diagnostics.py"), str(self.src), str(self.dst)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=15,
                                env=dict(os.environ, GITHUB_OUTPUT=str(readiness)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(readiness.read_text().splitlines(), ["ready=false", "path=" + str(self.dst), "ready=true"])
        self.assertTrue(json.loads((self.dst / "export.json").read_text())["complete"])
        foreign = self.base / "foreign"
        foreign.mkdir()
        (foreign / "keep.txt").write_text("чужой файл")
        readiness.unlink()
        command[-1] = str(foreign)
        refused = subprocess.run(command, capture_output=True, text=True, timeout=15,
                                 env=dict(os.environ, GITHUB_OUTPUT=str(readiness)))
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(readiness.read_text(), "ready=false\n")
        self.assertEqual((foreign / "keep.txt").read_text(), "чужой файл")

    def test_critical_dynamic_aliases_cover_output_stderr_and_runner_without_collisions(self):
        package, static = "example.test/diagnostics", "TestContext"
        names = [static + "/token=s3cr", static + "/token=s4cr"]
        events = []
        for name in names:
            events += self.critical_events(["=== RUN " + name + "\n"], package=package, test=name)[:-1]
        events.append({"Action": "fail", "Package": package})
        self.critical_fixture(events, stderr="\n".join(names))
        self.critical_runner("\n".join(names))
        self.assertEqual(exporter.export(self.src, self.dst), 0)
        published = self.published()
        self.assertNotIn("s3cr", published)
        self.assertNotIn("s4cr", published)
        manifest = json.loads(next(self.dst.glob("capture-*/manifest.json")).read_text())
        aliases = manifest["testAliases"]
        self.assertEqual(len(aliases), 2)
        self.assertEqual(len({entry["test"] for entry in aliases}), 2)
        self.assertEqual([entry["sourceEvents"] for entry in aliases], [[0, 1], [2, 3]])
        census = json.loads(next(self.dst.glob("capture-*/census.json")).read_text())
        self.assertEqual([entry["test"] for entry in census["namedFailures"]], [entry["test"] for entry in aliases])

    def test_critical_rehashed_semantic_contradictions_fail_closed(self):
        mutations = ("parseRC", "captureRC", "helperRC", "outcome", "packageOnlyFailures", "passedTests", "otherSkips", "unmetSkips", "passedPackages", "skippedPackages", "unterminatedPackages", "unterminatedTests", "hidden_package_start", "hidden_test_run")
        for mutation in ("законный близнец", *mutations):
            with self.subTest(mutation=mutation):
                directory = self.critical_fixture(self.critical_events())
                manifest = json.loads((directory / "manifest.json").read_text())
                census = json.loads((directory / "census.json").read_text())
                if mutation in ("parseRC", "captureRC", "helperRC"):
                    manifest[mutation] = 2
                elif mutation == "outcome":
                    manifest["outcome"] = "pass"
                elif mutation in ("passedTests", "otherSkips", "passedPackages", "skippedPackages"):
                    census[mutation] = 1
                elif mutation in ("unmetSkips", "unterminatedTests"):
                    census[mutation] = [{"package": "example.test/diagnostics", "test": "TestContext"}]
                elif mutation in ("packageOnlyFailures", "unterminatedPackages"):
                    census[mutation] = ["example.test/diagnostics"]
                elif mutation in ("hidden_package_start", "hidden_test_run"):
                    event = {"Action": "start", "Package": "example.test/unfinished"} if mutation == "hidden_package_start" else {"Action": "run", "Package": "example.test/diagnostics", "Test": "TestContext"}
                    with (directory / "stdout.jsonl").open("a") as stream:
                        stream.write(json.dumps(event) + "\n")
                    census["events"] += 1
                (directory / "census.json").write_text(json.dumps(census))
                self.critical_rehash(directory, manifest)
                if mutation == "законный близнец":
                    self.assertEqual(exporter.export(self.src, self.dst), 0)
                    self.assertTrue(json.loads((self.dst / "export.json").read_text())["complete"])
                else:
                    self.rejected()

    def test_review_r2_unscoped_build_events(self):
        package = "example.test/diagnostics"
        for failed in (False, True):
            with self.subTest(failed=failed):
                events = [{"ImportPath": "", "Action": "build-output", "Output": "WORK=/tmp/go-build123\n"}]
                if failed:
                    events.append({"ImportPath": "", "Action": "build-fail", "Output": "отказ общей сборки\n"})
                events += [{"Action": "start", "Package": package},
                           {"Action": "run", "Package": package, "Test": "TestContext"},
                           {"Action": "pass", "Package": package, "Test": "TestContext"},
                           {"Action": "pass", "Package": package}]
                directory = self.critical_fixture(events, rc=int(failed))
                # Ожидание независимо от результата production parser.
                expected = {"events": len(events), "nonJSON": 0, "unterminatedPackages": [], "unterminatedTests": [],
                            "packages": {package: "pass"}, "failedPackages": [], "namedFailures": [],
                            "packageOnlyFailures": [], "passedTests": 1, "failedTests": 0, "testExecutions": 1,
                            "unmetSkips": [], "otherSkips": 0, "passedPackages": 1, "skippedPackages": 0,
                            "builds": {"": "fail" if failed else "output"}, "failedBuilds": {}}
                with self.subTest(boundary="producer"):
                    self.assertEqual(json.loads((directory / "census.json").read_text()), expected)
                with self.subTest(boundary="exporter"):
                    (directory / "census.json").write_text(json.dumps(expected))
                    manifest = json.loads((directory / "manifest.json").read_text())
                    manifest["outcome"] = "package" if failed else "pass"
                    self.critical_rehash(directory, manifest)
                    self.assertEqual(exporter.export(self.src, self.dst), 0)
                    public = next(self.dst.glob("capture-*/stdout.jsonl"))
                    self.assertEqual([json.loads(line) for line in public.read_text().splitlines()], events)
                    self.assertEqual(json.loads(public.with_name("census.json").read_text()), expected)
                    self.assertEqual(json.loads(public.with_name("manifest.json").read_text())["outcome"], manifest["outcome"])
        for invalid in ({"Action": "pass", "Package": ""}, {"Action": "pass"}):
            with self.subTest(invalid=invalid):
                directory = self.critical_fixture([invalid] + self.critical_events(action="pass"), rc=0)
                self.assertEqual(json.loads((directory / "census.json").read_text())["nonJSON"], 1)
                self.rejected()

    def test_review_r2_alias_replacement_preserves_each_source(self):
        package = "example.test/diagnostics"
        for names in (("TestContext/ordinary-a", "TestContext/ordinary-b"),
                      ("TestContext/token=very-long-private-value", "TestContext/subtest-000001")):
            with self.subTest(names=names):
                lines = ["причина А: " + names[0] + "\n", "причина Б: " + names[1] + "\n"]
                events = []
                for name, line in zip(names, lines):
                    events += self.critical_events([line], package=package, test=name)[:-1]
                events.append({"Action": "fail", "Package": package})
                self.critical_fixture(events, stderr="".join(lines))
                self.critical_runner("".join(lines))
                self.assertEqual(exporter.export(self.src, self.dst), 0)
                producer_dir = next(path.parent for path in self.dst.glob("capture-*/stdout.jsonl"))
                public = [json.loads(line) for line in (producer_dir / "stdout.jsonl").read_text().splitlines()]
                aliases = ["TestContext/subtest-000001", "TestContext/subtest-000002"]
                expected_lines = ["причина А: " + aliases[0] + "\n", "причина Б: " + aliases[1] + "\n"]
                self.assertEqual(len(public), len(events))
                self.assertEqual([public[i]["Test"] for i in (0, 1, 2, 3)], [aliases[0], aliases[0], aliases[1], aliases[1]])
                for channel, actual in (("Output A", public[0]["Output"]), ("Output B", public[2]["Output"]),
                                        ("stderr", (producer_dir / "stderr.log").read_text()),
                                        ("runner", next(self.dst.glob("capture-*/target.log")).read_text())):
                    with self.subTest(channel=channel):
                        expected = expected_lines[0] if channel == "Output A" else expected_lines[1] if channel == "Output B" else "".join(expected_lines)
                        self.assertEqual(actual, expected)
                manifest = json.loads((producer_dir / "manifest.json").read_text())
                self.assertEqual(manifest["testAliases"], [{"package": package, "test": aliases[0], "sourceEvents": [0, 1]},
                                                         {"package": package, "test": aliases[1], "sourceEvents": [2, 3]}])
                census = json.loads((producer_dir / "census.json").read_text())
                self.assertEqual(census["testExecutions"], 2)
                self.assertEqual(census["failedTests"], 2)
                self.assertEqual({entry["test"] for entry in census["namedFailures"]}, set(aliases))
                self.assertNotIn("very-long-private-value", self.published())

    def test_review_r2_duplicate_members_refuse_public_readiness(self):
        cases = ("unique", "captureRC-2-0", "captureRC-0-2", "parseRC-2-0", "parseRC-0-2", "census", "event")
        for case in cases:
            with self.subTest(case=case):
                directory = self.critical_fixture(self.critical_events(["первичная причина\n"]))
                manifest = json.loads((directory / "manifest.json").read_text())
                if case == "census":
                    path = directory / "census.json"
                    raw = path.read_text()
                    self.assertIn('"test": "TestContext"', raw)
                    path.write_text(raw.replace('"test": "TestContext"', '"test": "TestOther", "test": "TestContext"', 1))
                elif case == "event":
                    path = directory / "stdout.jsonl"
                    raw = path.read_text()
                    self.assertIn('"Action": "output"', raw)
                    path.write_text(raw.replace('"Action": "output"', '"Action": "run", "Action": "output"', 1))
                self.critical_rehash(directory, manifest)
                if case.startswith(("captureRC-", "parseRC-")):
                    field, first, second = case.split("-")
                    path = directory / "manifest.json"
                    raw = path.read_text()
                    needle = json.dumps(field) + ": 0"
                    self.assertIn(needle, raw)
                    path.write_text(raw.replace(needle, json.dumps(field) + ": " + first + ", " + json.dumps(field) + ": " + second, 1))
                readiness = self.base / "readiness-r2"
                readiness.write_text("")
                result = subprocess.run([sys.executable, str(pathlib.Path(exporter.__file__)), str(self.src), str(self.dst)],
                                        env={**os.environ, "GITHUB_OUTPUT": str(readiness)}, capture_output=True, text=True, timeout=15)
                if case == "unique":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("ready=true\n", readiness.read_text())
                    self.assertEqual(json.loads(next(self.dst.glob("capture-*/manifest.json")).read_text())["outcome"], "named")
                else:
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(readiness.read_text(), "ready=false\n")
                    self.assertEqual([path.name for path in self.dst.iterdir()], ["export.json"])
                    self.assertFalse(json.loads((self.dst / "export.json").read_text())["complete"])
                    self.assertNotIn("первичная причина", self.published())

    def test_critical_unknown_nonzero_go_remains_diagnosable(self):
        self.critical_fixture(self.critical_events(["безопасная причина\n"], action="pass"), rc=2)
        self.assertEqual(exporter.export(self.src, self.dst), 0)
        manifest = json.loads(next(self.dst.glob("capture-*/manifest.json")).read_text())
        self.assertEqual(manifest["outcome"], "unknown")
        self.assertEqual(manifest["goRC"], 2)
        self.assertIn("безопасная причина", self.published())


if __name__ == "__main__":
    unittest.main()
