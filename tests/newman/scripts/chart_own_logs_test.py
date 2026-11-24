#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Сбор журнала own: настоящий шаг YAML, метки чарта и синтетический kubectl."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[3]
SECRET = "secret-fixture-only"
BEARER = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"


def wiring():
    workflow = yaml.safe_load((ROOT / ".github/workflows/e2e-newman.yml").read_text())
    job = workflow["jobs"]["chart-own"]
    steps = job["steps"]
    capture = next(step for step in steps if step.get("id") == "own-logs")
    uploads = [step for step in steps if step.get("with", {}).get("name", "").startswith("own-landing-logs-")]
    if len(uploads) != 1:
        raise AssertionError("нужен один артефакт журналов, отдельный для каждой половины")
    upload = uploads[0]
    for step in (capture, upload):
        if step.get("if") not in ("always()", "${{ always() }}") or step.get("continue-on-error"):
            raise AssertionError("сбор и публикация обязательны также после отказа набора")
    artifact_name = upload["with"]["name"]
    halves = [row["half"] for row in job["strategy"]["matrix"]["include"]]
    if set(halves) != {"entry", "keys"} or len(halves) != 2:
        raise AssertionError("перепись должна охватить обе действительные половины own")
    names = [artifact_name.replace("${{ matrix.half }}", half) for half in halves]
    if len(set(names)) != len(halves) or upload["with"].get("if-no-files-found") != "error":
        raise AssertionError("пустой или общий для двух половин артефакт недопустим")
    if not upload.get("uses", "").startswith("actions/upload-artifact@"):
        raise AssertionError("шаг обязан публиковать артефакт")
    if not steps.index(capture) < steps.index(upload) < next(i for i, step in enumerate(steps) if "stand-chart.sh down" in step.get("run", "")):
        raise AssertionError("журнал собирается и публикуется до сноса")
    # Разбирается именно карта меток шаблона pod; весь Go-template Helm не
    # исполняется. Значение name берётся из действительного values.yaml.
    chart = (ROOT / "deploy/templates/deployment.yaml").read_text()
    block = re.search(r"(?ms)^  template:\n    metadata:\n      labels:\n(.*?)^      annotations:", chart)
    if block is None:
        raise AssertionError("карта меток pod не найдена")
    name = yaml.safe_load((ROOT / "deploy/values.yaml").read_text())["name"]
    labels = yaml.safe_load(block[1].replace("{{ .Values.name }}", str(name)))
    return capture["run"], upload["with"]["path"], labels


def server_container():
    chart = (ROOT / "deploy/templates/deployment.yaml").read_text()
    block = re.search(r'(?m)^      containers:\n        - name: (.+)\n(?:.*\n){2}          command: (.+)$', chart)
    if block is None:
        raise AssertionError("контейнер сервера не найден в действительном chart")
    if yaml.safe_load(block[2]) != ["/usr/local/bin/kaname", "serve"]:
        raise AssertionError("диагностика обязана адресовать серверный процесс serve")
    name = yaml.safe_load((ROOT / "deploy/values.yaml").read_text())["name"]
    return block[1].replace("{{ .Values.name }}", str(name))


FAKE_KUBECTL = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["TRACE"], "a") as out:
    out.write(json.dumps(args) + "\n")
mode = os.environ["MODE"]
if "get" in args:
    selector = args[args.index("-l") + 1]
    key, value = selector.split("=", 1)
    if mode == "discovery-failed":
        print('{"password":"secret-fixture-only"}', file=sys.stderr)
        sys.exit(9)
    if mode == "discovery-warning":
        print('{"password":"secret-fixture-only"}', file=sys.stderr)
    if mode != "absent" and json.loads(os.environ["LABELS"]).get(key) == value:
        print("pod/kaname-one\npod/kaname-two")
    sys.exit(0)
if "logs" not in args:
    sys.exit(12)
if "-c" not in args or args[args.index("-c") + 1] != os.environ["SERVER_CONTAINER"]:
    sys.exit(13)
if mode == "empty-log":
    sys.exit(0)
original = ['{"why":"первичная причина","password":"secret-fixture-only"}',
            'Authorization: Bearer AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'] + ["поздняя запись " + str(i) for i in range(250)]
# Исходные строки r1 сохранены как отрицательная проба неизвестного текста.
# Положительный поток соответствует настоящему slog.JSONHandler.
lines = [original[0], json.dumps({"message": original[1]})] + [json.dumps({"message": line}, ensure_ascii=False) for line in original[2:]]
if mode == "original-plaintext":
    lines = original
elif mode == "typed-json":
    lines += [json.dumps({"nested": [{"password": "secret-fixture-only", "secret": 432198765}],
                         "ok": True, "absent": None, "count": 7, "ratio": 1.5,
                         "embedded": '{"password":"secret-fixture-only"}'})]
elif mode == "invalid-json" or (mode == "second-invalid" and "pod/kaname-two" in args):
    lines += ['{"password":"secret-fixture-only"']
elif mode == "duplicate-json":
    lines += ['{"password":"secret-fixture-only","password":"other"}']
elif mode == "scalar-json":
    lines += [json.dumps("secret-fixture-only")]
elif mode == "array-json":
    lines += ['[{"password":"secret-fixture-only"}]']
elif mode == "nonfinite-json":
    lines += ['{"number":NaN,"password":"secret-fixture-only"}']
elif mode == "overflow-json":
    lines += ['{"number":1e1000,"password":"secret-fixture-only"}']
for arg in args:
    if arg.startswith("--tail=") and arg != "--tail=-1":
        lines = lines[-int(arg.split("=")[1]):]
print("\n".join("2026-11-13T08:35:19Z " + line for line in lines))
if mode in ("logs-failed", "logs-warning"):
    print('{"password":"secret-fixture-only"}', file=sys.stderr)
    if mode == "logs-failed":
        sys.exit(7)
if mode == "unstructured-stderr":
    print('ошибка запроса: {"password":"secret-fixture-only"}', file=sys.stderr)
    sys.exit(8)
'''


class ChartOwnLogs(unittest.TestCase):
    def run_capture(self, body, public_path, labels, mode="ok"):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            scripts = base / ".github/scripts"
            scripts.mkdir(parents=True)
            cleaner = scripts / "redact-newman-report.py"
            shutil.copyfile(ROOT / ".github/scripts/redact-newman-report.py", cleaner)
            shutil.copyfile(ROOT / ".github/scripts/chart-own-log-admission.py", scripts / "chart-own-log-admission.py")
            if mode == "redaction-failed":
                cleaner.write_text("import pathlib,sys\np=pathlib.Path(sys.argv[sys.argv.index('--out')+1]); p.mkdir(parents=True,exist_ok=True)\n(p/'partial.log').write_text('secret-fixture-only')\nraise SystemExit(2)\n")
            binary = base / "bin"
            binary.mkdir()
            kubectl = binary / "kubectl"
            kubectl.write_text(FAKE_KUBECTL)
            kubectl.chmod(0o700)
            private = base / "runner"
            private.mkdir()
            env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"],
                       RUNNER_TEMP=str(private), KANAME_STAND_CLUSTER="fixture", MODE=mode,
                       LABELS=json.dumps(labels), SERVER_CONTAINER=server_container(), TRACE=str(base / "trace"))
            result = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", body],
                                    cwd=base, env=env, capture_output=True, text=True, timeout=30)
            public = base / public_path
            files = {str(p.relative_to(public)): p.read_text() for p in public.rglob("*") if p.is_file()}
            calls = [json.loads(line) for line in (base / "trace").read_text().splitlines()]
            exposed = result.stdout + result.stderr + "\n".join(files.values())
            self.assertNotIn(SECRET, exposed)
            self.assertNotIn(BEARER, exposed)
            has_raw_secret = (mode not in ("absent", "empty-log") and "--tail=-1" in body and
                              any("logs" in args for args in calls)) or mode == "discovery-failed"
            if has_raw_secret:
                raw = "\n".join(p.read_text() for d in private.glob("kaname-chart-logs.*") for p in d.iterdir() if p.is_file())
                self.assertIn(SECRET, raw, "первичный raw должен сохраниться приватно без изменения")
            return result, files, calls

    def test_actual_chart_and_workflow_preserve_early_cause_and_clean_secrets(self):
        body, path, labels = wiring()
        result, files, calls = self.run_capture(body, path, labels)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(files["capture.rc"], "0\n")
        self.assertEqual(files["redaction.rc"], "0\n")
        self.assertEqual(files["admission.rc"], "0\n")
        census = json.loads(files["admission.json"])
        self.assertTrue(census["complete"])
        self.assertEqual(census["records"], 504)
        for pod in ("kaname-one", "kaname-two"):
            self.assertIn("первичная причина", files[pod + ".json"])
            self.assertIn("поздняя запись 249", files[pod + ".json"])
            document = json.loads(files[pod + ".json"])
            self.assertEqual(document["pod"], "pod/" + pod)
            self.assertEqual(document["container"], server_container())
            self.assertEqual(document["container_log"][0]["kubectl_timestamp"], "2026-11-13T08:35:19Z")
            self.assertEqual(document["container_log"][0]["payload"]["why"], "первичная причина")
        log_calls = [args for args in calls if "logs" in args]
        self.assertEqual(len(log_calls), 2)
        for args in log_calls:
            self.assertIn("--tail=-1", args)
            self.assertEqual(args[args.index("-c") + 1], server_container())
            self.assertNotIn("--all-containers", args)
            self.assertIn("--timestamps", args)
        self.assertNotIn("первичная причина", result.stdout + result.stderr,
                         "сырой журнал нельзя печатать в консоль перед очисткой")

    def test_capture_failures_are_numeric_and_do_not_expose_partial_raw(self):
        body, path, labels = wiring()
        for mode in ("absent", "discovery-failed", "logs-failed", "empty-log", "redaction-failed"):
            with self.subTest(mode=mode):
                result, files, calls = self.run_capture(body, path, labels, mode)
                self.assertNotEqual(result.returncode, 0)
                if mode == "redaction-failed":
                    self.assertEqual(files["redaction.rc"], "2\n")
                    self.assertEqual(set(files), {"redaction-failed.txt", "capture.rc", "admission.rc", "admission.json", "redaction.rc"})
                else:
                    self.assertNotEqual(files["capture.rc"], "0\n")
                if mode in ("absent", "discovery-failed"):
                    self.assertFalse(any("logs" in args for args in calls))

    def test_structured_types_and_named_stderr_are_cleaned_recursively(self):
        body, path, labels = wiring()
        result, files, _ = self.run_capture(body, path, labels, "typed-json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        document = json.loads(files["kaname-one.json"])
        last = document["container_log"][-1]["payload"]
        self.assertEqual(last["count"], 7)
        self.assertEqual(last["ratio"], 1.5)
        self.assertTrue(last["ok"])
        self.assertIsNone(last["absent"])
        self.assertNotIn("432198765", files["kaname-one.json"])
        result, files, _ = self.run_capture(body, path, labels, "logs-failed")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(files["admission.rc"], "0\n")
        self.assertEqual(files["redaction.rc"], "0\n")
        self.assertEqual(set(files), {"capture-failed.txt", "capture.rc", "admission.rc", "admission.json", "redaction.rc"})
        result, files, _ = self.run_capture(body, path, labels, "logs-warning")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(json.loads(files["kaname-one.json"])["kubectl_stderr"]), 1)
        result, files, _ = self.run_capture(body, path, labels, "discovery-warning")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(json.loads(files["discovery.json"])["stderr"]), 1)

    def test_unknown_or_invalid_data_blocks_entire_payload(self):
        body, path, labels = wiring()
        for mode in ("original-plaintext", "invalid-json", "second-invalid", "duplicate-json", "scalar-json", "array-json",
                     "nonfinite-json", "overflow-json", "unstructured-stderr"):
            with self.subTest(mode=mode):
                result, files, _ = self.run_capture(body, path, labels, mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(files["admission.rc"], "2\n")
                self.assertEqual(files["redaction.rc"], "125\n")
                self.assertEqual(set(files), {"admission-failed.txt", "capture.rc", "admission.rc", "admission.json", "redaction.rc"})
                census = json.loads(files["admission.json"])
                self.assertFalse(census["complete"])
                self.assertGreater(census["rejected"], 0)

    def test_original_wrong_selector_and_truncated_tail_have_observable_failure(self):
        body, path, labels = wiring()
        self.assertIn("app=kaname", body)
        result, files, _ = self.run_capture(body.replace("app=kaname", "app.kubernetes.io/name=kaname"), path, labels)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(files["capture.rc"], "0\n")
        self.assertIn("--tail=-1", body)
        result, files, _ = self.run_capture(body.replace("--tail=-1", "--tail=200"), path, labels)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("первичная причина", files["kaname-one.json"],
                         "контрольная мутация должна терять раннюю запись, которую требует положительная проба")


if __name__ == "__main__":
    unittest.main()
