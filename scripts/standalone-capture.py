#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Частный захват одного запуска Go; файлы не предназначены для публикации."""
import hashlib
import importlib.util
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile

FILES = ("stdout.jsonl", "stderr.log", "go.rc", "census.json")
_spec = importlib.util.spec_from_file_location("standalone_protocol", pathlib.Path(__file__).with_name("standalone_protocol.py"))
protocol = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(protocol)
census = protocol.census


def write_json(path, value):
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as out:
        json.dump(value, out, ensure_ascii=False, indent=2)
        out.write("\n")
    tmp.replace(path)


def identity():
    result = {}
    for name, revision in (("commit", "HEAD"), ("tree", "HEAD^{tree}")):
        value = os.environ.get("STANDALONE_SOURCE_" + name.upper())
        if not value:
            try:
                probe = subprocess.run(["git", "rev-parse", revision], capture_output=True, text=True)
                value = probe.stdout.strip() if probe.returncode == 0 else "unknown"
            except OSError:
                value = "unknown"
        result[name] = value
    return result


def main():
    caller_umask = os.umask(0o077)
    args = sys.argv[1:] or ["-short"]
    capture = None
    manifest = None
    child = None
    interrupted = 0
    try:
        configured = os.environ.get("STANDALONE_DIAGNOSTICS_DIR")
        if configured:
            base = pathlib.Path(configured)
            if not base.is_absolute() or base.resolve() != base:
                raise ValueError("capture должен быть абсолютным путём без ссылок")
            base.mkdir(mode=0o700, parents=True, exist_ok=True)
        else:
            base = pathlib.Path(tempfile.gettempdir()).resolve()
        # Включая TMPDIR по умолчанию: каталог внутри cwd исчез бы с фикстурой.
        if base == pathlib.Path.cwd() or pathlib.Path.cwd() in base.parents:
            raise ValueError("capture расположен внутри фикстуры")
        capture = pathlib.Path(tempfile.mkdtemp(prefix="producer-", dir=base))
        manifest = {"version": 1, "kind": "producer", "source": identity(),
                    "target": "test-standalone", "args": ["go", "test", "./...", *args, "-count=1", "-json"],
                    "complete": False, "captureStatus": "incomplete", "censusStatus": "incomplete",
                    "goRC": None, "parseRC": None, "captureRC": None, "helperRC": None, "outcome": "unknown", "files": {}}
        write_json(capture / "manifest.json", manifest)
        print("Диагностика standalone: " + str(capture / "manifest.json"), flush=True)

        def stop(signum, _frame):
            nonlocal interrupted
            interrupted = signum
            if child is not None and child.poll() is None:
                try:
                    child.send_signal(signum)
                except ProcessLookupError:
                    pass

        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, stop)
        print("пробы модуля: go test ./... %s -count=1 -json" % " ".join(args), flush=True)
        with (capture / "stdout.jsonl").open("wb") as stdout, (capture / "stderr.log").open("wb") as stderr:
            child = subprocess.Popen(manifest["args"], stdout=stdout, stderr=stderr, umask=caller_umask)
            rc = child.wait()
        (capture / "go.rc").write_text(str(rc) + "\n", encoding="ascii")
        manifest["goRC"] = rc
        manifest["captureStatus"] = "complete" if not interrupted else "interrupted"
        manifest["captureRC"] = 0 if not interrupted else 2
        write_json(capture / "manifest.json", manifest)
        try:
            c = census(capture / "stdout.jsonl")
        except (ValueError, UnicodeError):
            manifest["parseRC"] = 2
            manifest["censusStatus"] = "error"
            manifest["helperRC"] = 2
            write_json(capture / "manifest.json", manifest)
            print("НЕ ВЫПОЛНИЛОСЬ: ошибка переписи; исходные потоки сохранены", file=sys.stderr)
            return 2
        write_json(capture / "census.json", c)
        valid = protocol.complete(c) and not interrupted and not (rc == 0 and protocol.helper_rc(c, 0) != 0)
        manifest["complete"] = valid
        manifest["captureStatus"] = "complete" if not interrupted else "interrupted"
        manifest["censusStatus"] = "complete" if valid else "incomplete"
        named, package_only = len(c["namedFailures"]), len(c["packageOnlyFailures"])
        outcome = protocol.outcome(c, rc) if valid else "unknown"
        manifest["outcome"] = outcome
        manifest["parseRC"] = 0 if valid else 2
        manifest["captureRC"] = 0 if not interrupted else 2
        manifest["helperRC"] = protocol.helper_rc(c, rc) if valid else 2
        for name in FILES:
            data = (capture / name).read_bytes()
            manifest["files"][name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        write_json(capture / "manifest.json", manifest)
        print("перепись: пакетов исполнено %d · пакетов с отказом %d · без файлов проб %d · "
              "проб ПРОПУЩЕНО по непостроенной предпосылке %d · пропущено по флагам прогона %d · проб упало %d" %
              (c["passedPackages"], len(c["failedPackages"]), c["skippedPackages"], len(c["unmetSkips"]), c["otherSkips"], named))
        # Полная перепись лежит в census.json; preview явно ограничен.
        print("исход standalone: %s; named failures %d; package failures %d; non-JSON %d" %
              (outcome, named, len(c["failedPackages"]), c["nonJSON"]))
        print("исполнений проб %d · успешных %d · отказавших %d · идентичностей сборки %d · отказов сборки %d" %
              (c["testExecutions"], c["passedTests"], c["failedTests"], len(c["builds"]), sum(a == "fail" for a in c["builds"].values())))
        if named:
            print("ПРОБЫ УПАЛИ: %d именованных отказов; полный список — census.json" % named)
        if package_only:
            print("ОТКАЗЫ ПАКЕТОВ БЕЗ ИМЕНИ ПРОБЫ: %d; первичная причина не установлена" % package_only)
        print("полный вывод и перепись: " + str(capture))
        if not valid:
            print("НЕ ВЫПОЛНИЛОСЬ: диагностика неполна; исходные потоки сохранены", file=sys.stderr)
            return 2
        if manifest["helperRC"] != 0:
            return manifest["helperRC"]
        print("пробы модуля зелены; пропущенное названо числом выше и в успех НЕ зачтено")
        return 0
    except (OSError, ValueError, UnicodeError) as exc:
        # В журнал не попадают произвольные значения исключения из чужого вывода.
        if manifest is not None:
            manifest["complete"] = False
            manifest["captureStatus"] = "error"
            manifest["captureRC"] = 2
            manifest["helperRC"] = 2
            try:
                write_json(capture / "manifest.json", manifest)
            except OSError:
                pass
        print("НЕ ВЫПОЛНИЛОСЬ: ошибка захвата или переписи (%s)" % type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
