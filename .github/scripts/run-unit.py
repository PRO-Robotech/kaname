#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Два непересекающихся unit-прогона и обязательная перепись их объединения."""

import collections
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

CHECK = "github.com/PRO-Robotech/kaname/internal/check"
TREE = "TestNoDeferredWorkInTheTree"
CENSUS = (
    "TestCensusDirectProducerRouteControls",
    "TestCensusDirectProducerProductionEdges",
    "TestCensusDirectProducerDecisionConfiguration",
    "TestCensusDirectProducerTerminalBranches",
    "TestCensusDirectProducerWriteIntent",
    "TestCensusDirectProducerErrorBinding",
    "TestCensusDirectProducerBooleanContinuation",
    "TestCensusDirectProducerConditionEvaluation",
    "TestCensusRPCProducerRouteControls",
    "TestCensusRPCProductionBindingCounterexamples",
    "TestCensusRPCObserverAndParenthesesControls",
)
FRESHNESS = {
    "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict": (
        "TestMatrixVolumeReportIsFreshAndItsSubjectHasNotMoved",
        "TestMatrixVolumeFreshnessGateCanFailAndCanStaySilent"),
    "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/scalegrid": (
        "TestScaleGridFullReportIsFreshAndItsSubjectHasNotMoved",
        "TestScaleGridFreshnessGateCanFailAndCanStaySilent"),
    "github.com/PRO-Robotech/kaname/tools/authzformbench": (
        "TestBenchReportsAreFreshAndTheirInstrumentHasNotMoved",
        "TestBenchFreshnessGateCanFailAndCanStaySilent"),
}
VERIFIER = Path(__file__).with_name("go-test-verdict.py")
CONTEXT_KEYS = (
    "GITHUB_SHA", "GITHUB_WORKFLOW", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
    "GITHUB_EVENT_NAME", "GITHUB_JOB", "RUNNER_OS", "RUNNER_ARCH",
    "TESTCONTAINERS_RYUK_DISABLED", "TESTCONTAINERS_HOST_OVERRIDE", "KANAME_REQUIRE_INTEGRATION",
    "KACHO_DERIVE_PARENT_COST", "KACHO_PERMANENT_PROJECT_COST", "KACHO_MATRIX_VOLUME",
    "KACHO_SCALEGRID_FULL", "KACHO_STRENGTH_FULL", "KACHO_STRENGTH_WRITE", "KACHO_RECOVERY_TIMING",
)


def pattern(names):
    return "^(" + "|".join(re.escape(name) for name in names) + ")$"


def identity():
    def git(arg):
        return subprocess.check_output(["git", "rev-parse", arg], text=True).strip()
    result = {"head": git("HEAD"), "tree": git("HEAD^{tree}"),
              **{key: os.environ[key] for key in
                 ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}}
    if (not all(re.fullmatch("[0-9a-f]{40}", result[key]) for key in ("head", "tree", "GITHUB_SHA"))
            or result["head"] != result["GITHUB_SHA"]
            or not all(re.fullmatch("[1-9][0-9]*", result[key]) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))):
        raise ValueError("неполная или чужая идентичность исходников/запуска")
    return result


def canonical(raw, log):
    with raw.open("rb") as source, log.open("wb") as output:
        rc = subprocess.run([sys.executable, str(VERIFIER)], stdin=source, stdout=output,
                            stderr=subprocess.STDOUT, check=False).returncode
    print(log.read_text(), end="", flush=True)
    return rc


def command(out, name, args):
    # Сырой поток закрывается до вердикта; отказ первого прогона не отменяет следующий.
    with (out / (name + ".json")).open("wb") as raw:
        try:
            rc = subprocess.run(["go", "test", *args, "-json"], stdout=raw,
                                stderr=subprocess.STDOUT, check=False).returncode
        except OSError as error:
            raw.write((str(error) + "\n").encode())
            rc = 127
    (out / (name + ".go.exitcode")).write_text(str(rc) + "\n")
    verdict = canonical(out / (name + ".json"), out / (name + ".verdict.txt"))
    result = {"go": rc, "canonical": verdict}
    (out / (name + ".rc.json")).write_text(json.dumps(result) + "\n")
    return result


def events(path):
    with path.open() as source:
        for line in source:
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError("событие не является объектом")
            yield event


def inventory(path):
    # -list берёт имена из того же скомпилированного набора и с тем же -race.
    # Benchmark не исполняется обычным go test; Example и Fuzz остаются в покрытии.
    packages = {}
    for event in events(path):
        package = event.get("Package")
        if event.get("Action") == "start":
            if package in packages:
                raise ValueError("повтор пакета в compiled inventory")
            packages[package] = set()
        if event.get("Action") == "output":
            for line in event.get("Output", "").splitlines():
                if re.fullmatch(r"(?:Test|Example|Fuzz)\w*", line):
                    if package not in packages or line in packages[package]:
                        raise ValueError("повтор или бесхозное имя в compiled inventory")
                    packages[package].add(line)
    if not packages or not set((TREE, *CENSUS)) <= packages.get(CHECK, set()):
        raise ValueError("обязательные имена отсутствуют в compiled inventory")
    for package, names in packages.items():
        if package != CHECK and names.intersection((TREE, *CENSUS)):
            raise ValueError("exact skip совпал с пробой другого пакета")
    return packages


def scope(path, expected, required):
    seen = collections.defaultdict(list)
    packages = collections.defaultdict(list)
    for event in events(path):
        action, package, name = event.get("Action"), event.get("Package"), event.get("Test")
        if name is None and action in ("start", "pass", "skip", "fail"):
            packages[package].append(action)
        if isinstance(name, str) and "/" not in name and action in ("run", "pass", "skip", "fail"):
            seen[(package, name)].append(action)
    if set(packages) != set(expected):
        raise ValueError("пропущен или добавлен пакет")
    if any(actions not in (["start", "pass"], ["start", "skip"]) for actions in packages.values()):
        raise ValueError("пакет не завершился однократно")
    names = {(package, name) for package, items in expected.items() for name in items}
    if set(seen) != names or not required <= names:
        raise ValueError("compiled inventory и фактически начатые TOP расходятся")
    for key, actions in seen.items():
        if actions != ["run", "pass"] and (key in required or actions != ["run", "skip"]):
            raise ValueError("обязательная проба пропущена/неполна либо TOP повторён: " + str(key))


def validate(part, out, source):
    manifest = json.loads((out / "context.json").read_text())
    if (set(manifest) != {"kind", "part", "source", "environment"}
            or manifest["kind"] != "unit" or manifest["part"] != part or manifest["source"] != source):
        raise ValueError("часть от другого исходника или запуска")
    environment = manifest["environment"]
    if (not isinstance(environment, dict) or set(environment) != set(CONTEXT_KEYS)
            or any(value is not None and not isinstance(value, str) for value in environment.values())
            or any(environment[key] != source[key] for key in ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))):
        raise ValueError("контекст среды неполон или противоречит источнику")
    names = ["inventory", "deferred-tree", "test"] if part == "main" else ["inventory", "census-test"]
    for name in names:
        rc = json.loads((out / (name + ".rc.json")).read_text())
        if set(rc) != {"go", "canonical"} or any(type(v) is not int or v != 0 for v in rc.values()):
            raise ValueError("фактический Go/канонический код не равен нулю: " + name)
        if canonical(out / (name + ".json"), out / (name + ".rechecked.txt")) != 0:
            raise ValueError("канонический повторный разбор отверг поток: " + name)
    compiled = inventory(out / "inventory.json")
    if part == "main":
        scope(out / "deferred-tree.json", {CHECK: {TREE}}, {(CHECK, TREE)})
        complement = {pkg: tests - set((TREE, *CENSUS)) if pkg == CHECK else tests
                      for pkg, tests in compiled.items()}
        scope(out / "test.json", complement, {(pkg, name) for pkg, names in FRESHNESS.items() for name in names})
    else:
        if set(compiled) != {CHECK}:
            raise ValueError("Census inventory содержит чужие пакеты")
        scope(out / "census-test.json", {CHECK: set(CENSUS)}, {(CHECK, name) for name in CENSUS})
    return compiled


def run(part, out):
    out.mkdir(parents=True, exist_ok=False)
    source = identity()
    context = {"kind": "unit", "part": part, "source": source,
               "environment": {key: os.environ.get(key) for key in CONTEXT_KEYS}}
    (out / "context.json").write_text(json.dumps(context, indent=2) + "\n")
    (out / "checkout-sha.txt").write_text(source["head"] + "\n")
    common = ["-race", "-short", "-count=1", "-timeout", "45m"]
    command(out, "inventory", ["./..." if part == "main" else "./internal/check", *common, "-list", "."])
    if part == "main":
        command(out, "deferred-tree", ["./internal/check", "-run", pattern((TREE,)), "-short", "-count=1", "-timeout", "4m"])
        command(out, "test", ["./...", *common, "-skip", pattern((TREE, *CENSUS))])
    else:
        command(out, "census-test", ["./internal/check", *common, "-run", pattern(CENSUS)])
    if identity() != source:
        raise ValueError("исходники изменились во время прогона")
    validate(part, out, source)


def aggregate(root):
    source = identity()
    root.mkdir(parents=True, exist_ok=True)
    (root / "union.json").unlink(missing_ok=True)
    (root / "checkout-sha.txt").write_text(source["head"] + "\n")
    (root / "context.json").write_text(json.dumps({"kind": "unit", "source": source}, indent=2) + "\n")
    # Старые имена артефакта сохраняются; Census имеет собственный сырой поток.
    codes = []
    for part, name, prefix in (("main", "deferred-tree", "tree"), ("main", "test", "race"),
                               ("census", "census-test", "census")):
        raw = root / part / (name + ".json")
        if raw.is_file():
            shutil.copyfile(raw, Path(name + ".json"))
        rc = root / part / (name + ".rc.json")
        if rc.is_file():
            values = json.loads(rc.read_text())
            for key, suffix in (("go", "go"), ("canonical", "verdict")):
                if type(values.get(key)) is int:
                    codes.append(prefix + "_" + suffix + "=" + str(values[key]))
    (root / "exit-codes.txt").write_text("\n".join(codes) + "\n")
    # Сначала проверяем обе части независимо; отсутствие одной никогда не зелёное.
    inventories, errors = {}, []
    for part in ("main", "census"):
        try:
            inventories[part] = validate(part, root / part, source)
        except (OSError, ValueError, TypeError, KeyError) as error:
            errors.append(part + ": " + str(error))
    if errors:
        raise ValueError("; ".join(errors))
    if inventories["main"][CHECK] != inventories["census"][CHECK]:
        raise ValueError("скомпилированный internal/check различается между частями")
    count = len(inventories["main"][CHECK])
    result = {"source": source, "internalCheckTOP": count, "tree": 1,
              "census": len(CENSUS), "complement": count - 1 - len(CENSUS)}
    (root / "union.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result), flush=True)


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("main", "census", "aggregate"):
        raise ValueError("нужны main|census|aggregate и каталог свидетельств")
    if sys.argv[1] == "aggregate":
        aggregate(Path(sys.argv[2]))
    else:
        run(sys.argv[1], Path(sys.argv[2]))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        print("unit: " + str(error), file=sys.stderr)
        sys.exit(1)
