#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Перепись и проверка одного диагностического потока standalone."""
import collections
import json

MARK = "УСЛОВИЕ НЕ СОЗДАНО"
TERMINALS = ("pass", "fail", "skip")
ACTIONS = ("start", "run", "pause", "cont", "output", *TERMINALS)


def unique_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("повтор имени JSON")
        result[key] = value
    return result


def event_from_line(line):
    event = json.loads(line, object_pairs_hook=unique_members)
    if not isinstance(event, dict) or not isinstance(event.get("Action"), str):
        raise ValueError("повреждённое событие Go")
    action = event["Action"]
    build = action in ("build-output", "build-fail")
    package = event.get("ImportPath") if build else event.get("Package")
    # Старый capture мог записать build identity в Package; это отдельная совместимая форма.
    if build and "ImportPath" not in event:
        package = event.get("Package")
    unscoped_build = build and "ImportPath" in event
    if ((not build and action not in ACTIONS) or not isinstance(package, str) or
            (not package and not unscoped_build)):
        raise ValueError("неизвестная форма события Go")
    for key in ("Test", "Output", "FailedBuild"):
        if key in event and not isinstance(event[key], str):
            raise ValueError("нестроковое поле события Go")
    if build and event.get("Test"):
        raise ValueError("build-событие не является исполнением пробы")
    if event.get("FailedBuild") and (build or event.get("Test") or action != "fail"):
        raise ValueError("некорректная связь FailedBuild")
    return event


def summarize(events, malformed=0):
    packages, builds, failed_builds = {}, {}, {}
    failed_packages, failed_tests = set(), set()
    seen_packages, open_packages, seen_tests, open_tests = set(), set(), set(), set()
    output = collections.defaultdict(list)
    passed_tests = other_skips = passed_packages = skipped_packages = failed_executions = 0
    unmet = []
    for event in events:
        action, test = event["Action"], event.get("Test")
        if action in ("build-output", "build-fail"):
            package = event.get("ImportPath", event.get("Package"))
            if builds.get(package) != "fail":
                builds[package] = "fail" if action == "build-fail" else "output"
            if "ImportPath" in event or action != "build-fail":
                continue
            # Совместимость прежней формы не смешивает настоящий ImportPath с Package.
            action = "fail"
        else:
            package = event["Package"]
        if action == "start" or package not in seen_packages:
            open_packages.add(package)
        seen_packages.add(package)
        if test:
            key = (package, test)
            if action == "run":
                open_tests.add(key)
                output.pop(key, None)
            elif key not in seen_tests:
                open_tests.add(key)
            seen_tests.add(key)
            if action == "output":
                output[key].append(event.get("Output", ""))
            elif action in TERMINALS:
                open_tests.discard(key)
                if action == "fail":
                    failed_tests.add(key)
                    failed_executions += 1
                elif action == "pass":
                    passed_tests += 1
                elif MARK in "".join(output[key]):
                    unmet.append({"package": package, "test": test})
                else:
                    other_skips += 1
                output.pop(key, None)
        elif action in TERMINALS:
            open_packages.discard(package)
            packages[package] = action
            if action == "fail":
                failed_packages.add(package)
            elif action == "pass":
                passed_packages += 1
            else:
                skipped_packages += 1
            if event.get("FailedBuild"):
                failed_builds[package] = event["FailedBuild"]
    if any(builds.get(build) != "fail" for build in failed_builds.values()):
        malformed += 1
    named = [{"package": p, "test": test} for p, test in sorted(failed_tests)]
    named_packages = {p for p, _ in failed_tests}
    return {"events": len(events), "nonJSON": malformed,
            "unterminatedPackages": sorted(open_packages),
            "unterminatedTests": [{"package": p, "test": test} for p, test in sorted(open_tests)],
            "packages": packages, "failedPackages": sorted(failed_packages), "namedFailures": named,
            "packageOnlyFailures": sorted(failed_packages - named_packages),
            "passedTests": passed_tests, "failedTests": failed_executions,
            "testExecutions": passed_tests + failed_executions + len(unmet) + other_skips,
            "unmetSkips": unmet, "otherSkips": other_skips,
            "passedPackages": passed_packages, "skippedPackages": skipped_packages,
            "builds": builds, "failedBuilds": failed_builds}


def census(path):
    events, malformed = [], 0
    with path.open(encoding="utf-8", errors="strict") as stream:
        for line in stream:
            try:
                events.append(event_from_line(line))
            except (ValueError, TypeError):
                malformed += 1
    return summarize(events, malformed)


def complete(census):
    return (census["nonJSON"] == 0 and bool(census["packages"]) and
            not census["unterminatedPackages"] and not census["unterminatedTests"])


def outcome(census, go_rc):
    if not complete(census):
        return "unknown"
    if census["namedFailures"]:
        return "mixed" if census["packageOnlyFailures"] else "named"
    if census["failedPackages"] or "fail" in census["builds"].values():
        return "package"
    return "pass" if go_rc == 0 else "unknown"


def helper_rc(census, go_rc):
    if not complete(census):
        return 2
    return int(go_rc != 0 or bool(census["namedFailures"]) or bool(census["failedPackages"]) or "fail" in census["builds"].values())


def validate(manifest, census, events):
    expected = summarize(events)
    # JSON-сравнение различает bool/int, а также отсутствие поля и нулевое значение.
    if json.dumps(census, sort_keys=True) != json.dumps(expected, sort_keys=True) or not complete(expected):
        raise ValueError("перепись расходится с потоком")
    if (type(manifest.get("goRC")) is not int or manifest.get("complete") is not True or
            manifest.get("captureStatus") != "complete" or manifest.get("censusStatus") != "complete"):
        raise ValueError("нет подтверждённого исхода Go")
    for key in ("parseRC", "captureRC"):
        if type(manifest.get(key)) is not int or manifest[key] != 0:
            raise ValueError("не завершён захват или разбор")
    if (type(manifest.get("helperRC")) is not int or manifest["helperRC"] != helper_rc(expected, manifest["goRC"]) or
            manifest.get("outcome") != outcome(expected, manifest["goRC"])):
        raise ValueError("исход расходится с переписью")
    if manifest["goRC"] == 0 and helper_rc(expected, 0) != 0:
        raise ValueError("Go объявил успех при наблюдённом отказе")
    return expected
