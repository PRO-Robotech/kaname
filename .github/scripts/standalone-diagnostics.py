#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Публикует только проверенную очищенную производную private capture.

Граница очистки — формы существующего redactor и структурированные JSON-тела.
Произвольный короткий непрозрачный секрет внутри прозы распознать нельзя.
"""
import argparse
import collections
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import sys
import tempfile

MAX_BYTES = 128 * 1024 * 1024
PRODUCER_FILES = {"manifest.json", "stdout.jsonl", "stderr.log", "go.rc", "census.json"}
RUNNER_FILES = {"runner.json", "target.log"}
EXPORT_ERROR = "экспорт диагностики отклонён: состав, полнота, размер или очистка"
_spec = importlib.util.spec_from_file_location("standalone_protocol", pathlib.Path(__file__).resolve().parents[2] / "scripts/standalone_protocol.py")
protocol = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(protocol)


def load_redactor():
    spec = importlib.util.spec_from_file_location("standalone_report_redactor", pathlib.Path(__file__).with_name("redact-newman-report.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def digest(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def read_json(path):
    # Повтор ключа не должен скрыть исходное значение от проверяющего.
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("повтор имени JSON")
            result[key] = value
        return result
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs)


def text_clean(raw, redactor):
    c = redactor.Census()
    # PEM и целое JSON-тело судятся до разбиения: короткий хвост тоже секретен.
    clean = redactor._scrub_body(raw, c)
    parts = []
    residue = []
    decoder = json.JSONDecoder()
    opener = re.compile(r'\{(?=\s*(?:"|\}|$))|\[(?=\s*(?:[\[{"\]0-9-]|true\b|false\b|null\b|$))')
    cursor = 0
    while cursor < len(clean):
        start = opener.search(clean, cursor)
        if start is None:
            parts.append(redactor.scrub_text(clean[cursor:]).text)
            break
        offset = start.start()
        parts.append(redactor.scrub_text(clean[cursor:offset]).text)
        try:
            _, end = decoder.raw_decode(clean, offset)
        except ValueError:
            # Оборванное тело с именованным секретом нельзя публиковать частями.
            for match in re.finditer(r'"((?:[^"\\]|\\.)*)"\s*:', clean[offset:]):
                key = json.loads('"' + match[1] + '"')
                if redactor._named_secret(key) or redactor._named_code(key):
                    raise ValueError("незавершённое секретное JSON-тело")
            parts.append(clean[offset])
            cursor = offset + 1
            continue
        part = redactor._scrub_body(clean[offset:end], c)
        redactor._residue_body(part, "JSON-фрагмент", None, residue)
        parts.append(part)
        cursor = end
    clean = "".join(parts)
    redactor._residue_body(clean, "поток", None, residue)
    if residue or redactor.residue_shaped(clean):
        raise ValueError("остаток после очистки")
    if raw.endswith("\n") and not clean.endswith("\n"):
        clean += "\n"
    return clean


def package_identity(value, allow_unscoped_build=False):
    # Имя пакета — идентификатор Go, а не имя credential-поля JSON.
    if allow_unscoped_build and value == "":
        return value
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_.~+/-]+(?: \[[A-Za-z0-9_.~+/-]+\])?", value) is None:
        raise ValueError("некорректная идентичность пакета")
    return value


def clean_events(events, redactor):
    streams = collections.defaultdict(list)
    generations = collections.defaultdict(int)
    aliases, alias_records = {}, []
    safe_events = []
    for index, event in enumerate(events):
        build = event["Action"] in ("build-output", "build-fail")
        package = package_identity(event.get("ImportPath", event.get("Package")), allow_unscoped_build="ImportPath" in event) if build else package_identity(event["Package"])
        source = ("build" if build else "test", package, event.get("Test", ""))
        if event["Action"] in ("run", "start"):
            generations[source] += 1
        if "Output" in event:
            streams[(source, generations[source])].append(index)
        # Только поля типизированного протокола обходят общий JSON-redactor.
        other = {k: v for k, v in event.items() if k not in ("Action", "Package", "ImportPath", "Test", "FailedBuild", "Output")}
        safe = json.loads(document_clean(other, redactor))
        safe["Action"] = event["Action"]
        for key in ("Package", "ImportPath", "FailedBuild"):
            if key in event:
                safe[key] = package_identity(event[key], allow_unscoped_build=build and key == "ImportPath")
        if "Test" in event:
            test = event["Test"]
            static, separator, _ = test.partition("/")
            if static and (not static.isidentifier() or not static.startswith(("Test", "Example", "Benchmark", "Fuzz"))):
                raise ValueError("некорректное статическое имя пробы")
            key = (package, test)
            if separator:
                if key not in aliases:
                    alias = static + "/subtest-%06d" % (len(alias_records) + 1)
                    aliases[key] = alias
                    alias_records.append({"package": package, "test": alias, "sourceEvents": []})
                alias = aliases[key]
                safe["Test"] = alias
                alias_records[int(alias.rsplit("-", 1)[1]) - 1]["sourceEvents"].append(index)
            else:
                safe["Test"] = static
        safe_events.append(safe)
    for (source, _), indices in streams.items():
        raw = "".join(events[i]["Output"] for i in indices)
        own_aliases = {key: alias for key, alias in aliases.items() if key[0] == source[1]}
        cleaned = text_clean(rewrite_test_names(raw, own_aliases), redactor)
        cursor = 0
        for position, index in enumerate(indices):
            end = len(cleaned) if position == len(indices) - 1 else min(len(cleaned), cursor + len(events[index]["Output"]))
            safe_events[index]["Output"] = cleaned[cursor:end]
            cursor = end
    return safe_events, aliases, alias_records


def rewrite_test_names(raw, aliases):
    # Go печатает полное имя также в Output; короткий динамический секрет формы не имеет.
    replacements = {}
    for (_, name), alias in sorted(aliases.items(), key=lambda item: len(item[0][1]), reverse=True):
        replacements.setdefault(name, alias)
    if not replacements:
        return raw
    # Callback заменяет только исходные совпадения; созданный alias повторно не читается.
    pattern = "|".join(re.escape(name) for name in replacements)
    return re.sub(pattern, lambda match: replacements[match.group(0)], raw)


def clean_census(census, aliases):
    # Статусы, счётчики и состав уже независимо сверены с исходным потоком.
    safe = dict(census)
    for field in ("namedFailures", "unterminatedTests", "unmetSkips"):
        safe[field] = [{"package": e["package"], "test": aliases.get((e["package"], e["test"]), e["test"])} for e in census[field]]
    return safe


# Partial никогда не пропускает текст через redactor: публикуется только закрытая схема.
PARTIAL_STATUS = "PARTIAL_DIAGNOSTIC"
PARTIAL_COUNTERS = {"events", "nonJSON", "passedTests", "failedTests", "testExecutions",
                    "otherSkips", "passedPackages", "skippedPackages"}
PARTIAL_TEST_LISTS = {"namedFailures", "unterminatedTests", "unmetSkips"}
PARTIAL_PACKAGE_LISTS = {"unterminatedPackages", "failedPackages", "packageOnlyFailures"}
PARTIAL_MAPS = {"packages", "builds", "failedBuilds"}
PARTIAL_CATEGORIES = {"unterminated-tests", "unterminated-packages", "interrupted", "complete-sibling"}


def strict_equal(left, right):
    # В том числе bool != int, NaN не является JSON числом протокола.
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def partial_package(value, allow_empty=False):
    package_identity(value, allow_unscoped_build=allow_empty)
    if value == "" and allow_empty:
        return value
    # Абсолютный/private путь и traversal не являются canonical import identity.
    identities = value[:-1].split(" [", 1) if " [" in value else [value]
    if any(part in ("", ".", "..") for identity in identities for part in identity.split("/")):
        raise ValueError("неканонический пакет")
    return value


def partial_events(raw):
    events = []
    for line in raw.decode("utf-8").splitlines():
        event = protocol.event_from_line(line)
        if set(event) - {"Time", "Action", "Package", "ImportPath", "Test", "Output", "Elapsed", "FailedBuild"}:
            raise ValueError("неизвестная схема события")
        if "Elapsed" in event and (type(event["Elapsed"]) not in (int, float) or event["Elapsed"] < 0):
            raise ValueError("нетипизированная длительность")
        # Числа проверяются и на NaN/Infinity; Time не экспортируется.
        json.dumps(event, allow_nan=False)
        if "Time" in event and (not isinstance(event["Time"], str) or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})", event["Time"]) is None):
            raise ValueError("нетипизированное время")
        build = event["Action"] in ("build-output", "build-fail")
        for key in ("Package", "ImportPath", "FailedBuild"):
            if key in event:
                partial_package(event[key], allow_empty=build and key == "ImportPath")
        if "ImportPath" in event and not build or "Test" in event and not event["Test"]:
            raise ValueError("противоречивая форма события")
        events.append(event)
    return events


def partial_producer(directory, index):
    manifest_raw = (directory / "manifest.json").read_bytes()
    m = json.loads(manifest_raw.decode("utf-8"), object_pairs_hook=protocol.unique_members)
    allowed = {"version", "kind", "source", "target", "args", "complete", "captureStatus", "censusStatus",
               "goRC", "parseRC", "captureRC", "helperRC", "outcome", "files"}
    if (not isinstance(m, dict) or set(m) - allowed or type(m.get("version")) is not int or
            m["version"] != 1 or m.get("kind") != "producer" or type(m.get("complete")) is not bool):
        raise ValueError("неизвестная схема producer")
    if "source" in m and (not isinstance(m["source"], dict) or set(m["source"]) - {"commit", "tree"} or
                           any(not isinstance(v, str) for v in m["source"].values())):
        raise ValueError("неизвестная source схема")
    if "target" in m and not isinstance(m["target"], str) or "args" in m and (not isinstance(m["args"], list) or any(not isinstance(a, str) for a in m["args"])):
        raise ValueError("нетипизированный producer")
    if not isinstance(m.get("files"), dict) or set(m["files"]) != PRODUCER_FILES - {"manifest.json"}:
        raise ValueError("неполные hashes producer")
    # Перепись разбирается из тех же байтов, чьи hashes проверены, без повторного read.
    payload = {name: (directory / name).read_bytes() for name in PRODUCER_FILES - {"manifest.json"}}
    for name, raw in payload.items():
        if not strict_equal(m["files"][name], digest(raw)):
            raise ValueError("байты producer изменились")
    for field in ("goRC", "parseRC", "captureRC", "helperRC"):
        if type(m.get(field)) is not int:
            raise ValueError("нет подтверждённого RC")
    if payload["go.rc"] != (str(m["goRC"]) + "\n").encode("ascii"):
        raise ValueError("исход Go расходится")
    c = json.loads(payload["census.json"].decode("utf-8"), object_pairs_hook=protocol.unique_members)
    events = partial_events(payload["stdout.jsonl"])
    expected = protocol.summarize(events)
    if not strict_equal(c, expected) or expected["nonJSON"] != 0:
        raise ValueError("перепись расходится с событиями")
    categories = []
    if m["complete"]:
        protocol.validate(m, c, events)
        categories.append("complete-sibling")
    else:
        if (m.get("captureStatus") not in ("complete", "interrupted") or m.get("censusStatus") != "incomplete" or
                m["parseRC"] != 2 or m["helperRC"] != 2 or m.get("outcome") != "unknown" or
                m["captureRC"] != (2 if m["captureStatus"] == "interrupted" else 0)):
            raise ValueError("неподтверждённый незавершённый producer")
        if c["unterminatedTests"]:
            categories.append("unterminated-tests")
        if c["unterminatedPackages"]:
            categories.append("unterminated-packages")
        if m["captureStatus"] == "interrupted":
            categories.append("interrupted")
        if not categories or m["goRC"] == 0 and (c["namedFailures"] or c["failedPackages"] or "fail" in c["builds"].values()):
            raise ValueError("противоречивый исход вместо interruption")
    capture = "capture-%04d" % index
    aliases, names, safe_events = {}, [], []
    for event_index, event in enumerate(events):
        build = event["Action"] in ("build-output", "build-fail")
        package = event.get("ImportPath", event.get("Package")) if build else event["Package"]
        safe = {"index": event_index, "action": event["Action"], "package": package}
        # Длительность отказа пакета помогает отличить его собственный таймаут от лимита задания.
        if event["Action"] == "fail" and "Test" not in event and "Elapsed" in event:
            safe["elapsedSeconds"] = event["Elapsed"]
        if "Test" in event:
            key = (package, event["Test"])
            if key not in aliases:
                alias = capture + "-test-%06d" % (len(aliases) + 1)
                aliases[key] = alias
                names.append({"package": package, "alias": alias})
            safe["testAlias"] = aliases[key]
        safe_events.append(safe)
    safe_census = clean_census(c, aliases)
    # Ни первоначальное статическое имя, ни динамический суффикс не выходят наружу.
    record = {"capture": capture, "kind": "producer", "categories": categories,
              "verifiedRC": {key: m[key] for key in ("goRC", "parseRC", "captureRC", "helperRC")},
              "census": safe_census, "aliases": names, "events": safe_events,
              "rawFiles": {name: digest(raw) for name, raw in {"manifest.json": manifest_raw, **payload}.items()},
              "source": {key: value if re.fullmatch(r"[0-9a-f]{40}", value) else "unknown"
                         for key in ("commit", "tree") for value in (m.get("source", {}).get(key, "unknown"),)}}
    return record, not m["complete"]


def validate_partial_report(report):
    # Этот же whitelist судит публикацию и право удалить прежнюю производную.
    if (not isinstance(report, dict) or set(report) != {"version", "complete", "status", "testAccepted", "outcome", "captures"} or
            type(report["version"]) is not int or report["version"] != 1 or report["complete"] is not False or
            report["testAccepted"] is not False or report["status"] != PARTIAL_STATUS or report["outcome"] != "unknown" or
            not isinstance(report["captures"], list) or not report["captures"]):
        raise ValueError("неизвестный partial экспорт")
    all_aliases = set()
    incomplete = False
    for index, record in enumerate(report["captures"]):
        if not isinstance(record, dict) or set(record) != {"capture", "kind", "categories", "verifiedRC", "census", "aliases", "events", "rawFiles", "source"}:
            raise ValueError("неизвестная partial запись")
        if record["capture"] != "capture-%04d" % index or record["kind"] != "producer":
            raise ValueError("неканоническая partial запись")
        raw_files = record["rawFiles"]
        if not isinstance(raw_files, dict) or set(raw_files) != PRODUCER_FILES:
            raise ValueError("неполная raw provenance")
        for item in raw_files.values():
            if (not isinstance(item, dict) or set(item) != {"bytes", "sha256"} or type(item["bytes"]) is not int or
                    item["bytes"] < 0 or not isinstance(item["sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None):
                raise ValueError("нетипизированная raw provenance")
        source = record["source"]
        if (not isinstance(source, dict) or set(source) != {"commit", "tree"} or
                any(not isinstance(v, str) or v != "unknown" and re.fullmatch(r"[0-9a-f]{40}", v) is None for v in source.values())):
            raise ValueError("нетипизированная source provenance")
        categories = record["categories"]
        if (not isinstance(categories, list) or not categories or any(not isinstance(v, str) or v not in PARTIAL_CATEGORIES for v in categories) or
                len(categories) != len(set(categories)) or "complete-sibling" in categories and len(categories) != 1):
            raise ValueError("неизвестная категория")
        incomplete |= "complete-sibling" not in categories
        rc = record["verifiedRC"]
        if not isinstance(rc, dict) or set(rc) != {"goRC", "parseRC", "captureRC", "helperRC"} or any(type(v) is not int for v in rc.values()):
            raise ValueError("нетипизированные RC")
        aliases = {}
        if not isinstance(record["aliases"], list):
            raise ValueError("нетипизированные aliases")
        for number, entry in enumerate(record["aliases"], 1):
            if not isinstance(entry, dict) or set(entry) != {"package", "alias"} or entry["alias"] != record["capture"] + "-test-%06d" % number:
                raise ValueError("неканонический alias")
            partial_package(entry["package"])
            if entry["alias"] in all_aliases:
                raise ValueError("повтор alias")
            all_aliases.add(entry["alias"]); aliases[entry["alias"]] = entry["package"]
        c = record["census"]
        if not isinstance(c, dict) or set(c) != PARTIAL_COUNTERS | PARTIAL_TEST_LISTS | PARTIAL_PACKAGE_LISTS | PARTIAL_MAPS:
            raise ValueError("неизвестная partial перепись")
        if any(type(c[k]) is not int or c[k] < 0 for k in PARTIAL_COUNTERS) or c["nonJSON"] != 0:
            raise ValueError("нетипизированные счётчики")
        for key in PARTIAL_TEST_LISTS:
            if not isinstance(c[key], list):
                raise ValueError("нетипизированные пробы")
            for item in c[key]:
                if (not isinstance(item, dict) or set(item) != {"package", "test"} or
                        not isinstance(item["test"], str) or aliases.get(item["test"]) != item["package"]):
                    raise ValueError("неизвестный alias переписи")
        for key in PARTIAL_PACKAGE_LISTS:
            if not isinstance(c[key], list):
                raise ValueError("нетипизированные пакеты")
            for value in c[key]: partial_package(value)
        for key in PARTIAL_MAPS:
            if not isinstance(c[key], dict):
                raise ValueError("нетипизированная карта пакетов")
            for name, value in c[key].items():
                partial_package(name, allow_empty=key == "builds")
                if key == "failedBuilds": partial_package(value, allow_empty=True)
                elif not isinstance(value, str) or value not in (("pass", "fail", "skip") if key == "packages" else ("fail", "output")):
                    raise ValueError("неизвестный статус пакета")
        if not isinstance(record["events"], list) or len(record["events"]) != c["events"]:
            raise ValueError("неполный event index")
        for number, event in enumerate(record["events"]):
            if (not isinstance(event, dict) or
                    set(event) - {"testAlias", "elapsedSeconds"} != {"index", "action", "package"} or
                    type(event["index"]) is not int or event["index"] != number or not isinstance(event["action"], str) or
                    event["action"] not in (*protocol.ACTIONS, "build-output", "build-fail")):
                raise ValueError("неизвестное partial событие")
            partial_package(event["package"], allow_empty=event["action"] in ("build-output", "build-fail"))
            if "testAlias" in event and (not isinstance(event["testAlias"], str) or aliases.get(event["testAlias"]) != event["package"]):
                raise ValueError("неизвестный event alias")
            if "elapsedSeconds" in event:
                elapsed = event["elapsedSeconds"]
                if (event["action"] != "fail" or "testAlias" in event or
                        type(elapsed) not in (int, float) or not 0 <= elapsed < float("inf")):
                    raise ValueError("нетипизированная длительность отказа пакета")
    if not incomplete:
        raise ValueError("partial без незавершённого producer")


def partial_export(groups, stage, dst, max_bytes):
    records = []
    has_incomplete = False
    for directory, kind in groups:
        if kind == "runner":
            # Runner не имеет producer hash-протокола: его текст/argv/RC не публикуются.
            m = read_json(directory / "runner.json")
            if (not isinstance(m, dict) or set(m) - {"version", "kind", "complete", "rc", "target"} or
                    type(m.get("version")) is not int or m["version"] != 1 or m.get("kind") != "runner" or m.get("complete") is not True or type(m.get("rc")) is not int):
                raise ValueError("неполный runner")
            if "target" in m and not isinstance(m["target"], str):
                raise ValueError("нетипизированный runner")
            continue
        record, incomplete = partial_producer(directory, len(records))
        records.append(record); has_incomplete |= incomplete
    if not has_incomplete:
        raise ValueError("нет незавершённого producer")
    report = {"version": 1, "complete": False, "status": PARTIAL_STATUS, "testAccepted": False,
              "outcome": "unknown", "captures": records}
    validate_partial_report(report)
    raw = (json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()
    if len(raw) > max_bytes:
        raise ValueError("partial превышает предел")
    (stage / "export.json").write_bytes(raw)
    validate_partial_report(read_json(stage / "export.json"))
    stage.rename(dst)
    return 2


def remove_previous_export(dst):
    if not dst.exists():
        return
    # Удаляется только проверенная производная нашего формата, не произвольный каталог.
    if not dst.is_dir() or any(p.is_symlink() for p in dst.rglob("*")):
        raise ValueError("чужое назначение экспорта")
    report = read_json(dst / "export.json")
    if not isinstance(report, dict) or report.get("version") != 1 or type(report.get("complete")) is not bool:
        raise ValueError("чужое назначение экспорта")
    expected = {"export.json"}
    if report["complete"]:
        if not isinstance(report.get("captures"), list) or not report["captures"]:
            raise ValueError("повреждён прежний экспорт")
        for record in report["captures"]:
            name = record["capture"]
            if re.fullmatch(r"capture-[0-9]{4,}", name) is None or name in expected:
                raise ValueError("повреждён прежний экспорт")
            expected.add(name)
            directory = dst / name
            names = PRODUCER_FILES if record["kind"] == "producer" else RUNNER_FILES if record["kind"] == "runner" else set()
            if not names or {p.name for p in directory.iterdir()} != names or set(record["files"]) != names:
                raise ValueError("повреждён прежний экспорт")
            for filename in names:
                path = directory / filename
                if not path.is_file() or record["files"][filename]["public"] != digest(path.read_bytes()):
                    raise ValueError("повреждён прежний экспорт")
    elif report.get("status") == PARTIAL_STATUS:
        validate_partial_report(report)
    elif set(report) != {"version", "complete", "error"} or report["error"] != EXPORT_ERROR:
        raise ValueError("чужое назначение экспорта")
    if {p.name for p in dst.iterdir()} != expected:
        raise ValueError("чужие файлы в назначении экспорта")
    shutil.rmtree(dst)


def document_clean(doc, redactor):
    c = redactor.Census()
    clean = redactor.redact_document(redactor._load_json(json.dumps(doc, ensure_ascii=False), redactor.CUT_EVERY_COPY), c)
    written = redactor._dump(clean, indent=1)
    residue = []
    redactor.residue(redactor._load_json(written, redactor.CHECK_EVERY_COPY), "документ", residue)
    if residue:
        raise ValueError("остаток JSON после очистки")
    return (written + "\n").encode()


def export(src, dst, max_bytes=MAX_BYTES):
    # Прежняя подтверждённая производная снимается до проверки нового capture.
    src, dst = pathlib.Path(src), pathlib.Path(dst)
    if not src.is_absolute() or not dst.is_absolute() or src.resolve() != src or dst.resolve() != dst:
        raise ValueError("пути должны быть абсолютными без ссылок")
    if src == dst or src in dst.parents or dst in src.parents or any(c in str(src) + str(dst) for c in "\r\n"):
        raise ValueError("нужен отдельный public каталог")
    remove_previous_export(dst)
    dst.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    stage = pathlib.Path(tempfile.mkdtemp(prefix="standalone-public-", dir=dst.parent))
    try:
        if not src.is_dir():
            raise ValueError("capture отсутствует")
        groups = []
        total = 0
        for directory in [src, *sorted(src.rglob("*"))]:
            if directory.is_symlink():
                raise ValueError("ссылка в capture")
            if not directory.is_dir():
                if not directory.is_file():
                    raise ValueError("необычный файл capture")
                total += directory.stat().st_size
                if total > max_bytes:
                    raise ValueError("capture превышает предел экспорта")
                continue
            files = {p.name for p in directory.iterdir() if not p.is_dir()}
            if not files:
                continue
            if files == PRODUCER_FILES:
                groups.append((directory, "producer"))
            elif files == RUNNER_FILES:
                groups.append((directory, "runner"))
            else:
                raise ValueError("неполный или неизвестный состав capture")
        if not groups:
            raise ValueError("capture пуст")
        # Имена из producer очищают также строки обрамляющего runner.
        groups.sort(key=lambda group: group[1] == "runner")
        # Complete-only идёт по прежней строгой ветке без изменения её verdict.
        producer_manifests = [read_json(directory / "manifest.json") for directory, kind in groups if kind == "producer"]
        if any(not isinstance(m, dict) for m in producer_manifests):
            raise ValueError("manifest не объект")
        if any(m.get("complete") is False for m in producer_manifests):
            return partial_export(groups, stage, dst, max_bytes)
        redactor = load_redactor()
        records = []
        public_aliases = {}
        for index, (directory, kind) in enumerate(groups):
            target = stage / ("capture-%04d" % index)
            target.mkdir(mode=0o700)
            names = PRODUCER_FILES if kind == "producer" else RUNNER_FILES
            manifest_name = "manifest.json" if kind == "producer" else "runner.json"
            m = read_json(directory / manifest_name)
            if not isinstance(m, dict):
                raise ValueError("manifest не объект")
            if type(m.get("version")) is not int or m["version"] != 1 or m.get("kind") != kind or m.get("complete") is not True:
                raise ValueError("незавершённый capture")
            if kind == "producer":
                for name in PRODUCER_FILES - {"manifest.json"}:
                    if m.get("files", {}).get(name) != digest((directory / name).read_bytes()):
                        raise ValueError("байты capture изменились")
                if (directory / "go.rc").read_text().strip() != str(m["goRC"]):
                    raise ValueError("исход Go расходится")
                c = read_json(directory / "census.json")
                if not isinstance(c, dict):
                    raise ValueError("перепись не объект")
                events = []
                for line in (directory / "stdout.jsonl").read_text(encoding="utf-8").splitlines():
                    events.append(protocol.event_from_line(line))
                protocol.validate(m, c, events)
                safe_events, aliases, alias_records = clean_events(events, redactor)
                public_aliases.update(aliases)
                encoded = b"".join((json.dumps(e, ensure_ascii=False) + "\n").encode() for e in safe_events)
                (target / "stdout.jsonl").write_bytes(encoded)
                (target / "census.json").write_text(json.dumps(clean_census(c, aliases), ensure_ascii=False) + "\n", encoding="utf-8")
                (target / "go.rc").write_text(str(m["goRC"])+"\n")
                stderr = rewrite_test_names((directory / "stderr.log").read_text(encoding="utf-8"), aliases)
                (target / "stderr.log").write_text(text_clean(stderr, redactor), encoding="utf-8")
                if not isinstance(m.get("source", {}), dict):
                    raise ValueError("source не объект")
                # Сырые hashes не выдаются за hashes очищенного payload.
                safe = {"version": 1, "kind": kind, "complete": True, "goRC": m["goRC"], "outcome": m.get("outcome"),
                        "parseRC": m["parseRC"], "captureRC": m["captureRC"], "helperRC": m["helperRC"],
                        "testAliases": alias_records,
                        "identityBoundary": "статическое имя Go сохранено; динамический суффикс заменён уникальным alias; sourceEvents — индексы в исходном stdout.jsonl с raw hash в export.json",
                        "countUnit": "passedTests/failedTests/testExecutions/unmetSkips/otherSkips — исполнения; namedFailures/failedPackages — разные идентичности",
                        "source": {k: m.get("source", {}).get(k) if re.fullmatch(r"[0-9a-f]{40,64}", str(m.get("source", {}).get(k))) else "unknown" for k in ("commit", "tree")}}
                (target / "manifest.json").write_text(json.dumps(safe, ensure_ascii=False)+"\n", encoding="utf-8")
            else:
                if type(m.get("rc")) is not int:
                    raise ValueError("нет исхода runner")
                runner_text = (directory / "target.log").read_text(encoding="utf-8").replace(str(src), "{private-capture}")
                (target / "target.log").write_text(text_clean(rewrite_test_names(runner_text, public_aliases), redactor), encoding="utf-8")
                safe = {"version": 1, "kind": kind, "complete": True, "rc": m["rc"], "target": text_clean(str(m.get("target", "")), redactor)}
                (target / "runner.json").write_text(json.dumps(safe, ensure_ascii=False)+"\n", encoding="utf-8")
            record = {"capture": target.name, "kind": kind, "files": {}}
            for name in sorted(names):
                record["files"][name] = {"raw": digest((directory / name).read_bytes()), "public": digest((target / name).read_bytes())}
            records.append(record)
        payload_bytes = sum(p.stat().st_size for p in stage.rglob("*") if p.is_file())
        report = {"version": 1, "complete": True, "captures": records,
                  "rawBytes": total, "publicBytes": payload_bytes,
                  "redactionBoundary": "формы существующего redactor и структурированные JSON-тела; произвольные непрозрачные значения в прозе не гарантируются"}
        # Итоговый размер включает собственную перепись экспорта.
        while True:
            report_bytes = (json.dumps(report, ensure_ascii=False, indent=2)+"\n").encode()
            public_bytes = payload_bytes + len(report_bytes)
            if public_bytes == report["publicBytes"]:
                break
            report["publicBytes"] = public_bytes
        if public_bytes > max_bytes:
            raise ValueError("очищенный payload превышает предел")
        (stage / "export.json").write_bytes(report_bytes)
        stage.rename(dst)
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        shutil.rmtree(stage)
        # Только фиксированный безопасный статус, без raw, путей и текста исключения.
        dst.mkdir(mode=0o700)
        (dst / "export.json").write_text(json.dumps({"version": 1, "complete": False, "error": EXPORT_ERROR}, ensure_ascii=False) + "\n", encoding="utf-8")
        return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("destination", type=pathlib.Path)
    args = parser.parse_args()
    try:
        output = os.environ.get("GITHUB_OUTPUT")
        if output:
            with open(output, "a", encoding="utf-8") as stream:
                stream.write("ready=false\n")
        code = export(args.source, args.destination)
        if code in (0, 2) and output:
            with open(output, "a", encoding="utf-8") as stream:
                stream.write("path=" + str(args.destination) + "\nready=true\n")
        return code
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        print("ОТКАЗ: некорректные пути экспорта диагностики", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
