#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""kaname#1125: допуск журналов chart-own к JSON-ветке существующего redactor.

Никакой raw-текст не становится строковым полем публичного документа. Поток
контейнера — timestamp kubectl и объект slog JSON; stderr kubectl — объект JSON
с необязательным timestamp. Иная форма закрывает весь payload. Оригиналы остаются
у вызывающего в RUNNER_TEMP. stdout этого помощника содержит только числа/флаги.
"""
import argparse
from datetime import datetime
import json
import math
from pathlib import Path
import re

TIMESTAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})) (.*)$")
POD = re.compile(r"pod/[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")


def members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("повторённое имя JSON")
        result[key] = value
    return result


def invalid_constant(_value):
    raise ValueError("нестандартное число JSON")


def representable(value):
    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError("непредставимое число")
    elif isinstance(value, dict):
        for key, child in value.items():
            representable(key)
            representable(child)
    elif isinstance(value, list):
        for child in value:
            representable(child)


def record(line, needs_timestamp):
    match = TIMESTAMP.fullmatch(line)
    if match:
        timestamp, body = match.groups()
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    elif needs_timestamp:
        raise ValueError("нет timestamp контейнера")
    else:
        timestamp, body = None, line
    payload = json.loads(body, object_pairs_hook=members, parse_constant=invalid_constant)
    if not isinstance(payload, dict):
        raise ValueError("журнал обязан содержать объект JSON")
    representable(payload)
    return {"kubectl_timestamp": timestamp, "payload": payload}


def admit(source, target, container):
    census = {"files": 0, "lines": 0, "records": 0, "rejected": 0, "complete": False}
    documents = {}

    def read(path):
        census["files"] += 1
        if path.is_symlink() or not path.is_file():
            raise ValueError("ожидался обычный файл")
        return path.read_text(encoding="utf-8", errors="strict")

    def stream(path, needs_timestamp):
        entries = []
        for number, line in enumerate(read(path).splitlines(), 1):
            census["lines"] += 1
            try:
                item = record(line, needs_timestamp)
            except (ValueError, UnicodeError, RecursionError, OverflowError):
                census["rejected"] += 1
                continue
            item["line"] = number
            entries.append(item)
            census["records"] += 1
        return entries

    try:
        if source.is_symlink() or target.is_symlink() or not source.is_dir() or not target.is_dir():
            raise ValueError("ожидались приватные каталоги")
        if source.resolve() == target.resolve() or any(target.iterdir()):
            raise ValueError("выход обязан быть отдельным пустым каталогом")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", container):
            raise ValueError("имя контейнера не представимо")
        pods = read(source / "pods.txt").splitlines()
        if not pods or len(set(pods)) != len(pods) or any(not POD.fullmatch(pod) for pod in pods):
            raise ValueError("перепись pod неполна")
        expected = {"pods.txt", "discovery.log"}
        for pod in pods:
            name = pod.removeprefix("pod/")
            expected.update({name + ".log", name + ".log.stderr.log"})
        if {p.name for p in source.iterdir()} != expected:
            raise ValueError("состав входов не совпал с переписью pod")
        documents["discovery.json"] = {"pods": pods, "stderr": stream(source / "discovery.log", False)}
        for pod in pods:
            name = pod.removeprefix("pod/")
            output = stream(source / (name + ".log"), True)
            if not output:
                census["rejected"] += 1
            documents[name + ".json"] = {
                "pod": pod,
                "container": container,
                "container_log": output,
                "kubectl_stderr": stream(source / (name + ".log.stderr.log"), False),
            }
        if census["rejected"]:
            return 2, census
        # Все документы собираются до первой записи; ошибка или неизвестная
        # строка не разрешают публикацию даже законной части того же журнала.
        for name, document in documents.items():
            (target / name).write_text(json.dumps(document, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
        census["complete"] = True
        return 0, census
    except (OSError, ValueError, UnicodeError, RecursionError, OverflowError):
        census["rejected"] += 1
        return 2, census


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="source", type=Path, required=True)
    parser.add_argument("--out", dest="target", type=Path, required=True)
    parser.add_argument("--container", required=True)
    args = parser.parse_args()
    rc, census = admit(args.source, args.target, args.container)
    print(json.dumps(census))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
