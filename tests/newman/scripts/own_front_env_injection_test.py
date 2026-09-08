#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Доказательство, что гейт адресации СПОСОБЕН упасть и способен смолчать.

Гоняется НАСТОЯЩАЯ судящая функция `audit`, а не её пересказ. Вход
синтетический; оси проверяются по одной, у каждой инъекции — законный близнец,
отличающийся ровно одним фактом.

КТО ЭТУ ПРОБУ ИСПОЛНЯЕТ: `.github/scripts/run-python-probes.py`. Состав он
собирает ОБХОДОМ дерева по образцу `services/*/tests/newman/scripts/*_test.py` и
НИ ОДИН файл проб по имени не называет — поэтому отдельного шага в конвейере файл
не требует, а искать вызывающего предикатом `git grep <имя файла>` бесполезно:
вызова по имени нет ни у кого. Код возврата при этом доезжает до вердикта шага.
Проводку держит `tools/pythonprobes`.
"""

import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import own_front_env_test as gate  # noqa: E402

FAILURES = []


def check(name, ok, detail=""):
    print(f"  {'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f": {detail}"))
    if not ok:
        FAILURES.append(f"{name}: {detail}")


def run(env_values, case_body):
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        env = d / "env.json"
        env.write_text(json.dumps({"values": env_values}, ensure_ascii=False), encoding="utf-8")
        cases = d / "cases"
        cases.mkdir()
        (cases / "synth.py").write_text(case_body, encoding="utf-8")
        return gate.audit(env, cases)


GOOD_ENV = [
    {"key": "baseUrl", "value": gate.EDGE_VALUE},
    {"key": "ownRestBaseUrl", "value": ""},
    {"key": "ownInternalRestBaseUrl", "value": ""},
]
GOOD_CASE = ('p = require_env_url("ownRestBaseUrl", "/x", "почему")\n'
             'q = require_env_url("ownInternalRestBaseUrl", "/y", "почему")\n')


def main():
    print("ось 1 — переменная собственного фронта не объявлена")
    _, f = run([v for v in GOOD_ENV if v["key"] != "ownInternalRestBaseUrl"], GOOD_CASE)
    check("инъекция: находка", any("ownInternalRestBaseUrl" in x for x in f), str(f))
    c, f = run(GOOD_ENV, GOOD_CASE)
    check("контроль: молчание", not f, str(f))
    check("контроль: предмет осмотрен", c["переменных в шаблоне"] == 3, str(c))

    print("ось 2 — переменная края ПЕРЕОПРЕДЕЛЕНА")
    bad = [dict(v) for v in GOOD_ENV]
    bad[0]["value"] = "http://localhost:19098"
    _, f = run(bad, GOOD_CASE)
    check("инъекция: находка", any("переопределена" in x for x in f), str(f))
    check("находка называет обе величины",
          any(gate.EDGE_VALUE in x and "19098" in x for x in f), str(f))

    print("ось 3 — переменная края ИСЧЕЗЛА (предмет сверки пропал)")
    _, f = run([v for v in GOOD_ENV if v["key"] != "baseUrl"], GOOD_CASE)
    check("инъекция: находка, а не тривиальное «не переопределена»",
          any("исчезла" in x for x in f), str(f))

    print("ось 4 — переменная объявлена, но НИКТО к ней не адресуется")
    _, f = run(GOOD_ENV, 'p = require_env_url("ownRestBaseUrl", "/x", "почему")\n')
    check("инъекция: находка", any("НИ ОДИН кейс" in x for x in f), str(f))
    _, f = run(GOOD_ENV, GOOD_CASE)
    check("контроль: обе читаются — молчание", not f, str(f))

    print("ось 5 — перепись считает адресатов, а не объявления")
    c, _ = run(GOOD_ENV, GOOD_CASE + 'r = require_env_url("baseUrl", "/z", "почему")\n')
    check("перепись называет каждую переменную отдельно",
          c.get("адресуются к baseUrl") == 1 and c.get("адресуются к ownRestBaseUrl") == 1, str(c))

    print()
    if FAILURES:
        print(f"ОТКАЗ: провалено утверждений {len(FAILURES)} из 9", file=sys.stderr)
        for x in FAILURES:
            print("  " + x, file=sys.stderr)
        return 1
    print("ЧИСТО: 9 утверждений, гейт способен упасть и способен смолчать по каждой оси")
    return 0


if __name__ == "__main__":
    sys.exit(main())
