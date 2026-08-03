#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1
"""Самопроверка exec-coverage.py: РАЗЛИЧАЕТ ли он записанный пропуск и немой разрыв.

ЧТО ДОКАЗЫВАЕТСЯ, и почему без этого нельзя.
`exec-coverage.py` объявляет правильной форму стража «утвердить, назвав переменную,
и только потом пропустить» — и до сих пор относил КАЖДЫЙ такой шаг к находке
ASSERTED-NOT-EXECUTED: страж утвердил (шаг «asserted») и не отправился (записи об
исполнении нет). То есть гейт наказывал форму, которую сам предписывает. На замере
боевой посадки 2026-07-31 это дало 135 шагов в 75 местах, и приёмка IAM-INT-1
назвала различимость записанного пропуска от немого открытым долгом (Р10).

Различитель, который вводится, обязан быть проверен В ОБЕ СТОРОНЫ, иначе он
превратится в амнистию: «есть страж — значит можно». Здесь четыре входа.

  (1) САНКЦИОНИРОВАННЫЙ страж, упало ЕГО утверждение → RECORDED-SKIP, гейт молчит.
  (2) Тот же шаг, но упало утверждение ТЕСТ-скрипта → ASSERTED-NOT-EXECUTED,
      находка. Тест-скрипт не выполняется без ответа, значит шаг ИСПОЛНЯЛСЯ, а
      запись о нём пропала — ровно тот класс, ради которого гейт заведён.
  (3) Пропуск БЕЗ утверждения (голый skipRequest) → немой explained-skip, НЕ
      RECORDED-SKIP: он ничего не оставляет в вердикте, и путать их нельзя.
  (4) Страж есть, но отчёт не говорит, ЧТО упало → находка (fail-closed):
      неустановимое не извиняется, иначе «объяснённый пропуск» станет корзиной
      «всё остальное», которой не бывает.

Запуск: python3 scripts/exec-coverage-selftest.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "exec_coverage", os.path.join(os.path.dirname(os.path.abspath(__file__)), "exec-coverage.py")
)
ec = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ec)

GUARD_NAME = "harness config: internalBaseUrl is set"
GUARD_FAIL = "internalBaseUrl is not set — the newman runner did not inject it."

GUARD_PRE = [
    "// HARNESS-CONFIG GUARD — internalBaseUrl is injected by the newman runner.",
    "const __cfgUrl = pm.environment.get('internalBaseUrl') || '';",
    "if (__cfgUrl) {",
    "  pm.request.url = __cfgUrl + '/iam/v1/internal/probe';",
    "} else {",
    f"  pm.test('{GUARD_NAME}', () => {{",
    f"    pm.expect.fail('{GUARD_FAIL}');",
    "  });",
    "  pm.execution.skipRequest();",
    "}",
]
BARE_SKIP_PRE = [
    "if (!pm.environment.get('opId')) { pm.execution.skipRequest(); }",
]


def _collection(pre_lines, name="guarded step"):
    return {
        "info": {"name": "selftest", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": [
            {
                "name": name,
                "request": {"method": "GET", "url": "{{internalBaseUrl}}/iam/v1/internal/probe"},
                "event": [
                    {"listen": "prerequest", "script": {"exec": pre_lines}},
                    {"listen": "test", "script": {"exec": ["pm.test('probe answers 200', () => pm.response.to.have.status(200));"]}},
                ],
            },
            {
                "name": "ordinary step",
                "request": {"method": "GET", "url": "{{baseUrl}}/iam/v1/users"},
                "event": [
                    {"listen": "test", "script": {"exec": ["pm.test('list answers 200', () => pm.response.to.have.status(200));"]}},
                ],
            },
        ],
    }


def _report(collection, executed_names, failures):
    """Отчёт newman: executions только для перечисленных шагов + список провалов."""
    # Курсор — то, по чему гейт опознаёт исполнение (позиция листа + длина
    # коллекции). Фикстура обязана быть НЕ снисходительнее продукта: отчёт без
    # курсоров гейт справедливо счёл бы «не про эту коллекцию».
    total = len(collection["item"])
    execs = []
    for i, it in enumerate(collection["item"]):
        if it["name"] in executed_names:
            execs.append({"cursor": {"position": i, "length": total},
                          "item": {"name": it["name"]},
                          "response": {"code": 200},
                          "assertions": [{"assertion": "ok", "skipped": False}]})
    return {
        "collection": {"info": collection["info"], "item": collection["item"]},
        "run": {
            "executions": execs,
            "failures": failures,
            "stats": {
                "requests": {"total": len(execs), "failed": 0},
                "assertions": {"total": len(execs) + len(failures), "failed": len(failures)},
            },
        },
    }


def _judge(collection, report):
    d = tempfile.mkdtemp()
    col_path = os.path.join(d, "selftest.postman_collection.json")
    with open(col_path, "w", encoding="utf-8") as fh:
        json.dump(collection, fh)
    out = os.path.join(d, "out")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "selftest.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh)
    return ec.check_collection(col_path, out)


def case(label, collection, report, want_token, want_ok):
    ok, judged, line, problems = _judge(collection, report)
    got_token = want_token in line
    verdict = "OK  " if (got_token and ok == want_ok) else "ПЛОХО"
    print(f"{verdict} {label}")
    print(f"        {line.strip()}")
    if verdict == "ПЛОХО":
        print(f"        ожидалось: в строке '{want_token}', вердикт ok={want_ok}; "
              f"получено ok={ok}")
        for p in problems:
            print(f"        {p}")
    return verdict == "OK  "


def main() -> int:
    print("=== exec-coverage: записанный пропуск vs немой разрыв, инъекция в обе стороны ===")
    good = True

    # (1) санкционированный страж, упало ЕГО утверждение → RECORDED-SKIP, не находка
    col = _collection(GUARD_PRE)
    rep = _report(col, {"ordinary step"}, [
        {"source": {"name": "guarded step"}, "parent": {"name": "selftest"},
         "error": {"name": "AssertionError", "test": GUARD_NAME, "message": GUARD_FAIL}},
    ])
    good &= case("(1) страж санкционированной формы, упало его утверждение",
                 col, rep, "RECORDED-SKIP", True)

    # (2) тот же страж, но упало утверждение ТЕСТ-скрипта → находка
    col = _collection(GUARD_PRE)
    rep = _report(col, {"ordinary step"}, [
        {"source": {"name": "guarded step"}, "parent": {"name": "selftest"},
         "error": {"name": "AssertionError", "test": "probe answers 200",
                   "message": "expected response to have status code 200"}},
    ])
    good &= case("(2) тот же шаг, упало утверждение тест-скрипта (значит он ИСПОЛНЯЛСЯ)",
                 col, rep, "ASSERTED-NOT-EXECUTED", False)

    # (3) голый skipRequest без утверждения → немой explained-skip, НЕ recorded
    col = _collection(BARE_SKIP_PRE, name="bare-skip step")
    rep = _report(col, {"ordinary step"}, [])
    ok, _judged, line, _pr = _judge(col, rep)
    got = ("explained-skip" in line) and ("RECORDED-SKIP" not in line)
    print(f"{'OK  ' if got else 'ПЛОХО'} (3) голый skipRequest без утверждения — немой пропуск, не записанный")
    print(f"        {line.strip()}")
    good &= got

    # (4) страж есть, но отчёт не говорит ЧТО упало → находка (fail-closed)
    col = _collection(GUARD_PRE)
    rep = _report(col, {"ordinary step"}, [
        {"source": {"name": "guarded step"}, "parent": {"name": "selftest"},
         "error": {"name": "AssertionError"}},
    ])
    good &= case("(4) страж есть, отчёт не называет упавшее утверждение — не извиняется",
                 col, rep, "ASSERTED-NOT-EXECUTED", False)

    print()
    if good:
        print("ДОКАЗАНО: различитель ловит немой разрыв, пропускает записанный пропуск "
              "и не превращается в амнистию по факту наличия стража.")
        return 0
    print("САМОПРОВЕРКА ПРОВАЛЕНА: различитель не подтверждён в обе стороны.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
