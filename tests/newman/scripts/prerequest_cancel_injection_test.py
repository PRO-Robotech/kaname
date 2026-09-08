#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Доказательство, что гейт отмены запроса СПОСОБЕН упасть и смолчать.

Гоняется НАСТОЯЩАЯ судящая функция `audit`, а не её пересказ. Дерево
синтетическое; у каждой инъекции есть законный близнец, отличающийся РОВНО
ОДНИМ фактом.

ПРОГОНОВ ПО ОСИ ТРИ, А НЕ ДВА. Инъекция обязана ронять только проверяемое:
если она попутно нарушает СОСЕДНИЙ контроль, красное приходит от соседа, и
новый гейт мог бы оказаться вакуумным, не показав этого ничем. Поэтому рядом
стоит прогон, где нарушена ось ДРУГОГО гейта (метка), и этот гейт обязан
СМОЛЧАТЬ: предметы у них разные — метка про КАТЕГОРИЮ исхода, отмена про то,
случился ли запрос вообще.

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

import prerequest_cancel_test as gate  # noqa: E402

FAILURES = []
TOTAL = 12


def check(name, ok, detail=""):
    print(f"  {'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f": {detail}"))
    if not ok:
        FAILURES.append(f"{name}: {detail}")


def run(pre_lines, test_lines=None):
    """Одна коллекция, один шаг: pre-request и (по желанию) тест-скрипт."""
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp) / "collections"
        root.mkdir(parents=True)
        events = [{"listen": "prerequest", "script": {"exec": list(pre_lines)}}]
        if test_lines is not None:
            events.append({"listen": "test", "script": {"exec": list(test_lines)}})
        (root / "synth.postman_collection.json").write_text(json.dumps(
            {"info": {"name": "synth"},
             "item": [{"name": "step",
                       "request": {"method": "GET", "url": "http://127.0.0.1/x"},
                       "event": events}]}, ensure_ascii=False), encoding="utf-8")
        return gate.audit(root)


SANCTIONED = ["if (!pm.environment.get('opVar')) {",
              "  pm.test('opVar захвачен', () => {",
              "    pm.expect.fail('opVar пуст');",
              "  });",
              "  pm.execution.skipRequest();",
              "}"]
# Различие с санкционированной формой — РОВНО ОДНО: чем отменяют запрос.
THROWING = ["if (!pm.environment.get('opVar')) {",
            "  throw new Error('opVar пуст');",
            "}"]


def main():
    print("ось 1 — контроль: санкционированная форма молчит")
    c, f = run(SANCTIONED)
    check("молчание", not f, str(f))
    check("предмет осмотрен, а не пропущен",
          c["pre-request скриптов"] == 1 and c["строк кода осмотрено"] > 0, str(c))
    check("и отмена сосчитана", c["отменяют пропуском"] == 1, str(c))

    print("ось 2 — инъекция: отмена исключением")
    c, f = run(THROWING)
    check("находка с координатой шага",
          len(f) == 1 and "synth" in f[0] and "step" in f[0], str(f))
    check("находка называет ПРЕДМЕТ, а не симптом",
          f and "запрос уходит" in f[0] and "skipRequest" in f[0], str(f))
    check("и перепись показывает, что отмены нет", c["отменяют пропуском"] == 0, str(c))

    print("ось 3 — законные близнецы: та же лексема НЕ в коде")
    _, f = run(["// throw здесь объясняет запрет, а не исполняет его", *SANCTIONED])
    check("в комментарии — молчание", not f, str(f))
    _, f = run(["pm.environment.set('why', 'не throw, а skipRequest');", *SANCTIONED])
    check("в строковом литерале — молчание", not f, str(f))
    _, f = run(["const u = 'http://x/y'; // адрес с // внутри литерала", *SANCTIONED])
    check("литерал адреса код не съедает", not f, str(f))

    print("ось 4 — предмет гейта только pre-request")
    _, f = run(SANCTIONED, test_lines=["if (!x) { throw new Error('в ТЕСТ-скрипте законно'); }"])
    check("throw в тест-скрипте находкой не является (запрос уже случился)", not f, str(f))

    print("ось 5 — инъекция ЧУЖОЙ оси: этот гейт обязан смолчать")
    unmarked = ["if (!pm.environment.get('jwtX')) {",
                "  pm.test('harness config: jwtX is set (subject under test)', () => {",
                "    pm.expect.fail('jwtX is not set');",
                "  });",
                "  pm.execution.skipRequest();",
                "}"]
    _, f = run(unmarked)
    check("непомеченный страж — предмет ДРУГОГО гейта, здесь молчание", not f, str(f))

    print("ось 6 — пустой обход не выдаётся за чистый")
    with tempfile.TemporaryDirectory() as tmp:
        c, f = gate.audit(pathlib.Path(tmp) / "нет-такого")
    check("каталога нет — находок нет, но и предмета нет",
          not f and c["pre-request скриптов"] == 0, f"{f} {c}")

    print()
    if FAILURES:
        print(f"ОТКАЗ: провалено утверждений {len(FAILURES)} из {TOTAL}", file=sys.stderr)
        for x in FAILURES:
            print("  " + x, file=sys.stderr)
        return 1
    print(f"ЧИСТО: {TOTAL} утверждений, гейт способен упасть и способен смолчать по каждой оси")
    return 0


if __name__ == "__main__":
    sys.exit(main())
