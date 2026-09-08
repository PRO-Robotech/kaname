#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Доказательство, что гейт единственности метки СПОСОБЕН упасть и смолчать.

Гоняется НАСТОЯЩАЯ судящая функция `audit`, а не её пересказ. Дерево
синтетическое; оси проверяются по одной, у каждой инъекции — законный близнец,
отличающийся РОВНО ОДНИМ фактом.

Литерал метки здесь тоже не выписывается: он берётся у того же производителя,
что и в самом гейте, — иначе доказательство стало бы третьим местом об одном
предмете.

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

import precondition_mark_test as gate  # noqa: E402

FAILURES = []


def check(name, ok, detail=""):
    print(f"  {'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f": {detail}"))
    if not ok:
        FAILURES.append(f"{name}: {detail}")


def build(tmp, producers, case_bodies, gate_body, guards=None):
    root = pathlib.Path(tmp)
    (root / "scripts").mkdir(parents=True)
    (root / "cases").mkdir()
    (root / "scripts" / "gen.py").write_text(producers, encoding="utf-8")
    (root / "scripts" / "assert-suites-green.sh").write_text(gate_body, encoding="utf-8")
    for name, body in case_bodies.items():
        (root / "cases" / name).write_text(body, encoding="utf-8")
    if guards is not None:
        (root / "collections").mkdir()
        (root / "collections" / "synth.postman_collection.json").write_text(
            json.dumps(collection(guards), ensure_ascii=False), encoding="utf-8")
    return root


def collection(guard_lines):
    """Синтетическая коллекция: один шаг, чей pre-request несёт данные строки."""
    return {"info": {"name": "synth"},
            "item": [{"name": "step", "request": {"method": "GET", "url": "http://127.0.0.1/x"},
                      "event": [{"listen": "prerequest",
                                 "script": {"exec": list(guard_lines)}}]}]}


def run(producers, case_bodies, gate_body, guards=None):
    with tempfile.TemporaryDirectory() as tmp:
        return gate.audit(build(tmp, producers, case_bodies, gate_body, guards))


# Метка — у производителя дерева, не выписана здесь.
MARK = gate.read_mark(gate.NEWMAN / "scripts" / "gen.py")[0]
ONE = f'PRECONDITION_MARK = "{MARK}"\n'
GOOD_GATE = 'echo hi\nPRECONDITION_MARK="$(python3 -c \'import gen; print(gen.PRECONDITION_MARK)\')"\n'
GOOD_CASES = {"a.py": "CASES = []\n", "b.py": "CASES = []\n"}


def main():
    print("ось 1 — производитель ровно один")
    c, f = run(ONE, GOOD_CASES, GOOD_GATE)
    check("контроль: молчание", not f, str(f))
    check("контроль: предмет осмотрен", c["файлов кейсов осмотрено"] == 2, str(c))
    _, f = run(ONE + f'PRECONDITION_MARK = "{MARK} и ещё"\n', GOOD_CASES, GOOD_GATE)
    check("инъекция: второе объявление — находка", any("производителей метки 2" in x for x in f), str(f))
    _, f = run("# метки нет вовсе\n", GOOD_CASES, GOOD_GATE)
    check("инъекция: производителя нет — находка", any("должен быть ровно один" in x for x in f), str(f))

    print("ось 2 — метку ставит кто-то ещё")
    bad = dict(GOOD_CASES)
    bad["b.py"] = f'CASES = []\n# {MARK} мой личный третий исход\n'
    _, f = run(ONE, bad, GOOD_GATE)
    check("инъекция: кейс ставит метку — находка с именем файла",
          any("b.py" in x and "сам" in x for x in f), str(f))
    _, f = run(ONE, GOOD_CASES, GOOD_GATE)
    check("законный близнец: тот же кейс без метки — молчание", not f, str(f))

    print("ось 3 — вердикт выписывает метку литералом")
    _, f = run(ONE, GOOD_CASES, GOOD_GATE + f'if [ "$x" = "{MARK}" ]; then :; fi\n')
    check("инъекция: находка", any("своим литералом" in x for x in f), str(f))

    print("ось 4 — вердикт не читает метку у производителя")
    _, f = run(ONE, GOOD_CASES, "echo hi\n")
    check("инъекция: находка", any("не берёт метку у производителя" in x for x in f), str(f))

    print("ось 5 — вердиктного гейта нет вовсе")
    with tempfile.TemporaryDirectory() as tmp:
        root = build(tmp, ONE, GOOD_CASES, GOOD_GATE)
        (root / "scripts" / "assert-suites-green.sh").unlink()
        _, f = gate.audit(root)
    check("инъекция: находка", any("вердиктного гейта нет" in x for x in f), str(f))

    print("ось 6 — производитель формы не ставит метку (по порождённым коллекциям)")
    # Три прогона, а не два: инъекция обязана ронять ТОЛЬКО проверяемое, иначе
    # красное пришло бы от соседней оси, а новая могла бы оказаться вакуумной,
    # не показав этого ничем.
    marked = [f"pm.test('{MARK} harness config: someVar is set', () => {{",
              "  pm.expect.fail('someVar is not set');", "});",
              "pm.execution.skipRequest();"]
    unmarked = [x.replace(f"{MARK} ", "") for x in marked]

    c, f = run(ONE, GOOD_CASES, GOOD_GATE, guards=marked)
    check("контроль: всё цело — молчат ОБЕ оси", not f, str(f))
    check("контроль: страж осмотрен и сосчитан помеченным",
          c.get("стражей harness config") == 1 and c.get("НЕ помечено") == 0, str(c))

    c, f = run(ONE, GOOD_CASES, GOOD_GATE, guards=unmarked)
    check("инъекция НОВОЙ оси: непомеченный страж — находка с координатой",
          len(f) == 1 and "synth" in f[0] and "step" in f[0] and "без метки" in f[0], str(f))
    check("и перепись называет ОБЕ величины, а не одну",
          c.get("стражей harness config") == 1 and c.get("НЕ помечено") == 1, str(c))

    bad_case = dict(GOOD_CASES)
    bad_case["b.py"] = f'CASES = []\n# {MARK} мой личный третий исход\n'
    _, f = run(ONE, bad_case, GOOD_GATE, guards=marked)
    check("инъекция СТАРОЙ оси: краснеет только она, новая молчит",
          len(f) == 1 and "b.py" in f[0], str(f))

    print("ось 7 — законные близнецы новой оси: молчание")
    op_guard = ["pm.test('operation id opId was captured', () => {",
                "  pm.expect.fail('opId is empty');", "});",
                "pm.execution.skipRequest();"]
    _, f = run(ONE, GOOD_CASES, GOOD_GATE, guards=op_guard)
    check("страж ПРЕДМЕТА ШАГА метки не несёт и находкой не является", not f, str(f))
    c, f = run(ONE, GOOD_CASES, GOOD_GATE,
               guards=["// harness config: someVar is set — проза об этой же защите",
                       *marked])
    check("та же фраза в КОММЕНТАРИИ за объявление не считается",
          not f and c.get("стражей harness config") == 1, f"{f} {c}")

    print()
    if FAILURES:
        print(f"ОТКАЗ: провалено утверждений {len(FAILURES)} из 15", file=sys.stderr)
        for x in FAILURES:
            print("  " + x, file=sys.stderr)
        return 1
    print("ЧИСТО: 15 утверждений, гейт способен упасть и способен смолчать по каждой оси")
    return 0


if __name__ == "__main__":
    sys.exit(main())
