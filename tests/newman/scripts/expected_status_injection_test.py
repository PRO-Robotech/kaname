#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Доказательство, что гейт ожидаемых статусов СПОСОБЕН упасть и способен смолчать.

Гоняется НАСТОЯЩАЯ судящая функция `audit`, а не её пересказ: проба,
повторяющая логику гейта, доказывала бы свойство копии. Вход синтетический —
проба на живом дефекте исчезает вместе с ним; оси проверяются по одной, и у
каждой инъекции есть законный близнец, отличающийся ровно одним фактом.

КТО ЭТУ ПРОБУ ИСПОЛНЯЕТ: `.github/scripts/run-python-probes.py`. Состав он
собирает ОБХОДОМ дерева по образцу `services/*/tests/newman/scripts/*_test.py` и
НИ ОДИН файл проб по имени не называет — поэтому отдельного шага в конвейере файл
не требует, а искать вызывающего предикатом `git grep <имя файла>` бесполезно:
вызова по имени нет ни у кого. Код возврата при этом доезжает до вердикта шага.
Проводку держит `tools/pythonprobes`.
"""

import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import expected_status_test as gate  # noqa: E402

FAILURES = []


def check(name, condition, detail=""):
    if condition:
        print(f"  ok   {name}")
    else:
        FAILURES.append(f"{name}: {detail}")
        print(f"  FAIL {name}: {detail}")


def audit_source(body):
    """Обход одного синтетического модуля кейсов."""
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        (d / "synth.py").write_text(body, encoding="utf-8")
        return gate.audit(d)


def main():
    print("ось 1 — форма `assert_status`")
    census, findings = audit_source("CASES = []\nx = assert_status(405)\n")
    check("инъекция: 405 — находка", len(findings) == 1 and "405" in findings[0], str(findings))
    check("находка называет причину", findings and "501" in findings[0], str(findings))
    census, findings = audit_source("CASES = []\nx = assert_status(400)\n")
    check("контроль: 400 — молчание", not findings, str(findings))
    check("контроль: предмет осмотрен", census["assert_status"] == 1, str(census))

    print("ось 2 — форма литерального сравнения")
    census, findings = audit_source(
        'CASES = []\ns = "pm.expect(pm.response.code).to.eql(412);"\n')
    check("инъекция: 412 — находка", len(findings) == 1 and "412" in findings[0], str(findings))
    census, findings = audit_source(
        'CASES = []\ns = "pm.expect(pm.response.code).to.eql(404);"\n')
    check("контроль: 404 — молчание", not findings, str(findings))
    check("контроль: предмет осмотрен", census["литерал"] == 1, str(census))

    print("ось 3 — форма полосы допустимых кодов")
    # Самая коварная: полоса проходит на возможном статусе, а невозможный
    # переживает в тексте как объявленное намерение.
    census, findings = audit_source(
        'CASES = []\ns = "pm.expect(pm.response.code).to.be.oneOf([400, 412]);"\n')
    check("инъекция: невозможный статус ВНУТРИ полосы — находка",
          len(findings) == 1 and "412" in findings[0], str(findings))
    census, findings = audit_source(
        'CASES = []\ns = "pm.expect(pm.response.code).to.be.oneOf([400, 403, 404]);"\n')
    check("контроль: полоса из производимых — молчание", not findings, str(findings))
    check("контроль: предмет осмотрен", census["полоса"] == 3, str(census))

    print("ось 4 — 422 и неназванный статус")
    _, findings = audit_source("CASES = []\nx = assert_status(422)\n")
    check("инъекция: 422 — находка", len(findings) == 1, str(findings))
    _, findings = audit_source("CASES = []\nx = assert_status(418)\n")
    check("инъекция: статус вне перечня поимённых — тоже находка",
          len(findings) == 1 and "418" in findings[0], str(findings))

    print("ось 5 — пустой обход не выдаётся за чистый")
    census, findings = audit_source("CASES = []\n")
    check("модуль без утверждений: находок нет...", not findings, str(findings))
    check("...но и предмета нет — гейт обязан отказать по перекличке",
          census["assert_status"] + census["литерал"] + census["полоса"] == 0, str(census))

    print()
    if FAILURES:
        print(f"ОТКАЗ: провалено утверждений {len(FAILURES)} из 14", file=sys.stderr)
        for f in FAILURES:
            print("  " + f, file=sys.stderr)
        return 1
    print("ЧИСТО: 14 утверждений, гейт способен упасть и способен смолчать по каждой оси")
    return 0


if __name__ == "__main__":
    sys.exit(main())
