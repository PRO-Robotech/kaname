#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Гейт: предохранитель шага ОТМЕНЯЕТ запрос, а не только называет его предмет.

ПРЕДМЕТ. Форма предохранителя объявлена из двух половин, и обе несущие: назвать
отказ с именем переменной И ПРОПУСТИТЬ ЗАПРОС. Первая половина нужна потому, что
пропущенный запрос не оставляет в отчёте следа вовсе; вторая — потому, что шаг с
незахваченной переменной спрашивает не о ресурсе, и ответ по такому адресу
судится дальше как свидетельство о продукте.

`throw` исполняет ПЕРВУЮ половину и не исполняет вторую. Исключение в
pre-request скрипте записывается отказом СКРИПТА — и запрос уходит. Это не
догадка о чужом механизме, а замер: на прогоне #2196 шаг опроса операции
исполнился 16 раз, ответ получили ВСЕ 16, и адрес у всех был собран из
незахваченной переменной. Отказ скрипта при этом сосчитан отдельной категорией,
то есть прогон краснеет ДВАЖДЫ об одном предмете, и оба раза не о нём.

САНКЦИОНИРОВАННАЯ ФОРМА ОТМЕНЫ ОДНА — `pm.execution.skipRequest()`: она
пропускает ровно один запрос, вместе с его тест-скриптом, поэтому ничего из
шага не судится, а утверждение из pre-request'а УЖЕ записано и держит пропуск
названным.

ПОЧЕМУ ПРЕДИКАТ ИМЕННО `throw`, А НЕ «ОБЪЯВИЛ ОТКАЗ И НЕ ПРОПУСТИЛ»
-------------------------------------------------------------------
Второй предикат ЗАМЕРЕН И ОТВЕРГНУТ: на дереве он даёт 2145 из 2145 «отменяют»
и НОЛЬ находок — при двух живых дефектах. Причина в том, что он судит СКРИПТ, а
`skipRequest()` стоит в ДРУГОЙ ветке того же скрипта (у шага два предохранителя:
адрес поверхности и предмет шага). Предикат, не различающий ветвей, здесь слеп
by construction.

`throw` таким свойством не обладает: брошенное исключение не отменяет запрос
НИКОГДА, какие бы ветки ни стояли рядом. Поэтому судится оно, и это факт о
механизме, а не эвристика.

ЧТО ЭТОТ ГЕЙТ ЧИТАЕТ. Порождённые коллекции, а не исходники кейсов: предохранители
в дереве двух родов — общие (`gen.py`) и рукописные, вписанные прямо в кейс.
Проверка по исходникам видела бы только первый род, а оба живых дефекта жили
ровно во втором. Исполняемая коллекция уравнивает их (тот же довод, что у
`gen.py::audit_phantom_drop`).

КОММЕНТАРИЙ ЗА КОД НЕ СЧИТАЕТСЯ. Слово `throw` стоит в прозе, объясняющей эту же
защиту, — гейт по сырому тексту краснел бы на собственном объяснении. Состояние
лексемы определяется разбором строки: строковый литерал и комментарий из кода
вычитаются.

ПЕРЕПИСЬ печатает объём осмотренного: «ноль находок» обязано быть отличимо от
«ноль прочитанного».

Самопроверка способности упасть и смолчать — `prerequest_cancel_injection_test.py`.

КТО ЭТУ ПРОБУ ИСПОЛНЯЕТ: `.github/scripts/run-python-probes.py`. Состав он
собирает ОБХОДОМ дерева по образцу `services/*/tests/newman/scripts/*_test.py` и
НИ ОДИН файл проб по имени не называет — поэтому отдельного шага в конвейере файл
не требует, а искать вызывающего предикатом `git grep <имя файла>` бесполезно:
вызова по имени нет ни у кого. Код возврата при этом доезжает до вердикта шага.
Проводку держит `tools/pythonprobes`.
"""

import json
import pathlib
import re
import sys

NEWMAN = pathlib.Path(__file__).resolve().parents[1]

RE_THROW = re.compile(r"\bthrow\b")
SKIP = "pm.execution.skipRequest"


def code_only(line: str) -> str:
    """Строка без строковых литералов и комментариев.

    Разбирается посимвольно, потому что `//` живёт и внутри литерала адреса
    (`'https://…'`), и вырезание по образцу отняло бы у строки её код. Полного
    разбора JavaScript здесь нет и не нужно: предмет — в каком состоянии стоит
    ОДНА лексема, а не что делает программа.
    """
    out, i, n = [], 0, len(line)
    quote = None
    while i < n:
        ch = line[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'`":
            quote = ch
            i += 1
            continue
        if ch == "/" and i + 1 < n and line[i + 1] == "/":
            break
        if ch == "/" and i + 1 < n and line[i + 1] == "*":
            j = line.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _scripts(node, listen):
    """Скрипты нужного слушателя у узла коллекции."""
    for ev in node.get("event", []) or []:
        if ev.get("listen") != listen:
            continue
        src = ev.get("script", {}).get("exec", []) or []
        if isinstance(src, str):
            src = [src]
        yield src


def audit(collections_dir):
    """Находки и перепись. Судится ИСПОЛНЯЕМАЯ часть pre-request скриптов."""
    findings = []
    census = {"коллекций": 0, "шагов": 0, "pre-request скриптов": 0,
              "строк кода осмотрено": 0, "отменяют пропуском": 0}
    if not collections_dir.is_dir():
        return census, findings

    for path in sorted(collections_dir.glob("*.json")):
        census["коллекций"] += 1
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            findings.append(f"{path.name}: коллекция не читается ({exc}) — "
                            f"о её предохранителях вердикта нет")
            continue

        def walk(node, trail):
            if isinstance(node, list):
                for child in node:
                    walk(child, trail)
                return
            if not isinstance(node, dict):
                return
            name = node.get("name") or trail
            if "request" in node:
                census["шагов"] += 1
            for src in _scripts(node, "prerequest"):
                census["pre-request скриптов"] += 1
                body = [code_only(x) for x in src]
                census["строк кода осмотрено"] += len(body)
                joined = "\n".join(body)
                if SKIP in joined:
                    census["отменяют пропуском"] += 1
                for lineno, code in enumerate(body, 1):
                    if RE_THROW.search(code):
                        findings.append(
                            f"{path.name} :: {name} — pre-request отменяет запрос "
                            f"исключением (строка {lineno}): брошенное исключение "
                            f"записывается отказом СКРИПТА, а запрос уходит по адресу "
                            f"из незахваченной переменной. Санкционированная отмена — "
                            f"{SKIP}()")
            walk(node.get("item", []), name)

        walk(doc.get("item", []), path.stem)
    return census, findings


def main():
    census, findings = audit(NEWMAN / "collections")
    print("перепись: " + " · ".join(f"{k} {v}" for k, v in census.items()))
    if census["pre-request скриптов"] == 0:
        print("ОТКАЗ: pre-request скриптов не прочитано — вердикт беспредметен",
              file=sys.stderr)
        return 1
    if findings:
        print(f"НАХОДКИ ({len(findings)}):", file=sys.stderr)
        for item in findings:
            print("  " + item, file=sys.stderr)
        return 1
    print("ЧИСТО: каждый предохранитель отменяет запрос пропуском, "
          "а не исключением")
    return 0


if __name__ == "__main__":
    sys.exit(main())
