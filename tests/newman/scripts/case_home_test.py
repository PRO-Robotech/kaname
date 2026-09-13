#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ДОМ МОДУЛЯ КЕЙСОВ: объявление сверяется с деревом, и расходиться им нечем.

ПРЕДМЕТ. Норма — корпус воркспейса, `e2e-flow.md` §7а «ДОМ пробы — репозиторий
её ПРЕДМЕТА, а не тот, через чей край она ходит». Решение владельца (2026-09-12)
дословно: «в канаме репозитории тестируем только сущности канаме, в качо
тестируем связку и не тестируем ресурсы канаме».

ДВА НЕЗАВИСИМЫХ ВЫРАЖЕНИЯ ОБ ОДНОМ ПРЕДМЕТЕ, И В ЭТОМ ВЕСЬ СМЫСЛ:

  ОБЪЯВЛЕНИЕ — `HOME` в самом модуле. Это АДЪЮДИКАЦИЯ: чей предмет утверждает
               проба. Машинно она не выводится — «утверждает ли это поведение
               службы или поведение края, опирающееся на службу» решает человек.
  ПРИЗНАК    — домены, выведенные из REST-путей ЭТОГО ЖЕ модуля. Он машинный и
               даёт КАНДИДАТОВ, а не вердикт.

Гейт требует их согласия. Выписанный отдельным списком разрез разошёлся бы с
деревом молча и разошёлся бы в одну сторону: новый модуль в него просто не
попал бы. Объявление живёт В МОДУЛЕ, рядом со своим предметом, поэтому второго
места не заводится.

ПРАВИЛА — И ПОЧЕМУ ИХ ЖЁСТКОСТЬ РАЗНАЯ

  R1  модуль обязан объявить `HOME`;
  R2  `HOME` ∈ {"kaname", "kacho"};
  R3  модуль, трогающий ЧУЖОЙ домен, не может быть домом службы. Это ЖЁСТКАЯ
      импликация, а не вкус: автономный стенд службы чужих доменов не поднимает
      вовсе, поэтому такой модуль здесь не исполним ни при каком устройстве;
  R4  модуль, трогающий ТОЛЬКО `iam`, по умолчанию дом службы — но объявить
      дом платформы ЕМУ НЕ ЗАПРЕЩЕНО: свойство может производить край (разбор
      доступа с извлечением области, скрытие существования, отображение кода в
      статус). Тогда обязан быть назван производитель — см. R5. Запретить этот
      случай значило бы объявить несуществующим ровно тот, ради которого
      различают «через чей край ходит» и «чей предмет»;
  R5  `HOME = "kacho"` обязан нести непустой `HOME_REASON` — поведение КАКОГО
      домена модуль утверждает. Это половина разреза, которая не выводится
      ничем, и предикат снятия задачи требует именно её.

ЧЕГО ЭТОТ ГЕЙТ НЕ ДЕЛАЕТ — сказано прямо. Он не судит, ВЕРНА ли адъюдикация:
`HOME_REASON` — проза, и её истинность машине недоступна. Он судит наличие,
допустимость значения, согласие с признаком и наличие названного производителя.
Тот же предел, что у машинного чтения вердикта приёмки: оно судит объявление.

ИСХОДЫ:
    0 — чисто, перепись напечатана;
    1 — находка ЛИБО пустой обход (модулей ноль — «ноль находок» тогда означало
        бы «ноль прочитанного», и это не вердикт).

САМОПРОВЕРКА — `--self-test`: синтетическое дерево, инъекция по КАЖДОЙ оси с
законным близнецом, плюс пустой обход. Без неё молчание гейта неотличимо от
молчания мёртвого гейта.
"""

from __future__ import annotations

import argparse
import ast
import pathlib
import re
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
CASES_DIR = HERE.parent / "cases"

OWN_REPO_HOME = "kaname"
PLATFORM_HOME = "kacho"
KNOWN_HOMES = (OWN_REPO_HOME, PLATFORM_HOME)

# Собственный домен ЭТОГО репозитория. Остальные — чужие по построению: их
# владелец другой репозиторий, и автономный стенд службы их не поднимает.
OWN_DOMAIN = "iam"

# Признак домена — REST-путь в объявлении кейса. Тот же предикат, что в теле
# задачи и в `e2e-flow.md` §7а: он и есть общий язык обеих сторон разреза.
DOMAIN_RE = re.compile(r"/(iam|geo|vpc|nlb|storage|compute|registry)/v1")


def domains_of(text: str) -> list[str]:
    """Домены, которые трогает модуль. Пусто — модуль не ходит ни в один."""
    return sorted(set(DOMAIN_RE.findall(text)))


def _module_str_constant(tree: ast.Module, name: str) -> str | None:
    """Значение строковой константы уровня модуля, БЕЗ импорта модуля.

    Импортировать нельзя: модули кейсов ждут инъекции помощников генератором,
    и импорт здесь превратил бы гейт в запуск чужого кода ради одной строки.
    """
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for tgt in node.targets:
            if isinstance(tgt, ast.Name) and tgt.id == name:
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    return node.value.value
                return ""      # объявлено, но не строковой константой
    return None                # не объявлено вовсе


def audit(cases_dir: pathlib.Path) -> tuple[list[str], dict]:
    findings: list[str] = []
    census = {"модулей": 0, "дом службы": 0, "дом платформы": 0,
              "трогают чужой домен": 0, "не трогают ни одного": 0}

    for path in sorted(cases_dir.glob("*.py")):
        if path.name.startswith("_"):
            continue           # общий помощник набора, не модуль кейсов
        text = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError as exc:
            findings.append(f"{path.name}: не разбирается как python ({exc})")
            continue

        census["модулей"] += 1
        doms = domains_of(text)
        foreign = [d for d in doms if d != OWN_DOMAIN]
        if foreign:
            census["трогают чужой домен"] += 1
        if not doms:
            census["не трогают ни одного"] += 1

        home = _module_str_constant(tree, "HOME")
        reason = _module_str_constant(tree, "HOME_REASON")

        if home is None:                                              # R1
            findings.append(
                f"{path.name}: не объявлен HOME. Домены по REST-путям: "
                f"{','.join(doms) or '(ни одного)'}. Дом пробы — репозиторий её ПРЕДМЕТА "
                f"(e2e-flow.md §7а); объяви HOME = \"kaname\" либо \"kacho\".")
            continue
        if home not in KNOWN_HOMES:                                   # R2
            findings.append(
                f"{path.name}: HOME={home!r} — неизвестный дом, ожидается один из {KNOWN_HOMES}")
            continue

        census["дом службы" if home == OWN_REPO_HOME else "дом платформы"] += 1

        if foreign and home == OWN_REPO_HOME:                         # R3
            findings.append(
                f"{path.name}: HOME=\"{OWN_REPO_HOME}\", но модуль трогает чужой домен "
                f"({','.join(foreign)}). Автономный стенд службы чужих доменов не поднимает — "
                f"здесь этот модуль не исполним ни при каком устройстве. Его предмет — связка, "
                f"дом которой платформа.")
        if home == PLATFORM_HOME and not (reason or "").strip():      # R5
            findings.append(
                f"{path.name}: HOME=\"{PLATFORM_HOME}\" без HOME_REASON. Назови, поведение КАКОГО "
                f"домена утверждает модуль: это та половина разреза, которая ничем не выводится.")

    return findings, census


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--self-test", action="store_true",
                    help="доказать способность гейта падать И молчать")
    ap.add_argument("--cases-dir", default=str(CASES_DIR))
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    cases_dir = pathlib.Path(args.cases_dir)
    findings, census = audit(cases_dir)

    print("перепись: " + " · ".join(f"{k} {v}" for k, v in census.items()))
    if census["модулей"] == 0:
        print(f"ОТКАЗ: обход пуст — модулей кейсов в {cases_dir} не прочитано ни одного.",
              file=sys.stderr)
        print("«Ноль находок» здесь означало бы «ноль прочитанного», а это не вердикт.",
              file=sys.stderr)
        return 1
    if findings:
        print(f"\nНАХОДОК: {len(findings)}", file=sys.stderr)
        for f in findings:
            print(f"  · {f}", file=sys.stderr)
        return 1
    print("ЧИСТО: у каждого модуля объявлен дом, и объявление сходится с деревом")
    return 0


# --------------------------------------------------------------------------
# САМОПРОВЕРКА
# --------------------------------------------------------------------------

_CLEAN_OWN = 'HOME = "kaname"\nSTEPS = ["/iam/v1/users"]\n'
_CLEAN_FOREIGN = ('HOME = "kacho"\nHOME_REASON = "связка iam×vpc: предмет — поведение vpc"\n'
                  'STEPS = ["/iam/v1/users", "/vpc/v1/networks"]\n')
_CLEAN_EDGE_ONLY_IAM = ('HOME = "kacho"\nHOME_REASON = "предмет — рубеж края, маршрут iam лишь носитель"\n'
                        'STEPS = ["/iam/v1/accounts"]\n')

_CASES = [
    # (имя, содержимое, обязана ли быть находка, что доказывает)
    ("clean_own.py",     _CLEAN_OWN,     False, "законный близнец R1/R3/R4"),
    ("clean_foreign.py", _CLEAN_FOREIGN, False, "законный близнец R3/R5"),
    ("clean_edge.py",    _CLEAN_EDGE_ONLY_IAM, False,
     "законный близнец R4: только iam, но дом платформы с названным производителем"),
    ("no_home.py",       'STEPS = ["/iam/v1/users"]\n', True, "R1: HOME не объявлен"),
    ("bad_home.py",      'HOME = "somewhere"\nSTEPS = ["/iam/v1/users"]\n', True,
     "R2: неизвестное значение"),
    ("foreign_own.py",   'HOME = "kaname"\nSTEPS = ["/iam/v1/users", "/nlb/v1/loadBalancers"]\n',
     True, "R3: чужой домен при доме службы"),
    ("kacho_no_reason.py", 'HOME = "kacho"\nSTEPS = ["/iam/v1/users", "/geo/v1/zones"]\n', True,
     "R5: дом платформы без названного производителя"),
    ("kacho_blank_reason.py",
     'HOME = "kacho"\nHOME_REASON = "   "\nSTEPS = ["/iam/v1/users", "/geo/v1/zones"]\n', True,
     "R5: пробельная причина причиной не является"),
]


def self_test() -> int:
    failures: list[str] = []
    checks = 0

    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)

        # ОСЬ ЗА ОСЬЮ: каждый дефект вносится ОТДЕЛЬНО, рядом с законными
        # близнецами. Свалив их в одно дерево, нельзя отличить «покраснел на
        # моём дефекте» от «покраснел на соседнем».
        for name, body, must_find, what in _CASES:
            d = root / f"case_{name[:-3]}"
            d.mkdir()
            for cname, cbody, *_ in _CASES[:3]:          # законные близнецы всегда рядом
                (d / cname).write_text(cbody, encoding="utf-8")
            (d / name).write_text(body, encoding="utf-8")
            findings, census = audit(d)
            mine = [f for f in findings if f.startswith(name)]
            checks += 1
            if must_find and not mine:
                failures.append(f"{what}: дефект внесён, гейт молчит ({name})")
            if not must_find and findings:
                failures.append(f"{what}: дерево законно, гейт нашёл {findings}")
            # контроль: близнецы не краснеют НИКОГДА
            checks += 1
            twins = [f for f in findings if not f.startswith(name)]
            if twins:
                failures.append(f"{what}: покраснел законный близнец, а не предмет: {twins}")

        # пустой обход — отказ, а не «чисто»
        empty = root / "empty"
        empty.mkdir()
        findings, census = audit(empty)
        checks += 1
        if census["модулей"] != 0:
            failures.append("пустой обход: перепись не ноль")
        rc = main(["--cases-dir", str(empty)])
        checks += 1
        if rc != 1:
            failures.append(f"пустой обход обязан быть отказом, получено rc={rc}")

        # модуль с ведущим подчёркиванием — помощник, а не модуль кейсов
        helper = root / "helper"
        helper.mkdir()
        (helper / "clean_own.py").write_text(_CLEAN_OWN, encoding="utf-8")
        (helper / "_helpers.py").write_text('STEPS = ["/vpc/v1/networks"]\n', encoding="utf-8")
        findings, census = audit(helper)
        checks += 1
        if findings or census["модулей"] != 1:
            failures.append(f"помощник `_*.py` обязан быть вне обхода: {findings}, {census}")

    print(f"самопроверка: утверждений {checks}, осей {len(_CASES)} + пустой обход + помощник")
    if failures:
        print("ОТКАЗ самопроверки:", file=sys.stderr)
        for f in failures:
            print(f"  · {f}", file=sys.stderr)
        return 1
    print("самопроверка ПРОЙДЕНА: гейт падает на каждой оси и молчит на законных близнецах")
    return 0


if __name__ == "__main__":
    sys.exit(main())
