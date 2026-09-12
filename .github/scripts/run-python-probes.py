#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Прогонщик регрессионных проб на python: пробы сюит обязаны ИСПОЛНЯТЬСЯ.

ПРЕДМЕТ
-------
Регрессионные пробы вокруг оснастки наборов newman. Живут они на ДВУХ уровнях, и
образцов состава поэтому два (см. `DEFAULT_PATTERNS` ниже):

  * `tests/newman/scripts/*_test.py` — пробы набора СЛУЖБЫ и вендоренного сюда
    вердиктного слоя (`assert-suites-green.sh`, `exec-coverage.py`, `coverage.py`).
    В дереве платформы этот слой судит семь её наборов и потому не принадлежит ни
    одному; здесь он ВЕНДОРЕН (`tests/newman/vendor-provenance.json`), потому что
    подъём за ним из отдельного репозитория корня монорепо не достаёт;
  * `tests/authz-fixtures/*_test.py` — пробы ПОСЕВА, который поднимает фикстуры
    боевой посадки. Слой третий, а не тот же самый: посев исполняется ДО первой
    коллекции, и его отказ не даёт ни одного отчёта — то есть вердиктный слой ему
    не судья, он лишь сообщает, что судить нечего.

    В ЭТОМ РЕПОЗИТОРИИ ПОСЕВА НЕТ НИ ОДНИМ ФАЙЛОМ, и образец находит ноль проб.
    Он оставлен НАМЕРЕННО и виден в переписи по каждому образцу на КАЖДОМ прогоне
    («по образцу tests/authz-fixtures/*_test.py: 0»), то есть долг называется
    числом, а не молчанием. Посев за всю историю репозитория службы не коммитился
    (`git log --oneline --all -- tests/authz-fixtures | wc -l` → 0); появится —
    образец начнёт находить его пробы сам, без правки прогонщика.

Их не запускал НИКТО: ни workflow, ни
Makefile, ни другой гейт. Слово `pytest` встречалось во всём дереве один раз — в
`.dockerignore`, где закрыт кэш его прогонов, то есть кто-то гонял их руками и
след остался только от кэша.

Цена не абстрактна. Среди этих проб — доказательство гейта, который в своё время
нашёл, что прогон послал не все запросы, а сюита при этом отчиталась зелёной.
То есть проверка, ловящая ложное зелёное, сама была ложно-зелёной: её вердикт не
доходил ни до чьего кода выхода.

ПОЧЕМУ PYTEST, А НЕ СОБСТВЕННЫЙ РАННЕР
--------------------------------------
28 проб из 48 принимают фикстуру `tmp_path` (свой временный каталог на пробу):
`exec_coverage_test.py` — 23, `coverage_test.py` — 5. Собственный раннер обязан
был бы либо воспроизвести внедрение фикстур и разбор утверждений, либо потребовать
переписать 28 рабочих проб под себя. Переписывать зелёные пробы под раннер,
который сам ещё надо доказать, — больший риск, чем взять исполнитель, чьё
поведение известно (и это прямо запрещает LEAN: не изобретать сложное там, где
хватает готового).

Форма `--self-test` (как у `deploy/scripts/assert-*.py`) уместна ГЕЙТУ: один
предмет, один вердикт, доказательство инъекцией. Здесь предмет другой — НАБОР из
48 независимых проб с интроспекцией утверждений. Оба вида в дереве уже есть:
`phantom_gate_test.py` написан гейтом (свой `main`, ноль функций `test_`), эти
четыре — набором, и написаны они именно под pytest (голый `assert`, `tmp_path`).

ПОЧЕМУ СВЕРХ PYTEST НУЖЕН ЭТОТ ФАЙЛ
-----------------------------------
Одного `pytest <каталог>` недостаточно, и это не вкусовщина:

  * pytest выходит кодом 5 только когда не собрано НИ ОДНОЙ пробы. Он ничего не
    скажет, если из пяти файлов молча выпали четыре — а это ровно тот класс,
    ради которого файл и написан;
  * состав обязан находиться ОБХОДОМ отслеживаемого дерева (`git ls-files`), а не
    перечисляться в шаге: тогда проба нового сервиса попадает под гейт по
    построению, а не после того, как кто-то вспомнит. Единица счёта — элемент,
    versioned в git, то есть то же множество, что увидит CI на свежем checkout'е;
  * `phantom_gate_test.py` устроен ГЕЙТОМ: pytest соберёт из него ноль проб и
    промолчит. Файл, попавший в состав и не давший ни одной пробы, — та же немота
    классом ниже, поэтому вид файла определяется РАЗБОРОМ, а исполняется каждый
    по своей форме;
  * «ноль исполненных» обязано быть ОТКАЗОМ, а не успехом, и объём осмотренного
    обязан печататься: иначе «ноль находок» неотличимо от «ноль прочитанного».

ВИД ФАЙЛА ЧИТАЕТСЯ РАЗБОРОМ (AST), А НЕ ГРЕПОМ. Строка `def test_...` встречается
в объяснениях и строковых литералах; грепом по тексту вид определялся бы по
прозе. Разбор видит объявления верхнего уровня и ветку `__main__` — то есть код.

ПРОПУСК НЕ ЗАСЧИТЫВАЕТСЯ ЗА ПРОХОД. Пропущенная проба — отказ прогонщика:
маскировка запрещена (`testing.md` §«E2E никогда не пропускаются»), и молчаливый
`skip` здесь — тот самый способ обойти.

Запуск:
  python3 .github/scripts/run-python-probes.py --self-test   # доказательство инъекцией
  python3 .github/scripts/run-python-probes.py               # прогон по дереву
"""
from __future__ import annotations

import argparse
import ast
import fnmatch
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

# Образцы состава. Тот же вид, что у сверщиков переписи кейсов
# (`services/*/tests/newman/scripts/validate-cases.py`): сюита названа звёздочкой,
# поэтому новая попадает под гейт сама.
#
# ОБРАЗЦОВ ДВА, И ЭТО НЕ УДОБСТВО. Пробы оснастки живут в `tests/newman/scripts/`
# двух разных уровней: у каждой суиты — свои (`services/<svc>/…`), и ОДИН на
# дерево — вокруг вердиктного слоя (`<корень>/tests/newman/scripts/`), который
# судит все восемь наборов и потому не принадлежит ни одному.
#
# ПОЧЕМУ НЕ ОДИН ОБРАЗЕЦ СО ЗВЁЗДОЧКОЙ ВПЕРЕДИ. `*` в pathspec git пересекает
# `/`, в `fnmatch` — пересекает, а в `filepath.Match` (на нём написан гейт
# проводки в дереве платформы) — НЕ пересекает. Один образец `*/tests/newman/…`
# читался бы прогонщиком и его гейтом ПО-РАЗНОМУ, и разошлись бы они молча: гейт
# объявил бы пробу невидимой там, где прогонщик её видит. Перечень явных
# образцов, ни один из которых не пересекает `/`, читается всеми тремя
# одинаково.
#
# ОБРАЗЕЦ, НЕ НАХОДЯЩИЙ НИЧЕГО, — НАХОДКА, а не мелочь: расширение обхода, не
# изменившее переписи, выглядит покрытием и им не является. В дереве платформы
# это требование держит гейт проводки; ЗДЕСЬ его нет, и держит только перепись по
# каждому образцу отдельно — она печатается всегда, поэтому ноль у образца посева
# виден на каждом прогоне и назван числом.
# Здесь был ТРЕТИЙ образец — `services/*/tests/newman/scripts/*_test.py`, пробы
# генератора коллекций СВОЕГО набора. Он снят вместе со своим предметом: такие
# пробы нёс только набор службы доступа, а служба вынесена отдельным продуктом
# (задача #1111). Образец, не находящий в дереве НИ ОДНОЙ пробы, — расширение
# вхолостую: он выглядит покрытием и им не является.
#
# Снятие обратимо и восстанавливается САМО: заведёт служба свои пробы этого
# уровня — второй половине гейта проводки в дереве платформы («всякий
# отслеживаемый файл проб покрыт образцом») покрыть его станет нечем. В ЭТОМ
# репозитории набор свои пробы этого уровня НЕСЁТ (26 файлов на момент
# вендоринга), и находит их ПЕРВЫЙ образец: `tests/newman/scripts/*_test.py` —
# набор здесь лежит в корне, а не под `services/<имя>/`.
DEFAULT_PATTERNS = (
    "tests/newman/scripts/*_test.py",
    "tests/authz-fixtures/*_test.py",
)

# Виды файла проб.
KIND_PYTEST = "набор pytest"
KIND_SCRIPT = "гейт со своим main"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def list_tracked(root: Path, patterns: tuple[str, ...]) -> list[str]:
    """Состав — по содержимому репозитория, с откатом на обход ФС.

    Для репозитория авторитет — версионный контроль (то же множество, что у CI на
    свежем checkout'е). В синтетическом дереве самопроверки git недоступен, и тогда
    обход идёт по файловой системе: тот же приём и по той же причине, что в
    `deploy/scripts/run-gate-self-tests.sh`.

    Образцы объединяются, а не выбираются: файл, попавший под два сразу, считается
    один раз — иначе перепись «файлов проб найдено» назвала бы больше, чем есть.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--", *patterns],
            capture_output=True, text=True, timeout=60, check=True).stdout
        names = sorted({n for n in out.split("\0") if n})
        if names:
            return names
    except (subprocess.SubprocessError, OSError):
        pass
    found = set()
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            rel = os.path.relpath(os.path.join(dirpath, f), root)
            rel = rel.replace(os.sep, "/")
            if any(fnmatch.fnmatch(rel, pat) for pat in patterns):
                found.add(rel)
    return sorted(found)


def classify(path: Path) -> tuple[str | None, list[str]]:
    """Вид файла и имена его проб — РАЗБОРОМ, а не поиском по тексту."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, OSError) as e:
        return None, [f"не разбирается: {e}"]

    probes = [
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    ]
    if probes:
        return KIND_PYTEST, sorted(probes)

    for node in tree.body:
        if not isinstance(node, ast.If):
            continue
        for sub in ast.walk(node.test):
            if isinstance(sub, ast.Name) and sub.id == "__name__":
                return KIND_SCRIPT, []
    return None, []


# МЕТКА ТРЕТЬЕГО ИСХОДА. Та же, что у Go-проб этого репозитория и у переписи
# `scripts/test-standalone.sh`: контракт между пробой и прогонщиком — ТЕКСТ метки,
# а не число её производителей.
#
# ЗАЧЕМ ОНА ЗДЕСЬ. Пропуск в общем случае — способ обойти, и прогонщик правильно
# считает его отказом. Но «условие не создано» — НЕ пропуск ради зелёного: это
# третий исход, у которого нет ни находки, ни прохода, и подавать его красным
# значит посылать читателя чинить то, чего не ломали. Здесь такой предмет реален:
# часть проб набора судит СКРИПТЫ ПОСЕВА, а посев в репозиторий службы не приехал
# ни одним файлом.
#
# ЭТО НЕ МАСКА, и различие проверяемо: помеченный пропуск идёт ОТДЕЛЬНЫМ числом,
# печатается в переписи и в ИТОГЕ, и НЕ засчитывается ни в проход, ни в отказ.
# Непомеченный пропуск остаётся отказом — то есть обойти по-прежнему нельзя, для
# этого надо ВПИСАТЬ метку, а вписанная метка видна в диффе и в выводе.
PRECONDITION_MARK = "УСЛОВИЕ НЕ СОЗДАНО"


def run_pytest(root: Path, files: list[str]) -> tuple[int, int, int, list[str]]:
    """Прогон набора. Возвращает (исполнено, провалено, не выполнилось, замечания).

    Счёт берётся из junit-XML, а не из разбора человекочитаемого хвоста: хвост
    меняется между версиями, и проверка, читающая его глазами, разошлась бы молча.
    """
    if not files:
        return 0, 0, 0, []
    xml_dir = Path(tempfile.mkdtemp(prefix="probes-junit-"))
    xml = xml_dir / "probes.xml"
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", *files,
             "-q", "-p", "no:cacheprovider", f"--junit-xml={xml}"],
            cwd=str(root), capture_output=True, text=True, timeout=900)
        sys.stdout.write(proc.stdout)
        if proc.stderr.strip():
            sys.stderr.write(proc.stderr)

        if not xml.is_file():
            return 0, 0, 0, [
                "pytest не оставил junit-отчёта — прогон НЕ ВЫПОЛНЕН, "
                f"и это не «ноль находок» (код выхода {proc.returncode})"]

        suite = ET.parse(xml).getroot()
        if suite.tag == "testsuites":
            inner = suite.find("testsuite")
            # `or` здесь читать нельзя: пустой элемент ложен по истинностному
            # значению, и вложенный отчёт без проб молча подменился бы внешним.
            if inner is not None:
                suite = inner
        total = int(suite.get("tests", 0))
        failures = int(suite.get("failures", 0))
        errors = int(suite.get("errors", 0))
        skipped = int(suite.get("skipped", 0))

        notes = []

        # ПРОПУСКИ РАЗБИРАЮТСЯ ПО ОДНОМУ, а не считаются числом из шапки: шапка
        # не говорит, помечен ли пропуск, а именно это и различает второй исход от
        # третьего. Читается ПРИЧИНА, объявленная пробой.
        unmet_names, plain_names = [], []
        for case in suite.iter("testcase"):
            node = case.find("skipped")
            if node is None:
                continue
            reason = (node.get("message") or "") + " " + (node.text or "")
            name = f"{case.get('classname','')}::{case.get('name','')}"
            (unmet_names if PRECONDITION_MARK in reason else plain_names).append(
                (name, reason.strip()))
        unmet = len(unmet_names)
        # `skipped` из шапки отчёта — ОРИЕНТИР, а не источник: он не говорит, помечен
        # ли пропуск. Расхождение шапки с разбором по одному означает, что отчёт
        # устроен иначе, чем думает этот разбор, — и молчать об этом нельзя.
        if unmet + len(plain_names) != skipped:
            notes.append(
                f"шапка отчёта называет пропусков {skipped}, разбор по одному нашёл "
                f"{unmet + len(plain_names)} — разбор пропусков читает не то, что "
                f"пишет pytest, и третий исход считается неверно")

        for name, reason in unmet_names:
            # Третий исход НАЗЫВАЕТСЯ, а не проглатывается: иначе «не выполнилось»
            # неотличимо от «прошло».
            print(f"  НЕ ВЫПОЛНИЛОСЬ: {name} — {reason}")
        if plain_names:
            # Маскировка запрещена: непомеченный пропуск не идёт в зачёт прохода.
            notes.append(
                f"{len(plain_names)} проб(а) ПРОПУЩЕНО без метки «{PRECONDITION_MARK}» "
                f"— пропуск не засчитывается за проход; пробе нужна своя посадка, "
                f"а не skip: " + ", ".join(n for n, _ in plain_names))
        if proc.returncode == 5:
            notes.append("pytest не собрал НИ ОДНОЙ пробы из переданных файлов")
        elif proc.returncode not in (0, 1):
            notes.append(f"pytest вышел кодом {proc.returncode} — прогон недействителен")
        return total - unmet, failures + errors + len(plain_names), unmet, notes
    finally:
        shutil.rmtree(xml_dir, ignore_errors=True)


def run_script(root: Path, rel: str) -> tuple[int, list[str]]:
    """Гейт со своим main: считается ОДНОЙ пробой, вердикт — его код выхода."""
    proc = subprocess.run([sys.executable, rel], cwd=str(root),
                          capture_output=True, text=True, timeout=600)
    sys.stdout.write(proc.stdout)
    if proc.stderr.strip():
        sys.stderr.write(proc.stderr)
    if proc.returncode != 0:
        return 1, [f"{rel}: вышел кодом {proc.returncode}"]
    return 1, []


def execute(root: Path, patterns: tuple[str, ...]) -> int:
    files = list_tracked(root, patterns)

    shown = ", ".join(patterns)
    print("===== регрессионные пробы python: перепись состава =====")
    print(f"образцов: {len(patterns)} — {shown}")
    # Перепись ПО КАЖДОМУ образцу отдельно. Одно суммарное число скрывает ровно
    # тот случай, ради которого образцов два: образец, переставший что-либо
    # находить, не меняет суммы, пока второй жив, — и его смерть неотличима от
    # исправной работы.
    for pat in patterns:
        n = sum(1 for rel in files if fnmatch.fnmatch(rel, pat))
        print(f"  по образцу {pat}: {n}")
    print(f"файлов проб найдено: {len(files)}")

    # Ноль файлов — ОТКАЗ. Пустой состав отчитался бы «всё чисто», и именно так
    # пробы этого набора прожили в дереве, не исполнившись ни разу: в репозитории
    # службы конвейер их не звал НИ ОДНИМ шагом (предикат на момент вендоринга:
    # `grep -rc run-python-probes .github/workflows/` → 0).
    if not files:
        print(f"ОТКАЗ: по образцам {shown} не найдено ни одного файла проб — "
              f"обход сломан либо пробы переехали. Пустой обход не является "
              f"доказательством чистоты.", file=sys.stderr)
        return 1

    pytest_files: list[str] = []
    script_files: list[str] = []
    problems: list[str] = []
    declared = 0

    for rel in files:
        kind, probes = classify(root / rel)
        if kind == KIND_PYTEST:
            pytest_files.append(rel)
            declared += len(probes)
            print(f"  {rel}: {KIND_PYTEST}, проб объявлено {len(probes)}")
        elif kind == KIND_SCRIPT:
            script_files.append(rel)
            print(f"  {rel}: {KIND_SCRIPT}")
        else:
            detail = f" ({probes[0]})" if probes else ""
            print(f"  {rel}: ВИД НЕ ОПОЗНАН{detail}")
            problems.append(
                f"{rel}: ни одной функции `test_*` верхнего уровня, ни ветки "
                f"`__main__` — такой файл собрал бы ноль проб и промолчал; "
                f"это немота, а не чистота")

    if shutil.which(sys.executable) and pytest_files:
        try:
            subprocess.run([sys.executable, "-c", "import pytest"],
                           capture_output=True, check=True, timeout=60)
        except (subprocess.SubprocessError, OSError):
            # Отсутствие инструмента — ОТКАЗ, а не пропуск: «не выполнилось» не
            # идёт в зачёт «прошло».
            print(f"ОТКАЗ: нет pytest, а под него написано файлов проб: "
                  f"{len(pytest_files)} (объявлено проб {declared}) — прогон НЕ "
                  f"ВЫПОЛНЕН. Установи его в шаге "
                  f"(`python3 -m pip install pytest`).", file=sys.stderr)
            return 2

    print()
    executed = 0
    failed = 0
    unmet = 0

    if pytest_files:
        print(f"===== прогон набора pytest ({len(pytest_files)} файл(ов)) =====")
        ran, bad, skipped_unmet, notes = run_pytest(root, pytest_files)
        executed += ran
        failed += bad
        unmet += skipped_unmet
        problems += notes
        print(f"проб исполнено (junit): {ran}; объявлено разбором: {declared}")
        # НЕДОБОР — находка: часть файла молча не собралась (ошибка импорта на
        # уровне модуля читается именно так). ПЕРЕБОР находкой не является и
        # быть не может: `@pytest.mark.parametrize` разворачивает ОДНО
        # объявление в несколько прогонов, и это штатная форма, а не дефект.
        #
        # Прежнее сравнение было на неравенство и потому краснело на законном
        # разворачивании: 109 объявлений против 114 прогонов, упавших проб ноль,
        # а прогон красен. Хуже того, текст описывал ОБРАТНОЕ направление —
        # читатель шёл искать несобравшийся файл, которого не существует, потому
        # что у ошибки импорта исход `исполнено > объявлено` невозможен by
        # construction.
        # Недобор считается ОТ ИСПОЛНИМОГО: объявленные пробы, чьё условие не
        # создано, исполниться не могли, и вычитать их надо здесь, а не из
        # вердикта. Иначе третий исход читался бы как несобравшийся файл.
        if ran and declared and ran < declared - skipped_unmet:
            problems.append(
                f"объявлено {declared} проб (из них не выполнилось "
                f"{skipped_unmet}), исполнено {ran} — часть файла не собралась; "
                f"недобор состава молчать не должен")

    for rel in script_files:
        print(f"===== {rel} (гейт со своим main) =====")
        ran, notes = run_script(root, rel)
        executed += ran
        failed += len(notes)
        problems += notes

    print()
    # ИТОГ НЕСЁТ ВСЕ ТРИ ЧИСЛА. Третье не вычитается из вердикта и не
    # засчитывается в успех, поэтому его отсутствие в строке итога сделало бы
    # «не выполнилось» неотличимым от «прошло».
    print(f"===== ИТОГ: файлов {len(files)} "
          f"(набор {len(pytest_files)}, гейт {len(script_files)}); "
          f"проб исполнено {executed}; провалено {failed}; "
          f"НЕ ВЫПОЛНИЛОСЬ {unmet} =====")

    if executed == 0:
        print("ОТКАЗ: не исполнено НИ ОДНОЙ пробы — это провал, а не чистота.",
              file=sys.stderr)
        return 1

    # ВЕРДИКТ ЧИТАЕТ ЧИСЛО УПАВШИХ, а не только перечень замечаний.
    #
    # Первая редакция выводила вердикт из `problems` — и печатала PASS, имея
    # `провалено 1`: упавшее утверждение даёт число, но не «замечание», поэтому
    # перечень оставался пуст. Ровно тот класс, который этот прогонщик и обслуживает
    # (прогонщик, печатающий зелёное при красном). Найдено собственной
    # самопроверкой, пункт (a).
    if failed or problems:
        print(f"ПРОВАЛ: пробы на python не зелёные "
              f"(упавших проб: {failed}; замечаний о составе: {len(problems)})",
              file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    if unmet:
        print(f"PASS: все {executed} исполненных проб(ы) зелёные; "
              f"НЕ ВЫПОЛНИЛОСЬ {unmet} — условие не создано, и это не зачтено "
              f"в проход (см. строки «НЕ ВЫПОЛНИЛОСЬ» выше)")
        return 0
    print(f"PASS: все {executed} проб(ы) исполнены и зелёные")
    return 0


# ── ДОКАЗАТЕЛЬСТВО ИНЪЕКЦИЕЙ, В ОБЕ СТОРОНЫ ─────────────────────────────────
#
# Прогонщик — тоже проверка, значит обязан быть доказан тем же способом, каким
# требует доказывать других: верни дефект → краснеет и называет координату;
# поставь рядом законную конструкцию той же формы → молчит.

_OK_PROBE = "def test_ok():\n    assert 1 == 1\n"
_BAD_PROBE = "def test_bad():\n    assert 1 == 2, 'внесённый дефект'\n"
# Помеченный пропуск: третий исход. Метка — ТА ЖЕ, что читает разбор выше, и
# берётся она из той же константы, а не выписывается второй раз.
_UNMET_PROBE = (
    "import pytest\n\n"
    "def test_unmet():\n"
    f"    pytest.skip('{PRECONDITION_MARK}: посев не приехал в этот репозиторий')\n")

_SKIPPED_PROBE = (
    "import pytest\n"
    "@pytest.mark.skip(reason='инъекция: пропуск не должен читаться проходом')\n"
    "def test_skipped():\n    assert False\n"
)
_SCRIPT_OK = "import sys\n\ndef main():\n    return 0\n\nif __name__ == '__main__':\n    sys.exit(main())\n"
_SCRIPT_BAD = "import sys\n\ndef main():\n    return 1\n\nif __name__ == '__main__':\n    sys.exit(main())\n"
# Ни функций `test_*`, ни ветки `__main__`: pytest собрал бы ноль и промолчал.
# Строка `def test_...` СТОИТ здесь — в объяснении, — чтобы предикат доказал, что
# он читает разбор, а не текст: по грепу этот файл был бы «набором».
_MUTE = '"""Пояснение, в котором встречается def test_looks_like_a_probe()."""\nX = 1\n'


def _tree(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="probes-selftest-"))
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return root


# `_at` СНЯТ вместе со своим предметом (2026-09-11): она писала синтетику под
# `services/x/tests/newman/scripts/`, копируя площадку третьего образца, а тот
# образец сам снят вместе со службой доступа (#1111) — обе площадки, которые
# читали такую синтетику, из `DEFAULT_PATTERNS` исчезли, и самопроверка молча
# перестала находить собственные фикстуры («не найдено ни одного файла проб»),
# хотя сам гейт был исправен. Площадки, которые ей нужны, — `_at_root` и
# `_at_seed` ниже; каждая привязана к образцу, который сегодня жив.


def _at_root(name: str, body: str) -> dict[str, str]:
    """Проба вердиктного слоя: она не принадлежит ни одной суите и лежит в корне."""
    return {f"tests/newman/scripts/{name}": body}


def _at_seed(name: str, body: str) -> dict[str, str]:
    """Проба ПОСЕВА: её предмет исполняется до первой коллекции любой суиты."""
    return {f"tests/authz-fixtures/{name}": body}


def _elsewhere(name: str, body: str) -> dict[str, str]:
    """Место, которого нет НИ В ОДНОМ образце, — контроль против бланкетного обхода."""
    return {f"tools/x/{name}": body}


def self_test() -> int:
    failures = []

    def check(label, cond, detail=""):
        if cond:
            print(f"  ок     {label}")
        else:
            print(f"  ПРОВАЛ {label}  {detail}")
            failures.append(label)

    import io
    import contextlib

    def run(files):
        root = _tree(files)
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                rc = execute(root, DEFAULT_PATTERNS)
        finally:
            shutil.rmtree(root, ignore_errors=True)
        return rc, buf.getvalue()

    print("(a) дефект внесён — прогонщик обязан покраснеть и назвать координату")
    rc, out = run(_at_root("alpha_test.py", _OK_PROBE + _BAD_PROBE))
    check("краснеет на упавшей пробе", rc == 1, out)
    check("называет файл", "alpha_test.py" in out, out)
    check("печатает перепись исполненного", "проб исполнено 2" in out, out)

    print("(b) законная конструкция той же формы — прогонщик обязан молчать")
    rc, out = run(_at_root("alpha_test.py", _OK_PROBE))
    check("молчит на зелёной пробе", rc == 0, out)
    check("перепись растёт, а не обнуляется", "проб исполнено 1" in out, out)

    print("(c) гейт со своим main исполняется и его вердикт доезжает")
    rc, out = run(_at_root("gate_test.py", _SCRIPT_BAD))
    check("краснеет на упавшем гейте", rc == 1, out)
    check("называет гейт", "gate_test.py" in out, out)
    rc, out = run(_at_root("gate_test.py", _SCRIPT_OK))
    check("молчит на зелёном гейте", rc == 0, out)

    print("(d) ноль найденного и ноль исполненного — ОТКАЗ, а не успех")
    rc, out = run({"services/x/tests/newman/scripts/helper.py": "X = 1\n"})
    check("пустой состав отвергнут", rc == 1, out)
    check("говорит, что обход ничего не нашёл", "не найдено ни одного файла" in out, out)

    print("(e) файл, который собрал бы ноль проб, — находка, а не тишина")
    rc, out = run(_at_root("mute_test.py", _MUTE))
    check("немой файл отвергнут", rc == 1, out)
    check("вид не опознан по РАЗБОРУ, не по слову в тексте",
          "ВИД НЕ ОПОЗНАН" in out, out)

    print("(f) пропуск не засчитывается за проход")
    rc, out = run(_at_root("skip_test.py", _OK_PROBE + _SKIPPED_PROBE))
    check("пропущенная проба роняет прогон", rc == 1, out)
    check("пропуск назван", "ПРОПУЩЕНО" in out, out)

    # ── (j) ТРЕТИЙ ИСХОД ОТЛИЧИМ ОТ ВТОРОГО — И ОТ ПЕРВОГО ───────────────────
    #
    # Ось доказывается ТРОЙКОЙ, а не парой, потому что различить надо три
    # состояния, а не два: помеченный пропуск НЕ роняет прогон (иначе «условие не
    # создано» подавалось бы красным), НЕ засчитывается в проход (иначе он был бы
    # маской) и НАЗЫВАЕТСЯ числом в итоге (иначе неотличим от прохода). Рядом —
    # законный близнец из (f): тот же пропуск БЕЗ метки по-прежнему красный, то
    # есть обойти можно только ВПИСАВ метку, а вписанная метка видна и в диффе, и
    # в выводе.
    print("(j) помеченный пропуск — третий исход, а не отказ и не проход")
    rc, out = run(_at_root("unmet_test.py", _OK_PROBE + _UNMET_PROBE))
    check("помеченный пропуск НЕ роняет прогон", rc == 0, out)
    check("он назван третьим исходом", "НЕ ВЫПОЛНИЛОСЬ" in out, out)
    check("итог печатает его число", "НЕ ВЫПОЛНИЛОСЬ 1 =====" in out, out)
    check("и он НЕ зачтён в проход", "исполнено 1;" in out, out)
    check("причина третьего исхода напечатана",
          "посев не приехал" in out or PRECONDITION_MARK in out, out)
    rc2, out2 = run(_at_root("unmet_only_test.py", _UNMET_PROBE))
    check("один только третий исход — ОТКАЗ: исполнено ноль", rc2 == 1, out2)
    check("и отказ объясняет, что не исполнено ничего",
          "не исполнено НИ ОДНОЙ пробы" in out2, out2)

    # ── (g) ВТОРОЙ ОБРАЗЕЦ ЖИВ, И ОН НЕ БЛАНКЕТНЫЙ ───────────────────────────
    #
    # Образец, добавленный и ничего не находящий, — расширение вхолостую: он
    # выглядит как покрытие и им не является. Ось доказывается ПАРОЙ: проба
    # вердиктного слоя (корень дерева) обязана быть найдена и исполнена, а такая
    # же проба в месте, которого не называет НИ ОДИН образец, — не найдена.
    # Без второй половины «нашёл» означало бы «беру всё подряд».
    print("(g) образец вердиктного слоя жив, и обход не бланкетный")
    rc, out = run(_at_root("verdict_layer_test.py", _OK_PROBE))
    check("проба вердиктного слоя найдена и зелена", rc == 0, out)
    check("названа координатой корня",
          "tests/newman/scripts/verdict_layer_test.py" in out, out)
    check("перепись по образцу вердиктного слоя не нулевая",
          "по образцу tests/newman/scripts/*_test.py: 1" in out, out)
    rc, out = run(_elsewhere("stray_test.py", _OK_PROBE))
    check("проба вне обоих образцов НЕ засчитывается", rc == 1, out)
    check("пустой обход назван отказом", "не найдено ни одного файла" in out, out)

    # ── (i) ТРЕТИЙ ОБРАЗЕЦ ЖИВ ───────────────────────────────────────────────
    #
    # Та же ось и по той же причине, что (g): образец, добавленный и ничего не
    # находящий, есть расширение вхолостую. Вторая половина пары — та же, что у
    # (g): `_elsewhere` вне ВСЕХ образцов по-прежнему не засчитывается, поэтому
    # «нашёл» здесь не означает «беру всё подряд».
    print("(i) образец слоя посева жив, и обход не бланкетный")
    rc, out = run(_at_seed("prodseed_synthetic_test.py", _SCRIPT_OK))
    check("проба посева найдена и зелена", rc == 0, out)
    check("названа координатой посева",
          "tests/authz-fixtures/prodseed_synthetic_test.py" in out, out)
    check("перепись по образцу посева не нулевая",
          "по образцу tests/authz-fixtures/*_test.py: 1" in out, out)

    # Прежде здесь стояли ТРИ полосы — суитная, вердиктная, посевная. Суитная
    # снята вместе со своим предметом (см. `DEFAULT_PATTERNS` выше); полос,
    # которые нужно развести парой файлов, осталось две.
    print("(h) обе полосы разом — перепись называет каждую своим числом")
    rc, out = run({**_at_root("verdict_layer_test.py", _OK_PROBE),
                   **_at_seed("prodseed_synthetic_test.py", _SCRIPT_OK)})
    check("оба образца дали по файлу", rc == 0, out)
    check("перепись вердиктного слоя не схлопнута",
          "по образцу tests/newman/scripts/*_test.py: 1" in out, out)
    check("перепись слоя посева не схлопнута",
          "по образцу tests/authz-fixtures/*_test.py: 1" in out, out)
    check("проб исполнено 2", "проб исполнено 2" in out, out)

    print()
    if failures:
        print(f"САМОПРОВЕРКА ПРОВАЛЕНА: {len(failures)} — {', '.join(failures)}",
              file=sys.stderr)
        return 1
    print("ДОКАЗАНО: прогонщик краснеет на дефекте, молчит на законной форме, "
          "отвергает пустой обход, немой файл и НЕПОМЕЧЕННЫЙ пропуск, а помеченный "
          "различает третьим исходом — не роняя прогон и не зачитывая в проход.")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=None,
                    help="корень обхода (по умолчанию — корень репозитория)")
    ap.add_argument("--pattern", action="append", default=None,
                    help="образец состава файлов проб (можно повторять; "
                         "по умолчанию — объявленный перечень)")
    ap.add_argument("--self-test", action="store_true",
                    help="доказать инъекцией: прогонщик краснеет на дефекте и молчит на законной форме")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    return execute(Path(args.root).resolve() if args.root else repo_root(),
                   tuple(args.pattern) if args.pattern else DEFAULT_PATTERNS)


if __name__ == "__main__":
    sys.exit(main())
