#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ДЕРЖАТЕЛЬ КЛАССА «ДВА МЕСТА ОБ ОДНОМ ПРЕДМЕТЕ, И ЛОЖНЫМ СТАЛО ДЕЙСТВУЮЩЕЕ».

ПРЕДМЕТ. Объявление конвейера и его собственные комментарии — два места об одном
предмете. Когда изменение заводит шаг, гоняющий коллекцию, соседняя строка,
утверждающая «не гоняется ни одна», становится ЛОЖЬЮ — и не какой-нибудь, а той,
которая ПЕЧАТАЕТСЯ В КАЖДЫЙ ПРОГОН и читается как действующее состояние.

ЭТО НАБЛЮДАЛОСЬ, А НЕ ПРЕДПОЛОЖЕНО. Изменение, заведшее прогон коллекции
`kaname-own-rest-front` на автономном стенде, оставило в том же файле два места:
комментарий у шага запретов формы и текст `::notice`, оба про «ни одна коллекция
на автономном стенде не гоняется». Второе печаталось в каждый прогон.

ТОТ ЖЕ КЛАСС ВТОРЫМ ПРЕДМЕТОМ: прогонщик проб на python в двух местах утверждал,
что посева в этом репозитории НЕТ НИ ОДНИМ ФАЙЛОМ, и назвал предикатом своего
снятия историю каталога фикстур. Посев приехал — оба места остались.

ПОЧЕМУ ГЕЙТ, А НЕ ВНИМАНИЕ. Оба утверждения верны ДО изменения и ложны ПОСЛЕ, а
изменение их не касается ни строкой: заметить нечего в диффе. Условие лжи
ВЫВОДИМО из дерева, значит проверяемо машиной.

ПОЧЕМУ УСЛОВНЫЙ, А НЕ ЗАПРЕТ ФРАЗЫ. Запрет фразы был бы бланкетным: до заведения
шага фраза ВЕРНА и обязана стоять. Поэтому предикат читает РАЗОБРАННОЕ объявление
конвейера, и находка появляется только вместе с шагом. Инъекция доказывает обе
стороны: шаг есть и фраза есть — красное; шага нет, фраза та же — молчит.

ПОЧЕМУ РАЗБОР, А НЕ ГРЕП. Имя коллекции встречается в комментариях объявления
десятки раз; проверка по подстроке краснела бы на собственном объяснении. Ключи
`jobs:` и шаги читаются разобранным YAML — тот же порядок, что требует ban #17.
"""

from __future__ import annotations

import ast
import importlib.util
import io
import pathlib
import re
import sys
import tokenize

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[3]
WORKFLOWS = ROOT / ".github" / "workflows"
FIXTURES = ROOT / "tests" / "authz-fixtures"
PROBE_RUNNER = ROOT / ".github" / "scripts" / "run-python-probes.py"


def _debt_module():
    """Разборщик объявления конвейера берётся У ПЕРЕПИСИ, а не переписывается.

    Второй разборщик того же предмета разошёлся бы с первым молча — ровно тот
    класс, который эта проба и держит. Имя файла с дефисом импортируется по пути.
    """
    path = ROOT / ".github" / "scripts" / "newman-suite-debt.py"
    spec = importlib.util.spec_from_file_location("newman_suite_debt", path)
    assert spec and spec.loader, f"не загружается {path}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules["newman_suite_debt"] = mod
    spec.loader.exec_module(mod)
    return mod


# Фраза-утверждение о том, что не гоняется НИ ОДНА коллекция. Ловится семья, а не
# один литерал: редакция меняет порядок слов, не меняя утверждения.
NO_COLLECTION_RUNS_RE = re.compile(
    r"ни одн[аой][^.\n]{0,80}коллекци[ияй][^.\n]{0,80}не гоня", re.IGNORECASE)
# Фраза-утверждение о том, что посева нет ни одним файлом.
NO_SEED_AT_ALL_RE = re.compile(
    r"посев[а-я]{0,3}[^.\n]{0,60}(нет ни одним файлом|не приехал)"
    r"|ПОСЕВА НЕТ НИ ОДНИМ ФАЙЛОМ", re.IGNORECASE)


def claims_no_collection_runs(text: str) -> list[str]:
    """Объявление конвейера читается ЦЕЛИКОМ, и это верно по существу: в нём нет
    строковых фикстур. Всё, что там написано, — либо комментарий читателю, либо
    текст, который прогон ПЕЧАТАЕТ."""
    return [m.group(0) for m in NO_COLLECTION_RUNS_RE.finditer(text)]


def prose_of_python(path: pathlib.Path) -> list[tuple[int, str]]:
    """ПРОЗА файла на python: строки документации и комментарии. Без литералов.

    Различение обязательно, и оно измерено: у прогонщика проб есть СИНТЕТИКА для
    инъекции, чья причина пропуска дословно говорит «посев не приехал в этот
    репозиторий». Это фикстура гипотетического случая, а не утверждение о дереве,
    и запрет по тексту файла краснел бы на ней — то есть требовал бы переписать
    законную пробу. Предикат по УЗЛУ различает их построением: проза — это
    docstring узла и комментарий лексера, литерал внутри кода — нет.
    """
    src = path.read_text(encoding="utf-8")
    out: list[tuple[int, str]] = []
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                out.append((getattr(node, "lineno", 1), doc))
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type == tokenize.COMMENT:
            out.append((tok.start[0], tok.string))
    return out


def claims_no_seed(path_or_text) -> list[str]:
    """Находки во ПРОЗЕ файла (или в переданном тексте — для инъекции)."""
    if isinstance(path_or_text, pathlib.Path):
        chunks = prose_of_python(path_or_text)
    else:
        chunks = [(0, str(path_or_text))]
    hits: list[str] = []
    for line, chunk in chunks:
        for m in NO_SEED_AT_ALL_RE.finditer(chunk):
            hits.append(f"строка {line}: {m.group(0)!r}" if line else m.group(0))
    return hits


# ── ПРЕДМЕТ 1: «не гоняется ни одна» против объявленного шага прогона ────────


def test_pipeline_declares_runs_and_nobody_claims_zero():
    mod = _debt_module()
    runs = mod.pipeline_runs(WORKFLOWS)
    files = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    assert files, f"в {WORKFLOWS} не прочитано ни одного объявления — проба беспредметна"
    print(f"осмотрено объявлений конвейера: {len(files)}; "
          f"коллекций, которые гоняет конвейер: {len(runs)} — {sorted(runs)}")
    if not runs:
        pytest.skip("УСЛОВИЕ НЕ СОЗДАНО: ни один шаг конвейера не гоняет коллекцию — "
                    "утверждение «не гоняется ни одна» здесь ВЕРНО и запрету не подлежит")
    bad = []
    for f in files:
        for hit in claims_no_collection_runs(f.read_text(encoding="utf-8")):
            bad.append(f"{f.relative_to(ROOT)}: {hit!r}")
    assert not bad, (
        f"конвейер гоняет {len(runs)} коллекци(й) ({sorted(runs)}), а его же объявление "
        f"в {len(bad)} мест(ах) утверждает, что не гоняется ни одна:\n  "
        + "\n  ".join(bad))


# ── ПРЕДМЕТ 2: «посева нет ни одним файлом» против приехавшего посева ────────


def test_seed_arrived_and_nobody_claims_it_absent():
    seeds = sorted(FIXTURES.glob("seed_*.py")) + sorted(FIXTURES.glob("seed-*.sh"))
    assert PROBE_RUNNER.is_file(), f"нет {PROBE_RUNNER} — проба беспредметна"
    print(f"посевов в {FIXTURES.relative_to(ROOT)}: {len(seeds)} — "
          f"{[p.name for p in seeds]}")
    if not seeds:
        pytest.skip("УСЛОВИЕ НЕ СОЗДАНО: посева в дереве нет — утверждение о его "
                    "отсутствии ВЕРНО и запрету не подлежит")
    hits = claims_no_seed(PROBE_RUNNER)
    assert not hits, (
        f"посев приехал ({len(seeds)}: {[p.name for p in seeds]}), а "
        f"{PROBE_RUNNER.relative_to(ROOT)} в {len(hits)} мест(ах) утверждает обратное:\n  "
        + "\n  ".join(hits))


# ── ПРЕДМЕТ 3: конвейер гоняет ТО, что перепись считает гоняемым ─────────────


def test_what_the_pipeline_runs_the_census_calls_runnable():
    """Одно расхождение — один дефект, и он ловится ОДНИМ предикатом.

    Если перепись объявляет коллекцию заблокированной, а шаг конвейера её гоняет,
    то одно из двух лжёт. Под этот предикат подпадают сразу три способа сломать
    привязку: посев перестал объявлять свою поверхность, имя поверхности
    разошлось с тем, что знает перепись, и посев перестал писать нужный ключ.
    """
    mod = _debt_module()
    runs = mod.pipeline_runs(WORKFLOWS)
    newman = ROOT / "tests" / "newman"
    if not runs:
        pytest.skip("УСЛОВИЕ НЕ СОЗДАНО: конвейер не гоняет ни одной коллекции")
    blocked = mod.blocked_stems(newman, WORKFLOWS)
    print(f"конвейер гоняет: {sorted(runs)}; перепись считает заблокированными: "
          f"{len(blocked)}")
    clash = sorted(set(runs) & set(blocked))
    assert not clash, (
        "шаг конвейера гоняет коллекции, которые перепись считает заблокированными: "
        + ", ".join(f"{s} — {'; '.join(blocked[s])}" for s in clash))


# ── ИНЪЕКЦИЯ: ОБЕ СТОРОНЫ, И РАЗБОР ПРОТИВ ГРЕПА ────────────────────────────

_WF_WITH_RUN = """\
name: proof
on: [push]
jobs:
  stand:
    steps:
      - name: коллекция гоняется
        run: |
          cd tests/newman
          ./scripts/run.sh --service kaname-own-rest-front
"""

_WF_WITHOUT_RUN = """\
name: proof
on: [push]
jobs:
  stand:
    steps:
      # тут когда-то стояло ./scripts/run.sh --service kaname-own-rest-front
      - name: ничего не гоняет
        run: echo нечего
"""


def test_injection_claim_is_red_only_when_a_step_runs_it(tmp_path):
    mod = _debt_module()
    claim = "ни одна коллекция на автономном стенде не гоняется"

    live = tmp_path / "live"
    live.mkdir()
    (live / "e2e.yml").write_text(_WF_WITH_RUN + f"\n# {claim}\n", encoding="utf-8")
    runs = mod.pipeline_runs(live)
    assert runs, "шаг прогона объявлен, а разборщик его не нашёл"
    assert claims_no_collection_runs((live / "e2e.yml").read_text(encoding="utf-8")), \
        "фраза внесена, а предикат её не видит"

    # Законный близнец: ТА ЖЕ фраза, но шага прогона нет — молчание обязательно.
    dead = tmp_path / "dead"
    dead.mkdir()
    (dead / "e2e.yml").write_text(_WF_WITHOUT_RUN + f"\n# {claim}\n", encoding="utf-8")
    assert mod.pipeline_runs(dead) == {}, (
        "`--service` стоит ТОЛЬКО в комментарии — значит разборщик читает текст, "
        "а не разобранный YAML: по грепу этот случай неотличим от объявленного шага")


def test_injection_seed_claim_is_red_only_when_a_seed_exists(tmp_path):
    claim = "В ЭТОМ РЕПОЗИТОРИИ ПОСЕВА НЕТ НИ ОДНИМ ФАЙЛОМ"
    assert claims_no_seed(claim), "фраза внесена, а предикат её не видит"
    assert not claims_no_seed(
        "посев приехал и доказывает себя инъекцией в форме --self-test"), \
        "законная формулировка объявлена находкой — предикат бланкетный"


def test_injection_prose_and_fixture_are_told_apart(tmp_path):
    """Литерал внутри кода — НЕ утверждение о дереве, и это доказывается парой.

    Без этой оси предикат был бы бланкетным: он краснел бы на синтетике инъекции,
    то есть требовал бы переписать законную пробу ради фразы в её фикстуре.
    """
    victim = tmp_path / "subject.py"
    victim.write_text(
        '"""Шапка: В ЭТОМ РЕПОЗИТОРИИ ПОСЕВА НЕТ НИ ОДНИМ ФАЙЛОМ."""\n'
        "SYNTHETIC = \"pytest.skip('посев не приехал в этот репозиторий')\"\n"
        "# и комментарий: посев не приехал\n",
        encoding="utf-8")
    hits = claims_no_seed(victim)
    assert len(hits) == 2, (
        f"ожидались ДВЕ находки (шапка и комментарий), литерал в счёт не идёт; "
        f"получено {len(hits)}: {hits}")
    assert any("строка 1" in h for h in hits), f"шапка не найдена: {hits}"
    assert not any("SYNTHETIC" in h for h in hits), f"литерал засчитан: {hits}"
