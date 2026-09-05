#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Инъекция для сверщика каталога кейсов — предмет живёт в общем слое, `casesindex.audit`.

ПОЧЕМУ ПРОБА ЛЕЖИТ ЗДЕСЬ, А НЕ РЯДОМ С ПРЕДМЕТОМ. Прогонщик проб находит их
образцом `services/*/tests/newman/scripts/*_test.py`; каталог общего слоя
(`tests/newman/kacholib/`) в этот образец НЕ попадает — под ним в дереве ноль
файлов `*_test.py`, и проба, положенная туда, не исполнялась бы НИКЕМ. Слот был
бы занят, а вердикта не было бы ни у одного утверждения — «не выполнилось»,
поданное как зелёное.

ЧТО ЗДЕСЬ ДОКАЗЫВАЕТСЯ. Гоняется НАСТОЯЩАЯ судящая функция `casesindex.audit`,
а не её пересказ: проба, повторяющая логику сверщика, доказывала бы свойство
копии. Вход — синтетический набор в `tmp_path`, собранный НАСТОЯЩИМ дескриптором
`Run` общего слоя, поэтому отбор модулей, загрузка кейсов и обход дублей идут тем
же кодом, что и генерация.

ПО КАЖДОЙ ОСИ — ОБЕ СТОРОНЫ. Инъекция обязана ронять ТОЛЬКО проверяемое: рядом с
каждым «краснеет» стоит законный близнец той же формы, на котором сверщик обязан
МОЛЧАТЬ. Односторонняя проба зеленела бы на сверщике, отвергающем всё, и краснела
бы на сверщике, не отвергающем ничего.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path


def _kacholib_dir() -> Path:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "tests" / "newman" / "kacholib"
        if (candidate / "casesindex.py").is_file():
            return candidate
    raise SystemExit("общий слой не найден: <корень>/tests/newman/kacholib/casesindex.py")


sys.path.insert(0, str(_kacholib_dir()))

import casesindex  # noqa: E402
from gen_shared import Run  # noqa: E402


@dataclass
class _Case:
    """Кейс синтетического набора. Тип объявляет НАБОР — общий слой его не знает."""

    id: str


class _Emit:
    """Форма коллекции здесь не нужна: сверщик каталога её не читает."""


def _suite(tmp_path: Path, modules: dict, index: str) -> tuple[Run, Path]:
    """Синтетический набор: модули кейсов + каталог. Возвращает (Run, путь каталога)."""
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir(parents=True, exist_ok=True)
    for name, ids in modules.items():
        body = ", ".join(f'Case(id="{i}")' for i in ids)
        (cases_dir / name).write_text(f"CASES = [{body}]\n", encoding="utf-8")
    docs = tmp_path / "docs"
    docs.mkdir(parents=True, exist_ok=True)
    index_file = docs / "CASES-INDEX.md"
    index_file.write_text(index, encoding="utf-8")
    run = Run(root=tmp_path, cases_dir=cases_dir, out_dir=tmp_path / "collections",
              scripts_dir=tmp_path / "scripts", emit=_Emit(), case_cls=_Case,
              injected={"Case": _Case})
    return run, index_file


def _index(total: int, per: dict, extra: str = "") -> str:
    rows = "\n".join(f"| `cases/{n}` | {c} |" for n, c in per.items())
    return (f"# синтетика\n\nВсего кейсов: {total}\n\n"
            f"| модуль | кейсов |\n|---|---:|\n{rows}\n\n{extra}\n")


def _audit(run, index_file, **kw):
    return casesindex.audit(run, index_file, **kw)


def _joined(findings) -> str:
    return "\n".join(findings)


# ── КОНТРОЛЬ: целый набор — сверщик молчит ──────────────────────────────────
#
# Без него всё нижеследующее зеленело бы и на сверщике, который краснеет всегда.

def test_intact_suite_is_silent(tmp_path):
    run, idx = _suite(tmp_path,
                      {"a.py": ["X-AA-OK", "X-AB-OK"], "b.py": ["X-BA-OK"]},
                      _index(3, {"a.py": 2, "b.py": 1},
                             "- `X-AA-OK`\n- `X-AB-OK`\n- `X-BA-OK`\n"))
    findings, cen = _audit(run, idx)
    assert findings == [], _joined(findings)
    assert (cen.modules, cen.cases, cen.unique_ids) == (2, 3, 3)
    assert cen.by_literal == 3
    # Перепись обязана быть НЕПУСТОЙ: «ноль находок» отличимо от «ноль прочитанного».
    assert cen.index_bytes > 0 and cen.census_rows == 2


# ── ОСЬ 1: дубль идентификатора ─────────────────────────────────────────────

def test_duplicate_id_across_modules_is_a_finding(tmp_path):
    run, idx = _suite(tmp_path,
                      {"a.py": ["X-AA-OK"], "b.py": ["X-AA-OK"]},
                      _index(2, {"a.py": 1, "b.py": 1}, "- `X-AA-OK`\n"))
    findings, _ = _audit(run, idx)
    joined = _joined(findings)
    assert "повторяется" in joined, joined
    # Находка обязана НАЗЫВАТЬ координату: по симптому читатель идёт искать не там.
    assert "X-AA-OK" in joined and "a.py" in joined and "b.py" in joined, joined


def test_distinct_ids_in_two_modules_are_silent(tmp_path):
    """Законный близнец: те же два модуля, идентификаторы разные."""
    run, idx = _suite(tmp_path,
                      {"a.py": ["X-AA-OK"], "b.py": ["X-BB-OK"]},
                      _index(2, {"a.py": 1, "b.py": 1}, "- `X-AA-OK`\n- `X-BB-OK`\n"))
    findings, _ = _audit(run, idx)
    assert findings == [], _joined(findings)


# ── ОСЬ 2: перепись каталога против дерева ──────────────────────────────────

def test_total_census_drift_is_a_finding(tmp_path):
    run, idx = _suite(tmp_path, {"a.py": ["X-AA-OK", "X-AB-OK"]},
                      _index(1, {"a.py": 2}, "- `X-AA-OK`\n- `X-AB-OK`\n"))
    findings, _ = _audit(run, idx)
    joined = _joined(findings)
    assert "Всего кейсов: 1" in joined and "в дереве 2" in joined, joined


def test_per_module_census_drift_is_a_finding(tmp_path):
    """Итог сходится, а модульное число — нет: выпадение внутри модуля."""
    run, idx = _suite(tmp_path, {"a.py": ["X-AA-OK"], "b.py": ["X-BA-OK"]},
                      _index(2, {"a.py": 2, "b.py": 0}, "- `X-AA-OK`\n- `X-BA-OK`\n"))
    findings, _ = _audit(run, idx)
    joined = _joined(findings)
    assert "cases/a.py" in joined and "объявлено 2" in joined, joined


def test_module_missing_from_census_is_a_finding(tmp_path):
    run, idx = _suite(tmp_path, {"a.py": ["X-AA-OK"], "b.py": ["X-BA-OK"]},
                      _index(2, {"a.py": 1}, "- `X-AA-OK`\n- `X-BA-OK`\n"))
    findings, _ = _audit(run, idx)
    joined = _joined(findings)
    assert "cases/b.py" in joined and "в переписи каталога отсутствует" in joined, joined


def test_census_may_be_waived_only_explicitly(tmp_path):
    """Законный близнец: набор, который перепись не ведёт, объявляет это ЯВНО.

    Умолчание — требовать перепись; послабление берётся параметром на связывании,
    где оно видно, а не молчанием сверщика.
    """
    run, idx = _suite(tmp_path, {"a.py": ["X-AA-OK"]},
                      "# синтетика\n\n- `X-AA-OK`\n")
    assert _audit(run, idx)[0] != []                     # с переписью — находка
    assert _audit(run, idx, require_census=False)[0] == []  # без неё — молчит


# ── ОСЬ 3: заголовок пережил свой модуль ────────────────────────────────────

def test_heading_naming_a_removed_module_is_a_finding(tmp_path):
    run, idx = _suite(tmp_path, {"a.py": ["X-AA-OK"]},
                      _index(1, {"a.py": 1},
                             "## `cases/gone.py` — 7 кейсов\n\n- `X-AA-OK`\n"))
    findings, _ = _audit(run, idx)
    joined = _joined(findings)
    assert "cases/gone.py" in joined and "которого в дереве нет" in joined, joined


def test_prose_about_a_removed_module_is_silent(tmp_path):
    """Законный близнец, и он НЕ формальность.

    Упоминание снятого модуля в ПРОЗЕ, прямо говорящей о снятии, — историческое
    свидетельство. Сверщик, запрещающий его, заставлял бы стирать объяснение
    вместе с ложью; поэтому судятся заголовки и строки переписи, а не весь текст.
    """
    run, idx = _suite(tmp_path, {"a.py": ["X-AA-OK"]},
                      _index(1, {"a.py": 1},
                             "Модуль `cases/gone.py` снят вместе со своим ресурсом.\n\n"
                             "- `X-AA-OK`\n"))
    findings, _ = _audit(run, idx)
    assert findings == [], _joined(findings)


# ── ОСЬ 4: покрытие идентификатора ──────────────────────────────────────────

def test_uncatalogued_id_is_a_finding(tmp_path):
    run, idx = _suite(tmp_path, {"a.py": ["X-AA-OK", "X-AB-OK"]},
                      _index(2, {"a.py": 2}, "- `X-AA-OK`\n"))
    findings, _ = _audit(run, idx)
    joined = _joined(findings)
    assert "X-AB-OK" in joined and "не каталогизирован" in joined, joined


def test_suffix_pattern_covers_the_id(tmp_path):
    """Законный близнец: покрытие паттерном, а не литералом."""
    run, idx = _suite(tmp_path, {"a.py": ["IAM-USR-GT-CRUD-OK"]},
                      _index(1, {"a.py": 1}, "- `*-GT-CRUD-OK`\n"))
    findings, cen = _audit(run, idx, strip_segments=2)
    assert findings == [], _joined(findings)
    assert cen.by_pattern == 1 and cen.by_literal == 0


def test_strip_depth_is_the_suites_decision(tmp_path):
    """Тот же вход, другая глубина — тот же паттерн уже НЕ покрывает.

    Ось заведена потому, что глубина у наборов разная, и молчаливая единица
    вместо двойки сделала бы паттерны iam беспредметными.
    """
    run, idx = _suite(tmp_path, {"a.py": ["IAM-USR-GT-CRUD-OK"]},
                      _index(1, {"a.py": 1}, "- `*-GT-CRUD-OK`\n"))
    assert _audit(run, idx, strip_segments=1)[0] != []


def test_index_tag_covers_the_id(tmp_path):
    """Законный близнец: тег `# index:` рядом со строкой `id=`."""
    run, idx = _suite(tmp_path, {"a.py": []}, _index(1, {"a.py": 1}, ""))
    (run.cases_dir / "a.py").write_text(
        'CASES = [\n'
        '    Case(id="X-AB-OK"),  # index: X-*-OK\n'
        ']\n', encoding="utf-8")
    findings, cen = _audit(run, idx)
    assert findings == [], _joined(findings)
    assert cen.by_tag == 1


def test_exempt_module_is_not_required_to_be_catalogued(tmp_path):
    """Освобождение действует ровно на объявленный образец, и только на него."""
    run, idx = _suite(tmp_path, {"internal-x.py": ["X-IN-OK"], "a.py": ["X-AA-OK"]},
                      _index(2, {"internal-x.py": 1, "a.py": 1}, "- `X-AA-OK`\n"))
    assert _audit(run, idx)[0] != []                                   # без освобождения
    findings, cen = _audit(run, idx, exempt_file_re=re.compile(r"^internal-"))
    assert findings == [], _joined(findings)
    assert cen.exempt_modules == 1 and cen.exempt_cases == 1


# ── ПРЕДПОСЫЛКА: пустой обход — ОТКАЗ, а не молчание ────────────────────────

def test_empty_module_walk_is_a_finding(tmp_path):
    """Сверщик, потерявший предмет, вечнозелен — поэтому пустой обход краснеет.

    Утверждение ключуется на «обход пуст», а не на слове «НОЛЬ»: слово стоит и в
    соседней ветке («кейсов НОЛЬ при N модулях»), и первая редакция этой пробы
    оставалась зелёной при СНЯТОЙ проверке пустого обхода — находка приходила от
    соседа. Поймано мутацией самой судящей функции, а не чтением.
    """
    run, idx = _suite(tmp_path, {}, _index(0, {}, ""))
    findings, cen = _audit(run, idx)
    assert cen.modules == 0
    joined = _joined(findings)
    assert "обход пуст" in joined, joined
    # И это ДРУГАЯ ветка, чем «модули есть, кейсов нет»: иначе две проверки
    # неразличимы, и снятие любой из них проходит молча.
    assert "нечего покрывать" not in joined, joined


def test_modules_without_cases_are_a_finding(tmp_path):
    """Модули есть, кейсов ноль: каталогу нечего покрывать — тоже отказ."""
    run, idx = _suite(tmp_path, {"a.py": []}, _index(0, {"a.py": 0}, ""))
    findings, cen = _audit(run, idx)
    assert cen.modules == 1 and cen.cases == 0
    assert "нечего покрывать" in _joined(findings), _joined(findings)


def test_missing_index_is_a_finding(tmp_path):
    run, _ = _suite(tmp_path, {"a.py": ["X-AA-OK"]}, "")
    findings, _ = _audit(run, tmp_path / "docs" / "NO-SUCH.md")
    assert "каталога кейсов нет" in _joined(findings), _joined(findings)


# ── ЧТО СВЕРЩИК НЕ СУДИТ — сказано пробой, а не только прозой ───────────────

def test_catalogue_entry_meaning_is_not_judged(tmp_path):
    """Против идентификатора может стоять неправда — сверщик этого не видит.

    Проба закрепляет ГРАНИЦУ доверия к зелёному вердикту: он означает «запись
    есть и числа сходятся», а не «написана правда». Без неё «каталог зелёный»
    читалось бы шире сделанного.
    """
    run, idx = _suite(tmp_path, {"a.py": ["X-AA-OK"]},
                      _index(1, {"a.py": 1}, "- `X-AA-OK` — заведомая неправда\n"))
    findings, _ = _audit(run, idx)
    assert findings == [], _joined(findings)
