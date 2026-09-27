#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ОБЪЯВЛЕНИЕ ВОЛНЫ ЦЕРЕМОНИИ СХОДИТСЯ С ДЕРЕВОМ СЛУЖБЫ (kaname#398).

ПРЕДМЕТ. Три читателя набора ищут объявление в СВОЁМ дереве —
`tests/newman/scripts/run.sh` (вычитание делегированных коллекций),
`tests/newman/scripts/run-ceremony.sh` (волна) и перепись долга. Пока файла не
было, прогонщик печатал «УСЛОВИЕ НЕ СОЗДАНО: нет объявления», а перечня коллекций,
которым нужен человеческий предъявитель, не называл никто: единственный его
производитель и был отсутствующим файлом.

ЧТО УТВЕРЖДАЕТСЯ — И ПОЧЕМУ ИМЕННО ЭТО:

  1. перечень волны объявления РАВЕН перечню «нужна церемония» переписи долга —
     не «похож», а равен, и непуст. Второй счётчик того же предмета разошёлся бы
     с первым молча; здесь он не второй, и это доказывается исходом;
  2. самопроверка объявления проходит — различение доказано инъекцией в обе
     стороны по каждой законной форме записи ключа;
  3. сверка объявления с деревом (`--verify`) чиста и печатает объём осмотренного;
  4. ответ «посев есть» сходится с файлом по пути, который объявление называет, и
     этот путь подпадает под отбор посевов переписи — иначе приехавший посев
     перепись не спросила бы, что он пишет;
  5. печать долга называет КАЖДУЮ коллекцию перечня и их число.

КТО ИСПОЛНЯЕТ: `.github/scripts/run-python-probes.py`, образец
`tests/authz-fixtures/*_test.py` — отдельного шага конвейера файл не требует.
"""

from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DECL = HERE / "ceremony_credentials.py"
SUITE = "tests/newman"


def _census():
    """Перепись загружается ПО ПУТИ: имя файла с дефисом не импортируется."""
    path = ROOT / ".github" / "scripts" / "newman-suite-debt.py"
    spec = importlib.util.spec_from_file_location("newman_suite_debt_ceremony_probe", path)
    assert spec and spec.loader, f"не загружается {path}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _decl(*args: str) -> subprocess.CompletedProcess:
    assert DECL.is_file(), f"объявления нет: {DECL}"
    return subprocess.run([sys.executable, str(DECL), "--root", str(ROOT), *args],
                          capture_output=True, text=True, timeout=300)


def test_wave_stems_equal_the_census_ceremony_need():
    proc = _decl("--suite", SUITE, "--stems")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    stems = {ln.strip() for ln in proc.stdout.splitlines() if ln.strip()}
    need = _census().ceremony_need(ROOT / SUITE)
    census = {s for s, keys in need.items() if keys}
    print(f"волна объявления: {len(stems)}; перепись «нужна церемония»: {len(census)}; "
          f"коллекций прочитано переписью: {len(need)}")
    assert census, "перепись не назвала ни одной коллекции — сравнивать не с чем"
    assert stems == census, (
        f"лишние у объявления: {sorted(stems - census)}; "
        f"пропущенные объявлением: {sorted(census - stems)}")


def test_declaration_self_test_passes():
    proc = _decl("--self-test")
    print(proc.stdout[-2000:])
    assert proc.returncode == 0, proc.stdout[-4000:] + proc.stderr[-2000:]


def test_declaration_agrees_with_the_tree():
    proc = _decl("--suite", SUITE, "--verify")
    print(proc.stdout)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "осмотрено:" in proc.stdout, "сверка не назвала объём осмотренного"


def test_seed_answer_agrees_with_the_file_and_the_census_glob():
    path = pathlib.Path(_decl("--seed-path").stdout.strip())
    assert path.parent == HERE, f"посев церемонии вне каталога посевов: {path}"
    census = _census()
    assert path.name in {p.name for p in census.seed_scripts(HERE)} or not path.exists(), \
        "существующий посев не подпадает под отбор посевов переписи"
    assert path.match("seed_*.py"), (
        f"имя посева {path.name} не подпадает под отбор переписи `seed_*.py`: "
        f"приехавший посев перепись не спросила бы, какие ключи он пишет")
    rc = _decl("--seed-exists").returncode
    assert rc == (0 if path.is_file() else 1), f"ответ {rc} при файле {path.is_file()}"


def test_debt_names_every_stem_and_their_number():
    stems = [ln.strip() for ln in _decl("--suite", SUITE, "--stems").stdout.splitlines()
             if ln.strip()]
    proc = _decl("--suite", SUITE, "--debt")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    missing = [s for s in stems if s not in proc.stdout]
    assert not missing, f"долг не назвал: {missing}"
    assert f": {len(stems)}" in proc.stdout, "долг не назвал число коллекций"
