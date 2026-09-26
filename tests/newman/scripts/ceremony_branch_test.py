#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ВЕТВЬ ВОЛНЫ ЦЕРЕМОНИИ В ПРОГОНЩИКЕ ЧИТАЕТ ИСХОДЫ ОБЪЯВЛЕНИЯ (kaname#398).

ПРЕДМЕТ. `run.sh` решает, вычитать ли из общей волны коллекции, которым нужен
человеческий предъявитель, по ответам объявления
(`tests/authz-fixtures/ceremony_credentials.py`). Ответов пять, и у каждого свой
печатный исход:

  1. объявления нет                   → «нет объявления», вычитания нет;
  2. объявление есть, посева нет      → «посева церемонии нет» И долг объявления;
  3. то же, но долг не напечатался    → «долг НЕ напечатан», прогонщик НЕ обрывается;
  4. посев есть, перечень выведен     → «делегировано коллекций: N», N — из перечня;
  5. посев есть, перечень НЕ выведен  → «перечень волны не выведен (код …)», вычитания нет.

Пятое — ради чего проба заведена. Перечень читался подстановкой процесса, где
код его отказа теряется, и упавший вывод печатался строкой «волна активна —
делегировано коллекций: 0». Ветвь станет живой вместе с посевом, и тогда эта
строка читалась бы как «волна пуста», а не как «ничего не выведено».

КАК ПРОБУЕТСЯ. Исполняется НАСТОЯЩИЙ блок прогонщика — от `_tree_root() {` до
`_is_delegated() {` — против синтетического корня, где объявление заменено
дублёром с управляемыми ответами. Границы блока — предпосылка пробы: не нашлась
граница — проба падает и называет её, а не молчит.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import textwrap

import pytest

HERE = pathlib.Path(__file__).resolve().parent
RUN_SH = HERE / "run.sh"
START = "_tree_root() {"
STOP = "_is_delegated() {"

DOUBLE = textwrap.dedent('''\
    import os, sys
    mode = os.environ["DOUBLE_MODE"]
    if "--seed-exists" in sys.argv:
        sys.exit(0 if mode.startswith("seed") else 1)
    if "--debt" in sys.argv:
        if mode == "no-seed-debt-fails":
            sys.exit(1)
        print("DEBT-PRINTED")
        sys.exit(0)
    if "--stems" in sys.argv:
        if mode == "seed-stems-fail":
            sys.exit(1)
        print("wave-a")
        print("wave-b")
        sys.exit(0)
    sys.exit(2)
''')


def _block() -> str:
    text = RUN_SH.read_text(encoding="utf-8")
    assert START in text, f"предпосылка: в {RUN_SH.name} нет границы «{START}»"
    assert STOP in text, f"предпосылка: в {RUN_SH.name} нет границы «{STOP}»"
    return text[text.index(START):text.index(STOP)]


def _run(tmp_path: pathlib.Path, mode: str | None) -> tuple[int, str, list[str]]:
    root = tmp_path / "root"
    newman = root / "tests" / "newman"
    newman.mkdir(parents=True)
    (root / "go.mod").write_text("module example\n", encoding="utf-8")
    if mode is not None:
        fx = root / "tests" / "authz-fixtures"
        fx.mkdir(parents=True)
        (fx / "ceremony_credentials.py").write_text(DOUBLE, encoding="utf-8")
    script = ("set -euo pipefail\n"
              f"NEWMAN_DIR={str(newman)!r}\n"
              "DELEGATED=(authz-failclosed)\n"
              + _block()
              + '\nprintf "DELEGATED=%s\\n" "${DELEGATED[*]}"\n')
    env = dict(os.environ, DOUBLE_MODE=mode or "")
    proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                          env=env, timeout=60)
    out = proc.stdout + proc.stderr
    last = [ln for ln in proc.stdout.splitlines() if ln.startswith("DELEGATED=")]
    delegated = last[-1][len("DELEGATED="):].split() if last else []
    return proc.returncode, out, delegated


def test_no_declaration_is_named_and_subtracts_nothing(tmp_path):
    rc, out, delegated = _run(tmp_path, None)
    assert rc == 0, out
    assert "нет объявления" in out, out
    assert delegated == ["authz-failclosed"], out


def test_declaration_without_seed_prints_the_debt(tmp_path):
    rc, out, delegated = _run(tmp_path, "no-seed")
    assert rc == 0, out
    assert "посева церемонии нет" in out, out
    assert "DEBT-PRINTED" in out, "долг объявления не напечатан: " + out
    assert delegated == ["authz-failclosed"], out


def test_debt_refusal_is_named_and_does_not_abort_the_runner(tmp_path):
    rc, out, delegated = _run(tmp_path, "no-seed-debt-fails")
    assert rc == 0, "прогонщик оборвался на отказе печати долга: " + out
    assert "долг НЕ напечатан" in out, out
    assert delegated == ["authz-failclosed"], out


def test_seed_and_stems_delegate_exactly_the_wave(tmp_path):
    rc, out, delegated = _run(tmp_path, "seed-ok")
    assert rc == 0, out
    assert "делегировано коллекций: 2" in out, out
    assert delegated == ["authz-failclosed", "wave-a", "wave-b"], out


def test_stems_refusal_is_not_printed_as_an_empty_wave(tmp_path):
    rc, out, delegated = _run(tmp_path, "seed-stems-fail")
    assert rc == 0, "прогонщик оборвался на отказе перечня: " + out
    assert "делегировано коллекций: 0" not in out, (
        "отказ перечня напечатан как пустая волна: " + out)
    assert "перечень волны не выведен (код 1)" in out, out
    assert delegated == ["authz-failclosed"], out


@pytest.mark.parametrize("boundary", [START, STOP])
def test_block_boundaries_exist(boundary):
    assert boundary in RUN_SH.read_text(encoding="utf-8"), boundary
