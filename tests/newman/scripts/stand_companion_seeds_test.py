# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Самопроверки посевов-соседей подкоманды `seed-stored-value` исполняются в конвейере.

ПРЕДМЕТ. Посевы `tests/authz-fixtures/seed_mail_pace.py` (Ф5-14, Ф5-26, Ф5-27) и
`tests/authz-fixtures/seed_key_person.py` (FP-12) зовёт подкоманда стенда
`seed-stored-value` задания `chart-own`, а их способность упасть доказывает форма
`--self-test`. Отдельного шага конвейера у этих самопроверок нет: пробы набора
(`tests/newman/scripts/*_test.py`) исполняет `run-python-probes.py` задания
`suite`, и эта проба несёт обе самопроверки туда. Код самопроверки, отличный от
нуля, — красное с её выводом, а не молчание.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
SEEDS = ("seed_mail_pace.py", "seed_key_person.py")


def _self_test(name: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(ROOT / "tests" / "authz-fixtures" / name), "--self-test"],
                          capture_output=True, text=True, timeout=300)


def test_seed_mail_pace_self_test_is_green():
    proc = _self_test(SEEDS[0])
    assert proc.returncode == 0, proc.stdout[-3000:] + proc.stderr[-2000:]
    assert "ДОКАЗАНО" in proc.stdout


def test_seed_key_person_self_test_is_green():
    proc = _self_test(SEEDS[1])
    assert proc.returncode == 0, proc.stdout[-3000:] + proc.stderr[-2000:]
    assert "ДОКАЗАНО" in proc.stdout


def test_both_companions_are_called_by_the_stand_subcommand():
    """Самопроверка без провязки ничего не держит: стенд обязан звать оба посева."""
    script = (ROOT / ".github" / "scripts" / "stand-chart.sh").read_text(encoding="utf-8")
    calls = [ln for ln in script.splitlines()
             if not ln.lstrip().startswith("#") and "tests/authz-fixtures/" in ln]
    for name in SEEDS:
        assert sum(name in ln for ln in calls) == 1, f"stand-chart.sh зовёт {name} не ровно один раз"
