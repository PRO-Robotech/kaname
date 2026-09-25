#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ВЕРДИКТ ВОЛНЫ ЦЕРЕМОНИИ ЧЕСТЕН: ни одно непрошедшее состояние не даёт 0 (kaname#398).

ПРЕДМЕТ. `run-ceremony.sh` выносит вердикт волны функцией `aggregate_verdict
<out_dir> <stem…>`. В дереве платформы её судила общая инъекция по всем
агрегаторам; в дереве службы того файла нет, и шапка волны называла держателем
координату, которой здесь не существует. Эта проба и есть держатель здесь.

ЧТО УТВЕРЖДАЕТСЯ. Чистый отчёт — 0. Каждое из пяти непрошедших состояний — не 0:
упавшее утверждение · запрос без ответа · немой отчёт (0 утверждений) ·
отсутствующий отчёт · ненулевой код newman. Итоговая строка называет «N/M
коллекций отчиталось» — отсутствие отчёта видно числом, а не только кодом.

ПРОБА СПОСОБНА УПАСТЬ. Отдельная ось портит функцию тем же дефектом, от которого
она защищает (снимает реакцию на упавшее утверждение), и требует, чтобы
соответствующее состояние тогда ПРОШЛО: иначе зелёный этой пробы неотличим от
зелёного пробы, которая функцию не вызывает.

КАК ИСПОЛНЯЕТСЯ. Берётся НАСТОЯЩИЙ текст функции — от `aggregate_verdict() {` до
первой строки `}` в начале строки. Граница не нашлась — проба падает и называет её.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess

import pytest

HERE = pathlib.Path(__file__).resolve().parent
WAVE = HERE / "run-ceremony.sh"
HEAD = "aggregate_verdict() {"
DEFECT_FROM = 'if [[ "$failed" -gt 0 ]]; then bad=1; fi'


def _function() -> str:
    text = WAVE.read_text(encoding="utf-8")
    assert HEAD in text, f"предпосылка: в {WAVE.name} нет «{HEAD}»"
    start = text.index(HEAD)
    end = text.index("\n}\n", start)
    return text[start:end + 3]


def _report(out: pathlib.Path, stem: str, *, total: int, failed: int,
            requests: int, unanswered: int, rc: str | None = "0") -> None:
    (out / f"{stem}.json").write_text(json.dumps({"run": {
        "stats": {"assertions": {"total": total, "failed": failed},
                  "requests": {"total": requests, "failed": unanswered}},
        "failures": []}}), encoding="utf-8")
    if rc is not None:
        (out / f"{stem}.rc").write_text(rc + "\n", encoding="utf-8")


def _verdict(func: str, out: pathlib.Path, stems: list[str]) -> tuple[int, str]:
    script = func + '\naggregate_verdict "$@"\n'
    proc = subprocess.run(["bash", "-c", script, "wave", str(out), *stems],
                          capture_output=True, text=True, timeout=60)
    return proc.returncode, proc.stdout + proc.stderr


STATES = {
    "clean": dict(total=3, failed=0, requests=3, unanswered=0, rc="0"),
    "failed-assertion": dict(total=3, failed=1, requests=3, unanswered=0, rc="0"),
    "unanswered": dict(total=3, failed=0, requests=3, unanswered=1, rc="0"),
    "mute": dict(total=0, failed=0, requests=1, unanswered=0, rc="0"),
    "nonzero-rc": dict(total=3, failed=0, requests=3, unanswered=0, rc="1"),
}


@pytest.fixture(scope="module")
def jq_present():
    if shutil.which("jq") is None:
        pytest.fail("УСЛОВИЕ НЕ СОЗДАНО: нет jq — агрегатор читает отчёт им, "
                    "и без него вердикт этой пробы не выносится")


def test_clean_report_passes(tmp_path, jq_present):
    _report(tmp_path, "c", **STATES["clean"])
    rc, out = _verdict(_function(), tmp_path, ["c"])
    assert rc == 0, out
    assert "TOTAL: 1/1 коллекций отчиталось" in out, out


@pytest.mark.parametrize("state", ["failed-assertion", "unanswered", "mute", "nonzero-rc"])
def test_every_failing_state_is_not_zero(tmp_path, jq_present, state):
    _report(tmp_path, "c", **STATES["clean"])
    _report(tmp_path, "s", **STATES[state])
    rc, out = _verdict(_function(), tmp_path, ["c", "s"])
    assert rc != 0, f"{state} прошёл как зелёный: {out}"


def test_missing_report_is_not_zero_and_is_counted(tmp_path, jq_present):
    _report(tmp_path, "c", **STATES["clean"])
    rc, out = _verdict(_function(), tmp_path, ["c", "absent"])
    assert rc != 0, out
    assert "MISSING" in out, out
    assert "TOTAL: 1/2 коллекций отчиталось" in out, out


def test_probe_can_fail_when_the_function_is_defective(tmp_path, jq_present):
    func = _function()
    assert DEFECT_FROM in func, f"предпосылка инъекции: в функции нет «{DEFECT_FROM}»"
    broken = func.replace(DEFECT_FROM, ":")
    _report(tmp_path, "s", **STATES["failed-assertion"])
    rc, out = _verdict(broken, tmp_path, ["s"])
    assert rc == 0, ("инъекция не сработала: испорченная функция всё равно краснеет — "
                     "значит проба различает не то, что заявляет: " + out)
