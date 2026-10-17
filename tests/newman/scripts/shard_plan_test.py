# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ПЛАН ШАРДОВ `chart-own` И СВОДНЫЙ ВЕРДИКТ ШАРДОВ СПОСОБНЫ УПАСТЬ (kaname#848).

ПРЕДМЕТ. Наборы слушателя формы гоняются матрицей шардов, у каждого шарда свой
стенд. Разрез вносит два новых способа потерять покрытие молча, и у каждого —
своя проба:

  1. набор, не попавший ни в один шард, не гонялся бы нигде, а каждый шард был
     бы зелёным. Прогонщик (`run.sh --shard-plan … --shard …`) отказывает с
     ИМЕНЕМ такого набора ДО стенда;
  2. шард, выпавший из матрицы либо не выложивший отчёт, не дал бы красного ни
     одному заданию матрицы. Сводный вердикт (`shard_plan.py --verdict`) судит
     отчёт КАЖДОГО набора КАЖДОГО шарда плана и краснеет на отсутствующем.

Каждое утверждение — парой: инъекция дефекта краснеет и называет координату,
законный близнец той же формы молчит.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile

NEWMAN = pathlib.Path(__file__).resolve().parents[1]
RUNNER = NEWMAN / "scripts" / "run.sh"
PLAN = NEWMAN / "chart-own-shards.txt"

sys.path.insert(0, str(NEWMAN / "scripts"))
import shard_plan  # noqa: E402


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(RUNNER), *args], capture_output=True,
                          text=True, timeout=120)


def _universe() -> list[str]:
    return shard_plan.universe(NEWMAN)


def _write_plan(tmp: pathlib.Path, shards: dict[str, list[str]]) -> pathlib.Path:
    p = tmp / "plan.txt"
    p.write_text("".join(f"{k}: {' '.join(v)}\n" for k, v in shards.items()),
                 encoding="utf-8")
    return p


def _report(d: pathlib.Path, stem: str, total: int = 3, failed: int = 0,
            rc: int = 0) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{stem}.json").write_text(json.dumps({"run": {"stats": {
        "assertions": {"total": total, "failed": failed},
        "requests": {"total": 2, "failed": 0}}}}), encoding="utf-8")
    (d / f"{stem}.rc").write_text(f"{rc}\n", encoding="utf-8")


def _reports(root: pathlib.Path, plan: dict[str, list[str]]) -> None:
    for shard, stems in plan.items():
        for s in stems:
            _report(root / shard, s)


def _verdict(plan: pathlib.Path, root: pathlib.Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(NEWMAN / "scripts" / "shard_plan.py"),
                           "--plan", str(plan), "--verdict", str(root)],
                          capture_output=True, text=True, timeout=60)


# ── предпосылка: вселенная выводится из дерева и непуста ─────────────────────

def test_universe_is_derived_and_nonempty() -> None:
    u = _universe()
    assert len(u) >= 2, f"вселенная наборов слушателя формы пуста либо вырождена: {u}"
    assert "kaname-login-lane" in u, u


def test_tree_plan_covers_the_universe_exactly() -> None:
    plan = shard_plan.parse(PLAN)
    union = [s for v in plan.values() for s in v]
    assert sorted(union) == sorted(_universe()), (union, _universe())
    assert len(plan) >= 3, f"шардов меньше трёх: {sorted(plan)}"


# ── прогонщик: набор вне шардов → отказ с именем ─────────────────────────────

def test_runner_refuses_a_suite_outside_every_shard() -> None:
    u = _universe()
    dropped = u[-1]
    with tempfile.TemporaryDirectory() as t:
        plan = _write_plan(pathlib.Path(t), {"x": u[:-1]})
        r = _run("--shard-plan", str(plan), "--shard", "x", "--list")
    assert r.returncode == 2, (r.returncode, r.stdout, r.stderr)
    assert dropped in r.stderr, r.stderr


def test_runner_lists_the_shard_of_a_covering_plan() -> None:
    u = _universe()
    with tempfile.TemporaryDirectory() as t:
        plan = _write_plan(pathlib.Path(t), {"x": u[:1], "y": u[1:]})
        r = _run("--shard-plan", str(plan), "--shard", "y", "--list")
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert r.stdout.split() == u[1:], r.stdout


def test_runner_refuses_an_unknown_shard_and_a_mix_with_service() -> None:
    r = _run("--shard-plan", str(PLAN), "--shard", "no-such-shard", "--list")
    assert r.returncode == 2 and "no-such-shard" in r.stderr, (r.returncode, r.stderr)
    r = _run("--shard-plan", str(PLAN), "--shard", next(iter(shard_plan.parse(PLAN))),
             "--service", "kaname-login-lane", "--list")
    assert r.returncode == 2, (r.returncode, r.stderr)


def test_plan_refuses_a_suite_in_two_shards() -> None:
    u = _universe()
    with tempfile.TemporaryDirectory() as t:
        plan = _write_plan(pathlib.Path(t), {"x": u, "y": u[:1]})
        r = _run("--shard-plan", str(plan), "--shard", "x", "--list")
    assert r.returncode == 2 and u[0] in r.stderr, (r.returncode, r.stderr)


# ── сводный вердикт: отчёт одного шарда удалён → красное ─────────────────────

PLAN_SYN = {"a": ["s1", "s2"], "b": ["s3"], "c": ["s4"]}


def test_verdict_green_when_every_report_is_there() -> None:
    with tempfile.TemporaryDirectory() as t:
        tmp = pathlib.Path(t)
        plan = _write_plan(tmp, PLAN_SYN)
        _reports(tmp / "r", PLAN_SYN)
        r = _verdict(plan, tmp / "r")
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert "наборов с отчётом 4 из 4" in r.stdout, r.stdout


def test_verdict_red_when_one_shard_report_is_removed() -> None:
    with tempfile.TemporaryDirectory() as t:
        tmp = pathlib.Path(t)
        plan = _write_plan(tmp, PLAN_SYN)
        _reports(tmp / "r", PLAN_SYN)
        for f in (tmp / "r" / "b").iterdir():
            f.unlink()
        (tmp / "r" / "b").rmdir()
        r = _verdict(plan, tmp / "r")
    assert r.returncode == 1, (r.returncode, r.stdout, r.stderr)
    assert "b" in r.stdout and "s3" in r.stdout, r.stdout


def test_verdict_red_when_one_suite_report_is_removed() -> None:
    with tempfile.TemporaryDirectory() as t:
        tmp = pathlib.Path(t)
        plan = _write_plan(tmp, PLAN_SYN)
        _reports(tmp / "r", PLAN_SYN)
        (tmp / "r" / "a" / "s2.json").unlink()
        r = _verdict(plan, tmp / "r")
    assert r.returncode == 1 and "s2" in r.stdout, (r.returncode, r.stdout)


def test_verdict_red_on_failed_empty_or_nonzero_rc() -> None:
    for kw in ({"failed": 1}, {"total": 0}, {"rc": 1}):
        with tempfile.TemporaryDirectory() as t:
            tmp = pathlib.Path(t)
            plan = _write_plan(tmp, PLAN_SYN)
            _reports(tmp / "r", PLAN_SYN)
            _report(tmp / "r" / "c", "s4", **kw)
            r = _verdict(plan, tmp / "r")
        assert r.returncode == 1 and "s4" in r.stdout, (kw, r.returncode, r.stdout)


def test_verdict_void_when_nothing_was_downloaded() -> None:
    with tempfile.TemporaryDirectory() as t:
        tmp = pathlib.Path(t)
        plan = _write_plan(tmp, PLAN_SYN)
        r = _verdict(plan, tmp / "absent")
    assert r.returncode == 2, (r.returncode, r.stdout, r.stderr)


def test_verdict_reads_shard_dirs_by_artifact_prefix() -> None:
    with tempfile.TemporaryDirectory() as t:
        tmp = pathlib.Path(t)
        plan = _write_plan(tmp, PLAN_SYN)
        for shard, stems in PLAN_SYN.items():
            for s in stems:
                _report(tmp / "r" / f"rep-{shard}", s)
        args = [sys.executable, str(NEWMAN / "scripts" / "shard_plan.py"),
                "--plan", str(plan), "--verdict", str(tmp / "r")]
        bare = subprocess.run(args, capture_output=True, text=True, timeout=60)
        named = subprocess.run(args + ["--prefix", "rep-"], capture_output=True,
                               text=True, timeout=60)
    assert bare.returncode == 1, (bare.returncode, bare.stdout)
    assert named.returncode == 0, (named.returncode, named.stdout, named.stderr)


def test_verdict_with_newman_judges_the_tree_plan_coverage() -> None:
    with tempfile.TemporaryDirectory() as t:
        tmp = pathlib.Path(t)
        u = _universe()
        plan = _write_plan(tmp, {"x": u[:-1]})
        _reports(tmp / "r", {"x": u[:-1]})
        r = subprocess.run([sys.executable, str(NEWMAN / "scripts" / "shard_plan.py"),
                            "--plan", str(plan), "--verdict", str(tmp / "r"),
                            "--newman", str(NEWMAN)],
                           capture_output=True, text=True, timeout=60)
    assert r.returncode == 2 and u[-1] in r.stderr, (r.returncode, r.stderr)
