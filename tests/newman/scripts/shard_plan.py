#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ПЛАН ШАРДОВ НАБОРОВ СЛУШАТЕЛЯ ФОРМЫ И СВОДНЫЙ ВЕРДИКТ ШАРДОВ (kaname#848).

ПРЕДМЕТ. Наборы слушателя формы гонялись одним вызовом на одном стенде задания
`chart-own` (3802–3905 с при пределе шага 3900 с), затем двумя половинами
kaname#941 (шаг 30,3–35,1 мин). Время шага — сумма наборов, и три из них длинные
сами по себе (их окна — литералы профиля и контракта). Разрез — матрица шардов,
у каждого шарда СВОЙ стенд; план разреза лежит в дереве одним файлом
(`tests/newman/chart-own-shards.txt`) и читается здесь, прогонщиком, переписью
долга набора и пробой матрицы задания (`matrix_findings`) — одним разбором.

ВСЕЛЕННАЯ ВЫВОДИТСЯ, А НЕ ВЫПИСЫВАЕТСЯ. Набор слушателя формы — тот, чей модуль
кейсов либо коллекция читает `loginLaneBaseUrl`: эту переменную пишет ТОЛЬКО
посев полосы входа стенда `chart-own` (`stand-chart.sh seed-login-lane`), значит
ни на каком другом стенде такой набор не исполним. Перечень выписанный разошёлся
бы с деревом молча; выведенный — нет: новый набор формы, не названный планом,
роняет прогонщик КАЖДОГО шарда с его именем.

ИСХОДЫ — ТРИ, И ОНИ РАЗЛИЧАЮТСЯ КОДОМ:

    0  — план покрывает вселенную ровно (каждый набор — в одном шарде) и, в
         режиме `--verdict`, отчёт каждого набора каждого шарда есть и зелен;
    1  — `--verdict`: отчёта нет, он красен либо пуст — это вердикт;
    2  — план не исполним (набор вне шардов, набор в двух шардах, набор без
         предмета, шард не назван) либо судить нечего (каталог отчётов не
         скачан): вердикта НЕТ, и это не зелёное.

Режимы:
    shard_plan.py --plan F --shard X [--newman DIR]   наборы шарда X по строке
    shard_plan.py --plan F --verdict DIR [--prefix P] сводный вердикт шардов
    shard_plan.py --plan F --stems                    все наборы плана по строке
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

NEWMAN = pathlib.Path(__file__).resolve().parents[1]
FORM_KEY = "loginLaneBaseUrl"
SHARD_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
STEM_RE = re.compile(r"^[A-Za-z0-9._-]+$")

OK, RED, VOID = 0, 1, 2


class PlanError(Exception):
    """План не исполним: вердикта по нему нет."""


def parse(path: pathlib.Path) -> dict[str, list[str]]:
    """{шард: [набор, …]} в порядке файла. Строка — `<шард>: <набор> <набор> …`.

    Порядок наборов внутри шарда НЕСУЩИЙ (прогонщик идёт по нему), порядок шардов
    — нет. Набор в двух шардах — отказ: он прошёл бы дважды и сосчитался бы за два.
    """
    try:
        text = pathlib.Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise PlanError(f"план шардов не прочитан: {path}: {e}") from e
    plan: dict[str, list[str]] = {}
    seen: dict[str, str] = {}
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        head, sep, rest = line.partition(":")
        shard = head.strip()
        if not sep or not SHARD_RE.match(shard):
            raise PlanError(f"{path}:{n}: строка не вида «<шард>: <набор> …»: {raw!r}")
        if shard in plan:
            raise PlanError(f"{path}:{n}: шард {shard} объявлен дважды")
        stems = rest.split()
        if not stems:
            raise PlanError(f"{path}:{n}: шард {shard} без наборов")
        for s in stems:
            if not STEM_RE.match(s):
                raise PlanError(f"{path}:{n}: имя набора не вида stem: {s!r}")
            if s in seen:
                raise PlanError(f"{path}:{n}: набор {s} назван в шардах {seen[s]} и "
                                f"{shard} — прошёл бы дважды")
            seen[s] = shard
        plan[shard] = stems
    if not plan:
        raise PlanError(f"{path}: в плане ноль шардов — разрезать нечего")
    return plan


def _stems_of(directory: pathlib.Path, suffix: str) -> dict[str, pathlib.Path]:
    out: dict[str, pathlib.Path] = {}
    for p in sorted(directory.glob(f"*{suffix}")):
        stem = p.name[: -len(suffix)]
        # Правило генератора и общего слоя отбора (`kacholib/stems.sh`): ведущее
        # подчёркивание — помощник, а не набор.
        if not stem.startswith("_"):
            out[stem] = p
    return out


def universe(newman: pathlib.Path = NEWMAN) -> list[str]:
    """Наборы слушателя формы: модуль кейсов ЛИБО коллекция читает `loginLaneBaseUrl`.

    Читаются оба носителя: модуль без сгенерированной коллекции — тоже набор, и
    прогонщик пометит его отсутствующим, а не потеряет. Ноль осмотренных файлов —
    отказ, а не пустая вселенная.
    """
    newman = pathlib.Path(newman)
    cases = _stems_of(newman / "cases", ".py")
    cols = _stems_of(newman / "collections", ".postman_collection.json")
    if not cases and not cols:
        raise PlanError(f"в {newman} ноль модулей кейсов и ноль коллекций — "
                        f"вселенную выводить не из чего")
    found = set()
    for src in (cases, cols):
        for stem, p in src.items():
            if FORM_KEY in p.read_text(encoding="utf-8", errors="replace"):
                found.add(stem)
    return sorted(found)


def coverage_findings(plan: dict[str, list[str]], uni: list[str]) -> list[str]:
    """Расхождение плана со вселенной В ОБЕ СТОРОНЫ, каждая находка — с именем."""
    named = {s for v in plan.values() for s in v}
    out = [f"набор {s} не попал ни в один шард плана — не гонялся бы нигде"
           for s in uni if s not in named]
    out += [f"набор {s} назван планом, а набором слушателя формы не является "
            f"(ни модуль, ни коллекция не читают {FORM_KEY}) — запись без предмета"
            for s in sorted(named - set(uni))]
    return out


def shard_stems(plan_path: pathlib.Path, shard: str,
                newman: pathlib.Path = NEWMAN) -> list[str]:
    plan = parse(plan_path)
    bad = coverage_findings(plan, universe(newman))
    if bad:
        raise PlanError("\n".join(bad))
    if shard not in plan:
        raise PlanError(f"шард {shard} планом {plan_path} не объявлен; "
                        f"объявлены: {', '.join(plan)}")
    return plan[shard]


MATRIX_REF = "${{ matrix.shard }}"
_SHARD_ARG_RE = re.compile(r'--shard\s+"?(\$\{\{\s*matrix\.shard\s*\}\}|\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?)"?')


def matrix_findings(doc: dict, plan: dict[str, list[str]], plan_name: str,
                    job: str = "chart-own",
                    verdict_job: str = "chart-own-verdict") -> list[str]:
    """Матрица задания и план — одно и то же в обе стороны; каждая находка — с именем.

    `doc` — разобранный workflow (разбор у вызывающего: этот модуль идёт и на
    голом python3 ранера, где yaml нет). Судится: шарды `strategy.matrix.shard`
    против строк плана; шаг наборов берёт перечень из плана `--shard-plan
    <plan_name>`, а шард — из `matrix.shard` (прямо либо через переменную env
    задания или шага); имя артефакта шарда — `<префикс>${{ matrix.shard }}`, и тот
    же префикс и план называет сводный вердикт `verdict_job`.
    """
    jobs = doc.get("jobs") or {}
    j = jobs.get(job)
    if not isinstance(j, dict):
        return [f"задания {job} в workflow нет — судить матрицу не по чему"]
    out: list[str] = []
    matrix = ((j.get("strategy") or {}).get("matrix")) or {}
    shards = matrix.get("shard") if isinstance(matrix, dict) else None
    if not isinstance(shards, list) or not shards or not all(isinstance(s, str) for s in shards):
        return [f"матрица задания {job} не перечисляет шарды списком ключа shard: {matrix!r}"]
    out += [f"шард {s} плана {plan_name} в матрице задания {job} нет — его наборы не "
            f"гонялись бы нигде" for s in plan if s not in shards]
    out += [f"шард {s} матрицы задания {job} планом {plan_name} не объявлен"
            for s in shards if s not in plan]
    env = dict(j.get("env") or {})
    runs = [(st, str(st.get("run", ""))) for st in j.get("steps") or []]
    taking = [(st, body) for st, body in runs
              if re.search(rf"--shard-plan\s+\S*{re.escape(plan_name)}\b", body)]
    if not taking:
        out.append(f"ни один шаг задания {job} не берёт перечень из плана "
                   f"(`--shard-plan {plan_name}`)")
    for st, body in taking:
        m = _SHARD_ARG_RE.search(body)
        senv = {**env, **(st.get("env") or {})}
        if not m or (m.group(2) and str(senv.get(m.group(2), "")).replace(" ", "")
                     != MATRIX_REF.replace(" ", "")):
            out.append(f"шаг «{st.get('name')}» задания {job}: шард `--shard` не из "
                       f"matrix.shard — матрица и прогон разошлись бы молча")
    names = [str((st.get("with") or {}).get("name", "")) for st in j.get("steps") or []
             if "upload-artifact" in str(st.get("uses", ""))]
    prefixes = [n[: -len(MATRIX_REF)] for n in names if n.endswith(MATRIX_REF)]
    v = jobs.get(verdict_job)
    vbody = " ".join(str(st.get("run", "")) for st in (v or {}).get("steps") or [])
    if not prefixes:
        out.append(f"артефакт отчёта задания {job} не именуется `<префикс>{MATRIX_REF}`")
    elif not isinstance(v, dict):
        out.append(f"задания сводного вердикта {verdict_job} нет")
    else:
        if not any(re.search(rf"--prefix\s+{re.escape(p)}(\s|$)", vbody) for p in prefixes):
            out.append(f"сводный вердикт {verdict_job} не читает отчёты по префиксу "
                       f"артефакта ({', '.join(prefixes)}): `--prefix` разошёлся")
        if not re.search(rf"--plan\s+\S*{re.escape(plan_name)}\b", vbody):
            out.append(f"сводный вердикт {verdict_job} судит не план {plan_name}")
    return out


def _suite_line(d: pathlib.Path, stem: str) -> tuple[bool, str]:
    js, rcf = d / f"{stem}.json", d / f"{stem}.rc"
    if not js.is_file():
        return False, "MISSING — отчёта нет"
    try:
        stats = json.loads(js.read_text(encoding="utf-8"))["run"]["stats"]
        total = int(stats["assertions"]["total"])
        failed = int(stats["assertions"]["failed"])
        unanswered = int(stats.get("requests", {}).get("failed", 0) or 0)
    except (OSError, ValueError, KeyError, TypeError) as e:
        return False, f"отчёт не разбирается ({type(e).__name__})"
    rc = rcf.read_text(encoding="utf-8").strip() if rcf.is_file() else "n/a"
    note = f"утверждений {total} · упало {failed} · без ответа {unanswered} · rc {rc}"
    if total == 0:
        return False, note + " — NOTHING RAN"
    if failed or unanswered or rc != "0":
        return False, note
    return True, note


def verdict(plan_path: pathlib.Path, reports: pathlib.Path,
            newman: pathlib.Path | None = None, prefix: str = "") -> int:
    """Сводный вердикт: отчёт КАЖДОГО набора КАЖДОГО шарда плана — `<DIR>/<префикс><шард>/`.

    Префикс — имя артефакта шарда без имени шарда: скачивание по образцу кладёт
    каждый артефакт в каталог его имени.
    """
    try:
        plan = parse(plan_path)
        if newman is not None:
            bad = coverage_findings(plan, universe(newman))
            if bad:
                raise PlanError("\n".join(bad))
    except PlanError as e:
        print(f"ОТКАЗ: {e}", file=sys.stderr)
        return VOID
    reports = pathlib.Path(reports)
    if not reports.is_dir():
        print(f"ОТКАЗ: каталога отчётов {reports} нет — не скачано ничего, судить "
              f"нечего; это не зелёное", file=sys.stderr)
        return VOID
    total = sum(len(v) for v in plan.values())
    good = reported = shards_seen = 0
    for shard, stems in plan.items():
        d = reports / f"{prefix}{shard}"
        if d.is_dir():
            shards_seen += 1
        else:
            print(f"шард {shard}: ОТЧЁТА ШАРДА НЕТ — каталог {d} не скачан")
        for stem in stems:
            ok, note = _suite_line(d, stem)
            if not note.startswith("MISSING"):
                reported += 1
            good += ok
            print(f"  {'ok  ' if ok else 'FAIL'} {shard} / {stem}: {note}")
    print(f"шардов с отчётом {shards_seen} из {len(plan)} · наборов с отчётом "
          f"{reported} из {total} · зелёных {good} из {total}")
    return OK if good == total else RED


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--plan", required=True, type=pathlib.Path)
    # Каталог набора: вселенная выводится из него. У `--verdict` он необязателен —
    # покрытие вселенной судит прогонщик каждого шарда; названный, он судится и здесь.
    ap.add_argument("--newman", type=pathlib.Path, default=None)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--shard")
    mode.add_argument("--verdict", type=pathlib.Path, metavar="DIR")
    mode.add_argument("--stems", action="store_true")
    ap.add_argument("--prefix", default="", help="--verdict: префикс каталога шарда")
    a = ap.parse_args(argv)
    if a.verdict is not None:
        return verdict(a.plan, a.verdict, a.newman, a.prefix)
    try:
        if a.stems:
            stems = [s for v in parse(a.plan).values() for s in v]
        else:
            stems = shard_stems(a.plan, a.shard, a.newman or NEWMAN)
    except PlanError as e:
        print(f"ОТКАЗ: {e}", file=sys.stderr)
        return VOID
    print("\n".join(stems))
    return OK


if __name__ == "__main__":
    sys.exit(main())
