#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""unit-shards — юниты `-race -short` матрицей шардов: план → шарды → сводный вердикт.

ПРЕДМЕТ (kaname#873)
--------------------
Юниты шли ОДНИМ заданием: стена 1192…1852 с (ствол 422d1bc6f — 1484 с, прогон
39026914830). Критический путь — несколько пакетов-гейтов дерева: замер
2026-10-17 (`go test ./... -race -short -json`, 144 пакета с пробами) —
`internal/check` 1255 с, `internal/supplyhygiene` 734 с,
`internal/apps/kaname/api/humansession` 637 с, `internal/apps/kaname/config`
460 с, `deploy` 300 с: пять пакетов — 72 % суммы. Пакеты внутри одного `go test`
идут параллельно, поэтому стена прогона — это время САМОГО ДОЛГОГО пакета, и
распил по пакетам её не опускает ниже 1255 с. Опускает её только распил ПАКЕТА.

ПОЧЕМУ `-race` ОСТАЁТСЯ И У ГЕЙТОВ ДЕРЕВА — ЗАМЕР, А НЕ ВКУС
-----------------------------------------------------------
Гонку детектор находит только там, где горутин больше одной. Перепись
конкурентности тяжёлых пакетов сделана двумя способами, и оба дали «есть»:

  * по тексту (лексер Go, вне комментариев и литералов): `internal/check` —
    `.Parallel()` 730, `go` 1, `select` 1, импорт `sync`; `internal/supplyhygiene`
    — `.Parallel()` 148, `go` 1; `deploy`, `config`, `humansession` — тоже;
  * исполнением (`go test -short -trace`, порождения горутин по стеку
    породившего): `internal/check` — 21 горутина, порождённая кодом модуля, и
    48 100 событий трассы со стеком `testing.(*T).Parallel` — параллельные пробы
    делят состояние пакета, и это ровно предмет детектора.

Значит снять `-race` с гейтов нельзя: стена опускается распилом пакета ПО ПРОБАМ.

ДВЕ ЕДИНИЦЫ РАЗДАЧИ
-------------------
  * пакет целиком — всякий пакет `go list ./...`, включая пакеты без проб: так
    шарды осматривают РОВНО то же множество, что и прежний `go test ./...`;
  * часть пакета — пакет, чей замеренный вес больше бюджета шарда, режется на
    N = ⌈вес / бюджет⌉ частей. Проба верхнего уровня (имя из `go test -list`)
    попадает в часть `sha256(имя) mod N`. Это чистая функция имени: части
    вычисляются независимо в разных заданиях и сходятся без обмена.

ПОЧЕМУ ВЕСА — ВЕДОМОСТЬ, И ПОЧЕМУ ЭТО БЕЗОПАСНО
-----------------------------------------------
Веса (`.github/unit-shard-weights.txt`) решают ТОЛЬКО раскладку: число частей
пакета и соседство в шарде. Полноту они не решают — пакет без строки
раздаётся с весом по умолчанию и строкой «вес не замерен», а строка о пакете,
которого нет в дереве, — находка (запись, пережившая предмет). Ошибись вес
вдвое — изменится стена, а не покрытие.

ПОЛНОТА — ЧИСЛАМИ, В ТРЁХ МЕСТАХ
--------------------------------
  1. план (`--plan`): множество розданных пакетов СОВПАДАЕТ с `go list ./...`,
     ни одного дважды, части каждого распиленного пакета — 0..N-1 ровно по разу;
  2. шард (`--run`): у каждой части — перечень проб пакета и её выборка; выборка
     сверяется с функцией разреза тут же, до прогона;
  3. свод (`--aggregate`): все шарды плана отчитались; пакеты, ВИДЕННЫЕ в потоках
     `go test -json`, совпадают с деревом плана; у распиленного пакета перечни
     всех частей равны, выборки не пересекаются и в объединении дают перечень;
     исполненные пробы части лежат в её выборке, а невыполненные — только
     замеры (`Benchmark*`, без `-bench` их не исполняет и прежний прогон).
Сверяются МНОЖЕСТВА, а не размеры: потеря плюс задвоение дают тот же размер.

ИСХОДЫ: 0 — зелено · 1 — находка либо красная проба · 2 — не выполнилось
(обход пуст, `go list` не отработал, отчёта нет). Ноль осмотренного — не зелёный.

Запуск:
  python3 .github/scripts/unit-shards.py --self-test
  python3 .github/scripts/unit-shards.py --plan --out unit-plan.json [--github-output "$GITHUB_OUTPUT"]
  python3 .github/scripts/unit-shards.py --run u01 --plan unit-plan.json --out-dir unit-out --attempt 1
  python3 .github/scripts/unit-shards.py --aggregate --plan unit-plan.json --dir unit-in \
      --plan-result success --shard-result success
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEIGHTS = ROOT / ".github" / "unit-shard-weights.txt"
VERDICT = ROOT / ".github" / "scripts" / "go-test-verdict.py"

# Бюджет шарда — в единицах ведомости весов (секунды пакета в прогоне `-race`).
# Предмет — стена шарда не больше 6 мин (kaname#873): из них подготовка и сборка
# под `-race` — около минуты на прогретом кэше, остальное — пробы.
BUDGET = 420
# Вес пакета без строки в ведомости. Он решает только раскладку (см. шапку).
DEFAULT_WEIGHT = 10

# Флаги прогона — ОДНО объявление: перечень частей (`-list`) и прогон обязаны
# собираться одинаково, иначе `-list` перечислил бы пробы другой сборки
# (`internal/check` несёт файл под `//go:build race`).
BUILD_FLAGS = ["-race"]
RUN_FLAGS = ["-short", "-count=1", "-timeout", "25m"]

TOP_NAME_RE = re.compile(r"^(Test|Benchmark|Fuzz|Example)[A-Za-z0-9_\u0080-￿]*$")


class Unmeasured(Exception):
    """Измерение не сделано. Отлично от «пакетов ноль»: сорвавшийся `go list`
    отдаёт пустой список, и пустая раздача дала бы зелёный прогон из ничего."""


# ─── разрез пакета по пробам ────────────────────────────────────────────────

def part_of(name: str, parts: int) -> int:
    """Часть пробы — чистая функция имени: два задания считают её одинаково."""
    return int(hashlib.sha256(name.encode("utf-8")).hexdigest()[:12], 16) % parts


def select(names: list[str], part: int, parts: int) -> list[str]:
    return sorted(n for n in names if part_of(n, parts) == part)


def run_regex(names: list[str]) -> str:
    """`-run` для выборки: имена — идентификаторы Go, экранировать нечего, а `/`
    (разделитель уровней `-run`) в имени верхнего уровня невозможен."""
    return "^(" + "|".join(names) + ")$"


def partition_findings(pkg: str, parts: int, listed: dict[int, list[str]],
                       selected: dict[int, list[str]]) -> list[str]:
    """Каждая проба — ровно в одной части. Вход — то, что отчитали части."""
    out: list[str] = []
    missing_parts = sorted(set(range(parts)) - set(selected))
    if missing_parts:
        out.append(f"{pkg}: нет отчёта частей {missing_parts} из {parts} — их пробы "
                   f"не исполнены, и «ноль упавших» про них не говорит ничего")
    lists = {tuple(v) for v in listed.values()}
    if len(lists) > 1:
        out.append(f"{pkg}: части перечислили РАЗНЫЕ наборы проб ({len(lists)} "
                   f"варианта) — разрез судит не одно и то же дерево")
    universe = set().union(*[set(v) for v in listed.values()]) if listed else set()
    owner: dict[str, list[int]] = {}
    for k, names in selected.items():
        for n in names:
            owner.setdefault(n, []).append(k)
    twice = sorted(n for n, ks in owner.items() if len(ks) > 1)
    if twice:
        out.append(f"{pkg}: проба в НЕСКОЛЬКИХ частях ({len(twice)}): "
                   f"{', '.join(twice[:8])} — время тратится дважды, вердиктов о ней два")
    nowhere = sorted(universe - set(owner))
    if nowhere and not missing_parts:
        out.append(f"{pkg}: проба НИ В ОДНОЙ части ({len(nowhere)}): "
                   f"{', '.join(nowhere[:8])} — она не исполнится, и это не будет видно")
    alien = sorted(set(owner) - universe)
    if alien:
        out.append(f"{pkg}: выборка несёт пробы не из перечня ({len(alien)}): "
                   f"{', '.join(alien[:8])}")
    return out


# ─── план ───────────────────────────────────────────────────────────────────

def go(args: list[str], timeout: int = 1800) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["go", *args], cwd=ROOT, capture_output=True, text=True,
                              timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        raise Unmeasured(f"`go {' '.join(args[:3])} …` не отработал: {e}") from e


def tree_packages() -> list[str]:
    """Пакеты `./...` — ТО ЖЕ множество, которое осматривал прежний `go test ./...`."""
    p = go(["list", "./..."])
    if p.returncode != 0:
        raise Unmeasured(f"`go list ./...` вышел кодом {p.returncode} — состав НЕ ИЗМЕРЕН: "
                         f"{p.stderr.strip()[:400]}")
    pkgs = sorted({x.strip() for x in p.stdout.splitlines() if x.strip()})
    if not pkgs:
        raise Unmeasured("пакетов НОЛЬ — обход пуст; пустая раздача дала бы зелёный "
                         "прогон, в котором не исполнилось ни одной пробы")
    return pkgs


def read_weights(path: Path) -> tuple[dict[str, int], list[str]]:
    weights: dict[str, int] = {}
    bad: list[str] = []
    if not path.is_file():
        raise Unmeasured(f"ведомость весов {path} не прочитана — раскладывать не из чего")
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        f = s.split()
        if len(f) != 2 or not f[0].isdigit():
            bad.append(f"{path.name}:{i}: строка не в форме «<секунды> <пакет>»: {s[:120]}")
            continue
        if f[1] in weights:
            bad.append(f"{path.name}:{i}: пакет {f[1]} назван дважды")
        weights[f[1]] = int(f[0])
    return weights, bad


def build_plan(tree: list[str], weights: dict[str, int], budget: int) -> dict:
    """Раскладка: тяжёлые пакеты режутся на части, затем LPT — самая тяжёлая
    единица в наименее загруженный шард; шардов — наименьшее число, при котором
    самый загруженный не выходит за бюджет (либо за самую тяжёлую единицу)."""
    units: list[tuple[int, dict]] = []
    for pkg in tree:
        w = weights.get(pkg, DEFAULT_WEIGHT)
        parts = max(1, math.ceil(w / budget))
        if parts == 1:
            units.append((w, {"pkg": pkg}))
        else:
            for k in range(parts):
                units.append((math.ceil(w / parts), {"pkg": pkg, "part": k, "parts": parts}))
    units.sort(key=lambda u: (-u[0], u[1]["pkg"], u[1].get("part", -1)))
    total = sum(w for w, _ in units)
    cap = max(budget, units[0][0] if units else 0)
    n = max(1, math.ceil(total / budget))
    while True:
        bins: list[list] = [[0, []] for _ in range(n)]
        for w, u in units:
            b = min(bins, key=lambda x: x[0])
            b[0] += w
            b[1].append(u)
        if max(b[0] for b in bins) <= cap or n >= len(units):
            break
        n += 1
    bins.sort(key=lambda b: -b[0])
    width = max(2, len(str(n)))
    shards = [{"id": f"u{i + 1:0{width}d}", "weight": w,
               "units": sorted(us, key=lambda u: (u["pkg"], u.get("part", -1)))}
              for i, (w, us) in enumerate(bins) if us]
    return {"budget": budget, "tree_packages": tree, "shards": shards}


def plan_findings(plan: dict) -> list[str]:
    """Перепись полноты плана: МНОЖЕСТВА, а не размеры."""
    out: list[str] = []
    tree = plan.get("tree_packages") or []
    if not tree:
        out.append("дерево плана ПУСТО — сверять раздачу не с чем")
    if not plan.get("shards"):
        out.append("ШАРДОВ НОЛЬ — раздавать некуда, и это отказ")
    whole: list[str] = []
    parts: dict[str, dict[int, int]] = {}
    declared_n: dict[str, set[int]] = {}
    for sh in plan.get("shards", []):
        for u in sh.get("units", []):
            if "part" in u:
                parts.setdefault(u["pkg"], {})
                parts[u["pkg"]][u["part"]] = parts[u["pkg"]].get(u["part"], 0) + 1
                declared_n.setdefault(u["pkg"], set()).add(u["parts"])
            else:
                whole.append(u["pkg"])
    handed = set(whole) | set(parts)
    lost = sorted(set(tree) - handed)
    alien = sorted(handed - set(tree))
    dup = sorted({p for p in whole if whole.count(p) > 1} | (set(whole) & set(parts)))
    if lost:
        out.append(f"ПАКЕТЫ ВЫПАЛИ ИЗ РАЗДАЧИ ({len(lost)}): {', '.join(lost[:8])} — их "
                   f"пробы не исполнятся, а «ноль упавших» про них не скажет ничего")
    if alien:
        out.append(f"В РАЗДАЧЕ ПАКЕТЫ НЕ ИЗ ДЕРЕВА ({len(alien)}): {', '.join(alien[:8])}")
    if dup:
        out.append(f"ПАКЕТ РОЗДАН ДВАЖДЫ ({len(dup)}): {', '.join(dup[:8])}")
    for pkg, got in sorted(parts.items()):
        ns = declared_n[pkg]
        if len(ns) != 1:
            out.append(f"{pkg}: части объявляют разное число частей {sorted(ns)}")
            continue
        n = next(iter(ns))
        if sorted(got) != list(range(n)) or any(c != 1 for c in got.values()):
            out.append(f"{pkg}: части {dict(sorted(got.items()))} при N={n} — каждая из "
                       f"0..{n - 1} обязана быть роздана ровно один раз")
    return out


def plan_census_text(plan: dict, weights: dict[str, int]) -> str:
    whole = sum(1 for sh in plan["shards"] for u in sh["units"] if "part" not in u)
    split = sorted({u["pkg"] for sh in plan["shards"] for u in sh["units"] if "part" in u})
    unweighed = [p for p in plan["tree_packages"] if p not in weights]
    lines = [
        "ПЕРЕПИСЬ ПЛАНА (единица — пакет `go list ./...`; часть — выборка проб "
        "верхнего уровня по sha256(имя) mod N)",
        f"  пакетов в дереве:      {len(plan['tree_packages'])}",
        f"  роздано целиком:       {whole}",
        f"  распилено по пробам:   {len(split)}",
        f"  шардов:                {len(plan['shards'])} (бюджет {plan['budget']} с веса)",
        f"  без замеренного веса:  {len(unweighed)} (вес по умолчанию {DEFAULT_WEIGHT})",
    ]
    for sh in plan["shards"]:
        desc = []
        for u in sh["units"]:
            if "part" in u:
                desc.append(f"{short(u['pkg'])}[{u['part'] + 1}/{u['parts']}]")
        n_whole = sum(1 for u in sh["units"] if "part" not in u)
        tail = (f"пакетов {n_whole}" if n_whole else "") + (" · " if n_whole and desc else "") \
            + " ".join(desc)
        lines.append(f"    {sh['id']}  вес {sh['weight']:5}  {tail}")
    return "\n".join(lines)


def short(pkg: str) -> str:
    return pkg.split("/kaname/", 1)[-1] if "/kaname/" in pkg else pkg


# ─── шард ───────────────────────────────────────────────────────────────────

def list_tests(pkg: str) -> list[str]:
    p = go(["test", *BUILD_FLAGS, "-list", ".", pkg])
    if p.returncode != 0:
        raise Unmeasured(f"`go test -list` для {pkg} вышел кодом {p.returncode}: "
                         f"{(p.stderr or p.stdout).strip()[-600:]}")
    names = sorted({x.strip() for x in p.stdout.splitlines() if TOP_NAME_RE.match(x.strip())})
    if not names:
        raise Unmeasured(f"`go test -list` для {pkg} не назвал ни одной пробы — резать "
                         f"нечего, а пустая часть дала бы зелёный из ничего")
    return names


def run_shard(plan: dict, shard_id: str, out_dir: Path, attempt: str) -> int:
    shard = next((s for s in plan.get("shards", []) if s["id"] == shard_id), None)
    if shard is None:
        sys.stderr.write(f"ОТКАЗ: шарда {shard_id} в плане нет; есть: "
                         f"{' '.join(s['id'] for s in plan.get('shards', []))}\n")
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)
    stream_path = out_dir / f"{shard_id}.a{attempt}.json"
    census_path = out_dir / f"{shard_id}.a{attempt}.census.json"
    census: dict = {"shard": shard_id, "attempt": attempt, "whole": [], "parts": [],
                    "go_test_rc": []}
    findings: list[str] = []
    not_done = False

    def go_test(args: list[str]) -> None:
        cmd = ["go", "test", *args]
        print("+ " + " ".join(a if len(a) < 160 else a[:150] + f"…({len(a)} симв.)" for a in cmd),
              flush=True)
        with stream_path.open("a", encoding="utf-8") as fh:
            rc = subprocess.run(cmd, cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT).returncode
        census["go_test_rc"].append(rc)
        print(f"  go test завершился с кодом {rc} (вердикт выносит прогонщик ниже)", flush=True)

    stream_path.write_text("", encoding="utf-8")
    whole = [u["pkg"] for u in shard["units"] if "part" not in u]
    census["whole"] = whole
    if whole:
        go_test([*BUILD_FLAGS, *RUN_FLAGS, "-json", *whole])
    for u in (u for u in shard["units"] if "part" in u):
        rec = {"pkg": u["pkg"], "part": u["part"], "parts": u["parts"]}
        try:
            names = list_tests(u["pkg"])
        except Unmeasured as e:
            findings.append(str(e))
            not_done = True
            census["parts"].append({**rec, "listed": [], "selected": [], "error": str(e)})
            continue
        chosen = select(names, u["part"], u["parts"])
        rec.update(listed=names, selected=chosen)
        census["parts"].append(rec)
        print(f"часть {u['part'] + 1}/{u['parts']} пакета {short(u['pkg'])}: проб в перечне "
              f"{len(names)}, в этой части {len(chosen)}", flush=True)
        if not chosen:
            # Пустая часть законна (мало проб, неровный хэш), но `-run` с пустой
            # альтернативой взял бы ВСЁ — поэтому пакет здесь не зовётся вовсе.
            continue
        go_test([*BUILD_FLAGS, *RUN_FLAGS, "-json", "-run", run_regex(chosen), u["pkg"]])
    census_path.write_text(json.dumps(census, ensure_ascii=False, indent=1) + "\n",
                           encoding="utf-8")

    with stream_path.open(encoding="utf-8") as fh:
        vrc = subprocess.run([sys.executable, str(VERDICT)], stdin=fh).returncode
    for f in findings:
        print(f"ОТКАЗ: {f}")
    if vrc == 1:
        return 1
    if not_done or vrc == 2:
        return 2
    return vrc


# ─── сводный вердикт ────────────────────────────────────────────────────────

def latest_reports(dirpath: Path) -> dict[str, tuple[Path, Path]]:
    """По каждому шарду — САМАЯ СВЕЖАЯ попытка: перезапущенный шард заливает
    опись с новым номером, а неперезапущенный оставляет законную прежнюю."""
    best: dict[str, tuple[int, Path, Path]] = {}
    for c in dirpath.rglob("*.census.json"):
        m = re.match(r"^(?P<id>[^.]+)\.a(?P<a>\d+)\.census\.json$", c.name)
        if not m:
            continue
        s = c.with_name(f"{m['id']}.a{m['a']}.json")
        a = int(m["a"])
        if m["id"] not in best or a > best[m["id"]][0]:
            best[m["id"]] = (a, c, s)
    return {k: (c, s) for k, (_, c, s) in best.items()}


def read_events(path: Path) -> list[dict]:
    out = []
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict):
            out.append(e)
    return out


def aggregate_findings(plan: dict, reports: dict[str, tuple[dict, list[dict]]]) -> tuple[list[str], dict]:
    """Находки свода по уже прочитанным отчётам — чистая функция (самопроба)."""
    out: list[str] = []
    planned = [s["id"] for s in plan.get("shards", [])]
    silent = sorted(set(planned) - set(reports))
    if silent:
        out.append(f"ШАРДЫ НЕ ОТЧИТАЛИСЬ ({len(silent)}): {', '.join(silent)} — их пакеты "
                   f"не судились, и молчание не есть зелёный")
    extra = sorted(set(reports) - set(planned))
    if extra:
        out.append(f"ОТЧЁТЫ ШАРДОВ НЕ ИЗ ПЛАНА: {', '.join(extra)}")

    seen_pkgs: dict[str, set[str]] = {}
    listed: dict[str, dict[int, list[str]]] = {}
    selected: dict[str, dict[int, list[str]]] = {}
    nparts: dict[str, int] = {}
    executed_by_part: dict[tuple[str, int], set[str]] = {}
    for sid, (census, events) in sorted(reports.items()):
        part_of_pkg = {p["pkg"]: p for p in census.get("parts", [])}
        for e in events:
            pkg = e.get("Package")
            if not pkg:
                continue
            if "Test" not in e and e.get("Action") in ("start", "skip", "pass", "fail"):
                seen_pkgs.setdefault(pkg, set()).add(sid)
            t = e.get("Test")
            if t and "/" not in t and e.get("Action") in ("pass", "fail", "skip") \
                    and pkg in part_of_pkg:
                executed_by_part.setdefault((pkg, part_of_pkg[pkg]["part"]), set()).add(t)
        for p in census.get("parts", []):
            listed.setdefault(p["pkg"], {})[p["part"]] = p.get("listed", [])
            selected.setdefault(p["pkg"], {})[p["part"]] = p.get("selected", [])
            nparts[p["pkg"]] = p["parts"]
            if p.get("error"):
                out.append(f"{p['pkg']} часть {p['part'] + 1}/{p['parts']}: {p['error']}")

    tree = set(plan.get("tree_packages", []))
    lost = sorted(tree - set(seen_pkgs))
    if lost and not silent:
        out.append(f"ПАКЕТЫ НЕ ОСМОТРЕНЫ НИ ОДНИМ ШАРДОМ ({len(lost)}): "
                   f"{', '.join(lost[:8])}")
    split = set(nparts)
    twice = sorted(p for p, sids in seen_pkgs.items() if len(sids) > 1 and p not in split)
    if twice:
        out.append(f"ПАКЕТ ОСМОТРЕН ДВАЖДЫ ({len(twice)}): {', '.join(twice[:8])}")
    alien = sorted(set(seen_pkgs) - tree)
    if alien:
        out.append(f"ОСМОТРЕНЫ ПАКЕТЫ НЕ ИЗ ДЕРЕВА ПЛАНА ({len(alien)}): {', '.join(alien[:8])}")

    for pkg in sorted(split):
        out.extend(partition_findings(pkg, nparts[pkg], listed[pkg], selected[pkg]))
        for k, chosen in selected[pkg].items():
            ran = executed_by_part.get((pkg, k), set())
            foreign = sorted(ran - set(chosen))
            if foreign:
                out.append(f"{pkg} часть {k + 1}/{nparts[pkg]}: исполнены пробы ВНЕ выборки "
                           f"({len(foreign)}): {', '.join(foreign[:8])}")
            unrun = sorted(n for n in set(chosen) - ran if not n.startswith("Benchmark"))
            if unrun:
                out.append(f"{pkg} часть {k + 1}/{nparts[pkg]}: выбранные пробы НЕ ИСПОЛНЕНЫ "
                           f"({len(unrun)}): {', '.join(unrun[:8])}")
    numbers = {"planned": len(planned), "reported": len(set(reports) & set(planned)),
               "tree": len(tree), "seen": len(set(seen_pkgs) & tree), "split": len(split)}
    return out, numbers


def aggregate(plan_path: Path, dirpath: Path, plan_result: str, shard_result: str) -> int:
    print(f"исход задания плана: {plan_result} · исход шардов: {shard_result}")
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"НЕ ВЫПОЛНИЛОСЬ: план не прочитан ({e}) — сводить не с чем")
        return 2
    reports: dict[str, tuple[dict, list[dict]]] = {}
    for sid, (c, s) in latest_reports(dirpath).items():
        try:
            reports[sid] = (json.loads(c.read_text(encoding="utf-8")), read_events(s))
        except (OSError, ValueError) as e:
            print(f"опись шарда {sid} не прочитана: {e}")
    findings, num = aggregate_findings(plan, reports)
    print("ПЕРЕПИСЬ СВОДА")
    print(f"  шардов в плане: {num['planned']} · отчиталось: {num['reported']}")
    print(f"  пакетов в дереве плана: {num['tree']} · осмотрено шардами: {num['seen']} · "
          f"распилено по пробам: {num['split']}")
    combined = dirpath / "unit-combined.json"
    latest = latest_reports(dirpath)
    with combined.open("w", encoding="utf-8") as fh:
        for sid in sorted(reports):
            fh.write(latest[sid][1].read_text(encoding="utf-8", errors="replace"))
    with combined.open(encoding="utf-8") as fh:
        vrc = subprocess.run([sys.executable, str(VERDICT)], stdin=fh,
                             capture_output=True, text=True)
    # Перепись прогонщика печатается целиком, но текст отказов уже напечатан
    # шардами — здесь он повторил бы журнал, и потому срезается до сводки.
    head = vrc.stdout.split("=== упавшие пробы", 1)
    # Итоговую строку прогонщика свод не повторяет: «ЗЕЛЁНЫЙ» о пробах рядом с
    # находками свода читался бы как вердикт всего задания. Исход прогонщика
    # назван кодом, вердикт задания — последней строкой ниже.
    body = [ln for ln in head[0].rstrip().splitlines()
            if not ln.startswith(("ЗЕЛЁНЫЙ:", "КРАСНЫЙ:", "НЕ ВЫПОЛНИЛОСЬ:"))]
    print("\n".join(body).rstrip())
    print(f"прогонщик по объединённому потоку шардов: код {vrc.returncode}")
    if len(head) > 1:
        tops = head[1].split("=== текст отказа", 1)[0]
        print("=== упавшие пробы" + tops.rstrip())
        print("(текст отказа — в журнале своего шарда)")
    bad_jobs = [r for r in (plan_result, shard_result) if r != "success"]
    if findings:
        print(f"НАХОДОК СВОДА: {len(findings)}")
        for f in findings:
            print("  · " + f)
    if vrc.returncode == 1 or findings:
        print("КРАСНЫЙ: свод юнитов.")
        return 1
    if bad_jobs or vrc.returncode == 2:
        print(f"НЕ ВЫПОЛНИЛОСЬ: задания плана/шардов дали {bad_jobs or '—'}, прогонщик — "
              f"код {vrc.returncode}. Это не зелёный вердикт.")
        return 2
    print("ЗЕЛЁНЫЙ: все шарды плана отчитались, роздано = дерево, отказов нет.")
    return 0


# ─── самопроба ──────────────────────────────────────────────────────────────

MOD = "github.com/PRO-Robotech/kaname"


def _case(name: str, expect_red: bool, findings: list[str], needle: str | None = None) -> bool:
    red = bool(findings)
    ok = red == expect_red and (needle is None or any(needle in f for f in findings))
    print(f"  [{'OK ' if ok else 'ОТКАЗ'}] {name}: находок {len(findings)} "
          f"(ждали {'красное' if expect_red else 'зелёное'})")
    if not ok:
        for f in findings:
            print("      · " + f[:220])
    return ok


def _ev(pkg: str, action: str, test: str | None = None) -> dict:
    e = {"Action": action, "Package": pkg}
    if test:
        e["Test"] = test
    return e


def self_test() -> int:
    print("самопроба раздачи и свода: инъекция в обе стороны по каждой оси")
    ok = True
    tree = [f"{MOD}/internal/check", f"{MOD}/internal/domain", f"{MOD}/deploy",
            f"{MOD}/cmd/kaname", f"{MOD}/pkg/api"]
    weights = {f"{MOD}/internal/check": 1000, f"{MOD}/internal/domain": 70,
               f"{MOD}/deploy": 300}
    plan = build_plan(tree, weights, 240)

    # Ось 1 — законная раскладка молчит; тяжёлый пакет распилен, лёгкие целиком.
    ok &= _case("контроль: законный план → зелено", False, plan_findings(plan))
    chk = [u for s in plan["shards"] for u in s["units"] if u["pkg"] == f"{MOD}/internal/check"]
    good = len(chk) == 5 and sorted(u["part"] for u in chk) == list(range(5))
    print(f"  [{'OK ' if good else 'ОТКАЗ'}] вес 1000 при бюджете 240 → 5 частей: "
          f"{sorted(u.get('part') for u in chk)}")
    ok &= good
    top = max(s["weight"] for s in plan["shards"])
    good = top <= 240
    print(f"  [{'OK ' if good else 'ОТКАЗ'}] самый загруженный шард {top} ≤ бюджета 240")
    ok &= good

    # Ось 2 — ПАКЕТ ВЫПАЛ из раздачи: класс, ради которого распил опасен.
    lost = json.loads(json.dumps(plan))
    for s in lost["shards"]:
        s["units"] = [u for u in s["units"] if u["pkg"] != f"{MOD}/pkg/api"]
    ok &= _case("пакет выпал из раздачи → красно", True, plan_findings(lost),
                "ВЫПАЛИ ИЗ РАЗДАЧИ")

    # Ось 3 — задвоение при совпавшем размере: потеря одного и повтор другого.
    dbl = json.loads(json.dumps(plan))
    for s in dbl["shards"]:
        s["units"] = [{"pkg": f"{MOD}/cmd/kaname"} if u["pkg"] == f"{MOD}/pkg/api" else u
                      for u in s["units"]]
    f = plan_findings(dbl)
    ok &= _case("потеря и задвоение при совпавшем размере → красно", True, f, "ДВАЖДЫ")
    ok &= _case("…и потеря названа отдельной находкой", True, f, "ВЫПАЛИ")

    # Ось 4 — часть пакета роздана дважды / не роздана.
    twice = json.loads(json.dumps(plan))
    twice["shards"][0]["units"].append({"pkg": f"{MOD}/internal/check", "part": 0, "parts": 5})
    ok &= _case("часть пакета роздана дважды → красно", True, plan_findings(twice), "ровно один")
    gone = json.loads(json.dumps(plan))
    for s in gone["shards"]:
        s["units"] = [u for u in s["units"]
                      if not (u["pkg"] == f"{MOD}/internal/check" and u.get("part") == 4)]
    ok &= _case("часть пакета не роздана → красно", True, plan_findings(gone), "ровно один")

    # Ось 5 — пустые входы — отказ, а не идеал.
    ok &= _case("ноль шардов → красно", True,
                plan_findings({"tree_packages": tree, "shards": []}), "ШАРДОВ НОЛЬ")
    ok &= _case("пустое дерево → красно", True,
                plan_findings({"tree_packages": [], "shards": plan["shards"]}), "ПУСТО")

    # Ось 6 — РАЗРЕЗ ПО ПРОБАМ: каждая проба ровно в одной части.
    names = [f"TestGate{i:03d}" for i in range(200)] + ["BenchmarkScan", "FuzzParse"]
    sel = {k: select(names, k, 5) for k in range(5)}
    lst = {k: list(names) for k in range(5)}
    ok &= _case("законный разрез → зелено", False,
                partition_findings("p", 5, lst, sel))
    spread = all(sel[k] for k in range(5))
    print(f"  [{'OK ' if spread else 'ОТКАЗ'}] хэш разносит 202 имени по всем частям: "
          f"{[len(sel[k]) for k in range(5)]}")
    ok &= spread
    det = select(names, 2, 5) == sel[2]
    print(f"  [{'OK ' if det else 'ОТКАЗ'}] разрез детерминирован: повторный расчёт той же "
          f"части совпал")
    ok &= det
    inj = {k: list(v) for k, v in sel.items()}
    inj[1] = inj[1] + [inj[0][0]]
    ok &= _case("проба в двух частях → красно", True,
                partition_findings("p", 5, lst, inj), "НЕСКОЛЬКИХ")
    inj = {k: list(v) for k, v in sel.items()}
    dropped = inj[3].pop()
    ok &= _case(f"проба ни в одной части ({dropped}) → красно", True,
                partition_findings("p", 5, lst, inj), "НИ В ОДНОЙ")
    inj = {k: list(v) for k, v in sel.items()}
    del inj[4]
    ok &= _case("часть не отчиталась → красно", True,
                partition_findings("p", 5, lst, inj), "нет отчёта частей")
    lst2 = {k: list(v) for k, v in lst.items()}
    lst2[2] = lst2[2][1:]
    ok &= _case("части перечислили разные наборы → красно", True,
                partition_findings("p", 5, lst2, sel), "РАЗНЫЕ")

    # Ось 7 — СВОД по отчётам: молчание шарда, потерянный пакет, проба вне выборки.
    small = build_plan([f"{MOD}/a", f"{MOD}/b", f"{MOD}/heavy"], {f"{MOD}/heavy": 500}, 240)
    hn = ["TestA", "TestB", "TestC", "TestD", "BenchmarkX"]
    reports: dict[str, tuple[dict, list[dict]]] = {}
    for s in small["shards"]:
        census: dict = {"shard": s["id"], "whole": [], "parts": []}
        evs: list[dict] = []
        for u in s["units"]:
            if "part" in u:
                ch = select(hn, u["part"], u["parts"])
                census["parts"].append({**u, "listed": hn, "selected": ch})
                evs.append(_ev(u["pkg"], "start"))
                evs += [_ev(u["pkg"], "pass", t) for t in ch if not t.startswith("Benchmark")]
                evs.append(_ev(u["pkg"], "pass"))
            else:
                census["whole"].append(u["pkg"])
                evs += [_ev(u["pkg"], "start"), _ev(u["pkg"], "pass", "TestX"),
                        _ev(u["pkg"], "pass")]
        reports[s["id"]] = (census, evs)
    f, num = aggregate_findings(small, reports)
    ok &= _case(f"свод: все шарды, роздано = дерево → зелено (шардов {num['planned']})",
                False, f)
    one = sorted(reports)[0]
    less = {k: v for k, v in reports.items() if k != one}
    ok &= _case("свод: шард не отчитался → красно", True,
                aggregate_findings(small, less)[0], "НЕ ОТЧИТАЛИСЬ")
    # пакет целиком молча не осмотрен: опись есть, событий о нём нет
    cut = json.loads(json.dumps(reports))
    for sid, (c, evs) in cut.items():
        if f"{MOD}/a" in c["whole"]:
            cut[sid] = (c, [e for e in evs if e["Package"] != f"{MOD}/a"])
    ok &= _case("свод: пакет без событий в потоке → красно", True,
                aggregate_findings(small, cut)[0], "НЕ ОСМОТРЕНЫ")
    # проба исполнена вне выборки своей части (сломанный `-run`)
    wide = json.loads(json.dumps(reports))
    for sid, (c, evs) in wide.items():
        for p in c["parts"]:
            if p["part"] == 0:
                evs.append(_ev(p["pkg"], "pass", next(n for n in hn if n not in p["selected"]
                                                      and not n.startswith("Benchmark"))))
    ok &= _case("свод: проба исполнена вне выборки → красно", True,
                aggregate_findings(small, wide)[0], "ВНЕ выборки")
    # выбранная проба не исполнена (а замер — законно не исполнен)
    miss = json.loads(json.dumps(reports))
    for sid, (c, evs) in miss.items():
        for p in c["parts"]:
            tests = [n for n in p["selected"] if not n.startswith("Benchmark")]
            if tests:
                miss[sid] = (c, [e for e in evs if e.get("Test") != tests[0]])
                break
    ok &= _case("свод: выбранная проба не исполнена → красно", True,
                aggregate_findings(small, miss)[0], "НЕ ИСПОЛНЕНЫ")
    has_bench = any("BenchmarkX" in p["selected"] for c, _ in reports.values()
                    for p in c["parts"])
    print(f"  [{'OK ' if has_bench else 'ОТКАЗ'}] близнец: замер в выборке без исполнения "
          f"не краснит свод (он в выборке: {has_bench}, свод контроля выше зелёный)")
    ok &= has_bench

    # Ось 8 — ведомость весов: строка о пакете вне дерева — находка, форма — тоже.
    w, bad = _weights_from_text("# шапка\n12 a/b\nx y\n5 a/b\n")
    good = len(bad) == 2 and w == {"a/b": 5}
    print(f"  [{'OK ' if good else 'ОТКАЗ'}] ведомость: кривая строка и повтор пакета — "
          f"находки ({len(bad)})")
    ok &= good
    stale = stale_weights({"a/b": 5, "gone/c": 7}, ["a/b"])
    good = stale == ["gone/c"]
    print(f"  [{'OK ' if good else 'ОТКАЗ'}] строка о пакете вне дерева — находка: {stale}")
    ok &= good

    print("самопроба:", "ПРОЙДЕНА" if ok else "ПРОВАЛЕНА")
    return 0 if ok else 1


def _weights_from_text(text: str) -> tuple[dict[str, int], list[str]]:
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "w.txt"
        p.write_text(text, encoding="utf-8")
        return read_weights(p)


def stale_weights(weights: dict[str, int], tree: list[str]) -> list[str]:
    return sorted(set(weights) - set(tree))


# ─── точка входа ────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="юниты -race матрицей шардов")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--plan", nargs="?", const="", default=None, metavar="PLAN",
                    help="без значения — построить план; со значением — путь к плану")
    ap.add_argument("--out", help="куда записать построенный план")
    ap.add_argument("--github-output", help="куда дописать `matrix=<json>`")
    ap.add_argument("--run", metavar="SHARD")
    ap.add_argument("--out-dir", default="unit-out")
    ap.add_argument("--attempt", default="1")
    ap.add_argument("--aggregate", action="store_true")
    ap.add_argument("--dir", default="unit-in")
    ap.add_argument("--plan-result", default="success")
    ap.add_argument("--shard-result", default="success")
    a = ap.parse_args()

    if a.self_test:
        return self_test()

    if a.run:
        plan = json.loads(Path(a.plan).read_text(encoding="utf-8"))
        return run_shard(plan, a.run, Path(a.out_dir), a.attempt)

    if a.aggregate:
        return aggregate(Path(a.plan), Path(a.dir), a.plan_result, a.shard_result)

    if a.plan == "":
        try:
            weights, bad = read_weights(WEIGHTS)
            tree = tree_packages()
        except Unmeasured as e:
            print(f"НЕ ВЫПОЛНИЛОСЬ: {e}")
            return 2
        stale = stale_weights(weights, tree)
        plan = build_plan(tree, weights, BUDGET)
        findings = plan_findings(plan) + bad + [
            f"{WEIGHTS.name}: строка о пакете, которого нет в дереве: {p} — запись пережила "
            f"предмет; снять её" for p in stale]
        print(plan_census_text(plan, weights))
        if a.out:
            Path(a.out).write_text(json.dumps(plan, ensure_ascii=False, indent=1) + "\n",
                                   encoding="utf-8")
            print(f"  план записан: {a.out}")
        if findings:
            print(f"НАХОДОК: {len(findings)}")
            for f in findings:
                print("  · " + f)
            return 1
        matrix = {"shard": [s["id"] for s in plan["shards"]]}
        if a.github_output:
            with open(a.github_output, "a", encoding="utf-8") as fh:
                fh.write("matrix=" + json.dumps(matrix) + "\n")
        print("роздано = дерево: ни одного пакета вне шардов, ни одного дважды, "
              "части распиленных — 0..N-1 ровно по разу")
        return 0

    ap.print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
