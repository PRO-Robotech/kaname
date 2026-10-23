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

КРИТЕРИЙ СТЕНЫ — ОТ СОЗДАНИЯ ПЕРВОГО ЗАДАНИЯ ЮНИТОВ ДО КОНЦА СВОДА
-----------------------------------------------------------------
Мерится `created_at` первого задания юнитов → `completed_at` задания `unit` одного
прогона (`gh api …/actions/runs/<id>/jobs`), и сравнивается с прежним
`created_at` → `completed_at` задания `unit` на ревизии-основании (28:05, прогон
39026914830). Исполнение шарда без ожидания исполнителя — НЕ стена: на первом
круге (PR kaname#875, прогон 39039147809) двенадцать шардов исполнялись
2:32…8:02, а ждали исполнителя 7:15…23:30, и стена вышла 33:44 против 28:05 при
«исполнении» 19:47. Вторая мера — минуты исполнителей (сумма длительностей
заданий): шардов не больше, чем окупает их ожидание.

ПЛАН СТРОИТ КАЖДЫЙ ШАРД, ОТДЕЛЬНОГО ЗАДАНИЯ ПЛАНА НЕТ
----------------------------------------------------
Второй круг (прогон 39082092467 @1c66d470d) шёл цепочкой «выбор затронутого →
задание плана → шарды → свод»: план исполнялся 17 с, а ЖДАЛ исполнителя 34:58, и
стена от его создания вышла 61:41 — каждое звено цепочки ждёт исполнителя заново,
а прежнее одно задание ждало один раз. План — чистая функция дерева и ведомости
весов, поэтому его строит каждый шард сам, и цепочка равна прежней: «выбор
затронутого → шарды → свод». Число шардов объявляет ОДНО место — матрица
процесса: шард строит план на её ширину (`strategy.job-total`) и берёт долю по
своему номеру (`strategy.job-index`), как контейнерные шарды. Свод сверяет, что
копии плана всех шардов СОВПАЛИ и что каждый шард плана отчитался.

Нижняя граница стены шарда — самая долгая НЕДЕЛИМАЯ проба: на первом круге
`internal/supplyhygiene` TestPlatformMintingClaimIsNotDeniedByThe… — 363 с из
459 с пакета. Разрез по пробам её не делит; её сокращение — предмет владельца
пакета, а не раскладки.

ДВЕ ЕДИНИЦЫ РАЗДАЧИ
-------------------
  * пакет целиком — всякий пакет `go list ./...`, включая пакеты без проб: так
    шарды осматривают РОВНО то же множество, что и прежний `go test ./...`;
  * часть пакета — пакет тяжелее порога (`PIECE_FRACTION` среднего шарда)
    режется на N = ⌈вес / порог⌉ частей. Проба верхнего уровня (имя из
    `go test -list`) попадает в часть `sha256(имя) mod N`. Это чистая функция
    имени: части вычисляются независимо в разных заданиях и сходятся без обмена.
    Вес части — крупные пробы ведомости, попавшие в неё, плюс остаток поровну.
    Части одного пакета в одном шарде идут ОДНИМ `go test`, вызовы шарда —
    одновременно, как пакеты внутри `go test ./...`.

ЕДИНИЦА СЧЁТА СВОДА — ПАКЕТ: у распиленного пакета в объединённом потоке один
исход (`fail`, если упала хоть одна часть), поэтому «пакетов осмотрено» равно
`go list ./...`, как у прежнего прогона.

ПОЧЕМУ ВЕСА — ВЕДОМОСТЬ, И ПОЧЕМУ ЭТО БЕЗОПАСНО
-----------------------------------------------
Веса (`.github/unit-shard-weights.txt`) решают ТОЛЬКО раскладку: число частей
пакета и соседство в шарде. Полноту они не решают — пакет без строки
раздаётся с весом по умолчанию и строкой «вес не замерен», а строка о пакете,
которого нет в дереве, — находка (запись, пережившая предмет). Ошибись вес
вдвое — изменится стена, а не покрытие.

ПОЛНОТА — ЧИСЛАМИ, В ТРЁХ МЕСТАХ
--------------------------------
  1. план (в каждом шарде до прогона; `--plan` — только он): множество розданных
     пакетов СОВПАДАЕТ с `go list ./...`, ни одного дважды, части каждого
     распиленного пакета — 0..N-1 ровно по разу;
  2. шард (`--run`): у каждой части — перечень проб пакета и её выборка; выборка
     сверяется с функцией разреза тут же, до прогона;
  3. свод (`--aggregate`): копии плана шардов совпали; все шарды плана
     отчитались; пакеты, ВИДЕННЫЕ в потоках `go test -json`, совпадают с
     деревом плана; у распиленного пакета перечни
     всех частей равны, выборки не пересекаются и в объединении дают перечень;
     исполненные пробы части лежат в её выборке, а невыполненные — только
     замеры (`Benchmark*`, без `-bench` их не исполняет и прежний прогон).
Сверяются МНОЖЕСТВА, а не размеры: потеря плюс задвоение дают тот же размер.

ИСХОДЫ: 0 — зелено · 1 — находка либо красная проба · 2 — не выполнилось
(обход пуст, `go list` не отработал, отчёта нет). Ноль осмотренного — не зелёный.

Запуск:
  python3 .github/scripts/unit-shards.py --self-test
  python3 .github/scripts/unit-shards.py --plan --job-total 5 [--out unit-plan.json]
  python3 .github/scripts/unit-shards.py --run --job-index 0 --job-total 5 --out-dir unit-out --attempt 1
  python3 .github/scripts/unit-shards.py --aggregate --dir unit-in --shard-result success
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

# ЧИСЛА ШАРДОВ ЗДЕСЬ НЕТ: его объявляет ОДНО место — матрица задания `unitshard`
# в ci.yml (там же замер, которым выбрано пять), и шард строит план на ширину
# матрицы (`--job-total` = `strategy.job-total`), как контейнерные шарды
# (`run-integration.sh`). Второе объявление разошлось бы с первым молча.
#
# Доля среднего шарда, больше которой пакет режется на части. Мелкие части
# усредняют неровность хэша: на первом круге две части `supplyhygiene` по
# хэшу имён дали 385 и 68 с — делёж по числу проб не делит время.
PIECE_FRACTION = 0.25
# Вес пакета без строки в ведомости. Он решает только раскладку (см. шапку).
DEFAULT_WEIGHT = 10

# Флаги прогона — ОДНО объявление: перечень частей (`-list`) и прогон обязаны
# собираться одинаково, иначе `-list` перечислил бы пробы другой сборки
# (`internal/check` несёт файл под `//go:build race`).
#
# `-timeout 45m` — запас к самому долгому пакету (kaname#949): `internal/check` на
# d34eab3f7 одним `go test ./... -race -short` — 1723,754 с, код 0 (внешний кластер,
# 4 CPU); при 25m тот же пакет снят паникой на 1501 с. 45m — 2700 с: доля пакета
# 64 %, запас 57 %. Часть распиленного пакета не дольше пакета, поэтому тот же
# предел держит и её. Предел растёт вслед за пакетом, а не вместо его ускорения:
# доля выше 75 % — предмет задачи, а не новое число. Предел задания шарда
# (`timeout-minutes` у `unitshard` в ci.yml) — этот плюс подготовка.
BUILD_FLAGS = ["-race"]
RUN_FLAGS = ["-short", "-count=1", "-timeout", "45m"]

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
    """Ведомость: «<секунды> <пакет>» — вес пакета; «<секунды> <пакет> <Проба>» —
    вес КРУПНОЙ пробы верхнего уровня. Крупная проба неделима: на первом круге
    одна проба `supplyhygiene` шла 363 с из 459 с пакета, и делёж пакета поровну
    по числу проб ставил её часть рядом с чужой нагрузкой. Ключ пробы в словаре —
    «<пакет> <Проба>»."""
    weights: dict[str, int] = {}
    bad: list[str] = []
    if not path.is_file():
        raise Unmeasured(f"ведомость весов {path} не прочитана — раскладывать не из чего")
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        f = s.split()
        if len(f) not in (2, 3) or not f[0].isdigit() or (
                len(f) == 3 and not TOP_NAME_RE.match(f[2])):
            bad.append(f"{path.name}:{i}: строка не в форме «<секунды> <пакет> [<Проба>]»: "
                       f"{s[:120]}")
            continue
        key = " ".join(f[1:])
        if key in weights:
            bad.append(f"{path.name}:{i}: {key} назван дважды")
        weights[key] = int(f[0])
    return weights, bad


def build_plan(tree: list[str], weights: dict[str, int], shards_n: int,
               fraction: float = PIECE_FRACTION) -> dict:
    """Раскладка ровно на `shards_n` шардов: пакет тяжелее доли среднего шарда
    режется на части, затем LPT — самая тяжёлая единица в наименее загруженный
    шард. Части одного пакета в одном шарде гоняются ОДНИМ `go test`."""
    units: list[tuple[int, dict]] = []
    total_w = sum(weights.get(p, DEFAULT_WEIGHT) for p in tree)
    budget = max(1, math.ceil(total_w / max(1, shards_n) * fraction))
    for pkg in tree:
        w = weights.get(pkg, DEFAULT_WEIGHT)
        parts = max(1, math.ceil(w / budget))
        if parts == 1:
            units.append((w, {"pkg": pkg}))
            continue
        # Вес части — крупные пробы, которые в неё попадают тем же разрезом, плюс
        # поровну остаток пакета. Разрез — по имени, поэтому оценка части
        # вычисляется без перечня проб и без сборки.
        big = {k.split(" ", 1)[1]: v for k, v in weights.items()
               if k.startswith(pkg + " ")}
        rest = max(0, w - sum(big.values())) / parts
        for k in range(parts):
            pw = rest + sum(v for n, v in big.items() if part_of(n, parts) == k)
            units.append((math.ceil(pw), {"pkg": pkg, "part": k, "parts": parts}))
    units.sort(key=lambda u: (-u[0], u[1]["pkg"], u[1].get("part", -1)))
    n = max(1, min(shards_n, len(units)))
    bins: list[list] = [[0, []] for _ in range(n)]
    for w, u in units:
        b = min(bins, key=lambda x: x[0])
        b[0] += w
        b[1].append(u)
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
        f"  шардов:                {len(plan['shards'])} (порог разреза {plan['budget']} с веса)",
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


def make_plan(shards_n: int) -> tuple[dict, list[str], str]:
    """План из дерева и ведомости — ОДНА функция у `--plan` и у каждого шарда:
    шарды строят его независимо, и сойтись копии могут, только если путь один.
    Не измерено (ведомость не прочитана, `go list` не отработал) — Unmeasured."""
    weights, bad = read_weights(WEIGHTS)
    tree = tree_packages()
    plan = build_plan(tree, weights, shards_n)
    findings = plan_findings(plan) + bad + [
        f"{WEIGHTS.name}: строка о пакете, которого нет в дереве: {p} — запись пережила "
        f"предмет; снять её" for p in stale_weights(weights, tree)]
    return plan, findings, plan_census_text(plan, weights)


def shard_of_index(plan: dict, index: int) -> str | None:
    """Номер задания матрицы (`strategy.job-index`, с нуля) → шард плана. План
    построен на ширину матрицы, поэтому номера и шарды взаимно однозначны; номер
    вне плана — не шард, и шард тогда не исполняет ничего."""
    shards = plan.get("shards", [])
    return shards[index]["id"] if 0 <= index < len(shards) else None


def agreed_plan(copies: dict[str, dict | None]) -> tuple[dict | None, list[str]]:
    """Копии плана, построенные шардами независимо, обязаны СОВПАСТЬ: свод судит
    по одному плану, и разошедшаяся копия значит, что шарды раздавали разное.
    `None` у шарда — опись есть, копии плана нет. Копий ноль — плана нет вовсе
    (`None`, без находок): это «не выполнилось», и решает его вызывающий."""
    out: list[str] = []
    missing = sorted(sid for sid, p in copies.items() if p is None)
    if missing:
        out.append(f"ШАРДЫ ОТЧИТАЛИСЬ без копии плана ({len(missing)}): {', '.join(missing)} "
                   f"— по какому плану они раздавали, не сверить")
    groups: dict[str, list[str]] = {}
    for sid, p in sorted(copies.items()):
        if p is not None:
            groups.setdefault(json.dumps(p, sort_keys=True, ensure_ascii=False), []).append(sid)
    if not groups:
        return None, out
    if len(groups) > 1:
        out.append(f"КОПИИ ПЛАНА ШАРДОВ РАЗОШЛИСЬ ({len(groups)} варианта): "
                   + " · ".join(", ".join(v) for v in groups.values())
                   + " — шарды раздавали разные деревья, свод судил бы одно из них")
    # Судит свод по копии большинства (при равенстве — по копии первого шарда):
    # при расхождении вердикт красный и без того, а перепись должна прочитаться.
    best = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[1][0]))[0]
    return json.loads(best[0]), out


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
    """Пакеты шарда — одним `go test`, каждый распиленный пакет — своим, с
    выборкой, равной объединению его частей в этом шарде. Вызовы идут
    ОДНОВРЕМЕННО, как пакеты внутри одного `go test ./...`: последовательные
    вызовы складывали бы время там, где прежний прогон его перекрывал."""
    shard = next((s for s in plan.get("shards", []) if s["id"] == shard_id), None)
    if shard is None:
        sys.stderr.write(f"ОТКАЗ: шарда {shard_id} в плане нет; есть: "
                         f"{' '.join(s['id'] for s in plan.get('shards', []))}\n")
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)
    stream_path = out_dir / f"{shard_id}.a{attempt}.json"
    census_path = out_dir / f"{shard_id}.a{attempt}.census.json"
    # Копия плана, по которому шард раздавал: свод сверяет копии всех шардов.
    (out_dir / f"{shard_id}.a{attempt}.plan.json").write_text(
        json.dumps(plan, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    census: dict = {"shard": shard_id, "attempt": attempt, "whole": [], "parts": [],
                    "go_test_rc": []}
    findings: list[str] = []
    not_done = False

    calls: list[list[str]] = []
    whole = [u["pkg"] for u in shard["units"] if "part" not in u]
    census["whole"] = whole
    if whole:
        calls.append([*BUILD_FLAGS, *RUN_FLAGS, "-json", *whole])
    split: dict[str, list[dict]] = {}
    for u in (u for u in shard["units"] if "part" in u):
        split.setdefault(u["pkg"], []).append(u)
    for pkg, us in sorted(split.items()):
        try:
            names = list_tests(pkg)
        except Unmeasured as e:
            findings.append(str(e))
            not_done = True
            for u in us:
                census["parts"].append({"pkg": pkg, "part": u["part"], "parts": u["parts"],
                                        "listed": [], "selected": [], "error": str(e)})
            continue
        chosen: list[str] = []
        for u in us:
            sel = select(names, u["part"], u["parts"])
            chosen += sel
            census["parts"].append({"pkg": pkg, "part": u["part"], "parts": u["parts"],
                                    "listed": names, "selected": sel})
        print(f"пакет {short(pkg)}: проб в перечне {len(names)}, части "
              f"{[u['part'] + 1 for u in us]} из {us[0]['parts']} — в этом шарде {len(chosen)}",
              flush=True)
        if chosen:
            # Пустая выборка законна (мало проб, неровный хэш), но `-run` с пустой
            # альтернативой взял бы ВСЁ — поэтому пакет тогда не зовётся вовсе.
            calls.append([*BUILD_FLAGS, *RUN_FLAGS, "-json", "-run", run_regex(sorted(chosen)), pkg])

    procs = []
    for i, args in enumerate(calls):
        part_path = out_dir / f".{shard_id}.a{attempt}.{i}.part"
        cmd = ["go", "test", *args]
        print("+ " + " ".join(x if len(x) < 160 else x[:150] + f"…({len(x)} симв.)" for x in cmd),
              flush=True)
        fh = part_path.open("w", encoding="utf-8")
        procs.append((subprocess.Popen(cmd, cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT),
                      fh, part_path))
    with stream_path.open("w", encoding="utf-8") as out:
        for proc, fh, part_path in procs:
            rc = proc.wait()
            fh.close()
            census["go_test_rc"].append(rc)
            print(f"  go test #{len(census['go_test_rc'])} завершился с кодом {rc} "
                  f"(вердикт выносит прогонщик ниже)", flush=True)
            out.write(part_path.read_text(encoding="utf-8", errors="replace"))
            part_path.unlink()
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

def latest_reports(dirpath: Path) -> dict[str, tuple[Path, Path, Path]]:
    """По каждому шарду — САМАЯ СВЕЖАЯ попытка: перезапущенный шард заливает
    опись с новым номером, а неперезапущенный оставляет законную прежнюю.
    Тройка путей — опись, поток `go test -json` и копия плана той же попытки."""
    best: dict[str, tuple[int, Path, Path, Path]] = {}
    for c in dirpath.rglob("*.census.json"):
        m = re.match(r"^(?P<id>[^.]+)\.a(?P<a>\d+)\.census\.json$", c.name)
        if not m:
            continue
        s = c.with_name(f"{m['id']}.a{m['a']}.json")
        p = c.with_name(f"{m['id']}.a{m['a']}.plan.json")
        a = int(m["a"])
        if m["id"] not in best or a > best[m["id"]][0]:
            best[m["id"]] = (a, c, s, p)
    return {k: (c, s, p) for k, (_, c, s, p) in best.items()}


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
        # Части одного пакета в шарде идут ОДНИМ `go test`, поэтому исполненная
        # проба относится к части тем же разрезом, которым выбиралась.
        own_parts: dict[str, tuple[int, set[int]]] = {}
        for p in census.get("parts", []):
            n, ks = own_parts.get(p["pkg"], (p["parts"], set()))
            ks.add(p["part"])
            own_parts[p["pkg"]] = (n, ks)
        for e in events:
            pkg = e.get("Package")
            if not pkg:
                continue
            if "Test" not in e and e.get("Action") in ("start", "skip", "pass", "fail"):
                seen_pkgs.setdefault(pkg, set()).add(sid)
            t = e.get("Test")
            if t and "/" not in t and e.get("Action") in ("pass", "fail", "skip") \
                    and pkg in own_parts:
                n, ks = own_parts[pkg]
                k = part_of(t, n)
                if k in ks:
                    executed_by_part.setdefault((pkg, k), set()).add(t)
                else:
                    out.append(f"{pkg}: шард {sid} исполнил {t} — пробу части {k + 1}/{n}, "
                               f"которой ему не раздавали")
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


def combined_events(reports: dict[str, tuple[dict, list[dict]]]) -> list[dict]:
    """Объединённый поток для прогонщика — ЕДИНИЦА СЧЁТА ПАКЕТ, а не вызов.

    Распиленный пакет исполняется в нескольких шардах, и каждый вызов шлёт свои
    события начала и исхода пакета: прогонщик насчитал бы его столько раз,
    сколько шардов его гоняли (первый круг: «прошло 148 · без проб 43» при 186
    пакетах). Здесь у распиленного пакета остаётся ОДНО начало и ОДИН исход —
    `fail`, если упала хоть одна часть (с её `FailedBuild`), иначе `pass`;
    события проб и вывод не трогаются."""
    split = {p["pkg"] for c, _ in reports.values() for p in c.get("parts", [])}
    out: list[dict] = []
    ends: dict[str, list[dict]] = {}
    for sid in sorted(reports):
        for e in reports[sid][1]:
            pkg = e.get("Package")
            if pkg in split and "Test" not in e and e.get("Action") in (
                    "start", "pass", "fail", "skip"):
                if e.get("Action") != "start":
                    ends.setdefault(pkg, []).append(e)
                continue
            out.append(e)
    for pkg in sorted(split):
        out.append({"Action": "start", "Package": pkg})
        got = ends.get(pkg, [])
        if not got:
            continue  # исхода нет — прогонщик назовёт пакет начатым и не завершённым
        failed = [e for e in got if e.get("Action") == "fail"]
        end = dict(failed[0]) if failed else {
            "Action": "pass" if any(e.get("Action") == "pass" for e in got) else "skip",
            "Package": pkg}
        end["Elapsed"] = max((e.get("Elapsed") or 0) for e in got)
        out.append(end)
    return out


def aggregate(dirpath: Path, shard_result: str) -> int:
    print(f"исход шардов: {shard_result}")
    reports: dict[str, tuple[dict, list[dict]]] = {}
    copies: dict[str, dict | None] = {}
    for sid, (c, s, p) in latest_reports(dirpath).items():
        try:
            reports[sid] = (json.loads(c.read_text(encoding="utf-8")), read_events(s))
        except (OSError, ValueError) as e:
            print(f"опись шарда {sid} не прочитана: {e}")
            continue
        try:
            copies[sid] = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            print(f"копия плана шарда {sid} не прочитана: {e}")
            copies[sid] = None
    plan, plan_bad = agreed_plan(copies)
    if plan is None:
        for f in plan_bad:
            print("  · " + f)
        if plan_bad:
            print("КРАСНЫЙ: свод юнитов — шарды отчитались без плана.")
            return 1
        print(f"НЕ ВЫПОЛНИЛОСЬ: в {dirpath} ни одной описи шарда с копией плана — сводить "
              f"не с чем (исход шардов: {shard_result})")
        return 2
    findings, num = aggregate_findings(plan, reports)
    findings = plan_bad + findings
    print("ПЕРЕПИСЬ СВОДА")
    print(f"  копий плана: {sum(1 for v in copies.values() if v is not None)} · "
          f"разошлось: {'да' if plan_bad else 'нет'}")
    print(f"  шардов в плане: {num['planned']} · отчиталось: {num['reported']}")
    print(f"  пакетов в дереве плана: {num['tree']} · осмотрено шардами: {num['seen']} · "
          f"распилено по пробам: {num['split']}")
    combined = dirpath / "unit-combined.json"
    with combined.open("w", encoding="utf-8") as fh:
        for e in combined_events(reports):
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")
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
    if findings:
        print(f"НАХОДОК СВОДА: {len(findings)}")
        for f in findings:
            print("  · " + f)
    if vrc.returncode == 1 or findings:
        print("КРАСНЫЙ: свод юнитов.")
        return 1
    if shard_result != "success" or vrc.returncode == 2:
        print(f"НЕ ВЫПОЛНИЛОСЬ: задания шардов дали {shard_result}, прогонщик — "
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
    plan = build_plan(tree, weights, 3)

    # Ось 1 — законная раскладка молчит; тяжёлый пакет распилен, лёгкие целиком.
    ok &= _case("контроль: законный план → зелено", False, plan_findings(plan))
    chk = [u for s in plan["shards"] for u in s["units"] if u["pkg"] == f"{MOD}/internal/check"]
    want = math.ceil(1000 / plan["budget"])
    good = len(chk) == want and sorted(u["part"] for u in chk) == list(range(want))
    print(f"  [{'OK ' if good else 'ОТКАЗ'}] вес 1000 при пороге {plan['budget']} → {want} "
          f"частей: {len(chk)}")
    ok &= good
    good = len(plan["shards"]) == 3
    print(f"  [{'OK ' if good else 'ОТКАЗ'}] шардов ровно столько, сколько задано: "
          f"{len(plan['shards'])} из 3")
    ok &= good
    ws = [s["weight"] for s in plan["shards"]]
    good = max(ws) - min(ws) <= plan["budget"]
    print(f"  [{'OK ' if good else 'ОТКАЗ'}] разброс загрузки {max(ws) - min(ws)} ≤ порога "
          f"разреза {plan['budget']}: {ws}")
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
    twice["shards"][0]["units"].append({"pkg": f"{MOD}/internal/check", "part": 0,
                                        "parts": want})
    ok &= _case("часть пакета роздана дважды → красно", True, plan_findings(twice), "ровно один")
    gone = json.loads(json.dumps(plan))
    for s in gone["shards"]:
        s["units"] = [u for u in s["units"]
                      if not (u["pkg"] == f"{MOD}/internal/check" and u.get("part") == 1)]
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
    small = build_plan([f"{MOD}/a", f"{MOD}/b", f"{MOD}/heavy"], {f"{MOD}/heavy": 500}, 2)
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
    # проба чужой части исполнена шардом (сломанный `-run`)
    wide = json.loads(json.dumps(reports))
    injected = False
    for sid, (c, evs) in wide.items():
        owned = {p["part"] for p in c["parts"]}
        n = c["parts"][0]["parts"] if c["parts"] else 0
        stray = [t for t in hn if n and not t.startswith("Benchmark")
                 and part_of(t, n) not in owned]
        if stray:
            evs.append(_ev(c["parts"][0]["pkg"], "pass", stray[0]))
            injected = True
            break
    ok &= _case(f"свод: исполнена проба чужой части → красно (инъекция поставлена: "
                f"{injected})", True, aggregate_findings(small, wide)[0], "не раздавали")
    # выборка части подменена: исполненное не лежит в объявленной выборке
    tamper = json.loads(json.dumps(reports))
    for sid, (c, evs) in tamper.items():
        p0 = next((p for p in c["parts"]
                   if any(not n.startswith("Benchmark") for n in p["selected"])), None)
        if p0:
            p0["selected"] = [n for n in p0["selected"] if n.startswith("Benchmark")]
            break
    ok &= _case("свод: выборка части не совпала с исполненным → красно", True,
                aggregate_findings(small, tamper)[0], "ВНЕ выборки")
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
    # Единица счёта свода — ПАКЕТ: распиленный пакет, исполненный несколькими
    # шардами, даёт в объединённом потоке ровно один исход.
    comb = combined_events(reports)
    ends = [e["Package"] for e in comb if "Test" not in e
            and e["Action"] in ("pass", "fail", "skip")]
    heavy_runs = sum(1 for c, _ in reports.values()
                     if any(p["pkg"] == f"{MOD}/heavy" for p in c["parts"]))
    good = sorted(ends) == sorted(small["tree_packages"]) and heavy_runs > 1
    print(f"  [{'OK ' if good else 'ОТКАЗ'}] объединённый поток: исходов пакетов {len(ends)} "
          f"при дереве {len(small['tree_packages'])} (распиленный гонялся шардами: "
          f"{heavy_runs})")
    ok &= good
    failed = json.loads(json.dumps(reports))
    for sid, (c, evs) in failed.items():
        if any(p["pkg"] == f"{MOD}/heavy" for p in c["parts"]):
            for e in evs:
                if e.get("Package") == f"{MOD}/heavy" and "Test" not in e \
                        and e["Action"] == "pass":
                    e["Action"] = "fail"
            break
    fe = [e for e in combined_events(failed) if e.get("Package") == f"{MOD}/heavy"
          and "Test" not in e and e["Action"] in ("pass", "fail")]
    good = [e["Action"] for e in fe] == ["fail"]
    print(f"  [{'OK ' if good else 'ОТКАЗ'}] упала одна часть — исход пакета в своде «fail»: "
          f"{[e['Action'] for e in fe]}")
    ok &= good
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

    # Ось 9 — КРУПНАЯ ПРОБА неделима: её вес достаётся ровно той части, куда
    # её кладёт разрез, а не делится поровну.
    bp = build_plan([f"{MOD}/x", f"{MOD}/y"],
                    {f"{MOD}/x": 1000, f"{MOD}/x TestBig": 600, f"{MOD}/y": 200}, 2)
    xs = [(s["weight"], u) for s in bp["shards"] for u in s["units"]
          if u["pkg"] == f"{MOD}/x"]
    n = xs[0][1]["parts"] if xs and "parts" in xs[0][1] else 1
    big_shard = next(s for s in bp["shards"] for u in s["units"]
                     if u["pkg"] == f"{MOD}/x" and u.get("part") == part_of("TestBig", n))
    others = [s["weight"] for s in bp["shards"] if s is not big_shard]
    good = n > 1 and big_shard["weight"] >= 600 and all(w < big_shard["weight"] for w in others)
    print(f"  [{'OK ' if good else 'ОТКАЗ'}] крупная проба (600 из 1000) лежит в своей части: "
          f"шард с ней {big_shard['weight']}, прочие {others}, частей {n}")
    ok &= good
    stale = stale_weights({f"{MOD}/x TestBig": 5, f"{MOD}/gone TestOld": 3}, [f"{MOD}/x"])
    good = stale == [f"{MOD}/gone TestOld"]
    print(f"  [{'OK ' if good else 'ОТКАЗ'}] строка пробы о пакете вне дерева — находка: {stale}")
    ok &= good

    # Ось 10 — ПЛАН СТРОИТ КАЖДЫЙ ШАРД: матрица объявлена процессом, а не выдана
    # отдельным заданием плана. Копии плана обязаны совпасть, а пропавшая копия —
    # не прочитаться зелёной.
    copies: dict[str, dict | None] = {s["id"]: json.loads(json.dumps(small))
                                      for s in small["shards"]}
    agreed, f = agreed_plan(copies)
    ok &= _case(f"копии плана {len(copies)} шардов совпали → зелено", False, f)
    good = agreed == small
    print(f"  [{'OK ' if good else 'ОТКАЗ'}] свод судит по согласованному плану: {good}")
    ok &= good
    first = sorted(copies)[0]
    drift = json.loads(json.dumps(copies))
    drift[first]["tree_packages"] = drift[first]["tree_packages"][1:]
    ok &= _case("копия плана одного шарда разошлась → красно", True,
                agreed_plan(drift)[1], "РАЗОШЛИСЬ")
    lost_copy = dict(copies)
    lost_copy[first] = None
    ok &= _case("шард отчитался без копии плана → красно", True,
                agreed_plan(lost_copy)[1], "без копии плана")
    nothing, f = agreed_plan({})
    good = nothing is None and not f
    print(f"  [{'OK ' if good else 'ОТКАЗ'}] ни одной копии плана — плана нет "
          f"(«не выполнилось»), а не пустой зелёный: {nothing is None}")
    ok &= good
    # Номер задания матрицы → шард плана: каждый номер 0..N-1 — ровно один шард,
    # номер вне плана — не шард (вызывающий отказывает «не выполнилось»).
    width = len(small["shards"])
    ids = [shard_of_index(small, i) for i in range(width)]
    good = ids == [s["id"] for s in small["shards"]] and len(set(ids)) == width
    print(f"  [{'OK ' if good else 'ОТКАЗ'}] номера матрицы 0..{width - 1} → шарды плана "
          f"без повторов: {ids}")
    ok &= good
    good = shard_of_index(small, width) is None and shard_of_index(small, -1) is None
    print(f"  [{'OK ' if good else 'ОТКАЗ'}] номер вне плана ({width}, -1) шардом не назван")
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
    return sorted(k for k in weights if k.split(" ", 1)[0] not in set(tree))


# ─── точка входа ────────────────────────────────────────────────────────────

def _count(raw: str | None, what: str, low: int) -> int | None:
    """Число из матрицы процесса либо None: не число — сверять не с чем."""
    s = (raw or "").strip()
    if not s.isdigit() or int(s) < low:
        print(f"НЕ ВЫПОЛНИЛОСЬ: {what} не названа числом ≥ {low} («{s}»)")
        return None
    return int(s)


def main() -> int:
    ap = argparse.ArgumentParser(description="юниты -race матрицей шардов")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--plan", action="store_true", help="построить план и перепись — только их")
    ap.add_argument("--out", help="куда записать построенный план")
    ap.add_argument("--run", action="store_true", help="план, перепись и доля шарда")
    ap.add_argument("--job-total", help="ширина матрицы процесса (`strategy.job-total`)")
    ap.add_argument("--job-index", help="номер задания матрицы с нуля (`strategy.job-index`)")
    ap.add_argument("--out-dir", default="unit-out")
    ap.add_argument("--attempt", default="1")
    ap.add_argument("--aggregate", action="store_true")
    ap.add_argument("--dir", default="unit-in")
    ap.add_argument("--shard-result", default="success")
    a = ap.parse_args()

    if a.self_test:
        return self_test()

    if a.aggregate:
        return aggregate(Path(a.dir), a.shard_result)

    if not (a.plan or a.run):
        ap.print_usage(sys.stderr)
        return 2
    total = _count(a.job_total, "ширина матрицы (--job-total)", 1)
    if total is None:
        return 2
    index = _count(a.job_index, "номер задания матрицы (--job-index)", 0) if a.run else 0
    if index is None:
        return 2

    # ПЕРЕПИСЬ ПОЛНОТЫ — ДО ПРОГОНА: шард, раздающий не дерево, не исполняет ничего.
    try:
        plan, findings, census = make_plan(total)
    except Unmeasured as e:
        print(f"НЕ ВЫПОЛНИЛОСЬ: {e}")
        return 2
    print(census)
    if a.out:
        Path(a.out).write_text(json.dumps(plan, ensure_ascii=False, indent=1) + "\n",
                               encoding="utf-8")
        print(f"  план записан: {a.out}")
    if findings:
        print(f"НАХОДОК ПЛАНА: {len(findings)}")
        for f in findings:
            print("  · " + f)
        return 1
    print("роздано = дерево: ни одного пакета вне шардов, ни одного дважды, "
          "части распиленных — 0..N-1 ровно по разу")
    if not a.run:
        return 0
    shard_id = shard_of_index(plan, index)
    if shard_id is None:
        print(f"НЕ ВЫПОЛНИЛОСЬ: задание матрицы №{index} из {total} — шарда с таким номером "
              f"в плане нет (шардов {len(plan['shards'])})")
        return 2
    print(f"задание матрицы №{index} из {total} → шард {shard_id}")
    return run_shard(plan, shard_id, Path(a.out_dir), a.attempt)


if __name__ == "__main__":
    sys.exit(main())
