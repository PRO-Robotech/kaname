#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Выбор затронутого: какие задания конвейера судят изменённые пути — и прогон их локально.

ПРЕДМЕТ (kaname#707; тот же механизм в kacho — kacho#3148)
---------------------------------------------------------
Решение владельца 2026-10-11: «Что бы на мелкую правку не генерить весь ci мы же можем
изолированно проверить только то что нужно а глобальный прогон делать тогда, когда надо
начать все собирать воедино».

На каждый запрос уходил весь набор: 4 процесса, 18 заданий, около 155 минут раннеров,
`chart-own` около 54 минут — и на правку одного newman-кейса тоже. Этот скрипт отвечает на один
вопрос: какие задания судят пути, изменённые относительно базы.

ОДИН ИСТОЧНИК ПРАВДЫ
--------------------
Карта «пути → задание» — `.github/ci-paths.json`. Её читают ТРИ потребителя, и второй
копии нет ни у одного:

* задание-детектор каждого процесса (`--github-output <процесс>`): на черновике запроса в
  ветку эпика исполняются только выбранные задания (`if:` по его выходу);
* сводный вердикт запроса (`--pr-aggregate`, задание `prverdict` процессов `ci.yml` и
  `e2e-newman.yml`): на черновике красный по построению «целевой прогон: N заданий из M»,
  на полном прогоне — зелёный, только если КАЖДОЕ задание процесса завершилось успехом
  (`skipped` на полном прогоне — красное: пропускать там некому);
* разработчик локально (`--run`): прогоняет затронутое до отправки.

ПОЛНЫЙ ПРОГОН — ВСЕГДА, КРОМЕ ЧЕРНОВИКА В ВЕТКУ ЭПИКА
---------------------------------------------------
Целевой прогон бывает ровно в одном случае: событие `pull_request`, запрос в состоянии
черновика, база — не из `full_bases` карты (`main`). Иначе (`ready_for_review`, запрос в
`main`, push, ручной запуск, расписание) — полный прогон того же состава, что и до
механизма. Отбор `on.pull_request.paths` не используется намеренно: процесс, отсечённый
фильтром путей, не заводит проверок вовсе, и сводный вердикт отвергает такой фильтр
(обязательная проверка, чей процесс не завёлся, висит «Expected» навсегда). Пропуск
заданием через `if:` даёт исход `skipped`, а его защита ветки засчитывает как пройденный —
поэтому черновик держит красным сводный вердикт `prverdict`, а не пропуск.

Путь, который не выбирает ни одна группа, и путь из `full_on` (сама карта, этот скрипт)
выбирают ВСЁ: неопознанное изменение судится целиком, а не никем. Файл процесса выбирает
все задания своего процесса.

ОБРАЗЕЦ «ЛЮБОЙ ПУТЬ» ПОКРЫТИЕМ НЕ СЧИТАЕТСЯ
------------------------------------------
Группа с образцом `**` (юниты) судит любую правку и потому добавляет свои
задания к каждому выбору. Но если бы такое совпадение засчитывалось покрытием, «путь не
выбирает ни одна группа» не случалось бы НИКОГДА: каталог, заведённый вчера, файл в корне —
всё «опознано» образцом, который опознаёт всё, и запасной ход к полному прогону мёртв
(возврат приёмки kaname#707, тот же дефект в kacho#3148). Поэтому покрытие решают только
образцы, сужающие что-то (`_universal` их отличает): путь, совпавший лишь с `**`, — неопознанный, и судится целиком.

КОДЫ
----
0 — всё затронутое зелёное (или перечень выведен); 1 — красное (перечень красных);
2 — не выполнилось: дифф пуст (ноль путей — это «смотреть не на что», а не «зелено»),
карта не разобрана, git не ответил, инструмента нет, исполнено ноль команд.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
MAP = HERE.parent / "ci-paths.json"
# Площадка отдаёт файлы запроса страницами по 100 и не больше 3000 всего: при пределе
# перечень неполон, и целевой выбор по нему был бы выбором по части изменения.
PR_FILES_CAP = 3000

GREEN, RED, VOID = 0, 1, 2


class MapError(Exception):
    """Карта не разобрана или противоречит себе. Это «не выполнилось», а не «пусто»."""


# ── образцы путей ────────────────────────────────────────────────────────────

def _glob_re(pattern: str) -> re.Pattern[str]:
    """`**` — любые сегменты (и ни одного), `*` — внутри сегмента, `?` — один знак."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def matches(path: str, patterns: list[str]) -> bool:
    return any(_glob_re(p).match(path) for p in patterns)


def _universal(pattern: str) -> bool:
    """Образец совпадает с ЛЮБЫМ путём (`**`, `**/*`, `*` с `**/`-приставками до него).

    Такой образец ничего не сужает: он добавляет задания группы к выбору, но покрытием пути не
    считается — иначе запасной ход «неопознанное → полный прогон» недостижим.
    """
    return re.fullmatch(r"(?:\*\*/)*\*\*?", pattern) is not None and pattern != "*"


# ── карта ────────────────────────────────────────────────────────────────────

@dataclass
class Group:
    id: str
    why: str
    jobs: list[str]
    paths: list[str]
    local: list[dict] = field(default_factory=list)


@dataclass
class PathMap:
    full_bases: list[str]
    full_on: list[str]
    always: list[str]
    detectors: dict[str, str]
    groups: list[Group]

    def all_jobs(self) -> set[str]:
        return {j for g in self.groups for j in g.jobs}


LOCAL_KINDS = {"cmd", "go-build", "go-test", "go-lint", "stand"}


def load_map(path: Path = MAP) -> PathMap:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MapError(f"карта {path} не прочитана: {exc}") from exc
    try:
        groups = [Group(id=g["id"], why=g["why"], jobs=list(g["jobs"]), paths=list(g["paths"]),
                        local=list(g.get("local", []))) for g in raw["groups"]]
        m = PathMap(full_bases=list(raw["full_bases"]), full_on=list(raw["full_on"]),
                    always=list(raw["always"]), detectors=dict(raw["detectors"]), groups=groups)
    except (KeyError, TypeError) as exc:
        raise MapError(f"карта {path}: нет обязательного ключа {exc}") from exc
    problems = []
    if not m.groups:
        problems.append("ноль групп — это не «выбирать нечего», а «карта не прочитана»")
    ids = [g.id for g in m.groups]
    if len(ids) != len(set(ids)):
        problems.append("повтор id группы")
    for g in m.groups:
        if not g.jobs or not g.paths:
            problems.append(f"группа {g.id}: пустые jobs или paths")
        for j in g.jobs:
            if j.count(":") != 1:
                problems.append(f"группа {g.id}: задание «{j}» не в форме <процесс>:<id>")
        for loc in g.local:
            if loc.get("kind") not in LOCAL_KINDS:
                problems.append(f"группа {g.id}: локальный вид «{loc.get('kind')}» не из "
                                f"{sorted(LOCAL_KINDS)}")
    if problems:
        raise MapError("карта противоречит себе:\n" + "\n".join(f"   • {p}" for p in problems))
    return m


# ── выбор ────────────────────────────────────────────────────────────────────

@dataclass
class Selection:
    full: bool
    reason: str
    files: list[str]
    groups: list[Group]
    jobs: list[str]           # «<процесс>:<id>», отсортировано

    def jobs_of(self, workflow: str) -> list[str]:
        return sorted(j.split(":", 1)[1] for j in self.jobs if j.split(":", 1)[0] == workflow)


def select(m: PathMap, files: list[str]) -> Selection:
    """Чистая функция: пути → группы и задания. Ноль путей — ноль выбранного."""
    files = sorted({f for f in files if f})
    if not files:
        return Selection(False, "дифф пуст", [], [], [])
    forcing = [f for f in files if matches(f, m.full_on)]
    if forcing:
        return Selection(True, f"тронута сама карта выбора ({forcing[0]}) — судится всё",
                         files, list(m.groups), sorted(m.all_jobs()))
    chosen: dict[str, Group] = {}
    jobs: set[str] = set()
    unclaimed = []
    for f in files:
        hit = False
        for g in m.groups:
            own_workflow = any(f == f".github/workflows/{j.split(':', 1)[0]}" for j in g.jobs)
            if matches(f, g.paths):
                chosen.setdefault(g.id, g)
                jobs.update(g.jobs)
                # Совпадение лишь с «любым путём» путь не опознаёт (см. шапку).
                hit = hit or matches(f, [p for p in g.paths if not _universal(p)])
            elif own_workflow:
                # Файл процесса судит его задания: изменение объявления — изменение их всех.
                wf = f.rsplit("/", 1)[1]
                jobs.update(j for j in g.jobs if j.split(":", 1)[0] == wf)
                chosen.setdefault(g.id, g)
                hit = True
        if not hit:
            unclaimed.append(f)
    if unclaimed:
        return Selection(True, f"путь не выбирает ни одна группа ({unclaimed[0]}) — "
                               f"неопознанное судится целиком", files, list(m.groups),
                         sorted(m.all_jobs()))
    return Selection(False, "целевой выбор", files, list(chosen.values()), sorted(jobs))


# ── вход: пути изменения ─────────────────────────────────────────────────────

def git_changed(base: str) -> list[str]:
    """Пути `<база>...HEAD` плюс незакоммиченные и неотслеживаемые: локально судится то,
    что уйдёт отправкой, и то, что ещё лежит в рабочем дереве."""
    def run(*args: str) -> list[str]:
        out = subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True,
                             text=True).stdout
        return [ln for ln in out.splitlines() if ln]
    files = run("diff", "--name-only", "--no-renames", f"{base}...HEAD")
    files += run("diff", "--name-only", "--no-renames", "HEAD")
    files += run("ls-files", "--others", "--exclude-standard")
    return files


def pr_files(repo: str, number: str) -> list[str] | None:
    """Пути запроса по API (GET). None — перечень неполон (предел площадки)."""
    out = subprocess.run(
        ["gh", "api", "--paginate", f"repos/{repo}/pulls/{number}/files?per_page=100",
         "--jq", ".[] | .filename, (.previous_filename // empty)"],
        check=True, capture_output=True, text=True).stdout
    files = [ln for ln in out.splitlines() if ln]
    return None if len(files) >= PR_FILES_CAP else files


# ── режим события ────────────────────────────────────────────────────────────

def event_mode(m: PathMap, event: str, draft: str, base: str) -> tuple[bool, str]:
    """(полный ли, почему). Целевой — только черновик запроса в ветку эпика."""
    if event != "pull_request":
        return True, f"событие {event or '—'}: полный прогон"
    if draft != "true":
        return True, "запрос не черновик (ready): полный прогон"
    if base in m.full_bases:
        return True, f"база {base}: полный прогон на каждом запросе"
    return False, f"черновик запроса в {base}: целевой прогон"


# ── проводка: каждое задание процессов запроса — в карте или в `always` ──────

def check_wiring(m: PathMap, workflows: Path) -> list[str]:
    """Находки проводки. Пустой перечень — проводка сходится с картой в обе стороны."""
    import yaml  # noqa: PLC0415 — нужен только здесь; детектору хватает json
    findings: list[str] = []
    seen: set[str] = set()
    examined = 0
    for wf in sorted({*workflows.glob("*.yml"), *workflows.glob("*.yaml")}):
        doc = yaml.safe_load(wf.read_text(encoding="utf-8"))
        on = doc.get("on", doc.get(True)) if isinstance(doc, dict) else None
        if not (isinstance(on, dict) and "pull_request" in on):
            continue
        jobs = doc.get("jobs") or {}
        detector = m.detectors.get(wf.name)
        if detector is None:
            # Процесс без детектора идёт целиком; в карте его заданий быть не должно.
            for jid in jobs:
                key = f"{wf.name}:{jid}"
                examined += 1
                seen.add(key)
                if key in m.all_jobs():
                    findings.append(f"{key}: в карте, а детектора у процесса нет — выбор не "
                                    f"исполнится")
                elif key not in m.always:
                    findings.append(f"{key}: процесс без детектора не объявлен в `always`")
            continue
        if detector not in jobs:
            findings.append(f"{wf.name}: детектор «{detector}» объявлен картой, а задания нет")
        for jid, job in jobs.items():
            key = f"{wf.name}:{jid}"
            examined += 1
            seen.add(key)
            if jid == detector:
                continue
            cond = str(job.get("if", "")) if isinstance(job, dict) else ""
            needs = job.get("needs", []) if isinstance(job, dict) else []
            needs = [needs] if isinstance(needs, str) else list(needs or [])
            if key in m.always:
                if f"'{jid}'" in cond:
                    findings.append(f"{key}: в `always`, а условие выбирает его по карте")
                continue
            if key not in m.all_jobs():
                findings.append(f"{key}: задания нет ни в одной группе карты и нет в `always` — "
                                f"на черновике его не выберет никто")
                continue
            want = (f"needs.{detector}.outputs.full == 'true' || contains(fromJSON("
                    f"needs.{detector}.outputs.jobs || '[]'), '{jid}')")
            if want not in cond or detector not in needs:
                findings.append(f"{key}: условие не несёт выбора детектора «{want}» "
                                f"(или нет needs: {detector})")
    for key in sorted((m.all_jobs() | set(m.always)) - seen):
        findings.append(f"{key}: в карте, а задания в процессах запроса нет — запись без предмета")
    if not examined:
        findings.append("осмотрено ноль заданий процессов запроса — это не «находок нет»")
    return findings


# ── локальный прогон ─────────────────────────────────────────────────────────

def _module_of(path: Path) -> Path | None:
    for d in [path.parent, *path.parent.parents]:
        if (d / "go.mod").exists():
            return d
        if d == ROOT:
            break
    return None


def go_packages(files: list[str], with_dependents: bool) -> dict[Path, list[str]]:
    """Модуль → пакеты (`./dir`) изменённых .go-файлов; с обратными зависимостями."""
    by_mod: dict[Path, set[str]] = {}
    for f in files:
        if not f.endswith(".go"):
            continue
        p = ROOT / f
        if not p.parent.is_dir():
            continue  # пакет снят целиком — судит сборка, а не прогон его проб
        mod = _module_of(p)
        if mod is None:
            continue
        rel = os.path.relpath(p.parent, mod)
        by_mod.setdefault(mod, set()).add("./" + rel if rel != "." else ".")
    out: dict[Path, list[str]] = {}
    for mod, dirs in by_mod.items():
        if not with_dependents:
            out[mod] = sorted(dirs)
            continue
        listing = subprocess.run(
            ["go", "list", "-e", "-f", "{{.Dir}}\t{{.ImportPath}}\t{{join .Deps \" \"}}"
             "\t{{join .TestImports \" \"}} {{join .XTestImports \" \"}}", "./..."],
            cwd=mod, check=True, capture_output=True, text=True).stdout
        rows = [ln.split("\t") for ln in listing.splitlines() if ln.count("\t") == 3]
        changed = {r[1] for r in rows
                   if "./" + os.path.relpath(r[0], mod) in dirs or (r[0] == str(mod) and "." in dirs)}
        pkgs = set()
        for d, imp, deps, timps in rows:
            if imp in changed or changed & set(deps.split()) or changed & set(timps.split()):
                rel = os.path.relpath(d, mod)
                pkgs.add("./" + rel if rel != "." else ".")
        out[mod] = sorted(pkgs)
    return out


@dataclass
class Step:
    group: str
    title: str
    argv: list[str]
    cwd: Path


def plan_local(sel: Selection, base: str) -> tuple[list[Step], list[str]]:
    """Шаги локального прогона и перечень «нужен стенд» (не исполняется)."""
    steps: list[Step] = []
    stands: list[str] = []
    seen: set[tuple] = set()

    def add(s: Step) -> None:
        key = (tuple(s.argv), str(s.cwd))
        if key not in seen:
            seen.add(key)
            steps.append(s)

    for g in sel.groups:
        for loc in g.local:
            kind = loc["kind"]
            if kind == "stand":
                stands.append(f"{g.id}: {loc.get('title', g.why)}")
            elif kind == "cmd":
                add(Step(g.id, loc.get("title", " ".join(loc["argv"])), list(loc["argv"]), ROOT))
            elif kind in ("go-build", "go-test", "go-lint"):
                mods = go_packages(sel.files, with_dependents=(kind == "go-test"))
                for mod, pkgs in sorted(mods.items()):
                    if not pkgs:
                        continue
                    if kind == "go-build":
                        add(Step(g.id, f"go vet ({len(pkgs)} пак.)", ["go", "vet", *pkgs], mod))
                    elif kind == "go-test":
                        add(Step(g.id, f"go test -race ({len(pkgs)} пак. с обратными "
                                       f"зависимостями)",
                                 ["go", "test", "-race", "-count=1", *pkgs], mod))
                    else:
                        add(Step(g.id, f"golangci-lint ({len(pkgs)} пак.)",
                                 ["golangci-lint", "run", "--timeout=10m",
                                  *[p + "/" if p != "." else "." for p in pkgs]], mod))
    return steps, stands


def run_local(steps: list[Step], stands: list[str]) -> int:
    red, void, done = [], [], 0
    for s in steps:
        print(f"── [{s.group}] {s.title}\n   $ (cd {os.path.relpath(s.cwd, ROOT)}) "
              f"{shlex.join(s.argv)}", flush=True)
        try:
            rc = subprocess.run(s.argv, cwd=s.cwd).returncode
        except FileNotFoundError:
            rc = 127
        if rc in (126, 127):
            void.append(f"[{s.group}] {s.title} — инструмента нет ({s.argv[0]})")
            continue
        done += 1
        if rc != 0:
            red.append(f"[{s.group}] {s.title} — код {rc}")
    print(f"\nисполнено шагов {done} из {len(steps)}; красных {len(red)}; не выполнилось "
          f"{len(void)}")
    for r in red:
        print(f"   ✗ {r}")
    for v in void:
        print(f"   ◌ {v}")
    if stands:
        print("нужен стенд (локально не гоняется, судит конвейер):")
        for s in stands:
            print(f"   ▲ {s}")
    if red:
        return RED
    if void or done == 0:
        print("ВЕРДИКТ: не выполнилось — это НЕ «зелено»")
        return VOID
    print("ВЕРДИКТ: затронутое зелёное (целевой зелёный; для вливания нужен полный прогон)")
    return GREEN


# ── вывод ────────────────────────────────────────────────────────────────────

def render(sel: Selection, m: PathMap) -> str:
    total = len(m.all_jobs())
    lines = [f"путей {len(sel.files)}; {sel.reason}",
             f"заданий выбрано {len(sel.jobs)} из {total} (плюс всегда идущих {len(m.always)})"]
    for g in sel.groups:
        lines.append(f"   ● {g.id}: {', '.join(g.jobs)}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--map", type=Path, default=MAP)
    ap.add_argument("--base", default=os.environ.get("KACHO_TRUNK_REF", "origin/main"),
                    help="база диффа <база>...HEAD (по умолчанию $KACHO_TRUNK_REF или origin/main)")
    ap.add_argument("--files-from", help="перечень путей построчно (- — stdin) вместо git")
    ap.add_argument("--run", action="store_true", help="исполнить затронутое локально")
    ap.add_argument("--json", action="store_true", help="выбор машинно (JSON)")
    ap.add_argument("--github-output", metavar="WORKFLOW",
                    help="детектор процесса: full/jobs в $GITHUB_OUTPUT по событию запроса")
    ap.add_argument("--pr-aggregate", metavar="WORKFLOW",
                    help="сводный вердикт запроса по $NEEDS (toJSON(needs)) и $DRAFT")
    ap.add_argument("--check-wiring", type=Path, metavar="WORKFLOWS_DIR",
                    help="сверить проводку процессов с картой в обе стороны")
    args = ap.parse_args(argv)

    try:
        m = load_map(args.map)
    except MapError as exc:
        print(f"ОТКАЗ: {exc}", file=sys.stderr)
        return VOID

    if args.check_wiring:
        found = check_wiring(m, args.check_wiring)
        print(f"проводка: групп {len(m.groups)}, заданий в карте {len(m.all_jobs())}, "
              f"всегда идущих {len(m.always)}, детекторов {len(m.detectors)}; находок {len(found)}")
        for f in found:
            print(f"   ✗ {f}")
        return RED if found else GREEN

    if args.github_output:
        return detector(m, args.github_output)

    if args.pr_aggregate:
        return pr_aggregate(m, args.pr_aggregate)

    try:
        if args.files_from:
            src = sys.stdin if args.files_from == "-" else open(args.files_from, encoding="utf-8")
            files = [ln.strip() for ln in src if ln.strip()]
        else:
            files = git_changed(args.base)
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"ОТКАЗ: пути изменения не получены ({exc}) — это НЕ «ничего не тронуто»",
              file=sys.stderr)
        return VOID

    sel = select(m, files)
    if args.json:
        print(json.dumps({"full": sel.full, "reason": sel.reason, "files": len(sel.files),
                          "groups": [g.id for g in sel.groups], "jobs": sel.jobs},
                         ensure_ascii=False))
    else:
        print(render(sel, m))
    if not sel.files:
        print("ВЕРДИКТ: дифф пуст — судить нечего, и это НЕ «зелено»")
        return VOID
    if not args.run:
        return GREEN
    try:
        steps, stands = plan_local(sel, args.base)
    except subprocess.CalledProcessError as exc:
        print(f"ОТКАЗ: граф пакетов не получен ({exc.stderr or exc}) — не выполнилось",
              file=sys.stderr)
        return VOID
    return run_local(steps, stands)


def pr_aggregate(m: PathMap, workflow: str) -> int:
    """Сводный вердикт запроса по заданиям своего процесса (`needs`).

    Черновик — красный ПРИ ЛЮБОМ исходе выбранных: вливать по целевому прогону нельзя по
    построению, а пропуск, который защита засчитала бы за успех, вердикт не зеленит.
    Полный прогон — зелёный, только если каждое задание процесса завершилось успехом:
    `skipped` там — задание, которое никто не исполнил."""
    try:
        needs = json.loads(os.environ["NEEDS"])
    except (KeyError, json.JSONDecodeError) as exc:
        print(f"ОТКАЗ: исходы заданий не получены ({exc}) — вердикта НЕТ", file=sys.stderr)
        return VOID
    mine = sorted({j.split(":", 1)[1] for j in m.all_jobs() if j.startswith(workflow + ":")})
    det = m.detectors.get(workflow)
    det_result = str((needs.pop(det, None) or {}).get("result")) if det else "success"
    if det_result != "success":
        print(f"::error title=выбор затронутого не исполнился::детектор {det} — {det_result}; "
              f"задания процесса не выбирал никто")
        return RED
    if not needs or set(needs) != set(mine):
        print(f"ОТКАЗ: needs {sorted(needs)} не совпадает с заданиями процесса в карте "
              f"{mine} — свод судил бы не всё", file=sys.stderr)
        return VOID
    results = {k: str(v.get("result")) for k, v in needs.items()}
    ran = {k: r for k, r in results.items() if r != "skipped"}
    bad = sorted(k for k, r in ran.items() if r != "success")
    draft = os.environ.get("EVENT") == "pull_request" and os.environ.get("DRAFT") == "true"
    for k in sorted(results):
        print(f"   · {k} — {results[k]}")
    if draft:
        state = "целевой зелёный" if ran and not bad else ("целевой КРАСНЫЙ: " + ", ".join(bad)
                                                          if bad else "исполнено ноль")
        print(f"::error title=черновик не вливается::целевой прогон: {len(ran)} заданий из "
              f"{len(results)}; {state}; полный прогон заводит перевод запроса в ready")
        return RED
    skipped = sorted(k for k, r in results.items() if r == "skipped")
    if bad or skipped:
        print(f"::error title=полный прогон не зелёный::не успех: {', '.join(bad) or '—'}; "
              f"не исполнено: {', '.join(skipped) or '—'}")
        return RED
    print(f"полный прогон: {len(results)} заданий из {len(results)} — все зелёные")
    return GREEN


def detector(m: PathMap, workflow: str) -> int:
    """Задание-детектор: пишет `full` и `jobs` своего процесса в $GITHUB_OUTPUT."""
    if workflow not in m.detectors:
        print(f"ОТКАЗ: процесс {workflow} не объявлен в detectors карты", file=sys.stderr)
        return VOID
    full, why = event_mode(m, os.environ.get("EVENT", ""), os.environ.get("DRAFT", ""),
                           os.environ.get("BASE", ""))
    jobs: list[str] = []
    if not full:
        try:
            files = pr_files(os.environ["REPO"], os.environ["PR"])
        except (KeyError, subprocess.CalledProcessError) as exc:
            print(f"ОТКАЗ: пути запроса не получены ({exc}) — выбора нет", file=sys.stderr)
            return VOID
        if files is None:
            full, why = True, f"путей запроса не меньше {PR_FILES_CAP} — перечень неполон"
        else:
            sel = select(m, files)
            print(render(sel, m))
            if not sel.files:
                print("ОТКАЗ: у запроса ноль путей — выбирать не из чего", file=sys.stderr)
                return VOID
            full = sel.full
            why = sel.reason
            jobs = sel.jobs_of(workflow)
    mine = sorted({j.split(":", 1)[1] for j in m.all_jobs() if j.startswith(workflow + ":")})
    print(f"режим: {'ПОЛНЫЙ' if full else 'ЦЕЛЕВОЙ'} — {why}")
    print(f"процесс {workflow}: заданий выбрано {len(mine) if full else len(jobs)} из {len(mine)}")
    out = os.environ.get("GITHUB_OUTPUT")
    lines = f"full={'true' if full else 'false'}\njobs={json.dumps(jobs)}\n"
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(lines)
    else:
        sys.stdout.write(lines)
    return GREEN


if __name__ == "__main__":
    sys.exit(main())
