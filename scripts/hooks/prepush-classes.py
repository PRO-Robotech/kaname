#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Классы красных кругов конвейера — до отправки и только по тронутым путям (kaname#822).

ЗАЧЕМ
-----
Перепись красных заданий конвейера за 14 суток (2026-10-02…2026-10-16, `gh run list
--status failure` по `pr-rule.yml`, `ci.yml`, `e2e-newman.yml` с разбором текста отказа
каждого задания) назвала четыре класса, которые хук отправки НЕ судил, хотя всё нужное для
суда лежит на машине отправляющего:

  · правило запроса — 26 красных прогонов: заголовок «[#N] …» вместо «#N …» (17, из
    них 13 — первый прогон ветки, то есть при создании запроса), заголовок с чужим
    номером (2), слияния не по форме и чужой номер у своего коммита ветки-номера (7,
    одно — ещё и с головой не-номером); разбивка — перепроверкой check-verifier
    `gh run view --log-failed` по тем же 26 прогонам (первая редакция: 18/7/1). Страж правила ветки (prepush-rule.sh) судит только НОВЫЕ коммиты
    отправки; конвейер судит весь диапазон base..head и заголовок запроса;
  · записи ревью молчат об опубликованном событии — 19: событие живёт на трекере,
    а не в дереве, и хук трекер не спрашивал;
  · ведомость долга сквозного набора против дерева — 29 заданий в 15 прогонах;
  · каталог прав против копии края — 5 (его судит prepush-edge.sh; здесь — только
    выбор, нужна ли сверка по тронутым путям).

Команды суда — те же файлы, что у конвейера, второй копии предиката нет:
`.github/scripts/pr-rule-check.sh`, `.github/scripts/review-event-silence.py`,
`.github/scripts/newman-suite-debt.py`. Выбор по путям — карта `.github/ci-paths.json`
через `.github/scripts/affected.py` (единственный источник «путь → задание»).

ЧТО ТРОНУТО — И ОТНОСИТЕЛЬНО ЧЕГО
--------------------------------
База ссылки — та, куда уйдёт её запрос:
  · запрос уже открыт — его база (`gh pr list --head`), и заголовок с телом судятся;
  · запроса нет — ближайшая из `main` и голов открытых запросов в `main` (ветки эпиков):
    меньше всего коммитов «вершина ^кандидат»; равенство — `main`. Заголовка ещё нет —
    судятся голова и коммиты (`pr-rule-check.sh --commits-only`), а «заголовок и тело —
    не судились» печатается строкой.
Ствола на удалённом нет вовсе (синтетический модуль проб) — правило запроса не
заводится, тронутым считается всё дерево вершины, и это печатается.

Классы и их выбор:
  · правило запроса  — всегда, когда база найдена (цена — git и один-два вызова gh);
  · записи ревью     — тронут путь под `REVIEWS` гейта либо сам гейт;
  · долг набора      — тронут путь группы задания `e2e-newman.yml:suite` карты либо
    файл её процесса `.github/workflows/e2e-newman.yml` (так выбирает и карта);
  · сверка с краем   — выбраны задания `ci.yml:catalogparity` либо
    `ci.yml:authzartifacts`, либо выбор полный (неопознанный путь судится целиком).

ВЫЗОВ И ИСХОДЫ
--------------
  prepush-classes.py plan --out DIR [--remote NAME]   (stdin — вход git хука отправки)
      пишет DIR/plan.json, DIR/classes и DIR/note (строка переписи хука); 0 — выбор
      установлен, 2 — не установлен.
  prepush-classes.py request|reviews|debt DIR
      0 — зелёное · 1 — красное · 3 — условие не создано (суд не исполнялся).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ZERO = "0" * 40
UNMET = 3
GH_TIMEOUT = 30
FETCH_TIMEOUT = 60
EDGE_JOBS = {"ci.yml:catalogparity", "ci.yml:authzartifacts"}
DEBT_JOBS = {"e2e-newman.yml:suite"}
NUMBER = re.compile(r"^[0-9]+$")
SLUG = re.compile(r"github\.com[:/]+([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")
TITLES = {
    "request": "правило запроса",
    "reviews": "записи ревью",
    "debt": "долг набора",
    "edge": "сверка с краем",
}
PR_RULE = ".github/scripts/pr-rule-check.sh"
SILENCE = ".github/scripts/review-event-silence.py"
DEBT = ".github/scripts/newman-suite-debt.py"
AFFECTED = ".github/scripts/affected.py"


def say(*lines: str) -> None:
    for ln in lines:
        print(ln, flush=True)


def run(argv: list[str], root: Path, timeout: int = 120, env: dict | None = None,
        stdin: str | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, cwd=root, capture_output=True, text=True, timeout=timeout,
                              env=env, input=stdin)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, "", "истёк срок %d с" % timeout)
    except OSError as exc:
        return subprocess.CompletedProcess(argv, 127, "", str(exc))


def git(root: Path, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return run(["git", *args], root, timeout=timeout)


def gh_json(root: Path, args: list[str]):
    """Ответ gh разобранным JSON; (None, причина) — gh нет, отказал или ответ не JSON."""
    if shutil.which("gh") is None:
        return None, "gh не найден в PATH"
    p = run(["gh", *args], root, timeout=GH_TIMEOUT)
    if p.returncode != 0:
        return None, "gh %s: код %d — %s" % (" ".join(args[:2]), p.returncode,
                                             (p.stderr or p.stdout).strip().replace("\n", " ")[:200])
    try:
        return json.loads(p.stdout or "null"), ""
    except json.JSONDecodeError as exc:
        return None, "gh %s: ответ не JSON (%s)" % (" ".join(args[:2]), exc)


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError("модуль %s не загружается" % path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def push_refs(root: Path, push_input: str) -> tuple[list[dict], str]:
    """Отправляемые ветки с содержимым; пустой вход — HEAD (хук позвали не отправкой)."""
    lines = [ln.split() for ln in push_input.splitlines() if ln.strip()]
    if not lines:
        tip = git(root, "rev-parse", "--verify", "-q", "HEAD^{commit}").stdout.strip()
        name = git(root, "symbolic-ref", "-q", "--short", "HEAD").stdout.strip() or "HEAD"
        return ([{"name": name, "tip": tip}] if tip else []), "вход пуст — судится HEAD (не отправка)"
    refs = []
    for f in lines:
        if len(f) < 4 or not f[2].startswith("refs/heads/") or f[1] == ZERO:
            continue
        refs.append({"name": f[2][len("refs/heads/"):], "tip": f[1]})
    return refs, "вход git: строк %d, веток с содержимым %d" % (len(lines), len(refs))


def remote_ref(root: Path, remote: str, branch: str) -> str:
    return git(root, "rev-parse", "-q", "--verify",
               "refs/remotes/%s/%s^{commit}" % (remote, branch)).stdout.strip()


def fetch(root: Path, remote: str, branch: str, notes: list[str]) -> None:
    p = git(root, "fetch", "-q", "--no-tags", remote,
            "+refs/heads/%s:refs/remotes/%s/%s" % (branch, remote, branch), timeout=FETCH_TIMEOUT)
    if p.returncode != 0:
        notes.append("fetch %s/%s не удался (код %d) — база по прежней ссылке клона: %s"
                     % (remote, branch, p.returncode, p.stderr.strip().replace("\n", " ")[:160]))


def plan(args) -> int:
    root = Path(git(Path.cwd(), "rev-parse", "--show-toplevel").stdout.strip() or ".")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    notes: list[str] = []
    try:
        affected = load_module(root / AFFECTED, "kaname_affected")
        pmap = affected.load_map(root / ".github" / "ci-paths.json")
    except Exception as exc:  # карта — единственный источник выбора; без неё выбирать нечем
        say("prepush-classes: НЕ ВЫПОЛНИЛОСЬ — карта выбора не прочитана: %s" % exc)
        return 2
    reviews_dir = "docs/specs/reviews"
    try:
        reviews_dir = load_module(root / SILENCE, "kaname_silence").REVIEWS
    except Exception as exc:
        notes.append("каталог записей ревью взят по умолчанию (%s): гейт не загрузился — %s"
                     % (reviews_dir, exc))

    refs, input_note = push_refs(root, sys.stdin.read())
    # Адрес — как записан в настройке, а не `remote get-url`: тот раскрывает
    # insteadOf, и площадка за подменой адреса стала бы неопознаваемой.
    url = git(root, "config", "--get", "remote.%s.url" % args.remote).stdout.strip()
    m = SLUG.search(url)
    slug = "%s/%s" % (m.group(1), m.group(2)) if m else ""
    gh_ok = bool(slug)
    if not slug:
        notes.append("удалённый «%s» не на GitHub (%s) — запросы не спрашивались" % (args.remote, url or "нет"))

    epics: list[str] = []
    if gh_ok and refs:
        data, why = gh_json(root, ["pr", "list", "-R", slug, "--base", "main", "--state", "open",
                                   "--json", "headRefName", "--limit", "200"])
        if data is None:
            gh_ok = False
            notes.append("запросы не спрошены: %s — база выбирается без голов эпиков" % why)
        else:
            epics = sorted({r.get("headRefName", "") for r in data if NUMBER.match(r.get("headRefName", ""))})
    if url:
        fetch(root, args.remote, "main", notes)

    touched: set[str] = set()
    for r in refs:
        r["pr"] = None
        if gh_ok:
            data, why = gh_json(root, ["pr", "list", "-R", slug, "--head", r["name"], "--state", "open",
                                       "--json", "number,title,body,baseRefName,isDraft", "--limit", "5"])
            if data is None:
                notes.append("запрос ветки %s не спрошен: %s" % (r["name"], why))
            elif len(data) == 1:
                r["pr"] = data[0]
            elif len(data) > 1:
                notes.append("у ветки %s открытых запросов %d — судятся голова и коммиты" % (r["name"], len(data)))
        if r["pr"]:
            base = r["pr"].get("baseRefName", "main")
            if url and base != "main":
                fetch(root, args.remote, base, notes)
            r["base"], r["base_why"] = base, "база запроса #%s" % r["pr"].get("number")
            r["base_sha"] = remote_ref(root, args.remote, base)
        else:
            best = None
            for cand in ["main"] + [e for e in epics if e != r["name"]]:
                sha = remote_ref(root, args.remote, cand)
                if not sha:
                    continue
                cnt = git(root, "rev-list", "--count", r["tip"], "^" + sha).stdout.strip()
                if not cnt.isdigit():
                    continue
                if best is None or int(cnt) < best[2]:
                    best = (cand, sha, int(cnt))
            if best:
                r["base"], r["base_sha"] = best[0], best[1]
                r["base_why"] = "запроса нет — ближайшая из main и голов эпиков (%d кандидатов), " \
                                "коммитов сверх неё %d" % (1 + len([e for e in epics if e != r["name"]]), best[2])
            else:
                r["base"], r["base_sha"], r["base_why"] = "", "", "ствола %s/main на удалённом нет" % args.remote
        if r["base_sha"]:
            p = git(root, "diff", "--name-only", "--no-renames", "%s...%s" % (r["base_sha"], r["tip"]))
        else:
            p = git(root, "ls-tree", "-r", "--name-only", r["tip"])
        if p.returncode != 0:
            say("prepush-classes: НЕ ВЫПОЛНИЛОСЬ — тронутые пути ветки %s не установлены: %s"
                % (r["name"], p.stderr.strip()))
            return 2
        touched.update(ln for ln in p.stdout.splitlines() if ln)

    files = sorted(touched)
    sel = affected.select(pmap, files)
    # Пути группы задания набора и файл его процесса — то же, что выбирает карта
    # (файл процесса выбирает свои задания). Правка ci.yml долга не выбирает: её не
    # выбирает и целевой прогон конвейера.
    debt_paths = [p for g in pmap.groups if DEBT_JOBS & set(g.jobs) for p in g.paths
                  if not affected._universal(p)] + [
                      ".github/workflows/%s" % j.split(":", 1)[0] for j in sorted(DEBT_JOBS)]
    chosen: dict[str, str | None] = {}
    based = [r for r in refs if r["base_sha"]]
    chosen["request"] = ("веток %d с базой" % len(based)) if based else None
    hit = [f for f in files if f == SILENCE or f.startswith(reviews_dir.rstrip("/") + "/")]
    chosen["reviews"] = ("тронуто %d путей: %s" % (len(hit), hit[0])) if hit else None
    hit = [f for f in files if affected.matches(f, debt_paths)]
    chosen["debt"] = ("тронуто %d путей: %s" % (len(hit), hit[0])) if hit else None
    jobs = sorted(EDGE_JOBS & set(sel.jobs))
    chosen["edge"] = ("выбор полный: %s" % sel.reason) if sel.full else (
        ("выбраны задания %s" % ", ".join(jobs)) if jobs else None)

    why_not = {
        "request": "базы нет ни у одной ветки (%s)" % "; ".join(r["base_why"] for r in refs) if refs
                   else "веток с содержимым нет",
        "reviews": "тронутых путей под %s/ и самого гейта нет" % reviews_dir,
        "debt": "тронутых путей группы задания e2e-newman.yml:suite и её файла процесса нет",
        "edge": "задания ci.yml:catalogparity и ci.yml:authzartifacts тронутыми путями не выбраны",
    }
    plan_doc = {"slug": slug, "remote": args.remote, "refs": refs, "touched": files,
                "classes": chosen, "notes": notes}
    (out / "plan.json").write_text(json.dumps(plan_doc, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "classes").write_text("".join(c + "\n" for c, v in chosen.items() if v), encoding="utf-8")
    # Строка переписи хука — ОДНА строка и при пустом выборе: счёт в оболочке
    # (`grep -c . f || echo 0`) печатал на пустом файле «0» дважды.
    picked = [TITLES[c] for c, v in chosen.items() if v]
    (out / "note").write_text("%d из %d выбрано по тронутым путям%s — строки «классы до отправки» выше\n"
                              % (len(picked), len(TITLES), (": " + ", ".join(picked)) if picked else ""),
                              encoding="utf-8")

    say("== классы до отправки (kaname#822): %s · путей тронуто %d" % (input_note, len(files)))
    for r in refs:
        pr = r["pr"]
        say("   ветка %s @ %s → база %s @ %s — %s%s" % (
            r["name"], r["tip"][:12], r["base"] or "—", (r["base_sha"] or "—")[:12], r["base_why"],
            (" · заголовок и тело судятся" if pr else " · заголовок и тело НЕ судятся: запроса нет")
            if r["base_sha"] else ""))
    for c, v in chosen.items():
        say("   %-16s: %s" % (TITLES[c], ("судится — " + v) if v else ("не выбран — " + why_not[c])))
    for n in notes:
        say("   примечание     : " + n)
    return 0


def read_plan(d: str) -> dict:
    return json.loads((Path(d) / "plan.json").read_text(encoding="utf-8"))


def root_of() -> Path:
    return Path(git(Path.cwd(), "rev-parse", "--show-toplevel").stdout.strip() or ".")


def show(p: subprocess.CompletedProcess) -> None:
    for s in (p.stdout, p.stderr):
        if s:
            sys.stdout.write(s if s.endswith("\n") else s + "\n")
    sys.stdout.flush()


def request(args) -> int:
    root, doc = root_of(), read_plan(args.dir)
    if not (root / PR_RULE).is_file():
        say("НЕ ВЫПОЛНИЛОСЬ: нет %s — правило запроса судить нечем" % PR_RULE)
        return UNMET
    red = unmet = judged = 0
    for r in doc["refs"]:
        if not r.get("base_sha"):
            continue
        env = {k: v for k, v in os.environ.items() if k not in ("PR_TITLE", "PR_BODY")}
        env.update(HEAD_REF=r["name"], BASE_SHA=r["base_sha"], HEAD_SHA=r["tip"])
        if doc.get("slug"):
            env["GITHUB_REPOSITORY"] = doc["slug"]
        argv = ["bash", PR_RULE]
        if r.get("pr"):
            env.update(PR_TITLE=r["pr"].get("title") or "", PR_BODY=r["pr"].get("body") or "")
        else:
            argv.append("--commits-only")
        p = run(argv, root, timeout=300, env=env)
        show(p)
        judged += 1
        if p.returncode == 1:
            red += 1
        elif p.returncode != 0:
            unmet += 1
            say("НЕ ВЫПОЛНИЛОСЬ: правило запроса ветки %s не судилось (код %d)" % (r["name"], p.returncode))
    say("правило запроса: судилось веток %d · красных %d · не выполнилось %d" % (judged, red, unmet))
    if red:
        return 1
    if unmet or not judged:
        return UNMET
    return 0


def gate(root: Path, rel: str, argv: list[str], unmet_codes: set[int], label: str,
         self_test: bool) -> int:
    if not (root / rel).is_file():
        say("НЕ ВЫПОЛНИЛОСЬ: нет %s — %s судить нечем" % (rel, label))
        return UNMET
    if self_test:
        p = run(["python3", rel, "--self-test"], root, timeout=300)
        show(p)
        if p.returncode != 0:
            say("%s: самопроба гейта красная (код %d) — его вердикту верить нельзя" % (label, p.returncode))
            return 1
    p = run(["python3", rel, *argv], root, timeout=300)
    show(p)
    if p.returncode == 0:
        return 0
    if p.returncode in unmet_codes:
        say("НЕ ВЫПОЛНИЛОСЬ: %s — гейт не смог судить (код %d)" % (label, p.returncode))
        return UNMET
    return 1


def reviews(args) -> int:
    root, doc = root_of(), read_plan(args.dir)
    worst = 0
    tips = sorted({r["tip"] for r in doc["refs"]})
    for tip in tips:
        rc = gate(root, SILENCE, ["--rev", tip], {2}, "записи ревью @%s" % tip[:12],
                  SILENCE in doc["touched"] and tip == tips[0])
        worst = 1 if 1 in (worst, rc) else max(worst, rc)
    return worst if tips else UNMET


def debt(args) -> int:
    root, doc = root_of(), read_plan(args.dir)
    return gate(root, DEBT, [], {75}, "долг сквозного набора", DEBT in doc["touched"])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan")
    p.add_argument("--out", required=True)
    p.add_argument("--remote", default="origin")
    for name in ("request", "reviews", "debt"):
        sub.add_parser(name).add_argument("dir")
    args = ap.parse_args()
    return {"plan": plan, "request": request, "reviews": reviews, "debt": debt}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
