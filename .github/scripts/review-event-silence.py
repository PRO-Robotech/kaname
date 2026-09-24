#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Гейт записей ревью: событие полномочия на трекере есть, а запись о нём молчит.

ПРЕДМЕТ
-------
Запись ревью (`docs/specs/reviews/<документ>/<sha256>.yaml`) несёт вердикт и
утверждение о санкции `effective_approval.issued`. Санкцию выдаёт не запись, а
ВНЕШНЕЕ событие полномочия — комментарий допущенной учётки в задаче трекера с
полями `role · verdict · subject · subject_revision · subject_sha256`. Когда
событие опубликовано, запись обязана нести блок `event` со `status: performed`,
а `effective_approval` — быть приведено к факту события.

Держатель задачи PRO-Robotech/kaname#302 судит запись, у которой блок `event`
УЖЕ есть (`performed` ⇒ `issued: true`). К записи без блока он слеп по
построению: в дереве о событии не сказано ничего, а событие живёт на трекере.
Поэтому этот гейт читает ТРЕКЕР. Измерено (kaname#402): на ревизии `4ed53c9b`
перепись #302 печатала «расхождений 0», а четыре записи с `verdict: APPROVED`,
`issued: false` и без блока `event` молчали о событиях, уже опубликованных.

ЧТО СУДИТСЯ
-----------
Каждая запись, у которой нет исполненного события (`event.status` не
`performed`) — во ВСЕХ трёх законных формах записи такого состояния: блока
`event` нет вовсе; блок есть со `status: not_performed`; блок есть с
`type: none`. Узкий отбор «`publication_pending` и нет блока» (так предикат
записан в теле #402) не видел второй формы, а она в дереве есть: запись с
`event.status: not_performed` при событии, опубликованном за шесть дней до
ревизии `4ed53c9b`.

Где искать событие, запись называет сама: задача — `subject.task`
(`<владелец>/<репозиторий>#<номер>`), учётка —
`effective_approval.publication_pending.expected_actor`, а без неё —
`authority.authorized_actors`. Событие опознаётся ЗАГОЛОВКОМ комментария (строки
`ключ: значение` до первой `---`), где есть все пять обязательных полей и
`subject_sha256` равен `subject.sha256` записи. Отпечаток, упомянутый в прозе
обсуждения, событием не является — это законный близнец самопробы.

ЧЕГО НЕ СУДИТ — И ЭТО ПЕЧАТАЕТСЯ ЧИСЛОМ
---------------------------------------
Запись без названной задачи не говорит, где искать. Если её вердикт `APPROVED`,
она могла бы нести санкцию — исход «не выполнилось». Если вердикт не выдаёт
санкции (`CHANGES_REQUESTED`), её счёт печатается отдельной строкой переписи и в
вердикт не входит: «судимо M из K» различимо с «судимо K из K».

ИСХОДЫ
------
  0 — расхождений 0 при непустом обходе, все нужные задачи трекера прочитаны;
  1 — расхождения есть: запись названа координатой, событие — адресом;
  2 — не выполнилось: обход пуст, трекер недоступен, запись не разобрана либо
      запись `APPROVED` не называет задачу. Это не зелёное.

Прогон:  python3 .github/scripts/review-event-silence.py [--rev REV]
         python3 .github/scripts/review-event-silence.py --self-test
Трекер читается `gh api` (в конвейере — `GH_TOKEN`); `--tracker-fixture DIR`
подставляет захваченные ответы API (`DIR/<владелец>/<репозиторий>/<номер>.json`,
массив комментариев в форме ответа API).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

NAME = "review-event-silence"
REVIEWS = "docs/specs/reviews"
REQUIRED_EVENT_FIELDS = ("role", "verdict", "subject", "subject_revision", "subject_sha256")
TASK_RE = re.compile(r"^([\w.-]+)/([\w.-]+)#(\d+)$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")

GREEN, RED, UNMET = 0, 1, 2


class Unmet(Exception):
    """Судить не по чему: вердикта нет — ни зелёного, ни красного."""


def git(root: str, *args: str) -> str:
    p = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True)
    if p.returncode != 0:
        raise Unmet("git %s: %s" % (" ".join(args), p.stderr.strip() or "код %d" % p.returncode))
    return p.stdout


def read_records(root: str, rev: str):
    """[(путь, текст)] записей ревью ревизии и число прочих файлов под каталогом."""
    import yaml  # noqa: F401 — отсутствие разборщика есть третий исход, а не отказ разбора

    listing = git(root, "ls-tree", "-r", "-z", "--name-only", rev, "--", REVIEWS)
    paths = [p for p in listing.split("\0") if p]
    records, other = [], 0
    for p in paths:
        parts = p.split("/")
        if len(parts) == 5 and p.endswith(".yaml"):
            records.append((p, git(root, "show", "%s:%s" % (rev, p))))
        else:
            other += 1
    return records, other


def event_header(body: str) -> dict:
    """Поля заголовка комментария: строки `ключ: значение` до первой `---`."""
    fields = {}
    for line in (body or "").splitlines():
        if line.strip() == "---":
            break
        m = re.match(r"^([a-z][a-z0-9_]*):\s*(.*?)\s*$", line)
        if m:
            fields.setdefault(m.group(1), m.group(2))
    return fields


class Tracker:
    """Комментарии задачи трекера: из API (`gh`) либо из захваченных ответов."""

    def __init__(self, fixture: str | None):
        self.fixture = fixture
        self.cache: dict[str, list] = {}
        self.comments_read = 0

    def comments(self, owner: str, repo: str, number: str) -> list:
        key = "%s/%s#%s" % (owner, repo, number)
        if key in self.cache:
            return self.cache[key]
        if self.fixture is not None:
            f = os.path.join(self.fixture, owner, repo, number + ".json")
            if not os.path.isfile(f):
                raise Unmet("трекер недоступен: захваченного ответа для %s нет (%s)" % (key, f))
            with open(f, encoding="utf-8") as fh:
                data = json.load(fh)
        else:
            if shutil.which("gh") is None:
                raise Unmet("трекер недоступен: `gh` не найден в PATH")
            p = subprocess.run(
                ["gh", "api", "--paginate", "repos/%s/%s/issues/%s/comments?per_page=100" % (owner, repo, number),
                 "--jq", ".[] | {id, html_url, created_at, body, user: {login: .user.login}}"],
                capture_output=True, text=True)
            if p.returncode != 0:
                raise Unmet("трекер недоступен: %s — %s" % (key, p.stderr.strip() or "код %d" % p.returncode))
            data = [json.loads(line) for line in p.stdout.splitlines() if line.strip()]
        if not isinstance(data, list):
            raise Unmet("ответ трекера для %s — не массив комментариев" % key)
        self.cache[key] = data
        self.comments_read += len(data)
        return data


def judge(root: str, rev: str, fixture: str | None):
    """(код, строки вывода)."""
    import yaml

    out = []
    sha = git(root, "rev-parse", "--verify", "%s^{commit}" % rev).strip()
    records, other = read_records(root, rev)
    if not records:
        raise Unmet("обход пуст: под %s на %s нет ни одной записи — «расхождений 0» значило бы «ноль прочитанного»"
                    % (REVIEWS, sha[:12]))

    performed = 0
    judged = []
    untasked_approved, untasked_other = [], []
    for path, text in records:
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise Unmet("%s не разбирается как YAML: %s" % (path, e)) from e
        if not isinstance(doc, dict):
            raise Unmet("%s — не отображение верхнего уровня" % path)
        ev = doc.get("event")
        if isinstance(ev, dict) and ev.get("status") == "performed":
            performed += 1
            continue
        subject = doc.get("subject") if isinstance(doc.get("subject"), dict) else {}
        ea = doc.get("effective_approval") if isinstance(doc.get("effective_approval"), dict) else {}
        task = subject.get("task")
        m = TASK_RE.match(task) if isinstance(task, str) else None
        if not m:
            (untasked_approved if doc.get("verdict") == "APPROVED" else untasked_other).append(path)
            continue
        subj_sha = subject.get("sha256")
        if not (isinstance(subj_sha, str) and SHA_RE.match(subj_sha)):
            raise Unmet("%s: subject.sha256 не отпечаток — сверять событие не с чем" % path)
        pending = ea.get("publication_pending") if isinstance(ea.get("publication_pending"), dict) else {}
        actors = pending.get("expected_actor")
        if isinstance(actors, str):
            actors = [actors]
        if not actors:
            auth = doc.get("authority") if isinstance(doc.get("authority"), dict) else {}
            actors = auth.get("authorized_actors") or []
        if not actors:
            raise Unmet("%s: учётка события не названа (ни expected_actor, ни authorized_actors)" % path)
        if not isinstance(ev, dict):
            state = "без блока event"
        else:
            state = "event.status: %s, event.type: %s" % (ev.get("status"), ev.get("type"))
        judged.append((path, m.groups(), subj_sha, set(actors), state, ea.get("issued")))

    tracker = Tracker(fixture)
    # Событие считается ОДИН раз на комментарий: записей одной задачи много, и
    # счёт по записям печатал бы событий больше, чем прочитано комментариев.
    events_seen: set = set()
    findings = []
    for path, (owner, repo, number), subj_sha, actors, state, issued in judged:
        for c in tracker.comments(owner, repo, number):
            if not isinstance(c, dict):
                continue
            login = (c.get("user") or {}).get("login")
            hdr = event_header(c.get("body") or "")
            if not all(k in hdr for k in REQUIRED_EVENT_FIELDS):
                continue
            events_seen.add((owner, repo, number, c.get("id")))
            if login not in actors or hdr["subject_sha256"] != subj_sha:
                continue
            findings.append(
                "%s: событие полномочия опубликовано — %s (%s, %s, verdict %s), а запись %s, "
                "effective_approval.issued: %s" % (
                    path, c.get("html_url") or c.get("id"), login, c.get("created_at"),
                    hdr.get("verdict"), state, issued))
            break

    tasks = len(tracker.cache)
    out.append("%s: ревизия %s" % (NAME, sha[:12]))
    out.append("осмотрено записей        : %d  (прочих файлов под %s: %d)" % (len(records), REVIEWS, other))
    out.append("  с исполненным событием : %d  (event.status: performed — судит держатель #302)" % performed)
    out.append("  без исполненного       : %d" % (len(records) - performed))
    out.append("    судимо               : %d  (названы задача и учётка)" % len(judged))
    out.append("    задача не названа    : %d  (вердикт без санкции; в вердикт не входит)" % len(untasked_other))
    out.append("    задача не названа, APPROVED: %d" % len(untasked_approved))
    out.append("задач трекера прочитано  : %d · комментариев : %d · событий полномочия распознано : %d"
               % (tasks, tracker.comments_read, len(events_seen)))
    out.append("расхождений              : %d" % len(findings))
    out.extend("  " + f for f in findings)
    if findings:
        out.append("ОТКАЗ: запись молчит об опубликованном событии — дописать блок event и привести "
                   "effective_approval к факту события (отдельным коммитом поверх записи).")
        return RED, out
    if untasked_approved:
        out.extend("  не судимо: " + p for p in untasked_approved)
        raise_lines = out + ["НЕ ВЫПОЛНИЛОСЬ: запись APPROVED не называет задачу — где искать её событие, "
                             "не сказано, и зелёным такой исход не бывает."]
        return UNMET, raise_lines
    out.append("ЗЕЛЁНОЕ: ни одна судимая запись не молчит об опубликованном событии.")
    return GREEN, out


def run(root: str, rev: str, fixture: str | None) -> int:
    try:
        code, lines = judge(root, rev, fixture)
    except Unmet as e:
        print("%s: НЕ ВЫПОЛНИЛОСЬ — %s" % (NAME, e), file=sys.stderr)
        print("  Это не зелёное и не красное: вердикта о записях нет.", file=sys.stderr)
        return UNMET
    stream = sys.stdout if code == GREEN else sys.stderr
    for line in lines:
        print(line, file=stream)
    return code


# ── САМОПРОБА ────────────────────────────────────────────────────────────────
#
# Захваченный ответ API трекера — НАСТОЯЩИЙ, а не сочинённый: два комментария
# задачи PRO-Robotech/kacho#1271 учётки `pointpu`, снятые 2026-09-24
# (`gh api repos/PRO-Robotech/kacho/issues/comments/<id>`), поля урезаны до тех,
# что читает гейт; тело второго — первые 400 знаков. Первый — событие полномочия
# о редакции 4 приёмки Ф5 (`fe558cc8…`), одной из четырёх записей #402. Второй —
# рабочий комментарий той же учётки, где отпечаток упомянут ПРОЗОЙ: событием он не
# является, и гейт обязан это различать.
CAPTURED_EVENT = {
    "id": 5797646399,
    "html_url": "https://github.com/PRO-Robotech/kacho/issues/1271#issuecomment-5797646399",
    "created_at": "2026-09-23T15:26:54Z",
    "user": {"login": "pointpu"},
    "body": "role: acceptance-reviewer\nverdict: APPROVED\n"
            "subject: PRO-Robotech/kaname:docs/engineering/acceptance/recovery-of-access.md\n"
            "subject_revision: 295fc77cf7b6a1c96a8a3a264448ab6527a199a7\n"
            "subject_sha256: fe558cc810e569f456e9b2da1200c4396afaf39ae52450787484e74beaced170\n"
            "\n---\n\nсведение с Ф3 Р10 по kaname#305\n",
}
CAPTURED_OTHER = {
    "id": 5695398606,
    "html_url": "https://github.com/PRO-Robotech/kacho/issues/1271#issuecomment-5695398606",
    "created_at": "2026-09-16T09:42:55Z",
    "user": {"login": "pointpu"},
    "body": "## Перемер посылки перед первой строкой кода (ствол `kaname@a69c79d6`, 2026-09-16)\n\n"
            "Приёмка APPROVED, отпечаток сходится с записью ревью (`e889257f…`). Сделан **один** "
            "сценарийный блок — тот, чьё «Дано» строит сегодняшнее дерево:\n\n**Ф5-10 + Ф5-11 — сдано:** "
            "гейт `TestEveryMailKindHasExactlyOneSender` (`internal/check/mail_kind_sender_parity*.go`), "
            "PR PRO-Robotech/kaname#164. Перепись на стволе: «в",
}
SUBJECT_SHA = "fe558cc810e569f456e9b2da1200c4396afaf39ae52450787484e74beaced170"
SIBLING_SHA = "5b70cc583c7d4d3fc451dd35758d404ee0897410c449ad46c4c1ac1ce864ce3d"
RECORD_PATH = "%s/recovery-of-access/%s.yaml" % (REVIEWS, SUBJECT_SHA)


def silent_record(event_block: str = "", task: str = "PRO-Robotech/kacho#1271", verdict: str = "APPROVED") -> str:
    """Запись в форме четырёх записей #402: publication_pending, issued: false."""
    task_line = "  task: %s\n" % task if task else ""
    return (
        "schema_version: 1\nkind: acceptance_review\nsubject:\n"
        "  repository: PRO-Robotech/kaname\n"
        "  path: docs/engineering/acceptance/recovery-of-access.md\n"
        "  sha256: %s\n%s"
        "verdict: %s\nreviewer_role: acceptance-reviewer\n"
        "effective_approval:\n  issued: false\n  ban1_lifted: false\n"
        "  publication_pending:\n    required_for_sanction: true\n    expected_actor: pointpu\n"
        "authority:\n  authorized_actors: [pointpu]\n%s" % (SUBJECT_SHA, task_line, verdict, event_block))


def self_test() -> int:
    checks, failed = 0, 0
    work = tempfile.mkdtemp(prefix="review-event-silence.")
    try:
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.path.join(work, "gitconfig"), GIT_CONFIG_NOSYSTEM="1")
        with open(env["GIT_CONFIG_GLOBAL"], "w", encoding="utf-8") as fh:
            fh.write("[user]\n\tname = probe\n\temail = probe@example.invalid\n[commit]\n\tgpgsign = false\n")

        def repo(name: str, files: dict) -> str:
            d = os.path.join(work, name)
            os.makedirs(d)
            subprocess.run(["git", "init", "-q", d], check=True, env=env)
            for rel, text in files.items():
                f = os.path.join(d, rel)
                os.makedirs(os.path.dirname(f), exist_ok=True)
                with open(f, "w", encoding="utf-8") as fh:
                    fh.write(text)
            subprocess.run(["git", "-C", d, "add", "-A"], check=True, env=env)
            subprocess.run(["git", "-C", d, "commit", "-q", "--allow-empty", "-m", "#1 фикстура"], check=True, env=env)
            return d

        def fixture(name: str, comments) -> str:
            d = os.path.join(work, name, "PRO-Robotech", "kacho")
            os.makedirs(d)
            if comments is not None:
                with open(os.path.join(d, "1271.json"), "w", encoding="utf-8") as fh:
                    json.dump(comments, fh, ensure_ascii=False)
            return os.path.join(work, name)

        def case(label, root, fx, want, must=()):
            nonlocal checks, failed
            try:
                code, lines = judge(root, "HEAD", fx)
            except Unmet as e:
                code, lines = UNMET, [str(e)]
            text = "\n".join(lines)
            checks += 1
            if code == want and all(s in text for s in must):
                print("  ok   — %s (код %d)" % (label, code))
            else:
                failed += 1
                print("  БЕДА — %s: код %d, ждали %d и %s:\n%s" % (label, code, want, list(must), text), file=sys.stderr)

        with_event = fixture("fx-event", [CAPTURED_OTHER, CAPTURED_EVENT])
        without_event = fixture("fx-none", [CAPTURED_OTHER])
        no_answer = fixture("fx-absent", None)
        # Производные от захваченного события — каждый отличается от него ОДНИМ
        # фактом: отпечаток назван прозой, а не заголовком; автор — не допущенная
        # учётка. Ни то, ни другое санкцией не является.
        prose = dict(CAPTURED_EVENT, id=1, body="обсуждение: запись о subject_sha256 %s ещё не "
                     "опубликована, событие будет отдельным комментарием\n" % SUBJECT_SHA)
        stranger = dict(CAPTURED_EVENT, id=2, user={"login": "someone-else"})
        prose_only = fixture("fx-prose", [CAPTURED_OTHER, prose])
        stranger_only = fixture("fx-stranger", [CAPTURED_OTHER, stranger])
        # У каждого свойства разбора, объявленного в ПРЕДМЕТЕ, — свой близнец, тоже
        # отличающийся от захваченного события ОДНИМ фактом:
        #   отпечаток сверяется — событие той же учётки в той же задаче о СОСЕДНЕЙ
        #     редакции (такое в kacho#1271 есть: 5b70cc58…, комментарий 5707963723);
        #   заголовок кончается первой `---` — поле ниже черты заголовком не является;
        #   нужны все пять полей — по близнецу без каждого из них.
        head, sep, tail = CAPTURED_EVENT["body"].partition("\n---\n")

        def header_without(field: str) -> str:
            return "\n".join(ln for ln in head.split("\n") if not ln.startswith(field + ":")) + sep + tail

        sibling = dict(CAPTURED_EVENT, id=3, body=CAPTURED_EVENT["body"].replace(SUBJECT_SHA, SIBLING_SHA))
        below = dict(CAPTURED_EVENT, id=4, body=header_without("subject_sha256") + "subject_sha256: %s\n" % SUBJECT_SHA)
        sibling_only = fixture("fx-sibling", [CAPTURED_OTHER, sibling])
        below_only = fixture("fx-below", [CAPTURED_OTHER, below])

        silent = repo("silent", {RECORD_PATH: silent_record()})
        case("законный близнец: та же учётка, та же задача, событие о другом отпечатке", silent, sibling_only, GREEN,
             ("расхождений              : 0", "событий полномочия распознано : 1"))
        case("законный близнец: subject_sha256 ниже черты `---`, в заголовке его нет", silent, below_only, GREEN,
             ("расхождений              : 0", "событий полномочия распознано : 0"))
        for field in REQUIRED_EVENT_FIELDS:
            partial = dict(CAPTURED_EVENT, id=5, body=header_without(field))
            case("законный близнец: в заголовке нет поля %s" % field, silent,
                 fixture("fx-without-" + field, [CAPTURED_OTHER, partial]), GREEN,
                 ("расхождений              : 0", "событий полномочия распознано : 0"))
        case("инъекция: без блока event при опубликованном событии", silent, with_event, RED,
             (RECORD_PATH, CAPTURED_EVENT["html_url"], "без блока event", "расхождений              : 1"))
        case("законный близнец: та же запись, в ответе события с этим отпечатком нет", silent, without_event, GREEN,
             ("расхождений              : 0", "судимо               : 1", "событий полномочия распознано : 0"))
        case("законный близнец: отпечаток назван прозой, заголовка события нет", silent, prose_only, GREEN,
             ("расхождений              : 0", "событий полномочия распознано : 0"))
        case("законный близнец: событие опубликовала не допущенная учётка", silent, stranger_only, GREEN,
             ("расхождений              : 0", "событий полномочия распознано : 1"))
        np_rec = repo("notperf", {RECORD_PATH: silent_record(
            "event:\n  type: issue_comment\n  status: not_performed\n")})
        case("инъекция второй формы: event.status: not_performed при опубликованном событии", np_rec, with_event, RED,
             (RECORD_PATH, "event.status: not_performed"))
        none_rec = repo("type-none", {RECORD_PATH: silent_record(
            "event:\n  type: none\n  status: not_performed\n")})
        case("инъекция третьей формы: event.type: none при опубликованном событии", none_rec, with_event, RED,
             (RECORD_PATH, "event.type: none"))
        perf = repo("performed", {RECORD_PATH: silent_record(
            "event:\n  type: issue_comment\n  status: performed\n")})
        case("вне предмета: исполненное событие судит #302, здесь молчание", perf, with_event, GREEN,
             ("с исполненным событием : 1", "судимо               : 0"))
        case("трекер недоступен — не выполнилось, а не зелёное", silent, no_answer, UNMET, ("трекер недоступен",))
        empty = repo("empty", {"README": "нет записей\n"})
        case("пустой обход — не выполнилось", empty, with_event, UNMET, ("обход пуст",))
        untasked = repo("untasked", {RECORD_PATH: silent_record(task="")})
        case("APPROVED без задачи — не выполнилось", untasked, with_event, UNMET, ("не называет задачу", RECORD_PATH))
        untasked_cr = repo("untasked-cr", {RECORD_PATH: silent_record(task="", verdict="CHANGES_REQUESTED")})
        case("без задачи и без санкции — строка переписи, не находка", untasked_cr, with_event, GREEN,
             ("задача не названа    : 1", "судимо               : 0"))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print("%s --self-test: утверждений %d, не сошлось %d" % (NAME, checks, failed))
    if checks == 0:
        print("БЕСПРЕДМЕТНО: ни одного утверждения не исполнено.", file=sys.stderr)
        return UNMET
    return RED if failed else GREEN


def main() -> int:
    ap = argparse.ArgumentParser(prog=NAME, description=__doc__.split("\n")[0])
    ap.add_argument("--rev", default="HEAD", help="ревизия, чьи записи судятся (умолчание HEAD)")
    ap.add_argument("--tracker-fixture", default=None, help="каталог захваченных ответов API трекера")
    ap.add_argument("--self-test", action="store_true", help="самопроба инъекцией и законными близнецами")
    a = ap.parse_args()
    try:
        import yaml  # noqa: F401
    except ImportError:
        print("%s: НЕ ВЫПОЛНИЛОСЬ — нет разборщика YAML (python3-yaml)" % NAME, file=sys.stderr)
        return UNMET
    if a.self_test:
        return self_test()
    root = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True)
    if root.returncode != 0:
        print("%s: НЕ ВЫПОЛНИЛОСЬ — это не рабочая копия git" % NAME, file=sys.stderr)
        return UNMET
    return run(root.stdout.strip(), a.rev, a.tracker_fixture)


if __name__ == "__main__":
    sys.exit(main())
