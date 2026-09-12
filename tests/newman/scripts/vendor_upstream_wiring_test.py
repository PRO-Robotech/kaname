#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Держатель ПРОВЯЗКИ сверки: пин объявлен ОДИН раз, и конвейер сверку ТРЕБУЕТ.

ПРЕДМЕТ — НЕ содержимое копий (его держит `vendor_provenance_test.py`), а УСЛОВИЕ
её сверки с оригиналом. До 2026-09-12 условия не было вовсе: держатель печатал
«сверено с оригиналом 0» и выходил кодом 0, то есть ось «оригинал ушёл вперёд» в
конвейере не измерялась НИ РАЗУ при 14 файлах и 31 объявленной подстановке.
Починка держателя (код 3 вместо молчаливого 0) сама по себе ничего не измеряет:
она лишь ДАЁТ конвейеру возможность потребовать сверку. Требует её конвейер, и
вот это держит настоящая проба.

ЧТО ДЕРЖИТ, ПО ОСЯМ:

  1. ЗАПИСЬ НЕСЁТ ПИН В ГОДНОЙ ФОРМЕ: `upstream.repo` и `upstream.revision` из 40
     шестнадцатеричных знаков. Ревизия-тег или короткий хэш не годятся: тег
     переставляют, короткий хэш коллизует.
  2. ПИН ОБЪЯВЛЕН РОВНО В ОДНОМ МЕСТЕ. Второе объявление разошлось бы с первым
     МОЛЧА: копия сверялась бы с ревизией, из которой её не брали, и оба места
     были бы правы о своём. Предикат — перепись отслеживаемых файлов, несущих
     строку ревизии; их обязан быть ровно один, и это сама запись.
  3. КОНВЕЙЕР СВЕРКУ ТРЕБУЕТ: есть шаг, зовущий держателя с `--require-upstream`.
  4. ТОМУ ЖЕ ШАГУ ДАНО ДЕРЕВО — `KANAME_VENDOR_UPSTREAM` в его `env:` либо в
     тексте его `run:`. Требование без дерева даёт третий исход на каждом прогоне,
     то есть конвейер, который не зеленеет никогда, — и его отключат.
  5. ДЕРЕВО ВЫБИРАЕТСЯ ПО ПИНУ, А НЕ «ПОСЛЕДНЕЕ», И ПИН БЕРЁТСЯ ИЗ ЗАПИСИ.
     Шаг `actions/checkout` с `repository:` в ТОМ ЖЕ задании; и `repository`, и
     `ref` — ВЫРАЖЕНИЯ `${{ steps.<id>.outputs.… }}`, а шаг с этим `<id>` обязан
     ЧИТАТЬ запись (её путь стоит в его `run:`). Литерал вместо выражения и есть
     второе место объявления из оси 2; выражение, ссылающееся на шаг, который
     записи не читает, — то же второе место, лишь спрятанное за подстановкой.
  6. ВЫБОРКА ИДЁТ В ПОДКАТАЛОГ (`path:`) и СТОИТ РАНЬШЕ сверки. Выборка чужого
     дерева в корень затёрла бы рабочую копию службы, а выборка после сверки
     означала бы сверку с тем, чего ещё нет.

ПОЧЕМУ РАЗБОР YAML, А НЕ ПОИСК ПОДСТРОКИ. Строка `--require-upstream`
встречается и в комментариях — в этом файле, в шапке держателя, в объяснениях
самого процесса. Проверка подстрокой зеленела бы на СВОЁМ ЖЕ объяснении: это
ровно тот класс, который корпус ловит. Поэтому судятся узлы разобранного
описания, а её собственная способность упасть доказывается осью, где флаг стоит
ТОЛЬКО в комментарии.

ИСХОДЫ:
    0 — провязка на месте;
    1 — находка;
    2 — беспредметно: нет записи · нет описания процесса · нет средства разбора
        YAML · обход не дал ни одного шага. Это НЕ «ноль находок».

Самопроверка способности упасть — `--self-test`: по каждой оси инъекция с
законным близнецом на синтетическом дереве вне репозитория.

КТО ЭТУ ПРОБУ ИСПОЛНЯЕТ: `.github/scripts/run-python-probes.py` — обходом дерева
по образцу `tests/newman/scripts/*_test.py`, без называния файла по имени. Её
`--self-test` зовётся отдельным шагом процесса, потому что прогонщик зовёт файл
без аргументов, и вердикту нельзя верить прежде доказательства.
"""

import json
import os
import pathlib
import re
import subprocess
import sys

SCRIPTS = pathlib.Path(__file__).resolve().parent
REPO = SCRIPTS.parents[2]

WORKFLOW_REL = ".github/workflows/e2e-newman.yml"
RECORD_REL = "tests/newman/vendor-provenance.json"
HOLDER_NAME = "vendor_provenance_test.py"
REQUIRE_FLAG = "--require-upstream"
UPSTREAM_ENV = "KANAME_VENDOR_UPSTREAM"
CHECKOUT_ACTION = "actions/checkout"
REVISION_FORM = re.compile(r"^[0-9a-f]{40}$")
STEP_OUTPUT = re.compile(r"\$\{\{\s*steps\.([A-Za-z0-9_-]+)\.outputs\.")

# Каталоги, куда обход за вторым объявлением не заходит: индекс git — не файл
# дерева, кэш интерпретатора тоже.
WALK_SKIP = {".git", "__pycache__", "node_modules"}


class Bespredmetno(Exception):
    """Условие не создано: судить нечего, и в успех это не засчитывается."""


def tracked_files(root: pathlib.Path) -> tuple[list[pathlib.Path], str]:
    """Состав для переписи второго объявления — по индексу git, с откатом на ФС.

    Для репозитория авторитет — версионный контроль: то же множество, что у CI на
    свежем checkout'е. В синтетическом дереве самопроверки git отсутствует (и, что
    важнее, обход вверх нашёл бы ЧУЖОЙ репозиторий), поэтому источник выбирается
    по совпадению корня, а не по тому, ответил ли git.
    """
    try:
        top = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, timeout=60).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        top = ""
    if top and pathlib.Path(top).resolve() == root.resolve():
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                             capture_output=True, text=True, timeout=120, check=True).stdout
        return [root / n for n in out.split("\0") if n], "индекс git"
    found = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in WALK_SKIP]
        for f in files:
            found.append(pathlib.Path(dirpath) / f)
    return sorted(found), "обход файловой системы"


def load_workflow(root: pathlib.Path) -> dict:
    try:
        import yaml
    except ImportError as exc:
        raise Bespredmetno(
            f"нет средства разбора YAML ({exc}) — описание процесса НЕ ЧИТАЛОСЬ. "
            f"Поставьте pyyaml: `python3 -m pip install pyyaml`. Поиск подстрокой "
            f"здесь не годится: флаг встречается в комментариях.") from exc
    path = root / WORKFLOW_REL
    if not path.is_file():
        raise Bespredmetno(f"описания процесса нет по адресу {path}")
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
        raise Bespredmetno(f"{WORKFLOW_REL}: разобранное описание не несёт заданий")
    return doc


def judge(root: pathlib.Path) -> tuple[list[str], dict]:
    findings: list[str] = []

    record_path = root / RECORD_REL
    if not record_path.is_file():
        raise Bespredmetno(f"записи вендоринга нет по адресу {record_path}")
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise Bespredmetno(f"запись вендоринга нечитаема: {exc}") from exc

    upstream = record.get("upstream") or {}
    repo, revision = str(upstream.get("repo", "")), str(upstream.get("revision", ""))

    # ── ОСЬ 1: форма пина.
    if not repo:
        findings.append(f"{RECORD_REL}: запись не называет репозиторий оригинала "
                        f"(upstream.repo) — сверять не с чем")
    if not REVISION_FORM.match(revision):
        findings.append(
            f"{RECORD_REL}: ревизия оригинала «{revision or '—'}» не в форме полного "
            f"хэша (40 шестнадцатеричных знаков). Тег переставляют, короткий хэш "
            f"коллузирует — пин, который можно передвинуть, пином не является")

    # ── ОСЬ 2: пин объявлен ровно в одном месте.
    files, source = tracked_files(root)
    needle = revision.encode() if revision else b""
    carriers: list[str] = []
    scanned = 0
    if needle:
        for path in files:
            try:
                blob = path.read_bytes()
            except OSError:
                continue
            scanned += 1
            if needle in blob:
                carriers.append(str(path.relative_to(root)))
    if scanned == 0:
        raise Bespredmetno(
            f"по составу из «{source}» не прочитано ни одного файла — перепись "
            f"второго объявления пуста, и это не «ноль находок»")
    if len(carriers) > 1:
        findings.append(
            f"ревизия оригинала объявлена в {len(carriers)} местах: "
            f"{', '.join(sorted(carriers))}. Второе место разойдётся с первым МОЛЧА — "
            f"копия сверялась бы с ревизией, из которой её не брали")
    elif carriers and carriers[0] != RECORD_REL:
        findings.append(
            f"ревизия оригинала объявлена в {carriers[0]}, а не в записи вендоринга "
            f"({RECORD_REL}) — у пина обязан быть один дом, и это дом записи")

    # ── ОСИ 3-6: провязка в описании процесса.
    workflow = load_workflow(root)
    jobs = workflow["jobs"]
    steps_seen = 0
    require_at: list[tuple[str, int, dict]] = []
    plain_at: list[tuple[str, int, dict]] = []
    for job_name, job in jobs.items():
        for idx, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict):
                continue
            steps_seen += 1
            run = str(step.get("run") or "")
            if HOLDER_NAME in run:
                (require_at if REQUIRE_FLAG in run else plain_at).append((job_name, idx, step))
    if steps_seen == 0:
        raise Bespredmetno(f"{WORKFLOW_REL}: обход не дал ни одного шага")

    if not require_at:
        where = (f" (держателя зовут без него в задании «{plain_at[0][0]}»)"
                 if plain_at else "")
        findings.append(
            f"{WORKFLOW_REL}: ни один шаг не зовёт {HOLDER_NAME} с {REQUIRE_FLAG}{where} — "
            f"значит ось «оригинал ушёл вперёд» конвейером НЕ ИЗМЕРЯЕТСЯ, а её "
            f"неизмеренность даёт код 0 и неотличима от измеренной")

    for job_name, idx, step in require_at:
        env = step.get("env") or {}
        run = str(step.get("run") or "")
        if UPSTREAM_ENV not in env and UPSTREAM_ENV not in run:
            findings.append(
                f"{WORKFLOW_REL}: задание «{job_name}», шаг {idx}: сверка потребована, "
                f"а дерево не дано — {UPSTREAM_ENV} нет ни в env:, ни в run:. Такой шаг "
                f"выдаёт третий исход на КАЖДОМ прогоне, и его отключат")

        job_steps = [st for st in (jobs[job_name].get("steps") or []) if isinstance(st, dict)]
        by_id = {str(st.get("id")): st for st in job_steps if st.get("id")}
        checkouts = [(jdx, st.get("with") or {}) for jdx, st in enumerate(job_steps)
                     if str(st.get("uses") or "").startswith(CHECKOUT_ACTION)
                     and "repository" in (st.get("with") or {})]
        if not checkouts:
            findings.append(
                f"{WORKFLOW_REL}: задание «{job_name}»: сверка потребована, а шага "
                f"{CHECKOUT_ACTION} с repository: в задании нет — дерево оригинала браться "
                f"неоткуда, и «условие не создано» станет вечным исходом")
            continue
        for jdx, with_ in checkouts:
            for key in ("repository", "ref"):
                raw = str(with_.get(key, ""))
                ids = STEP_OUTPUT.findall(raw)
                if not ids:
                    if key == "repository" and raw == repo and repo:
                        # Литеральное имя репозитория — не пин: его не переставляют
                        # каждый день. Но и оно обязано совпадать с записью, иначе
                        # сверка шла бы с ЧУЖИМ деревом при сходящихся именах файлов.
                        continue
                    findings.append(
                        f"{WORKFLOW_REL}: задание «{job_name}», шаг {jdx}: {key} «{raw or '—'}» — "
                        f"литерал, а не выражение из записи. Пин обязан читаться из "
                        f"{RECORD_REL} в прогоне: литерал здесь и есть второе место объявления")
                    continue
                for sid in ids:
                    producer = by_id.get(sid)
                    if producer is None:
                        findings.append(
                            f"{WORKFLOW_REL}: задание «{job_name}», шаг {jdx}: {key} ссылается "
                            f"на шаг id «{sid}», которого в задании нет — подстановка выйдет пустой")
                    elif RECORD_REL not in str(producer.get("run") or ""):
                        findings.append(
                            f"{WORKFLOW_REL}: задание «{job_name}», шаг {jdx}: {key} берётся из "
                            f"шага «{sid}», который {RECORD_REL} НЕ ЧИТАЕТ — значит пин взят не "
                            f"из записи, и это второе место объявления за подстановкой")
            if not str(with_.get("path", "")).strip():
                findings.append(
                    f"{WORKFLOW_REL}: задание «{job_name}», шаг {jdx}: у выборки оригинала "
                    f"нет path: — чужое дерево легло бы в корень и затёрло рабочую копию службы")
            if jdx > idx:
                findings.append(
                    f"{WORKFLOW_REL}: задание «{job_name}»: выборка оригинала (шаг {jdx}) "
                    f"стоит ПОСЛЕ сверки (шаг {idx}) — сверять было бы нечего")

    census = {"файлов осмотрено": scanned, "источник состава": source,
              "заданий": len(jobs), "шагов": steps_seen,
              "мест объявления ревизии": len(carriers),
              "шагов с требованием сверки": len(require_at)}
    return findings, census


def verdict(root: pathlib.Path) -> int:
    try:
        findings, census = judge(root)
    except Bespredmetno as exc:
        print(f"БЕСПРЕДМЕТНО: {exc}", file=sys.stderr)
        print("Это НЕ «ноль находок»: вердикта о провязке сверки нет вовсе.", file=sys.stderr)
        return 2
    print("перепись: " + " · ".join(f"{k} {v}" for k, v in census.items()))
    if findings:
        print(f"НАХОДОК {len(findings)}:", file=sys.stderr)
        for f in findings:
            print(f"  · {f}", file=sys.stderr)
        return 1
    print("ЧИСТО: пин объявлен один раз, конвейер сверку ТРЕБУЕТ, дерево берётся "
          "по пину в подкаталог и раньше сверки.")
    return 0


# ─────────────────────────── доказательство способности упасть ───────────────

GOOD_WORKFLOW = """
name: e2e-newman
on:
  push:
    branches: [main]
jobs:
  suite:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - name: ревизия платформы
        id: vendor-pin
        run: jq -r .upstream.revision tests/newman/vendor-provenance.json >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v7
        with:
          repository: ${{ steps.vendor-pin.outputs.repo }}
          ref: ${{ steps.vendor-pin.outputs.revision }}
          path: upstream-kacho
      - name: вендоренный слой сходится с записью и с оригиналом
        env:
          KANAME_VENDOR_UPSTREAM: upstream-kacho
        run: python3 tests/newman/scripts/vendor_provenance_test.py --require-upstream
"""

REV_A = "a" * 40


def _build(root: pathlib.Path, *, revision: str = REV_A, repo: str = "PRO-Robotech/kacho",
           workflow: str | None = None, extra: dict[str, str] | None = None) -> None:
    (root / "tests/newman").mkdir(parents=True)
    (root / ".github/workflows").mkdir(parents=True)
    (root / RECORD_REL).write_text(json.dumps(
        {"upstream": {"repo": repo, "revision": revision},
         "files": [{"path": "tests/newman/kacholib/stems.sh"}]}, ensure_ascii=False), encoding="utf-8")
    body = GOOD_WORKFLOW if workflow is None else workflow
    (root / WORKFLOW_REL).write_text(body.replace("${REPO}", repo), encoding="utf-8")
    for rel, text in (extra or {}).items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")


FAILURES: list[str] = []


def _check(name: str, want: int, root: pathlib.Path, needle: str = "") -> None:
    import contextlib
    import io
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = verdict(root)
    text = out.getvalue() + err.getvalue()
    ok = rc == want and (not needle or needle in text)
    print(f"  {'ok  ' if ok else 'FAIL'} {name} (код {rc})")
    if not ok:
        FAILURES.append(f"{name}: " + (f"ожидался код {want}, получен {rc}"
                                       if rc != want else f"в выводе нет «{needle}»"))
        for line in text.splitlines()[:10]:
            print(f"    {line}")


def self_test() -> int:
    import tempfile
    print("провязка сверки: доказательство способности упасть")
    with tempfile.TemporaryDirectory(prefix="kaname-vendor-wiring-") as tmp:
        base = pathlib.Path(tmp)

        # КОНТРОЛЬ: правильно провязанное дерево молчит. Без него всё ниже
        # зеленело бы на пробе, которая краснеет всегда.
        t = base / "control"; _build(t)
        _check("контроль: провязка на месте — код 0", 0, t, "ЧИСТО")

        t = base / "second-home"; _build(t, extra={"docs/wiring.md": f"пин {REV_A}\n"})
        _check("ревизия названа ВТОРЫМ местом — находка с обоими адресами", 1, t,
               "объявлена в 2 местах")

        #    ЗАКОННЫЙ БЛИЗНЕЦ: второй файл есть, но ревизии не несёт — молчит.
        t = base / "second-home-twin"; _build(t, extra={"docs/wiring.md": "пин читается из записи\n"})
        _check("посторонний файл без ревизии — НЕ находка", 0, t, "ЧИСТО")

        t = base / "literal-ref"
        _build(t, workflow=GOOD_WORKFLOW.replace(
            "ref: ${{ steps.vendor-pin.outputs.revision }}", f"ref: {REV_A}"))
        _check("ref литералом — находка (и это второе место объявления)", 1, t, "литерал")

        #    ЗАКОННЫЙ БЛИЗНЕЦ: repository литералом, равным записи, — НЕ находка.
        #    Имя репозитория не пин: его не переставляют, и второго значения у него
        #    в записи нет. Красное здесь означало бы запрет по форме, а не по делу.
        t = base / "literal-repo-twin"
        _build(t, workflow=GOOD_WORKFLOW.replace(
            "repository: ${{ steps.vendor-pin.outputs.repo }}", "repository: ${REPO}"))
        _check("repository литералом, равным записи — НЕ находка", 0, t, "ЧИСТО")

        #    А вот ЧУЖОЕ имя репозитория — находка: имена файлов сошлись бы, и
        #    сверка шла бы с чужим деревом молча.
        t = base / "alien-repo"
        _build(t, workflow=GOOD_WORKFLOW.replace(
            "repository: ${{ steps.vendor-pin.outputs.repo }}",
            "repository: PRO-Robotech/kaname"))
        _check("repository литералом, ЧУЖИМ записи — находка", 1, t, "литерал")

        #    ПИН ЗА ПОДСТАНОВКОЙ, НО НЕ ИЗ ЗАПИСИ: выражение ссылается на шаг,
        #    который записи не читает. Форма правильная, дом пина — второй.
        t = base / "expr-not-from-record"
        _build(t, workflow=GOOD_WORKFLOW.replace(
            'run: jq -r .upstream.revision tests/newman/vendor-provenance.json >> "$GITHUB_OUTPUT"',
            'run: echo "revision=deadbeef" >> "$GITHUB_OUTPUT"'))
        _check("выражение из шага, который записи НЕ ЧИТАЕТ — находка", 1, t,
               "НЕ ЧИТАЕТ")

        #    И ссылка на шаг, которого в задании нет.
        t = base / "expr-dangling"
        _build(t, workflow=GOOD_WORKFLOW.replace("steps.vendor-pin.outputs.revision",
                                                 "steps.no-such-step.outputs.revision"))
        _check("выражение ссылается на несуществующий шаг — находка", 1, t,
               "которого в задании нет")

        t = base / "no-require"
        _build(t, workflow=GOOD_WORKFLOW.replace(" --require-upstream", ""))
        _check("держателя зовут БЕЗ требования сверки — находка", 1, t,
               "ни один шаг не зовёт")

        # КЛЮЧЕВАЯ ОСЬ: флаг стоит ТОЛЬКО в комментарии. Проверка подстрокой
        # зеленела бы здесь — то есть на собственном объяснении процесса.
        t = base / "flag-in-comment"
        _build(t, workflow=GOOD_WORKFLOW.replace(
            "        run: python3 tests/newman/scripts/vendor_provenance_test.py --require-upstream",
            "        # сверка идёт с --require-upstream, см. шапку держателя\n"
            "        run: python3 tests/newman/scripts/vendor_provenance_test.py"))
        _check("флаг только в КОММЕНТАРИИ — находка (читается разобранный YAML)", 1, t,
               "ни один шаг не зовёт")

        t = base / "no-env"
        _build(t, workflow=GOOD_WORKFLOW.replace(
            "        env:\n          KANAME_VENDOR_UPSTREAM: upstream-kacho\n", ""))
        _check("сверка потребована, дерево не дано — находка", 1, t, "дерево не дано")

        t = base / "no-checkout"
        _build(t, workflow=GOOD_WORKFLOW.replace(
            "      - uses: actions/checkout@v7\n        with:\n"
            "          repository: ${{ steps.vendor-pin.outputs.repo }}\n"
            "          ref: ${{ steps.vendor-pin.outputs.revision }}\n"
            "          path: upstream-kacho\n", ""))
        _check("выборки оригинала в задании нет — находка", 1, t, "браться неоткуда")

        t = base / "no-path"
        _build(t, workflow=GOOD_WORKFLOW.replace("          path: upstream-kacho\n", ""))
        _check("выборка без path: — находка (затёрла бы копию службы)", 1, t, "нет path:")

        t = base / "checkout-after"
        _build(t, workflow=GOOD_WORKFLOW.replace(
            "      - uses: actions/checkout@v7\n        with:\n"
            "          repository: ${{ steps.vendor-pin.outputs.repo }}\n"
            "          ref: ${{ steps.vendor-pin.outputs.revision }}\n"
            "          path: upstream-kacho\n", "") + """      - uses: actions/checkout@v7
        with:
          repository: ${{ steps.vendor-pin.outputs.repo }}
          ref: ${{ steps.vendor-pin.outputs.revision }}
          path: upstream-kacho
""")
        _check("выборка ПОСЛЕ сверки — находка", 1, t, "стоит ПОСЛЕ сверки")

        t = base / "short-rev"; _build(t, revision="370c154d")
        _check("ревизия коротким хэшем — находка", 1, t, "не в форме полного хэша")

        t = base / "no-record"; _build(t); (t / RECORD_REL).unlink()
        _check("записи нет — код 2, а НЕ 1 и НЕ 0", 2, t, "БЕСПРЕДМЕТНО")

        t = base / "no-workflow"; _build(t); (t / WORKFLOW_REL).unlink()
        _check("описания процесса нет — код 2", 2, t, "БЕСПРЕДМЕТНО")

        t = base / "no-steps"
        _build(t, workflow="name: x\njobs:\n  suite:\n    runs-on: ubuntu-latest\n    steps: []\n")
        _check("обход не дал ни одного шага — код 2, а НЕ 0", 2, t, "ни одного шага")

    if FAILURES:
        print(f"\nПРОВАЛЕНО утверждений: {len(FAILURES)}", file=sys.stderr)
        for f in FAILURES:
            print(f"  · {f}", file=sys.stderr)
        return 1
    print("\nВСЕ утверждения сошлись: проба провязки падает там, где должна, "
          "и молчит на законных близнецах.")
    return 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()
    return verdict(REPO)


if __name__ == "__main__":
    sys.exit(main())
