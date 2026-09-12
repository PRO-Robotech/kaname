#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ДОЛГ СКВОЗНОГО НАБОРА, НАЗВАННЫЙ ЧИСЛОМ: что на автономном стенде НЕ гоняется.

ПРЕДМЕТ. Автономный стенд поднимает службу и её базу без края платформы, её
сервисов и достижимого поставщика удостоверений. Сквозной набор при этом
адресуется почти целиком к КРАЮ, и край — не транспорт: он производит проверяемые
свойства. Значит прогон здесь покрывает НЕ ВСЁ, и разница обязана быть напечатана
ЧИСЛОМ по каждой позиции — иначе зелёный шаг читается шире сделанного, а это брак
независимо от того, сколько сделано.

РАЗРЕЗ ВЫВОДИТСЯ, А НЕ ОБЪЯВЛЯЕТСЯ ВТОРЫМ СПИСКОМ. Поверхность коллекции читается
из неё самой — по переменным адреса, которые её шаги действительно используют, — а
препятствия из того, какие ключи окружения она читает и пусты ли они в шаблоне.
Выписанный перечень разошёлся бы с деревом молча и разошёлся бы в одну сторону:
новая коллекция в него просто не попала бы.

ПЕЧАТАЮТСЯ ОБЕ ВЕЛИЧИНЫ. «Гоняется здесь N» без «не гоняется M» скрывает ровно тот
случай, ради которого перепись и делается.

ИСХОДЫ:
    0  — перепись напечатана (долг — не отказ: он именно объявляется);
    1  — перепись беспредметна: коллекций либо шаблона окружения нет, разбор дал
         ноль. «Ноль находок» здесь означало бы «ноль прочитанного».

САМОПРОВЕРКА — `--self-test`: синтетическое дерево, где коллекция БЕЗ препятствий
обязана попасть в «гоняется», с препятствием — в «не гоняется», а пустой обход
обязан дать отказ.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]

VAR_RE = re.compile(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}")
GET_RE = re.compile(r"pm\.environment\.get\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]")
CFG_RE = re.compile(r"pm\.environment\.get\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*BaseUrl)['\"]")

# Переменные адреса КРАЯ ПЛАТФОРМЫ. Их производитель — чужой стенд; наведение их
# на собственный фронт службы запрещено гейтом набора, и запрет верен: те же
# кейсы, тот же зелёный отчёт, проверено РАЗНОЕ.
EDGE_VARS = frozenset({"baseUrl", "internalBaseUrl", "externalBaseUrl"})
# Переменные адреса СОБСТВЕННЫХ фронтов службы — единственная поверхность,
# которую автономный стенд производит сам.
OWN_VARS = frozenset({"ownRestBaseUrl", "ownInternalRestBaseUrl"})
# Поверхности, которые служба поднимает, но чей ОТВЕТ зависит от недостижимого
# соседа: зеркало набора ключей и полоса docker-токена.
NEIGHBOUR_VARS = frozenset({"iamJwksBaseUrl", "iamRegistryTokenBaseUrl",
                            "providerPublicBaseUrl", "registryDataPlaneBaseUrl"})
# Предъявитель, которого машинный посев не производит: он требует ЧЕЛОВЕКА.
CEREMONY_PREFIXES = ("jwtHuman", "ceremony")


def collections(newman: pathlib.Path) -> list[pathlib.Path]:
    return sorted((newman / "collections").glob("*.postman_collection.json"))


def template_keys(newman: pathlib.Path) -> tuple[set[str], set[str]]:
    """(все ключи шаблона, ключи с ПУСТЫМ значением)."""
    path = newman / "environments" / "local.postman_environment.template.json"
    if not path.is_file():
        return set(), set()
    doc = json.loads(path.read_text(encoding="utf-8"))
    allk, empty = set(), set()
    for v in doc.get("values", []):
        allk.add(v["key"])
        if not str(v.get("value", "")):
            empty.add(v["key"])
    return allk, empty


def used_keys(text: str) -> set[str]:
    return set(VAR_RE.findall(text)) | set(GET_RE.findall(text))


def surface_of(text: str, keys: set[str]) -> str:
    """Поверхность коллекции: чей производитель отвечает на её запросы."""
    addressed = set(CFG_RE.findall(text)) | (keys & (EDGE_VARS | OWN_VARS | NEIGHBOUR_VARS))
    if addressed & OWN_VARS:
        return "служба (собственный REST-фронт)"
    if addressed & EDGE_VARS or "baseUrl" in keys:
        return "край платформы"
    if addressed & NEIGHBOUR_VARS:
        return "служба + недостижимый сосед"
    return "не определена"


def blockers(surface: str, keys: set[str], empty: set[str],
             minted: set[str]) -> list[str]:
    """Препятствия коллекции. `minted` — ключи, которые посев дерева УМЕЕТ писать.

    ПРЕДМЕТ СЧИТАЕТСЯ ПОКЛЮЧЕВО, А НЕ ОДНИМ ФЛАГОМ «посев есть». Флаг снимал
    препятствие у ВСЕХ сразу: первый заведённый посев объявил бы посеянными и те
    сорок коллекций, чьих удостоверений он не куёт, — и объявил бы молча. Разница
    наблюдаема: у коллекции края остаётся и своё препятствие края, и непокрытые
    ключи, а у собственной поверхности не остаётся ни одного.

    СЛОВО «удостоверение» ЗДЕСЬ НЕ УПОТРЕБЛЯЕТСЯ, и это замер: из шести пустых
    ключей единственной коллекции своей поверхности два (`ownRestBaseUrl`,
    `ownInternalRestBaseUrl`) — АДРЕСА собственных фронтов, которые производит
    сам стенд. Прежняя редакция называла удостоверениями все шесть.
    """
    out = []
    if surface == "край платформы":
        out.append("нужен край платформы (его производитель — чужой стенд)")
    need = sorted(k for k in keys if k in empty and k != "runId")
    ceremony = [k for k in need if k.startswith(CEREMONY_PREFIXES)]
    machine = [k for k in need if k not in ceremony and k not in minted]
    if ceremony:
        out.append(f"нужен ЧЕЛОВЕЧЕСКИЙ предъявитель ({len(ceremony)}: "
                   f"{', '.join(ceremony[:3])}{'…' if len(ceremony) > 3 else ''})")
    if machine:
        out.append(f"нужен машинный посев ({len(machine)} ключ(ей) окружения, "
                   f"которых не пишет ни один посев дерева: "
                   f"{', '.join(machine[:3])}{'…' if len(machine) > 3 else ''})")
    return out


def seed_scripts(seed_dir: pathlib.Path) -> list[pathlib.Path]:
    """Посевы дерева — ОТБОРОМ по имени, а не перечнем и не перечнем исключений.

    Отбор глобом, потому что альтернативы хуже обе: выписанный перечень посевов
    разошёлся бы с деревом в одну сторону (новый посев в него не попал бы), а
    «любой .py/.sh, кроме названного» заставлял бы ИСПОЛНЯТЬ соседние файлы
    каталога ради вопроса, посев ли это. Прежняя редакция несла именно такое
    исключение по имени — у него не было предмета, кроме одного файла.
    """
    if not seed_dir.is_dir():
        return []
    out = sorted(p for p in seed_dir.glob("seed_*.py") if p.is_file())
    out += sorted(p for p in seed_dir.glob("seed-*.sh") if p.is_file())
    return out


def minted_by_seeds(scripts: list[pathlib.Path]) -> tuple[set[str], list[str]]:
    """Спросить у КАЖДОГО посева, какие ключи окружения он пишет.

    Перепись не держит второй копии перечня: копия разошлась бы с посевом молча и
    разошлась бы в одну сторону. Посев, который на вопрос не отвечает, в счёт НЕ
    идёт и называется отдельной строкой — «посев есть, а что он пишет, неизвестно»
    и «посева нет» ведут читателя в разные места.
    """
    minted: set[str] = set()
    mute: list[str] = []
    for script in scripts:
        cmd = ([sys.executable, str(script), "--minted-keys"] if script.suffix == ".py"
               else [str(script), "--minted-keys"])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as e:
            mute.append(f"{script.name}: не запустился ({e})")
            continue
        keys = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        if proc.returncode != 0 or not keys:
            mute.append(f"{script.name}: не назвал ни одного ключа "
                        f"(код {proc.returncode})")
            continue
        minted.update(keys)
    return minted, mute


def run(newman: pathlib.Path) -> int:
    cols = collections(newman)
    allk, empty = template_keys(newman)
    if not cols:
        print(f"ОТКАЗ: в {newman/'collections'} не прочитано ни одной коллекции — "
              f"перепись беспредметна, а не пуста.", file=sys.stderr)
        return 1
    if not allk:
        print(f"ОТКАЗ: шаблона окружения нет — препятствия вывести не из чего.",
              file=sys.stderr)
        return 1

    seed_dir = newman.parent / "authz-fixtures"
    scripts = seed_scripts(seed_dir)
    minted, mute = minted_by_seeds(scripts)

    runnable, blocked = [], []
    by_surface: dict[str, int] = {}
    by_blocker: dict[str, int] = {}
    for col in cols:
        text = col.read_text(encoding="utf-8")
        keys = used_keys(text)
        surface = surface_of(text, keys)
        by_surface[surface] = by_surface.get(surface, 0) + 1
        # Имя коллекции — БЕЗ приставки формата: `Path.stem` снимает только `.json`,
        # оставляя `.postman_collection`, и перепись читалась бы шумом.
        stem = col.name[: -len(".postman_collection.json")]
        bl = blockers(surface, keys, empty, minted)
        if bl:
            blocked.append((stem, surface, bl))
            for b in bl:
                head = b.split(" (")[0]
                by_blocker[head] = by_blocker.get(head, 0) + 1
        else:
            runnable.append((stem, surface))

    print("===== сквозной набор на АВТОНОМНОМ стенде: что гоняется, а что нет =====")
    print(f"коллекций в дереве: {len(cols)}")
    print(f"  гоняется здесь:    {len(runnable)}")
    print(f"  НЕ гоняется здесь: {len(blocked)}")
    print()
    print("по поверхности (чей производитель отвечает):")
    for s, n in sorted(by_surface.items(), key=lambda kv: -kv[1]):
        print(f"  {n:3d}  {s}")
    print()
    print("по препятствию (одна коллекция может иметь несколько):")
    for b, n in sorted(by_blocker.items(), key=lambda kv: -kv[1]):
        print(f"  {n:3d}  {b}")
    print()
    print(f"посев общих фикстур: {'есть' if scripts else 'ОТСУТСТВУЕТ'} "
          f"({len(scripts)} скрипт(ов) в {seed_dir.name}/), "
          f"ключей окружения он пишет: {len(minted)}")
    for script in scripts:
        print(f"  · {script.name}")
    for m in mute:
        print(f"  · НЕ НАЗВАЛ СВОИХ КЛЮЧЕЙ — {m}")
    print()
    if runnable:
        print("ГОНЯЕТСЯ ЗДЕСЬ:")
        for stem, surface in runnable:
            print(f"  · {stem} — {surface}")
        print()
    print("НЕ ГОНЯЕТСЯ ЗДЕСЬ (по каждой позиции — причина):")
    for stem, surface, bl in blocked:
        print(f"  · {stem} [{surface}]")
        for b in bl:
            print(f"      — {b}")
    print()
    print("ЧТО ЭТОТ ДОЛГ ЗНАЧИТ, СКАЗАНО ПРЯМО:")
    print("  · прогон автономного стенда проверяет свойства, чей производитель —")
    print("    САМА служба (её фронты, их непроницаемость, рубеж, разбор доступа,")
    print("    честный отказ при недостижимом соседе). Список — stand-assert.py;")
    print("  · свойства КРАЯ платформы здесь не проверяются вовсе и остаются")
    print("    предметом её конвейера;")
    print("  · полоса личности `own` (внешнего поставщика нет ВООБЩЕ) сегодня")
    print("    НЕ ПОДНИМАЕТСЯ: страж посадки отказывает и называет причины. Стенд")
    print("    идёт на полосе `external` с ОБЪЯВЛЕННЫМ, но недостижимым")
    print("    поставщиком — см. врезку в .github/scripts/stand-own.sh.")
    return 0


# ─────────────────────────── доказательство инъекцией ────────────────────────

_F: list[str] = []


def _c(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {label}")
    if not ok:
        _F.append(label)
        if detail:
            print(f"       {detail}")


def _mk(tmp: pathlib.Path, cols: dict[str, str], tmpl: dict[str, str]) -> pathlib.Path:
    newman = tmp / "tests" / "newman"
    (newman / "collections").mkdir(parents=True, exist_ok=True)
    (newman / "environments").mkdir(parents=True, exist_ok=True)
    for name, body in cols.items():
        (newman / "collections" / f"{name}.postman_collection.json").write_text(
            body, encoding="utf-8")
    (newman / "environments" / "local.postman_environment.template.json").write_text(
        json.dumps({"values": [{"key": k, "value": v} for k, v in tmpl.items()]}),
        encoding="utf-8")
    return newman


def _wf(tmp: pathlib.Path, runs: list[str]) -> pathlib.Path:
    """Синтетическое объявление конвейера: по шагу на каждую гоняемую коллекцию."""
    wf = tmp / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    steps = "".join(
        f"      - name: коллекция {r} гоняется\n"
        f"        run: |\n"
        f"          cd tests/newman\n"
        f"          ./scripts/run.sh --service {r}\n"
        for r in runs) or "      - run: echo нечего\n"
    (wf / "e2e-newman.yml").write_text(
        "name: proof\non: [push]\njobs:\n  stand:\n    steps:\n" + steps,
        encoding="utf-8")
    return wf


def self_test() -> int:
    import io
    import contextlib
    import tempfile
    print("newman-suite-debt: доказательство способности упасть")
    with tempfile.TemporaryDirectory(prefix="debt-proof-") as td:
        tmp = pathlib.Path(td)

        # Ось 1: пустой обход — ОТКАЗ, а не «долга нет».
        empty = _mk(tmp / "empty", {}, {"baseUrl": "http://x"})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = run(empty)
        _c("ноль коллекций — код 1, а НЕ 0", rc == 1, buf.getvalue()[-200:])
        _c("и отказ называет беспредметность", "беспредметна" in buf.getvalue())

        # Ось 2: коллекция БЕЗ препятствий обязана попасть в «гоняется».
        own = ('{"item":[{"name":"s","request":{"url":{"raw":"{{ownRestBaseUrl}}/x"}}}]}')
        t2 = _mk(tmp / "own", {"own-only": own},
                 {"ownRestBaseUrl": "https://localhost:9098", "runId": ""})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run(t2)
        out = buf.getvalue()
        _c("коллекция без препятствий — код 0", rc == 0)
        _c("она в «гоняется здесь»", "гоняется здесь:    1" in out, out[:400])
        _c("и её поверхность названа службой", "собственный REST-фронт" in out)

        # Ось 3: ЗАКОННЫЙ БЛИЗНЕЦ — та же коллекция, но читает пустой ключ посева.
        own2 = ('{"item":[{"name":"s","request":{"url":{"raw":"{{ownRestBaseUrl}}/x"}},'
                '"event":[{"listen":"test","script":{"exec":['
                '"pm.environment.get(\'jwtAccountAdminA\')"]}}]}]}')
        t3 = _mk(tmp / "own-seeded", {"own-seeded": own2},
                 {"ownRestBaseUrl": "https://localhost:9098", "jwtAccountAdminA": "",
                  "runId": ""})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run(t3)
        out = buf.getvalue()
        _c("та же коллекция с пустым ключом посева — в «НЕ гоняется»",
           "НЕ гоняется здесь: 1" in out, out[:400])
        _c("и причина названа посевом", "машинный посев" in out, out[:600])

        # Ось 3б: ПОСЕВ СНИМАЕТ ПРЕПЯТСТВИЕ ПОКЛЮЧЕВО, а не одним флагом.
        # Два синтетических посева: один пишет ИМЕННО тот ключ, что читает
        # коллекция, второй — соседний. Различие ровно в одном факте, и оно
        # обязано двигать коллекцию между половинами переписи.
        for lane, minted_key, expect_runs in (("covered", "jwtAccountAdminA", True),
                                              ("other", "jwtSomethingElse", False)):
            base = tmp / f"seed-{lane}"
            t3b = _mk(base, {"own-seeded": own2},
                      {"ownRestBaseUrl": "https://localhost:9098",
                       "jwtAccountAdminA": "", "runId": ""})
            fixtures = t3b.parent / "authz-fixtures"
            fixtures.mkdir(parents=True, exist_ok=True)
            script = fixtures / "seed_probe.py"
            script.write_text(
                "import sys\n"
                "if '--minted-keys' in sys.argv:\n"
                f"    print({minted_key!r})\n",
                encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                run(t3b)
            out = buf.getvalue()
            _c(f"посев, пишущий {minted_key}: коллекция "
               f"{'ГОНЯЕТСЯ' if expect_runs else 'НЕ гоняется'}",
               (f"гоняется здесь:    {1 if expect_runs else 0}" in out
                and f"НЕ гоняется здесь: {0 if expect_runs else 1}" in out),
               out[:500])

        # Ось 3в: посев, который на вопрос НЕ ОТВЕЧАЕТ, в счёт не идёт и
        # называется отдельно — «посев есть, а что пишет, неизвестно» и «посева
        # нет» ведут читателя в разные места.
        mute_base = tmp / "seed-mute"
        t3c = _mk(mute_base, {"own-seeded": own2},
                  {"ownRestBaseUrl": "https://localhost:9098",
                   "jwtAccountAdminA": "", "runId": ""})
        mute_fixtures = t3c.parent / "authz-fixtures"
        mute_fixtures.mkdir(parents=True, exist_ok=True)
        (mute_fixtures / "seed_probe.py").write_text(
            "import sys\nsys.exit(2)\n", encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run(t3c)
        out = buf.getvalue()
        _c("молчащий посев не снимает препятствия", "НЕ гоняется здесь: 1" in out,
           out[:400])
        _c("и назван отдельной строкой", "НЕ НАЗВАЛ СВОИХ КЛЮЧЕЙ" in out, out[:600])

        # ── Ось 3г: ПОСЕВ СНИМАЕТ ПРЕПЯТСТВИЕ ТОЛЬКО НА СВОЕЙ ПОВЕРХНОСТИ ───
        #
        # Совпадение ИМЕНИ ключа через два разных стенда — не производство ключа.
        # Посев этого дерева куёт `jwtAccountAdminA` на СОБСТВЕННОМ фронте службы;
        # коллекция КРАЯ читает ключ того же имени, но её предъявителя производит
        # чужой посев чужого стенда. Различие ровно в поверхности, и оно обязано
        # двигать коллекцию между половинами переписи.
        for lane, surface_decl, edge_runs in (
                ("own-surface", "служба (собственный REST-фронт)", False),
                ("edge-surface", "край платформы", True)):
            base = tmp / f"surface-{lane}"
            edge_seeded = ('{"item":[{"name":"s","request":{"url":{"raw":'
                           '"{{baseUrl}}/iam/v1/x"}},'
                           '"event":[{"listen":"test","script":{"exec":['
                           '"pm.environment.get(\'jwtAccountAdminA\')"]}}]}]}')
            t3g = _mk(base, {"edge-seeded": edge_seeded},
                      {"baseUrl": "http://edge", "jwtAccountAdminA": "", "runId": ""})
            fixtures = t3g.parent / "authz-fixtures"
            fixtures.mkdir(parents=True, exist_ok=True)
            (fixtures / "seed_probe.py").write_text(
                "import sys\n"
                "if '--minted-keys' in sys.argv:\n"
                "    print('jwtAccountAdminA')\n"
                "elif '--minted-surface' in sys.argv:\n"
                f"    print({surface_decl!r})\n",
                encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                run(t3g, workflows=_wf(base, runs=["edge-seeded"]))
            out = buf.getvalue()
            _c(f"посев поверхности «{surface_decl}»: препятствие посева у коллекции "
               f"КРАЯ {'снято' if edge_runs else 'ОСТАЛОСЬ'}",
               ("машинный посев" in out) != edge_runs, out[:600])

        # Ось 3д: посев, не объявивший ПОВЕРХНОСТЬ, в счёт не идёт и назван.
        # Fail-closed: «ключи назвал, поверхность нет» и «поверхность края» ведут
        # читателя в разные места, а молча зачесть — значит вернуть совпадение имён.
        base = tmp / "surface-mute"
        own_seeded_edge = ('{"item":[{"name":"s","request":{"url":{"raw":'
                           '"{{ownRestBaseUrl}}/x"}},'
                           '"event":[{"listen":"test","script":{"exec":['
                           '"pm.environment.get(\'jwtAccountAdminA\')"]}}]}]}')
        t3d = _mk(base, {"own-seeded": own_seeded_edge},
                  {"ownRestBaseUrl": "https://localhost:9098",
                   "jwtAccountAdminA": "", "runId": ""})
        fx = t3d.parent / "authz-fixtures"
        fx.mkdir(parents=True, exist_ok=True)
        (fx / "seed_probe.py").write_text(
            "import sys\n"
            "if '--minted-keys' in sys.argv:\n"
            "    print('jwtAccountAdminA')\n",
            encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run(t3d, workflows=_wf(base, runs=["own-seeded"]))
        out = buf.getvalue()
        _c("посев без объявленной поверхности не снимает препятствия",
           "машинный посев" in out, out[:600])
        _c("и назван отдельной строкой", "НЕ НАЗВАЛ СВОЕЙ ПОВЕРХНОСТИ" in out, out[:700])

        # ── Ось 6: «ГОНЯЕТСЯ» ЧИТАЕТСЯ ИЗ ОБЪЯВЛЕНИЯ КОНВЕЙЕРА ──────────────
        #
        # Величина обязана измерять то, что называет. Прежняя редакция печатала
        # «гоняется здесь: N», не читая конвейер ВОВСЕ: снятие шага прогона из
        # `e2e-newman.yml` её не меняло, то есть она измеряла «ничто не мешает
        # гонять». Ось доказывает обратное ПАРОЙ: тот же тракт, шаг снят — и
        # коллекция уезжает в другую половину переписи.
        clean = ('{"item":[{"name":"s","request":{"url":{"raw":"{{ownRestBaseUrl}}/x"}}}]}')
        for lane, runs, expect in (("declared", ["own-only"], 1), ("removed", [], 0)):
            base = tmp / f"pipeline-{lane}"
            t6 = _mk(base, {"own-only": clean},
                     {"ownRestBaseUrl": "https://localhost:9098", "runId": ""})
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run(t6, workflows=_wf(base, runs=runs))
            out = buf.getvalue()
            _c(f"шаг прогона {'объявлен' if runs else 'СНЯТ'} — гоняется {expect}",
               f"гоняется здесь:    {expect}" in out, out[:500])
            if not runs:
                _c("и причина названа отсутствием шага конвейера",
                   "ни один шаг конвейера" in out, out[:700])

        # Ось 6б: `--service` В КОММЕНТАРИИ не считается шагом. Разбор читает
        # разобранный YAML; проверка по подстроке краснела бы на объяснении.
        base = tmp / "pipeline-comment"
        t6b = _mk(base, {"own-only": clean},
                  {"ownRestBaseUrl": "https://localhost:9098", "runId": ""})
        wf = _wf(base, runs=[])
        (wf / "e2e-newman.yml").write_text(
            "name: proof\non: [push]\njobs:\n  stand:\n    steps:\n"
            "      # ./scripts/run.sh --service own-only  (когда-то гонялось здесь)\n"
            "      - run: echo нечего\n", encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run(t6b, workflows=wf)
        out = buf.getvalue()
        _c("`--service` только в комментарии — НЕ шаг прогона",
           "гоняется здесь:    0" in out, out[:500])

        # Ось 6в: объявлений конвейера НЕТ — третий исход, а не «гоняется 0».
        base = tmp / "pipeline-absent"
        t6c = _mk(base, {"own-only": clean},
                  {"ownRestBaseUrl": "https://localhost:9098", "runId": ""})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = run(t6c, workflows=base / "нет-такого-каталога")
        _c("каталога объявлений нет — код 75, а НЕ 0 и не 1", rc == 75,
           buf.getvalue()[-300:])
        _c("и текст называет несозданное условие",
           "УСЛОВИЕ НЕ СОЗДАНО" in buf.getvalue(), buf.getvalue()[-300:])

        # Ось 4: коллекция края попадает в «не гоняется» с причиной про край.
        edge = ('{"item":[{"name":"s","request":{"url":{"raw":"{{baseUrl}}/iam/v1/x"}}}]}')
        t4 = _mk(tmp / "edge", {"edge-only": edge}, {"baseUrl": "http://x", "runId": ""})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run(t4)
        out = buf.getvalue()
        _c("коллекция края — в «НЕ гоняется»", "НЕ гоняется здесь: 1" in out, out[:400])
        _c("и причина названа краем", "нужен край платформы" in out)

        # Ось 5: ОБЕ величины печатаются всегда — и когда вторая ноль.
        _c("печатаются обе величины, а не только одна",
           "гоняется здесь:" in out and "НЕ гоняется здесь:" in out)

    print()
    if _F:
        print(f"САМОПРОВЕРКА ПРОВАЛЕНА: {len(_F)} — {', '.join(_F)}", file=sys.stderr)
        return 1
    print("ДОКАЗАНО: пустой обход отвергается, поверхность и препятствия выводятся из "
          "коллекции, а законный близнец (тот же адрес, но пустой ключ посева) уезжает "
          "в другую половину переписи.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--newman", default=str(ROOT / "tests" / "newman"))
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    return run(pathlib.Path(args.newman))


if __name__ == "__main__":
    sys.exit(main())
