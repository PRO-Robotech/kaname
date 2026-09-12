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

«ГОНЯЕТСЯ» ЧИТАЕТСЯ ИЗ ОБЪЯВЛЕНИЯ КОНВЕЙЕРА, А НЕ ВЫВОДИТСЯ ИЗ ОТСУТСТВИЯ
ПРЕПЯТСТВИЙ. Прежняя редакция печатала «гоняется здесь: 1», не читая конвейер
ВОВСЕ: снятие шага прогона из `.github/workflows/e2e-newman.yml` величину не
меняло. То есть она утверждала «гоняется», а измеряла «ничто не мешает гонять» —
две разные вещи, и расходятся они именно в том случае, ради которого перепись
делается. Теперь у коллекции два независимых условия, и оба названы по каждой
позиции: препятствия по дереву И шаг конвейера, который её гоняет.

Объявление читается РАЗОБРАННЫМ (`yaml.safe_load`), а не подстрокой: имя
коллекции встречается в комментариях объявления десятки раз, и проверка по
подстроке считала бы собственное объяснение.

ИСХОДЫ:
    0  — перепись напечатана (долг — не отказ: он именно объявляется);
    1  — перепись беспредметна: коллекций либо шаблона окружения нет, разбор дал
         ноль. «Ноль находок» здесь означало бы «ноль прочитанного»;
   75  — УСЛОВИЕ НЕ СОЗДАНО: объявлений конвейера не прочитано ни одного либо нет
         разборщика YAML. Величина «гоняется» тогда не измерена, и печатать ноль
         значило бы выдать несозданное условие за вердикт.

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

RC_UNMET = 75

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
# ИДЕНТИФИКАТОР ЧЕЛОВЕКА ЦЕРЕМОНИИ — та же природа, что у его предъявителя, и тот
# же производитель. Выведено ЗАМЕРОМ по кейсам, а не по имени: `humanAccCrudUserId`
# читается в папке, чей предъявитель — `jwtHumanAccCrud`, утверждением
# «ownerUserId == caller», и образец требует префикса `usr`. То есть ключ есть
# идентификатор ТОГО ЖЕ вызывающего, и машинный посев не производит его ни при
# каком устройстве: служебная учётка человеком не является, её идентификатор несёт
# префикс `sva`, а подставленное значение дало бы кейс, проверивший подстановку.
#
# ИМЯ ВРЁТ В ОБЕ СТОРОНЫ, поэтому образец узкий. `svaInviteeId` по имени похож на
# приглашённого человека, а кейсы читают его при `subjectType=service_account` —
# это МАШИННЫЙ ключ, и он обязан остаться в машинном препятствии.
CEREMONY_ID_RE = re.compile(r"^human[A-Z][A-Za-z0-9]*UserId$")
# ПРЕДЪЯВИТЕЛЬ ПОВЫШЕННОГО УРОВНЯ — тоже церемония, под каким бы именем слот ни
# стоял. Сходится из двух независимых мест: набор объявляет
# `jwtAccountAdminAStepUp` НЕПОДДЕЛЫВАЕМЫМ посевом (шапка
# `cases/iam-interactive-client.py`), а продукт берёт `kaname_acr` только из сессии
# поставщика (`token_enrichment_service.go` кладёт пробросом,
# `authzguard/acr_floor.go` читает) — служебная учётка от порога освобождена, то
# есть поднять уровень машине нечем.
CEREMONY_STEPUP_SUFFIX = "StepUp"
# АДРЕС ПОВЕРХНОСТИ — не удостоверение и не предмет посева: его НАЗЫВАЕТ посадка.
# Объединение всех трёх наборов адресов выше; своя поверхность здесь тоже нужна —
# посев её адреса пишет, и тогда ключ отсеется как покрытый, а не как адрес.
ADDRESS_VARS = EDGE_VARS | OWN_VARS | NEIGHBOUR_VARS


def is_ceremony_key(key: str) -> bool:
    """Ключ, производимый ЦЕРЕМОНИЕЙ человека: предъявитель либо его идентификатор."""
    return (key.startswith(CEREMONY_PREFIXES)
            or key.endswith(CEREMONY_STEPUP_SUFFIX)
            or bool(CEREMONY_ID_RE.match(key)))


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
             minted_by_surface: dict[str, set[str]],
             runs: list[str] | None = None) -> list[str]:
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

    ПРИРОД У НЕПОКРЫТОГО КЛЮЧА ТРИ, И РАЗНЫЕ У НИХ ПРОИЗВОДИТЕЛИ. Прежняя
    редакция сваливала их в одно препятствие «нужен машинный посев», и это не
    неточность формулировки, а ОБЪЯВЛЕНИЕ НЕИСПОЛНИМОЙ ВОЗМОЖНОСТИ: строка звала
    читателя завести машинный посев тому, чего машинный посев не производит.
    Перепись по стволу 37ace71de4 дала на 20 ключей машинного препятствия 4 ключа
    природы «человек» (`humanAccCrudUserId`, `humanAccRdDeriveUserId`,
    `humanAccRdSagaUserId`, `jwtAccountAdminAStepUp`) и 2 природы «адрес»
    (`iamJwksBaseUrl`, `providerPublicBaseUrl`) — то есть каждый третий.

      · ЦЕРЕМОНИЯ ЧЕЛОВЕКА — предъявитель человека либо его идентификатор;
      · АДРЕС поверхности — его называет посадка, не подписант;
      · машинный посев — удостоверение, которое чеканит сама служба.

    И ПОВЕРХНОСТЬ НАЗЫВАЕТСЯ В СТРОКЕ, А НЕ ТОЛЬКО СЧИТАЕТСЯ. Учёт по
    поверхности здесь с самого начала, а строка про него молчала: «не пишет ни
    один посев ЭТОЙ поверхности» не называла, КАКОЙ. Цена измерена и это план
    целой полосы: печатный долг показывал 39 коллекций с препятствием «нужен
    машинный посев», под него заводилась полоса «расширить посев», — а все 39
    суть коллекции КРАЯ, которым посев собственного фронта не зачитывается НИ
    ОДНИМ ключом by construction (ось 3г). Число, на которое ставился план,
    сдвинуть было нечем, и увидеть это по печатному долгу читатель не мог.

    КЛЮЧ ЗАЧИТЫВАЕТСЯ ТОЛЬКО СВОЕЙ ПОВЕРХНОСТИ, И ЭТО ЗАМЕР. Учёт по одному
    перечню имён снял препятствие посева у ВОСЬМИ коллекций, из которых СЕМЬ —
    коллекции КРАЯ платформы: их `jwtAccountAdmin*` производит чужой посев чужого
    стенда, а совпало только ИМЯ ключа. Предъявитель, выкованный на собственном
    фронте службы, краю не годится ничем — ни издателем, ни адресатом, ни
    арендатором. Поэтому `minted_by_surface` — отображение «поверхность → ключи»,
    и посев, своей поверхности не объявивший, не зачитывается НИКОМУ.
    """
    out = []
    if runs is not None and not runs:
        out.append("ни один шаг конвейера её не гоняет "
                   "(объявление читается разобранным YAML)")
    if surface == "край платформы":
        out.append("нужен край платформы (его производитель — чужой стенд)")
    minted = minted_by_surface.get(surface, set())
    need = sorted(k for k in keys if k in empty and k != "runId")
    ceremony = [k for k in need if is_ceremony_key(k)]
    rest = [k for k in need if k not in ceremony and k not in minted]
    address = [k for k in rest if k in ADDRESS_VARS]
    machine = [k for k in rest if k not in ADDRESS_VARS]
    if ceremony:
        out.append(f"нужна ЦЕРЕМОНИЯ ЧЕЛОВЕКА ({len(ceremony)} ключ(ей) — "
                   f"предъявитель человека либо его идентификатор, производит их "
                   f"одна и та же церемония, а машинный посев не производит ни "
                   f"одного: "
                   f"{', '.join(ceremony[:3])}{'…' if len(ceremony) > 3 else ''})")
    if address:
        out.append(f"нужен АДРЕС поверхности «{surface}» ({len(address)} ключ(ей) — "
                   f"его НАЗЫВАЕТ посадка, ни один подписант его не выпускает: "
                   f"{', '.join(address[:3])}{'…' if len(address) > 3 else ''})")
    if machine:
        out.append(f"нужен машинный посев поверхности «{surface}» "
                   f"({len(machine)} ключ(ей) окружения, которых не пишет ни один "
                   f"посев ЭТОЙ поверхности: "
                   f"{', '.join(machine[:3])}{'…' if len(machine) > 3 else ''})")
    return out


# Коллекция, которую гоняет шаг конвейера: `run.sh --service <stem>`.
SERVICE_ARG_RE = re.compile(r"--service\s+([A-Za-z0-9._-]+)")


def pipeline_runs(workflows: pathlib.Path) -> dict[str, list[str]]:
    """{stem: [«задание/шаг», …]} — какие коллекции гоняет объявление конвейера.

    Читается РАЗОБРАННЫЙ YAML: ключи `jobs:`, их `steps[]`, тело `run:`. Имя
    коллекции стоит в комментариях объявления десятки раз, поэтому подстрочный
    предикат считал бы собственное объяснение — тот же порядок, что требует ban #17
    от гейта на кириллический ключ задания.

    Пустой словарь означает РОВНО «ни один шаг не гоняет ни одной коллекции».
    Отличить это от «объявлений не прочитано» — забота вызывающего: он спрашивает
    `workflow_files` отдельно.
    """
    import yaml  # локально: его отсутствие — третий исход, а не отказ разбора

    out: dict[str, list[str]] = {}
    for f in workflow_files(workflows):
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            raise Unmet(f"{f.name} не разбирается как YAML: {e}") from e
        if not isinstance(doc, dict):
            continue
        jobs = doc.get("jobs")
        if not isinstance(jobs, dict):
            continue
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            for i, stepv in enumerate(job.get("steps") or []):
                if not isinstance(stepv, dict):
                    continue
                body = stepv.get("run")
                if not isinstance(body, str):
                    continue
                label = f"{f.name}:{job_id}/{stepv.get('name') or f'шаг {i + 1}'}"
                for stem in SERVICE_ARG_RE.findall(body):
                    out.setdefault(stem, []).append(label)
    return out


def workflow_files(workflows: pathlib.Path) -> list[pathlib.Path]:
    if not workflows.is_dir():
        return []
    return sorted(workflows.glob("*.yml")) + sorted(workflows.glob("*.yaml"))


class Unmet(Exception):
    """Условие не создано: величина не измерена, и ноль вместо неё — ложь."""


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


def _ask(script: pathlib.Path, flag: str) -> tuple[int, list[str]]:
    cmd = ([sys.executable, str(script), flag] if script.suffix == ".py"
           else [str(script), flag])
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return proc.returncode, [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]


def minted_by_seeds(scripts: list[pathlib.Path]
                    ) -> tuple[dict[str, set[str]], list[str]]:
    """Спросить у КАЖДОГО посева, какие ключи он пишет И ДЛЯ КАКОЙ ПОВЕРХНОСТИ.

    Перепись не держит второй копии ни перечня, ни поверхности: копия разошлась бы
    с посевом молча и разошлась бы в одну сторону. Посев, который на вопрос не
    отвечает, в счёт НЕ идёт и называется отдельной строкой — «посев есть, а что он
    пишет, неизвестно» и «посева нет» ведут читателя в разные места.

    ПОВЕРХНОСТЬ СПРАШИВАЕТСЯ ОТДЕЛЬНЫМ ВОПРОСОМ И FAIL-CLOSED. Посев, назвавший
    ключи и НЕ назвавший поверхность, не зачитывается никому: молча зачесть его
    значило бы вернуть учёт по совпадению имён, который и дал 40 → 32 через два
    разных стенда.
    """
    minted: dict[str, set[str]] = {}
    mute: list[str] = []
    for script in scripts:
        try:
            rc_keys, keys = _ask(script, "--minted-keys")
        except (OSError, subprocess.SubprocessError) as e:
            mute.append(f"{script.name}: не запустился ({e})")
            continue
        if rc_keys != 0 or not keys:
            mute.append(f"{script.name}: не назвал ни одного ключа "
                        f"(код {rc_keys})")
            continue
        try:
            rc_surf, surf = _ask(script, "--minted-surface")
        except (OSError, subprocess.SubprocessError) as e:
            mute.append(f"{script.name}: НЕ НАЗВАЛ СВОЕЙ ПОВЕРХНОСТИ "
                        f"(не запустился: {e})")
            continue
        if rc_surf != 0 or len(surf) != 1:
            mute.append(f"{script.name}: НЕ НАЗВАЛ СВОЕЙ ПОВЕРХНОСТИ "
                        f"(код {rc_surf}, строк {len(surf)}) — его {len(keys)} "
                        f"ключ(ей) не зачтены НИКОМУ: имя ключа совпадает через "
                        f"разные стенды, а предъявитель не переносится")
            continue
        minted.setdefault(surf[0], set()).update(keys)
    return minted, mute


def survey(newman: pathlib.Path, workflows: pathlib.Path):
    """Разрез дерева: (гоняемые, заблокированные, по поверхности, по препятствию, …).

    Вынесен отдельной функцией затем, чтобы держатель согласованности
    (`tests/newman/scripts/pipeline_claims_test.py`) спрашивал ТУ ЖЕ величину, а не
    считал свою: второй счётчик того же предмета расходится с первым молча.
    """
    cols = collections(newman)
    allk, empty = template_keys(newman)
    if not cols:
        raise ValueError(f"в {newman/'collections'} не прочитано ни одной коллекции — "
                         f"перепись беспредметна, а не пуста")
    if not allk:
        raise ValueError("шаблона окружения нет — препятствия вывести не из чего")

    wfs = workflow_files(workflows)
    if not wfs:
        raise Unmet(f"в {workflows} не прочитано ни одного объявления конвейера — "
                    f"величина «гоняется» НЕ ИЗМЕРЕНА, и ноль вместо неё был бы ложью")
    runs = pipeline_runs(workflows)

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
        bl = blockers(surface, keys, empty, minted, runs.get(stem, []))
        if bl:
            blocked.append((stem, surface, bl))
            for b in bl:
                head = b.split(" (")[0]
                by_blocker[head] = by_blocker.get(head, 0) + 1
        else:
            runnable.append((stem, surface, runs.get(stem, [])))
    return (cols, wfs, runs, scripts, minted, mute, runnable, blocked,
            by_surface, by_blocker)


def blocked_stems(newman: pathlib.Path, workflows: pathlib.Path) -> dict[str, list[str]]:
    """{stem: [препятствие, …]} — для держателя согласованности дерева."""
    _, _, _, _, _, _, _, blocked, _, _ = survey(newman, workflows)
    return {stem: bl for stem, _, bl in blocked}


def run(newman: pathlib.Path, workflows: pathlib.Path | None = None) -> int:
    if workflows is None:
        workflows = ROOT / ".github" / "workflows"
    try:
        (cols, wfs, runs, scripts, minted, mute, runnable, blocked,
         by_surface, by_blocker) = survey(newman, workflows)
    except ValueError as e:
        print(f"ОТКАЗ: {e}.", file=sys.stderr)
        return 1
    except ModuleNotFoundError as e:
        print(f"УСЛОВИЕ НЕ СОЗДАНО: нет разборщика YAML ({e}) — объявление конвейера "
              f"не прочитано, величина «гоняется» НЕ ИЗМЕРЕНА.", file=sys.stderr)
        return RC_UNMET
    except Unmet as e:
        print(f"УСЛОВИЕ НЕ СОЗДАНО: {e}.", file=sys.stderr)
        return RC_UNMET

    print("===== сквозной набор на АВТОНОМНОМ стенде: что гоняется, а что нет =====")
    print(f"коллекций в дереве: {len(cols)}")
    print(f"  гоняется здесь:    {len(runnable)}")
    print(f"  НЕ гоняется здесь: {len(blocked)}")
    print()
    # ОБЪЁМ ОСМОТРЕННОГО — рядом с величиной: «гоняется N», напечатанное
    # переписью, которая конвейер не читает, измеряет не то, что называет.
    print(f"объявлений конвейера прочитано: {len(wfs)} "
          f"({', '.join(f.name for f in wfs)})")
    print(f"коллекций гоняют шаги конвейера: {len(runs)}")
    for stem, where in sorted(runs.items()):
        print(f"  · {stem} ← {'; '.join(where)}")
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
          f"({len(scripts)} скрипт(ов) в authz-fixtures/), "
          f"ключей окружения он пишет: {sum(len(v) for v in minted.values())}")
    for surface, keys in sorted(minted.items()):
        print(f"  · для поверхности «{surface}»: {len(keys)} ключ(ей)")
    for script in scripts:
        print(f"  · {script.name}")
    for m in mute:
        print(f"  · НЕ НАЗВАЛ СВОИХ КЛЮЧЕЙ — {m}")
    print()
    if runnable:
        print("ГОНЯЕТСЯ ЗДЕСЬ (и КАКИМ шагом конвейера):")
        for stem, surface, where in runnable:
            print(f"  · {stem} — {surface}")
            for w in where:
                print(f"      ← {w}")
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
            rc = run(empty, workflows=_wf(tmp / "empty", runs=[]))
        _c("ноль коллекций — код 1, а НЕ 0", rc == 1, buf.getvalue()[-200:])
        _c("и отказ называет беспредметность", "беспредметна" in buf.getvalue())

        # Ось 2: коллекция БЕЗ препятствий обязана попасть в «гоняется».
        own = ('{"item":[{"name":"s","request":{"url":{"raw":"{{ownRestBaseUrl}}/x"}}}]}')
        t2 = _mk(tmp / "own", {"own-only": own},
                 {"ownRestBaseUrl": "https://localhost:9098", "runId": ""})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run(t2, workflows=_wf(tmp / "own", runs=["own-only"]))
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
            run(t3, workflows=_wf(tmp / "own-seeded", runs=["own-seeded"]))
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
                f"    print({minted_key!r})\n"
                "elif '--minted-surface' in sys.argv:\n"
                "    print('служба (собственный REST-фронт)')\n",
                encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                run(t3b, workflows=_wf(base, runs=["own-seeded"]))
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
            run(t3c, workflows=_wf(mute_base, runs=["own-seeded"]))
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

        # ── Ось 7: ПРИРОДА КЛЮЧА РАЗЛИЧАЕТСЯ, И «ЧЕЛОВЕК» НЕ ЗОВЁТ МАШИНУ ───
        #
        # ЗАМЕР, А НЕ ИМЯ. `humanAccCrudUserId` читается кейсом как идентификатор
        # ТОГО ЖЕ вызывающего, чей предъявитель — `jwtHumanAccCrud`: утверждение
        # кейса — «ownerUserId == caller», и образец требует префикса `usr`.
        # Значит ключ производит ЦЕРЕМОНИЯ, а машинный посев не производит его ни
        # при каком устройстве: служебная учётка человеком не является, её
        # идентификатор несёт префикс `sva`, и подставленное значение дало бы
        # кейс, проверивший подстановку.
        #
        # ЦЕНА ПРЕЖНЕГО УЧЁТА НАЗВАНА: строка долга звала читателя завести
        # машинный посев тому, чего машинный посев не производит, — то есть
        # ОБЪЯВЛЯЛА возможность, неисполнимую by construction.
        #
        # ЗАКОННЫЙ БЛИЗНЕЦ РЯДОМ и отличается ОДНИМ фактом: `svaInviteeId` —
        # идентификатор СЛУЖЕБНОЙ учётки (кейсы читают его при
        # `subjectType=service_account`), и он обязан остаться машинным.
        for lane, key, want_ceremony in (("human-id", "humanAccCrudUserId", True),
                                         ("machine-id", "svaInviteeId", False)):
            base = tmp / f"nature-{lane}"
            body = ('{"item":[{"name":"s","request":{"url":{"raw":'
                    '"{{baseUrl}}/iam/v1/x"}},'
                    '"event":[{"listen":"test","script":{"exec":['
                    f'"pm.environment.get(\'{key}\')"]}}}}]}}]}}')
            t7 = _mk(base, {"nature": body},
                     {"baseUrl": "http://edge", key: "", "runId": ""})
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                run(t7, workflows=_wf(base, runs=["nature"]))
            out = buf.getvalue()
            # СУДИТСЯ ГОЛОВА ПРЕПЯТСТВИЯ, А НЕ ПОДСТРОКА ВЫВОДА, и это не
            # педантизм: первая редакция этой оси искала «машинный посев» по
            # всему выводу и краснела на СОБСТВЕННОМ объяснении препятствия
            # церемонии («…машинный посев не производит ни одного»). Тот самый
            # класс, который шапка `pipeline_runs` называет про грепанье
            # комментариев, применённый не к конвейеру, а к самой переписи.
            _c(f"{key}: препятствие названо "
               f"{'ЦЕРЕМОНИЕЙ ЧЕЛОВЕКА' if want_ceremony else 'машинным посевом'}",
               ("нужна ЦЕРЕМОНИЯ ЧЕЛОВЕКА" in out) == want_ceremony
               and ("нужен машинный посев поверхности" in out) != want_ceremony,
               out[:900])

        # ── Ось 7б: ПРЕДЪЯВИТЕЛЬ ПОВЫШЕННОГО УРОВНЯ — ТОЖЕ ЦЕРЕМОНИЯ ─────────
        #
        # ЗАМЕР, И ОН СХОДИТСЯ ИЗ ДВУХ НЕЗАВИСИМЫХ МЕСТ. Шапка
        # `cases/iam-interactive-client.py` говорит дословно:
        # «`jwtAccountAdminAStepUp` is declared unforgeable by the seed itself …
        # and every other `jwt*` fixture is a ServiceAccount token, i.e.
        # acr-exempt». И это подтверждается устройством продукта: `kaname_acr`
        # приходит ТОЛЬКО из сессии поставщика (`token_enrichment_service.go`
        # кладёт его пробросом, `authzguard/acr_floor.go` читает), а служебная
        # учётка от порога ОСВОБОЖДЕНА — то есть поднять уровень машине нечем.
        #
        # Значит приставки `jwtHuman` недостаточно: `*StepUp` — предъявитель, чей
        # производитель церемония, под каким бы именем слот ни стоял.
        # Законный близнец отличается ОДНИМ фактом: `jwtAccountAdminA` без
        # повышения — служебная учётка, и он обязан остаться машинным.
        for lane, key, want_ceremony in (("stepup", "jwtAccountAdminAStepUp", True),
                                         ("plain", "jwtAccountAdminA", False)):
            base = tmp / f"stepup-{lane}"
            body = ('{"item":[{"name":"s","request":{"url":{"raw":'
                    '"{{baseUrl}}/iam/v1/x"}},'
                    '"event":[{"listen":"test","script":{"exec":['
                    f'"pm.environment.get(\'{key}\')"]}}}}]}}]}}')
            t7b = _mk(base, {"stepup": body},
                      {"baseUrl": "http://edge", key: "", "runId": ""})
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                run(t7b, workflows=_wf(base, runs=["stepup"]))
            out = buf.getvalue()
            _c(f"{key}: препятствие названо "
               f"{'ЦЕРЕМОНИЕЙ ЧЕЛОВЕКА' if want_ceremony else 'машинным посевом'}",
               ("нужна ЦЕРЕМОНИЯ ЧЕЛОВЕКА" in out) == want_ceremony
               and ("нужен машинный посев поверхности" in out) != want_ceremony,
               out[:900])

        # ── Ось 8: АДРЕС — НЕ ПОСЕВ, И ЕГО ПРОИЗВОДИТ СТЕНД ──────────────────
        #
        # Тот же класс, что уже назван в шапке `blockers`: из шести пустых ключей
        # своей поверхности два были АДРЕСАМИ, и прежняя редакция звала их
        # удостоверениями. Ключи `iamJwksBaseUrl` и `providerPublicBaseUrl` — того
        # же рода: их не выпускает ни один подписант, их НАЗЫВАЕТ посадка.
        # Законный близнец — предъявитель той же коллекции: он обязан остаться
        # машинным посевом.
        for lane, key, want_address in (("addr", "iamJwksBaseUrl", True),
                                        ("cred", "jwtBootstrap", False)):
            base = tmp / f"addrnature-{lane}"
            body = ('{"item":[{"name":"s","request":{"url":{"raw":'
                    '"{{baseUrl}}/iam/v1/x"}},'
                    '"event":[{"listen":"test","script":{"exec":['
                    f'"pm.environment.get(\'{key}\')"]}}}}]}}]}}')
            t8 = _mk(base, {"nature": body},
                     {"baseUrl": "http://edge", key: "", "runId": ""})
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                run(t8, workflows=_wf(base, runs=["nature"]))
            out = buf.getvalue()
            _c(f"{key}: препятствие названо "
               f"{'АДРЕСОМ' if want_address else 'машинным посевом'}",
               ("нужен АДРЕС поверхности" in out) == want_address
               and ("нужен машинный посев поверхности" in out) != want_address,
               out[:900])

        # ── Ось 9: СТРОКА ДОЛГА НАЗЫВАЕТ ПОВЕРХНОСТЬ, ЧЕЙ ПОСЕВ ТРЕБУЕТСЯ ────
        #
        # ЦЕНА ИЗМЕРЕНА И ОНА — ПЛАН ЦЕЛОЙ ПОЛОСЫ. Учёт поклюсевой и по
        # поверхности стоит здесь с самого начала (оси 3б и 3г), а вот СТРОКА про
        # него молчала: она говорила «которых не пишет ни один посев ЭТОЙ
        # поверхности», не называя, КАКОЙ. Читатель печатного долга видел 39
        # коллекций с препятствием «нужен машинный посев» и заводил полосу
        # «расширить посев» — при том что все 39 суть коллекции КРАЯ, и посев
        # собственного фронта им не зачитывается НИ ОДНИМ ключом by construction.
        # То есть число, на которое ставился план, сдвинуть было нечем.
        #
        # Инъекция: коллекция КРАЯ и посев СВОЕЙ поверхности в одном дереве.
        # Строка обязана назвать «край платформы» — производителя, которого нет, —
        # а не поверхность посева, который в дереве лежит.
        base = tmp / "surface-named"
        edge_seeded = ('{"item":[{"name":"s","request":{"url":{"raw":'
                       '"{{baseUrl}}/iam/v1/x"}},'
                       '"event":[{"listen":"test","script":{"exec":['
                       '"pm.environment.get(\'jwtAccountAdminA\')"]}}]}]}')
        t9 = _mk(base, {"edge-seeded": edge_seeded},
                 {"baseUrl": "http://edge", "jwtAccountAdminA": "", "runId": ""})
        fx9 = t9.parent / "authz-fixtures"
        fx9.mkdir(parents=True, exist_ok=True)
        (fx9 / "seed_probe.py").write_text(
            "import sys\n"
            "if '--minted-keys' in sys.argv:\n"
            "    print('jwtAccountAdminA')\n"
            "elif '--minted-surface' in sys.argv:\n"
            "    print('служба (собственный REST-фронт)')\n",
            encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run(t9, workflows=_wf(base, runs=["edge-seeded"]))
        out = buf.getvalue()
        _c("строка машинного посева НАЗЫВАЕТ поверхность, чей посев требуется",
           "машинный посев поверхности «край платформы»" in out, out[:800])
        _c("и НЕ называет поверхность посева, который в дереве лежит",
           "машинный посев поверхности «служба" not in out, out[:800])

        # Ось 4: коллекция края попадает в «не гоняется» с причиной про край.
        edge = ('{"item":[{"name":"s","request":{"url":{"raw":"{{baseUrl}}/iam/v1/x"}}}]}')
        t4 = _mk(tmp / "edge", {"edge-only": edge}, {"baseUrl": "http://x", "runId": ""})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run(t4, workflows=_wf(tmp / "edge", runs=["edge-only"]))
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
    ap.add_argument("--workflows", default=str(ROOT / ".github" / "workflows"))
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    return run(pathlib.Path(args.newman), pathlib.Path(args.workflows))


if __name__ == "__main__":
    sys.exit(main())
