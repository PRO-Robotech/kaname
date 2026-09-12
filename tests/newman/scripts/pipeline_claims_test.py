#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ДЕРЖАТЕЛЬ КЛАССА «ДВА МЕСТА ОБ ОДНОМ ПРЕДМЕТЕ, И ЛОЖНЫМ СТАЛО ДЕЙСТВУЮЩЕЕ».

ПРЕДМЕТ. Объявление конвейера и его собственные комментарии — два места об одном
предмете. Когда изменение заводит шаг, гоняющий коллекцию, соседняя строка,
утверждающая «не гоняется ни одна», становится ЛОЖЬЮ — и не какой-нибудь, а той,
которая ПЕЧАТАЕТСЯ В КАЖДЫЙ ПРОГОН и читается как действующее состояние.

ЭТО НАБЛЮДАЛОСЬ, А НЕ ПРЕДПОЛОЖЕНО. Изменение, заведшее прогон коллекции
`kaname-own-rest-front` на автономном стенде, оставило в том же файле два места:
комментарий у шага запретов формы и текст `::notice`, оба про «ни одна коллекция
на автономном стенде не гоняется». Второе печаталось в каждый прогон.

ТОТ ЖЕ КЛАСС ВТОРЫМ ПРЕДМЕТОМ: прогонщик проб на python в двух местах утверждал,
что посева в этом репозитории НЕТ НИ ОДНИМ ФАЙЛОМ, и назвал предикатом своего
снятия историю каталога фикстур. Посев приехал — оба места остались.

КЛАСС ПРИХОДИТ НЕ ПО ОДНОМУ, И ЭТО ИЗМЕРЕНО ЦЕНОЙ ТРЁХ КРУГОВ РЕВЬЮ. Одна линия
дала четыре места: два нашли первым заходом, третье — вторым, четвёртое — третьим,
и каждый раз класс объявлялся закрытым. Четвёртое (`paginated_binding_reads_test.py`,
премисса пробы посева) держатель НЕ ВИДЕЛ by construction: он читал ДВА пинованных
адреса и печатал объём, который сам же и пиновал, — «ноль находок» было неотличимо
от «этот файл не читали». Поэтому предмет 2 судит ОТСЛЕЖИВАЕМОЕ ДЕРЕВО ЦЕЛИКОМ
разбором по форме, а объём называет числом на каждом прогоне.

ПРЕДМЕТ 2б — ЧИСЛО, ПРИСТАВЛЕННОЕ К ПРЕДИКАТУ ПО ИСТОРИИ КАТАЛОГА ФИКСТУР. Снятое
утверждение назвало предикатом своего снятия счёт коммитов по рефам, и следующая
редакция этот счёт ПЕРЕМЕРИЛА и записала числом — то есть заменила ложь о дереве
на число, которого у дерева нет. Замер: одна и та же команда в ОДНОЙ копии даёт
ноль на местном `main`, единицу на `origin/main`, четыре на ветке линии и пять по
всем рефам при пятнадцати рефах. Утверждение на такой величине неопровержимо, и
починить его правкой числа нельзя — только предикатом ПО ДЕРЕВУ.

ПОЧЕМУ ГЕЙТ, А НЕ ВНИМАНИЕ. Оба утверждения верны ДО изменения и ложны ПОСЛЕ, а
изменение их не касается ни строкой: заметить нечего в диффе. Условие лжи
ВЫВОДИМО из дерева, значит проверяемо машиной.

ПОЧЕМУ УСЛОВНЫЙ, А НЕ ЗАПРЕТ ФРАЗЫ. Запрет фразы был бы бланкетным: до заведения
шага фраза ВЕРНА и обязана стоять. Поэтому предикат читает РАЗОБРАННОЕ объявление
конвейера, и находка появляется только вместе с шагом. Инъекция доказывает обе
стороны: шаг есть и фраза есть — красное; шага нет, фраза та же — молчит.

ПОЧЕМУ РАЗБОР, А НЕ ГРЕП. Имя коллекции встречается в комментариях объявления
десятки раз; проверка по подстроке краснела бы на собственном объяснении. Ключи
`jobs:` и шаги читаются разобранным YAML — тот же порядок, что требует ban #17.
"""

from __future__ import annotations

import ast
import importlib.util
import io
import json
import pathlib
import re
import subprocess
import sys
import tokenize

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[3]
WORKFLOWS = ROOT / ".github" / "workflows"
FIXTURES = ROOT / "tests" / "authz-fixtures"
PROBE_RUNNER = ROOT / ".github" / "scripts" / "run-python-probes.py"
# Запись вендоринга — ТРЕТЬЕ место того же утверждения: прогонщик проб вендорен, и
# его местная правка объявлена в записи ДОСЛОВНО (поля `local` и `why`). Ложное
# утверждение живёт поэтому в двух файлах сразу, и правка только одного оставила бы
# запись расходящейся с копией — это ловит держатель вендоринга, но уже не по
# предмету утверждения, а по отпечатку.
VENDOR_RECORD = ROOT / "tests" / "newman" / "vendor-provenance.json"


def authored_prose_of_record(path: pathlib.Path) -> list[tuple[str, str]]:
    """Проза, авторская ДЛЯ ЗАПИСИ и только для неё: поля `why`.

    ПОЧЕМУ НЕ `local`. Это дословная копия текста, который лежит в самом файле, и
    держатель вендоринга проверяет вхождение (`local` обязано встречаться в копии
    ровно один раз). Значит всякое ПРОЗАИЧЕСКОЕ утверждение из `local` уже судится
    по узлу — там, где различимы шапка, комментарий и строковый литерал. В записи
    эта различимость потеряна: синтетика инъекции («посев не приехал в этот
    репозиторий» внутри фикстуры) выглядит в `local` так же, как шапка, и запрет по
    `local` требовал бы переписать законную пробу.

    ПОЧЕМУ НЕ `upstream`. Это проза дерева платформы; её здесь не правят, и судить
    её значило бы требовать правки чужого файла в чужом репозитории.
    """
    doc = json.loads(path.read_text(encoding="utf-8"))
    out: list[tuple[str, str]] = []
    for entry in doc.get("files", []):
        for rw in entry.get("rewrites", []):
            if isinstance(rw.get("why"), str):
                out.append((f"{entry['path']} подстановка строки {rw.get('line')} "
                            f"поле why", rw["why"]))
    return out


def _debt_module():
    """Разборщик объявления конвейера берётся У ПЕРЕПИСИ, а не переписывается.

    Второй разборщик того же предмета разошёлся бы с первым молча — ровно тот
    класс, который эта проба и держит. Имя файла с дефисом импортируется по пути.
    """
    path = ROOT / ".github" / "scripts" / "newman-suite-debt.py"
    spec = importlib.util.spec_from_file_location("newman_suite_debt", path)
    assert spec and spec.loader, f"не загружается {path}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules["newman_suite_debt"] = mod
    spec.loader.exec_module(mod)
    return mod


# Фраза-утверждение о том, что не гоняется НИ ОДНА коллекция. Ловится семья, а не
# один литерал: редакция меняет порядок слов, не меняя утверждения.
NO_COLLECTION_RUNS_RE = re.compile(
    r"ни одн[аой][^.\n]{0,80}коллекци[ияй][^.\n]{0,80}не гоня", re.IGNORECASE)
# Фраза-утверждение о том, что посева нет ни одним файлом.
NO_SEED_AT_ALL_RE = re.compile(
    r"посев[а-я]{0,3}[^.\n]{0,60}(нет ни одним файлом|не приехал)"
    r"|ПОСЕВА НЕТ НИ ОДНИМ ФАЙЛОМ", re.IGNORECASE)


def claims_no_collection_runs(text: str) -> list[str]:
    """Объявление конвейера читается ЦЕЛИКОМ, и это верно по существу: в нём нет
    строковых фикстур. Всё, что там написано, — либо комментарий читателю, либо
    текст, который прогон ПЕЧАТАЕТ."""
    return [m.group(0) for m in NO_COLLECTION_RUNS_RE.finditer(text)]


def prose_of_python(path: pathlib.Path) -> list[tuple[int, str]]:
    """ПРОЗА файла на python: строки документации и комментарии. Без литералов.

    Различение обязательно, и оно измерено: у прогонщика проб есть СИНТЕТИКА для
    инъекции, чья причина пропуска дословно говорит «посев не приехал в этот
    репозиторий». Это фикстура гипотетического случая, а не утверждение о дереве,
    и запрет по тексту файла краснел бы на ней — то есть требовал бы переписать
    законную пробу. Предикат по УЗЛУ различает их построением: проза — это
    docstring узла и комментарий лексера, литерал внутри кода — нет.
    """
    src = path.read_text(encoding="utf-8")
    out: list[tuple[int, str]] = []
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                out.append((getattr(node, "lineno", 1), doc))
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type == tokenize.COMMENT:
            out.append((tok.start[0], tok.string))
    return out


# ── ОБХОД ВСЕГО ДЕРЕВА: ФОРМЫ ПЕРЕЧИСЛЕНЫ ЧИСЛОМ ─────────────────────────────
#
# ПОЧЕМУ ОБХОД, А НЕ ПЕРЕЧЕНЬ ФАЙЛОВ. Прежняя редакция читала ДВА пинованных
# адреса — прогонщик проб и авторские поля записи вендоринга, — и была ЗЕЛЕНА,
# пока то же утверждение стояло третьим местом в `paginated_binding_reads_test.py`.
# Молчание держателя было неотличимо от его отсутствия: он не судил файл, а
# перепись печатала объём, который сам же и был пинован. Пинованный перечень
# держит ровно свои адреса — а класс приходит НЕ ПО ОДНОМУ: в одной линии он
# нашёлся четыре раза, и трижды его закрывали как закрытый.
#
# ФОРМЫ, В КОТОРЫХ УТВЕРЖДЕНИЕ О ДЕРЕВЕ ЗАПИСЫВАЕТСЯ, — ИХ ОДИННАДЦАТЬ. Форма,
# о которой выражение не знает, даёт не красное и не зелёное, а МОЛЧАНИЕ, поэтому
# перечень назван числом и перепись печатает счёт ПО КАЖДОЙ форме:
#
#    1 шапка python (модуль · класс · функция)                        судится
#    2 комментарий python                                             судится
#    3 строковый литерал python                              НЕ ПОРОЖДАЕТСЯ
#    4 комментарий C-подобного (go · ts · tsx · js · css): // и /* */  судится
#    5 комментарий решёткой (sh · yml · yaml · mk · conf · Dockerfile) судится
#    6 печатаемая строка того же файла — не комментарий                судится
#    7 проза markdown вне ограды                                      судится
#    8 текст внутри ограды markdown                                   судится
#    9 авторское поле записи вендоринга (`why`)                        судится
#   10 дословная копия в записи вендоринга (`local`/`upstream`) НЕ ПОРОЖДАЕТСЯ
#   11 комментарий sql (`--`)                                         судится
#
# Девять форм из одиннадцати судятся. Две не доходят до отбора вовсе — их не
# порождают производители, и причина у каждой ЗАМЕРЕНА, а не предположена:
# `prose_of_python` не отдаёт строковый литерал (форма 3), `authored_prose_of_record`
# отдаёт только авторское поле записи (форма 10 остаётся у держателя вендоринга,
# который судит копию по отпечатку). Отбора по имени формы в обходе поэтому НЕТ:
# ветка, которой нечего отбирать, читалась бы как второй, тайный перечень
# прощённых. Прочие расширения читаются целиком как форма 6 — файл без известного
# синтаксиса комментария всё равно обязан быть осмотрен, иначе «ноль находок»
# означало бы «ноль прочитанного».
#
# ПЕРЕПИСЬ ПЕЧАТАЕТ ТОЛЬКО ТЕ ФОРМЫ, КОТОРЫЕ В ДЕРЕВЕ ЕСТЬ, и число файлов на
# единицу меньше отслеживаемых — ровно на этот файл, см. исключение ниже.
#
# ЕДИНСТВЕННОЕ ИСКЛЮЧЕНИЕ — ЭТОТ ФАЙЛ, И ОНО ПО ПОСТРОЕНИЮ, А НЕ ПО ИМЕНИ. Модуль,
# ОБЪЯВЛЯЮЩИЙ выражение, объясняет класс своей прозой, и проверка, считающая своё
# объяснение, — тот же дефект, что она ловит. Исключение берётся из `__file__`,
# поэтому вторым файлом оно стать не может: списка прощённых здесь нет, и завести
# его нечем. Что исключение не глушит близнеца в ЧУЖОМ файле, доказывает инъекция.
#
# ОСТАТОК НАЗВАН ПРЯМО, А НЕ ЗАМОЛЧАН: прозу ЭТОГО файла не держит ничто, и ложь
# о дереве, внесённая сюда, проедет молча. Снимается это не списком и не вторым
# выражением, а вторым ЧИТАТЕЛЕМ: предикат снятия — проба в другом файле, которая
# судит прозу этого. Заводить её здесь нельзя by construction — она оказалась бы
# в том же файле и унаследовала бы тот же дефект.
SELF = pathlib.Path(__file__).resolve()

_C_LIKE = {".go", ".ts", ".tsx", ".js", ".css"}
_HASH_LIKE = {".sh", ".yml", ".yaml", ".mk", ".conf", ".gitignore", ".dockerignore",
              ".tpl"}
_MARKDOWN = {".md", ".mdx"}


def tracked_files(root: pathlib.Path) -> list[pathlib.Path]:
    """Состав обхода — ОТСЛЕЖИВАЕМОЕ дерево, а не всё, что лежит на диске.

    Кэш интерпретатора, отчёты прогонов и чужие рабочие копии под тем же корнем
    предметом утверждений о дереве не являются, и включать их значило бы делать
    вердикт свойством того, что кто-то забыл убрать.
    """
    out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                         capture_output=True, check=True)
    return [root / rel for rel in out.stdout.decode("utf-8").split("\0") if rel]


def _c_like_comments(text: str) -> list[tuple[str, int, str]]:
    """Формы 4: `//` и `/* */`, лексером — строковый литерал в счёт не идёт."""
    out, i, n, line = [], 0, len(text), 1
    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch in ('"', "'", "`"):
            quote = ch
            i += 1
            while i < n and text[i] != quote:
                if text[i] == "\\" and quote != "`":
                    i += 1
                if i < n and text[i] == "\n":
                    line += 1
                i += 1
            i += 1
            continue
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            out.append(("4-C//", line, text[i:end]))
            i = end
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i)
            end = n if end < 0 else end + 2
            chunk = text[i:end]
            out.append(("4-C/**/", line, chunk))
            line += chunk.count("\n")
            i = end
            continue
        i += 1
    return out


def _by_line(text: str, marker: str, tag_comment: str) -> list[tuple[str, int, str]]:
    """Формы 5 и 11 (комментарий) плюс форма 6 (печатаемая строка того же файла).

    Печатаемое судится наравне с комментарием: текст, который прогон ПЕЧАТАЕТ,
    читается как действующее состояние дерева — ровно так `::notice` и пережил
    свой предмет в предмете 1 этой пробы.
    """
    out = []
    for i, ln in enumerate(text.splitlines(), 1):
        tag = tag_comment if ln.lstrip().startswith(marker) else "6-печатаемое"
        out.append((tag, i, ln))
    return out


def prose_units(path: pathlib.Path) -> list[tuple[str, int, str]]:
    """Единицы текста файла по ФОРМЕ. Нечитаемое как utf-8 — не текст."""
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    suffix = path.suffix
    if suffix == ".py":
        try:
            chunks = prose_of_python(path)
        except (SyntaxError, ValueError):
            # Файл, который не разбирается, — НЕ «ноль находок»: он читается
            # целиком как печатаемое, иначе обход молча терял бы предмет.
            return [("6-печатаемое", 1, text)]
        # Комментарий отличается от шапки ПО УЗЛУ: `prose_of_python` отдаёт
        # комментарии токеном лексера, и токен начинается с решётки.
        return [(("2-комментарий" if chunk.lstrip().startswith("#") else "1-шапка"),
                 line, chunk) for line, chunk in chunks]
    if suffix in _C_LIKE:
        return _c_like_comments(text)
    if suffix in _HASH_LIKE or path.name in ("Makefile", "Dockerfile"):
        return _by_line(text, "#", "5-решётка")
    if suffix == ".sql":
        return _by_line(text, "--", "11-sql")
    if suffix in _MARKDOWN:
        out, fenced = [], False
        for i, ln in enumerate(text.splitlines(), 1):
            if ln.lstrip().startswith("```"):
                fenced = not fenced
                continue
            out.append(("8-ограда" if fenced else "7-проза", i, ln))
        return out
    if suffix == ".json":
        return [("9-why", 0, chunk) for _, chunk in _record_why_or_empty(path)]
    return [("6-печатаемое", i, ln) for i, ln in enumerate(text.splitlines(), 1)]


def _record_why_or_empty(path: pathlib.Path) -> list[tuple[str, str]]:
    """Форма 9 — только у записи вендоринга; прочий json есть ДАННЫЕ, не проза."""
    if path.resolve() != VENDOR_RECORD.resolve():
        return []
    try:
        return authored_prose_of_record(path)
    except (json.JSONDecodeError, KeyError, OSError):
        return []


# Предикат по ИСТОРИИ каталога фикстур, к которому ПРИСТАВЛЕНО ЧИСЛО. Запрет здесь
# БЛАНКЕТНЫЙ, и это единственное место корпуса, где бланкетный запрет верен по
# существу: величина не есть свойство дерева. Та же команда в ОДНОЙ копии отвечает
# по-разному в зависимости от названного рефа — на местном `main` одно, на ветке
# линии другое, по всем рефам третье. Значит у числа нет ни верного значения, ни
# неверного: утверждение на нём НЕОПРОВЕРЖИМО, то есть замером не является, и
# «починить число» тут нечем — предикат обязан читать ДЕРЕВО.
# Законный близнец, который обязан молчать: то же число, названное предикатом ПО
# ДЕРЕВУ (`git ls-files -- tests/authz-fixtures | wc -l`), и сама история, названная
# негодной БЕЗ числа.
_HISTORY_OF_FIXTURES = re.compile(r"git\s+log[^\n]{0,200}?authz-fixtures")
_NUMBER_ATTACHED = re.compile(r"(→|->|даёт|дает|равн[а-яё]*|получ[а-яё]*)\s*«?\d")


def cites_fixture_history_count(chunk: str) -> list[str]:
    """Находки формы «предикат по истории каталога фикстур ДАЁТ N»."""
    low = chunk.lower()
    if "git" not in low or "log" not in low:      # следует из выражения ниже
        return []
    hits = []
    for m in _HISTORY_OF_FIXTURES.finditer(chunk):
        tail = chunk[m.end():m.end() + 200]
        num = _NUMBER_ATTACHED.search(tail)
        if num:
            hits.append(f"{m.group(0)!r} … {num.group(0)!r}")
    return hits


def sweep(files, *, root: pathlib.Path):
    """Обход: (находки оси A, находки оси B, объём осмотренного по формам)."""
    volume: dict[str, int] = {}
    read = 0
    hits_a: list[str] = []
    hits_b: list[str] = []
    for path in files:
        if not path.is_file() or path.resolve() == SELF:
            continue
        units = prose_units(path)
        read += 1
        try:
            where = path.relative_to(root)
        except ValueError:
            where = path
        for form, line, chunk in units:
            volume[form] = volume.get(form, 0) + 1
            if "посев" in chunk.lower():          # следует из NO_SEED_AT_ALL_RE
                for m in NO_SEED_AT_ALL_RE.finditer(chunk):
                    hits_a.append(f"{where}:{line} [{form}] {m.group(0)!r}")
            for hit in cites_fixture_history_count(chunk):
                hits_b.append(f"{where}:{line} [{form}] {hit}")
    return hits_a, hits_b, read, volume


def claims_no_seed(path_or_text) -> list[str]:
    """Находки во ПРОЗЕ файла (или в переданном тексте — для инъекции)."""
    if isinstance(path_or_text, pathlib.Path):
        chunks = prose_of_python(path_or_text)
    else:
        chunks = [(0, str(path_or_text))]
    hits: list[str] = []
    for line, chunk in chunks:
        for m in NO_SEED_AT_ALL_RE.finditer(chunk):
            hits.append(f"строка {line}: {m.group(0)!r}" if line else m.group(0))
    return hits


# ── ПРЕДМЕТ 1: «не гоняется ни одна» против объявленного шага прогона ────────


def test_pipeline_declares_runs_and_nobody_claims_zero():
    mod = _debt_module()
    runs = mod.pipeline_runs(WORKFLOWS)
    files = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    assert files, f"в {WORKFLOWS} не прочитано ни одного объявления — проба беспредметна"
    print(f"осмотрено объявлений конвейера: {len(files)}; "
          f"коллекций, которые гоняет конвейер: {len(runs)} — {sorted(runs)}")
    if not runs:
        pytest.skip("УСЛОВИЕ НЕ СОЗДАНО: ни один шаг конвейера не гоняет коллекцию — "
                    "утверждение «не гоняется ни одна» здесь ВЕРНО и запрету не подлежит")
    bad = []
    for f in files:
        for hit in claims_no_collection_runs(f.read_text(encoding="utf-8")):
            bad.append(f"{f.relative_to(ROOT)}: {hit!r}")
    assert not bad, (
        f"конвейер гоняет {len(runs)} коллекци(й) ({sorted(runs)}), а его же объявление "
        f"в {len(bad)} мест(ах) утверждает, что не гоняется ни одна:\n  "
        + "\n  ".join(bad))


# ── ПРЕДМЕТ 2: «посева нет ни одним файлом» против приехавшего посева ────────


def _print_volume(read: int, volume: dict) -> int:
    """Объём осмотренного — ЧИСЛОМ и по каждой форме. Без него «ноль находок»
    неотличимо от «ноль прочитанного», и ровно так эта проба и прожила зелёной
    при живом дефекте в третьем файле."""
    total = sum(volume.values())
    print(f"ОБЪЁМ ОСМОТРЕННОГО: файлов {read}, единиц текста {total}; по формам: "
          + ", ".join(f"{form} {volume[form]}" for form in sorted(volume)))
    return total


def test_seed_arrived_and_nobody_claims_it_absent():
    seeds = sorted(FIXTURES.glob("seed_*.py")) + sorted(FIXTURES.glob("seed-*.sh"))
    assert PROBE_RUNNER.is_file(), f"нет {PROBE_RUNNER} — проба беспредметна"
    print(f"посевов в {FIXTURES.relative_to(ROOT)}: {len(seeds)} — "
          f"{[p.name for p in seeds]}")
    if not seeds:
        pytest.skip("УСЛОВИЕ НЕ СОЗДАНО: посева в дереве нет — утверждение о его "
                    "отсутствии ВЕРНО и запрету не подлежит")
    files = tracked_files(ROOT)
    assert len(files) > 1, (
        f"обход отслеживаемого дерева дал {len(files)} файл(ов) — это «не "
        f"выполнилось», а не «ноль находок»")
    hits, _, read, volume = sweep(files, root=ROOT)
    total = _print_volume(read, volume)
    assert read and total, (
        "обход пуст: прочитано файлов "
        f"{read}, единиц текста {total} — вердикта о дереве нет")
    assert not hits, (
        f"посев приехал ({len(seeds)}: {[p.name for p in seeds]}), а дерево в "
        f"{len(hits)} мест(ах) утверждает обратное:\n  " + "\n  ".join(hits))


# ── ПРЕДМЕТ 2б: число, приставленное к предикату по истории каталога фикстур ──


def test_no_prose_puts_a_number_on_the_fixture_history_predicate():
    """Утверждение, опирающееся на счёт коммитов по рефам, неопровержимо.

    Это НЕ дубль предмета 2: там утверждение ложно и становится ложным вместе с
    приездом посева, здесь величина не есть свойство дерева ВООБЩЕ — ни до, ни
    после. Поэтому предмет 2 условный (молчит, пока посева нет), а этот —
    бланкетный, и обоснование у бланкетности своё, названное у выражения.
    """
    files = tracked_files(ROOT)
    _, hits, read, volume = sweep(files, root=ROOT)
    total = _print_volume(read, volume)
    assert read and total, (
        f"обход пуст: файлов {read}, единиц {total} — вердикта нет")
    assert not hits, (
        f"в {len(hits)} мест(ах) к предикату по истории каталога фикстур приставлено "
        f"число, которого у него нет: та же команда отвечает по-разному от рефа к "
        f"рефу, значит проверить это число нечем. Предикат о посеве читает ДЕРЕВО "
        f"(`git ls-files -- tests/authz-fixtures | wc -l`):\n  " + "\n  ".join(hits))


# ── ПРЕДМЕТ 3: конвейер гоняет ТО, что перепись считает гоняемым ─────────────


def test_what_the_pipeline_runs_the_census_calls_runnable():
    """Одно расхождение — один дефект, и он ловится ОДНИМ предикатом.

    Если перепись объявляет коллекцию заблокированной, а шаг конвейера её гоняет,
    то одно из двух лжёт. Под этот предикат подпадают сразу три способа сломать
    привязку: посев перестал объявлять свою поверхность, имя поверхности
    разошлось с тем, что знает перепись, и посев перестал писать нужный ключ.
    """
    mod = _debt_module()
    runs = mod.pipeline_runs(WORKFLOWS)
    newman = ROOT / "tests" / "newman"
    if not runs:
        pytest.skip("УСЛОВИЕ НЕ СОЗДАНО: конвейер не гоняет ни одной коллекции")
    blocked = mod.blocked_stems(newman, WORKFLOWS)
    print(f"конвейер гоняет: {sorted(runs)}; перепись считает заблокированными: "
          f"{len(blocked)}")
    clash = sorted(set(runs) & set(blocked))
    assert not clash, (
        "шаг конвейера гоняет коллекции, которые перепись считает заблокированными: "
        + ", ".join(f"{s} — {'; '.join(blocked[s])}" for s in clash))


# ── ИНЪЕКЦИЯ: ОБЕ СТОРОНЫ, И РАЗБОР ПРОТИВ ГРЕПА ────────────────────────────

_WF_WITH_RUN = """\
name: proof
on: [push]
jobs:
  stand:
    steps:
      - name: коллекция гоняется
        run: |
          cd tests/newman
          ./scripts/run.sh --service kaname-own-rest-front
"""

_WF_WITHOUT_RUN = """\
name: proof
on: [push]
jobs:
  stand:
    steps:
      # тут когда-то стояло ./scripts/run.sh --service kaname-own-rest-front
      - name: ничего не гоняет
        run: echo нечего
"""


def test_injection_claim_is_red_only_when_a_step_runs_it(tmp_path):
    mod = _debt_module()
    claim = "ни одна коллекция на автономном стенде не гоняется"

    live = tmp_path / "live"
    live.mkdir()
    (live / "e2e.yml").write_text(_WF_WITH_RUN + f"\n# {claim}\n", encoding="utf-8")
    runs = mod.pipeline_runs(live)
    assert runs, "шаг прогона объявлен, а разборщик его не нашёл"
    assert claims_no_collection_runs((live / "e2e.yml").read_text(encoding="utf-8")), \
        "фраза внесена, а предикат её не видит"

    # Законный близнец: ТА ЖЕ фраза, но шага прогона нет — молчание обязательно.
    dead = tmp_path / "dead"
    dead.mkdir()
    (dead / "e2e.yml").write_text(_WF_WITHOUT_RUN + f"\n# {claim}\n", encoding="utf-8")
    assert mod.pipeline_runs(dead) == {}, (
        "`--service` стоит ТОЛЬКО в комментарии — значит разборщик читает текст, "
        "а не разобранный YAML: по грепу этот случай неотличим от объявленного шага")


def test_injection_seed_claim_is_red_only_when_a_seed_exists(tmp_path):
    claim = "В ЭТОМ РЕПОЗИТОРИИ ПОСЕВА НЕТ НИ ОДНИМ ФАЙЛОМ"
    assert claims_no_seed(claim), "фраза внесена, а предикат её не видит"
    assert not claims_no_seed(
        "посев приехал и доказывает себя инъекцией в форме --self-test"), \
        "законная формулировка объявлена находкой — предикат бланкетный"


def test_injection_prose_and_fixture_are_told_apart(tmp_path):
    """Литерал внутри кода — НЕ утверждение о дереве, и это доказывается парой.

    Без этой оси предикат был бы бланкетным: он краснел бы на синтетике инъекции,
    то есть требовал бы переписать законную пробу ради фразы в её фикстуре.
    """
    victim = tmp_path / "subject.py"
    victim.write_text(
        '"""Шапка: В ЭТОМ РЕПОЗИТОРИИ ПОСЕВА НЕТ НИ ОДНИМ ФАЙЛОМ."""\n'
        "SYNTHETIC = \"pytest.skip('посев не приехал в этот репозиторий')\"\n"
        "# и комментарий: посев не приехал\n",
        encoding="utf-8")
    hits = claims_no_seed(victim)
    assert len(hits) == 2, (
        f"ожидались ДВЕ находки (шапка и комментарий), литерал в счёт не идёт; "
        f"получено {len(hits)}: {hits}")
    assert any("строка 1" in h for h in hits), f"шапка не найдена: {hits}"
    assert not any("SYNTHETIC" in h for h in hits), f"литерал засчитан: {hits}"
# ── ИНЪЕКЦИЯ ОБХОДА: КООРДИНАТА НАХОДИТСЯ, БЛИЗНЕЦ МОЛЧИТ ────────────────────


def _tree(tmp_path, files: dict) -> tuple[pathlib.Path, list[pathlib.Path]]:
    """Синтетическое дерево: обход принимает СОСТАВ, а не зовёт git.

    Иначе инъекция требовала бы репозитория под временным каталогом, то есть
    доказывала бы заодно поведение git, а не выражения.
    """
    paths = []
    for rel, body in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        paths.append(path)
    return tmp_path, paths


def test_injection_sweep_finds_the_claim_in_any_file_and_names_it(tmp_path):
    """Внесённое утверждение находится С КООРДИНАТОЙ — в ЛЮБОМ файле дерева.

    Ось, которой у прежней редакции не было: она судила два пинованных адреса, и
    третье место того же утверждения — комментарий в пробе набора — проезжало
    молча. Здесь оно вносится ИМЕННО туда, где проехало.
    """
    claim = "В репозиторий службы посев не приехал ни одним файлом"
    root, files = _tree(tmp_path, {
        "tests/newman/scripts/some_probe_test.py":
            "def test_x():\n"
            f"    # ПРЕМИССА: {claim} (предикат ниже)\n"
            "    pass\n",
        "docs/note.md": f"Заметка: {claim}.\n",
        "internal/app/seed.go": f"package app\n\n// {claim}\n",
        "deploy/run.sh": f"#!/bin/sh\n# {claim}\necho ok\n",
        "internal/migrations/1.sql": f"-- {claim}\nSELECT 1;\n",
    })
    hits, _, read, volume = sweep(files, root=root)
    assert read == 5, f"прочитано {read} файл(ов) из 5: {volume}"
    assert len(hits) == 5, f"ожидались пять находок по пяти формам, получено {hits}"
    forms = {h.split("[", 1)[1].split("]", 1)[0] for h in hits}
    assert forms == {"2-комментарий", "7-проза", "4-C//", "5-решётка", "11-sql"}, forms
    assert any("some_probe_test.py:2" in h for h in hits), (
        f"координата пробы набора не названа — ровно она и проезжала: {hits}")


def test_injection_sweep_is_silent_on_prose_about_the_class(tmp_path):
    """Законный близнец: проза О КЛАССЕ, а не утверждение о дереве, — молчит.

    Без этой оси запрет был бы бланкетным и требовал бы переписать всякий разбор
    класса, включая этот файл.
    """
    root, files = _tree(tmp_path, {
        "tests/newman/scripts/twin_test.py":
            "def test_y():\n"
            "    # Класс: утверждение о дереве переживает свой предмет, и держатель\n"
            "    # краснеет, когда предмет вернулся. Посев тут приехал.\n"
            "    pass\n",
        "docs/twin.md": "Посев приехал и доказывает себя инъекцией `--self-test`.\n",
        "internal/app/twin.go":
            "package app\n\n"
            '// посев не приехал — это СТРОКА фикстуры ниже, а не утверждение\n'
            'const s = "посев не приехал"\n',
    })
    hits, _, read, volume = sweep(files, root=root)
    assert read == 3, f"прочитано {read} из 3: {volume}"
    go_hits = [h for h in hits if "twin.go" in h]
    assert len(go_hits) == 1 and "4-C//" in go_hits[0], (
        f"комментарий Go обязан находиться, а строковый литерал — нет: {hits}")
    assert not [h for h in hits if "twin.go" not in h], (
        f"проза о классе объявлена находкой — запрет бланкетный: {hits}")


def test_injection_sweep_excludes_only_the_predicate_owner(tmp_path):
    """Исключение — ОДИН файл, и он свой. Близнец в чужом файле обязан найтись."""
    root, files = _tree(tmp_path, {
        "other.py": 'MSG = 1\n# посев не приехал ни одним файлом\n',
    })
    hits, _, _, _ = sweep(files, root=root)
    assert len(hits) == 1, f"близнец в чужом файле не найден: {hits}"
    # Тот же текст в ЭТОМ файле обходом не судится, и это единственный адрес.
    hits_self, _, read_self, _ = sweep([SELF], root=SELF.parent)
    assert read_self == 0 and not hits_self, (
        f"производитель выражения судит собственную прозу: прочитано {read_self}, "
        f"находок {hits_self}")


def test_injection_sweep_rejects_an_empty_traversal(tmp_path):
    """Пустой обход — «не выполнилось», а не «ноль находок»."""
    hits, hits_b, read, volume = sweep([], root=tmp_path)
    assert (read, hits, hits_b, volume) == (0, [], [], {}), (read, hits, hits_b, volume)
    # Именно поэтому обе пробы выше требуют read и total НЕПУСТЫМИ: пустой обход
    # без этого требования дал бы «нарушений нет».


# ── ИНЪЕКЦИЯ ОСИ B: ЧИСЛО У ИСТОРИИ КРАСНЕЕТ, ЧИСЛО У ДЕРЕВА МОЛЧИТ ──────────


def test_injection_number_on_history_is_red_number_on_tree_is_not():
    red = ("предикат: `git log --oneline --all -- tests/authz-fixtures | wc -l` → 0 "
           "за всю его историю")
    assert cites_fixture_history_count(red), f"внесённое число не найдено: {red}"

    red_words = ("предикатом снятия была история каталога "
                 "(`git log --all -- tests/authz-fixtures`). Предикат даёт 3")
    assert cites_fixture_history_count(red_words), (
        "число, приставленное словом «даёт», не найдено — выражение знает только "
        "стрелку, и редакция обходит его переписыванием")

    green_tree = "`git ls-files -- tests/authz-fixtures | wc -l` → 2, из них посев один"
    assert not cites_fixture_history_count(green_tree), (
        "число у предиката ПО ДЕРЕВУ объявлено находкой — запрет бланкетный")

    green_named = ("предикатом снятия была ИСТОРИЯ каталога фикстур — счёт коммитов, "
                   "достижимых из рефов копии; свойством дерева он не является")
    assert not cites_fixture_history_count(green_named), (
        "история, названная негодной БЕЗ числа, объявлена находкой")

    green_other = "`git log --oneline -- internal/` → 12 коммитов"
    assert not cites_fixture_history_count(green_other), (
        "история ЧУЖОГО каталога объявлена находкой — выражение не различает предмет")
