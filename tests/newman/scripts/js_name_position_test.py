# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Значение вызывающего, попадающее в ИМЯ порождаемого скрипта (#1220).

ПРЕДМЕТ — ПОЗИЦИЯ, А НЕ ЗНАКИ
=============================
Соседние корпуса закрываются экранированием: значение остаётся значением, а
меняется лишь его запись — строка через `js_str` (#1181), литерал выражения
через `js_regex_src`/`js_regex_literal_text` (#1202). Здесь значение садится в
ИМЯ: в лексему-идентификатор порождаемого кода либо в ключ переменной прогона
(`pm.environment.get('_ck_…')`).

У имени исхода «экранировать» НЕТ, и это не оговорка, а свойство позиции:

  * имя либо годно, либо порождаемый файл не разбирается вовсе;
  * там, где значение — лишь ЧАСТЬ имени, сериализатор ХУЖЕ отказа: он вернёт
    разбираемый скрипт с ДРУГИМ именем, и тот, кто имя пишет, разойдётся с тем,
    кто его читает;
  * то же имя уезжает и в АДРЕС (`/operations/{{_…RevOp}}`), а адрес — не
    JavaScript: сериализатор строки там неприменим by construction. Экранировать
    одну сторону и не экранировать другую значит развести писателя и читателя
    МОЛЧА.

Исходов ровно два: проверить годность при генерации (отказ называет место) либо
не подставлять в имя вовсе.

ПОЧЕМУ ЭТО НЕ ВИДНО В ВЕРДИКТЕ
==============================
newman записывает исключение скрипта в `testScripts`, а НЕ в `assertions.failed`.
Шаг, чей скрипт не разобрался, даёт НОЛЬ упавших утверждений: кейс перестаёт
проверять что бы то ни было и продолжает отчитываться зелёным по этой величине.
Третья категория исхода («не выполнилось»), зачтённая в «прошло».

ДВЕ ФОРМЫ ОДНОЙ ПОЗИЦИИ, И ЗАКРЫВАЕТСЯ ЗДЕСЬ ОДНА
=================================================
Разбор различает их по соседнему знаку ПОРОЖДАЕМОГО текста:

  * ФРАГМЕНТ имени — значение склеено с буквами имени (`_ck_{name}`,
    `_{tag}Started`). Здесь ломается и синтаксис, и ТОЖДЕСТВО имени: подпись
    `tuple-present-vol`, отображённая `-`→`_`, даёт тот же ключ, что подпись
    `tuple_present_vol`. Это предмет #1220, и он закрывается;
  * ИМЯ ЦЕЛИКОМ — значение и есть весь ключ (`pm.environment.get('{op_var}')`).
    Шов там объявляет имя своим контрактом, тождество склейкой не рушится, а
    синтаксическая сторона уже лежит внутри корпуса #1181 (подстановка в
    строковый литерал) и держится его храповиком. Заводить над теми же местами
    второй храповик значило бы завести два места об одном предмете, поэтому
    здесь эта форма названа ЧИСЛОМ (`WHOLE_NAME_CEILING`) и не более того.

ЧТО УТВЕРЖДАЕТ ЭТА ПРОБА
========================
1. ФОРМА, по всему дереву: каждая ФРАГМЕНТНАЯ подстановка в позицию имени несёт
   ЗАПИСАННЫЙ исход. Место без записи и запись без места — обе находки, и каждая
   своим утверждением, иначе ведомость переживёт свой предмет.
2. ФОРМА, по провенансу: шов, записанный как ИМЯ, обязан проверяться при
   генерации — в ТОЙ ЖЕ функции, ДО подстановки, значение обязано быть
   присвоено через `js_name`. Проверка «где-то в файле» пропустила бы вторую
   функцию с тем же именем параметра, а их в дереве две.
3. СУЩЕСТВО: `js_name` на негодном имени ОТКАЗЫВАЕТ и называет место, а рядом
   доказано, что отказ не вакуумен — то же значение без помощника даёт
   неразбираемый скрипт (судит НАСТОЯЩИЙ движок) либо разбираемый скрипт с
   ЧУЖИМ ключом.
4. ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: законное имя проходит ДОСЛОВНО, а порождаемый шаг
   по-прежнему разбирается. Без него зелёное давал бы помощник, отвергающий всё.
5. ПЕРЕПИСЬ печатает объём осмотренного и падает на пустом обходе: «ноль
   находок» обязано быть отличимо от «ноль прочитанного».

ГРАНИЦЫ, НАЗВАННЫЕ ЧИСЛОМ, А НЕ УМОЛЧАНИЕМ
==========================================
  * СОСТОЯНИЕ СЧИТАЕТСЯ НА f-СТРОКУ (см. `newman_js_lexer`): литерал, открытый в
    одном элементе списка и закрытый в соседнем, разбору невидим. Держится
    утверждением, а не памятью: перепись печатает это число и падает на ненуле;
  * ОСМАТРИВАЕТСЯ ТОЛЬКО `ast.JoinedStr`. Имя, собранное конкатенацией
    (`"/operations/{{" + op_var + "}}"`), под перепись не подпадает — но это и не
    JavaScript, а адрес; и его источник — то же значение, которое проверяет
    `js_name` на шве кода. Число формы печатается переписью;
  * ключом переменной прогона считается литерал, открытый НЕПОСРЕДСТВЕННО после
    вызова доступа (`pm.environment.get(` и родня). Ключ, собранный в
    промежуточной переменной JavaScript, разбору невидим; их число печатается
    отдельным утверждением и сегодня равно нулю.

ПОЧЕМУ ПРОБА ЛЕЖИТ ЗДЕСЬ
========================
Каталог выбран не по принадлежности предмета (места в двух сюитах), а по тому,
кто пробу ИСПОЛНЯЕТ: `.github/scripts/run-python-probes.py` собирает состав по
образцу `services/*/tests/newman/scripts/*_test.py`. Проба, положенная
«правильнее» — в `deploy/` или в `gateway/`, — не исполнялась бы вовсе, а это
ровно тот класс, который она и стережёт. Та же причина и у обоих близнецов.
"""
import ast
import importlib.util
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import newman_js_lexer as jslex  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[5]
CASE_GLOBS = ("services/*/tests/newman/cases/*.py",
              "gateway/tests/newman/cases/*.py")
GEN_GLOBS = ("services/*/tests/newman/scripts/gen.py",
             "gateway/tests/newman/scripts/gen.py")
ALL_GLOBS = CASE_GLOBS + GEN_GLOBS

NAME, CODE = "имя", "код"

# Знаки, из которых состоит имя. Склейка подстановки с любым из них означает,
# что значение становится ЧАСТЬЮ одной лексемы, а не отдельной.
_IDCH = re.compile(r"[A-Za-z0-9_$]")

# Доступ к переменной ПРОГОНА: за открывающей скобкой идёт ИМЯ, а не значение.
_ACCESSOR = re.compile(
    r"pm\.(environment|collectionVariables|variables|globals|iterationData)"
    r"\.(get|set|unset|has|replaceIn)\(\s*$")

# ВЕДОМОСТЬ ИСХОДОВ. Ключ — (файл, функция, что подставляется). Номер строки не
# годится: он двигается от чужой правки. Функция входит в ключ потому, что одно
# и то же имя параметра встречается в РАЗНЫХ функциях одного файла, и запись «на
# файл» разрешила бы вторую из них молча.
RECORDED = {
    # ИМЯ: значение сплавляется в ключ переменной прогона → проверка при генерации.
    ("services/iam/tests/newman/cases/iam-rbac-scope-grant.py",
     "revoke_binding_steps", "acb_var"): NAME,
    ("services/iam/tests/newman/cases/iam-rbac-subjects.py",
     "teardown_delete", "op_var"): NAME,
    ("services/iam/tests/newman/cases/rbac-subject-channel-equivalence.py",
     "poll_op", "op_var"): NAME,
    ("services/iam/tests/newman/cases/rbac-subject-channel-equivalence.py",
     "pre_clean", "tag"): NAME,
    ("services/iam/tests/newman/cases/rbac-subject-channel-equivalence.py",
     "_revoke_phantom", "grant_op_var"): NAME,
    ("services/iam/tests/newman/cases/rbac-subject-channel-equivalence.py",
     "revoke_await", "rev_op_var"): NAME,
    ("services/iam/tests/newman/cases/rbac-subject-channel-equivalence.py",
     "member_op", "op_var"): NAME,
    ("services/iam/tests/newman/cases/rbac-visibility-set.py",
     "preclean_account_loop", "tag"): NAME,
    ("services/storage/tests/newman/cases/sec-d.py",
     "_check_step", "counter"): NAME,
    # НЕ ИМЯ: здесь подставляется КОД — готовый фрагмент условия
    # (`" && b.roleId === '…'"`), и шов это объявляет. В позицию склейки он
    # попадает лишь потому, что фрагмент НАЧИНАЕТСЯ разделителем; знаки самого
    # фрагмента — предмет другого корпуса (подстановка кода), не #1220.
    # Запись самоистекает: перестанет шов быть склеенным — она потеряет предмет
    # и станет находкой утверждения «запись без места».
    ("services/iam/tests/newman/cases/iam-authz-grant-check-propagation.py",
     "resolve_binding_id_step", "role_filter"): CODE,
}

# Потолок соседней формы: подстановок, где значение — ИМЯ ЦЕЛИКОМ (весь ключ).
# Замер 2026-08-24 на `f091a8026` + эта правка. Расти нельзя; закрыли место —
# опустите число тем же изменением. Ноль означает, что форма кончилась и храповик
# пора снять вместе с ней.
WHOLE_NAME_CEILING = 157


# ------------------------------------------------------------------ разбор

def _owner(tree: ast.AST, lineno: int) -> str:
    """Имя ВНУТРЕННЕЙ функции, накрывающей строку; «<модуль>» — если её нет."""
    best = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.lineno <= lineno <= (node.end_lineno or node.lineno):
            if best is None or node.lineno > best.lineno:
                best = node
    return best.name if best else "<модуль>"


def _root_name(expr: str) -> str:
    """Корневое имя выражения подстановки: `acb_var`, `name.replace(…)` → `name`."""
    try:
        node = ast.parse(expr, mode="eval").body
    except SyntaxError:  # pragma: no cover — выражение всегда разбирается
        return expr
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    if isinstance(node, ast.Call):
        return node.func.id if isinstance(node.func, ast.Name) else ""
    return node.id if isinstance(node, ast.Name) else ""


def _split(places):
    """(фрагменты имени, имя целиком) — ОДИН предикат на дерево и на синтетику.

    Второй копии здесь не заводится намеренно: копия разошлась бы с оригиналом
    молча — и разошлась бы именно там, где расхождение не видно, то есть в
    самопроверке, которая и должна доказывать способность гейта упасть.
    """
    frag, whole = [], []
    for pl in places:
        glued = bool(_IDCH.match(pl.before or "")) or bool(_IDCH.match(pl.after or ""))
        if pl.state == jslex.CODE:
            if glued:
                frag.append(pl)
        elif pl.state in jslex.IN_STRING and _ACCESSOR.search(pl.opener or ""):
            (frag if glued else whole).append(pl)
    return frag, whole


def _places():
    """(файлы, перепись, фрагменты имени, имя целиком) — ОБХОДОМ дерева."""
    paths, total, places = jslex.scan_tree(REPO_ROOT, ALL_GLOBS)
    frag, whole = _split(places)
    return paths, total, frag, whole


def _seams(places):
    """{(файл, функция, выражение): [подстановки]} — ключ ведомости."""
    trees, out = {}, {}
    for pl in places:
        if pl.path not in trees:
            trees[pl.path] = ast.parse((REPO_ROOT / pl.path).read_text(encoding="utf-8"))
        out.setdefault((pl.path, _owner(trees[pl.path], pl.lineno), pl.expr),
                       []).append(pl)
    return out


def _checked_before(source: str, func: str, root: str, lineno: int) -> bool:
    """Присвоено ли `root` через `js_name` В ТОЙ ЖЕ функции и ДО этой строки."""
    tree = ast.parse(source)
    scopes = [n for n in ast.walk(tree)
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == func] or [tree]
    for scope in scopes:
        if isinstance(scope, ast.Module) is False and not (
                scope.lineno <= lineno <= (scope.end_lineno or scope.lineno)):
            continue
        for node in ast.walk(scope):
            if not isinstance(node, ast.Assign) or node.lineno >= lineno:
                continue
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if root not in targets:
                continue
            for inner in ast.walk(node.value):
                if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name) \
                        and inner.func.id == "js_name":
                    return True
    return False


# --------------------------------------------------------------- генераторы

def _generators() -> dict:
    """Генераторы сюит — ОБХОДОМ ДЕРЕВА, а не перечнем."""
    mods = {}
    for glob in GEN_GLOBS:
        for path in sorted(REPO_ROOT.glob(glob)):
            name = path.parts[len(REPO_ROOT.parts)]
            if name == "services":
                name = path.parts[len(REPO_ROOT.parts) + 1]
            spec = importlib.util.spec_from_file_location(f"kacho_name_gen_{name}", path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            sys.path.insert(0, str(path.parent))
            try:
                spec.loader.exec_module(module)
            finally:
                sys.path.pop(0)
            mods[name] = module
    assert mods, "генераторов в дереве НЕ НАЙДЕНО — проба беспредметна, а не зелена"
    return mods


GENERATORS = _generators()


def _parses(source: str):
    """(разобралось?, ответ движка). Обёртка-функция — как исполняет postman."""
    driver = ("const fs=require('fs');"
              "try{new Function(fs.readFileSync(process.argv[1],'utf8'));"
              "process.stdout.write('OK');}"
              "catch(e){process.stdout.write('ERR '+e.name+': '+e.message);}")
    with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8",
                                     delete=False) as fh:
        fh.write(source)
        name = fh.name
    try:
        proc = subprocess.run(["node", "-e", driver, name],
                              capture_output=True, text=True, timeout=60)
    except FileNotFoundError:  # pragma: no cover — окружение без node
        raise AssertionError(
            "node не найден: разобрать порождаемый JavaScript нечем. Это «ноль "
            "прочитанного», а не «ноль находок», поэтому проба ПАДАЕТ.") from None
    finally:
        Path(name).unlink(missing_ok=True)
    out = proc.stdout.strip()
    assert out.startswith(("OK", "ERR")), f"разборщик не ответил: {proc!r}"
    return out == "OK", out


# ------------------------------------------------------------------- форма

def test_every_name_fragment_carries_a_recorded_outcome():
    """ФОРМА + перепись. Место без записи и запись без места — обе находки."""
    paths, total, frag, whole = _places()
    assert paths, "деклараций и генераторов не найдено — перепись беспредметна"
    assert total["js_fstrings"], (
        "f-строк, порождающих JavaScript, не найдено НИ ОДНОЙ — предикат переписи "
        "перестал узнавать свой предмет, и его молчание ничего не значит")
    assert total["open_at_end"] == 0, (
        f"f-строк, оставляющих литерал открытым: {total['open_at_end']}. "
        f"Состояние считается НА f-строку, поэтому такие места разбору невидимы "
        f"и перепись занизила бы себя МОЛЧА")

    seams = _seams(frag)
    unrecorded = sorted(k for k in seams if k not in RECORDED)
    assert not unrecorded, (
        "подстановка в ФРАГМЕНТ имени без записанного исхода: "
        + "; ".join(f"{p}::{f}::{{{e}}}" for p, f, e in unrecorded)
        + ". Исходов два: проверить годность при генерации (`js_name`) либо не "
          "подставлять в имя. Экранирования среди них НЕТ — имя либо годно, либо "
          "порождаемый скрипт не разбирается")
    orphan = sorted(k for k in RECORDED if k not in seams)
    assert not orphan, (
        "запись ведомости без места в дереве: "
        + "; ".join(f"{p}::{f}::{{{e}}}" for p, f, e in orphan)
        + ". Исключение живёт, пока у него есть предмет: снимите запись тем же "
          "изменением, которым сняли шов")

    print(f"осмотрено: файлов {len(paths)}, f-строк {total['fstrings']}, "
          f"порождающих JavaScript {total['js_fstrings']}, подстановок "
          f"{total['interpolations']}; в позиции ИМЕНИ {len(frag) + len(whole)} "
          f"(фрагментом {len(frag)} в {len(seams)} швах, целиком {len(whole)})")
    if not frag and not RECORDED:
        print("    предмет исчерпан: фрагментных швов ноль — снимите ведомость "
              "вместе с этим утверждением")


def test_every_fragment_recorded_as_a_name_is_checked_at_generation():
    """ПРОВЕНАНС: записанное как ИМЯ проверяется `js_name` в той же функции."""
    _paths, _total, frag, _whole = _places()
    seams = _seams(frag)
    unguarded, names = [], 0
    for key, places in sorted(seams.items()):
        if RECORDED.get(key) != NAME:
            continue
        names += 1
        path, func, expr = key
        first = min(pl.lineno for pl in places)
        root = _root_name(expr)
        if "js_name" in expr:
            continue
        source = (REPO_ROOT / path).read_text(encoding="utf-8")
        if not root or not _checked_before(source, func, root, first):
            unguarded.append(f"{path}::{func}::{{{expr}}} (первая подстановка "
                             f"строка {first})")
    assert not unguarded, (
        f"швов, записанных как ИМЯ, но НЕ проверяемых при генерации: "
        f"{len(unguarded)}\n  " + "\n  ".join(unguarded)
        + "\n  Присвойте значение через `js_name(..., where=…)` В ТОЙ ЖЕ функции "
          "и ДО подстановки: негодное имя обязано ронять генерацию с именем "
          "места, а не рвать синтаксис коллекции там, где автор значения этого "
          "не увидит")

    # Помощник обязан ПРИЕЗЖАТЬ в декларацию: объявленная проверка, которой в
    # пространстве имён нет, роняла бы генерацию `NameError`, а не отказом.
    suites = sorted({p.split("/")[1] for p, _f, _e in seams
                     if RECORDED.get((p, _f, _e)) == NAME})
    missing = [s for s in suites if not hasattr(GENERATORS.get(s), "js_name")]
    assert not missing, (
        f"сюиты, чья декларация зовёт `js_name`, а генератор его не впрыскивает: "
        f"{missing}")
    print(f"осмотрено: швов ИМЯ {names}, сюит с впрыском {len(suites)}")


def test_the_forms_outside_the_census_are_named_by_number():
    """Формы вне переписи названы ЧИСЛОМ: ноль без имени читается как «искали»."""
    concat, computed_key = 0, 0
    for glob in ALL_GLOBS:
        for path in sorted(REPO_ROOT.glob(glob)):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                # Имя, собранное конкатенацией: это АДРЕС (`{{…}}`), не JavaScript.
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                    flat = [node.left, node.right]
                    if any(isinstance(x, ast.Constant) and isinstance(x.value, str)
                           and "{{" in x.value for x in flat):
                        concat += 1
                # Ключ, собранный в переменной JavaScript: разбору он невидим.
                if isinstance(node, ast.JoinedStr):
                    static = "".join(v.value for v in node.values
                                     if isinstance(v, ast.Constant))
                    if re.search(r"pm\.environment\.(get|set|unset)\(\s*[A-Za-z_$]",
                                 static):
                        computed_key += 1
    assert computed_key == 0, (
        f"ключей переменной прогона, собранных в ПЕРЕМЕННОЙ JavaScript: "
        f"{computed_key}. Разбор такой ключ не видит, поэтому перепись занизила "
        f"бы себя молча — либо соберите ключ на месте, либо расширьте предикат")
    print(f"осмотрено вне переписи: имён через конкатенацию (адрес, не JavaScript) "
          f"{concat}, ключей из переменной JavaScript {computed_key}")


def test_the_whole_name_corpus_is_named_by_number():
    """ГРАНИЦА формы «имя целиком» названа числом и держится храповиком."""
    _paths, _total, _frag, whole = _places()
    assert len(whole) <= WHOLE_NAME_CEILING, (
        f"подстановок, где значение — ИМЯ ЦЕЛИКОМ: {len(whole)} при потолке "
        f"{WHOLE_NAME_CEILING}. Расти этой границе нельзя: новое место обязано "
        f"либо проверяться `js_name`, либо не подставлять в имя")
    if len(whole) < WHOLE_NAME_CEILING:
        print(f"    храповик пора опустить: {WHOLE_NAME_CEILING} -> {len(whole)}"
              + ("; форма кончилась — снимите храповик вместе с ней"
                 if not whole else ""))
    print(f"осмотрено: подстановок «имя целиком» {len(whole)} в "
          f"{len(_seams(whole))} швах")


# ---------------------------------------------------------------- существо

# ВРАЖДЕБНЫЕ ИМЕНА РАЗДЕЛЕНЫ ПО ВРЕДУ, и разделение это не косметическое: у двух
# половин РАЗНЫЕ наблюдаемые следствия, и вторая — причина, по которой проверка
# «а разбирается ли?» этот класс НЕ закрывает.
HOSTILE_TO_SYNTAX = [
    ("апостроф закрывает литерал ключа", "tuple-present-vol's"),
    ("обратный слэш экранирует закрывающую кавычку", "vol\\"),
    ("конец строки рвёт строку скрипта", "vol\nnext"),
]

# Эти скрипт НЕ ломают: внутри одинарных кавычек они законные ЗНАКИ. Ломается
# другое — ИМЯ: ключ перестаёт быть именем, и автор значения не узнает об этом
# ниоткуда, потому что и разбор, и прогон молчат.
HOSTILE_TO_THE_NAME = [
    ("двойная кавычка", 'say"no"'),
    ("пробел разрывает лексему", "two words"),
    ("закрывающая скобка", "vol)"),
    ("подстановка окружения внутри имени: ключом станет её ТЕКСТ", "{{volId}}"),
]

HOSTILE_NAMES = HOSTILE_TO_SYNTAX + HOSTILE_TO_THE_NAME + [("пустое имя", "")]

BENIGN_NAMES = ["chUserAcbRevOp", "_ck_tuple_present_vol", "tag17", "A_b_9"]


def test_a_hostile_name_is_refused_with_the_place():
    """СУЩЕСТВО: негодное имя роняет генерацию и называет МЕСТО."""
    checked = 0
    for svc, mod in sorted(GENERATORS.items()):
        js_name = getattr(mod, "js_name", None)
        if js_name is None:
            continue
        for why, value in HOSTILE_NAMES:
            where = f"{svc}/проба/{why}"
            try:
                js_name(value, where=where)
            except ValueError as exc:
                assert where in str(exc), (
                    f"{svc}: отказ на {value!r} ({why}) НЕ называет место: {exc}")
                checked += 1
                continue
            raise AssertionError(
                f"{svc}: негодное имя {value!r} ({why}) ПРИНЯТО. Имя не "
                f"экранируется — принятое негодное уедет в коллекцию и там "
                f"либо порвёт синтаксис, либо назовёт ЧУЖУЮ переменную")
    assert checked, "генераторов с `js_name` не найдено — проба беспредметна"
    print(f"осмотрено: генераторов с `js_name` "
          f"{sum(1 for m in GENERATORS.values() if hasattr(m, 'js_name'))}, "
          f"негодных имён {len(HOSTILE_NAMES)}, отказов {checked}")


def _key_line(value: str) -> str:
    """Тот же шов, что у настоящего кейса: ключ переменной прогона со склейкой."""
    return (f"if (pm.environment.get('_ck_{value}_started') !== pm.info.requestName)"
            f" {{ pm.environment.set('_ck_{value}', '0'); }}")


def test_the_refusal_has_a_subject_hostile_names_break_the_script():
    """ПРЕДМЕТ отказа: эти имена без помощника дают НЕРАЗБИРАЕМЫЙ скрипт."""
    kept = []
    for why, value in HOSTILE_TO_SYNTAX:
        ok, answer = _parses(_key_line(value))
        if ok:
            kept.append(f"{value!r} ({why})")
    assert not kept, (
        "имена, объявленные рвущими синтаксис, движок ПРИНЯЛ: " + "; ".join(kept)
        + ". Тогда у этой половины утверждения нет предмета — либо шов сменился, "
          "либо список устарел")
    for value in BENIGN_NAMES:
        ok, answer = _parses(_key_line(value))
        assert ok, f"законное имя {value!r} рвёт скрипт: {answer}"
    print(f"осмотрено: имён, рвущих синтаксис, {len(HOSTILE_TO_SYNTAX)}; "
          f"законных, скрипт сохраняющих, {len(BENIGN_NAMES)}")


def test_the_shape_check_catches_what_a_parse_check_would_miss():
    """ПОЧЕМУ проверка формы, а не «разбирается ли»: половина вреда молчалива.

    Эти имена дают РАЗБИРАЕМЫЙ скрипт — и потому проверка разбором (та, что уже
    стоит над сгенерированными коллекциями) их пропускает целиком. Ключ при этом
    именем быть перестаёт: `{{volId}}` станет ключом ДОСЛОВНО, а не значением
    переменной; пробел и скобка дают ключ, которого ни один читатель не назовёт.
    Значит утверждение «скрипт разбирается» не покрывает предмет #1220, и это
    здесь ДОКАЗАНО движком, а не объявлено.
    """
    missed = []
    for why, value in HOSTILE_TO_THE_NAME:
        ok, _answer = _parses(_key_line(value))
        if not ok:
            missed.append(f"{value!r} ({why})")
    assert not missed, (
        "имена, объявленные молчаливыми, движок ОТВЕРГ: " + "; ".join(missed)
        + ". Тогда они принадлежат первой половине, и это утверждение теряет "
          "предмет — перенесите их в HOSTILE_TO_SYNTAX")
    print(f"осмотрено: имён, которые проверка разбором ПРОПУСКАЕТ, "
          f"{len(HOSTILE_TO_THE_NAME)} — их ловит только проверка формы имени")


def test_a_legitimate_name_passes_verbatim_and_the_step_parses():
    """ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ на настоящем шве: подпись → ключ → разбор."""
    gen = GENERATORS["storage"]
    mod = gen._RUN.load(
        REPO_ROOT / "services/storage/tests/newman/cases/sec-d.py")
    step = mod._check_step("tuple-present-vol", "storage_volume", "volumeId",
                           expect_allowed=True)
    body = "\n".join(step.test_script)
    assert "_ck_volumeId_present" in body, (
        "законное имя перестало доходить до ключа ДОСЛОВНО — помощник "
        f"переписывает значение, а не проверяет его: {body[:300]}")
    ok, answer = _parses(body)
    assert ok, f"законный шаг не разбирается: {answer}"
    for svc, m in sorted(GENERATORS.items()):
        js_name = getattr(m, "js_name", None)
        if js_name is None:
            continue
        for value in BENIGN_NAMES:
            got = js_name(value, where=f"{svc}/контроль")
            assert got == value, (
                f"{svc}: законное имя {value!r} вернулось как {got!r} — помощник "
                f"переписывает имя, и писатель разойдётся с читателем")
    print(f"осмотрено: законных имён {len(BENIGN_NAMES)} на "
          f"{sum(1 for m in GENERATORS.values() if hasattr(m, 'js_name'))} "
          f"генераторах, плюс настоящий шаг storage")


def test_the_name_no_longer_derives_from_the_step_title():
    """ИСХОД 2 на настоящем шве: подстановка ПРОЗЫ в имя СНЯТА, а не починена.

    ПРЕДМЕТ ДОКАЗАН, а не объявлен: прежняя сборка ключа (`_ck_` + подпись, где
    `-` переведён в `_`) неоднозначна — две РАЗНЫЕ подписи дают ОДИН ключ, и
    скрипт при этом разбирается, поэтому ни один разбор такого не поймает. Ниже
    это воспроизведено, а затем показано, что сегодняшний ключ от подписи не
    зависит вовсе.
    """
    collide = {n: f"_ck_{n.replace('-', '_')}"
               for n in ("tuple-present-vol", "tuple_present_vol")}
    assert len(set(collide.values())) == 1, (
        "прежняя сборка перестала сводить две подписи в один ключ — утверждение "
        "потеряло предмет, и вместе с ним отпадает довод в пользу снятия")

    gen = GENERATORS["storage"]
    mod = gen._RUN.load(
        REPO_ROOT / "services/storage/tests/newman/cases/sec-d.py")

    def key_of(title):
        step = mod._check_step(title, "storage_volume", "volumeId",
                               expect_allowed=True)
        keys = {m for line in step.test_script
                for m in re.findall(r"_ck_[A-Za-z0-9_]+", line)}
        assert keys, f"шаг перестал нести ключ переменной прогона: {step.test_script}"
        return keys

    a = key_of("tuple-present-vol")
    b = key_of("совсем другая подпись — и с апострофом'")
    assert a == b, (
        f"ключ по-прежнему зависит от ПОДПИСИ шага: {sorted(a)} против "
        f"{sorted(b)}. Пока зависит — подпись остаётся источником имени, и вред "
        f"снят не был")
    assert all("volumeId" in k for k in a), (
        f"ключ выводится не из `id_var`: {sorted(a)}. Тогда неизвестно, из чего "
        f"он выводится, и утверждение о снятии прозы вакуумно")

    # Две пробы одного ресурса обязаны остаться РАЗЛИЧИМЫМИ: общий ключ вернул бы
    # тот самый вред, ради которого подстановку снимали.
    withdrawn = mod._check_step("tuple-withdrawn-vol", "storage_volume", "volumeId",
                                expect_allowed=False)
    wk = {m for line in withdrawn.test_script
          for m in re.findall(r"_ck_[A-Za-z0-9_]+", line)}
    assert wk.isdisjoint(a), (
        f"проба «применён» и проба «снят» делят ключ {sorted(wk & a)} — общий "
        f"счётчик означает общий бюджет повторов")
    print(f"осмотрено: подписей 2 → ключ один и тот же {sorted(a)}; "
          f"ожиданий 2 → ключи различны")


# ------------------------------------------------- способность упасть и смолчать

# Синтетика повторяет ФОРМУ настоящей декларации, а не её упрощение: шаг
# собирается f-строкой, ключ переменной прогона склеен с суффиксом, значение
# приходит параметром. Фикстура, снисходительнее продукта, сделала бы невидимым
# ровно тот дефект, ради которого её ставят.
_SYNTHETIC_UNGUARDED = '''
def teardown(op_var):
    return [
        f"if (pm.environment.get('_{op_var}Started') !== pm.info.requestName) {{ pm.environment.set('_{op_var}Count', '0'); }}",
    ]
'''

_SYNTHETIC_GUARDED = '''
def teardown(op_var):
    op_var = js_name(op_var, where="синтетика/teardown/op_var")
    return [
        f"if (pm.environment.get('_{op_var}Started') !== pm.info.requestName) {{ pm.environment.set('_{op_var}Count', '0'); }}",
    ]
'''

# ЗАКОННЫЙ БЛИЗНЕЦ той же формы: значение — ИМЯ ЦЕЛИКОМ, а не его часть. Гейт
# обязан молчать: склейки нет, тождество имени значением не рушится, а
# синтаксическая сторона принадлежит соседнему корпусу (#1181).
_SYNTHETIC_WHOLE = '''
def teardown(op_var):
    return [
        f"if (pm.environment.get('{op_var}') !== pm.info.requestName) {{ pm.environment.set('{op_var}', '0'); }}",
    ]
'''

# ВТОРОЙ ЗАКОННЫЙ БЛИЗНЕЦ: та же склейка, но НЕ в имени — внутри подписи шага.
# Там значение остаётся текстом, и его исход — сериализатор (#1181), не проверка
# годности имени. Гейт, ловящий форму «склеено», покраснел бы и здесь.
_SYNTHETIC_TITLE = '''
def teardown(op_var):
    return [
        f"pm.test('teardown_{op_var}_done', () => pm.expect(pm.response.code).to.eql(200));",
    ]
'''


# ФИКСТУРА ПОРЯДКА: присвоение через `js_name` ЕСТЬ, но стоит ПОСЛЕ подстановки —
# к тому моменту негодное имя уже в скрипте. Отличается от закрытого шва ровно
# одним: местом строки.
_SYNTHETIC_LATE = '''
def teardown(op_var):
    steps = [
        f"if (pm.environment.get('_{op_var}Started') !== pm.info.requestName) {{ pm.environment.set('_{op_var}Count', '0'); }}",
    ]
    op_var = js_name(op_var, where="синтетика/поздно")
    return steps
'''


def _fragments_of(source: str):
    _seen, places = jslex.scan_source(source, "<синтетика>")
    frag, _whole = _split(places)
    return frag


def test_the_gate_falls_on_an_injected_defect_and_stays_silent_on_its_twin():
    """ИНЪЕКЦИЯ В ОБЕ СТОРОНЫ — на синтетике, тем же предикатом, что дерево."""
    # (а) дефект возвращён: шов виден гейту и НЕ проверяется при генерации.
    frag = _fragments_of(_SYNTHETIC_UNGUARDED)
    assert frag, ("гейт не увидел склейку значения с именем переменной прогона — "
                  "он перестал узнавать СВОЙ предмет, и его молчание на дереве "
                  "ничего не значит")
    first = min(pl.lineno for pl in frag)
    assert not _checked_before(_SYNTHETIC_UNGUARDED, "teardown", "op_var", first), (
        "провенанс объявил непроверенное значение проверенным")

    # (б) тот же шов, закрытый исходом: гейт обязан смолчать.
    frag_ok = _fragments_of(_SYNTHETIC_GUARDED)
    assert frag_ok, "закрытый шов перестал быть виден переписи — он выпал из счёта"
    first_ok = min(pl.lineno for pl in frag_ok)
    assert _checked_before(_SYNTHETIC_GUARDED, "teardown", "op_var", first_ok), (
        "провенанс не признал `js_name` в той же функции до подстановки — гейт "
        "краснел бы на исполненном исходе, и его сняли бы первым же ложным "
        "срабатыванием")

    # ПОРЯДОК значим, и это утверждение не должно быть вакуумным: у фикстуры
    # ЕСТЬ присвоение через `js_name`, и отличается она от закрытого шва РОВНО
    # тем, что присвоение стоит ПОСЛЕ подстановки. Первая редакция снимала
    # присвоение целиком — тогда провенанс отказывал по отсутствию присвоения, а
    # проверка порядка не исполнялась вовсе и осталась зелёной при снятом
    # порядке (проверено инъекцией: снятие `node.lineno >= lineno` не покраснело).
    frag_late = _fragments_of(_SYNTHETIC_LATE)
    assert frag_late, "фикстура позднего исхода перестала нести подстановку в имя"
    assert _SYNTHETIC_LATE.count("js_name(") == 1, (
        "фикстура позднего исхода потеряла присвоение — тогда провенанс "
        "откажет по его ОТСУТСТВИЮ, и порядок останется непроверенным")
    assert not _checked_before(_SYNTHETIC_LATE, "teardown", "op_var",
                               min(pl.lineno for pl in frag_late)), (
        "провенанс зачёл проверку, стоящую ПОСЛЕ подстановки: к тому моменту "
        "негодное имя уже в скрипте")

    # (в) законные близнецы той же формы — гейт молчит, и по РАЗНЫМ причинам.
    assert not _fragments_of(_SYNTHETIC_WHOLE), (
        "гейт счёл фрагментом имя ЦЕЛИКОМ — тогда он ловит форму, а не существо, "
        "и первый же ложный срабат его отключит")
    assert not _fragments_of(_SYNTHETIC_TITLE), (
        "гейт счёл фрагментом имени склейку внутри ПОДПИСИ шага — там значение "
        "остаётся текстом, и его исход другой (#1181)")

    # (г) СОБСТВЕННАЯ ПРЕДПОСЫЛКА: разбор обязан отличать ключ доступа от прочих
    # литералов. Ключ, открытый не вызовом доступа, фрагментом имени не считается.
    not_a_key = ('\ndef s(v):\n    return [f"console.log(\'prefix_{v}_suffix\');"]\n')
    assert not _fragments_of(not_a_key), (
        "гейт счёл ключом переменной прогона обычный литерал — предикат «литерал "
        "открыт вызовом доступа» перестал различать, и перепись завысила бы себя")
    print("осмотрено: инъекций 6 — дефект найден, исход зачтён, поздний исход "
          "отвергнут, три законных близнеца молчат")
