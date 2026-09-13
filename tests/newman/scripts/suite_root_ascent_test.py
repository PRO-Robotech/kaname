#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ДЕРЖАТЕЛЬ КЛАССА «КОРЕНЬ ДЕРЕВА ВЫВЕДЕН АРИФМЕТИКОЙ ЧУЖОЙ РАСКЛАДКИ».

ПРЕДМЕТ. Фиксированная глубина подъёма (`../../../..`) есть свойство РАСКЛАДКИ,
а не дерева. В монорепо набор лежал на `services/iam/tests/newman`, и четыре
вверх были корнем; после выноса службы набор лежит на `tests/newman`, и те же
четыре вверх уезжают ДВУМЯ уровнями ВЫШЕ корня — наружу репозитория. Скрипт при
этом не падает: он читает несуществующий путь и ведёт себя так, будто предмета
нет.

ПОЧЕМУ ЭТО ДЕРЖАТЕЛЬ, А НЕ РАЗОВАЯ ПРАВКА. Мест было три, и исход у них РАЗНЫЙ:
два отказывают громко (`exit 2`), третье — `run.sh`, отбор волны церемонии —
пропускает МОЛЧА, потому что признаком активации служит НЕПЕЧАТАНИЕ строки, а
отсутствующую строку не ищет никто. Правка трёх мест закрыла бы экземпляры;
следующий скрипт набора завёл бы четвёртое тем же движением.

ПОЧЕМУ ПОДЪЁМ ДО ПРИЗНАКА, А НЕ ДО КАТАЛОГА ФИКСТУР. Соблазн — искать вверх сам
`tests/authz-fixtures`. Тогда «корень не найден» и «объявления нет» становятся
ОДНИМ исходом, и различение, ради которого эта проба написана, исчезает.
Признаком корня служит `go.mod`: модуль у репозитория ровно один
(`.claude/rules/polyrepo.md` §Build-граф), поэтому ближайший объемлющий `go.mod`
и есть корень дерева — by construction, а не по счёту сегментов.

ОСЬ 2 — ОТСУТСТВИЕ ОБЪЯВЛЕНИЯ ЕСТЬ ИСХОД, А НЕ ПРОПУСК. Условная ветвь без
`else` печатает только в счастливом случае; «волна не активирована» тогда
неотличима от «волна активирована и пуста». Третья категория исхода обязана быть
названа (`.claude/rules/testing.md` §«три исхода»).

ГРАНИЦА ОСИ 2 НАЗВАНА ПРЯМО: проба судит ФОРМУ ветви — что у условия есть
`else` и что он печатает, — а не истинность напечатанного. Истинность текста
держать нечем: он о состоянии, которого в момент прогона проб нет.

ПОЧЕМУ РАЗБОР ПО СТРОКЕ-КОДУ, А НЕ ПО ТЕКСТУ ФАЙЛА. Эта шапка и комментарии
самих скриптов ОБЪЯСНЯЮТ фиксированный подъём — проверка по подстроке краснела
бы на собственном объяснении (`.claude/rules/testing.md` §«Гейт на класс», п. 4).
Судится исполняемая часть строки: комментарий отбрасывается, `#` внутри кавычек
комментарием не считается.

КТО ЭТУ ПРОБУ ИСПОЛНЯЕТ: `.github/scripts/run-python-probes.py`, обходом дерева
по образцу `tests/newman/scripts/*_test.py`. Проводку держит этот прогонщик;
одноимённый гейт проводки — координата ДЕРЕВА ПЛАТФОРМЫ, в этом репозитории его
нет.
"""

from __future__ import annotations

import pathlib
import re
import sys

SCRIPTS = pathlib.Path(__file__).resolve().parent
SELF = pathlib.Path(__file__).resolve()

# Подъём фиксированной глубиной: три и более `..` подряд через `/`. Два уровня
# (`../..`) оставлены вне суждения намеренно — ими адресуют СОСЕДА в наборе
# (`scripts/` → `tests/newman/`), и это свойство самого набора, а не дерева.
FIXED_ASCENT_RE = re.compile(r"\.\./\.\./\.\.(?:/\.\.)*")


def executable_part(line: str) -> str:
    """Исполняемая часть строки оболочки: комментарий отброшен.

    `#` внутри одинарных или двойных кавычек комментария не открывает — иначе
    строка `echo "путь ../../../.. был бы #такой"` читалась бы обрезанной, а
    находка внутри неё потерялась бы молча.
    """
    out: list[str] = []
    quote = ""
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == "\\" and quote == '"':
                out.append(ch)
                i += 1
                if i < len(line):
                    out.append(line[i])
                    i += 1
                continue
            if ch == quote:
                quote = ""
            out.append(ch)
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "#":
            # Решётка открывает комментарий только в начале слова.
            if not out or out[-1].isspace():
                break
        out.append(ch)
        i += 1
    return "".join(out)


def shell_scripts(root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(p for p in root.glob("*.sh") if p.is_file())


def ascent_findings(paths) -> tuple[list[str], int, int]:
    """(находки, файлов прочитано, строк-кода осмотрено)."""
    hits: list[str] = []
    read = 0
    lines_seen = 0
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        read += 1
        for i, raw in enumerate(text.splitlines(), 1):
            code = executable_part(raw)
            if not code.strip():
                continue
            lines_seen += 1
            m = FIXED_ASCENT_RE.search(code)
            if m:
                hits.append(f"{path.name}:{i} {code.strip()!r} — подъём {m.group(0)!r}")
    return hits, read, lines_seen


def _strip_quoted(code: str) -> str:
    """Строковые литералы вырезаны: `fi` и `else` внутри текста — не ключевые слова."""
    out: list[str] = []
    quote = ""
    for ch in code:
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in ("'", '"'):
            quote = ch
            continue
        out.append(ch)
    return "".join(out)


def branch_shape(text: str, anchor: str) -> dict:
    """Форма условной ветви, В КОТОРОЙ упомянут `anchor`.

    Возвращает: найден ли якорь, есть ли `else` на том же уровне вложенности и
    печатает ли этот `else`. Уровень считается по ключевым словам вне кавычек и
    вне комментария — `if`/`fi` встречаются и в прозе, и в текстах сообщений.
    """
    lines = text.splitlines()
    seen = [i for i, ln in enumerate(lines) if anchor in executable_part(ln)]
    if not seen:
        return {"найден": False}
    # Якорь встречается и в ПРИСВАИВАНИИ, и в УСЛОВИИ. Нужно условие: первая
    # строка, где якорь стоит и слово `if` ОТКРЫВАЕТ ветвь. Прежняя редакция
    # брала первое вхождение вообще, попадала на присваивание строкой выше
    # `if` и объявляла ветвь отсутствующей — то есть краснела по верной причине
    # неверным доводом.
    start = next((i for i in seen
                  if _strip_quoted(executable_part(lines[i])).split()[:1] == ["if"]),
                 None)
    if start is None:
        start = seen[0]
    # Назад до открывающего `if` этой ветви.
    depth = 0
    open_at = None
    for i in range(start, -1, -1):
        words = _strip_quoted(executable_part(lines[i])).split()
        for w in reversed(words):
            if w == "fi":
                depth += 1
            elif w == "if":
                if depth == 0:
                    open_at = i
                    break
                depth -= 1
        if open_at is not None:
            break
    if open_at is None:
        return {"найден": True, "ветвь": False}
    depth = 0
    has_else = False
    else_prints = False
    in_else = False
    for i in range(open_at, len(lines)):
        code = _strip_quoted(executable_part(lines[i]))
        words = code.split()
        for w in words:
            if w == "if":
                depth += 1
            elif w == "fi":
                depth -= 1
                if depth == 0:
                    return {"найден": True, "ветвь": True,
                            "else": has_else, "else печатает": else_prints,
                            "строка if": open_at + 1, "строка fi": i + 1}
            elif w in ("else", "elif") and depth == 1:
                has_else = True
                in_else = True
        if in_else and depth == 1 and words and words[0] in ("echo", "printf", "print"):
            else_prints = True
    return {"найден": True, "ветвь": True, "else": has_else,
            "else печатает": else_prints, "строка if": open_at + 1, "строка fi": None}


# Признак корня внутри тела `_tree_root`: `[[ -f "$d/<признак>" ]]`.
ROOT_MARKER_RE = re.compile(r'-f\s+"\$[A-Za-z_][A-Za-z0-9_]*/([^"$]+)"')
ROOT_FN_RE = re.compile(r"^_tree_root\s*\(\)")


def root_markers(paths) -> tuple[dict, int]:
    """Признаки корня, по которым поднимается каждая копия `_tree_root`.

    ПОЧЕМУ ЭТО ОСЬ, А НЕ ПЕДАНТИЗМ. Бутстрап неустраним и потому повторён у
    каждого прогонщика (общий слой нельзя найти его же средствами). Три копии
    одного предмета расходятся МОЛЧА: копия, поднявшаяся по другому признаку,
    найдёт другой корень и прочитает другой путь, а отказа не будет ни у одной.
    Согласие копий обязано быть held-свойством, а не обещанием комментария.

    Тело функции читается от её объявления до `}` в первой колонке; тот же
    приём, что у ветви, и по той же причине: `}` внутри строки — не конец тела,
    поэтому литералы вырезаны.
    """
    out: dict[str, list[str]] = {}
    fns = 0
    for path in paths:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        i = 0
        while i < len(lines):
            if ROOT_FN_RE.match(executable_part(lines[i]).strip()):
                fns += 1
                j = i + 1
                found: list[str] = []
                while j < len(lines):
                    code = executable_part(lines[j])
                    if _strip_quoted(code).rstrip() == "}":
                        break
                    found += ROOT_MARKER_RE.findall(code)
                    j += 1
                for mk in found:
                    out.setdefault(mk, []).append(f"{path.name}:{i + 1}")
                if not found:
                    out.setdefault("<признака нет>", []).append(f"{path.name}:{i + 1}")
                i = j
            i += 1
    return out, fns


# ── ВЕРДИКТ ────────────────────────────────────────────────────────────────
#
# ФОРМА — ГЕЙТ СО СВОИМ `main`, А НЕ НАБОР pytest, и это решение, а не привычка.
# Прогонщик проб (`.github/scripts/run-python-probes.py`) исполняет обе формы и
# различает их РАЗБОРОМ; форма гейта исполняется голым `python3`, поэтому вердикт
# этой пробы добывается на машине разработчика без установки чего бы то ни было.
# Набор pytest на машине без него даёт не красное и не зелёное, а «не
# выполнилось», — то есть форма выбрана по тому, где проба обязана уметь
# ответить.

FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f": {detail}"))
    if not ok:
        FAILURES.append(f"{name}: {detail}")


def axis_fixed_depth() -> None:
    """Ось 1: ни один скрипт набора не выводит корень фиксированной глубиной."""
    print("ось 1 — корень дерева выведен фиксированной глубиной подъёма")
    paths = shell_scripts(SCRIPTS)
    check("предмет осмотрен: скрипты набора на месте", bool(paths),
          f"в {SCRIPTS} не прочитано ни одного скрипта — проба беспредметна")
    if not paths:
        return
    hits, read, lines_seen = ascent_findings(paths)
    print(f"  ОБЪЁМ ОСМОТРЕННОГО: скриптов оболочки {read}, строк-кода {lines_seen}")
    check("обход не пуст", bool(read and lines_seen),
          f"скриптов {read}, строк-кода {lines_seen} — вердикта о дереве нет")
    check("находок нет", not hits,
          f"корень выведен фиксированной глубиной в {len(hits)} мест(ах) — это "
          f"свойство РАСКЛАДКИ, а не дерева: " + "; ".join(hits))


def axis_ceremony_outcome() -> None:
    """Ось 2: отсутствие объявления церемонии — печатаемый исход, не пропуск."""
    print("ось 2 — отсутствие объявления церемонии как исход")
    run_sh = SCRIPTS / "run.sh"
    check("предмет осмотрен: run.sh на месте", run_sh.is_file(), f"нет {run_sh}")
    if not run_sh.is_file():
        return
    shape = branch_shape(run_sh.read_text(encoding="utf-8"), "_CEREMONY_DECL")
    print(f"  форма ветви активации волны церемонии: {shape}")
    check("объявление церемонии найдено", bool(shape.get("найден")),
          "предмет ветви исчез — молчание оси неотличимо от её смерти")
    if not shape.get("найден"):
        return
    check("объявление стоит в условной ветви", bool(shape.get("ветвь")), str(shape))
    check("у условия есть ПЕЧАТАЮЩАЯ ветвь else",
          bool(shape.get("else") and shape.get("else печатает")),
          "отсутствие объявления — МОЛЧАЛИВЫЙ пропуск: «волна не активирована» "
          f"неотличимо от «волна активирована и пуста». Форма ветви: {shape}")


def axis_markers_agree() -> None:
    """Ось 3: все копии `_tree_root` поднимаются по ОДНОМУ признаку."""
    print("ось 3 — согласие копий подъёма по признаку корня")
    markers, fns = root_markers(shell_scripts(SCRIPTS))
    print(f"  ОБЪЁМ ОСМОТРЕННОГО: объявлений _tree_root {fns}, "
          f"различных признаков {len(markers)} — "
          + ("; ".join(f"{k} ({', '.join(v)})" for k, v in sorted(markers.items()))
             or "нет"))
    check("объявление подъёма в дереве есть", fns > 0,
          "ни один прогонщик набора не поднимается до признака — ось беспредметна, "
          "и её молчание неотличимо от её смерти")
    if not fns:
        return
    check("признак корня ОДИН на все копии", len(markers) == 1,
          f"копии `_tree_root` поднимаются по РАЗНЫМ признакам и найдут разные "
          f"корни, не отказав ни одна: {markers}")


def main() -> int:
    axis_fixed_depth()
    axis_ceremony_outcome()
    axis_markers_agree()
    print()
    if FAILURES:
        print(f"ОТКАЗ: провалено утверждений {len(FAILURES)}", file=sys.stderr)
        for x in FAILURES:
            print("  " + x, file=sys.stderr)
        return 1
    print("ЧИСТО: корень выводится признаком, отсутствие объявления названо исходом")
    return 0


if __name__ == "__main__":
    sys.exit(main())
