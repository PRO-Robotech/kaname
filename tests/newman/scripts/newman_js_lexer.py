# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Лексическое состояние ПОРОЖДАЕМОГО JavaScript в точке каждой подстановки.

ЗАЧЕМ ОТДЕЛЬНЫЙ МОДУЛЬ
======================
Генераторы сюит собирают скрипт шага f-строками, поэтому вопрос «куда садится
значение вызывающего» — один и тот же для двух разных проб:

  * `js_literal_escape_test.py` (#1181) — садится ли значение внутрь СТРОКОВОГО
    литерала или комментария; там оно обязано ехать сериализатором;
  * `js_regex_literal_test.py` (#1202) — садится ли значение внутрь литерала
    РЕГУЛЯРНОГО ВЫРАЖЕНИЯ; там сериализатор строки СМЕНИЛ БЫ СМЫСЛ, и предмет
    закрывается иначе.

Вопроса два, механизм один. Две копии разошлись бы между собой ровно так же, как
разошлись сами помощники генераторов, — поэтому обход дерева и разбор состояния
живут здесь, а каждая проба лишь ОТБИРАЕТ из общего перечня своё состояние.

ЧТО ЭТОТ РАЗБОР УМЕЕТ И ЧЕГО НЕ УМЕЕТ
=====================================
Он читает f-строку генератора как поток лексем JavaScript и различает: код,
одинарно- и двойно-кавычечный литерал, шаблонный литерал, строчный и блочный
комментарий, литерал регулярного выражения и класс символов внутри него.

`/` неоднозначен: это и деление, и начало регулярного выражения. Различается по
ПРЕДЫДУЩЕЙ значащей лексеме — после имени, числа, `)`, `]` это деление, иначе
начало литерала. Ключевые слова (`return`, `typeof`, …) — имена по виду, но после
них идёт именно регулярное выражение, поэтому они перечислены отдельно.

Он НЕ разбирает JavaScript целиком и не обязан: предмет обеих проб — состояние в
точке подстановки, а не разбор программы. Судить готовый скрипт целиком —
работа `deploy/scripts/assert-generated-scripts-parse.js`, и она делается
настоящим движком.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import NamedTuple

# Состояния. Значение — то, что печатается в находке, поэтому оно человеческое.
CODE = "code"
SQ = "'…'"
DQ = '"…"'
TPL = "`…`"
LINE_COMMENT = "//…"
BLOCK_COMMENT = "/*…*/"
REGEX = "/…/"
REGEX_CLASS = "/[…]/"

IN_STRING = (SQ, DQ, TPL)
IN_REGEX = (REGEX, REGEX_CLASS)
IN_COMMENT = (LINE_COMMENT, BLOCK_COMMENT)

# Признак того, что f-строка порождает JavaScript, а не путь/идентификатор/JSON.
JS_MARKERS = ("pm.", "console.", "=>", "const ", "let ", "var ", "if (", "//",
              "function", "return ", "postman.", "JSON.")

# Помощники, чей аргумент — ТЕКСТ, а не код: их f-строки исполняться не будут,
# они лишь соберут человеческую фразу, которую сериализатор потом закодирует.
# Без этого исключения фраза вида «error text matches /…/» читалась бы как
# комментарий или как регулярное выражение — то есть проба судила бы прозу.
TEXT_ARGUMENT_HELPERS = ("js_str", "js_comment", "js_regex_literal_text")

# Сколько знаков кода помнить для вопроса «чем открыт литерал». Хвост, а не вся
# строка: предмет — ближайший вызов (`pm.environment.get(`), а не история шага.
_TAIL = 64

# После этих слов `/` начинает регулярное выражение, а не делит.
_REGEX_PRECEDING_KEYWORDS = frozenset((
    "return", "typeof", "case", "in", "of", "new", "delete", "void", "do",
    "else", "instanceof", "yield", "await", "throw",
))


class Place(NamedTuple):
    """Одна подстановка: где стоит, в каком состоянии и что подставляется.

    Три последних поля отвечают на вопрос, который состояния не различают:
    садится ли значение в ИМЯ. Литерал закрывается экранированием, имя — нет
    (#1220), поэтому пробе про имена нужны соседние знаки и то, чем открыт
    текущий литерал. Поля добавлены с умолчаниями: прежние вызывающие читают
    `state`/`expr` и об этих полях не знают.
    """
    path: str          # путь относительно корня дерева
    lineno: int
    state: str
    expr: str          # исходный текст выражения подстановки
    before: str = ""   # знак ПОРОЖДАЕМОГО текста непосредственно слева
    after: str = ""    # он же справа ("" — конец f-строки, "\x00" — соседняя подстановка)
    opener: str = ""   # хвост КОДА: чем открыт литерал, а в коде — что стоит слева

    def __str__(self) -> str:  # координата в форме, пригодной для перехода
        return f"{self.path}:{self.lineno} состояние {self.state}: {{{self.expr}}}"


def _not_generated_javascript(tree: ast.AST) -> set:
    """id() f-строк, которые порождаемым скриптом НЕ станут.

    Два вида, и оба обязательны, иначе проба судила бы прозу:

      * прямой аргумент помощника, берущего ТЕКСТ (`js_str` и его родня): фраза
        «error text matches /…/» — человеческая подпись шага, а её косые черты
        и `//` прочитались бы как выражение и как комментарий;
      * сообщение отказа (всё, что внутри `raise`): оно адресовано оператору
        генератора и в коллекцию не попадает вовсе. Сообщение помощника
        `js_regex_src` само называет литерал `/образец/флаги` — то есть без
        этого исключения объяснение защиты читалось бы её собственной находкой.
    """
    marked = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Raise):
            for inner in ast.walk(node):
                if isinstance(inner, ast.JoinedStr):
                    marked.add(id(inner))
            continue
        if not isinstance(node, ast.Call):
            continue
        name = node.func.id if isinstance(node.func, ast.Name) else (
            node.func.attr if isinstance(node.func, ast.Attribute) else "")
        if name not in TEXT_ARGUMENT_HELPERS:
            continue
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            if isinstance(arg, ast.JoinedStr):
                marked.add(id(arg))
    return marked


def scan_source(source: str, path_label: str) -> tuple[dict, list]:
    """(перепись, перечень подстановок) для одного файла генератора.

    Перепись печатается вызывающим: «ноль находок» обязано быть отличимо от
    «ноль прочитанного», поэтому объём осмотренного — отдельное утверждение.
    """
    tree = ast.parse(source, filename=path_label)
    skip = _not_generated_javascript(tree)
    seen = {"fstrings": 0, "js_fstrings": 0, "interpolations": 0,
            "open_at_end": 0}
    places: list = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        seen["fstrings"] += 1
        if id(node) in skip:
            continue
        static = "".join(v.value for v in node.values if isinstance(v, ast.Constant))
        if not any(m in static for m in JS_MARKERS):
            continue
        seen["js_fstrings"] += 1

        state = CODE
        prev = ""    # предыдущая значащая лексема (последний её символ)
        word = ""    # накопленное слово — чтобы узнать ключевое слово перед `/`
        last = ""    # последний знак ПОРОЖДАЕМОГО текста, в любом состоянии
        code_tail = ""   # хвост кода — для вопроса «чем открыт литерал»
        open_ctx = ""    # снимок этого хвоста в точке открытия литерала
        for idx, part in enumerate(node.values):
            if isinstance(part, ast.Constant):
                text, i = str(part.value), 0
                while i < len(text):
                    c, step = text[i], 1
                    was = state
                    # Экранирование действует в литералах строки и выражения.
                    if state in IN_STRING + IN_REGEX and c == "\\" and i + 1 < len(text):
                        i += 2
                        continue
                    if state in IN_STRING:
                        if (state == SQ and c == "'") or (state == DQ and c == '"') \
                                or (state == TPL and c == "`"):
                            state, prev, word = CODE, "'", ""
                    elif state == LINE_COMMENT:
                        if c == "\n":
                            state, prev, word = CODE, "", ""
                    elif state == BLOCK_COMMENT:
                        if c == "*" and i + 1 < len(text) and text[i + 1] == "/":
                            state, prev, word, step = CODE, "", "", 2
                    elif state == REGEX:
                        if c == "[":
                            state = REGEX_CLASS
                        elif c == "/":
                            state, prev, word = CODE, "'", ""
                    elif state == REGEX_CLASS:
                        if c == "]":
                            state = REGEX
                    elif c in "'\"`":
                        state = {"'": SQ, '"': DQ, "`": TPL}[c]
                    elif c == "/":
                        nxt = text[i + 1] if i + 1 < len(text) else ""
                        if nxt == "/":
                            state, step = LINE_COMMENT, 2
                        elif nxt == "*":
                            state, step = BLOCK_COMMENT, 2
                        elif not (prev and (prev.isalnum() or prev in "_$)]")
                                  and word not in _REGEX_PRECEDING_KEYWORDS):
                            state = REGEX
                    if state == CODE and not c.isspace():
                        prev = c
                        word = word + c if (c.isalnum() or c in "_$") else ""
                    if was == CODE:
                        if state == CODE:
                            code_tail = (code_tail + c)[-_TAIL:]
                        else:
                            # Литерал/комментарий открылся ЭТИМ знаком, поэтому
                            # хвост кода снимается ДО него: он и есть «чем открыт».
                            open_ctx = code_tail
                    last = text[i + step - 1]
                    i += step
            else:
                seen["interpolations"] += 1
                expr = part.value
                nxt = node.values[idx + 1] if idx + 1 < len(node.values) else None
                if nxt is None:
                    after = ""
                elif isinstance(nxt, ast.Constant):
                    t = str(nxt.value)
                    after = t[0] if t else ""
                else:
                    after = "\x00"   # соседняя подстановка, знака между ними нет
                places.append(Place(path_label, part.lineno, state,
                                    _source_of(source, expr),
                                    before=last, after=after,
                                    opener=code_tail if state == CODE else open_ctx))
                last = "\x00"
                if state == CODE:
                    # Подставленное значение — лексема как всякая другая: после
                    # неё `/` делит, а не открывает регулярное выражение.
                    prev, word = "x", ""
                    code_tail = (code_tail + "\x00")[-_TAIL:]
        if state not in (CODE, LINE_COMMENT):
            # ПРЕДПОСЫЛКА разбора: состояние считается НА f-СТРОКУ. Литерал,
            # открытый здесь и закрытый в соседнем элементе списка, разбору
            # невидим — следующая f-строка начнётся с состояния «код». Пока это
            # число ноль, граница предпосылки предметом не задета; вызывающий
            # обязан его печатать и на нём падать, иначе перепись занизит молча.
            #
            # СТРОЧНЫЙ КОММЕНТАРИЙ ИСКЛЮЧЁН, и это не послабление: элемент списка
            # — это ОДНА строка порождаемого скрипта (они склеиваются через
            # `\n`), поэтому `//` закрывается концом строки by construction и
            # ни на какой соседний элемент не переносится. Первая редакция этого
            # счётчика исключения не делала и дала 13 «находок» — все тринадцать
            # оказались подписью шага вида `// per-step auth: …`, то есть
            # законной формой, а не задетой предпосылкой.
            seen["open_at_end"] += 1
    return seen, places


def _source_of(source: str, node: ast.AST) -> str:
    return ast.get_source_segment(source, node) or "?"


def scan_tree(root: Path, globs) -> tuple[list, dict, list]:
    """(файлы, перепись, подстановки) — ОБХОДОМ дерева, а не перечнем.

    Перечень, выписанный руками, разошёлся бы с деревом молча — и уже расходился:
    первая редакция пробы #1181 обходила только `services/*`, поэтому восьмой
    генератор был невидим для всех её утверждений сразу.
    """
    paths = [p for g in globs for p in sorted(root.glob(g))]
    total = {"fstrings": 0, "js_fstrings": 0, "interpolations": 0,
             "open_at_end": 0}
    places: list = []
    for path in paths:
        seen, found = scan_source(path.read_text(encoding="utf-8"),
                                  str(path.relative_to(root)))
        for key in total:
            total[key] += seen[key]
        places += found
    return paths, total, places
