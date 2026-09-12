#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Гейт: тело ответа, участвующее в сравнении, захватывается и сверяется ОДНОЙ формой.

ПРЕДМЕТ
-------
Тело ответа в пробе существует в ДВУХ формах, и они не равны:

  * `pm.response.text()`               — байты, пришедшие по проводу;
  * `JSON.stringify(pm.response.json())` — разбор и ПЕЧАТЬ ЗАНОВО.

Утверждение, сравнивающее одну форму с другой, проверяет не продукт, а СБОРКУ.
`protojson` после каждой запятой однострочного вывода ставит пробел либо не
ставит — по решению, выведенному из хэша двоичного файла (`internal/detrand`:
«the output does not change within a program, while ensuring that the output is
unstable across different builds»). Внутри процесса решение постоянно, между
сборками — нет.

ЦЕНА ИЗМЕРЕНА, А НЕ ПРЕДПОЛОЖЕНА. Два прогона одного набора на соседних
ревизиях: тела 74 и 76 байт при побайтово одинаковых скриптах шагов. Пока провод
отдавал компактно, смешанное сравнение зеленело; как только сборка сменила
решение — покраснели два утверждения из 56, и покраснели они не на дефекте
продукта. То есть эти утверждения были зелены ПО СОВПАДЕНИЮ всю свою жизнь.

ЧТО ТРЕБУЕТСЯ
-------------
Если значение окружения захвачено ОДНОЙ формой тела, то всякое сравнение с ним
на другом шаге обязано брать ТУ ЖЕ форму. Смешение форм — находка.

Гейт НЕ требует конкретной формы: набор вправе сравнивать хоть сырое, хоть
пересобранное. Он требует, чтобы форма была ОДНА — потому что «какая именно»
есть решение автора, а «одинаковая ли» решается машинно.

ЧТО ЭТО НЕ ЛОВИТ — названо честно. Захват величины, ТЕЛОМ не являющейся
(массив идентификаторов, выборка полей, счётчик), под гейт не подпадает: там
пересборка законна и обычна. Признак тела — форма захвата дословно называет
`pm.response.text()` либо печатает заново то, что вернул `pm.response.json()`.

ЧИТАЕТСЯ ИСПОЛНЯЕМАЯ ЧАСТЬ, А НЕ ТЕКСТ КЕЙСА. Судятся сгенерированные
коллекции: там лежит ровно то, что исполнит newman. Разбор снимает строковые
литералы и комментарии — иначе объяснение этого же класса в шапке набора стало
бы находкой (первая редакция гейта на это и покраснела).

Запуск:
  python3 scripts/body_capture_form_test.py --self-test   # доказательство инъекцией
  python3 scripts/body_capture_form_test.py               # обход дерева

КТО ЭТУ ПРОБУ ИСПОЛНЯЕТ: `.github/scripts/run-python-probes.py`. Состав он
собирает обходом дерева по образцу `services/*/tests/newman/scripts/*_test.py` и
ни один файл проб по имени не называет.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

RAW = "raw"
SERIALIZED = "serialized"

_SET = re.compile(r"pm\.environment\.set\(\s*'([A-Za-z0-9_]+)'\s*,")
_GET = re.compile(r"pm\.environment\.get\(\s*'([A-Za-z0-9_]+)'\s*\)")
_RAW_CALL = re.compile(r"pm\.response\.text\(\)")
_SER_CALL = re.compile(r"JSON\.stringify\(")
_JSON_CALL = re.compile(r"pm\.response\.json\(\)")


def strip_js_noise(src: str) -> str:
    """Снять комментарии и СОДЕРЖИМОЕ строковых литералов, сохранив длину строк.

    Иначе гейт судил бы прозу: `JSON.stringify` встречается и в тексте
    утверждения, и в объяснении класса в шапке набора. Первая редакция гейта
    ровно на этом и покраснела — на собственном объяснении.

    Граница названа: разбор посимвольный, а не полноценный разборщик JS.
    Литерал регулярного выражения распознаётся по позиции (после `(`, `,`, `=`,
    `!`, `:`, `&`, `|`, `?`, `{`, `;` либо начала строки) — этого довольно для
    скриптов набора; регулярка, начинающаяся с `/` в позиции операнда деления,
    была бы прочитана как деление. Такой формы в дереве нет, а появится —
    самопроверка (g) её и назовёт.
    """
    out, i, n = [], 0, len(src)
    prev_significant = ""
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if c == "/" and nxt == "*":
            i += 2
            while i + 1 < n and not (src[i] == "*" and src[i + 1] == "/"):
                if src[i] == "\n":
                    out.append("\n")
                i += 1
            i += 2
            continue
        if c in "'\"`":
            quote = c
            i += 1
            start = i
            while i < n:
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == quote:
                    break
                i += 1
            body = src[start:i]
            # ИМЯ переменной окружения — тоже литерал, и вычистить его нельзя:
            # без него не видно, ЧТО с чем сравнивают. Поэтому содержимое
            # сохраняется, когда оно похоже на идентификатор, и гасится иначе.
            # Проза утверждения содержит пробелы и скобки и потому гасится —
            # ровно ради этого стриппер и написан.
            keep = bool(re.fullmatch(r"[A-Za-z0-9_.:/-]*", body))
            out.append(quote)
            out.append(body if keep else " " * len(body.replace("\n", "")))
            out.append(quote)
            i += 1
            prev_significant = quote
            continue
        if c == "/" and prev_significant in ("", "(", ",", "=", "!", ":", "&", "|", "?", "{", ";", "["):
            # литерал регулярного выражения: съедаем до незаэкранированного `/`
            out.append(" ")
            i += 1
            in_class = False
            while i < n and src[i] != "\n":
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == "[":
                    in_class = True
                elif src[i] == "]":
                    in_class = False
                elif src[i] == "/" and not in_class:
                    break
                i += 1
            i += 1
            while i < n and src[i].isalpha():   # флаги
                i += 1
            prev_significant = ")"
            continue
        out.append(c)
        if not c.isspace():
            prev_significant = c
        i += 1
    return "".join(out)



def _balanced(src: str, open_at: int) -> str:
    """Текст внутри скобок, открытых в позиции `open_at`."""
    depth, i = 0, open_at
    while i < len(src):
        if src[i] == "(":
            depth += 1
        elif src[i] == ")":
            depth -= 1
            if depth == 0:
                return src[open_at + 1 : i]
        i += 1
    return src[open_at + 1 :]


def _json_aliases(src: str) -> set[str]:
    """Имена, которым присвоен разобранный ответ: `const j = pm.response.json();`."""
    out = set()
    for m in re.finditer(r"(?:const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*pm\.response\.json\(\)", src):
        out.add(m.group(1))
    return out


def _form_of(expr: str, aliases: set[str]) -> str | None:
    """Форма тела в выражении, либо None — если это не тело."""
    if _RAW_CALL.search(expr):
        return RAW
    if _SER_CALL.search(expr):
        inner = _balanced(expr, expr.index("JSON.stringify(") + len("JSON.stringify"))
        if _JSON_CALL.search(inner):
            return SERIALIZED
        if inner.strip() in aliases:
            return SERIALIZED
    return None


def _scripts(collection: dict):
    """(имя шага, исполняемый текст скрипта) по всей коллекции."""
    def walk(node, trail):
        name = node.get("name", "")
        here = trail + [name] if name else trail
        for ev in node.get("event", []) or []:
            body = "\n".join((ev.get("script", {}) or {}).get("exec", []) or [])
            if body.strip():
                yield " / ".join(here), strip_js_noise(body)
        for child in node.get("item", []) or []:
            yield from walk(child, here)

    yield from walk(collection, [])


def _split_top(expr: str) -> list:
    """Разбить по запятым ВЕРХНЕГО уровня, не заходя в скобки и литералы."""
    parts, depth, buf, quote = [], 0, [], ""
    for ch in expr:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    parts.append("".join(buf))
    return parts


def _drop_expect_messages(st: str) -> str:
    """Убрать ВТОРОЙ довод `pm.expect(значение, сообщение)`.

    Сообщение — проза для отчёта, а не сравниваемое. Читая его наравне со
    значением, гейт объявил бы находкой законное утверждение
    `pm.expect(JSON.stringify(pm.response.json()), pm.response.text())` — обе
    стороны там пересобранные, а сырое тело стоит текстом отказа. Такая находка
    была получена на живом дереве и снята этим правилом; инструмент, у которого
    находки ложные, перестают читать.
    """
    out, i = [], 0
    needle = "pm.expect("
    while True:
        j = st.find(needle, i)
        if j < 0:
            out.append(st[i:])
            return "".join(out)
        open_at = j + len(needle) - 1
        inner = _balanced(st, open_at)
        out.append(st[i:open_at + 1])
        out.append(_split_top(inner)[0])
        out.append(")")
        i = open_at + 1 + len(inner) + 1


def _env_aliases(src: str) -> dict:
    """Локальные имена, связанные со значением окружения.

    ФОРМ ЗАПИСИ ДВЕ, И ВТОРАЯ — ОБЫЧНАЯ. Сравнение почти никогда не стоит на
    той же строке, что и чтение: набор пишет `const foreign =
    pm.environment.get('X');`, а сверяет строкой ниже. Распознаватель, знающий
    только совпадение в одной строке, эту форму НЕ ВИДИТ — и молчит, что
    неотличимо от чистоты. Первая редакция гейта была слепа ровно здесь:
    перепись давала 119 сравнений и 0 находок при трёх настоящих дефектах.
    """
    out = {}
    for m in re.finditer(
            r"(?:const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*pm\.environment\.get\(\s*'([A-Za-z0-9_]+)'\s*\)", src):
        out[m.group(1)] = m.group(2)
    return out


def _statements(src: str):
    for chunk in src.split(";"):
        if chunk.strip():
            yield chunk


def audit(files, out=sys.stdout) -> int:
    findings, seen_files, seen_scripts, seen_vars, seen_cmp = [], 0, 0, set(), 0
    for path in files:
        try:
            doc = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            findings.append(f"{path}: коллекция не читается — {exc}")
            continue
        seen_files += 1
        captured: dict[str, tuple[str, str]] = {}   # var -> (форма, шаг)
        compares: list[tuple[tuple, str | None, str]] = []
        for step, src in _scripts(doc):
            seen_scripts += 1
            aliases = _json_aliases(src)
            envs = _env_aliases(src)
            for m in _SET.finditer(src):
                var = m.group(1)
                expr = _balanced(src, src.index("(", m.start()))
                value = expr.split(",", 1)[1] if "," in expr else expr
                form = _form_of(value, aliases)
                if form:
                    captured[var] = (form, step)
                    seen_vars.add((str(path), var))
            for st in _statements(src):
                if _SET.search(st):
                    continue          # захват, а не сравнение
                refs = {m.group(1) for m in _GET.finditer(st)}
                for local, var in envs.items():
                    if re.search(rf"\b{re.escape(local)}\b", st):
                        refs.add(var)
                if not refs:
                    continue
                form = _form_of(_drop_expect_messages(st), aliases)
                compares.append((tuple(sorted(refs)), form, step))
                seen_cmp += 1
        for refs, form, step in compares:
            known = [(v,) + captured[v] for v in refs if v in captured]
            if not known:
                continue
            # (а) сравнение захваченного тела с телом ЭТОГО ответа
            if form:
                for var, cap_form, cap_step in known:
                    if cap_form != form:
                        findings.append(
                            f"{path}: '{var}' захвачено формой {cap_form} на шаге «{cap_step}», "
                            f"а сравнивается формой {form} на шаге «{step}» — вердикт "
                            f"утверждения становится свойством СБОРКИ, а не продукта")
            # (б) сравнение двух захваченных тел между собой
            forms = {f for _, f, _ in known}
            if len(forms) > 1:
                names = ", ".join(f"'{v}'({f})" for v, f, _ in known)
                findings.append(
                    f"{path}: на шаге «{step}» сравниваются тела РАЗНЫХ форм — {names}; "
                    f"равенство или различие таких строк ни о чём не свидетельствует")

    print(f"осмотрено: коллекций {seen_files}, скриптов {seen_scripts}, "
          f"захваченных тел {len(seen_vars)}, сравнений с ними {seen_cmp}", file=out)
    if seen_files == 0 or seen_scripts == 0:
        print("ОТКАЗ: обход пуст — вердикт беспредметен, «ноль находок» здесь "
              "означает «ноль прочитанного»", file=out)
        return 1
    if findings:
        for f in sorted(set(findings)):
            print(f"НАХОДКА: {f}", file=out)
        print(f"находок: {len(set(findings))}", file=out)
        return 1
    print("находок: 0", file=out)
    return 0


def _tracked_collections(root: Path):
    """Коллекции — по индексу git, ДВУМЯ образцами раскладки.

    Прежде образец был один — `*/tests/newman/collections/*.…`, — и он верен в
    дереве платформы, где набор лежит под `services/<имя>/`. В отдельном
    репозитории службы набор лежит прямо в `tests/newman`, образец не совпадает ни
    с одной коллекцией, и проба честно объявляла обход пустым: «ноль находок»
    здесь означало «ноль прочитанного» при 41 коллекции в дереве.

    Образцы объединяются, а не выбираются: файл, попавший под оба, считается один
    раз, иначе перепись назвала бы больше, чем есть.
    """
    res = subprocess.run(
        ["git", "-C", str(root), "ls-files",
         "tests/newman/collections/*.postman_collection.json",
         "*/tests/newman/collections/*.postman_collection.json"],
        capture_output=True, text=True, check=False)
    seen = sorted({line for line in res.stdout.splitlines() if line.strip()})
    return [root / line for line in seen]


def _repo_root() -> Path:
    res = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                         cwd=Path(__file__).parent, capture_output=True, text=True, check=True)
    return Path(res.stdout.strip())


# ─────────────────────────── доказательство инъекцией ────────────────────────
FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {label}")
    if not ok:
        FAILURES.append(label)
        if detail:
            print("       " + detail.replace("\n", "\n       "))


def _collection(capture: str, compare: str) -> dict:
    return {
        "info": {"name": "synthetic"},
        "item": [
            {"name": "step-a", "event": [{"listen": "test", "script": {"exec": [
                "const j = pm.response.json();",
                f"pm.environment.set('probeBody', {capture});",
            ]}}]},
            {"name": "step-b", "event": [{"listen": "test", "script": {"exec": [
                "pm.test('t', () => {",
                f"  pm.expect({compare}).to.eql(pm.environment.get('probeBody'));",
                "});",
            ]}}]},
        ],
    }


def _run(doc: dict, tmp: Path) -> tuple[int, str]:
    import io
    p = tmp / "synthetic.postman_collection.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    buf = io.StringIO()
    rc = audit([p], out=buf)
    return rc, buf.getvalue()


def self_test() -> int:
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        print("(a) инъекция: захват пересобранным, сравнение сырым — НАХОДКА")
        rc, out = _run(_collection("JSON.stringify(j)", "pm.response.text()"), tmp)
        check("гейт краснеет", rc == 1, out)
        check("называет переменную", "'probeBody'" in out, out)
        check("называет обе формы", "serialized" in out and "raw" in out, out)
        check("называет шаг", "step-b" in out, out)

        print("(b) законный близнец: обе стороны СЫРЫЕ — молчит")
        rc, out = _run(_collection("pm.response.text()", "pm.response.text()"), tmp)
        check("гейт молчит", rc == 0, out)

        print("(b') законный близнец: обе стороны ПЕРЕСОБРАННЫЕ — молчит")
        rc, out = _run(_collection("JSON.stringify(j)", "JSON.stringify(pm.response.json())"), tmp)
        check("форма не навязывается, лишь бы одна", rc == 0, out)

        print("(c) не-тело под гейт не подпадает")
        rc, out = _run(_collection("JSON.stringify(ids)", "pm.response.text()"), tmp)
        check("захват массива идентификаторов — не находка", rc == 0, out)

        print("(d) читается исполняемая часть, а не текст")
        doc = _collection("pm.response.text()", "pm.response.text()")
        doc["item"][0]["event"][0]["script"]["exec"].insert(
            0, "// пояснение: JSON.stringify(pm.response.json()) здесь НЕ применяется")
        rc, out = _run(doc, tmp)
        check("объяснение класса в комментарии находкой не считается", rc == 0, out)

        print("(e) пустой обход — отказ, а не чистота")
        import io
        buf = io.StringIO()
        rc = audit([], out=buf)
        check("ноль коллекций → код 1", rc == 1, buf.getvalue())
        check("говорит про беспредметность", "беспредметен" in buf.getvalue(), buf.getvalue())

        print("(g) регулярка в скрипте не ломает разбор и не даёт ложной находки")
        doc = _collection("pm.response.text()", "pm.response.text()")
        doc["item"][1]["event"][0]["script"]["exec"].insert(
            0, "  const shape = s => s.replace(/acc[0-9a-z]+/g, '<id>');")
        rc, out = _run(doc, tmp)
        check("законный близнец с регуляркой молчит", rc == 0, out)
        doc2 = _collection("JSON.stringify(j)", "pm.response.text()")
        doc2["item"][1]["event"][0]["script"]["exec"].insert(
            0, "  const shape = s => s.replace(/acc[0-9a-z]+/g, '<id>');")
        rc, out = _run(doc2, tmp)
        check("та же форма с дефектом — по-прежнему находка", rc == 1, out)

        print("(h) второй довод pm.expect — сообщение, а не сравниваемое")
        doc = {
            "info": {"name": "synthetic"},
            "item": [
                {"name": "step-a", "event": [{"listen": "test", "script": {"exec": [
                    "pm.environment.set('probeBody', JSON.stringify(pm.response.json()));"]}}]},
                {"name": "step-b", "event": [{"listen": "test", "script": {"exec": [
                    "pm.expect(JSON.stringify(pm.response.json()), pm.response.text())"
                    "  .to.eql(pm.environment.get('probeBody'));"]}}]},
            ],
        }
        rc, out = _run(doc, tmp)
        check("сырое тело в СООБЩЕНИИ находкой не считается", rc == 0, out)
        doc["item"][1]["event"][0]["script"]["exec"] = [
            "pm.expect(pm.response.text(), 'msg')"
            "  .to.eql(pm.environment.get('probeBody'));"]
        rc, out = _run(doc, tmp)
        check("сырое тело в ЗНАЧЕНИИ по-прежнему находка", rc == 1, out)

        print("(f) перепись печатается всегда")
        rc, out = _run(_collection("pm.response.text()", "pm.response.text()"), tmp)
        check("объём осмотренного назван", "осмотрено: коллекций 1" in out, out)

    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} — {', '.join(FAILURES)}")
        return 1
    print("body_capture_form_test: самопроверка OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--self-test", action="store_true",
                    help="доказательство инъекцией: гейт умеет краснеть и умеет молчать")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    root = _repo_root()
    files = _tracked_collections(root)
    return audit(files)


if __name__ == "__main__":
    sys.exit(main())
