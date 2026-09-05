# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Значение вызывающего, попадающее в литерал РЕГУЛЯРНОГО ВЫРАЖЕНИЯ порождаемого
скрипта, обязано нести записанный исход: код — проверяется, текст — экранируется
по правилам выражения (#1202).

ЧЕМ ЭТО ОТЛИЧАЕТСЯ ОТ #1181
===========================
Проба-близнец `js_literal_escape_test.py` судит подстановку в СТРОКОВЫЙ литерал и
в комментарий: там вызывающий даёт ТЕКСТ, и он обязан ехать сериализатором. Здесь
вызывающий даёт КОД — знаки регулярного выражения значимы, и сериализатор строки
СМЕНИЛ БЫ СМЫСЛ: образец перестал бы совпадать. Поэтому те же места близнец
намеренно не трогает, а закрываются они иначе.

Незакрытым при этом оставалось то же самое: значение извне попадает в порождаемый
код без разбора. Негодный образец ломает не текст, а СИНТАКСИС, и ломает его в
СГЕНЕРИРОВАННОМ файле, которого автор значения не видит. Дальше два исхода, оба
плохи: скрипт не исполняется вовсе (newman пишет это в `testScripts`, а НЕ в
`assertions.failed` — ноль упавших утверждений, «не выполнилось», зачтённое в
«прошло») либо исполняется и утверждает не то.

ТРИ ИСХОДА, ЧЕТВЁРТОГО НЕТ
==========================
1. КОД — образец проверяется на разбираемость ПРИ ГЕНЕРАЦИИ (`js_regex_src`), и
   негодный роняет генерацию С ИМЕНЕМ МЕСТА, а не уезжает в коллекцию;
2. ТЕКСТ — экранируется по правилам РЕГУЛЯРНОГО ВЫРАЖЕНИЯ, не строки
   (`js_regex_literal_text`);
3. место снято вместе с предметом.
Исход выбран и ЗАПИСАН по каждому месту в ведомости `RECORDED` ниже.

ПОЧЕМУ РАЗБИРАЕМОСТИ МАЛО, И ЭТО ИЗМЕРЕНО, А НЕ ПРЕДПОЛОЖЕНО
============================================================
`new Function("return /" + образец + "/;")` на образце `x/; process.exit(1); //`
разбирается УСПЕШНО: литерал закрылся на первом же разделителе, а хвост стал
кодом. То есть проверка «разбирается ли» пропускает ровно ту подмену, ради
которой заведена. Поэтому `js_regex_src` требует ДВУХ свойств сразу: литерал
обязан ОХВАТИТЬ весь образец (лексический разбор тела выражения — свой, без
движка, иначе судить пришлось бы исполнением чужого кода) И разобраться
настоящим движком.

ЧТО УТВЕРЖДАЕТ ЭТА ПРОБА — ПЯТЬ РАЗНЫХ ВОПРОСОВ
===============================================
1. ФОРМА, по всему дереву: каждая подстановка в литерал регулярного выражения
   стоит в ведомости и обёрнута помощником СВОЕГО исхода. Перепись печатает,
   сколько мест каждого исхода, — «ноль находок» отличимо от «ноль рассмотренных».
2. САМОИСТЕЧЕНИЕ: запись ведомости, потерявшая предмет в дереве, — НАХОДКА, а не
   тишина. Иначе ведомость пережила бы места, ради которых заведена.
3. СУЩЕСТВО исхода «код»: негодный образец РОНЯЕТ генерацию, называя место.
4. ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ исхода «код»: законный образец, чей смысл и состоит в
   значимых знаках, проходит МОЛЧА и стоит в скрипте ДОСЛОВНО. Без него зелёное
   давал бы помощник, отвергающий всё, — и сломал бы то, ради чего эти места
   вынесены из #1181.
5. СУЩЕСТВО и ОБРАТИМОСТЬ исхода «текст»: враждебный текст не рвёт синтаксис, а
   собранное выражение совпадает с ним ДОСЛОВНО и не совпадает со строкой, где те
   же знаки сработали бы операторами.

ГРАНИЦА, НАЗВАННАЯ ЧИСЛОМ, А НЕ УМОЛЧАНИЕМ
==========================================
Перепись обходит ГЕНЕРАТОРЫ (`*/tests/newman/scripts/gen.py`) — тот же корпус, что
у близнеца, поэтому числа обеих проб сравнимы. ДЕКЛАРАЦИИ КЕЙСОВ
(`*/tests/newman/cases/*.py`) под неё не подпадают, и это сказано числом: тем же
разбором там 3 подстановки в литерал выражения и 471 — в литерал строки или
комментарий. Второе — корпус #1181, чья граница проходит там же; первое — тот же
класс, что здесь, но в другом корпусе, и распространение переписи на декларации
тянет за собой оба числа сразу. Предикат, чтобы перемерить:

    python3 - <<'PY'
    import sys; sys.path.insert(0, "services/iam/tests/newman/scripts")
    from pathlib import Path
    import newman_js_lexer as L
    _p, _t, pl = L.scan_tree(Path("."), ("services/*/tests/newman/cases/*.py",
                                         "gateway/tests/newman/cases/*.py"))
    print(sum(x.state in L.IN_REGEX for x in pl),
          sum(x.state in L.IN_STRING + L.IN_COMMENT for x in pl))
    PY

Так же названы числом ещё три зоны, у каждой в дереве сегодня ноль вхождений —
а ноль, который не назван, читается как «искали и не нашли», хотя означает «не
искали»:

  * СОСТОЯНИЕ СЧИТАЕТСЯ НА f-СТРОКУ. Литерал, открытый в одном элементе списка и
    закрытый в соседнем, разбору невидим. Это единственная из четырёх границ,
    которая держится не числом в докстроке, а УТВЕРЖДЕНИЕМ: перепись печатает
    «f-строк, оставляющих литерал открытым, N» и падает на N > 0. Сегодня N = 0.
    Строчный комментарий из счёта исключён by construction — элемент списка это
    ОДНА строка скрипта, и `//` закрывается её концом; без этого исключения
    счётчик давал 13 «находок», все тринадцать — законная подпись шага;
  * ОСМАТРИВАЕТСЯ ТОЛЬКО `ast.JoinedStr`. Скрипт, собранный `%`-форматом,
    `.format` или конкатенацией, под перепись не подпадает. Замер (единица —
    узел разбора; конкатенация посчитана тремя предикатами, потому что цепочка
    `a + b + c` — это два узла): `%`-формат 26, `.format` 1, конкатенация 137
    узлов / 97 внешних выражений / 77 внешних с прямым строковым операндом. С
    открывателем литерала выражения (`to.match(/`, `.test(/`, `RegExp(`) среди
    них — 0 в каждой из трёх форм;
  * ПРЕДФИЛЬТР ПО МАРКЕРАМ. f-строка без маркера JavaScript в статической части
    (путь, идентификатор, JSON) переписью не судится: отсеяно 473, из них с
    открывателем литерала выражения — 0.

Предикат для двух последних:

    python3 - <<'PY'
    import ast, sys
    from pathlib import Path
    sys.path.insert(0, "services/iam/tests/newman/scripts")
    import newman_js_lexer as L
    OPEN = ("to.match(/", ".test(/", "RegExp(", "match(/")
    pct = cat = fmt = skipped = hits = 0
    for g in ("services/*/tests/newman/scripts/gen.py",
              "gateway/tests/newman/scripts/gen.py"):
        for p in sorted(Path(".").glob(g)):
            tree = ast.parse(p.read_text(encoding="utf-8"))
            drop = L._not_generated_javascript(tree)
            for n in ast.walk(tree):
                if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod):
                    pct += isinstance(n.left, ast.Constant)
                elif isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
                    cat += any(isinstance(s, ast.Constant) and
                               isinstance(s.value, str) for s in (n.left, n.right))
                elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                    fmt += n.func.attr == "format"
                elif isinstance(n, ast.JoinedStr) and id(n) not in drop:
                    st = "".join(v.value for v in n.values
                                 if isinstance(v, ast.Constant))
                    if not any(m in st for m in L.JS_MARKERS):
                        skipped += 1
                        hits += any(o in st for o in OPEN)
    print(pct, fmt, cat, skipped, hits)
    PY

Граница названа здесь именно затем, чтобы «ноль находок» этой пробы не читалось
шире, чем она осматривает.

ПОЧЕМУ ПРОБА ЛЕЖИТ ЗДЕСЬ
========================
Каталог выбран не по принадлежности предмета (места в шести сюитах), а по тому,
кто пробу ИСПОЛНЯЕТ: `.github/scripts/run-python-probes.py` собирает состав по
образцу `services/*/tests/newman/scripts/*_test.py`. Проба, положенная
«правильнее» — в `deploy/` или в `gateway/`, — не исполнялась бы вовсе, а это
ровно тот класс, который она стережёт. Та же причина и у близнеца.
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import newman_js_lexer as jslex  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[5]
GEN_GLOBS = ("services/*/tests/newman/scripts/gen.py",
             "gateway/tests/newman/scripts/gen.py")

CODE, TEXT = "код", "текст"
SANITISER = {CODE: "js_regex_src(", TEXT: "js_regex_literal_text("}

# ВЕДОМОСТЬ ИСХОДОВ. Ключ — (файл, что подставляется); номер строки не годится,
# он двигается от чужой правки. Запись без места в дереве и место без записи —
# обе находки, и каждая своим утверждением.
RECORDED = {
    ("services/compute/tests/newman/scripts/gen.py", "msg_regex"): CODE,
    ("services/iam/tests/newman/scripts/gen.py", "msg_regex"): CODE,
    ("services/nlb/tests/newman/scripts/gen.py", "prefix_regex"): CODE,
    ("services/nlb/tests/newman/scripts/gen.py", "retry_when"): CODE,
    ("services/registry/tests/newman/scripts/gen.py", "prefix_regex"): CODE,
    ("services/storage/tests/newman/scripts/gen.py", "msg_regex"): CODE,
    ("services/vpc/tests/newman/scripts/gen.py", "resource_name"): TEXT,
}


def _generators() -> dict:
    """Генераторы сюит — ОБХОДОМ ДЕРЕВА, а не перечнем (как у близнеца)."""
    mods = {}
    for glob in GEN_GLOBS:
        for path in sorted(REPO_ROOT.glob(glob)):
            name = path.parts[len(REPO_ROOT.parts)]
            if name == "services":
                name = path.parts[len(REPO_ROOT.parts) + 1]
            spec = importlib.util.spec_from_file_location(f"kacho_regex_gen_{name}", path)
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


# ------------------------------------------------------------------ движок

def _parse_as_function_body(source: str):
    """(разобралось?, сообщение). Обёртка-функция — как исполняет postman."""
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


def _regex_matches(pattern: str, subjects: list) -> list:
    """Для каждой строки — совпало ли выражение. Судит НАСТОЯЩИЙ движок."""
    driver = ("const a=JSON.parse(process.argv[1]);"
              "const r=new RegExp(a.pattern);"
              "process.stdout.write(JSON.stringify(a.subjects.map(s=>r.test(s))));")
    payload = json.dumps({"pattern": pattern, "subjects": subjects})
    proc = subprocess.run(["node", "-e", driver, payload],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, f"движок отверг выражение: {proc.stderr[:400]}"
    return json.loads(proc.stdout)


# ------------------------------------------------------ перепись по дереву

def _predmet(expr: str) -> str:
    """Что именно подставляется: аргумент помощника, если он есть, иначе всё."""
    for helper in SANITISER.values():
        if expr.startswith(helper):
            depth, out = 0, []
            for ch in expr[len(helper):]:
                if ch in "([{":
                    depth += 1
                elif ch in ")]}":
                    if depth == 0:
                        break
                    depth -= 1
                elif ch == "," and depth == 0:
                    break
                out.append(ch)
            return "".join(out).strip()
    return expr


def _regex_places():
    paths, total, places = jslex.scan_tree(REPO_ROOT, GEN_GLOBS)
    return paths, total, [p for p in places if p.state in jslex.IN_REGEX]


def test_every_regex_substitution_carries_a_recorded_outcome():
    """ФОРМА + перепись по исходам. Место без записи — находка, а не тишина."""
    paths, total, places = _regex_places()
    assert paths, "генераторов не найдено — перепись беспредметна, а не пуста"
    assert total["js_fstrings"], (
        "f-строк, порождающих JavaScript, не найдено НИ ОДНОЙ — предикат переписи "
        "перестал узнавать свой предмет, и его молчание ничего не значит")
    assert places, (
        "подстановок в литерал регулярного выражения не найдено НИ ОДНОЙ — либо "
        "предмет снят целиком (тогда ведомость обязана опустеть), либо разбор "
        "перестал различать литерал выражения и его молчание ничего не значит")

    per_outcome = {CODE: 0, TEXT: 0}
    findings = []
    for place in places:
        key = (place.path, _predmet(place.expr))
        outcome = RECORDED.get(key)
        if outcome is None:
            findings.append(
                f"{place} — исход НЕ ЗАПИСАН: подстановка в литерал регулярного "
                f"выражения обязана нести один из трёх исходов (#1202)")
            continue
        per_outcome[outcome] += 1
        if not place.expr.startswith(SANITISER[outcome]):
            findings.append(
                f"{place} — записан исход «{outcome}», но значение подставлено "
                f"без {SANITISER[outcome]}…)")
    print(f"осмотрено: генераторов {len(paths)}, f-строк {total['fstrings']}, "
          f"из них порождающих JS {total['js_fstrings']}, подстановок "
          f"{total['interpolations']}, из них в литерале регулярного выражения "
          f"{len(places)}; исходы: код {per_outcome[CODE]}, текст "
          f"{per_outcome[TEXT]}, снято {len(RECORDED) - sum(per_outcome.values())}; "
          f"f-строк, оставляющих литерал открытым, {total['open_at_end']}")
    assert total["open_at_end"] == 0, (
        f"f-строк, где литерал остаётся открытым до конца строки: "
        f"{total['open_at_end']}. Состояние считается НА f-СТРОКУ, поэтому "
        f"продолжение такого литерала в соседнем элементе списка разбору "
        f"НЕВИДИМО, и перепись занизит молча. Предпосылка задета: либо закройте "
        f"литерал в той же f-строке, либо научите разбор переносить состояние")
    assert not findings, (
        f"мест без записанного исхода либо без помощника своего исхода: "
        f"{len(findings)}\n  " + "\n  ".join(findings))


def test_the_ledger_expires_with_its_subject():
    """САМОИСТЕЧЕНИЕ. Запись, которой больше нечего называть, — находка."""
    _paths, _total, places = _regex_places()
    live = {(p.path, _predmet(p.expr)) for p in places}
    orphaned = sorted(k for k in RECORDED if k not in live)
    assert not orphaned, (
        f"записей ведомости, потерявших предмет: {len(orphaned)} — место снято "
        f"или переименовано, а запись пережила его\n  " +
        "\n  ".join(f"{p}: {{{e}}} -> «{RECORDED[(p, e)]}»" for p, e in orphaned))
    print(f"осмотрено: записей ведомости {len(RECORDED)}, живых мест {len(live)}")


def _classify(source: str) -> list:
    """Как перепись судит один файл: (что подставлено, обёрнуто ли своим)."""
    _seen, places = jslex.scan_source(source, "<синтетика>")
    return [(_predmet(p.expr),
             any(p.expr.startswith(h) for h in SANITISER.values()))
            for p in places if p.state in jslex.IN_REGEX]


def test_the_census_discriminates_wrapped_from_unwrapped():
    """Инъекция переписи в ОБЕ стороны — на синтетике, без правки дерева.

    Без этой пробы «ноль находок» переписи означал бы только то, что дерево
    сегодня в порядке, и ничего — о её способности находку УВИДЕТЬ. Синтетика
    берётся вместо правки живого генератора намеренно: инъекция, требующая
    испортить дерево, прогоняется один раз руками и потом не прогоняется никогда.
    """
    unwrapped = _classify('S = f"pm.expect(x).to.match(/{msg_regex}/);"\n')
    assert unwrapped == [("msg_regex", False)], (
        f"перепись НЕ УВИДЕЛА голую подстановку в литерал выражения: {unwrapped}")

    wrapped_code = _classify(
        'S = f"pm.expect(x).to.match(/{js_regex_src(msg_regex, where=\'a/b\')}/);"\n')
    assert wrapped_code == [("msg_regex", True)], (
        f"перепись не узнала помощника исхода «код»: {wrapped_code}")

    wrapped_text = _classify(
        'S = f"pm.expect(x).to.match(/^{js_regex_literal_text(resource_name)} x$/);"\n')
    assert wrapped_text == [("resource_name", True)], (
        f"перепись не узнала помощника исхода «текст»: {wrapped_text}")

    # Законный близнец: та же обёртка ВНЕ литерала выражения находкой не будет —
    # иначе перепись ловила бы форму вызова, а не место подстановки.
    outside = _classify('S = f"pm.expect(x).to.eql({js_regex_src(p, where=\'q\')});"\n')
    assert outside == [], f"перепись сочла находкой подстановку в КОД: {outside}"
    print("осмотрено: синтетических источников 4 (голый · «код» · «текст» · вне литерала)")


# ------------------------------------------------------------------- швы

# (сервис, подпись места, вызов). Вызов получает модуль генератора и образец.
CODE_SEAMS = [
    ("compute", "assert_op_error/msg_regex",
     lambda g, p: g.assert_op_error(3, "INVALID_ARGUMENT", msg_regex=p)),
    ("iam", "assert_op_error/msg_regex",
     lambda g, p: g.assert_op_error(3, "INVALID_ARGUMENT", msg_regex=p)),
    ("storage", "assert_op_error/msg_regex",
     lambda g, p: g.assert_op_error(3, "INVALID_ARGUMENT", msg_regex=p)),
    ("nlb", "assert_operation_envelope/prefix_regex",
     lambda g, p: g.assert_operation_envelope(prefix_regex=p)),
    ("registry", "assert_operation_envelope/prefix_regex",
     lambda g, p: g.assert_operation_envelope(prefix_regex=p)),
    ("nlb", "poll_operation_until_done/retry_when",
     lambda g, p: g.poll_operation_until_done(retry_from="create-lb", retry_when=p)),
]

TEXT_SEAMS = [
    ("vpc", "conf_not_found_text/resource_name",
     lambda g, t: g.conf_not_found_text("NET", "/vpc/v1/networks", t)),
]

# Негодные образцы. Каждый ломает СИНТАКСИС порождаемого файла, и ни один не
# виден автору значения: он пишет декларацию кейса, а рвётся коллекция.
BAD_PATTERNS = [
    ("голый разделитель закрывает литерал", "not found/again"),
    ("подмена: литерал закрылся, хвост стал КОДОМ", "x/; process.exit(1); //"),
    ("незакрытая группа", "^(nlb|tgr"),
    ("незакрытый класс символов", "^[a-z0-9"),
    ("конец строки внутри литерала", "not\nfound"),
    ("одинокий обратный слэш в конце", "not found\\"),
    ("пустой образец — это комментарий, а не выражение", ""),
    # Разделители строк записаны экранированными намеренно: вписанные знаками,
    # они невидимы в исходнике и первый же редактор молча их съест.
    ("разделитель строк U+2028", "not\u2028found"),
    ("разделитель строк U+2029", "not\u2029found"),
    ("возврат каретки", "not\rfound"),
]

# Законные образцы, чей смысл И СОСТОИТ в значимых знаках: помощник обязан
# пропустить их МОЛЧА и не тронуть ни одного знака.
GOOD_PATTERNS = [
    "^(nlb|tgr|lst)[a-z0-9]+$",
    "not found|allocation unavailable",
    r"^User usr[a-z0-9]+ still has active access bindings in \d+ project",
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",
    r"a\/b",          # экранированный разделитель — законен
    "[/]",            # разделитель ВНУТРИ класса литерал не закрывает
    "^Network .* not found$",
]

# Враждебный текст для исхода «текст»: знаки выражения обязаны стать буквами.
HOSTILE_TEXT = ("Route table (v2) [beta] a.b*c$ ^d|e+f? {1,2} \\ /slash/ "
                "конец\nстроки </script>")
BENIGN_TEXT = "Security group"
TEXT_INPUTS = (HOSTILE_TEXT, BENIGN_TEXT, "", " ", "/", "\\", ".*", "a|b",
               "Route table", "a.c", "[x]", "(1)", "a*", "^$", "{2}", "a+b?",
               # Разделители строк — экранированными: знаками они невидимы
               # в исходнике, и первый же редактор молча их съест.
               "\n", "\r", "\u2028", "\u2029")


def _lines(produced) -> list:
    """Строки скриптов из того, что вернул помощник: список строк, Step или Case."""
    if isinstance(produced, list) and all(isinstance(x, str) for x in produced):
        return [produced]
    steps = getattr(produced, "steps", None)
    if steps is not None:
        out = []
        for step in steps:
            out += _lines(step)
        return out
    pre = list(getattr(produced, "pre_script", []) or [])
    test = list(getattr(produced, "test_script", []) or [])
    return [block for block in (pre, test) if block]


def _render(svc: str, call, value: str) -> str:
    blocks = _lines(call(GENERATORS[svc], value))
    assert blocks, f"{svc}: помощник не вернул ни одной строки скрипта"
    return "\n\n".join("\n".join(block) for block in blocks)


def test_every_recorded_place_has_a_seam():
    """Место в ведомости без шва — непроверенное место, а не проверенное."""
    seamed = {(svc, label.split("/")[-1]) for svc, label, _ in CODE_SEAMS + TEXT_SEAMS}
    missing = []
    for (path, expr), outcome in sorted(RECORDED.items()):
        svc = path.split("/")[1] if path.startswith("services/") else path.split("/")[0]
        if (svc, expr) not in seamed:
            missing.append(f"{path}: {{{expr}}} «{outcome}»")
    assert not missing, (
        f"записей ведомости без шва: {len(missing)}\n  " + "\n  ".join(missing))
    print(f"осмотрено: записей ведомости {len(RECORDED)}, "
          f"швов {len(CODE_SEAMS) + len(TEXT_SEAMS)}")


def test_bad_pattern_fails_generation_naming_the_place():
    """СУЩЕСТВО «код». Негодный образец роняет ГЕНЕРАЦИЮ, а не коллекцию."""
    leaked = []
    for svc, label, call in CODE_SEAMS:
        for why, pattern in BAD_PATTERNS:
            try:
                source = _render(svc, call, pattern)
            except ValueError as exc:
                # Место — это ПОЛНАЯ координата «сервис/помощник/параметр», а не
                # имя функции: помощник у трёх сюит одноимённый, и проверка по
                # имени зеленела бы на `where=`, называющем ЧУЖОЙ сервис.
                if f"{svc}/{label}" not in str(exc):
                    leaked.append(
                        f"{svc}::{label} отверг «{why}», НЕ НАЗВАВ место "
                        f"(ждали «{svc}/{label}»): {exc}")
                continue
            ok, message = _parse_as_function_body(source)
            leaked.append(
                f"{svc}::{label} ПРИНЯЛ негодный образец ({why}); порождённый "
                f"скрипт " + ("разбирается — образец сменил смысл молча"
                              if ok else f"НЕ разбирается -> {message}"))
    assert not leaked, (
        f"мест, где негодный образец уезжает в коллекцию: {len(leaked)}\n  "
        + "\n  ".join(leaked))
    print(f"осмотрено: швов «код» {len(CODE_SEAMS)}, негодных образцов "
          f"{len(BAD_PATTERNS)}, проверок {len(CODE_SEAMS) * len(BAD_PATTERNS)}")


def test_legal_pattern_passes_untouched_and_verbatim():
    """ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ «код»: значимые знаки обязаны уцелеть ДОСЛОВНО."""
    broken = []
    for svc, label, call in CODE_SEAMS:
        for pattern in GOOD_PATTERNS:
            try:
                source = _render(svc, call, pattern)
            except ValueError as exc:
                broken.append(
                    f"{svc}::{label} отверг ЗАКОННЫЙ образец /{pattern}/: {exc}")
                continue
            ok, message = _parse_as_function_body(source)
            if not ok:
                broken.append(f"{svc}::{label} на /{pattern}/ -> {message}")
            elif f"/{pattern}/" not in source:
                broken.append(
                    f"{svc}::{label} исказил образец: /{pattern}/ в скрипте не "
                    f"найден — экранирование сменило бы СМЫСЛ выражения")
    assert not broken, (
        f"мест, где законный образец не проходит дословно: {len(broken)}\n  "
        + "\n  ".join(broken))
    print(f"осмотрено: швов «код» {len(CODE_SEAMS)}, законных образцов "
          f"{len(GOOD_PATTERNS)}, проверок {len(CODE_SEAMS) * len(GOOD_PATTERNS)}")


def test_hostile_text_becomes_letters_not_operators():
    """СУЩЕСТВО и ОБРАТИМОСТЬ «текст»: знаки выражения обязаны стать буквами."""
    broken = []
    for svc, label, call in TEXT_SEAMS:
        for text in TEXT_INPUTS:
            ok, message = _parse_as_function_body(_render(svc, call, text))
            if not ok:
                broken.append(f"{svc}::{label} на тексте {text!r} -> {message}")
    assert not broken, (
        f"мест, где текст рвёт порождаемый скрипт: {len(broken)}\n  "
        + "\n  ".join(broken))

    absent = [svc for svc, _l, _c in TEXT_SEAMS
              if not hasattr(GENERATORS[svc], "js_regex_literal_text")]
    assert not absent, (
        f"генераторы без помощника js_regex_literal_text: {absent} — значит текст "
        f"вызывающего всё ещё вклеивается между косыми чертами")
    for svc, _label, _call in TEXT_SEAMS:
        escape = GENERATORS[svc].js_regex_literal_text
        for text in TEXT_INPUTS:
            pattern = escape(text)
            # Контроль в обе стороны: выражение обязано совпасть с самим текстом
            # и НЕ совпасть со строкой, где те же знаки сработали операторами.
            decoy = "".join("X" if ch in ".*+?|^$()[]{}\\/" else ch for ch in text)
            hits = _regex_matches(pattern, [text, decoy])
            assert hits[0], (
                f"{svc}: экранированный текст {text!r} не совпадает САМ С СОБОЙ — "
                f"экранирование сменило смысл")
            if decoy != text:
                assert not hits[1], (
                    f"{svc}: экранированный текст {text!r} совпал со строкой "
                    f"{decoy!r}, где его знаки сработали ОПЕРАТОРАМИ — "
                    f"экранирование неполно")
    print(f"осмотрено: швов «текст» {len(TEXT_SEAMS)}, входов {len(TEXT_INPUTS)}")


# ------------------------------------------------------- контроль разборщика

_LEXER_CASES = [
    ("подстановка внутри литерала выражения",
     'f"pm.expect(x).to.match(/{p}/);"', jslex.REGEX),
    ("подстановка внутри класса символов",
     'f"pm.expect(x).to.match(/[{p}]/);"', jslex.REGEX_CLASS),
    ("подстановка ПОСЛЕ закрытого выражения — это код",
     'f"pm.expect(x).to.match(/^a$/) && f({p});"', jslex.CODE),
    ("кавычка ВНУТРИ выражения не открывает литерал строки",
     "f\"pm.expect(x).to.match(/won't/) && f({p});\"", jslex.CODE),
    ("экранированный разделитель выражение не закрывает",
     'f"pm.expect(x).to.match(/a\\\\/b{p}/);"', jslex.REGEX),
    ("деление — не выражение",
     'f"const a = pm.x / 2, b = {p};"', jslex.CODE),
    ("после return разделитель открывает выражение",
     'f"return /a{p}/;"', jslex.REGEX),
    ("строчный комментарий",
     'f"// pm.x {p}"', jslex.LINE_COMMENT),
    ("блочный комментарий",
     'f"const a = 1; /* pm.x {p} */"', jslex.BLOCK_COMMENT),
    ("одинарно-кавычечный литерал",
     "f\"pm.test('{p}', () => 1);\"", jslex.SQ),
]


def test_the_lexer_reads_each_state_the_way_javascript_does():
    """Контроль разбора: находка и её законный близнец — по каждому состоянию."""
    wrong = []
    for why, source, want in _LEXER_CASES:
        _seen, places = jslex.scan_source(f"p = 'x'\nS = {source}\n", "<проба>")
        got = [pl.state for pl in places]
        if got != [want]:
            wrong.append(f"{why}: ожидалось [{want}], разбор дал {got}")
    assert not wrong, (
        f"состояний, прочитанных неверно: {len(wrong)} из {len(_LEXER_CASES)}\n  "
        + "\n  ".join(wrong))

    # Фраза, отданная сериализатору, — ТЕКСТ, а не код: её косые черты не
    # открывают выражение, иначе проба судила бы прозу.
    _seen, places = jslex.scan_source(
        "js_str = str\n"
        "S = f\"pm.test({js_str(f'error text matches /{r}/')}, () => 1);\"\n",
        "<проба>")
    assert [p.state for p in places] == [jslex.CODE], (
        f"фраза внутри js_str прочитана как код: {[str(p) for p in places]}")

    # Сообщение отказа — не порождаемый скрипт: оно адресовано оператору
    # генератора. Иначе объяснение самой защиты стало бы её находкой.
    _seen, places = jslex.scan_source(
        'def f(p):\n'
        '    raise ValueError(f"pm.x: образец /{p}/ не разбирается")\n',
        "<проба>")
    assert places == [], f"сообщение отказа прочитано как код: {[str(p) for p in places]}"

    # Счётчик задетой предпосылки — в обе стороны. Без этой пары он тихо стал бы
    # вакуумным: сузить его до «никогда не срабатывает» ничего не стоит.
    carried, _pl = jslex.scan_source(
        'S = f"pm.test(\'не закрыт {p}"\n', "<проба>")
    assert carried["open_at_end"] == 1, (
        f"незакрытый литерал НЕ засчитан как задетая предпосылка: {carried}")
    for why, source in (
            ("строчный комментарий закрывается концом строки",
             'S = f"// pm.x {p}"\n'),
            ("закрытый литерал предпосылки не задевает",
             'S = f"pm.test(\'закрыт {p}\');"\n')):
        ok, _pl = jslex.scan_source(source, "<проба>")
        assert ok["open_at_end"] == 0, f"{why}: засчитано как задетая предпосылка"
    print(f"осмотрено: состояний {len(_LEXER_CASES)}, контролей «это не скрипт» 2, "
          f"контролей предпосылки 3")
