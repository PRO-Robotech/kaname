# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Текст вызывающего, попадающий в ПОРОЖДАЕМЫЙ JavaScript, обязан кодироваться
сериализатором, а не вклеиваться между кавычками (#1181).

ПРЕДМЕТ
=======
Помощник генератора принимает от автора кейса человеческую фразу — пояснение,
фрагмент контракт-тона, подпись шага, имя переменной — и подставляет её внутрь
строкового литерала порождаемого скрипта. Апостроф закрывает литерал, перевод
строки разрывает строку, `</script>` закрывает элемент: ломается не текст, а
СИНТАКСИС файла, которого автор фразы не видит.

ПОЧЕМУ ЭТО НЕ ВИДНО В ВЕРДИКТЕ
==============================
newman записывает исключение скрипта в `testScripts`, а НЕ в `assertions.failed`.
Шаг, чей скрипт не разобрался, даёт НОЛЬ упавших утверждений: кейс перестаёт
проверять что бы то ни было и продолжает отчитываться зелёным по этой величине.
Это третья категория исхода («не выполнилось»), зачтённая в «прошло».

ЧТО УТВЕРЖДАЕТ ЭТА ПРОБА — ЧЕТЫРЕ РАЗНЫХ ВОПРОСА
================================================
1. ФОРМА, по всему дереву: ни одна подстановка не садится внутрь литерала или
   комментария порождаемого скрипта иначе как через `js_str` / `js_comment`.
   Перепись обходит генераторы ОБХОДОМ ДЕРЕВА и печатает объём осмотренного,
   поэтому новый генератор попадает под неё по построению.
2. СУЩЕСТВО, по швам: помощник, которому дали ВРАЖДЕБНУЮ фразу, всё равно
   порождает разбираемый JavaScript. Форма без существа зеленела бы на
   сериализаторе, который ничего не кодирует.
3. ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: обычная фраза по-прежнему читается в скрипте
   ДОСЛОВНО. Без него зелёное давал бы и помощник, выбрасывающий текст.
4. ОБРАТИМОСТЬ — НАСТОЯЩИМ ДВИЖКОМ. Литерал вычисляется node и обязан дать
   исходную строку. Судить надо тем языком, который литерал и будет исполнять:
   `json.loads` не знает ни `\\'`, ни `<\\/`, то есть проверял бы другой язык.

ПОЧЕМУ ПРОБА ОДНА НА ВСЕ ГЕНЕРАТОРЫ И ПОЧЕМУ ОНА ЛЕЖИТ ЗДЕСЬ
============================================================
Шов один и тот же у восьми наборов, а тело пробы — одно; восемь копий разошлись
бы между собой ровно так же, как разошлись сами помощники. Каталог выбран не по
принадлежности предмета, а по тому, кто пробу ИСПОЛНЯЕТ: прогонщик
`.github/scripts/run-python-probes.py` собирает состав по образцу
`services/*/tests/newman/scripts/*_test.py`. Проба, положенная «правильнее» — в
`deploy/` или в `gateway/`, — не исполнялась бы вовсе, а это ровно тот класс,
который она и стережёт.

ГРАНИЦА, НАЗВАННАЯ ЧЕСТНО
=========================
Перепись судит подстановку в СТРОКОВЫЙ литерал и в СТРОЧНЫЙ комментарий. Два
состояния она не судит, и оба названы числом, а не умолчанием.

1. ЛИТЕРАЛ РЕГУЛЯРНОГО ВЫРАЖЕНИЯ. Там вызывающий передаёт не текст, а КОД, и
   кодирование его строкой сменило бы смысл — образец перестал бы совпадать.
   Отдельный предмет (#1202), и он ЗАКРЫТ: у соседней пробы
   `js_regex_literal_test.py` своя ведомость исходов на 7 мест — 6 «код»
   (проверяются при генерации) и 1 «текст» (экранируется по правилам
   выражения). Прежняя редакция этого абзаца называла 3 места и говорила
   «оставлена как есть»; и число, и утверждение устарели — предикат переписи
   там был грепом по `to.match(/`, а мест по МЕХАНИЗМУ оказалось семь.

2. БЛОЧНЫЙ КОММЕНТАРИЙ `/* … */`. Разбор ЭТОЙ пробы такого состояния не знает
   вовсе: подстановка внутрь блочного комментария читается им как код и
   находкой не станет. Безопасной формы для неё в дереве тоже нет — `js_comment`
   закрывает конец строки, но не `*/`. Замер разбором, который это состояние
   различает (`newman_js_lexer.py`): таких подстановок 2, обе в одном
   генераторе, обе — целочисленные константы самого генератора, то есть текста
   вызывающего среди них нет. Предикат, чтобы перемерить:

       python3 - <<'PY'
       import sys; sys.path.insert(0, "tests/newman/scripts")
       from pathlib import Path
       import newman_js_lexer as L
       _p, _t, places = L.scan_tree(Path("."), (
           "services/*/tests/newman/scripts/gen.py",
           "gateway/tests/newman/scripts/gen.py"))
       print([str(x) for x in places if x.state == L.BLOCK_COMMENT])
       PY

   Это долг #1181, а не пропуск #1202, и он записан здесь, потому что иначе
   «ноль находок» этой пробы читалось бы шире, чем она осматривает.
"""
import ast
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

def _repo_root() -> Path:
    """Корень репозитория — ПО МАРКЕРУ, а не отсчётом уровней.

    Прежде стояло `parents[5]` — верно ровно пока набор лежал под
    `<корень>/tests/newman/scripts`. В отдельном репозитории службы
    набор лежит двумя уровнями выше, и `parents[5]` уезжает ВЫШЕ корня — в чужой
    каталог файловой системы. Обход тогда не пуст, он ПОСТОРОННИЙ, и это хуже:
    пустой обход проба объявляет беспредметным, а посторонний вынесет вердикт о
    чужом дереве.

    Маркер — `.git` (в рабочей копии он бывает файлом, поэтому `exists`, а не
    `is_dir`); запасной — `go.mod` рядом с каталогом набора.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / ".git").exists():
            return parent
    for parent in here.parents:
        if (parent / "go.mod").is_file() and (parent / "tests" / "newman").is_dir():
            return parent
    raise AssertionError(
        f"корень репозитория не найден подъёмом от {here}: ни `.git`, ни `go.mod` "
        f"рядом с каталогом набора. Обходить нечего, и это не «ноль находок»")


REPO_ROOT = _repo_root()

# ИМЯ НАБОРА ДЛЯ КОРНЕВОЙ РАСКЛАДКИ. Ведомости ниже ключуются именем набора, и
# заведены они, когда набор лежал в `services/iam/`. В отдельном репозитории
# службы набор лежит в корне, и вывод «первый сегмент пути» дал бы `tests` —
# ключ, которого нет ни в одной ведомости: каждая запись осиротела бы разом, и
# выглядело бы это как шесть находок вместо одной смены раскладки.
#
# Имя объявлено КОНСТАНТОЙ, а не выведено: набор здесь один, и он тот самый —
# домен `kaname.cloud.iam.v1`. Выводить его из чего-либо значило бы завести
# второе место об одном предмете.
ROOT_SUITE_NAME = "iam"


def _suite_name(path, root) -> str:
    """Имя набора по пути его генератора/кейса. Раскладок ДВЕ, и обе названы."""
    rel = path.parts[len(root.parts):]
    if rel and rel[0] == "services":
        return rel[1]
    if rel and rel[0] == "tests":
        return ROOT_SUITE_NAME
    return rel[0] if rel else ROOT_SUITE_NAME

# КОРНЕВОЙ НАБОР идёт ПЕРВЫМ: это форма отдельного репозитория службы, где набор
# лежит прямо в `tests/newman`. Образцы платформы оставлены — в её дереве они
# находят семь остальных генераторов, а здесь не находят ничего, и это не
# послабление: обход пуст только если не нашлось НИ ОДНОГО, и тогда проба
# объявляет себя беспредметной.
GEN_GLOBS = ("tests/newman/scripts/gen.py",
             "services/*/tests/newman/scripts/gen.py",
             "gateway/tests/newman/scripts/gen.py")

# Враждебная фраза: каждый знак закрывает свой контекст. Апостроф — литерал в
# одинарных кавычках, кавычка — в двойных, обратный слэш — начало экранирующей
# последовательности, перевод строки — саму строку и комментарий, `</script>` —
# элемент документа, U+2028/U+2029 — литерал у сборок до ES2019, обратная кавычка
# и `${` — шаблонный литерал.
HOSTILE = ("the facade's OWN record \" \\ конец\nстроки </script> "
           "\u2028\u2029 ` ${payload}")   # разделители строк — экранированы,
# иначе они невидимы в исходнике и первый же редактор молча их съест

BENIGN = "IBT-06 control: how the internal listener answers"


def _generators() -> dict:
    """Генераторы сюит — ОБХОДОМ ДЕРЕВА, а не перечнем.

    Перечень, выписанный руками, разошёлся бы с деревом молча — и разошёлся:
    первая редакция этого файла обходила только `services/*`, поэтому восьмой
    генератор (`gateway/`), несущий ТРЕТЬЮ копию `require_env_url`, был невидим
    для всех её утверждений сразу.
    """
    mods = {}
    for glob in GEN_GLOBS:
        for path in sorted(REPO_ROOT.glob(glob)):
            name = _suite_name(path, REPO_ROOT)
            spec = importlib.util.spec_from_file_location(f"kacho_gen_{name}", path)
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


# ----------------------------------------------------------------- разборщик

def _parse_as_function_body(source: str):
    """(разобралось?, сообщение). Обёртка-функция — как исполняет postman.

    postman исполняет скрипт шага как ТЕЛО ФУНКЦИИ: `return` верхнего уровня там
    законен, и разбор без обёртки дал бы тысячи ложных находок.
    """
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
            "прочитанного», а не «ноль находок», поэтому проба ПАДАЕТ, а не "
            "пропускается.") from None
    finally:
        Path(name).unlink(missing_ok=True)
    out = proc.stdout.strip()
    assert out.startswith(("OK", "ERR")), f"разборщик не ответил: {proc!r}"
    return out == "OK", out


def _eval_literals(literals):
    """Значения литералов, вычисленные НАСТОЯЩИМ движком JS."""
    driver = ("const L=JSON.parse(process.argv[1]);"
              "process.stdout.write(JSON.stringify(L.map(l=>eval('('+l+')'))));")
    proc = subprocess.run(["node", "-e", driver, json.dumps(literals)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, f"движок отверг литерал: {proc.stderr[:400]}"
    return json.loads(proc.stdout)


# ------------------------------------------------------- перепись по дереву

_JS_MARKERS = ("pm.", "console.", "=>", "const ", "let ", "var ", "if (", "//",
               "function", "return ", "postman.", "JSON.")
_SANITISERS = ("js_str(", "js_comment(")
_OUT, _SQ, _DQ, _TPL, _CMT = "code", "'…'", '"…"', "`…`", "//…"
_DECODE = {"'": "'", '"': '"', "\\": "\\", "n": "\n", "t": "\t", "r": "\r"}


def _lexical_state_at_each_interpolation(path: Path):
    """(перепись, находки) — где подстановка садится внутрь литерала/комментария.

    Предикат — МЕХАНИЗМ подстановки, а не имя функции: поле замены, чьё
    лексическое состояние JS есть «внутри литерала» либо «внутри комментария».
    """
    src = path.read_text(encoding="utf-8")
    seen = {"fstrings": 0, "js_fstrings": 0, "interpolations": 0}
    findings = []
    for node in ast.walk(ast.parse(src, filename=str(path))):
        if not isinstance(node, ast.JoinedStr):
            continue
        seen["fstrings"] += 1
        static = "".join(v.value for v in node.values if isinstance(v, ast.Constant))
        if not any(m in static for m in _JS_MARKERS):
            continue
        seen["js_fstrings"] += 1
        state = _OUT
        for part in node.values:
            if isinstance(part, ast.Constant):
                text, i = str(part.value), 0
                while i < len(text):
                    c, step = text[i], 1
                    if state in (_SQ, _DQ, _TPL) and c == "\\" and i + 1 < len(text):
                        c, step = _DECODE.get(text[i + 1], text[i + 1]), 2
                        i += step
                        continue
                    if state in (_SQ, _DQ, _TPL):
                        if (state == _SQ and c == "'") or (state == _DQ and c == '"') \
                                or (state == _TPL and c == "`"):
                            state = _OUT
                    elif state == _CMT:
                        if c == "\n":
                            state = _OUT
                    elif c in "'\"`":
                        state = {"'": _SQ, '"': _DQ, "`": _TPL}[c]
                    elif c == "/" and i + 1 < len(text) and text[i + 1] == "/":
                        state, step = _CMT, 2
                    i += step
            else:
                seen["interpolations"] += 1
                if state == _OUT:
                    continue
                expr = ast.get_source_segment(src, part.value) or "?"
                if not expr.startswith(_SANITISERS):
                    findings.append(f"{path}:{part.lineno} состояние {state}: {{{expr}}}")
    return seen, findings


def test_no_caller_text_is_pasted_between_quotes_anywhere_in_the_tree():
    """ФОРМА. Ни одной подстановки в литерал/комментарий помимо сериализатора."""
    paths = [p for g in GEN_GLOBS for p in sorted(REPO_ROOT.glob(g))]
    assert paths, "генераторов не найдено — перепись беспредметна, а не пуста"
    total = {"fstrings": 0, "js_fstrings": 0, "interpolations": 0}
    findings = []
    for path in paths:
        seen, found = _lexical_state_at_each_interpolation(path)
        for k in total:
            total[k] += seen[k]
        findings += found
    assert total["js_fstrings"], (
        "f-строк, порождающих JavaScript, не найдено НИ ОДНОЙ — предикат "
        "переписи перестал узнавать свой предмет, и её молчание ничего не значит")
    print(f"осмотрено: генераторов {len(paths)}, f-строк {total['fstrings']}, "
          f"из них порождающих JS {total['js_fstrings']}, подстановок в них "
          f"{total['interpolations']}")
    assert not findings, (
        f"подстановок, вклеенных между кавычками помимо js_str/js_comment: "
        f"{len(findings)}\n  " + "\n  ".join(findings))


# ------------------------------------------------------------------- швы

# (сервис, подпись, вызов). Вызов получает модуль генератора и текст, который
# подставляется в проверяемый параметр.
SEAMS = [
    # ЗАПИСИ ОСТАЛЬНЫХ НАБОРОВ СНЯТЫ ВМЕСТЕ СО СВОИМ ПРЕДМЕТОМ: их генераторы и
    # кейсы живут в дереве платформы, а в этом репозитории их нет ни одного файла.
    # Запись, которой нечего проверять, — находка по правилу самой ведомости, а не
    # мелочь. В дереве платформы они остались при своих наборах.
    ("iam", "require_env_url/why",
     lambda g, t: g.require_env_url("internalBaseUrl", "/iam/v1/internal/x", t)),
    ("iam", "require_env_url/var",
     lambda g, t: g.require_env_url(t, "/iam/v1/internal/x", "why")),
    ("iam", "require_env_url/path",
     lambda g, t: g.require_env_url("internalBaseUrl", t, "why")),
    ("iam", "assert_op_error/msg_substr",
     lambda g, t: g.assert_op_error(3, "INVALID_ARGUMENT", msg_substr=t)),
    ("iam", "assert_answered/label", lambda g, t: g.assert_answered(t)),
]


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


def _render(svc: str, call, text: str) -> str:
    blocks = _lines(call(GENERATORS[svc], text))
    assert blocks, f"{svc}: помощник не вернул ни одной строки скрипта"
    return "\n\n".join("\n".join(block) for block in blocks)


def test_every_generator_of_the_tree_is_covered_by_the_seam_table():
    """Новый набор без записи в таблице швов — находка, а не тишина."""
    covered = {svc for svc, _, _ in SEAMS}
    missing = sorted(set(GENERATORS) - covered)
    assert not missing, (
        f"генераторы без записи в таблице швов: {missing}; перечень выводится из "
        f"дерева, поэтому новый набор обязан назвать свои швы, а не унаследовать "
        f"молчание. Осмотрено генераторов: {len(GENERATORS)}")
    print(f"осмотрено: генераторов {len(GENERATORS)}, швов {len(SEAMS)}")


def test_hostile_caller_text_still_yields_parsable_script():
    """СУЩЕСТВО. Враждебная фраза не ломает СИНТАКСИС порождаемого скрипта."""
    broken = []
    for svc, label, call in SEAMS:
        ok, message = _parse_as_function_body(_render(svc, call, HOSTILE))
        if not ok:
            broken.append(f"{svc}::{label} → {message}")
    assert not broken, (
        f"швов, где текст вызывающего рвёт порождаемый JavaScript: {len(broken)} "
        f"из {len(SEAMS)}\n  " + "\n  ".join(broken))


def test_benign_caller_text_survives_verbatim():
    """ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: обычная фраза остаётся в скрипте ДОСЛОВНО."""
    lost = []
    for svc, label, call in SEAMS:
        source = _render(svc, call, BENIGN)
        ok, message = _parse_as_function_body(source)
        if not ok:
            lost.append(f"{svc}::{label} не разобрался на безобидном входе → {message}")
        elif BENIGN not in source:
            lost.append(f"{svc}::{label} потерял текст вызывающего")
    assert not lost, "\n  ".join(lost)


def test_js_str_is_reversible_under_a_real_engine():
    """ОБРАТИМОСТЬ. Литерал, вычисленный node, даёт исходную строку.

    Судит движок, а не `json.loads`: одинарно-кавычечный литерал с `\\'` и `<\\/`
    — законный JavaScript и НЕ законный JSON, поэтому проверка через json
    отвечала бы про другой язык.
    """
    samples = [HOSTILE, BENIGN, "", "'", '"', "\\", "\n\r\t", "</script>", "  ",
               "тон отказа: network is not empty", "'; process.exit(1); //",
               "".join(chr(c) for c in range(1, 128))]
    absent = [svc for svc, m in GENERATORS.items()
              if not (hasattr(m, "js_str") and hasattr(m, "js_comment"))]
    assert not absent, (
        f"генераторы без сериализатора js_str/js_comment: {absent} — значит текст "
        f"вызывающего всё ещё вклеивается между кавычками")
    for svc, module in GENERATORS.items():
        literals = [module.js_str(s) for s in samples]
        for lit in literals:
            assert lit.startswith("'") and lit.endswith("'"), (
                f"{svc}: js_str вернул не одинарно-кавычечный литерал: {lit!r}; "
                f"двойная кавычка сменила бы байты закоммиченных коллекций")
        for want, got in zip(samples, _eval_literals(literals)):
            assert want == got, f"{svc}: js_str({want!r}) не обратим → {got!r}"
        # комментарий: значение вставляют в текст, конец строки обязан исчезнуть
        for sample in samples:
            assert "\n" not in module.js_comment(sample), (
                f"{svc}: js_comment оставил конец строки — остаток значения "
                f"станет КОДОМ, а не комментарием")


def test_the_parser_stays_silent_on_a_legal_twin():
    """Контроль разборщика: законный скрипт шага не объявляется находкой."""
    ok, message = _parse_as_function_body(
        "if (!pm.environment.get('opId')) { return; }\n"
        "pm.request.url = 'http://x' + pm.variables.replaceIn('/v1/a/{{id}}');\n"
        "pm.test('ok', () => pm.expect(1).to.eql(1));\n")
    assert ok, f"разборщик краснеет на законном близнеце: {message}"
    bad, message = _parse_as_function_body("pm.test('a's b', () => {});\n")
    assert not bad, "разборщик НЕ краснеет на заведомо негодном скрипте"
    assert "SyntaxError" in message, message
