# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Текст вызывающего, попадающий в ПОРОЖДАЕМЫЙ JavaScript, обязан кодироваться
сериализатором, а не вклеиваться между кавычками (#1181).

ПРЕДМЕТ
=======
Помощник генератора принимает от автора кейса человеческую фразу — пояснение,
фрагмент контракт-тона, подпись шага — и подставляет её внутрь строкового
литерала порождаемого скрипта. Апостроф закрывает литерал, перевод строки
разрывает строку, `</script>` закрывает элемент: ломается не текст, а СИНТАКСИС
файла, которого автор фразы не видит.

ПОЧЕМУ ЭТО НЕ ВИДНО В ВЕРДИКТЕ
==============================
newman записывает исключение скрипта в `testScripts`, а НЕ в `assertions.failed`.
Шаг, чей скрипт не разобрался, даёт НОЛЬ упавших утверждений: кейс перестаёт
проверять что бы то ни было и продолжает отчитываться зелёным по этой величине.
Это третья категория исхода («не выполнилось»), зачтённая в «прошло».

ЧТО УТВЕРЖДАЕТ ЭТА ПРОБА
========================
1. Отрицание: помощник, которому дали ВРАЖДЕБНУЮ фразу, всё равно порождает
   разбираемый JavaScript. Разбор — в обёртке-функции (`new Function`), потому
   что postman исполняет скрипт шага как ТЕЛО ФУНКЦИИ: `return` верхнего уровня
   там законен, и разбор без обёртки дал бы тысячи ложных находок.
2. Положительный контроль: обычная фраза по-прежнему читается в скрипте
   ДОСЛОВНО. Без него зелёное давал бы и помощник, выбрасывающий текст.
3. Свойство сериализатора: `js_str` — обратимая функция, `json.loads` возвращает
   исходную строку. Без него «экранирование» могло бы быть искажением.
4. Контроль самого разборщика: законный близнец (скрипт с `return` верхнего
   уровня и подстановкой `{{var}}`) обязан МОЛЧАТЬ.

ПОЧЕМУ ПРОБА ОДНА НА ВСЕ ГЕНЕРАТОРЫ
===================================
Шов один и тот же у семи наборов, а тело пробы — одно. Семь копий этого файла
разошлись бы между собой ровно так же, как разошлись сами помощники: у geo
экранирование было РУКОПИСНЫМ и неполным (`\\` и `'`, но не перевод строки), у
registry подпись вклеивалась, тогда как одноимённый помощник iam её кодировал.
Перечень генераторов ВЫВОДИТСЯ из дерева: новый набор без записи в таблице швов
роняет пробу, а не проходит незамеченным.
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[5]

# Враждебная фраза: каждый знак закрывает свой контекст. Апостроф — литерал в
# одинарных кавычках, кавычка — в двойных, обратный слэш — начало экранирующей
# последовательности, перевод строки — саму строку, `</script>` — элемент
# документа, U+2028/U+2029 — литерал у сборок до ES2019, обратная кавычка и `${`
# — шаблонный литерал.
HOSTILE = (
    "the facade's OWN record \" \\ конец\nстроки </script> "
    "    ` ${payload}"
)

BENIGN = "IBT-06 control: how the internal listener answers"


def _generators() -> dict:
    """Генераторы сюит — обходом дерева, а не перечнем."""
    mods = {}
    for path in sorted(REPO_ROOT.glob("services/*/tests/newman/scripts/gen.py")):
        svc = path.parts[len(REPO_ROOT.parts) + 1]
        spec = importlib.util.spec_from_file_location(f"kacho_gen_{svc}", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        sys.path.insert(0, str(path.parent))
        try:
            spec.loader.exec_module(module)
        finally:
            sys.path.pop(0)
        mods[svc] = module
    assert mods, "генераторов в дереве НЕ НАЙДЕНО — проба беспредметна, а не зелена"
    return mods


GENERATORS = _generators()


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
            "прочитанного», а не «ноль находок», поэтому проба ПАДАЕТ, а не "
            "пропускается.") from None
    finally:
        Path(name).unlink(missing_ok=True)
    out = proc.stdout.strip()
    assert out.startswith(("OK", "ERR")), f"разборщик не ответил: {proc!r}"
    return out == "OK", out


# Швы: (сервис, подпись, вызов). Вызов получает модуль генератора и текст,
# который подставляется в проверяемый параметр.
SEAMS = [
    ("iam", "require_env_url/why",
     lambda g, t: g.require_env_url("internalBaseUrl", "/iam/v1/internal/x", t)),
    ("iam", "require_env_url/var",
     lambda g, t: g.require_env_url(t, "/iam/v1/internal/x", "why")),
    ("iam", "require_env_url/path",
     lambda g, t: g.require_env_url("internalBaseUrl", t, "why")),
    ("iam", "assert_op_error/msg_substr",
     lambda g, t: g.assert_op_error(3, "INVALID_ARGUMENT", msg_substr=t)),
    ("iam", "assert_answered/label", lambda g, t: g.assert_answered(t)),
    ("registry", "require_env_url/why",
     lambda g, t: g.require_env_url("internalBaseUrl", "/registry/v1/x", t)),
    ("registry", "require_env_url/var",
     lambda g, t: g.require_env_url(t, "/registry/v1/x", "why")),
    ("registry", "require_env_url/path",
     lambda g, t: g.require_env_url("internalBaseUrl", t, "why")),
    ("registry", "assert_answered/label", lambda g, t: g.assert_answered(t)),
    ("compute", "assert_op_error/msg_substr",
     lambda g, t: g.assert_op_error(3, "INVALID_ARGUMENT", msg_substr=t)),
    ("compute", "assert_op_error_oneof/msg_substr",
     lambda g, t: g.assert_op_error_oneof([3, 5], "INVALID_ARGUMENT/NOT_FOUND",
                                          msg_substr=t)),
    ("storage", "assert_op_error/msg_substr",
     lambda g, t: g.assert_op_error(3, "INVALID_ARGUMENT", msg_substr=t)),
    ("storage", "assert_op_error_oneof/msg_substr",
     lambda g, t: g.assert_op_error_oneof([3, 5], "INVALID_ARGUMENT/NOT_FOUND",
                                          msg_substr=t)),
    ("storage", "wait_until_ready/subject",
     lambda g, t: g.wait_until_ready(
         g.Step(name="get-volume", method="GET", path="/storage/v1/volumes/{{v}}"),
         ready="READY", subject=t)),
    ("geo", "assert_operation_failed/message_substr",
     lambda g, t: g.assert_operation_failed(6, "ALREADY_EXISTS", message_substr=t)),
    ("vpc", "assert_cleanup_delete/what",
     lambda g, t: g.assert_cleanup_delete(t, "адрес занят интерфейсом")),
    ("vpc", "assert_cleanup_delete/refusal",
     lambda g, t: g.assert_cleanup_delete("адрес A", t)),
    ("vpc", "assert_empty_page/why", lambda g, t: g.assert_empty_page(t)),
    # Уже кодирующие помощники — положительный контроль: они обязаны
    # ОСТАТЬСЯ кодирующими (форма выведена разбором 2026-08-03, см. их godoc).
    ("nlb", "assert_refused_sync_or_async/what",
     lambda g, t: g.assert_refused_sync_or_async(t)),
    ("vpc", "assert_refused_sync_or_async/what",
     lambda g, t: g.assert_refused_sync_or_async(t)),
]


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
    """Отрицание: враждебная фраза не ломает СИНТАКСИС порождаемого скрипта."""
    broken = []
    for svc, label, call in SEAMS:
        ok, message = _parse_as_function_body(_render(svc, call, HOSTILE))
        if not ok:
            broken.append(f"{svc}::{label} → {message}")
    assert not broken, (
        f"швов, где текст вызывающего рвёт порождаемый JavaScript: {len(broken)} "
        f"из {len(SEAMS)}\n  " + "\n  ".join(broken))


def test_benign_caller_text_survives_verbatim():
    """Положительный контроль: обычная фраза остаётся в скрипте ДОСЛОВНО."""
    lost = []
    for svc, label, call in SEAMS:
        source = _render(svc, call, BENIGN)
        ok, message = _parse_as_function_body(source)
        if not ok:
            lost.append(f"{svc}::{label} не разобрался на безобидном входе → {message}")
        elif BENIGN not in source:
            lost.append(f"{svc}::{label} потерял текст вызывающего")
    assert not lost, "\n  ".join(lost)


def test_js_str_is_reversible_in_every_generator():
    """Свойство сериализатора: кодирование обратимо, значит текст не искажён."""
    samples = [HOSTILE, BENIGN, "", "'", '"', "\\", "\n\r\t", "</script>",
               "  ", "тон отказа: network is not empty"]
    absent = [svc for svc, m in GENERATORS.items() if not hasattr(m, "js_str")]
    assert not absent, (
        f"генераторы без сериализатора js_str: {absent} — значит текст "
        f"вызывающего всё ещё вклеивается между кавычками")
    for svc, module in GENERATORS.items():
        for sample in samples:
            literal = module.js_str(sample)
            assert literal[0] in "\"'", f"{svc}: js_str не вернул литерал: {literal!r}"
            assert json.loads(literal) == sample, (
                f"{svc}: js_str({sample!r}) не обратим: {literal!r}")


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
