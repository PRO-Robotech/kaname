#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1
"""Самопроверка exec-coverage.py: РАЗЛИЧАЕТ ли он записанный пропуск и немой разрыв.

ЧТО ДОКАЗЫВАЕТСЯ, и почему без этого нельзя.
`exec-coverage.py` объявляет правильной форму стража «утвердить, назвав переменную,
и только потом пропустить» — и до сих пор относил КАЖДЫЙ такой шаг к находке
ASSERTED-NOT-EXECUTED: страж утвердил (шаг «asserted») и не отправился (записи об
исполнении нет). То есть гейт наказывал форму, которую сам предписывает. На замере
боевой посадки 2026-07-31 это дало 135 шагов в 75 местах, и приёмка IAM-INT-1
назвала различимость записанного пропуска от немого открытым долгом (Р10).

Различитель, который вводится, обязан быть проверен В ОБЕ СТОРОНЫ, иначе он
превратится в амнистию: «есть страж — значит можно».

СТРАЖ ЖИВЁТ В ДВУХ МЕСТАХ, И ДО СИХ ПОР ПРОВЕРЯЛОСЬ ОДНО. Пре-скрипт бывает
элементным, а бывает КОРНЕВЫМ (`collection.event`) и ПАПОЧНЫМ — Postman исполняет
все три перед каждым запросом. Замер по дереву на `dfd2c027` (предикат — в теле
задачи #661): коллекций 89, корневого стража несут 57 (`vpc 18/18`, `nlb 9/9`,
`storage 9/9`, `compute 7/7`, `geo 7/7`, `registry 5/5`, `gateway 2/2`, `iam 0/32`).
Гейт писался в iam, где этой формы нет вовсе, и эта самопроверка строила стража
ТОЛЬКО элементным — поэтому слепота пережила инъекцию: доказательство существовало
и не касалось той формы, в которой страж применяется чаще всего.

Отсюда обе оси ниже: КАЖДЫЙ вход даётся в элементной и в корневой (а где различие
осмысленно — и в папочной) форме, и добавлена ось «имя утверждения собрано
конкатенацией» — корневые стражи дерева именно так и написаны
(`'предусловие: {{' + _n + '}} …'`, `'FIXTURE REQUIRED: ' + __missing.join(', ')`),
поэтому сверка по литералу до склейки не сошлась бы даже с ПРОЧИТАННЫМ стражем.

Входов шестнадцать.

  (1) САНКЦИОНИРОВАННЫЙ страж, упало ЕГО утверждение → RECORDED-SKIP, гейт молчит.
  (2) Тот же шаг, но упало утверждение ТЕСТ-скрипта → ASSERTED-NOT-EXECUTED,
      находка. Тест-скрипт не выполняется без ответа, значит шаг ИСПОЛНЯЛСЯ, а
      запись о нём пропала — ровно тот класс, ради которого гейт заведён.
  (3) Пропуск БЕЗ утверждения (голый skipRequest) → немой explained-skip, НЕ
      RECORDED-SKIP: он ничего не оставляет в вердикте, и путать их нельзя.
  (4) Страж есть, но отчёт не говорит, ЧТО упало → находка (fail-closed):
      неустановимое не извиняется, иначе «объяснённый пропуск» станет корзиной
      «всё остальное», которой не бывает.

Запуск: python3 scripts/exec-coverage-selftest.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "exec_coverage", os.path.join(os.path.dirname(os.path.abspath(__file__)), "exec-coverage.py")
)
ec = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ec)

GUARD_NAME = "harness config: internalBaseUrl is set"
GUARD_FAIL = "internalBaseUrl is not set — the newman runner did not inject it."

GUARD_PRE = [
    "// HARNESS-CONFIG GUARD — internalBaseUrl is injected by the newman runner.",
    "const __cfgUrl = pm.environment.get('internalBaseUrl') || '';",
    "if (__cfgUrl) {",
    "  pm.request.url = __cfgUrl + '/iam/v1/internal/probe';",
    "} else {",
    f"  pm.test('{GUARD_NAME}', () => {{",
    f"    pm.expect.fail('{GUARD_FAIL}');",
    "  });",
    "  pm.execution.skipRequest();",
    "}",
]
BARE_SKIP_PRE = [
    "if (!pm.environment.get('opId')) { pm.execution.skipRequest(); }",
]


def _collection(pre_lines, name="guarded step", root_pre=None, folder_pre=None,
                root_test=None):
    """Коллекция из двух листьев. `pre_lines` — пре-скрипт ПЕРВОГО листа.

    `root_pre` / `folder_pre` — скрипты КОРНЯ коллекции и объемлющей ПАПКИ. Обе
    формы законны в Postman и обе исполняются перед каждым запросом; перепись
    обязана читать их так же, как элементные, иначе страж, живущий там, для неё
    не существует — а именно там он и живёт в 57 коллекциях дерева из 89.
    """
    guarded = {
        "name": name,
        "request": {"method": "GET", "url": "{{internalBaseUrl}}/iam/v1/internal/probe"},
        "event": [
            {"listen": "test", "script": {"exec": ["pm.test('probe answers 200', () => pm.response.to.have.status(200));"]}},
        ],
    }
    if pre_lines is not None:
        guarded["event"].insert(0, {"listen": "prerequest", "script": {"exec": pre_lines}})
    ordinary = {
        "name": "ordinary step",
        "request": {"method": "GET", "url": "{{baseUrl}}/iam/v1/users"},
        "event": [
            {"listen": "test", "script": {"exec": ["pm.test('list answers 200', () => pm.response.to.have.status(200));"]}},
        ],
    }
    items = [guarded, ordinary]
    if folder_pre is not None:
        items = [{"name": "folder", "item": items,
                  "event": [{"listen": "prerequest", "script": {"exec": folder_pre}}]}]
    col = {
        "info": {"name": "selftest", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": items,
    }
    ev = []
    if root_pre is not None:
        ev.append({"listen": "prerequest", "script": {"exec": root_pre}})
    if root_test is not None:
        ev.append({"listen": "test", "script": {"exec": root_test}})
    if ev:
        col["event"] = ev
    return col


def _leaves(col):
    """Листья в порядке исполнения — тем же обходом, что и у переписи."""
    out = []

    def walk(items):
        for it in items:
            if "request" in it:
                out.append(it)
            if "item" in it:
                walk(it["item"])

    walk(col["item"])
    return out


def _report(collection, executed_names, failures):
    """Отчёт newman: executions только для перечисленных шагов + список провалов."""
    # Курсор — то, по чему гейт опознаёт исполнение (позиция листа + длина
    # коллекции). Фикстура обязана быть НЕ снисходительнее продукта: отчёт без
    # курсоров гейт справедливо счёл бы «не про эту коллекцию». Позиции берутся
    # по ПЛОСКОМУ обходу листьев — иначе фикстура с папкой считала бы их иначе,
    # чем перепись, и проба утверждала бы не о том.
    leaves = _leaves(collection)
    total = len(leaves)
    execs = []
    for i, it in enumerate(leaves):
        if it["name"] in executed_names:
            execs.append({"cursor": {"position": i, "length": total},
                          "item": {"name": it["name"]},
                          "response": {"code": 200},
                          "assertions": [{"assertion": "ok", "skipped": False}]})
    return {
        "collection": {"info": collection["info"], "item": collection["item"],
                       **({"event": collection["event"]} if "event" in collection else {})},
        "run": {
            "executions": execs,
            "failures": failures,
            "stats": {
                "requests": {"total": len(execs), "failed": 0},
                "assertions": {"total": len(execs) + len(failures), "failed": len(failures)},
            },
        },
    }


def _judge(collection, report):
    d = tempfile.mkdtemp()
    col_path = os.path.join(d, "selftest.postman_collection.json")
    with open(col_path, "w", encoding="utf-8") as fh:
        json.dump(collection, fh)
    out = os.path.join(d, "out")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "selftest.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh)
    return ec.check_collection(col_path, out)


def case(label, collection, report, want_token, want_ok):
    ok, judged, line, problems = _judge(collection, report)
    got_token = want_token in line
    verdict = "OK  " if (got_token and ok == want_ok) else "ПЛОХО"
    print(f"{verdict} {label}")
    print(f"        {line.strip()}")
    if verdict == "ПЛОХО":
        print(f"        ожидалось: в строке '{want_token}', вердикт ok={want_ok}; "
              f"получено ok={ok}")
        for p in problems:
            print(f"        {p}")
    return verdict == "OK  "


def case_problem(label, collection, report, want_substrings, want_ok):
    """Вход, на котором гейт обязан НАЗВАТЬ находку — и назвать её координату.

    Утверждается текст находки, а не только вердикт: запрет, который краснеет, не
    говоря ГДЕ, посылает читателя искать по всей коллекции, и его снимают первым.
    """
    ok, _judged, line, problems = _judge(collection, report)
    blob = "\n".join(problems)
    missing = [w for w in want_substrings if w not in blob]
    verdict = "OK  " if (not missing and ok == want_ok) else "ПЛОХО"
    print(f"{verdict} {label}")
    print(f"        {line.strip()}")
    if verdict == "ПЛОХО":
        print(f"        ожидалось: в находках {want_substrings}, вердикт ok={want_ok}; "
              f"получено ok={ok}, не найдено {missing}")
        for p in problems:
            print(f"        {p}")
    return verdict == "OK  "


def case_silent(label, collection, report):
    """Законный близнец: та же внешность, находки быть не должно."""
    ok, _judged, line, problems = _judge(collection, report)
    verdict = "OK  " if (ok and not problems) else "ПЛОХО"
    print(f"{verdict} {label}")
    print(f"        {line.strip()}")
    if verdict == "ПЛОХО":
        for p in problems:
            print(f"        {p}")
    return verdict == "OK  "


def main() -> int:
    print("=== exec-coverage: записанный пропуск vs немой разрыв, инъекция в обе стороны ===")
    good = True

    # (1) санкционированный страж, упало ЕГО утверждение → RECORDED-SKIP, не находка
    col = _collection(GUARD_PRE)
    rep = _report(col, {"ordinary step"}, [
        {"source": {"name": "guarded step"}, "parent": {"name": "selftest"},
         "error": {"name": "AssertionError", "test": GUARD_NAME, "message": GUARD_FAIL}},
    ])
    good &= case("(1) страж санкционированной формы, упало его утверждение",
                 col, rep, "RECORDED-SKIP", True)

    # (2) тот же страж, но упало утверждение ТЕСТ-скрипта → находка
    col = _collection(GUARD_PRE)
    rep = _report(col, {"ordinary step"}, [
        {"source": {"name": "guarded step"}, "parent": {"name": "selftest"},
         "error": {"name": "AssertionError", "test": "probe answers 200",
                   "message": "expected response to have status code 200"}},
    ])
    good &= case("(2) тот же шаг, упало утверждение тест-скрипта (значит он ИСПОЛНЯЛСЯ)",
                 col, rep, "ASSERTED-NOT-EXECUTED", False)

    # (3) голый skipRequest без утверждения → немой explained-skip, НЕ recorded
    col = _collection(BARE_SKIP_PRE, name="bare-skip step")
    rep = _report(col, {"ordinary step"}, [])
    ok, _judged, line, _pr = _judge(col, rep)
    got = ("explained-skip" in line) and ("RECORDED-SKIP" not in line)
    print(f"{'OK  ' if got else 'ПЛОХО'} (3) голый skipRequest без утверждения — немой пропуск, не записанный")
    print(f"        {line.strip()}")
    good &= got

    # (4) страж есть, но отчёт не говорит ЧТО упало → находка (fail-closed)
    col = _collection(GUARD_PRE)
    rep = _report(col, {"ordinary step"}, [
        {"source": {"name": "guarded step"}, "parent": {"name": "selftest"},
         "error": {"name": "AssertionError"}},
    ])
    good &= case("(4) страж есть, отчёт не называет упавшее утверждение — не извиняется",
                 col, rep, "ASSERTED-NOT-EXECUTED", False)


    # ── ОСЬ 2: тот же страж, но в КОРНЕ КОЛЛЕКЦИИ, и имя собрано конкатенацией ──
    #
    # Ровно та форма, что стоит в 57 коллекциях дерева. Пока перепись читала только
    # элементные скрипты, каждый такой САНКЦИОНИРОВАННЫЙ пропуск считался находкой:
    # на прогоне 32077150454 (шард nlb) — 157 находок при `SKIPS: 0 RECORDED-SKIP`.
    ROOT_GUARD = [
        "(function () {",
        "  var _u = '';",
        "  try { _u = pm.request.url.toString(); } catch (e) { return; }",
        "  var _all = _u.match(/\\{\\{[A-Za-z0-9_]+\\}\\}/g);",
        "  if (!_all) { return; }",
        "  var _n = _all[0].slice(2, -2);",
        "  if (pm.variables.has(_n)) { return; }",
        "  pm.test('предусловие: {{' + _n + '}} не было захвачено — запрос не отправлен', function () {",
        "    pm.expect.fail(_n + ' не определена ни в одной области.');",
        "  });",
        "  pm.execution.skipRequest();",
        "})();",
    ]
    ROOT_FAIL_NAME = "предусловие: {{lbId}} не было захвачено — запрос не отправлен"

    col = _collection(None, root_pre=ROOT_GUARD)
    rep = _report(col, {"ordinary step"}, [
        {"source": {"name": "guarded step"}, "parent": {"name": "selftest"},
         "error": {"name": "AssertionError", "test": ROOT_FAIL_NAME,
                   "message": "lbId не определена ни в одной области."}},
    ])
    good &= case("(5) страж в КОРНЕ коллекции, имя собрано конкатенацией — записанный пропуск",
                 col, rep, "RECORDED-SKIP", True)

    # (6) тот же корневой страж, но упало утверждение ТЕСТ-скрипта → находка.
    # Положительный контроль к (5): отрицание годится только в паре с ним, иначе
    # «прочитали корень» неотличимо от «извинили всё, у чего корень есть».
    col = _collection(None, root_pre=ROOT_GUARD)
    rep = _report(col, {"ordinary step"}, [
        {"source": {"name": "guarded step"}, "parent": {"name": "selftest"},
         "error": {"name": "AssertionError", "test": "probe answers 200",
                   "message": "expected response to have status code 200"}},
    ])
    good &= case("(6) корневой страж есть, упало утверждение тест-скрипта — находка",
                 col, rep, "ASSERTED-NOT-EXECUTED", False)

    # (7) имя ПОХОЖЕ на стражево, но под шаблон не подходит → находка.
    # Шаблон строится из самой конкатенации: литералы дословно, динамические члены
    # — подстановкой. Так «прочитан корень» не превращается в «совпадает по началу».
    col = _collection(None, root_pre=ROOT_GUARD)
    rep = _report(col, {"ordinary step"}, [
        {"source": {"name": "guarded step"}, "parent": {"name": "selftest"},
         "error": {"name": "AssertionError",
                   "test": "предусловие: {{lbId}} не было захвачено — но запрос ушёл",
                   "message": "…"}},
    ])
    good &= case("(7) имя похоже на стражево, но шаблону не отвечает — не извиняется",
                 col, rep, "ASSERTED-NOT-EXECUTED", False)

    # (8) имя стража ЦЕЛИКОМ динамическое → шаблон был бы «что угодно», то есть
    # амнистия. Fail-closed: такой страж не извиняет никого.
    col = _collection(None, root_pre=[
        "if (!pm.variables.has('x')) {",
        "  pm.test(__nm, function () { pm.expect.fail(__why); });",
        "  pm.execution.skipRequest();",
        "}",
    ])
    rep = _report(col, {"ordinary step"}, [
        {"source": {"name": "guarded step"}, "parent": {"name": "selftest"},
         "error": {"name": "AssertionError", "test": "что угодно", "message": "…"}},
    ])
    good &= case("(8) имя стража целиком динамическое — не извиняет никого (fail-closed)",
                 col, rep, "ASSERTED-NOT-EXECUTED", False)

    # (9) страж в ПАПКЕ. В дереве сегодня папочных скриптов ноль (2563 папки, 0 с
    # событиями) — и это ровно та причина, по которой проба нужна: следующая
    # слепота придёт этой формой, а «ноль в дереве» её не отменяет.
    col = _collection(None, folder_pre=ROOT_GUARD)
    rep = _report(col, {"ordinary step"}, [
        {"source": {"name": "guarded step"}, "parent": {"name": "folder"},
         "error": {"name": "AssertionError", "test": ROOT_FAIL_NAME, "message": "…"}},
    ])
    good &= case("(9) страж в ПАПКЕ — читается так же, как корневой",
                 col, rep, "RECORDED-SKIP", True)

    # ── ОСЬ 3: статические запреты в корне. Для 57 коллекций из 89 они не
    # проверялись ВООБЩЕ: маска, внесённая в корневой скрипт, гейтом не ловилась.
    col = _collection(None, root_pre=[
        "if (!pm.environment.get('opId')) { pm.execution.setNextRequest(null); }",
    ])
    rep = _report(col, {"guarded step", "ordinary step"}, [])
    good &= case_problem("(10) setNextRequest(null) в КОРНЕВОМ скрипте — запрет краснеет",
                         col, rep, ["BANNED setNextRequest(null)", "корень коллекции"], False)

    # (11) законный близнец той же внешности: тот же текст, но в КОММЕНТАРИИ. Гейт
    # обязан молчать — иначе первое же объяснение рядом с запретом покраснит 57
    # коллекций, и запрет снимут как ложный.
    col = _collection(None, root_pre=[
        "// НИКОГДА не пиши pm.execution.setNextRequest(null) — он завершает ПРОГОН.",
        "/* и в блочном комментарии тоже: setNextRequest(null) */",
        "pm.environment.set('_ok', '1');",
    ])
    rep = _report(col, {"guarded step", "ordinary step"}, [])
    good &= case_silent("(11) тот же запрет в КОММЕНТАРИИ корня — гейт молчит", col, rep)

    # (12) комментарий отрезается разбором, а не «до первой косой черты»: внутри
    # регулярного выражения `//` — это код. Иначе строка с регуляркой съедала бы
    # остаток себя, и запрет за ней стал бы невидим.
    col = _collection(None, root_pre=[
        "var _re = /https:\\/\\//; if (_re.test('x')) { pm.execution.setNextRequest(null); }",
    ])
    rep = _report(col, {"guarded step", "ordinary step"}, [])
    good &= case_problem("(12) `//` внутри регулярного выражения — это код, запрет за ним виден",
                         col, rep, ["BANNED setNextRequest(null)"], False)

    # (13) НЕМОЙ корневой пропуск НЕ объясняет пропавший хвост. Это анти-маскировка:
    # корневой страж исполняется перед КАЖДЫМ запросом, поэтому засчитать его в
    # «объяснённые пропуски» значило бы объявить объяснённым любое усечение — то
    # есть убить ровно тот класс, ради которого перепись заведена.
    col = _collection(None, root_pre=["if (!pm.variables.has('zzz')) { pm.execution.skipRequest(); }"])
    rep = _report(col, {"guarded step"}, [])
    good &= case("(13) немой корневой skipRequest НЕ объясняет пропавший хвост",
                 col, rep, "UNEXPLAINED", False)

    # (14) немой страж по переменной окружения — в корне. Тот же запрет 1б, та же
    # цена: потерянная переменная тихо снимает проверки со ВСЕЙ коллекции сразу.
    col = _collection(None, root_pre=[
        "const b = pm.environment.get('internalBaseUrl') || '';",
        "if (!b) { pm.execution.skipRequest(); }",
    ])
    rep = _report(col, {"guarded step", "ordinary step"}, [])
    good &= case_problem("(14) немой страж по internalBaseUrl в корне — запрет краснеет",
                         col, rep, ["SILENT environment guard", "internalBaseUrl"], False)

    # (15) тот же близнец, но в ЭЛЕМЕНТНОМ скрипте: правило одно на все области.
    # Сегодня запрет читал сырой текст и краснел на объяснении рядом с собой —
    # то есть предписанная им же документация была нарушением.
    col = _collection([
        "// запрещено: pm.execution.setNextRequest(null) завершает ПРОГОН.",
        "if (!pm.environment.get('opId')) { pm.execution.skipRequest(); }",
    ])
    rep = _report(col, {"ordinary step"}, [])
    good &= case_silent("(15) запрет в КОММЕНТАРИИ элемента — гейт молчит", col, rep)

    # (16) упоминание запрета внутри СТРОКОВОГО ЛИТЕРАЛА — это проза, а не вызов.
    # Наши генераторы пишут в имена утверждений и тексты провалов длинные
    # объяснения; читая сырой текст, запрет краснел бы на тексте о самом себе.
    # Вызов при этом отличается от упоминания разбором, а не длиной строки:
    # положительный близнец — случаи (10) и (12), где вызов настоящий.
    col = _collection([
        "pm.test('никогда не зови setNextRequest(null): он завершает прогон', function () {",
        "  pm.expect(1).to.eql(1);",
        "});",
    ])
    rep = _report(col, {"guarded step", "ordinary step"}, [])
    good &= case_silent("(16) упоминание запрета в СТРОКЕ — не вызов, гейт молчит", col, rep)

    print()
    if good:
        print("ДОКАЗАНО: различитель ловит немой разрыв, пропускает записанный пропуск "
              "и не превращается в амнистию по факту наличия стража.")
        return 0
    print("САМОПРОВЕРКА ПРОВАЛЕНА: различитель не подтверждён в обе стороны.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
