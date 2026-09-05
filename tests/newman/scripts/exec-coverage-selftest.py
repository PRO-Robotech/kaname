#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
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

Входов восемнадцать.

  (1) САНКЦИОНИРОВАННЫЙ страж, упало ЕГО утверждение → RECORDED-SKIP, гейт молчит.
  (2) Тот же шаг, но упало утверждение ТЕСТ-скрипта → ASSERTED-NOT-EXECUTED,
      находка. Тест-скрипт не выполняется без ответа, значит шаг ИСПОЛНЯЛСЯ, а
      запись о нём пропала — ровно тот класс, ради которого гейт заведён.
  (3) Пропуск БЕЗ утверждения (голый skipRequest) → немой explained-skip, НЕ
      RECORDED-SKIP: он ничего не оставляет в вердикте, и путать их нельзя.
  (4) Страж есть, но отчёт не говорит, ЧТО упало → находка (fail-closed):
      неустановимое не извиняется, иначе «объяснённый пропуск» станет корзиной
      «всё остальное», которой не бывает.
  (5) Страж ОБЪЯВЛЕН, но НЕ СРАБОТАЛ: записи об исполнении шага нет и ни одного
      утверждения от него нет тоже. Шаг обязан быть НАЗВАН (UNEXPLAINED плюс
      координата), а не зачтён пропущенным по факту наличия стража. Извиняет не
      объявление стража, а его упавшее утверждение.

      Пара даётся ВНУТРИ ОДНОЙ КОЛЛЕКЦИИ, и иначе её дать нельзя. Корневой страж
      объявлен сразу для ВСЕХ шагов — значит вопрос «страж сработал или только
      объявлен» решается ПОШАГОВО, и проверить это можно лишь там, где под одним
      объявленным стражем один шаг извинён, а другой назван. Две отдельные
      коллекции (в одной сработал, в другой нет) того же не утверждают: каждая
      по отдельности объяснима и «зачётом по объявлению», и разбором отчёта.

ОСЬ (5) ЗАМЕНЯЕТ ПУНКТ, КОТОРЫЙ ДЕРЖАЛСЯ ПАМЯТЬЮ (задача #722). Предикат снятия
#661 требовал сверки с отчётом КОНКРЕТНОГО исторического прогона (`RECORDED-SKIP
15`, `ASSERTED-NOT-EXECUTED 0` на наборе placement-coherence). Отчёта в
репозитории нет, прогон не воспроизводится — такой пункт нельзя ни подтвердить,
ни опровергнуть. Здесь то же свойство — «санкционированной формой засчитывается
СРАБОТАВШИЙ страж, а не объявленный» — утверждается входом, который строится на
месте и прогоняется в любой момент.

Запуск: python3 scripts/exec-coverage-selftest.py
"""
from __future__ import annotations

import copy
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
                root_test=None, twin_name=None):
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
    if twin_name is not None:
        # Второй лист ТОЙ ЖЕ формы: собственного пре-скрипта у него нет, страж
        # наследуется из корня — ровно как у первого. По коллекции эти два шага
        # неразличимы by construction; развести их может только ОТЧЁТ, и это и
        # есть предмет пары (17)/(18).
        twin = copy.deepcopy(guarded)
        twin["name"] = twin_name
        items = [guarded, twin, ordinary]
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


def case_split(label, collection, report, want_tokens, names, not_names):
    """Вход, на котором ОДНА коллекция обязана разойтись НАДВОЕ: часть шагов
    извинена, часть названа. Утверждает три вещи, и у каждой — своя мутация,
    которую не ловит ни один другой член (проверено инъекцией, см. ниже):

      * `want_tokens` — полосы вердикта ВМЕСТЕ С ЧИСЛАМИ (`1 RECORDED-SKIP`,
        `1 UNEXPLAINED`). Ловит подмену записанного пропуска немым
        `explained-skip`: находка та же, координата та же, вердикт тот же —
        расходится ровно полоса, а различать их и есть работа переписи (вход 3);
      * `names` — координаты, которые находка обязана НАЗВАТЬ. Ловит находку
        без координаты: запрет, который краснеет, не говоря ГДЕ, снимают первым;
      * `not_names` — координаты, которых в находках быть НЕ ДОЛЖНО. Ловит
        перечень, собранный не из своего набора: числа в строке остаются
        верными, вердикт красным, названная координата на месте — и вдобавок
        назван ИЗВИНЁННЫЙ шаг. Ни `case`, ни `case_problem` этого не видят:
        оба смотрят только на присутствие.

    ВЕРДИКТА ОТДЕЛЬНЫМ ЧЛЕНОМ ЗДЕСЬ НЕТ — намеренно, и это исправление прежней
    редакции. `check_collection` возвращает `not problems` первым элементом на
    ВСЕХ ПЯТИ путях возврата (предикат:
    `grep -c 'return (not problems' exec-coverage.py` → 5), то есть «вердикт
    зелёный» и «находок нет» — одно утверждение по построению. Непустой `names`
    уже означает `ok=False`. Прежний помощник нёс такой член и обосновывал его
    различием, которого в этом гейте нет: снятие члена не меняло исхода ни на
    базовом прогоне, ни на одной из трёх инъекций — признак пустого утверждения,
    а не строгости. Поэтому `ok` здесь только печатается в диагностике.
    """
    ok, _judged, line, problems = _judge(collection, report)
    blob = "\n".join(problems)
    missing = [w for w in want_tokens if w not in line]
    absent = [w for w in names if w not in blob]
    leaked = [w for w in not_names if w in blob]
    verdict = "OK  " if not (missing or absent or leaked) else "ПЛОХО"
    print(f"{verdict} {label}")
    print(f"        {line.strip()}")
    if verdict == "ПЛОХО":
        print(f"        ожидалось: в строке {list(want_tokens)}, в находках {list(names)}, "
              f"БЕЗ {list(not_names)}; получено ok={ok}"
              f"{f', нет полос {missing}' if missing else ''}"
              f"{f', нет координат {absent}' if absent else ''}"
              f"{f', назван извинённый {leaked}' if leaked else ''}")
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

    def _guard_fired(step):
        """Отчётная запись «страж СРАБОТАЛ на шаге `step`»: его утверждение упало.

        Именно она — единственное, чем санкционированный пропуск отличается от
        объявленного стража, потому что по коду коллекции они неразличимы.
        """
        return {"source": {"name": step}, "parent": {"name": "selftest"},
                "error": {"name": "AssertionError", "test": ROOT_FAIL_NAME,
                          "message": "lbId не определена ни в одной области."}}

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

    # ── ОСЬ 4: СТРАЖ ОБЪЯВЛЕН ≠ СТРАЖ СРАБОТАЛ ───────────────────────────────
    #
    # Граница амнистии, и она НЕ совпадает с (13). Там корневой пропуск немой —
    # `_recorded_skip_guards` стражем его не признаёт вовсе (утверждения в
    # скрипте нет), поэтому и зачитывать нечего. Здесь форма САНКЦИОНИРОВАННАЯ,
    # страж прочитан и признан — а часть шагов всё равно исчезает бесследно: ни
    # записи об исполнении, ни единого утверждения. Значит на них страж не
    # срабатывал, и пропали они по другой причине — ровно усечение, ради
    # которого перепись и заведена.
    #
    # ПАРА ДАЁТСЯ ВНУТРИ ОДНОЙ КОЛЛЕКЦИИ, и это не оформление. Корневой скрипт
    # объявлен сразу для ВСЕХ шагов, поэтому «сработал или только объявлен» —
    # вопрос ПОШАГОВЫЙ. Две коллекции (в одной сработал, в другой нет) его не
    # задают: каждая по отдельности одинаково объяснима и разбором отчёта, и
    # зачётом по факту объявления. Здесь под ОДНИМ объявленным стражем стоят два
    # неразличимых по коду шага, и перепись обязана развести их по отчёту:
    # `guarded step` извинить и НЕ называть, `silent step` — назвать.
    #
    # Соблазн зачесть такой шаг пропущенным реален: это и есть тот «фикс» ложных
    # срабатываний #661, от которого шапка exec-coverage.py отговаривает прямо.
    # Корневой скрипт исполняется перед КАЖДЫМ запросом, поэтому зачёт по факту
    # ОБЪЯВЛЕНИЯ стража объявил бы объяснённым любое усечение сразу в 57
    # коллекциях из 90 — перемер на `aea75498` тем же предикатом, что в шапке
    # (там он пинится к `dfd2c027` и даёт 57 из 89: числитель не сдвинулся,
    # знаменатель вырос на одну коллекцию iam, где этой формы нет; на HEAD этой
    # ветки предикат повторён и даёт те же 57 из 90, зеркало «без корневого
    # стража» — 33).
    #
    # ИНЪЕКЦИЯ, КОТОРОЙ ЭТА ПАРА ДОКАЗАНА (шесть мутаций `exec-coverage.py`;
    # прогон каждой — с базового дерева, красное называет координату):
    #
    #   A  зачёт по факту ОБЪЯВЛЕНИЯ стража          → красен ТОЛЬКО (17)
    #   B  находка без координаты                    → красен ТОЛЬКО (17)
    #   C  `_failure_belongs_to_guard` → False       → красны (1)(5)(9)(17)(18)
    #   D  перечень координат шире своего набора     → красен ТОЛЬКО (17)
    #   E  извиняется лишь ПЕРВЫЙ страж коллекции    → красен ТОЛЬКО (18)
    #   F  записанный пропуск подан explained-skip   → красны (1)(5)(9)(17)(18)
    #
    # E — то, ради чего близнец (18) не может быть повторением (5): на ОДНОМ
    # извинённом шаге «первый страж» и «каждый страж» неразличимы by
    # construction, поэтому (5) на E зелен. D — то, ради чего у (17) свой
    # помощник: замена его на `case_problem` оставляет D НЕЗАМЕЧЕННОЙ, и весь
    # прогон выходит кодом 0 на сломанном гейте.
    col = _collection(None, root_pre=ROOT_GUARD, twin_name="silent step")
    rep = _report(col, {"ordinary step"}, [_guard_fired("guarded step")])
    good &= case_split(
        "(17) под одним стражем один СРАБОТАЛ, другой лишь ОБЪЯВЛЕН — "
        "первый извинён, второй назван",
        col, rep,
        want_tokens=["1 RECORDED-SKIP", "1 UNEXPLAINED"],
        names=["never executed", "silent step"],
        not_names=["guarded step"])

    # (18) ЗАКОННЫЙ БЛИЗНЕЦ: та же коллекция, тот же страж, те же три шага — но
    # сработал он на ОБОИХ, и оба утверждения доехали в отчёт. Тогда пропуск
    # записан, счётен и виден в вердикте полосой `2 RECORDED-SKIP`, а перепись
    # обязана молчать. Без этой половины (17) ловил бы форму («у шага есть
    # корневой страж»), а не существо («страж сработал»), и первый же
    # санкционированный пропуск отключил бы проверку как ложную.
    #
    # Вход отличается от (5) не оформлением: там ОДИН страж на ДВУХ листьях и
    # полоса `1 RECORDED-SKIP`, здесь ДВА извинённых шага на трёх и полоса
    # `2 RECORDED-SKIP`. Это ловит мутацию, которой (5) не видит by construction:
    # «извиняется только ПЕРВЫЙ страж коллекции» — на одном шаге она неотличима
    # от исправного гейта.
    #
    # Отдельного помощника здесь нет намеренно: `case` утверждает полосу И
    # молчание сразу, потому что вердикт этого гейта есть `not problems`
    # (см. `case_split`). Второй член был бы вторым именем того же утверждения.
    col = _collection(None, root_pre=ROOT_GUARD, twin_name="silent step")
    rep = _report(col, {"ordinary step"},
                  [_guard_fired("guarded step"), _guard_fired("silent step")])
    good &= case("(18) тот же вход, но страж СРАБОТАЛ на ОБОИХ — оба пропуска записаны",
                 col, rep, "2 RECORDED-SKIP", True)

    print()
    if good:
        print("ДОКАЗАНО: различитель ловит немой разрыв, пропускает записанный пропуск "
              "и не превращается в амнистию по факту наличия стража.")
        return 0
    print("САМОПРОВЕРКА ПРОВАЛЕНА: различитель не подтверждён в обе стороны.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
