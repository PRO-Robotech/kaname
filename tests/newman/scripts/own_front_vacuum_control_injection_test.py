#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Доказательство, что гейт контроля непустоты СПОСОБЕН упасть и способен смолчать.

Гоняется НАСТОЯЩАЯ судящая функция `audit`, а не её пересказ, и вход берётся
ПОРОЖДЁННЫЙ — та самая коллекция дерева. Оси проверяются по одной; у каждой
инъекции законный близнец, отличающийся ровно одним фактом.

ПОЧЕМУ ИНЪЕКЦИЯ СНИМАЕТ ИМЕННО КОНТРОЛЬ. Дефект, который гейт обязан ловить, —
отрицание БЕЗ положительного контроля. Поэтому инъекция вырезает блок между
маркерами `>>> / <<<` и не трогает больше ничего: если бы она заодно ломала
что-то ещё, красное приходило бы от соседа, и гейт мог бы оказаться мёртвым, не
показав этого ничем.

КТО ЭТУ ПРОБУ ИСПОЛНЯЕТ: `.github/scripts/run-python-probes.py`. Состав он
собирает ОБХОДОМ дерева по образцу `services/*/tests/newman/scripts/*_test.py` и
НИ ОДИН файл проб по имени не называет — поэтому отдельного шага в конвейере файл
не требует, а искать вызывающего предикатом `git grep <имя файла>` бесполезно:
вызова по имени нет ни у кого. Код возврата при этом доезжает до вердикта шага.
Проводку держит `tools/pythonprobes`.
Попадания у этого имени в дереве ЕСТЬ, и они ПРОЗА, а не вызов: `docs/RESULTS.md`
и шапка самого гейта `own_front_vacuum_control_test.py`. Прочитать их как «зовут
отсюда» нельзя — исполняет файл по-прежнему только обход выше.
"""

import copy
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import own_front_vacuum_control_test as gate  # noqa: E402

OPEN = ">>> контроль непустоты"
CLOSE = "<<< контроль непустоты"

FAILURES = []
PASSED = [0]


def check(name, ok, detail=""):
    print(f"  {'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f": {detail}"))
    PASSED[0] += 1
    if not ok:
        FAILURES.append(f"{name}: {detail}")


def load():
    return json.loads(gate.COLLECTION.read_text(encoding="utf-8"))


def leaves(doc):
    def walk(nodes):
        for node in nodes:
            if "item" in node:
                yield from walk(node["item"])
            else:
                yield node
    return list(walk(doc["item"]))


def script_of(node):
    for ev in node.get("event", []):
        if ev.get("listen") == "test":
            return ev["script"]["exec"]
    return None


def strip_control(doc, step):
    """Вырезать блоки контроля у одного шага — РОВНО ОДИН факт."""
    removed = 0
    for node in leaves(doc):
        if node["name"].split(" :: ")[-1] != step:
            continue
        exec_lines = script_of(node)
        kept, inside = [], False
        for line in exec_lines:
            if OPEN in line:
                inside = True
                removed += 1
                continue
            if CLOSE in line:
                inside = False
                continue
            if not inside:
                kept.append(line)
        exec_lines[:] = kept
    return removed


def add_assertion(doc, step, js):
    for node in leaves(doc):
        if node["name"].split(" :: ")[-1] == step:
            script_of(node).extend(js)
            return True
    return False


def rename_assertion(doc, step, title, new_title):
    for node in leaves(doc):
        if node["name"].split(" :: ")[-1] != step:
            continue
        exec_lines = script_of(node)
        for i, line in enumerate(exec_lines):
            if title in line:
                exec_lines[i] = line.replace(title, new_title)
                return True
    return False


def targets_of(step):
    return sorted(t for (s, t) in gate.TARGETS if s == step)


def main():
    base = load()

    print("ось 0 — законный близнец: дерево как есть")
    census, findings = gate.audit(copy.deepcopy(base))
    check("контроль: молчание", not findings, "; ".join(findings)[:400])
    check("предмет осмотрен", census["шагов"] > 0 and census["утверждений"] > 0, str(census))
    check("миров исполнено = 2 + число целей",
          census["миров исполнено"] == 2 + census["целей объявлено"], str(census))
    check("в W_today проходит МЕНЬШЕ, чем в W_hiding — иначе миры не различаются",
          census["прошло в W_today"] < census["прошло в W_hiding"], str(census))

    steps = sorted({s for (s, _t) in gate.TARGETS})
    print(f"ось 1 — снят контроль, по одному шагу (шагов с целями: {len(steps)})")
    for step in steps:
        doc = copy.deepcopy(base)
        removed = strip_control(doc, step)
        check(f"[{step}] блок контроля найден и вырезан", removed > 0, f"вырезано {removed}")
        _c, f = gate.audit(doc)
        named = [t for t in targets_of(step) if any(t in x and "ПРОШЛО" in x for x in f)]
        check(f"[{step}] инъекция: находка называет свои цели",
              sorted(named) == targets_of(step),
              f"названо {named}, ожидалось {targets_of(step)}")
        others = [t for (s, t) in gate.TARGETS
                  if s != step and any(t in x and "ПРОШЛО" in x for x in f)]
        check(f"[{step}] инъекция роняет ТОЛЬКО свои цели", not others, str(others))

    print("ось 2 — цель переименована (утверждение снято или названо иначе)")
    doc = copy.deepcopy(base)
    step, title = next(iter(gate.TARGETS))
    check("подмена внесена", rename_assertion(doc, step, title, title + " ЗАЧЕМ-ТО"))
    _c, f = gate.audit(doc)
    check("инъекция: находка «цель не найдена»",
          any("не найдена в коллекции" in x for x in f), "; ".join(f)[:300])

    print("ось 3 — НОВОЕ утверждение, зеленеющее на одинаковых ответах")
    doc = copy.deepcopy(base)
    check("подмена внесена", add_assertion(doc, "nonsense-path-on-own-front", [
        "pm.test('SYNTH: в теле нет постороннего имени', () =>",
        "  pm.expect(pm.response.text()).to.not.include('nobody-writes-this'));",
    ]))
    _c, f = gate.audit(doc)
    check("инъекция: находка «не объявлено честным наблюдением»",
          any("не объявлено" in x and "SYNTH" in x for x in f), "; ".join(f)[:300])

    print("ось 4 — послабление истекает само")
    doc = copy.deepcopy(base)
    saved = dict(gate.HONEST_IN_W_TODAY)
    try:
        gate.HONEST_IN_W_TODAY[("nonexistent-step", "нет такого утверждения")] = "синтетика"
        _c, f = gate.audit(doc)
        check("запись без предмета — находка",
              any("пережила свой предмет" in x for x in f), "; ".join(f)[:300])
        gate.HONEST_IN_W_TODAY.clear()
        gate.HONEST_IN_W_TODAY.update(saved)
        gate.HONEST_IN_W_TODAY[("own-public-front-serves-rest", "status 200")] = "синтетика"
        _c, f = gate.audit(copy.deepcopy(base))
        check("запись, которой нечего прощать, — находка",
              any("прощать нечего" in x for x in f), "; ".join(f)[:300])
    finally:
        gate.HONEST_IN_W_TODAY.clear()
        gate.HONEST_IN_W_TODAY.update(saved)

    print("ось 5 — пустой обход: ОТКАЗ, а не молчание")
    try:
        gate.audit({"item": []})
        check("пустая коллекция даёт отказ", False, "audit промолчал на пустом обходе")
    except gate.VerdictHasNoSubject as exc:
        check("пустая коллекция даёт отказ", "ноль шагов" in str(exc), str(exc))

    print("ось 6 — подмена `pm` не способна дать ЗЕЛЁНОЕ на незнакомой цепочке")
    # Предмет оси — не «бросает исключение в python», а «не зеленеет»: бросок
    # внутри `pm.test` записывается УПАВШИМ утверждением, ровно как у настоящего
    # движка. Подделка, отвечающая «хорошо» на то, чего не понимает, была бы
    # снисходительнее продукта.
    got = gate.run_world([("synth", "pm.test('x', () => pm.expect(1).to.be.frobnicated);")],
                         {"synth": (200, "{}")})
    verdict = got[("synth", "x")]
    check("неизвестный член chai не даёт зелёного", not verdict["passed"], str(verdict))
    check("и находка называет причину", "frobnicated" in verdict["error"],
          verdict["error"][:200])

    print("ось 7 — законный близнец оси 6: известная цепочка судит по существу")
    got = gate.run_world([("synth", "pm.test('y', () => pm.expect(1).to.eql(1));"
                                    "pm.test('z', () => pm.expect(1).to.eql(2));")],
                         {"synth": (200, "{}")})
    check("верное утверждение проходит", got[("synth", "y")]["passed"], str(got[("synth", "y")]))
    check("неверное утверждение падает", not got[("synth", "z")]["passed"], str(got[("synth", "z")]))

    print("ось 8 — ЗАГОЛОВКИ ответа моделируются, и модель не снисходительнее продукта")
    # Заголовок — часть ответа, и утверждения набора о подсказке аутентификации
    # читают именно его. Мир, заголовков не знающий, ронял бы такое утверждение
    # «скрипт упал вне утверждения» — то есть краснел бы по чужому предмету.
    # Проверяется в ОБЕ стороны: объявленный доезжает, необъявленный читается
    # отсутствующим, регистр не различается — иначе модель была бы СТРОЖЕ
    # продукта и красила бы то, что на стенде зелено.
    js = ("pm.test('есть', () => pm.expect(pm.response.headers.get('WWW-Authenticate'))"
          ".to.eql('Bearer'));"
          "pm.test('регистр', () => pm.expect(pm.response.headers.get('www-authenticate'))"
          ".to.eql('Bearer'));"
          "pm.test('нет', () => pm.expect(pm.response.headers.get('X-Absent')).to.eql(null));")
    got = gate.run_world([("synth", js)], {"synth": (401, "{}", {"WWW-Authenticate": "Bearer"})})
    check("объявленный заголовок доезжает до скрипта", got[("synth", "есть")]["passed"],
          str(got[("synth", "есть")]))
    check("поиск не различает регистр — как у postman-collection",
          got[("synth", "регистр")]["passed"], str(got[("synth", "регистр")]))
    check("необъявленный читается как отсутствующий", got[("synth", "нет")]["passed"],
          str(got[("synth", "нет")]))
    # Законный близнец: тот же скрипт в мире БЕЗ заголовка обязан УПАСТЬ на
    # утверждении о наличии — иначе «модель заголовков есть» неотличимо от
    # «модель отвечает „Bearer“ всем».
    got = gate.run_world([("synth", js)], {"synth": (403, "{}")})
    check("в мире без заголовка утверждение о наличии падает",
          not got[("synth", "есть")]["passed"], str(got[("synth", "есть")]))
    check("а утверждение об отсутствии — по-прежнему проходит",
          got[("synth", "нет")]["passed"], str(got[("synth", "нет")]))

    total = len(FAILURES)
    print()
    if PASSED[0] == 0:
        print("ОТКАЗ: исполнено ноль утверждений — вердикт беспредметен", file=sys.stderr)
        return 1
    if total:
        print(f"ОТКАЗ: провалено {total} из {PASSED[0]}", file=sys.stderr)
        for x in FAILURES:
            print("  " + x, file=sys.stderr)
        return 1
    print(f"ЧИСТО: утверждений {PASSED[0]}, осей 9 — гейт способен упасть по каждой и "
          f"способен смолчать на законном близнеце")
    return 0


if __name__ == "__main__":
    sys.exit(main())
