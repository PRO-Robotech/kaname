#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Доказательство: вердиктный гейт различает «условие не создано» и находку — КОДОМ.

ПРЕДМЕТ. Категория, названная только словами в выводе, машинно не существует:
читающий вердикт (шаг конвейера, хук отправки, свод) видит ненулевой код и
читает красное о продукте. Поэтому проверяется не текст, а ПАРА «текст + код
возврата».

Гоняется НАСТОЯЩИЙ гейт (`scripts/assert-suites-green.sh`) на синтетических
отчётах: newman для этого не нужен, и доказательство исполнимо в любом дереве.
Оси — по одной, различие между инъекцией и её законным близнецом РОВНО ОДНО:
помечено падение меткой или нет.

Литерал метки здесь не выписывается — берётся у её единственного производителя
(см. `precondition_mark_test.py`), иначе доказательство стало бы третьим местом
об одном предмете.

КТО ЭТУ ПРОБУ ИСПОЛНЯЕТ: `.github/scripts/run-python-probes.py`. Состав он
собирает ОБХОДОМ дерева по образцам `services/*/tests/newman/scripts/*_test.py`
и `tests/newman/scripts/*_test.py` (эта проба — во втором) и
НИ ОДИН файл проб по имени не называет — поэтому отдельного шага в конвейере файл
не требует, а искать вызывающего предикатом `git grep <имя файла>` бесполезно:
вызова по имени нет ни у кого. Код возврата при этом доезжает до вердикта шага.
Проводку держит `tools/pythonprobes`.
"""

import json
import pathlib
import re
import subprocess
import sys
import tempfile

SCRIPTS = pathlib.Path(__file__).resolve().parent
GATE = SCRIPTS / "assert-suites-green.sh"
REPO = SCRIPTS.parents[2]

# ── МЕТКА БЕРЁТСЯ У НАСТОЯЩЕГО ПРОИЗВОДИТЕЛЯ, А НЕ ВЫПИСЫВАЕТСЯ ЗДЕСЬ ─────────
#
# Прежде она бралась `import gen` из каталога САМОГО гейта — и это работало ровно
# пока гейт лежал внутри одной из суит. Гейт один на дерево и своего `gen.py` не
# имеет; выписать метку литералом значило бы завести третье место об одном
# предмете, а оно разошлось бы молча.
#
# Поэтому производитель ИЩЕТСЯ обходом, а не называется координатой: суита,
# названная поимённо, унесла бы доказательство с собой при первом же переезде.

RE_PRODUCER = re.compile(r'^PRECONDITION_MARK\s*=\s*(["\'])(?P<mark>.+?)\1\s*$', re.M)


def suite_generators() -> list[pathlib.Path]:
    """Все производители метки дерева — по одному на набор newman."""
    # КОРНЕВОЙ НАБОР — форма ОТДЕЛЬНОГО репозитория службы. Строка верна и в
    # дереве платформы: там такого файла нет, и `is_file()` ниже его отбросит.
    found = sorted(REPO.glob("tests/newman/scripts/gen.py"))
    found += sorted(REPO.glob("services/*/tests/newman/scripts/gen.py"))
    found += sorted(REPO.glob("*/tests/newman/scripts/gen.py"))
    return [g for g in found if g.is_file()]


def read_mark() -> str:
    gens = suite_generators()
    if not gens:
        print("ОТКАЗ: в дереве не найдено ни одного производителя метки "
              "(*/tests/newman/scripts/gen.py) — доказывать нечего, и это не "
              "«ноль находок»", file=sys.stderr)
        raise SystemExit(1)
    m = RE_PRODUCER.search(gens[0].read_text(encoding="utf-8"))
    if not m:
        print(f"ОТКАЗ: {gens[0].relative_to(REPO)} не объявляет PRECONDITION_MARK "
              "присвоением — предпосылка пробы не выполняется", file=sys.stderr)
        raise SystemExit(1)
    return m.group("mark")


MARK = read_mark()

FAILURES = []


def check(name, want_rc, got_rc, out, needle=""):
    ok = want_rc == got_rc and (not needle or needle in out)
    print(f"  {'ok  ' if ok else 'FAIL'} {name} (код {got_rc})", end="")
    if ok:
        print()
    else:
        why = (f"ожидался код {want_rc}" if want_rc != got_rc
               else f"в выводе нет «{needle}»")
        print(f" — {why}")
        FAILURES.append(f"{name}: {why}")


def build(root: pathlib.Path, total: int, marked: int, plain: int,
          with_producer: bool = True) -> None:
    """Синтетическая суита: производитель метки, коллекция, отчёт.

    `with_producer=False` снимает РОВНО ОДИН факт — `scripts/gen.py` суиты, — и
    больше ничего: это законный близнец для оси «без производителя гейт
    отказывает».
    """
    (root / "collections").mkdir(parents=True)
    (root / "out").mkdir()
    if with_producer:
        (root / "scripts").mkdir()
        # Значение НЕ выписано: оно прочитано у настоящего производителя выше.
        (root / "scripts" / "gen.py").write_text(
            f"PRECONDITION_MARK = {MARK!r}\n", encoding="utf-8")
    (root / "collections" / "synth.postman_collection.json").write_text(json.dumps({
        "info": {"name": "synth",
                 "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": [{"name": "step", "request": {"method": "GET", "url": "http://127.0.0.1/x"}}],
    }), encoding="utf-8")
    failures = []
    for _ in range(marked):
        failures.append({"error": {"name": "AssertionError",
                                   "test": f"{MARK} harness config: someBaseUrl is set",
                                   "message": "не инъектирована"},
                         "source": {"name": "step"}})
    for _ in range(plain):
        failures.append({"error": {"name": "AssertionError",
                                   "test": "статус ответа 200",
                                   "message": "получено 500"},
                         "source": {"name": "step"}})
    (root / "out" / "synth.json").write_text(json.dumps({"run": {
        "stats": {"requests": {"total": 1, "failed": 0},
                  "assertions": {"total": total, "failed": marked + plain},
                  "testScripts": {"total": 1, "failed": 0},
                  "prerequestScripts": {"total": 1, "failed": 0}},
        "executions": [{"cursor": {"position": 0, "iteration": 0},
                        "item": {"name": "step"}, "response": {"code": 200}}],
        "failures": failures}}, ensure_ascii=False), encoding="utf-8")


def run_gate(root: pathlib.Path, gate: pathlib.Path = GATE):
    proc = subprocess.run(["bash", str(gate)], cwd=str(root),
                          capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)

        print("ось 1 — упало ТОЛЬКО помеченное: третий исход, свой код")
        a = tmp / "a"; build(a, 5, 3, 0)
        rc, out = run_gate(a)
        check("код 3 и категория названа", 3, rc, out, "УСЛОВИЕ НЕ СОЗДАНО: 3")
        check("и находок объявлено ноль", 3, rc, out, "находок 0")

        print("ось 2 — то же плюс ОДНО непомеченное: находка объявляется первой")
        b = tmp / "b"; build(b, 5, 3, 1)
        rc, out = run_gate(b)
        check("код 1, а не 3 (иначе категория стала бы маской)", 1, rc, out, "находок 1")
        check("и помеченное по-прежнему сосчитано отдельно", 1, rc, out, "УСЛОВИЕ НЕ СОЗДАНО 3")

        print("ось 3 — законный близнец: те же числа, но ничего не упало")
        c = tmp / "c"; build(c, 5, 0, 0)
        rc, out = run_gate(c)
        check("зелено", 0, rc, out, "GREEN")

        print("ось 4 — метка НИЧЕГО не вычитает: помеченное остаётся в числе падений")
        d = tmp / "d"; build(d, 5, 3, 0)
        rc, out = run_gate(d)
        check("в TOTAL стоит 3 failed, а не 0", 3, rc, out, "3 failed")

        # ── ось 5 ────────────────────────────────────────────────────────────
        # Прежде здесь гейт УНОСИЛСЯ от своего `gen.py` в чужой каталог: это
        # доказывало предмет старой формы — «метка читается рядом с гейтом».
        # Адресат чтения теперь ПРОВЕРЯЕМАЯ СУИТА, поэтому и снимать надо её
        # производителя. Отличие от оси 1 — РОВНО ОДИН факт: `scripts/gen.py`.
        print("ось 5 — у суиты нет производителя метки: гейт ОТКАЗЫВАЕТ, а не берёт умолчание")
        e = tmp / "e"; build(e, 5, 3, 0, with_producer=False)
        rc, out = run_gate(e)
        check("код 1 и отказ назван", 1, rc, out, "метку третьего исхода не прочитать")
        check("отказ называет путь, по которому читали", 1, rc, out, "gen.py::PRECONDITION_MARK")

    print()
    if FAILURES:
        print(f"ОТКАЗ: провалено утверждений {len(FAILURES)} из 8", file=sys.stderr)
        for x in FAILURES:
            print("  " + x, file=sys.stderr)
        return 1
    print("ЧИСТО: 8 утверждений — третий исход отличим кодом возврата, "
          "находка объявляется первой, вычитания нет")
    return 0


if __name__ == "__main__":
    sys.exit(main())
