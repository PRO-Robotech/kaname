# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ПРОВЯЗКА ПРЕДПОЛЁТА: прогонщик зовёт его, и зовёт ДО первой коллекции.

ПРЕДМЕТ. Предполёт доказан своей инъекцией (`seed_preflight.py --self-test`), и
это доказательство о НЁМ. О том, что прогонщик его ЗОВЁТ, оно не говорит ничего:
скрипт, способный упасть, и скрипт, чей код возврата кто-то читает, — разные
утверждения, и второе теряется молча. Цену этого класса дерево уже платило:
переходник хука лежал на месте и звал скрипт, которого не было, — провязка
выглядела исполненной, а не проверялась ни разу.

ТРИ УТВЕРЖДЕНИЯ, И КАЖДОЕ СВОИМ ПРЕДИКАТОМ:

  1. вызов есть, и он адресует ИМЕННО этот файл;
  2. вызов стоит РАНЬШЕ первого `run_one` — причина, названная после первого
     падения, стоит прогона;
  3. код возврата читается КАК ДАННЫЕ (`|| rc=$?` плюс развилка), а не как
     условие продолжения: тело `run.sh` идёт под `set -e`, и голый вызов оборвал
     бы прогонщик ДО развилки — молча, тем же способом, каким это уже случалось
     с шагом конвейера.

ИНЪЕКЦИЯ — в обе стороны и на синтетике: текст без вызова роняет утверждение,
текст с вызовом ПОСЛЕ первой коллекции роняет утверждение о порядке, а законный
близнец (вызов в комментарии) провязкой НЕ считается.
"""

from __future__ import annotations

import pathlib
import re

NEWMAN = pathlib.Path(__file__).resolve().parents[1]
RUNNER = NEWMAN / "scripts" / "run.sh"
PREFLIGHT = NEWMAN / "scripts" / "seed_preflight.py"

# Вызов — строка, НЕ начинающаяся с `#`: имя скрипта стоит и в прозе шапки, и
# предикат по подстроке считал бы собственное объяснение.
CALL_RE = re.compile(r"^(?!\s*#).*seed_preflight\.py", re.M)
RUN_ONE_RE = re.compile(r"^(?!\s*#)\s*run_one\s+", re.M)
# Чтение кода как ДАННЫХ: присваивание из `$?` в той же команде.
RC_AS_DATA_RE = re.compile(r"\|\|\s*_?preflight_rc=\$\?")


def call_position(text: str) -> int | None:
    m = CALL_RE.search(text)
    return m.start() if m else None


def first_run_one(text: str) -> int | None:
    m = RUN_ONE_RE.search(text)
    return m.start() if m else None


def test_the_runner_calls_the_preflight_before_the_first_collection():
    assert PREFLIGHT.is_file(), (
        f"предмет провязки отсутствует: {PREFLIGHT} нет в дереве — "
        f"утверждение о вызове было бы о несуществующем")
    text = RUNNER.read_text(encoding="utf-8")
    print(f"перепись: прогонщик {RUNNER.name}, строк {text.count(chr(10))}; "
          f"вызовов предполёта {len(CALL_RE.findall(text))}; "
          f"вызовов run_one {len(RUN_ONE_RE.findall(text))}")

    call = call_position(text)
    assert call is not None, (
        "прогонщик НЕ зовёт предполёт: его инъекция доказывает способность "
        "упасть, а не то, что кто-то её результат читает")

    first = first_run_one(text)
    assert first is not None, (
        "обход пуст: в прогонщике не найдено ни одного `run_one` — порядок "
        "проверять не с чем, и вердикт был бы о предикате, а не о файле")
    assert call < first, (
        f"предполёт вызван ПОСЛЕ первой коллекции (позиция {call} против {first}): "
        f"причина, названная после первого падения, стоит прогона")

    assert RC_AS_DATA_RE.search(text), (
        "код возврата предполёта не читается как ДАННЫЕ: тело прогонщика идёт "
        "под `set -e`, и голый вызов оборвал бы его ДО развилки — молча")
    assert re.search(r"75\)", text), (
        "развилка не различает третий исход: «условие не создано» обязано иметь "
        "свою ветку, иначе оно вычтется из вердикта либо зачтётся в успех")


def test_injection_the_wiring_claim_is_red_only_when_the_call_is_there():
    ok = "set -e\npython3 x/seed_preflight.py --env e || _preflight_rc=$?\nrun_one \"a\"\n"
    assert call_position(ok) is not None and call_position(ok) < first_run_one(ok)
    assert RC_AS_DATA_RE.search(ok)

    # (+) вызова нет вовсе — утверждение обязано пасть.
    gone = "set -e\nrun_one \"a\"\n"
    assert call_position(gone) is None, "предикат находит вызов там, где его нет"

    # (+) вызов ПОСЛЕ первой коллекции — падает утверждение о порядке, а не о
    # наличии: две разные находки ведут читателя в разные места.
    late = "set -e\nrun_one \"a\"\npython3 x/seed_preflight.py || _preflight_rc=$?\n"
    assert call_position(late) is not None
    assert call_position(late) > first_run_one(late), "порядок не различается"

    # (−) ЗАКОННЫЙ БЛИЗНЕЦ: имя в комментарии провязкой не является. Без него
    # предикат краснел бы на собственном объяснении в шапке прогонщика.
    prose = "set -e\n# раньше здесь звался seed_preflight.py — снят\nrun_one \"a\"\n"
    assert call_position(prose) is None, (
        "имя в комментарии принято за вызов — предикат судит текст, а не код")

    # (−) ЗАКОННЫЙ БЛИЗНЕЦ: голый вызов без чтения кода. Наличие есть, чтения нет.
    bare = "set -e\npython3 x/seed_preflight.py\nrun_one \"a\"\n"
    assert call_position(bare) is not None
    assert RC_AS_DATA_RE.search(bare) is None, (
        "голый вызов принят за чтение кода — тогда обрыв под `set -e` был бы невидим")
