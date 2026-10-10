# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Ожидание письма в наборе ключей доступа считает только письма СВОЕГО вида (kaname#684).

ПРЕДМЕТ. Дверь кодов приёмника стенда (`GET /codes?to=…&after=<заголовок>`)
отдаёт по элементу на КАЖДОЕ письмо адресату, а для письма без названного
заголовка — null. Личность полосы Ф13 кладёт посев, и письмо подтверждения
адреса посева уже лежит у приёмника, когда Ф13-25 ждёт письма восстановления.
Ожидание, считавшее элементы вместе с null, принимало письмо посева за пришедшее
письмо восстановления: код — пустой, завершение восстановления — 400 «code:
required», и каскад шагов за ним. Падение зависело от того, успело ли письмо
восстановления к первому опросу.

Держит проба: каждый шаг коллекции `kaname-access-keys`, читающий перечень
кодов, считает только непустые строки (та же форма, что у ожидания набора
восстановления), и ни один не считает перечень целиком. Пустой обход — отказ.
"""

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
COLLECTION = ROOT / "tests" / "newman" / "collections" / "kaname-access-keys.postman_collection.json"

READS_CODES = "__codes = pm.response.json().codes"
COUNTS_OWN_KIND = "__codes.filter(c => typeof c === 'string' && c.length > 0)"
COUNTS_EVERY_LETTER = "Array.isArray(__codes) ? __codes :"


def _test_scripts(node, out):
    if isinstance(node, dict):
        for ev in node.get("event", []) or []:
            if ev.get("listen") == "test":
                out.append((node.get("name", "?"), "\n".join((ev.get("script") or {}).get("exec", []) or [])))
        for child in node.get("item", []) or []:
            _test_scripts(child, out)
    return out


def letter_count_findings(scripts):
    """(читающих коды, [имена шагов, считающих письма чужого вида])."""
    readers = [(name, text) for name, text in scripts if READS_CODES in text]
    bad = [name for name, text in readers if COUNTS_EVERY_LETTER in text or COUNTS_OWN_KIND not in text]
    return len(readers), bad


def test_every_letter_await_counts_only_its_own_kind():
    scripts = _test_scripts(json.loads(COLLECTION.read_text(encoding="utf-8")), [])
    readers, bad = letter_count_findings(scripts)
    print(f"тестовых скриптов осмотрено: {len(scripts)}; читающих перечень кодов: {readers}; "
          f"считающих письма чужого вида: {len(bad)}")
    assert readers > 0, "ни один шаг не читает перечень кодов — обход пуст, вердикта нет"
    assert not bad, f"ожидание письма считает письма чужого вида (null двери кодов): {bad[:3]}"


def test_injection_raw_count_is_found_and_filtered_twin_is_silent():
    raw = ("s", f"let __codes = null; try {{ {READS_CODES}; }} catch (e) {{}}\n"
                f"const __all = {COUNTS_EVERY_LETTER} [];")
    own = ("t", f"let __codes = null; try {{ {READS_CODES}; }} catch (e) {{}}\n"
                f"const __all = Array.isArray(__codes) ? {COUNTS_OWN_KIND} : [];")
    assert letter_count_findings([raw]) == (1, ["s"]), "счёт всех писем не распознан"
    assert letter_count_findings([own]) == (1, []), "законная форма принята за счёт всех писем"


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ok   {name}")
            except AssertionError as e:
                failed += 1
                print(f"  ПРОВАЛ {name}: {e}")
    sys.exit(1 if failed else 0)
