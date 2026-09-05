#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Доказательство стража класса «фантомный идентификатор» — ИНЪЕКЦИЕЙ, в обе стороны.

Страж (`gen.assert_phantom_drop`) запрещает опрос операции, который не снимает
предвыделенный идентификатор, когда операция закончилась ОШИБКОЙ. Запрет чего-то стоит
только если проверен с двух сторон:

  (a) верни дефект — страж КРАСНЕЕТ и НАЗЫВАЕТ КООРДИНАТУ;
  (b) поставь рядом ЗАКОННУЮ конструкцию той же формы — страж МОЛЧИТ.

Без (b) страж ловил бы форму, а не существо, и первый же ложный срабат его отключил бы.
Плюс две проверки о самом страже: он читает ИСПОЛНЯЕМУЮ часть (маркер в комментарии не
засчитывается) и он падает, когда его СОБСТВЕННАЯ предпосылка перестала быть верной.

Запуск: python3 scripts/phantom_gate_test.py
"""
import io
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gen  # noqa: E402

REGISTER = [
    "try {",
    "  const _pv = JSON.parse(pm.environment.get('_provisionalIds') || '[]');",
    "  if (_pv.indexOf('crudThingId') === -1) _pv.push('crudThingId');",
    "  pm.environment.set('_provisionalIds', JSON.stringify(_pv));",
    "} catch (e) {}",
]

POLLER_BLIND = [
    "const j = pm.response.json();",
    "if (!j.done) { pm.execution.setNextRequest(pm.info.requestName); return; }",
    "pm.test('operation done', () => pm.expect(j.done).to.eql(true));",
]

# ЗАКОННАЯ конструкция той же формы: поллер снимает фантом САМ, адресно, без общего
# реестра. Это второй санкционированный способ — страж обязан на нём молчать.
POLLER_OWN_DROP = POLLER_BLIND + [
    "if (j.error) { pm.environment.unset('crudThingId'); }",
]

# Маркер есть, но только в КОММЕНТАРИИ, объясняющем защиту. Защиты нет.
POLLER_COMMENT_ONLY = POLLER_BLIND + [
    "// на ошибке следовало бы сделать pm.environment.unset('_provisionalIds')",
    "/* _provisionalIds unset */",
]


def _collection(poller_script, register=True, collection_level=None):
    steps = [{
        "name": "CASE-X :: create",
        "request": {"method": "POST", "url": {"raw": "{{baseUrl}}/iam/v1/things"}},
        "event": [{"listen": "test", "script": {"type": "text/javascript",
                                                "exec": (REGISTER if register else ["// no capture"])}}],
    }, {
        "name": "CASE-X :: poll-op",
        "request": {"method": "GET", "url": {"raw": "{{baseUrl}}/operations/{{opId}}"}},
        "event": [{"listen": "test", "script": {"type": "text/javascript", "exec": poller_script}}],
    }]
    col = {
        "info": {"name": "probe"},
        "event": [],
        "item": [{"name": "CASE-X — probe", "item": steps}],
    }
    if collection_level:
        col["event"].append({"listen": "test",
                             "script": {"type": "text/javascript", "exec": collection_level}})
    return col


def _run(col):
    with tempfile.TemporaryDirectory() as d:
        Path(d, "probe.postman_collection.json").write_text(json.dumps(col))
        buf = io.StringIO()
        rc = gen.assert_phantom_drop(Path(d), out=buf)
        return rc, buf.getvalue()


FAILURES = []


def check(name, cond, detail=""):
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}  {detail}")
        FAILURES.append(name)


def main():
    print("(a) дефект возвращён — страж обязан покраснеть и назвать координату")
    rc, out = _run(_collection(POLLER_BLIND))
    check("краснеет", rc == 1, out)
    check("называет координату", "CASE-X :: poll-op" in out, out)

    print("(b) законная конструкция той же формы — страж обязан молчать")
    rc, out = _run(_collection(POLLER_OWN_DROP))
    check("молчит на адресном снятии", rc == 0, out)
    rc, out = _run(_collection(POLLER_BLIND, collection_level=gen.POST_GLOBAL))
    check("молчит на снятии уровня коллекции", rc == 0, out)
    check("перепись растёт, а не обнуляется", "папок 1" in out, out)

    print("(c) страж читает исполняемую часть, а не текст")
    rc, out = _run(_collection(POLLER_COMMENT_ONLY))
    check("маркер в комментарии не засчитывается", rc == 1, out)

    print("(d) страж проверяет СВОЮ предпосылку")
    rc, out = _run(_collection(POLLER_BLIND, register=False))
    check("нет регистрации — предпосылка ложна, отказ", rc == 1, out)
    check("говорит про предпосылку", "ПРЕДПОСЫЛКА" in out, out)
    with tempfile.TemporaryDirectory() as d:
        buf = io.StringIO()
        rc = gen.assert_phantom_drop(Path(d), out=buf)
    check("пустое дерево — ноль находок не выдаётся за чистоту", rc == 1, buf.getvalue())

    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} — {', '.join(FAILURES)}")
        return 1
    print("phantom_gate_test: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
