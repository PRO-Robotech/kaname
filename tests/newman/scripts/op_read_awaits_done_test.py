# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Чтение операции, утверждающее её завершение, дожидается завершения (kaname#948).

ПРЕДМЕТ. Мутация отвечает конвертом Operation сразу, работа идёт асинхронно.
Шаг, который читает `/operations/{{X}}` ОДИН раз и утверждает `done === true`,
выносит вердикт о расписании воркера, а не о продукте: на CI kaname#881 кейс
IAM-USR-DL-FLOW-TENANT-LEAVES (KN664-50) прочёл удаление проекта с `done:false` и
покраснел двумя утверждениями, хотя операция завершилась бы успешно.

Законных форм у такого чтения ДВЕ, и проба знает обе:
  * шаг опрашивает сам — самоповтор `setNextRequest(pm.info.requestName)`;
  * ближайший предыдущий шаг той же папки — самоопрос ТОЙ ЖЕ переменной X.
Предыдущий опрос ДРУГОЙ переменной формой не является: `poll_operation_until_done`
опрашивает общий `opId`, и стоящий перед чтением именованной `op_var` опрос ждёт
чужую операцию — это ровно то место, где класс прятался.

Судятся СГЕНЕРИРОВАННЫЕ коллекции дерева: правка мимо генератора пробу не обходит.
Перепись печатается отдельно от находок, и ноль прочитанных читателей — красное.
Исполняет `.github/scripts/run-python-probes.py` (обход по образцу `*_test.py`).
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gen  # noqa: E402

COLLECTIONS = Path(__file__).resolve().parents[1] / "collections"

_OP_PATH = re.compile(r"/operations/\{\{([A-Za-z0-9_]+)\}\}")
_DONE_ASSERT = re.compile(r"j\.done\b[^;]*\.to\.eql\(true\)")
_SELF_POLL = "setNextRequest(pm.info.requestName)"


def _url(item):
    u = (item.get("request") or {}).get("url")
    return (u.get("raw") or "") if isinstance(u, dict) else (u or "")


def _code(item, listen):
    out = []
    for ev in item.get("event") or []:
        if ev.get("listen") == listen:
            ex = (ev.get("script") or {}).get("exec") or []
            out.append("\n".join(ex) if isinstance(ex, list) else str(ex))
    return "\n".join(out)


def _leaves(node):
    for it in node.get("item") or []:
        if "item" in it:
            yield from _leaves(it)
        else:
            yield it


def audit(collections_dir: Path) -> dict:
    """Перепись и находки: одиночное чтение операции, утверждающее done, без опроса."""
    census = {"collections": 0, "folders": 0, "items": 0, "readers": 0,
              "self_polling": 0, "after_same_var_poll": 0}
    findings = []
    for path in sorted(collections_dir.glob("*.json")):
        col = json.loads(path.read_text())
        census["collections"] += 1
        for folder in col.get("item") or []:
            if "item" not in folder:
                continue
            census["folders"] += 1
            items = list(_leaves(folder))
            census["items"] += len(items)
            for i, it in enumerate(items):
                m = _OP_PATH.search(_url(it))
                method = ((it.get("request") or {}).get("method") or "GET").upper()
                test = _code(it, "test")
                if method != "GET" or not m or not _DONE_ASSERT.search(test):
                    continue
                census["readers"] += 1
                if _SELF_POLL in test:
                    census["self_polling"] += 1
                    continue
                prev = items[i - 1] if i > 0 else None
                pm_ = _OP_PATH.search(_url(prev)) if prev is not None else None
                if pm_ and pm_.group(1) == m.group(1) and _SELF_POLL in _code(prev, "test"):
                    census["after_same_var_poll"] += 1
                    continue
                findings.append(f"{path.name} :: {it.get('name')} — читает {m.group(1)} одним GET "
                                f"и утверждает done; опроса той же операции перед ним нет")
    return {"census": census, "findings": findings}


def _poll_item(name, var):
    return {"name": name, "request": {"method": "GET", "url": {"raw": "{{baseUrl}}/operations/{{" + var + "}}"}},
            "event": [{"listen": "test", "script": {"exec": [
                "const j = pm.response.json();",
                "if (!j.done) { const _d = Date.now(); while (Date.now() - _d < 500) void 0; "
                "pm.execution.setNextRequest(pm.info.requestName); return; }",
                "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));"]}}]}


def _single_read_item(name, var):
    return {"name": name, "request": {"method": "GET", "url": {"raw": "{{baseUrl}}/operations/{{" + var + "}}"}},
            "event": [{"listen": "test", "script": {"exec": [
                "const j = pm.response.json();",
                "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));"]}}]}


def _write(tmp_path, items):
    (tmp_path / "c.postman_collection.json").write_text(json.dumps(
        {"item": [{"name": "CASE", "item": items}]}))
    return tmp_path


# ── Держатель по дереву ────────────────────────────────────────────────────────

def test_every_operation_read_asserting_done_awaits_that_operation():
    res = audit(COLLECTIONS)
    c = res["census"]
    print(f"[op-read-awaits-done] осмотрено: коллекций {c['collections']}, папок {c['folders']}, "
          f"элементов {c['items']}; читателей операции с done {c['readers']} "
          f"(самоопрос {c['self_polling']}, после опроса той же операции {c['after_same_var_poll']}); "
          f"находок {len(res['findings'])}")
    assert c["collections"] > 0 and c["readers"] > 0, f"переписи нет — прочитано ноль: {c}"
    assert res["findings"] == [], "\n".join(res["findings"])


# ── Производитель: помощник успеха опрашивает сам ─────────────────────────────

def test_assert_op_success_polls_its_own_operation_until_done():
    step = gen.assert_op_success(op_var="kn948OpId")
    js = "\n".join(step.test_script)
    assert step.path == "/operations/{{kn948OpId}}", step.path
    loop, done = js.find(_SELF_POLL), js.find("pm.test('operation done'")
    assert loop != -1, "assert_op_success читает операцию одним GET — без самоповтора"
    assert done > loop, "утверждение done стоит раньше петли опроса"
    head = js[:loop].splitlines()[-4:]
    assert any("while (Date.now() - " in ln for ln in head), \
        "между опросами нет настоящей паузы (busy-wait перед setNextRequest)"
    assert f"pc < {gen.POLL_CAP}" in js, "петля опроса без предела POLL_CAP"


# ── Инъекция: дефект краснеет, законные близнецы молчат ───────────────────────

def test_injected_single_read_after_a_poll_of_another_variable_is_found(tmp_path):
    """Форма KN664-50: опрос общего opId, затем одиночное чтение именованной op_var."""
    res = audit(_write(tmp_path, [_poll_item("CASE :: poll-op", "opId"),
                                  _single_read_item("CASE :: assert-op-success", "kn664LPrjOpId")]))
    assert len(res["findings"]) == 1, res
    assert "CASE :: assert-op-success" in res["findings"][0] and "kn664LPrjOpId" in res["findings"][0]


def test_injected_single_read_first_in_folder_is_found(tmp_path):
    res = audit(_write(tmp_path, [_single_read_item("CASE :: assert-op-success", "opId")]))
    assert len(res["findings"]) == 1, res


def test_lawful_twins_are_silent(tmp_path):
    res = audit(_write(tmp_path, [_poll_item("CASE :: poll-op", "opId"),
                                  _single_read_item("CASE :: assert-op-success", "opId"),
                                  _poll_item("CASE :: assert-op-success #2", "kn664LAccOpId")]))
    assert res["findings"] == [], res
    assert res["census"]["readers"] == 3
    assert res["census"]["self_polling"] == 2 and res["census"]["after_same_var_poll"] == 1


def test_empty_tree_is_not_a_silent_green(tmp_path):
    res = audit(tmp_path)
    assert res["census"]["collections"] == 0 and res["census"]["readers"] == 0
