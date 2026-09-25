#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Держатель класса «повтор окна прав стоит там, где окна нет» — перепись и инъекция.

ПРЕДМЕТ (kaname#393). Ограниченный повтор `retry_until_authorized` пережидает ОДНО
окно — материализацию прав владельца на свой свежий ресурс — и потому законен в
одном месте: на первом обращении к такому ресурсу с ожидаемым успехом. Шапка самой
обёртки это говорит («Do NOT wrap negative / cross-account-deny / absent-id
steps»), и правило наборов тоже (`ryw-retry-never-on-negatives`,
`retry-only-first-fresh-read`). Отрицательный шаг под повтором уходит до
шестнадцати раз, и его отказ читается не сразу, а на исчерпании бюджета.

ЗАМЕР ДО ПРАВКИ (ревизия `d22123ba`, порождённые коллекции дерева): шагов 2259,
обёрнутых 442, обёрнутых без единого `2xx` в объявленном исходе — 33 в 12
коллекциях из 47; из них 29 обернул предикат генератора, 4 — вызов в кейсе.

ВТОРАЯ ОСЬ — ПОВЕРХНОСТЬ БЕЗ ОКНА. Слушатель формы (`loginLaneBaseUrl`) стоит не
за шлюзом прав: у его шагов свежие переменные — признак формы и печенье, и окна,
которое пережидает обёртка, там нет вовсе. Замер до правки: обёрнуто 25 шагов
этой поверхности из 58.

ЧТО СУДИТСЯ — ИСХОД, А НЕ ПРОВЯЗКА. Перепись читает ПОРОЖДЁННЫЕ коллекции: шаг
обёрнут, если его скрипт проверки несёт счётчик повтора `_authRetryCount`; его
объявленный исход — `_accepted_http_codes` общего слоя (второй разборщик того же
предмета разошёлся бы с генератором молча); поверхность — метка
`require_env_url` в пред-скрипте шага.

ПРЕДПОСЫЛКА (0): множество поверхностей без окна объявляет генератор
(`NO_AUTHZ_WINDOW_SURFACES`); нет его там — отказ, своей копии здесь нет.

ИНЪЕКЦИЯ В ОБЕ СТОРОНЫ И НА ДВУХ УРОВНЯХ:
  (а) перепись: обёрнутое отрицание — находка с именем шага; обёрнутое
      положительное первое обращение — молчание; обёрнутый шаг поверхности без
      окна — находка; тот же шаг на собственном фронте — молчание; пустой обход —
      отказ, а не «ноль находок»;
  (б) генератор: отрицание на свежей переменной НЕ оборачивается, положительное
      первое обращение оборачивается, шаг слушателя формы не оборачивается;
      явная просьба обернуть отрицание в кейсе — отказ генерации с именем шага.

ИСХОДЫ: 0 — находок нет и обход непуст; 1 — находка либо пустой обход.

КТО ИСПОЛНЯЕТ: `.github/scripts/run-python-probes.py` — обходом по образцу
`tests/newman/scripts/*_test.py`, по имени файл не называет никто.
"""
from __future__ import annotations

import json
import re
import sys
import tempfile
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gen  # noqa: E402

COLLECTIONS = Path(__file__).resolve().parents[1] / "collections"

# Метка поверхности — та, что ставит `require_env_url` первой строкой своего блока.
_SURFACE_RE = re.compile(r"^// HARNESS-CONFIG GUARD — ([A-Za-z_][A-Za-z0-9_]*) is injected")
# Поверхности, у которых окна материализации прав нет: берутся у генератора, а не
# выписываются здесь второй раз. Нет множества у генератора — пусто, и проверка
# предпосылки в `main` отказывает, а своей копии перепись не подставляет.
def _no_window_surfaces(mod) -> frozenset:
    return getattr(mod, "NO_AUTHZ_WINDOW_SURFACES", frozenset())


NO_WINDOW = _no_window_surfaces(gen)


def _items(node):
    for it in node.get("item", []):
        if "request" in it:
            yield it
        else:
            yield from _items(it)


def _script(item, listen: str) -> list[str]:
    out: list[str] = []
    for ev in item.get("event", []):
        if ev.get("listen") == listen:
            out += ev.get("script", {}).get("exec", [])
    return out


def _surface(pre: list[str]) -> str | None:
    for line in pre:
        m = _SURFACE_RE.match(line)
        if m:
            return m.group(1)
    return None


def census(collections: Path) -> tuple[dict, list[str]]:
    """(перепись, находки) по порождённым коллекциям каталога."""
    n = {"коллекций": 0, "шагов": 0, "обёрнутых": 0,
         "обёрнутых отрицаний": 0, "обёрнутых без окна": 0}
    found: list[str] = []
    for f in sorted(collections.glob("*.postman_collection.json")):
        n["коллекций"] += 1
        stem = f.name[: -len(".postman_collection.json")]
        for it in _items(json.loads(f.read_text(encoding="utf-8"))):
            n["шагов"] += 1
            test = "\n".join(_script(it, "test"))
            if "_authRetryCount" not in test:
                continue
            n["обёрнутых"] += 1
            acc = gen._accepted_http_codes(test)
            if acc and not any(200 <= c < 300 for c in acc):
                n["обёрнутых отрицаний"] += 1
                found.append(f"{stem} :: {it['name']} — обёрнут повтором окна прав, а "
                             f"объявленный исход {sorted(acc)} без единого 2xx")
            surface = _surface(_script(it, "prerequest"))
            if surface in NO_WINDOW:
                n["обёрнутых без окна"] += 1
                found.append(f"{stem} :: {it['name']} — обёрнут повтором окна прав на "
                             f"поверхности {surface}, у которой окна нет")
    return n, found


def run_census(collections: Path, out=sys.stdout) -> int:
    n, found = census(collections)
    print("перепись: " + " · ".join(f"{k} {v}" for k, v in n.items()), file=out)
    if not n["коллекций"] or not n["шагов"]:
        print(f"ОТКАЗ: обход пуст ({collections}) — «ноль находок» здесь значило бы "
              f"«ноль прочитанного»", file=out)
        return 1
    if found:
        print(f"НАХОДКА: {len(found)} шаг(ов) под повтором окна прав там, где окна нет "
              f"либо шаг ждёт отказа:", file=out)
        for x in found:
            print(f"  · {x}", file=out)
        return 1
    print("ЧИСТО: повтор окна прав стоит только на шагах с ожидаемым успехом и только "
          "на поверхностях с окном", file=out)
    return 0


# ─────────────────────────── инъекция ─────────────────────────────────────

FAILURES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if cond else 'FAIL'} {name}" + ("" if cond else f"  {detail}"))
    if not cond:
        FAILURES.append(name)


def _item(name: str, test: list[str], pre: list[str] | None = None) -> dict:
    return {"name": name,
            "request": {"method": "GET", "url": {"raw": "{{baseUrl}}/iam/v1/things/{{thingId}}"}},
            "event": [{"listen": "prerequest", "script": {"exec": pre or []}},
                      {"listen": "test", "script": {"exec": test}}]}


_WRAPPED = ["if (pm.environment.get('_authRetryStarted') !== pm.info.requestName) {",
            "  pm.environment.set('_authRetryCount', '0');", "}"]


def _census_of(*items) -> tuple[int, str]:
    import io
    with tempfile.TemporaryDirectory() as d:
        Path(d, "probe.postman_collection.json").write_text(
            json.dumps({"info": {"name": "probe"}, "item": [{"name": "CASE-X", "item": list(items)}]}),
            encoding="utf-8")
        buf = io.StringIO()
        rc = run_census(Path(d), out=buf)
        return rc, buf.getvalue()


def _step(name: str, status: int, pre: list[str] | None = None, path: str = "/iam/v1/things/{{thingId}}"):
    return gen.Step(name=name, method="GET", path=path, pre_script=list(pre or []),
                    test_script=list(gen.assert_status(status)))


def _seed():
    return gen.Step(name="create", method="POST", path="/iam/v1/things",
                    test_script=[*gen.assert_status(200),
                                 "pm.environment.set('thingId', pm.response.json().id);"])


def _wrapped(step) -> bool:
    return "_authRetryCount" in "\n".join(step.test_script)


def main() -> int:
    print("(0) предпосылка: поверхности без окна объявляет генератор")
    check("генератор объявляет поверхности без окна (`NO_AUTHZ_WINDOW_SURFACES`)", bool(NO_WINDOW),
          "в gen.py множества нет — ось поверхности у переписи слепа")
    check("ИНЪЕКЦИЯ: у модуля без множества перепись не берёт своей копии",
          _no_window_surfaces(types.SimpleNamespace()) == frozenset(),
          f"взято {sorted(_no_window_surfaces(types.SimpleNamespace()))} — копия вместо генератора")

    print("(а) перепись: обе стороны каждой оси")
    rc, out = _census_of(_item("CASE-X :: neg", [*_WRAPPED, "pm.response.to.have.status(404);",
                                                 "pm.test('s', () => pm.expect(pm.response.code).to.eql(404));"]))
    check("обёрнутое отрицание — находка", rc == 1 and "CASE-X :: neg" in out, out)
    rc, out = _census_of(_item("CASE-X :: pos", [*_WRAPPED,
                                                 "pm.test('s', () => pm.expect(pm.response.code).to.eql(200));"]))
    check("ЗАКОННЫЙ БЛИЗНЕЦ: обёрнутое положительное первое обращение — молчание", rc == 0, out)
    lane = gen.require_env_url("loginLaneBaseUrl", "/iam/v1/auth/logout", "проба")
    own = gen.require_env_url("ownRestBaseUrl", "/iam/v1/auth/logout", "проба")
    ok200 = [*_WRAPPED, "pm.test('s', () => pm.expect(pm.response.code).to.eql(200));"]
    rc, out = _census_of(_item("CASE-X :: lane", ok200, lane))
    check("обёрнутый шаг поверхности без окна — находка", rc == 1 and "loginLaneBaseUrl" in out, out)
    rc, out = _census_of(_item("CASE-X :: own", ok200, own))
    check("ЗАКОННЫЙ БЛИЗНЕЦ: тот же шаг на собственном фронте — молчание", rc == 0, out)
    with tempfile.TemporaryDirectory() as d:
        import io
        buf = io.StringIO()
        check("пустой обход — отказ, а не «ноль находок»", run_census(Path(d), out=buf) == 1,
              buf.getvalue())

    print("(б) генератор: решение об обёртке")
    auto = getattr(gen, "_auto_rya", None)
    check("у набора есть адаптер предиката (`_auto_rya`)", callable(auto), "адаптера нет")
    if callable(auto):
        neg = gen._wrap_own_fresh_reads([_seed(), _step("neg", 400)], auto, rename=False)[1]
        check("отрицание на свежей переменной НЕ оборачивается", not _wrapped(neg))
        pos = gen._wrap_own_fresh_reads([_seed(), _step("pos", 200)], auto, rename=False)[1]
        check("ЗАКОННЫЙ БЛИЗНЕЦ: положительное первое обращение оборачивается", _wrapped(pos))
        on_lane = gen._wrap_own_fresh_reads(
            [_seed(), _step("lane", 200, pre=lane)], auto, rename=False)[1]
        check("шаг слушателя формы не оборачивается", not _wrapped(on_lane))
    explicit = getattr(gen, "_rya", None)
    try:
        explicit(_step("neg-explicit", 400))
        refused, why = False, ""
    except ValueError as e:
        refused, why = True, str(e)
    check("явная просьба обернуть отрицание — отказ генерации с именем шага",
          refused and "neg-explicit" in why, why or "обёрнуто молча")
    try:
        w = explicit(_step("pos-explicit", 200))
        check("ЗАКОННЫЙ БЛИЗНЕЦ: явная обёртка положительного шага ставится", _wrapped(w))
    except ValueError as e:
        check("ЗАКОННЫЙ БЛИЗНЕЦ: явная обёртка положительного шага ставится", False, str(e))

    print("(в) порождённые коллекции дерева")
    rc = run_census(COLLECTIONS)
    check("в дереве нет повтора окна прав на отрицании и на поверхности без окна", rc == 0)

    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} — {', '.join(FAILURES)}")
        return 1
    print("fresh_read_wrap_test: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
