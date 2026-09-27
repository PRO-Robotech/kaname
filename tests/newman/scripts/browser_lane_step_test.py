# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Шаг, который ведёт себя как БРАУЗЕР и как клиент OAuth, а не как клиент JSON API.

ПРЕДМЕТ. Церемония `authorization_code` (приёмка LINE-A-1) говорит на трёх
языках, которых у остального набора нет, и каждый из них генератор обязан уметь
выразить, иначе кейс утверждает не то, что написано в его заголовке:

  1. ПЕРЕНАПРАВЛЕНИЕ. Код приходит в `Location` ответа `302`. Прогонщик по
     умолчанию идёт по перенаправлению сам, и шаг видит ответ ЧУЖОГО адреса
     возврата вместо ответа точки авторизации: «302 с кодом» и «отказ без
     перенаправления» становятся неразличимы. Поле `follow_redirects=False`
     эмитится как `protocolProfileBehavior.followRedirects: false`;
  2. БАНКА ПЕЧЕНИЙ. Прогонщик хранит `Set-Cookie` и сам прикладывает его к
     следующему запросу на тот же хост — порт границей печенья не является.
     Тогда отрицание «сессии нет» получает сессию из банки и зеленеет на
     реализации, которая сессию не спрашивает. Поле `cookie_jar=False` эмитится
     как `protocolProfileBehavior.disableCookies: true`: печенье шаг несёт
     только явным заголовком;
  3. ФОРМА. Токен-эндпоинт принимает `application/x-www-form-urlencoded`
     (RFC 6749 §4.1.3), а генератор знал только JSON. Поле `form` — пары
     «имя, значение»; тело эмитится ТЕМ ЖЕ режимом `raw`, что и JSON, поэтому
     страж неразрешённой подстановки (он читает `pm.request.body.raw`) видит и
     его. Значение с подстановкой `{{имя}}` уходит как есть: кодировать его —
     дело пред-скрипта, который кладёт в переменную уже закодированное.

ЗАКОННЫЙ БЛИЗНЕЦ У КАЖДОГО ПОЛЯ. Шаг без поля эмитится БАЙТОВО как прежде —
иначе расширение перекрасило бы восемьдесят коллекций, не меняя ни одного
кейса, и гейт воспроизводимости поймал бы не дефект, а правку.

КТО ЭТУ ПРОБУ ИСПОЛНЯЕТ: `.github/scripts/run-python-probes.py` (обход дерева по
образцу `tests/newman/scripts/*_test.py`); файл годен и для прямого запуска —
ветка `__main__` исполняет каждую `test_*` и печатает число исполненных.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gen  # noqa: E402


def _item(**fields):
    step = gen.Step(name="s", method=fields.pop("method", "GET"),
                    path=fields.pop("path", "/iam/v1/authorize"), **fields)
    return gen._RUN.step_item(step)


def _content_types(item):
    return [h["value"] for h in item["request"]["header"] if h["key"].lower() == "content-type"]


# ── 1. перенаправление ─────────────────────────────────────────────────────

def test_redirect_is_not_followed_when_the_step_says_so():
    item = _item(follow_redirects=False)
    assert item.get("protocolProfileBehavior", {}).get("followRedirects") is False, item


def test_redirect_setting_is_absent_by_default():
    item = _item()
    assert "followRedirects" not in item.get("protocolProfileBehavior", {}), item


# ── 2. банка печений ───────────────────────────────────────────────────────

def test_cookie_jar_is_switched_off_when_the_step_says_so():
    item = _item(cookie_jar=False)
    assert item.get("protocolProfileBehavior", {}).get("disableCookies") is True, item


def test_cookie_jar_setting_is_absent_by_default():
    item = _item()
    assert "disableCookies" not in item.get("protocolProfileBehavior", {}), item


def test_three_behaviours_share_one_block_and_none_overwrites_another():
    item = _item(insecure_tls=True, follow_redirects=False, cookie_jar=False)
    ppb = item.get("protocolProfileBehavior", {})
    assert ppb == {"strictSSL": False, "followRedirects": False, "disableCookies": True}, ppb


def test_insecure_tls_alone_is_emitted_byte_as_before():
    item = _item(insecure_tls=True)
    assert item["protocolProfileBehavior"] == {"strictSSL": False}, item


# ── 3. форма ───────────────────────────────────────────────────────────────

def test_form_is_emitted_as_raw_urlencoded_with_its_content_type():
    item = _item(method="POST", path="/iam/v1/token",
                 form=[("grant_type", "authorization_code"), ("code", "{{_c}}")])
    body = item["request"].get("body")
    assert body == {"mode": "raw", "raw": "grant_type=authorization_code&code={{_c}}"}, body
    assert _content_types(item) == ["application/x-www-form-urlencoded"], item["request"]["header"]


def test_form_literal_value_is_percent_encoded_and_placeholder_is_left_intact():
    item = _item(method="POST", path="/iam/v1/token",
                 form=[("redirect_uri", "https://a.test/cb?x=1&y=2"), ("v", "{{_v}}")])
    raw = item["request"]["body"]["raw"]
    assert raw == "redirect_uri=https%3A%2F%2Fa.test%2Fcb%3Fx%3D1%26y%3D2&v={{_v}}", raw


def test_json_step_keeps_its_json_content_type():
    item = _item(method="POST", path="/iam/v1/auth/login", body={"a": 1})
    assert _content_types(item) == ["application/json"], item["request"]["header"]
    assert item["request"]["body"]["options"] == {"raw": {"language": "json"}}, item


def test_form_and_json_body_on_one_step_is_refused():
    try:
        _item(method="POST", path="/iam/v1/token", body={"a": 1}, form=[("b", "2")])
    except ValueError as exc:
        assert "form" in str(exc) and "body" in str(exc), exc
    else:
        raise AssertionError("шаг с двумя телами принят: одно из них молча перезаписало бы другое")


def test_unresolved_placeholder_guard_still_reads_the_form_body():
    """Страж подстановки видит тело формы — оно в том же режиме `raw`."""
    item = _item(method="POST", path="/iam/v1/token", form=[("code", "{{_neverSet}}")])
    pre = "\n".join(next(ev["script"]["exec"] for ev in item["event"] if ev["listen"] == "prerequest"))
    assert "pm.request.body.raw" in pre, pre
    assert item["request"]["body"]["mode"] == "raw"


def _main() -> int:
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 — каждое падение называется поимённо
            failed += 1
            print(f"FAIL {name}: {type(exc).__name__}: {exc}")
        else:
            print(f"ok   {name}")
    print(f"исполнено {len(tests)} · упало {failed}")
    if not tests:
        print("ОТКАЗ: ни одной пробы не собрано — обход пуст")
        return 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main())
