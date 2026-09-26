# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Проба гейта `second_factor_assertion_values_test.py`: краснеет на дефекте и
молчит на законном близнеце (kaname#417).

Каждая пара одно-фактна: инъекция и близнец — один и тот же шаг, и отличаются
они ОДНОЙ строкой скрипта. Инъекция обязана дать находку, называющую ту роль
значения, в которой оно ушло в утверждение (предмет, сообщение, ожидаемое, имя
утверждения, текст исключения, журнал), и вид удостоверения; близнец — ноль
находок. Без близнеца «краснеет» неотличимо от «краснеет всегда».

Гейт импортируется ПО ИМЕНИ: переименование его файла роняет эту пробу, а не
проходит мимо неё.
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import second_factor_assertion_values_test as gate  # noqa: E402


def _doc(*lines, listen="test", body=None):
    req = {"method": "POST", "url": {"raw": "{{loginLaneBaseUrl}}/iam/v1/auth/login"}}
    if body is not None:
        req["body"] = {"mode": "raw", "raw": body}
    return {"item": [{"name": "SF-PROBE :: step", "request": req,
                      "event": [{"listen": listen, "script": {"exec": list(lines)}}]}]}


def _findings(*lines, **kw):
    census, findings = gate.audit(_doc(*lines, **kw))
    assert census["мест вызова"] >= 1, census
    return findings


# (что внесено, строка инъекции, строка близнеца, роль в находке, вид в находке)
PAIRS = [
    ("тело ответа в сообщении",
     "pm.test('x', () => pm.expect(pm.response.code, JSON.stringify(pm.response.json())).to.eql(200));",
     "pm.test('x', () => pm.expect(pm.response.code, 'код ответа').to.eql(200));",
     "сообщение", "запасной код"),
    ("секрет предметом",
     "pm.test('x', () => pm.expect(pm.response.json().secret).to.match(/^[A-Z2-7]{32}$/));",
     "pm.test('x', () => pm.expect(/^[A-Z2-7]{32}$/.test(pm.response.json().secret), 'форма секрета').to.eql(true));",
     "предмет", "секрет кода по времени"),
    ("пароль ожидаемым",
     "pm.test('x', () => pm.expect(true, 'x').to.eql(pm.environment.get('loginLanePassword')));",
     "pm.test('x', () => pm.expect(pm.environment.get('loginLanePassword') === 'y', 'x').to.eql(false));",
     "ожидаемое", "пароль"),
    ("заголовки ответа в сообщении",
     "pm.test('x', () => pm.expect(1, JSON.stringify(pm.response.headers.all())).to.eql(1));",
     "pm.test('x', () => pm.expect(pm.response.headers.all().filter(h => h.key === 'Set-Cookie').length, 'печений').to.eql(2));",
     "сообщение", "печенье сессии"),
    ("запасной код в имени утверждения",
     "pm.test('code ' + pm.response.json().backupCodes[0], () => pm.expect(1, 'x').to.eql(1));",
     "pm.test('code first', () => pm.expect(1, 'x').to.eql(1));",
     "имя утверждения", "запасной код"),
    ("признак формы в тексте fail",
     "pm.test('x', () => pm.expect.fail('got ' + pm.response.json().csrfToken));",
     "pm.test('x', () => pm.expect.fail('got no token'));",
     "сообщение", "признак формы"),
    ("секрет в тексте исключения внутри утверждения",
     "pm.test('x', () => { throw new Error(pm.response.json().secret); });",
     "pm.test('x', () => { throw new Error('boom'); });",
     "текст исключения", "секрет кода по времени"),
    ("запасные коды в журнал",
     "pm.test('x', () => pm.expect(1, 'x').to.eql(1)); console.log(pm.response.json().backupCodes);",
     "pm.test('x', () => pm.expect(1, 'x').to.eql(1)); console.log('ok');",
     "журнал", "запасной код"),
]


@pytest.mark.parametrize("label,inj,twin,role,kind", PAIRS, ids=[p[0] for p in PAIRS])
def test_value_in_assertion_is_found_and_twin_is_silent(label, inj, twin, role, kind):
    found = _findings(inj)
    hits = [f for f in found if f" · {role}: " in f and kind in f]
    assert hits, f"{label}: инъекция не найдена в роли {role!r} видом {kind!r}: {found}"
    assert _findings(twin) == [], f"{label}: близнец дал находки: {_findings(twin)}"


def test_finding_names_the_kind_not_the_value():
    found = _findings("pm.test('x', () => pm.expect(pm.response.json().secret).to.eql(''));")
    text = "\n".join(found)
    assert found and gate.SECRET not in text, "находка печатает значение, а не вид"


def test_env_value_under_a_name_the_redactor_does_not_know_is_found():
    # Значение — запасной код: формы у него нет, и срез режет его только по имени.
    # Секрет кода по времени сюда не годится — его срез узнаёт и видом, и
    # инъекция с ним была бы законной (замер на этой правке: находок 0).
    inj = _findings("pm.test('x', () => pm.expect(1, 'x').to.eql(1));",
                    "pm.environment.set('sfStash', pm.response.json().backupCodes[0]);")
    assert any("'sfStash'" in f and "запасной код" in f for f in inj), inj
    twin = _findings("pm.test('x', () => pm.expect(1, 'x').to.eql(1));",
                     "pm.environment.set('sfStashSecret', pm.response.json().backupCodes[0]);")
    assert twin == [], twin


def test_site_that_never_runs_is_found():
    inj = _findings("if (pm.response.code === 999) { pm.test('never', () => pm.expect(1, 'x').to.eql(1)); }",
                    "pm.test('always', () => pm.expect(1, 'x').to.eql(1));")
    assert any("не исполнилось ни в одном мире" in f for f in inj), inj
    twin = _findings("if (pm.response.code === 200) { pm.test('once', () => pm.expect(1, 'x').to.eql(1)); }",
                     "pm.test('always', () => pm.expect(1, 'x').to.eql(1));")
    assert twin == [], twin


def test_unknown_member_of_the_fake_throws_and_is_found():
    inj = _findings("pm.test('x', () => pm.expect(1, 'x').to.eql(1));", "pm.response.notAMember;")
    assert any("скрипт упал вне утверждения" in f for f in inj), inj
    twin = _findings("pm.test('x', () => pm.expect(1, 'x').to.eql(1));", "pm.response.code;")
    assert twin == [], twin


def test_prerequest_scripts_are_judged_too():
    inj = _findings("pm.test('pre', () => pm.expect(pm.environment.get('loginLanePassword'), 'x').to.be.a('string'));",
                    listen="prerequest")
    assert any(" · prerequest " in f and "пароль" in f for f in inj), inj


def test_empty_walk_is_not_a_verdict():
    with pytest.raises(gate.VerdictHasNoSubject):
        gate.audit({"item": []})
    with pytest.raises(gate.VerdictHasNoSubject):
        gate.audit(_doc("const a = 1;"))
