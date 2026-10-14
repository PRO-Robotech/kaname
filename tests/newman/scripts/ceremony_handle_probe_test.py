# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Проба способности упасть: утверждения о рукоятке церемонии в наборе
`kaname-access-keys` различают решение Р3 и отвергнутый им исход.

ПРЕДМЕТ — утверждения Ф13-33 (I) (приёмка `passwordless-login-with-access-key.md`):
рукоятка `user.id` испытания регистрации — 64 байта, не нули, не несёт ни `id`,
ни адреса человека; две церемонии одного человека дают одну рукоятку; у двух
людей — разные. Прежнее утверждение набора ждало байты платформенного `id` —
ровно отвергнутый исход Р3 — и сменилось вместе с производителем (kaname#351).

КАК. Строки скрипта берутся у ТЕХ ЖЕ помощников, что порождают коллекцию
(загрузчик генератора, а не копия), и исполняются НАСТОЯЩИМ движком JS (node)
в подставной песочнице: `pm.test` записывает исход каждого утверждения по
имени, `pm.expect(...).to.eql` сравнивает глубоко. Каждая инъекция меняет ОДИН
факт против законного близнеца, и от неё краснеет ровно названное утверждение;
близнец — ноль отказов. Вход отвергнутого исхода Р3 стоит среди инъекций
дословно: рукоятка = байты платформенного `id`.

Провязка — отдельной пробой: шаги `ak40-begin`, `ak40-begin-again` и
`ak05b-begin` в декларации несут эти строки; иначе зелёное здесь ничего не
говорило бы о коллекции.
"""

import base64
import importlib.util
import json
import os
import pathlib
import subprocess
import sys

import pytest

SUITE = pathlib.Path(__file__).resolve().parents[1]
CASES = SUITE / "cases" / "kaname-access-keys.py"

ID_A = "usr5xr9fmn9rhzv07q21"
EMAIL_A = "ak-a-run1@example.test"
ID_B = "usrb0000000000000002"
EMAIL_B = "ak-b-run1@example.test"


def _declaration():
    name = "kaname_access_keys_gen_for_handle_probe"
    path = SUITE / "scripts" / "gen.py"
    spec = importlib.util.spec_from_file_location(name, path)
    gen = importlib.util.module_from_spec(spec)
    sys.modules[name] = gen
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(gen)
    finally:
        sys.path.pop(0)
    return gen._RUN.load(CASES)


M = _declaration()

_DRIVER = r"""
const inp = JSON.parse(require('fs').readFileSync(process.argv[1], 'utf8'));
const env = Object.assign({}, inp.env);
const results = {};
const eql = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const pm = {
  environment: { get: (k) => env[k], set: (k, v) => { env[k] = v; }, unset: (k) => { delete env[k]; } },
  expect: (v) => ({ to: { eql: (w) => { if (!eql(v, w)) { throw new Error('expected ' + JSON.stringify(v) + ' to eql ' + JSON.stringify(w)); } } } }),
  test: (name, fn) => { try { fn(); results[name] = 'pass'; } catch (e) { results[name] = 'fail'; } },
};
const __j = inp.body;
new Function('pm', '__j', inp.script)(pm, __j);
process.stdout.write(JSON.stringify({ results: results, env: env }));
"""


def _run(lines, body, env, tmp_path):
    payload = tmp_path / "in.json"
    payload.write_text(json.dumps({"script": "\n".join(lines), "body": body, "env": env}), encoding="utf-8")
    try:
        proc = subprocess.run(["node", "-e", _DRIVER, str(payload)], capture_output=True, text=True, timeout=60)
    except FileNotFoundError:  # pragma: no cover — окружение без node
        raise AssertionError("node не найден: исполнить порождаемый JavaScript нечем — это «ноль "
                             "исполненного», а не «ноль отказов», поэтому проба ПАДАЕТ") from None
    assert proc.returncode == 0, proc.stderr[:600]
    out = json.loads(proc.stdout)
    assert out["results"], "ни одного утверждения не исполнено — вердикта нет"
    return out


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


TWIN = bytes(range(1, 65))  # 64 байта, без `id` и адреса, не нули
assert len(TWIN) == 64


def _with(raw: bytes, needle: str, at: int = 10) -> bytes:
    n = needle.encode()
    return raw[:at] + n + raw[at + len(n):]


ENV_A = {"akAUserId": ID_A, "akAEmail": EMAIL_A}
L64 = "X: рукоятка человека — 64 байта в канонической записи, не нули"
LNAME = "X: рукоятка не несёт ни id, ни адреса человека"

# (что внесено, user.id, окружение, утверждения, которые обязаны покраснеть).
# Отвергнутый исход Р3 краснит ОБА утверждения, и это не два внесённых факта, а
# два следствия одного: байты `id` и короче нормы, и несут `id`.
INJECTIONS = [
    ("рукоятка = байты платформенного id (отвергнутый исход Р3)", _b64(ID_A.encode()), ENV_A, sorted([L64, LNAME])),
    ("в 64 байтах стоит id человека", _b64(_with(TWIN, ID_A)), ENV_A, [LNAME]),
    ("в 64 байтах стоит адрес человека другим регистром", _b64(_with(TWIN, EMAIL_A.upper())), ENV_A, [LNAME]),
    ("рукоятка из нулей", _b64(bytes(64)), ENV_A, [L64]),
    ("63 байта", _b64(TWIN[:63]), ENV_A, [L64]),
    ("запись не каноническая (base64url без дополнения)", _b64(TWIN).replace("+", "-").replace("/", "_").rstrip("="),
     ENV_A, [L64]),
    ("id человека набору не известен — «не несёт» на пустом образце", _b64(TWIN), {"akAEmail": EMAIL_A}, [LNAME]),
]


def test_lawful_twin_is_silent(tmp_path):
    out = _run(M._handle_is_its_own("X", "akA"), {"user": {"id": _b64(TWIN)}}, ENV_A, tmp_path)
    assert out["results"] == {L64: "pass", LNAME: "pass"}, out


@pytest.mark.parametrize("label,uid,env,red", INJECTIONS, ids=[i[0] for i in INJECTIONS])
def test_injection_reddens_exactly_its_assertion(label, uid, env, red, tmp_path):
    out = _run(M._handle_is_its_own("X", "akA"), {"user": {"id": uid}}, env, tmp_path)
    fails = sorted(k for k, v in out["results"].items() if v == "fail")
    assert fails == red, (label, out)


def test_same_handle_twice_passes_and_another_fails(tmp_path):
    lines = M._handle_same_as("X", "akA", "akAHandle")
    name = "X: две церемонии одного человека — одна рукоятка"
    same = _run(lines, {"user": {"id": _b64(TWIN)}}, {"akAHandle": _b64(TWIN)}, tmp_path)
    other = _run(lines, {"user": {"id": _b64(TWIN[::-1])}}, {"akAHandle": _b64(TWIN)}, tmp_path)
    unset = _run(lines, {"user": {"id": _b64(TWIN)}}, {}, tmp_path)
    assert [same["results"][name], other["results"][name], unset["results"][name]] == ["pass", "fail", "fail"]


def test_two_people_have_different_handles(tmp_path):
    lines = M._handle_differs_from("X", "akB", "akAHandle")
    name = "X: у двух разных людей рукоятки разные"
    env = {"akBUserId": ID_B, "akBEmail": EMAIL_B, "akAHandle": _b64(TWIN)}
    own = _run(lines, {"user": {"id": _b64(TWIN[::-1])}}, env, tmp_path)
    shared = _run(lines, {"user": {"id": _b64(TWIN)}}, env, tmp_path)
    assert [own["results"][name], shared["results"][name]] == ["pass", "fail"]
    assert all(v == "pass" for v in own["results"].values()), own


def test_first_ceremony_records_the_handle_only_when_well_formed(tmp_path):
    """`ak40-begin` записывает рукоятку A, и только годной формы: иначе вторая
    церемония сравнивала бы с мусором и «одна рукоятка» зеленела бы на нём."""
    steps = {s.name: s for c in M.CASES for s in c.steps}
    script = steps["ak40-begin"].test_script
    tail = [ln for ln in script if "akAHandle" in ln or "_akHandleFacts" in ln or "_akHf" in ln]
    good = _run(tail, {"user": {"id": _b64(TWIN)}}, ENV_A, tmp_path)
    bad = _run(tail, {"user": {"id": _b64(ID_A.encode())}}, dict(ENV_A, akAHandle="stale"), tmp_path)
    assert good["env"].get("akAHandle") == _b64(TWIN), good
    assert "akAHandle" not in bad["env"], bad


def test_steps_carry_the_handle_assertions():
    steps = {s.name: s for c in M.CASES for s in c.steps}
    want = {
        "ak40-begin": M._handle_is_its_own("AK40-BEGIN", "akA"),
        "ak40-begin-again": M._handle_same_as("AK40-BEGIN-AGAIN", "akA", "akAHandle"),
        "ak05b-begin": M._handle_differs_from("AK05B-BEGIN", "akB", "akAHandle"),
    }
    for name, lines in want.items():
        assert name in steps, f"шага {name} в декларации нет"
        script = steps[name].test_script
        missing = [ln for ln in lines if ln not in script]
        assert not missing, (name, missing)
    order = [s.name for c in M.CASES for s in c.steps]
    assert order.index("ak40-begin") < order.index("ak40-begin-again") < order.index("ak05b-begin")
    legacy = [s.name for c in M.CASES for s in c.steps
              if any("платформенный id байтами" in ln for ln in s.test_script)]
    assert legacy == [], legacy


if __name__ == "__main__":  # pragma: no cover
    sys.exit(pytest.main([os.path.abspath(__file__), "-q"]))
