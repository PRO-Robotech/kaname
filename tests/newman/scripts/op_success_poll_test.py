# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""`assert_op_success` опрашивает операцию ДО ЗАВЕРШЕНИЯ, а не читает её один раз.

ПРЕДМЕТ. Мутация возвращает `Operation`, и воркер доводит её асинхронно. Шаг,
читающий операцию ОДНИМ запросом сразу после мутации, судит не исход операции, а
то, успел ли воркер раньше запроса: на kaname#624 (задание 112371853207, кейс
IAM-ACC-ID-23, шаг `assert-op-success #2`) операция правки меток была прочитана с
`"done":false` — и оба утверждения упали, хотя следующий шаг того же кейса
(`r-keeps-its-name`) увидел метки применёнными. Соседний помощник
`assert_op_error` эту гонку уже снял опросом; этот — нет.

КАК ПРОВЕРЯЕТСЯ. Тест-скрипт порождённого шага исполняется НАСТОЯЩИМ движком
(node) как тело функции — так его исполняет postman — против подставного `pm`,
который отвечает заданной последовательностью конвертов операции и перезапускает
шаг ровно тогда, когда скрипт сам просит `setNextRequest` на своё имя; на
каждом вызове, как и newman, перед тест-скриптом исполняется предзапрос шага
(в нём сброс счётчика опроса по имени шага). Часы
подставные: занятое ожидание между опросами не стоит прогону реального времени.

Утверждения — об ИСХОДЕ, в обе стороны:
  * незавершённая операция, затем завершённая успехом → зелёное, и ни одного
    утверждения на промежуточном конверте;
  * завершённая ОШИБКОЙ → красное `operation succeeded` (опрос не проглатывает
    отказ);
  * не завершилась за бюджет → красное `operation done` после ровно `POLL_CAP`
    перезапусков (опрос конечен).
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gen  # noqa: E402

_DRIVER = r"""
const fs = require('fs');
const body = fs.readFileSync(process.argv[1], 'utf8');
const plan = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const preBody = fs.readFileSync(process.argv[3], 'utf8');
const fn = new Function('pm', 'Date', body);
const pre = new Function('pm', 'Date', preBody);
let clock = 0;
const FakeDate = { now: () => (clock += 1000) };
const env = { opId: 'iop1' };
const results = [];
let invocations = 0, reinvocations = 0, idx = 0;
for (const run of plan.runs) {
  for (;;) {
    const resp = plan.responses[Math.min(idx++, plan.responses.length - 1)];
    let next = null;
    const deep = (a, b) => JSON.stringify(a) === JSON.stringify(b);
    const pm = {
      info: { requestName: run },
      response: { code: 200, json: () => resp, text: () => JSON.stringify(resp) },
      environment: {
        get: k => env[k], set: (k, v) => { env[k] = String(v); }, unset: k => { delete env[k]; },
      },
      execution: { setNextRequest: n => { next = n; }, skipRequest: () => { throw new Error('skipRequest on a captured opId'); } },
      expect: (v, msg) => ({ to: {
        eql: x => { if (!deep(v, x)) throw new Error((msg || '') + ' expected ' + JSON.stringify(v) + ' to eql ' + JSON.stringify(x)); },
      } }),
      test: (name, f) => {
        try { f(); results.push({ run, name, ok: true }); }
        catch (e) { results.push({ run, name, ok: false, err: String(e.message).slice(0, 200) }); }
      },
    };
    invocations++;
    pre(pm, FakeDate);
    fn(pm, FakeDate);
    if (next === run) { reinvocations++; continue; }
    break;
  }
}
process.stdout.write(JSON.stringify({ results, invocations, reinvocations, env }));
"""


def _test_script(step) -> str:
    return "\n".join(step.test_script)


def _run(responses, runs=("C :: assert-op-success",)):
    """Исполнить тест-скрипт шага по плану; вернуть разобранный исход."""
    step = gen.assert_op_success()
    with tempfile.TemporaryDirectory() as d:
        body = Path(d) / "body.js"
        plan = Path(d) / "plan.json"
        pre = Path(d) / "pre.js"
        body.write_text(_test_script(step), encoding="utf-8")
        pre.write_text("\n".join(step.pre_script), encoding="utf-8")
        plan.write_text(json.dumps({"responses": responses, "runs": list(runs)}),
                        encoding="utf-8")
        try:
            proc = subprocess.run(["node", "-e", _DRIVER, str(body), str(plan), str(pre)],
                                  capture_output=True, text=True, timeout=120)
        except FileNotFoundError:  # pragma: no cover — окружение без node
            raise AssertionError(
                "node не найден: исполнить порождённый скрипт нечем. Это «ноль "
                "исполненного», а не «ноль находок», поэтому проба ПАДАЕТ.") from None
    assert proc.returncode == 0, f"движок отверг скрипт шага: {proc.stderr[:600]}"
    return json.loads(proc.stdout)


_PENDING = {"id": "iop1", "done": False}
_OK = {"id": "iop1", "done": True, "response": {"@type": "x", "id": "acc1"}}
_ERR = {"id": "iop1", "done": True, "error": {"code": 9, "message": "refused"}}


_SUCCEEDED = "operation succeeded (response, no error)"


def _by_name(out):
    return {r["name"]: r for r in out["results"]}


def _count(out, name):
    return sum(1 for r in out["results"] if r["name"] == name)


def test_pending_operation_is_polled_until_done_then_judged_green():
    out = _run([_PENDING, _PENDING, _OK])
    assert out["reinvocations"] == 2, out
    assert out["invocations"] == 3, out
    assert all(r["ok"] for r in out["results"]), out
    # Об исходе судится ровно один раз — на завершённом конверте, а не на
    # промежуточных: на промежуточных проверяется только, что чтение ответило.
    assert _count(out, "operation done") == 1, out
    assert _count(out, _SUCCEEDED) == 1, out


def test_already_done_operation_is_judged_on_the_first_read():
    """Законный близнец: операция, завершённая к первому чтению, судится сразу,
    без единого перезапуска."""
    out = _run([_OK])
    assert out["reinvocations"] == 0, out
    assert all(r["ok"] for r in out["results"]), out
    assert _count(out, "operation done") == 1 and _count(out, _SUCCEEDED) == 1, out


def test_operation_finished_with_error_stays_red():
    out = _run([_PENDING, _ERR])
    res = _by_name(out)
    assert res["operation done"]["ok"], out
    assert not res[_SUCCEEDED]["ok"], out


def test_operation_never_done_is_red_after_the_bounded_budget():
    out = _run([_PENDING])
    assert out["reinvocations"] == gen.POLL_CAP, out
    res = _by_name(out)
    assert not res["operation done"]["ok"], out


def test_budget_does_not_leak_into_the_next_step():
    """Второй шаг того же вида начинает свой бюджет с нуля: счётчик привязан к
    имени шага и снимается на исходе. Счётчик здесь сбрасывает ПРЕДЗАПРОС шага,
    поэтому подставной прогон исполняет и его."""
    out = _run([_PENDING, _OK, _PENDING, _OK],
               runs=("C :: assert-op-success", "C :: assert-op-success #2"))
    assert out["reinvocations"] == 2, out
    assert all(r["ok"] for r in out["results"]), out
    assert _count(out, _SUCCEEDED) == 2, out
    assert not any(k in ("_pollCount", "_pollStarted") for k in out["env"]), out


if __name__ == "__main__":
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                fails += 1
                print(f"FAIL {name}: {str(e)[:400]}")
    sys.exit(1 if fails else 0)
