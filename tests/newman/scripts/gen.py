#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""
tests/newman/scripts/gen.py — генератор Postman collections из декларативных case-файлов.

Использование:
    python3 scripts/gen.py             # все ресурсы
    python3 scripts/gen.py iam-account # один ресурс (по stem case-файла)

Источник истины — модули в tests/newman/cases/<resource>.py, каждый экспортирует
переменную CASES — список объектов Case (см. ниже).

REST-пути задаются самими case-файлами (`/iam/v1/...`, `/geo/v1/...`); мутации
возвращают Operation, которая поллится через общий OpsProxy api-gateway
(`/operations/{id}`, id-prefix `epd`). LRO-poll helper (POST → Operation → poll
GET /operations/{id} до done → assert response/error) — переиспользуемый шаг ниже.
"""
from __future__ import annotations

import json
import re
import sys
import uuid
import importlib.util
from pathlib import Path
from dataclasses import dataclass, field, replace
from typing import List, Dict, Optional

ROOT = Path(__file__).resolve().parents[1]
CASES_DIR = ROOT / "cases"
OUT_DIR = ROOT / "collections"


# ---------------------------------------------------------------------------
# Декларативные структуры
# ---------------------------------------------------------------------------

@dataclass
class Step:
    """Один HTTP-запрос внутри case."""
    name: str
    method: str
    path: str  # относительный, {{baseUrl}} префикс автоматически
    body: Optional[Dict] = None
    pre_script: List[str] = field(default_factory=list)
    test_script: List[str] = field(default_factory=list)
    # Per-step auth override (used by the authz-deny suite).
    #   None              — header не трогается (default — inherit collection Bearer если есть)
    #   "anonymous"       — Authorization header снимается перед запросом
    #   "<envVarName>"    — Authorization: Bearer {{envVarName}} (значение читается из env при выполнении)
    #   AUTH_INHERIT_OP   — resolved at build time to the auth of the step that
    #                       captured `op_var` (see AUTH_INHERIT_OP below)
    auth: Optional[str] = None
    # Which env var holds the Operation id this step reads. Only meaningful for
    # the op-poll/assert helpers; drives AUTH_INHERIT_OP resolution.
    op_var: Optional[str] = None
    # Skip TLS certificate verification FOR THIS STEP ONLY (emitted as the item's
    # `protocolProfileBehavior.strictSSL`).
    #
    # Used by the external-isolation negatives, which talk to the api-gateway TLS
    # listener through a `kubectl port-forward`. That listener's certificate is
    # issued by the internal CA for its in-cluster names
    # (api-gateway.kacho.svc.cluster.local); a forwarded socket is reached as
    # 127.0.0.1, which no certificate on the stand names — and adding a name to the
    # host's resolver is exactly the manual, privileged step this harness must not
    # require. What these steps assert is WHICH ROUTES THE LISTENER SERVES, not the
    # trust chain of a tunnel that is already not the production network path.
    #
    # Deliberately per-step and not a runner-wide `--insecure`: a blanket flag
    # would also switch off verification for every other request in the suite,
    # silently and invisibly. Here it is declared on the one item that needs it and
    # is visible in the generated collection.
    insecure_tls: bool = False


# Sentinel `auth` value: "poll the Operation as whoever MINTED it".
#
# WHY THIS EXISTS. `OperationService.Get` is principal-scoped and hides a foreign
# operation behind 404 (hide-existence). The op-poll helpers used to hard-code a
# DEFAULT principal (`jwtAccountAdminA`), which is only correct for the cases whose
# mutation happens to run as that same principal. Any case that mutates as somebody
# else — IAM-USR-DL-CRUD-OK deletes as `jwtInvitee` — polls an operation it is not
# allowed to see and gets a perfectly correct 404 for POLL_CAP retries: 52 failing
# assertions with one root, and a fix applied case-by-case would simply wait for the
# next case to be written the same way.
#
# So the DEFAULT is now "inherit": at collection-build time the poll step takes the
# auth of the nearest preceding step that captured its operation-id variable. An
# explicit `auth=` argument still wins (some cases deliberately poll as a different,
# authorised principal); if nothing in the case minted the id — the case polls an id
# seeded by an earlier case — the historical default applies.
AUTH_INHERIT_OP = "\0inherit-op-principal"

# The principal used when a case has no local op-producer to inherit from.
DEFAULT_OP_POLL_AUTH = "jwtAccountAdminA"


@dataclass
class Case:
    """Один тестовый кейс — может содержать несколько шагов."""
    id: str  # например DISK-CR-CRUD-OK
    title: str  # человеко-читаемое описание
    classes: List[str]  # CRUD / VAL / NEG / BVA / ...
    priority: str  # P0 / P1 / P2 / P3
    steps: List[Step]


# ---------------------------------------------------------------------------
# Глобальный prerequest (runId генерация + _suiteFolder* алиасы + страж адреса)
# ---------------------------------------------------------------------------

# СТРАЖ НЕРАЗРЕШЁННОГО АДРЕСА — на уровне КОЛЛЕКЦИИ.
#
# ЧТО ЗАПРЕЩАЕТСЯ. Newman подставляет `{{имя}}` только если переменная где-то
# определена; неопределённую он оставляет ЛИТЕРАЛОМ и отправляет как есть. Тогда
# запрос уходит на адрес вида `/operations/{{visSetAcctOp}}`, сервис честно отвечает
# `invalid operation id`, а поллер крутит на этом весь свой предел — потому что
# «не done» он читает как «ещё не готово», хотя повтор не может сойтись НИКОГДА.
#
# ЧТО ЭТО СТОИЛО (замер боевой посадки 2026-07-30, отчёты прогона на 1090 упавших):
# из 12823 исполнений 992 ушли с неразрешённым `{{имя}}` в адресе. Из них
#   — 791 дали упавшие утверждения: ОДНА отвергнутая мутация размножалась
#     до 30 одинаковых отказов на каждый поллер (только `rbac-visibility-set` — 582);
#   — 201 не дали НИ ОДНОГО утверждения: запрос исполнялся 30 раз против шаблона
#     и исчезал из вердикта бесследно. Это хуже красного: «не выполнилось» тихо
#     засчитывалось в «прошло» (testing.md).
#
# ПОЧЕМУ НА УРОВНЕ КОЛЛЕКЦИИ. Страж этого класса уже есть — `_op_id_guard` в
# `poll_operation_until_done`, и его собственный docstring описывает ровно этот дефект.
# Но он покрывает ТОЛЬКО шаги, порождённые общим helper'ом: перепись по 82
# сгенерированным коллекциям — 2571 опрос операции, из них под стражей 188. Остальные
# поллеры рукописные, вшиты в кейсы. Скрипт уровня коллекции исполняется ПЕРЕД КАЖДЫМ
# запросом, поэтому покрывает оба рода разом и не может быть забыт автором нового кейса.
#
# ПОЧЕМУ ЭТО НЕ МАСКИРОВКА. Отказ не исчезает — он остаётся, названный по имени
# переменной и по причине («предусловия не было»), и приходит ОДИН раз вместо тридцати.
# А 201 исполнение, которое сейчас не утверждает вообще ничего, впервые становится
# видимым. Число различимых находок не уменьшается ни на одну.
#
# ПРЕДИКАТ УЗКИЙ НАМЕРЕННО. Срабатывает, только когда имя НЕ ОПРЕДЕЛЕНО НИ В ОДНОЙ
# области (`pm.variables.has` смотрит все). Переменная, заданная ПУСТОЙ, — законный
# негативный кейс («пустой id → 400»); newman подставит её пустой строкой, литерала в
# адресе не останется, и страж до неё не доберётся by construction.
_URL_VAR_GUARD = [
    "(function () {",
    "  var _u = '';",
    "  try { _u = pm.request.url.toString(); } catch (e) { return; }",
    "  var _all = _u.match(/\\{\\{[A-Za-z0-9_]+\\}\\}/g);",
    "  if (!_all) { return; }",
    "  var _n = null;",
    "  for (var _i = 0; _i < _all.length; _i++) {",
    "    var _c = _all[_i].slice(2, -2);",
    "    if (!pm.variables.has(_c)) { _n = _c; break; }",
    "  }",
    "  if (_n === null) { return; }",
    "  pm.test('предусловие: {{' + _n + '}} не было захвачено — запрос не отправлен', function () {",
    "    pm.expect.fail(_n + ' не определена ни в одной области. Мутация, которая должна была её "
    "захватить, не вернула Operation (была отвергнута), либо захват не состоялся. Отправка ушла бы "
    "литералом и повтор не сошёлся бы никогда.');",
    "  });",
    "  pm.execution.skipRequest();",
    "})();",
]

PRE_GLOBAL = [
    "if (!pm.environment.get('runId') || pm.environment.get('runId') === '') {",
    "  // runId формат: только [a-z0-9], без точки, начинается с буквы — чтобы проходить compute name regex",
    "  const t = Date.now().toString(36);",
    "  const r = Math.floor(Math.random() * 1e9).toString(36);",
    "  pm.environment.set('runId', ('r' + t + r).replace(/[^a-z0-9]/g, '').slice(0, 11));",
    "}",
    "pm.environment.set('_suiteProjectId', pm.environment.get('existingProjectId'));",
    "pm.environment.set('_suiteFolderCrossId', pm.environment.get('existingProjectCrossId'));",
    # _URL_VAR_GUARD ЗДЕСЬ БОЛЬШЕ НЕ СТОИТ — он переехал в конец пред-скрипта КАЖДОГО
    # шага (step_to_item). Причина — порядок исполнения newman: prerequest коллекции
    # идёт до prerequest шага, поэтому отсюда страж судил об адресе раньше, чем шаг
    # успевал задать переменные, которыми владеет сам.
]


# POST_GLOBAL — снятие ФАНТОМНОГО идентификатора, на уровне КОЛЛЕКЦИИ.
#
# Идентификатор ресурса берётся из `metadata` сразу после мутации: до завершения
# операции другого источника нет. Но он ПРЕДВЫДЕЛЕН и приходит даже у операции, которая
# закончится ошибкой, — тогда в переменной остаётся ресурс, которого в базе не существует.
# Он выглядит настоящим, поэтому кейс не падает на месте, а продолжает работу с ним и
# плодит производные отказы вокруг пустоты (замер боевой посадки 2026-07-30: одна
# неудача создания аккаунта — 550 упавших утверждений в одной коллекции, и разбор увело
# в ложную сторону).
#
# ПОЧЕМУ НА УРОВНЕ КОЛЛЕКЦИИ, А НЕ В ОБЩЕМ ПОЛЛЕРЕ. Поллеров в дереве два рода: общий
# helper и рукописные, вшитые в кейсы. Правка общего закрывала первый род и оставляла
# второй — перепись по сгенерированным коллекциям показала 236 опросов операции в 90
# папках, и подавляющая часть промахов приходилась именно на рукописные. Скрипт уровня
# коллекции исполняется ПОСЛЕ КАЖДОГО ответа, поэтому покрывает оба рода разом и не
# может быть забыт автором нового кейса — это и есть починка класса, а не экземпляра.
#
# НИ ОДНОГО УТВЕРЖДЕНИЯ ЗДЕСЬ НЕТ. `pm.test` в скрипте уровня коллекции добавил бы по
# утверждению на КАЖДЫЙ запрос и раздул бы счётчики вердикта. Здесь только побочный
# эффект над окружением.
POST_GLOBAL = [
    "try {",
    "  const _ct = (pm.response && pm.response.headers && pm.response.headers.get('Content-Type')) || '';",
    "  if (_ct.indexOf('json') !== -1) {",
    "    const _j = pm.response.json();",
    # Только конверт Operation: `done` вместе с `id`. Иначе обычный ресурс с полем
    # `done` мог бы случайно снять регистрацию.
    "    if (_j && _j.done === true && typeof _j.id === 'string' && _j.id !== '') {",
    "      if (_j.error) {",
    "        const _pv = JSON.parse(pm.environment.get('_provisionalIds') || '[]');",
    "        _pv.forEach(function (k) { pm.environment.unset(k); });",
    "      }",
    "      pm.environment.unset('_provisionalIds');",
    "    }",
    "  }",
    "} catch (e) { /* не JSON, не Operation — регистрация остаётся как есть */ }",
]


# ---------------------------------------------------------------------------
# Polling caps (single source of truth)
# ---------------------------------------------------------------------------
#
# POLL_CAP — one standardised retry cap for ALL bounded poll/retry loops in the
# suite (Operation-poll AND get-after-delete poll-until-gone). A single cap plus a
# per-case counter reset avoids inconsistent caps and shared-counter bleed that would
# otherwise let poll iterations leak across cases (a later case starting
# mid-exhaustion → reordered/aborted run → non-deterministic assertion COUNT). Both
# the Operation-poll helper (`poll_operation_until_done`) and the get-after-delete
# helper (`get_until_gone`) reset their counter on first entry (pre-request,
# request-name-scoped flag) so a value left over from a prior case can never shorten
# the next case's loop.
#
# The budget is POLL_CAP x the inter-poll delay, and the delay is a real 500 ms
# busy-wait in every loop that uses this cap (newman fires setNextRequest before any
# setTimeout, so a busy-wait is the only way to actually space polls out). So 50 polls
# is ~25 s of wall-clock, not the "~6-10 s" this paragraph claimed before the delay
# existed — generous enough for the async Delete Operation to finish AND for the FGA
# owner-tuple removal to propagate before the get-after-delete assertion runs.
#
# The number matters beyond arithmetic: a known-failing record in docs/RESULTS.md
# justified itself as covering "a ~15 s budget", a figure that came from a stale comment
# in cases/authz-deny.py and never from this constant. A record resting on a window that
# is not the one being executed cannot be refuted by measuring.
#
# The cap is 50 (not lower) because the flat owner/creator access on a
# freshly-created iam_access_binding OBJECT converges at ~4 s under full-pipeline CI
# load — just past a ~3.7 s cap (the read-after-write poll observed 403 to ~3.7 s,
# then the same object read 200 at ~4.0 s — access IS guaranteed and DOES appear,
# proven by the 200s; a lower cap gave up one beat early). This is the grant→access
# propagation window (TIMING, not a deny-hole): poll_request_until_status only retries
# the propagation-window codes and asserts on the TERMINAL response, so a genuine
# never-converging deny still fails at the higher cap — it is NOT masked.
POLL_CAP = 50


# ---------------------------------------------------------------------------
# Утилиты-сниппеты pm.*
# ---------------------------------------------------------------------------

def assert_status(code: int) -> List[str]:
    return [
        f"pm.test('status {code}', () => pm.expect(pm.response.code).to.eql({code}));",
    ]


def assert_answered(label: str) -> List[str]:
    """Assert that the request got a RESPONSE AT ALL, before asserting anything
    about it.

    WHY THIS IS A SEPARATE, EXPLICIT ASSERTION
    ------------------------------------------
    When a request dies before an HTTP exchange completes — DNS, refused
    connection, TLS, timeout — newman still runs the test script, with an empty
    response. `pm.response.code` is then `undefined`, and this shape

        const code = pm.response.code;
        if (code === undefined) { return; }   // "unreachable = PASS"
        pm.expect(code).to.equal(404);

    records a PASSING assertion for a check that never happened. It was written on
    the reasoning that an unreachable endpoint is itself proof of the isolation
    being asserted. It is not: "I could not reach it" and "it refused me" are
    different findings, and only the second is evidence. The first is a broken
    harness — and one that reads green is worse than one that reads red, because
    nobody goes looking.

    Eight ban-#6 negatives (Internal* must not be reachable on the advertised
    external endpoint) carried that shape while the advertised host did not
    resolve. Every layer agreed nothing was wrong: the assertion passed, the
    execution-coverage gate saw a cursor position and called it executed, and the
    suite gate SUBTRACTED the one honest signal (`requests.failed`) as DNS noise.

    So the first thing a probe asserts is that it got an answer. If it did not,
    this fails, loudly, naming the step — and every assertion after it fails too,
    because `undefined` does not equal the expected status. That is the intended
    behaviour: a check that did not happen must not be able to report success.
    """
    return [
        # Encoded, not pasted: `label` is caller text and an apostrophe in it would break
        # the literal, so the step would stop parsing and silently not run — the very
        # outcome this probe exists to make impossible.
        f"pm.test({json.dumps(f'{label}: request was ANSWERED (a check that did not run is not a check that passed)')}, () => {{",
        "  pm.expect(pm.response && pm.response.code,",
        "    'no response — the endpoint was not reached. This is a broken harness, not a passing check: "
        "fix reachability (the runner forwards the port and injects the base URL) or delete the probe.')",
        "    .to.be.a('number');",
        "});",
    ]


def assert_grpc_code(code: int, code_name: str) -> List[str]:
    return [
        f"pm.test('grpc code {code} ({code_name})', () => {{",
        "  const j = pm.response.json();",
        f"  pm.expect(j.code, JSON.stringify(j)).to.eql({code});",
        "});",
    ]


def assert_unscoped_rejected(action: Optional[str] = None,
                             unscoped_resource: Optional[str] = None) -> List[str]:
    """An UNSCOPED create (no account/project anchor in the body) is REJECTED.

    Two defensible outcomes, both "rejected" — this is the platform-wide
    authz-first ordering (security.md), already encoded by the identical helper in
    the vpc/nlb/compute/storage suites:

      403 PERMISSION_DENIED (code 7) — the gateway scope_extractor cannot resolve a
        scope for the anti-BOLA check, so it fail-closes on the unscoped anchor
        (`account:*`) BEFORE the backend ever validates the body;
      400 INVALID_ARGUMENT (code 3) — the backend's "scope is required" when the
        request does reach it.

    Tolerating both is NOT the whole helper. A bare `403|400` negative passes on ANY
    refusal — a permission-catalog miss, a malformed body, a typo in the path — i.e.
    exactly the "negative that passes for the wrong reason" this suite keeps finding.
    So pass `action` (+ `unscoped_resource`) to PIN which refusal it is: on the 403
    branch the `ErrorInfo` must carry `reason=AUTHZ_DENIED` and that method's action
    (an EMPTY action means the catalog had no entry — a routing/catalog regression,
    not the invariant under test); on the 400 branch the message must name the scope.
    """
    out = [
        "pm.test('unscoped rejected (400 InvalidArgument or 403 authz-first)', () => {",
        "  pm.expect(pm.response.code, pm.response.text()).to.be.oneOf([400, 403]);",
        "});",
        "pm.test('grpc code 3 (INVALID_ARGUMENT) or 7 (PERMISSION_DENIED)', () => {",
        "  const j = pm.response.json();",
        "  pm.expect(j.code, JSON.stringify(j)).to.be.oneOf([3, 7]);",
        "});",
    ]
    if action is None:
        return out
    res_line = (
        f"    pm.expect(md.resource, JSON.stringify(j)).to.eql('{unscoped_resource}');"
        if unscoped_resource else "    // resource anchor not pinned for this RPC"
    )
    out += [
        f"pm.test('the refusal is about the MISSING SCOPE on {action}, not some other rejection', () => {{",
        "  const j = pm.response.json();",
        "  if (pm.response.code === 403) {",
        "    const info = (j.details || []).find(d => (d['@type'] || '').includes('ErrorInfo'));",
        "    pm.expect(info, 'ErrorInfo detail: ' + JSON.stringify(j)).to.be.an('object');",
        "    pm.expect(info.reason, JSON.stringify(j)).to.eql('AUTHZ_DENIED');",
        "    const md = info.metadata || {};",
        f"    pm.expect(md.action, 'empty action = permission-catalog miss, not a scope refusal: ' "
        f"+ JSON.stringify(j)).to.eql('{action}');",
        res_line,
        "  } else {",
        "    pm.expect((j.message || '').toLowerCase(), JSON.stringify(j))",
        "      .to.satisfy(m => m.includes('scope') || m.includes('account') || m.includes('project'));",
        "  }",
        "});",
    ]
    return out


def assert_scoped_authz_deny(action: str,
                             resource_expr: Optional[str] = None) -> List[str]:
    """A 403 must be the per-object deny under test, not a permission-catalog miss.

    Companion to `assert_unscoped_rejected` above (same discriminator, different
    shape): that one covers "rejected, 400-or-403"; this one covers "denied, 403,
    on a specific object". Both live here so there is exactly ONE implementation
    of the catalog-miss discriminator — do not re-derive a third copy in a case
    file.

    Why it is needed. The api-gateway fail-closes with 403 AUTHZ_DENIED when the
    requested method has no permission-catalog entry — which is also what a
    MISROUTED path produces, because an unresolvable path yields no FQN to look
    up. Both denials are `{"code":7}`, so a negative that asserts only the status
    code passes on either, and a wrong path turns the whole case into a tautology
    (three such cases were found and removed on 2026-07-26).

    The two are distinguishable in the body: a real per-object deny carries the
    resolved permission and scope in `ErrorInfo.metadata` (`action`, `resource`),
    whereas the catalog miss carries an EMPTY action — the descriptor is built
    before the entry is known. Asserting the action pins the deny to the RPC.

    `resource_expr` is a JS EXPRESSION (not a literal): `{{var}}` is not
    interpolated inside test scripts, so a variable-bearing scope must be read
    with `pm.environment.get()`. Pass it whenever the scope the gateway resolves
    is deterministic — `resourceLabel()` renders `"<object_type>:<id>"`, or
    `"<object_type>:*"` when the extractor resolves no id. Omit it for RPCs whose
    scope anchor is a cluster singleton (id not known to a black-box caller); the
    `action` assertion alone already excludes the catalog miss.
    """
    out = [
        "pm.test('403 PermissionDenied (code 7)', () => {",
        "  pm.expect(pm.response.code).to.eql(403);",
        "  pm.expect(pm.response.json().code, pm.response.text()).to.eql(7);",
        "});",
        f"pm.test('deny is the scoped authz deny on {action}, not a permission-catalog miss', () => {{",
        "  const j = pm.response.json();",
        "  const info = (j.details || []).find(d => (d['@type'] || '').includes('ErrorInfo'));",
        "  pm.expect(info, 'ErrorInfo detail: ' + JSON.stringify(j)).to.be.an('object');",
        "  pm.expect(info.reason, JSON.stringify(j)).to.eql('AUTHZ_DENIED');",
        "  const md = info.metadata || {};",
        f"  pm.expect(md.action, 'empty action means the catalog had no entry for the method (misrouted path?): ' + JSON.stringify(j)).to.eql('{action}');",
    ]
    if resource_expr:
        out.append(f"  pm.expect(md.resource, JSON.stringify(j)).to.eql({resource_expr});")
    out.append("});")
    return out


def assert_field_violation(field_name: str) -> List[str]:
    return [
        f"pm.test('field violation on \"{field_name}\"', () => {{",
        "  const j = pm.response.json();",
        "  const det = (j.details || []).find(d => (d['@type']||'').includes('BadRequest'));",
        "  pm.expect(det, 'BadRequest detail').to.be.an('object');",
        f"  const fv = (det.fieldViolations || []).find(v => v.field === '{field_name}');",
        f"  pm.expect(fv, 'fieldViolation for {field_name}').to.be.an('object');",
        "});",
    ]


_ENV_SET_RE = re.compile(r"""pm\.environment\.set\(\s*['"](\w+)['"]""")


def _captured_op_vars(test_script: List[str]) -> List[str]:
    """Operation-id env vars this step WRITES.

    Recognises both the `save_from_response` helper and the hand-written
    `pm.environment.set('opId', j.id || '')` idiom several cases use inline — the
    producer of an operation id is whoever wrote the variable, however they wrote it."""
    return [v for v in _ENV_SET_RE.findall("\n".join(test_script)) if _is_operation_id_var(v)]


def _is_operation_id_var(env_var: str) -> bool:
    """Does this env var hold an Operation id (i.e. is it consumed by an op-poll)?

    Naming is the contract across every case file: the shared `opId`, or a per-case
    variable ending in `OpId` (`vbcDelOpId`, `badRoleInvOpId`, `addAisOpId`, …)."""
    return env_var == "opId" or env_var.endswith("OpId") or env_var.endswith("OperationId")


def save_from_response(jsonpath: str, env_var: str) -> List[str]:
    """Сохранить значение из response в env.

    OPERATION IDS ARE CLEARED FIRST — the capture is a REPLACE, not an upsert.

    `opId` is one shared environment variable and the poll step that reads it is the
    very next request. When a mutation is REJECTED (400/403) the response carries no
    `id`, so the write below never happens — and the variable silently keeps the
    PREVIOUS case's operation. The poll then fetches a stale, unrelated, long-since
    `done` operation, `done === true` holds, and the case reports GREEN having
    verified nothing about the mutation it was written for. Two live examples:
    IAM-USR-INV-IDEM-REINVITE (re-invite 400s on a missing field, poll confirms the
    PRIOR invite → "idempotency" never once exercised) and IAM-ROL-DL-NEG-SYSTEM
    (system-role delete 403s, the `if (!opId) skipRequest()` guard is DEFEATED by the
    stale value, and the poll asserts FAILED_PRECONDITION against the previous case's
    SUCCESSFUL delete).

    Clearing first makes a failed capture observable: the guard skips as intended, or
    the poll fails loudly on an empty id, instead of passing on a foreign object.
    Non-operation captures (resource ids) are deliberately NOT cleared — several cases
    save a resource id once and read it many steps later, across requests that do not
    return it; the stale-poll class is specific to ids consumed immediately."""
    reset = [f"pm.environment.unset('{env_var}');"] if _is_operation_id_var(env_var) else []
    # ЗАХВАТ ИЗ МЕТАДАННЫХ ОПЕРАЦИИ — ПРОВИЗОРНЫЙ, И ЭТО ОТМЕЧАЕТСЯ ЗДЕСЬ.
    #
    # `metadata.<res>Id` доступен СРАЗУ, до `done`, и другого источника id до завершения
    # операции нет. Но он ПРЕДВЫДЕЛЕН и присутствует даже у операции, которая завершится
    # ОШИБКОЙ. Тогда в переменной остаётся id ресурса, которого в базе нет, — «фантом»:
    # он выглядит настоящим, поэтому кейс не падает здесь, а уезжает дальше и производит
    # сотни производных отказов вокруг несуществующего объекта (замер 2026-07-30: одна
    # неудача `Account.Create` дала 550 упавших утверждений в одной коллекции и увела
    # разбор в ложную сторону).
    #
    # Сам захват отменить нельзя, поэтому имя переменной РЕГИСТРИРУЕТСЯ как провизорное;
    # снимает его тот, кто первым узнаёт исход, — шаг опроса операции (см.
    # poll_operation_until_done). Регистрация, а не немедленная очистка: на этом шаге
    # исход ещё неизвестен.
    provisional = []
    if ".metadata" in jsonpath and not _is_operation_id_var(env_var):
        provisional = [
            "try {",
            "  const _pv = JSON.parse(pm.environment.get('_provisionalIds') || '[]');",
            f"  if (_pv.indexOf('{env_var}') === -1) _pv.push('{env_var}');",
            "  pm.environment.set('_provisionalIds', JSON.stringify(_pv));",
            "} catch (e) {}",
        ]
    return [
        *reset,
        "try {",
        "  const j = pm.response.json();",
        f"  const v = ({jsonpath});",
        f"  if (v !== undefined && v !== null) pm.environment.set('{env_var}', String(v));",
        "} catch (e) {}",
        *provisional,
    ]


def assert_operation_envelope() -> List[str]:
    """An async mutation returned an Operation envelope with an IAM operation id.

    The prefix is `iop` (domain.PrefixOperationIAM). It used to read `epd` here —
    the COMPUTE operation prefix, copied in with the generator — which this suite
    can never produce, so every case using this helper failed on an assertion that
    was wrong rather than on the behaviour it was written to pin.
    """
    return [
        "pm.test('Operation envelope returned', () => {",
        "  const j = pm.response.json();",
        "  pm.expect(j.id, 'operation.id').to.match(/^iop[a-z0-9]+$/);",
        "  pm.expect(j.metadata, 'operation.metadata').to.be.an('object');",
        "});",
    ]


def assert_created_at_seconds(jsonpath="pm.response.json().createdAt") -> List[str]:
    """CONF: created_at truncate до секунд — нет дробной части."""
    return [
        "pm.test('createdAt truncated to seconds', () => {",
        f"  const ts = ({jsonpath});",
        "  pm.expect(ts, 'createdAt present').to.be.a('string');",
        "  // RFC3339; если есть дробная часть — это .000... либо отсутствует",
        "  const m = ts.match(/\\.(\\d+)/);",
        "  if (m) pm.expect(parseInt(m[1].padEnd(9,'0'), 10), 'sub-second part is zero').to.eql(0);",
        "});",
    ]


# ---------------------------------------------------------------------------
# Harness-config guard — the ONE place the "base URL came from the environment"
# idiom is allowed to live.
# ---------------------------------------------------------------------------

def require_env_url(var: str, path: str, why: str = "") -> List[str]:
    """Pre-request block: point this request at {{<var>}}+path, and FAIL if <var>
    is not set.

    WHY THIS ASSERTS INSTEAD OF ONLY SKIPPING
    -----------------------------------------
    Two guards look identical and are not the same thing:

      * an OPERATION guard — `if (!opId) skipRequest()` — is a LEGAL skip. The
        create under test was rejected on purpose, so there is no operation to
        poll and nothing to assert. Nothing is lost.

      * an ENVIRONMENT guard — `if (!internalBaseUrl) skipRequest()` — is a
        BROKEN HARNESS. The check it removes is still meaningful and still
        expected to run; the only reason it cannot is that the runner did not
        inject the variable (deploy/scripts/newman-e2e.sh / newman-parallel.sh
        pass it as `--env-var`).

    newman leaves NO trace of a skipped request — no assertion, no failure, no
    execution record — so the second kind used to pass by never running. That is
    the same blindness as the `setNextRequest(null)` truncation, one level down:
    there the run ended, here the run continues and quietly drops checks. The
    execution-coverage gate cannot tell them apart either, because BOTH are an
    explicit `skipRequest()` and both are therefore "explained".

    So the missing variable is asserted here. If it is lost, the suite goes RED
    with the variable's name in the message instead of silently shrinking. The
    request is still skipped afterwards — sending it to the wrong listener would
    only add a cascade of confusing 404s on top of a failure already reported.

    exec-coverage.py enforces this shape statically: a `skipRequest()` guard that
    reads a *BaseUrl variable and carries no `pm.test(` fails the gate.

    WHY THE PATH IS RESOLVED EXPLICITLY (`pm.variables.replaceIn`)
    -------------------------------------------------------------
    Assigning `pm.request.url` REPLACES the parsed Url with whatever string this
    block builds. Every earlier caller passed a constant path, so nothing in it
    ever needed substituting and the question never came up. A path naming a
    resource — `/iam/v1/internal/interactiveClients/{{icId}}` — does need it, and
    relying on newman to substitute a template inside a URL the pre-request script
    just overwrote is relying on ordering nobody here has pinned. If it did NOT
    substitute, the request would travel with the literal `{{icId}}` in it and the
    service would answer a perfectly correct refusal about an id nobody named —
    the same shape as the unresolved-address class the collection-level guard was
    written for, one level further in.

    So the path is resolved HERE, before the assignment, by the documented
    primitive. On a path with no `{{…}}` this is the identity function, which is
    why every existing caller is byte-unchanged in behaviour. The collection-level
    `_URL_VAR_GUARD` still runs FIRST and still refuses to send a request whose
    original URL names a variable that is undefined in every scope, so "the
    variable was never captured" remains a reported failure and not a silent
    substitution of the empty string.
    """
    reason = f" — {why}" if why else ""
    return [
        f"// HARNESS-CONFIG GUARD — {var} is injected by the newman runner (--env-var).",
        "// Missing value = misconfigured harness, NOT a legal mode: FAIL, then skip.",
        f"const __cfgUrl = pm.environment.get('{var}') || pm.variables.get('{var}') || '';",
        "if (__cfgUrl) {",
        # replaceIn is identity on a template-free path; see the docstring above.
        f"  pm.request.url = __cfgUrl + pm.variables.replaceIn('{path}');",
        "} else {",
        f"  pm.test('harness config: {var} is set{reason}', () => {{",
        f"    pm.expect.fail('{var} is not set — the newman runner "
        "(deploy/scripts/newman-e2e.sh / newman-parallel.sh --env-var) did not inject it. "
        "This step cannot run, and a check that cannot run MUST NOT be silently dropped.');",
        "  });",
        "  pm.execution.skipRequest();",
        "}",
    ]


_RYA_SEQ = [0]


def retry_until_authorized(step: Step, budget: int = 15, interval_ms: int = 400,
                           retry_on=(403, 404)) -> Step:
    """Wrap the FIRST access of the caller's OWN just-created resource in a bounded
    read-your-writes retry over the owner-tuple materialization window.

    opgate (the create confirm-gate) was removed by design-review: Operation.done now
    means the resource is DURABLE, but its owner/creator FGA tuple materializes
    eventually-consistent (at-least-once drainer + reconciler + sync-registrar
    optimisation). Under load the first post-create Get/Update/Delete of the fresh
    resource can briefly return 403 (PERMISSION_DENIED) or 404 at the authz gate
    before the tuple is visible. This is a textbook read-your-writes lag -> the CLIENT
    retries; it is NOT a server barrier.

    Retries the SAME request (setNextRequest -> self) while the response code is in
    `retry_on` (default 403/404), spacing attempts by ~interval_ms (busy-wait -- newman
    fires setNextRequest before any setTimeout). budget*interval_ms bounds the wait
    (default 15*400ms = ~6s) -- fail-closed: on any other code the wrapped step's real
    test_script runs exactly once, and once the budget is spent it ALSO runs on the
    terminal 403/404 (a genuine, non-converging deny still FAILS the real assertions --
    never masked, never infinite).

    Use ONLY on the first access of the caller's OWN fresh resource. Do NOT wrap
    negative / cross-account-deny / absent-id steps (a poll there would mask a real
    deny). The counter/started env-vars are request-name-scoped (step names are
    globally unique after serialization) so the loop never bleeds across cases or
    steps -- same discipline as poll_operation_until_done.
    """
    # Полоса, по которой приходит окно видимости, задаётся МЕТОДОМ, а не вкусом
    # автора: у мутации отказ виден как 403, а у ЧТЕНИЯ он спрятан под 404
    # (hide-existence: текст отказа побайтово равен настоящему «не найдено», см.
    # `security.md`). Поэтому рукописное `retry_on=(403,)` на GET — обёртка,
    # которая не может сработать на том коде, который она увидит: форма есть,
    # содержания нет. Такое место в дереве нашлось (vpc1 `get-no-dhcp`: 404 на
    # первом же обращении, ретрай не сработал ни разу, шаг упал). Чинится по
    # построению здесь, а не перечнем в кейсах; 404, названный шагом законным
    # исходом, в retry_on не попадает вовсе — его отсекает вызывающий.
    # Ожидание НИКОГДА не включает код, который шаг сам объявил приемлемым
    # исходом: иначе проба пережидала бы ровно то, ради чего написана, и жгла бы
    # бюджет на успехе. Нормализация здесь, а не у вызывающих: рукописные
    # обёртки этого не делали (5 мест в дереве ждали заявленный ими же 404).
    _acc = _accepted_http_codes("\n".join(step.test_script))
    retry_on = tuple(c for c in retry_on if c not in _acc)
    if step.method == "GET" and 404 not in retry_on and 404 not in _acc:
        retry_on = tuple(retry_on) + (404,)
    if not retry_on:
        # Ждать нечего: все коды полосы видимости объявлены исходами. Обёртка
        # выродилась бы в петлю, которая не может сработать, — не ставим её.
        return step
    retry_set = ",".join(str(c) for c in retry_on)
    guard = [
        "// bounded read-your-writes retry over the owner-tuple materialization window",
        "// (opgate removed -> eventual-consistency); retries SELF only on 403/404.",
        "if (pm.environment.get('_authRetryStarted') !== pm.info.requestName) {",
        "  pm.environment.set('_authRetryCount', '0');",
        "  pm.environment.set('_authRetryStarted', pm.info.requestName);",
        "}",
        "const _arc = parseInt(pm.environment.get('_authRetryCount') || '0', 10);",
        f"if ([{retry_set}].includes(pm.response.code) && _arc < {budget}) {{",
        "  pm.environment.set('_authRetryCount', String(_arc + 1));",
        f"  const _ard = Date.now(); while (Date.now() - _ard < {interval_ms}) {{ /* owner-tuple materialization wait */ }}",
        "  pm.execution.setNextRequest(pm.info.requestName);",
        "  return;",
        "}",
        "pm.environment.unset('_authRetryCount');",
        "pm.environment.unset('_authRetryStarted');",
    ]
    _RYA_SEQ[0] += 1
    # Give the wrapped step a globally-unique name so its self-retry
    # setNextRequest(pm.info.requestName) always resolves to ITSELF. Newman resolves a
    # setNextRequest name to the FIRST item with that name in the collection; these
    # suites mostly do NOT prefix step names by case-id, so a wrapped step whose bare
    # name repeats would otherwise jump the retry to an earlier same-named step — the
    # exact hazard poll_operation_until_done avoids via its unique poll-op-<n> name.
    return replace(step, name=f"{step.name}-rya{_RYA_SEQ[0]}",
                   test_script=guard + list(step.test_script))


def retry_until_absent(step: Step, still_present_expr: str, budget: int = 25,
                       interval_ms: int = 500) -> Step:
    """Bounded retry a "must-be-ABSENT/empty" read over a read-your-writes-ON-REVOKE
    window — the MIRROR of retry_until_authorized for the deny/revoke side.

    A grant the suite just REVOKED (or a residual account-A grant it just STRIPPED via a
    pre-clean) can still be visible for a beat: the FGA tuple removal / list-authz
    negative-cache lags a few seconds after the revoke Operation is done (Kachō is
    eventually-consistent — api-conventions.md). So a "non-member sees EMPTY" /
    "not-granted subject does NOT see the id" leak-guard flakes on the pre-convergence
    window under parallel load (the serial run's timing hid it).

    `still_present_expr` is a JS boolean that is TRUE while the thing that MUST become
    absent is STILL present (e.g. `((pm.response.json().users)||[]).length > 0`, or the
    leaked id is still in the array). Retries SELF while it is truthy, spacing attempts by
    ~interval_ms (busy-wait — newman fires setNextRequest before any setTimeout).

    Fail-OPEN at the budget: once spent, the wrapped step's real assertions run exactly
    once on the terminal response — so a GENUINE over-grant / real leak (the thing NEVER
    becomes absent) still FAILS the assertion. It is impossible to mask a persistent leak;
    only a transient revoke/pre-clean-materialization window is absorbed. Use ONLY on a
    negative "must be absent/empty" read whose emptiness is GUARANTEED once the suite's own
    revoke/pre-clean materializes — NEVER to paper over a cross-account deny or a real hole.

    The step name is preserved (not suffixed): these leak-guard steps are often the target
    of a pre-clean `setNextRequest('<name>')` jump, and the self-loop uses the dynamic
    pm.info.requestName so it self-resolves without a rename."""
    guard = [
        "// bounded retry over the revoke/pre-clean materialization window (read-your-writes",
        "// ON REVOKE): retry SELF while the must-be-absent thing is still present, spacing",
        "// ~interval_ms. Fail-open at budget -> the real assertion below runs once and FAILS",
        "// if it is STILL present (a GENUINE over-grant / leak never clears -> NEVER masked).",
        "if (pm.environment.get('_absRetryStarted') !== pm.info.requestName) {",
        "  pm.environment.set('_absRetryCount', '0');",
        "  pm.environment.set('_absRetryStarted', pm.info.requestName);",
        "}",
        "const _absc = parseInt(pm.environment.get('_absRetryCount') || '0', 10);",
        "let _stillPresent = false;",
        f"try {{ _stillPresent = ({still_present_expr}); }} catch (e) {{ _stillPresent = false; }}",
        f"if (pm.response.code === 200 && _stillPresent && _absc < {budget}) {{",
        "  pm.environment.set('_absRetryCount', String(_absc + 1));",
        f"  const _absd = Date.now(); while (Date.now() - _absd < {interval_ms}) {{ /* revoke-materialization wait */ }}",
        "  pm.execution.setNextRequest(pm.info.requestName);",
        "  return;",
        "}",
        "pm.environment.unset('_absRetryCount');",
        "pm.environment.unset('_absRetryStarted');",
    ]
    return replace(step, test_script=guard + list(step.test_script))


def _op_id_guard(op_var: str, required: bool) -> List[str]:
    """Pre-request guard: do not send the poll when `op_var` is empty.

    Since the capture clears the variable first (save_from_response), an empty
    `op_var` now means exactly one thing: the mutation this poll belongs to did not
    return an Operation. Two intents, two shapes — and the difference is the whole
    point of the guard:

      required=True  (default) — the case under test asserts its mutation succeeded,
        so a missing id is a DEFECT of that case. Report it once, naming the
        variable, then skip: without the report the poll silently disappears (the
        second-order blindness exec-coverage.py documents); without the skip the
        gateway receives a literal `{{opId}}` and answers `invalid operation id`
        POLL_CAP times, burying one root cause under 50 identical failures.

      required=False — a best-effort `cleanup-*` teardown. Its DELETE is allowed to
        be refused (403/404 for a resource another suite already removed); there is
        genuinely nothing to poll and nothing is lost. This is the sanctioned
        operation-guard skip (exec-coverage.py: "a create refused on purpose
        genuinely has nothing to poll"), NOT an environment guard.
    """
    if not required:
        return [
            f"// best-effort teardown: no Operation to poll when the cleanup was refused.",
            f"if (!pm.environment.get('{op_var}')) {{ pm.execution.skipRequest(); }}",
        ]
    return [
        f"// OPERATION GUARD — '{op_var}' is captured by the mutation this poll follows.",
        "// Empty = that mutation returned no Operation. Report it (a skipped request",
        "// leaves no trace at all) and skip, rather than polling a literal template.",
        f"if (!pm.environment.get('{op_var}')) {{",
        f"  pm.test('operation id {op_var} was captured (the mutation returned an Operation)', () => {{",
        f"    pm.expect.fail('{op_var} is empty — the mutation this poll belongs to did not "
        "return an Operation (it was rejected, or its capture failed). Polling would hit an "
        "unresolved template; a previous case\\'s operation is NOT a substitute.');",
        "  });",
        "  pm.execution.skipRequest();",
        "}",
    ]


def poll_operation_until_done(auth: str = AUTH_INHERIT_OP, required: bool = True) -> Step:
    """Reusable poll step: до POLL_CAP попыток (через setNextRequest), потом fail если done остался false.

    The auth parameter carries a valid Bearer token: without one the gateway exempts
    OperationService/Get but the IAM service's anti-anonymous interceptor still
    rejects unauthenticated callers with 401 UNAUTHENTICATED (code 16).

    By DEFAULT it is AUTH_INHERIT_OP — the poll runs as whoever minted the operation
    (see AUTH_INHERIT_OP). `OperationService.Get` hides a foreign operation as 404,
    so a hard-coded principal 404s on every case that mutates as somebody else.
    Pass an explicit principal only when the case deliberately polls as a different,
    authorised caller.

    The retry cap is POLL_CAP (single source of truth — see the constant above).
    Between retries a ~500ms busy-wait spaces out the polls (see the test script),
    so POLL_CAP polls cover ~POLL_CAP*0.5s of the async-op tail before giving up —
    a real wait, not a back-to-back hammer, so a legitimately-slow worker finishes
    in dev/CI instead of failing on premature exhaustion (Koren #1 latency).

    Per-case counter reset: `_pollCount` is reset to 0 on FIRST entry via
    the pre-request, guarded by a request-name-scoped `_pollStarted` flag so the
    self-re-invoking loop (setNextRequest → same request) does NOT reset on every
    iteration. Both env vars are cleared on terminal exit. This makes the iteration
    count immune to bleed from a prior case (which previously could start this loop
    mid-exhaustion → premature cap → non-deterministic assertion count).
    """
    return Step(
        name="poll-op",
        method="GET",
        path="/operations/{{opId}}",
        auth=auth,
        op_var="opId",
        pre_script=[
            *_op_id_guard("opId", required),
            "// poll-counter reset on first entry (request-name-scoped flag);",
            "// re-invocations via setNextRequest skip the reset.",
            "if (pm.environment.get('_pollStarted') !== pm.info.requestName) {",
            "  pm.environment.set('_pollCount', '0');",
            "  pm.environment.set('_pollStarted', pm.info.requestName);",
            "}",
        ],
        test_script=[
            "pm.test('poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
            "const j = pm.response.json();",
            "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
            f"if (!j.done && pc < {POLL_CAP}) {{",
            "  pm.environment.set('_pollCount', String(pc + 1));",
            # Real inter-poll delay (~500ms) between retries. newman runs test scripts
            # synchronously and fires setNextRequest before any setTimeout callback, so a
            # busy-wait is the only way to actually space out polls; POLL_CAP*0.5s then
            # covers the async-op tail (p95 3s / max 10s) instead of hammering back-to-back
            # (~15ms/poll via --delay-request 15) which never waits for the op (Koren #1).
            "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            "pm.environment.unset('_pollCount');",
            "pm.environment.unset('_pollStarted');",
            "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
            # СНЯТИЕ ФАНТОМА ЗДЕСЬ НЕ ДУБЛИРУЕТСЯ. Оно живёт на уровне коллекции
            # (POST_GLOBAL) — там оно покрывает и рукописные поллеры, которых в дереве
            # большинство. Копия в этом helper'е закрывала только его собственные шаги и,
            # вклинившись между `if (j.error) …` и его `else`, ПЕРЕПРИВЯЗАЛА этот `else`
            # к соседнему условию: `lastOpError` снимался ровно тогда, когда ошибка ЕСТЬ.
            # Потребителей у переменной в этой суите нет (0 чтений), поэтому вреда не
            # случилось — но ветка означала обратное написанному, а это ловушка для
            # следующего читателя. Условие и его `else` снова стоят рядом.
            "if (j.error) pm.environment.set('lastOpError', JSON.stringify(j.error));",
            "else pm.environment.unset('lastOpError');",
            "if (j.response) pm.environment.set('lastOpResponse', JSON.stringify(j.response));",
        ],
    )


def get_until_gone(path: str, label: str, auth: str = "jwtAccountAdminA") -> Step:
    """Reusable get-after-delete step: poll the GET until the resource is GONE.

    Replaces the previous unconditional "single GET → assert 404/403 once"
    pattern that raced the async Delete Operation: Delete returns an
    async Operation; even after the Operation-poll reports done, the soft-delete
    read-projection and FGA owner-tuple removal can lag a beat, so an immediate
    GET could still return 200 → `expected 200 to be one of [404,403]`. The
    assertion was correct; the SETUP raced.

    Here the GET is retried (bounded by POLL_CAP, via setNextRequest) until it
    returns 404 (NOT_FOUND) or 403 (FGA tuple gone → no path); only if it is
    STILL 200 after the cap do we assert and fail. This waits for the real
    terminal "gone" state deterministically — it is NOT a blanket suite retry.

    A dedicated counter (`_goneCount`) and first-entry flag (`_goneStarted`,
    request-name-scoped) keep this loop isolated from the Operation-poll loop and
    immune to cross-case bleed (same discipline as poll_operation_until_done).
    """
    return Step(
        name="get-after-delete",
        method="GET",
        path=path,
        auth=auth,
        pre_script=[
            "// gone-counter reset on first entry (request-name-scoped flag);",
            "// re-invocations via setNextRequest skip the reset.",
            "if (pm.environment.get('_goneStarted') !== pm.info.requestName) {",
            "  pm.environment.set('_goneCount', '0');",
            "  pm.environment.set('_goneStarted', pm.info.requestName);",
            "}",
        ],
        test_script=[
            "const gc = parseInt(pm.environment.get('_goneCount') || '0', 10);",
            f"if (pm.response.code === 200 && gc < {POLL_CAP}) {{",
            "  // resource not yet gone (async delete + FGA-tuple removal lag) — retry.",
            "  pm.environment.set('_goneCount', String(gc + 1));",
            # Real inter-poll delay (~500ms) between retries (Koren #1) — see
            # poll_request_until_status: back-to-back re-fires exhaust the cap before the
            # async delete + FGA-tuple removal settles, flaking the terminal "gone" RED.
            "  const _gd = Date.now(); while (Date.now() - _gd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            "pm.environment.unset('_goneCount');",
            "pm.environment.unset('_goneStarted');",
            f"pm.test({json.dumps(f'{label}: gone after delete — 404 or 403')}, () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.be.oneOf([404, 403]));",
        ],
    )


def poll_request_until_status(name: str, method: str, path: str, test_script: List[str],
                              auth: str = "jwtAccountAdminA",
                              expect_code: int = 200,
                              retry_on=(403, 404),
                              retry_predicate: Optional[str] = None,
                              body: Optional[Dict] = None) -> Step:
    """Reusable poll-for-propagation step for read-after-WRITE on a fresh resource.

    flat-RBAC is eventually-consistent on grant→access: an
    AccessBinding.Create / a forward-materialized owner/creator tuple is written
    synchronously, but its VISIBILITY at the api-gateway authz gate (the gate
    evaluates `<caller> editor|viewer on iam_access_binding:<id>` resolved via the
    binding's account-anchor parent-tuple) propagates a beat after Operation→done.
    A step that does `create → IMMEDIATELY GET/DELETE the fresh binding and asserts
    200` therefore flakes with an intermittent 403 (pre-convergence window) under
    full-pipeline CI load — even though the access is GUARANTEED to materialize
    (proven DETERMINISTICALLY by the real-OpenFGA integration tests:
    sync-live-FGA-write own-object on create + batch-chunk ≤100 + per-tuple retry
    write the tuple before Operation.done). The lag is TIMING, not a hole.

    This helper retries the SAME request (bounded by POLL_CAP, via setNextRequest)
    while the response code is in `retry_on` (the propagation-window codes, default
    403/404), and runs the case's real `test_script` only on the TERMINAL response —
    the first time the code leaves the retry set, or once the cap is hit (so a
    genuine, non-converging deny still surfaces as a real failure, never masked).

    This is the read-after-write mirror of get_until_gone (which polls the
    delete-side "gone" terminal). It is legitimate ONLY because the access is
    proven to appear; do NOT use it on negative / no-leak / must-DENY steps
    (those stay single-shot — a poll would mask a real leak).

    retry_predicate (optional): an extra JS boolean expression evaluated in the
    test_script scope. When it is truthy AND code is the expected success code, the
    step retries — for LIST read-after-write, where the RPC returns 200 but the
    fresh row is not yet in the result set (same account-anchor propagation lag).
    e.g. retry_predicate="(() => { const j = pm.response.json(); const id =
    pm.environment.get('crudAcbId'); return id && !(j.accessBindings||[]).some(b =>
    b.id === id); })()". It must converge (the row is guaranteed to appear), so a
    real never-appears bug still fails at the cap — it is NOT masked.

    A per-step counter (`_poll200_<name>`) + first-entry flag (request-name-scoped)
    isolate this loop from the Operation-poll / gone-poll loops and from other
    poll-200 steps (no cross-case / cross-step bleed; same per-case reset discipline).
    """
    safe = name.replace("-", "_")
    counter_var = f"_poll200_{safe}"
    started_var = f"_poll200_started_{safe}"
    retry_set = ",".join(str(c) for c in retry_on)
    return Step(
        name=name,
        method=method,
        path=path,
        auth=auth,
        body=body,
        pre_script=[
            "// poll-for-propagation counter reset on first entry (request-name-scoped);",
            "// re-invocations via setNextRequest skip the reset.",
            f"if (pm.environment.get('{started_var}') !== pm.info.requestName) {{",
            f"  pm.environment.set('{counter_var}', '0');",
            f"  pm.environment.set('{started_var}', pm.info.requestName);",
            "}",
        ],
        test_script=[
            f"const _p200c = parseInt(pm.environment.get('{counter_var}') || '0', 10);",
            f"const _p200retryCode = [{retry_set}].includes(pm.response.code);",
            (f"const _p200retryPred = (pm.response.code === {expect_code}) && ({retry_predicate});"
             if retry_predicate is not None else "const _p200retryPred = false;"),
            f"if ((_p200retryCode || _p200retryPred) && _p200c < {POLL_CAP}) {{",
            "  // access not yet visible at the authz gate (grant→FGA propagation window) — retry.",
            f"  pm.environment.set('{counter_var}', String(_p200c + 1));",
            # Real inter-poll delay (~500ms) between retries (Koren #1). newman fires
            # setNextRequest before any setTimeout, so a busy-wait is the only way to
            # actually space out the retries; without it POLL_CAP retries fire
            # back-to-back (~round-trip only) and exhaust the budget BEFORE the
            # grant→FGA / owner-tuple materialization window closes → a converging
            # access flakes RED at the cap. Same discipline as poll_operation_until_done.
            "  const _p200d = Date.now(); while (Date.now() - _p200d < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            f"pm.environment.unset('{counter_var}');",
            f"pm.environment.unset('{started_var}');",
            # Terminal response: the case's real assertions run exactly once.
            *test_script,
        ],
    )


def assert_op_error(code: int, code_name: str, msg_substr: Optional[str] = None,
                    msg_regex: Optional[str] = None, auth: str = AUTH_INHERIT_OP,
                    op_var: str = "opId") -> Step:
    """Поллит /operations/{op_var} до done и проверяет, что operation завершилась с error.code == code.

    The auth parameter carries a valid Bearer token: OperationService/Get is
    <exempt> in the catalog but IAM's anti-anonymous interceptor still blocks
    unauthenticated callers → 401. By default it is AUTH_INHERIT_OP — the step
    reads the operation as whoever minted `op_var` (a foreign operation is hidden
    as 404, so a hard-coded principal reads nothing).

    op_var: the env-var name holding the operation id to assert.
    A step that returns its Operation into a PER-CASE var (e.g. the :verb-action
    cases that save into `addAisOpId` / `rmOpId`) MUST pass that same var here —
    otherwise this helper reads the SHARED `opId`, which a later/other case (or
    suite) overwrites between the action and this assertion, so it polls a
    FOREIGN operation (the IAM-ACB-ADD/RM red was reading an IssueSAKey op,
    code 13). Default "opId" keeps every existing caller byte-identical.

    Poll-until-done: this is a self-re-invoking poll step
    (setNextRequest → same request, bounded by POLL_CAP) with a request-name-scoped
    counter `_opErrCount`/`_opErrStarted`, matching the green inline poll cases
    (e.g. IAM-ACB-CR-TARGET-NEG-COVERAGE). The previous single non-polling GET
    raced the async worker — the action enqueues an Operation that is not yet
    `done` on the immediate next GET — and asserted on a stale envelope.
    """
    body = [
        "const j = pm.response.json();",
        "if (pm.environment.get('_opErrStarted') !== pm.info.requestName) { pm.environment.set('_opErrCount', '0'); pm.environment.set('_opErrStarted', pm.info.requestName); }",
        "const pc = parseInt(pm.environment.get('_opErrCount') || '0', 10);",
        f"if (!j.done && pc < {POLL_CAP}) {{",
        "  pm.environment.set('_opErrCount', String(pc + 1));",
        "  const _ipd1 = Date.now(); while (Date.now() - _ipd1 < 500) void 0; /* real inter-poll delay: cap 50 x 500ms ~= 25s budget (testing.md) */",
        "  pm.execution.setNextRequest(pm.info.requestName);",
        "  return;",
        "}",
        "pm.environment.unset('_opErrCount');",
        "pm.environment.unset('_opErrStarted');",
        "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
        f"pm.test('error code {code} ({code_name})', () => pm.expect(j.error && j.error.code, JSON.stringify(j)).to.eql({code}));",
    ]
    if msg_substr is not None:
        body.append(f"pm.test('error text includes \"{msg_substr}\"', () => pm.expect((j.error && j.error.message || '').toLowerCase(), JSON.stringify(j)).to.include('{msg_substr.lower()}'));")
    if msg_regex is not None:
        body.append(f"pm.test('error text matches /{msg_regex}/', () => pm.expect(j.error && j.error.message || '', JSON.stringify(j)).to.match(/{msg_regex}/));")
    return Step(name="assert-op-error", method="GET", path="/operations/{{" + op_var + "}}",
                auth=auth, op_var=op_var, pre_script=_op_id_guard(op_var, True), test_script=body)


def assert_op_success(auth: str = AUTH_INHERIT_OP, op_var: str = "opId") -> Step:
    """The auth parameter ensures the step carries a valid Bearer token; by default
    it inherits the principal that minted `op_var` (AUTH_INHERIT_OP)."""
    return Step(name="assert-op-success", method="GET", path="/operations/{{" + op_var + "}}",
                auth=auth, op_var=op_var, pre_script=_op_id_guard(op_var, True),
                test_script=[
                    "const j = pm.response.json();",
                    "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                    "pm.test('operation succeeded (response, no error)', () => pm.expect(Boolean(j.response) && !j.error, JSON.stringify(j)).to.eql(true));",
                ])


# ---------------------------------------------------------------------------
# Переиспользуемые блоки кейсов (compute-specific, generic)
# ---------------------------------------------------------------------------

def list_page_block(prefix, list_path, folder_param=True):
    """BVA для List RPC: page_size 0 / 1 / 1000 / 1001 / garbage token.

    folder_param=True — list_path требует ?projectId=... (Disk/Image/Snapshot/Instance);
    folder_param=False — справочники (DiskType/Zone) — без projectId.
    """
    base = f"{list_path}?projectId={{{{_suiteProjectId}}}}&" if folder_param else f"{list_path}?"
    return [
        Case(id=f"{prefix}-LST-BVA-PAGESIZE-ZERO",
             title="List pageSize=0 → default applied (200)",
             classes=["BVA", "PAGE"], priority="P2",
             steps=[Step(name="ps0", method="GET", path=f"{base}pageSize=0",
                         test_script=[*assert_status(200)])]),
        Case(id=f"{prefix}-LST-BVA-PAGESIZE-1",
             title="List pageSize=1 → ≤1 item",
             classes=["BVA", "PAGE"], priority="P2",
             steps=[Step(name="ps1", method="GET", path=f"{base}pageSize=1",
                         test_script=[*assert_status(200),
                                      "pm.test('at most 1 item', () => { const j = pm.response.json(); const k = Object.keys(j).find(x => Array.isArray(j[x])); pm.expect((j[k]||[]).length).to.be.at.most(1); });"])]),
        Case(id=f"{prefix}-LST-BVA-PAGESIZE-MAX-1000",
             title="List pageSize=1000 (boundary max) → 200",
             classes=["BVA", "PAGE"], priority="P2",
             steps=[Step(name="ps1000", method="GET", path=f"{base}pageSize=1000",
                         test_script=[*assert_status(200)])]),
        Case(id=f"{prefix}-LST-BVA-PAGESIZE-OVER-1001",
             title="List pageSize=1001 (over max) → 400 InvalidArgument",
             classes=["BVA", "VAL"], priority="P1",
             steps=[Step(name="ps1001", method="GET", path=f"{base}pageSize=1001",
                         test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT")])]),
        Case(id=f"{prefix}-LST-PAGE-TOKEN-GARBAGE",
             title="List с garbage page_token → 400 InvalidArgument",
             classes=["PAGE", "VAL"], priority="P1",
             steps=[Step(name="bad-token", method="GET", path=f"{base}pageSize=10&pageToken=not-a-real-token",
                         test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT")])]),
    ]


def name_validation_block(prefix, create_path, body_extra=None, wrap=None):
    """ECP/BVA по полю name для compute (lowercase-only regex `|[a-z]([-_a-z0-9]{0,61}[a-z0-9])?`):
      - empty name → 200 (proto pattern допускает пустую строку)
      - len=63 (max) → 200
      - len=64 (over) → 400
      - UPPERCASE → 400  (compute lowercase-only — НЕ как VPC)
      - начинается с цифры → 400
      - начинается с дефиса → 400
      - спец-символы → 400

    body_extra — обязательные поля кроме projectId/name.
    wrap(case) — опциональный декоратор (для Image/Snapshot/Instance которым нужен pre-disk и т.п.);
                 если задан — name-кейсы которые ожидают 200 оборачиваются (нужен реальный ресурс),
                 остальные (400) — нет (отказ синхронный, до создания зависимостей).
    """
    body_extra = body_extra or {}
    wrap = wrap or (lambda c: c)
    base = lambda name: {"projectId": "{{_suiteProjectId}}", "name": name, **body_extra}
    out = []
    out.append(wrap(Case(id=f"{prefix}-CR-VAL-NAME-EMPTY-OK",
        title="Create с empty name → 200 (proto pattern допускает пустую строку)",
        classes=["VAL", "BVA"], priority="P2",
        steps=[Step(name="cr-empty", method="POST", path=create_path, body=base(""),
                    test_script=[*assert_status(200), *save_from_response("j.id", "opId")]),
               poll_operation_until_done()])))
    out.append(wrap(Case(id=f"{prefix}-CR-BVA-NAME-MAX-63",
        title="Create с name len=63 (max) → 200",
        classes=["BVA"], priority="P2",
        steps=[Step(name="cr-max63", method="POST", path=create_path,
                    body=base("n" + "abcdefghij" * 6 + "ab"),  # 1+60+2 = 63
                    test_script=[*assert_status(200), *save_from_response("j.id", "opId")]),
               poll_operation_until_done()])))
    out.append(Case(id=f"{prefix}-CR-BVA-NAME-OVER-64",
        title="Create с name len=64 (over-max) → 400 InvalidArgument",
        classes=["BVA", "VAL"], priority="P1",
        steps=[Step(name="cr-over", method="POST", path=create_path,
                    body=base("n" + "abcdefghij" * 6 + "abc"),  # 64
                    test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT")])]))
    out.append(Case(id=f"{prefix}-CR-VAL-NAME-UPPERCASE",
        title="Create с UPPERCASE name → 400 (compute lowercase-only — НЕ как VPC)",
        classes=["VAL"], priority="P1",
        steps=[Step(name="cr-upper", method="POST", path=create_path, body=base("InvalidUpper-{{runId}}"),
                    test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT")])]))
    out.append(Case(id=f"{prefix}-CR-VAL-NAME-DIGIT-START",
        title="Create с name начинающимся с цифры → 400 (name regex)",
        classes=["VAL"], priority="P1",
        steps=[Step(name="cr-digit", method="POST", path=create_path, body=base("9invalid-{{runId}}"),
                    test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT")])]))
    out.append(Case(id=f"{prefix}-CR-VAL-NAME-HYPHEN-START",
        title="Create с name начинающимся с дефиса → 400",
        classes=["VAL"], priority="P1",
        steps=[Step(name="cr-hyphen", method="POST", path=create_path, body=base("-bad-{{runId}}"),
                    test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT")])]))
    out.append(Case(id=f"{prefix}-CR-VAL-NAME-SPECIAL-CHARS",
        title="Create с спец-символами в name → 400",
        classes=["VAL"], priority="P1",
        steps=[Step(name="cr-special", method="POST", path=create_path, body=base("name!@#-{{runId}}"),
                    test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT")])]))
    return out


def labels_validation_block(prefix, create_path, body_extra=None, wrap=None):
    """ECP по labels: uppercase key → 400; invalid key char → 400; 64 (max) → 200; 65 (over) → 400."""
    body_extra = body_extra or {}
    wrap = wrap or (lambda c: c)
    base = lambda name, labels: {"projectId": "{{_suiteProjectId}}", "name": name, "labels": labels, **body_extra}
    return [
        Case(id=f"{prefix}-CR-VAL-LABELS-UPPERCASE-KEY",
             title="Create с UPPERCASE label key → 400",
             classes=["VAL"], priority="P1",
             steps=[Step(name="cr-lbl-up", method="POST", path=create_path,
                         body=base(f"{prefix.lower()}-lblup-{{{{runId}}}}", {"BADKEY": "v"}),
                         test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT")])]),
        Case(id=f"{prefix}-CR-VAL-LABELS-INVALID-KEY-CHAR",
             title="Create с invalid char в label key → 400",
             classes=["VAL"], priority="P1",
             steps=[Step(name="cr-lbl-bad", method="POST", path=create_path,
                         body=base(f"{prefix.lower()}-lblbad-{{{{runId}}}}", {"bad key!": "v"}),
                         test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT")])]),
        wrap(Case(id=f"{prefix}-CR-BVA-LABELS-MAX-64",
             title="Create с 64 labels (max) → 200",
             classes=["BVA"], priority="P2",
             steps=[Step(name="cr-lbl-max", method="POST", path=create_path,
                         body=base(f"{prefix.lower()}-lblm-{{{{runId}}}}", {f"k{i}": f"v{i}" for i in range(64)}),
                         test_script=[*assert_status(200), *save_from_response("j.id", "opId")]),
                    poll_operation_until_done()])),
        Case(id=f"{prefix}-CR-BVA-LABELS-OVER-65",
             title="Create с 65 labels (over-max) → 400",
             classes=["BVA", "VAL"], priority="P1",
             steps=[Step(name="cr-lbl-over", method="POST", path=create_path,
                         body=base(f"{prefix.lower()}-lblo-{{{{runId}}}}", {f"k{i}": f"v{i}" for i in range(65)}),
                         test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT")])]),
    ]


def description_validation_block(prefix, create_path, body_extra=None, wrap=None):
    """BVA по description: 256 (max) → 200; 257 (over) → 400."""
    body_extra = body_extra or {}
    wrap = wrap or (lambda c: c)
    base = lambda name, desc: {"projectId": "{{_suiteProjectId}}", "name": name, "description": desc, **body_extra}
    return [
        wrap(Case(id=f"{prefix}-CR-BVA-DESC-MAX-256",
             title="Create с description len=256 (max) → 200",
             classes=["BVA"], priority="P2",
             steps=[Step(name="cr-desc-max", method="POST", path=create_path,
                         body=base(f"{prefix.lower()}-descm-{{{{runId}}}}", "x" * 256),
                         test_script=[*assert_status(200), *save_from_response("j.id", "opId")]),
                    poll_operation_until_done()])),
        Case(id=f"{prefix}-CR-BVA-DESC-OVER-257",
             title="Create с description len=257 (over-max) → 400",
             classes=["BVA", "VAL"], priority="P1",
             steps=[Step(name="cr-desc-over", method="POST", path=create_path,
                         body=base(f"{prefix.lower()}-d2-{{{{runId}}}}", "x" * 257),
                         test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT")])]),
    ]


def filter_block(prefix, list_path):
    """Filter syntax: name="X" → 200; garbage → 200|400; unknown field → 200|400."""
    sep = "&"
    return [
        Case(id=f"{prefix}-LST-FILTER-NAME-OK",
             title="List с filter name=\"foo\" → 200",
             classes=["FILTER", "CRUD"], priority="P2",
             steps=[Step(name="flt-ok", method="GET",
                         path=f"{list_path}?projectId={{{{_suiteProjectId}}}}{sep}filter=name%3D%22foo%22",
                         test_script=[*assert_status(200)])]),
        Case(id=f"{prefix}-LST-FILTER-GARBAGE",
             title="List с garbage filter syntax → 200 или 400",
             classes=["FILTER", "VAL"], priority="P2",
             steps=[Step(name="flt-bad", method="GET",
                         path=f"{list_path}?projectId={{{{_suiteProjectId}}}}{sep}filter=this%20is%20not%20valid%20syntax",
                         test_script=["pm.test('200 or 400', () => pm.expect(pm.response.code).to.be.oneOf([200, 400]));"])]),
        Case(id=f"{prefix}-LST-FILTER-UNKNOWN-FIELD",
             title="List с filter на unsupported field → 200 или 400",
             classes=["FILTER", "VAL"], priority="P2",
             steps=[Step(name="flt-unk", method="GET",
                         path=f"{list_path}?projectId={{{{_suiteProjectId}}}}{sep}filter=nonexistent_field%3D%22x%22",
                         test_script=["pm.test('200 or 400', () => pm.expect(pm.response.code).to.be.oneOf([200, 400]));"])]),
    ]


def security_injection_block(prefix, create_path, list_path, body_extra=None):
    """Security probes: SQL/cmd/XSS injection в name; никогда 500 / нет утечки pgx-stack."""
    body_extra = body_extra or {}
    injections = [
        ("sqli", "test' OR 1=1--"),
        ("union", "x' UNION SELECT * FROM operations--"),
        ("xss", "<script>alert(1)</script>"),
        ("cmd", "; rm -rf / ;"),
        ("path", "../../etc/passwd"),
        ("longpayload", "a" * 200),
    ]
    out = []
    for name, payload in injections:
        out.append(Case(id=f"{prefix}-CR-SEC-{name.upper()}",
            title=f"Security probe: {name} в name → handled, без 500/leak",
            classes=["SEC", "VAL", "NEG"], priority="P0",
            steps=[Step(name=f"sec-{name}", method="POST", path=create_path,
                        body={"projectId": "{{_suiteProjectId}}", "name": payload[:200], **body_extra},
                        test_script=[
                            "pm.test('not 500', () => pm.expect(pm.response.code).to.not.eql(500));",
                            "pm.test('handled 2xx/4xx', () => pm.expect(pm.response.code).to.be.oneOf([200, 400, 413]));",
                            "const body = JSON.stringify(pm.response.json() || {}).toLowerCase();",
                            "pm.test('no panic/sqlstate/stacktrace leak', () => { pm.expect(body).to.not.include('panic'); pm.expect(body).to.not.include('sqlstate'); pm.expect(body).to.not.include('goroutine'); });",
                        ])]))
    out.append(Case(id=f"{prefix}-LST-SEC-FILTER-SQLI",
        title="Security: SQL injection в filter → не 500",
        classes=["SEC", "VAL", "NEG"], priority="P0",
        steps=[Step(name="lst-sqli", method="GET",
                    path=f"{list_path}?projectId={{{{_suiteProjectId}}}}&filter=name%3D%22a%27%20OR%201%3D1--%22",
                    test_script=["pm.test('not 500', () => pm.expect(pm.response.code).to.not.eql(500));",
                                 "pm.test('handled', () => pm.expect(pm.response.code).to.be.oneOf([200, 400]));"])]))
    return out


def http_method_block(prefix, base_path):
    """HTTP method semantics: PUT / DELETE-on-list → 404|405|501."""
    return [
        Case(id=f"{prefix}-METHOD-PUT-NOT-ALLOWED",
             title="PUT на List endpoint → 404/405/501",
             classes=["VAL", "NEG"], priority="P3",
             steps=[Step(name="put-list", method="PUT", path=base_path, body={"projectId": "{{_suiteProjectId}}"},
                         test_script=["pm.test('not allowed', () => pm.expect(pm.response.code).to.be.oneOf([404, 405, 501]));"])]),
        Case(id=f"{prefix}-METHOD-DELETE-LIST",
             title="DELETE на List endpoint (без id) → 404/405/501",
             classes=["VAL", "NEG"], priority="P3",
             steps=[Step(name="del-list", method="DELETE", path=base_path,
                         test_script=["pm.test('not allowed', () => pm.expect(pm.response.code).to.be.oneOf([404, 405, 501]));"])]),
    ]


def malformed_body_block(prefix, create_path):
    """Malformed JSON / empty body."""
    return [
        Case(id=f"{prefix}-CR-VAL-MALFORMED-JSON",
             title="Create с malformed JSON → 400/415",
             classes=["VAL", "NEG"], priority="P2",
             steps=[Step(name="cr-malformed", method="POST", path=create_path, body=None,
                         pre_script=["pm.request.body = { mode: 'raw', raw: '{invalid json---}' };"],
                         test_script=["pm.test('400 or 415', () => pm.expect(pm.response.code).to.be.oneOf([400, 415]));"])]),
        Case(id=f"{prefix}-CR-VAL-EMPTY-BODY",
             title="Create с пустым body → 400 (project_id required)",
             classes=["VAL", "NEG"], priority="P2",
             steps=[Step(name="cr-empty-body", method="POST", path=create_path, body={},
                         test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT")])]),
    ]


# ---------------------------------------------------------------------------
# Сериализация в Postman v2.1
# ---------------------------------------------------------------------------

def _auth_pre_script(auth: str) -> List[str]:
    """Generates the JS snippet for a per-step Authorization header override.

    Для "anonymous" — снимает Authorization. Для имени env-переменной —
    Authorization: Bearer <значение env-var>. Snippet идет в начало
    step.pre_script, перед всеми остальными pre-script строками."""
    if auth == AUTH_INHERIT_OP:
        # Unresolved sentinel: case_to_postman resolves it before this point. Reaching
        # here means a Step bypassed the case builder — fail loudly rather than emit a
        # step whose principal is a literal control character.
        raise ValueError("AUTH_INHERIT_OP reached _auth_pre_script unresolved — "
                         "steps must be emitted through case_to_postman()")
    if auth == "anonymous":
        return [
            "// per-step auth: anonymous step",
            "pm.request.headers.remove('Authorization');",
        ]
    return [
        f"// per-step auth: bearer from env '{auth}'",
        f"const __t = pm.environment.get('{auth}') || pm.variables.get('{auth}') || '';",
        "if (__t) {",
        "  pm.request.headers.upsert({key: 'Authorization', value: 'Bearer ' + __t});",
        "} else {",
        # HARNESS-CONFIG GUARD. An `auth="<envVar>"` step names a SUBJECT the case
        # is about ("a never-granted user must see nothing", "a foreign editor must
        # be denied"). If the fixture seed never wrote that variable, silently
        # dropping the header does not skip the check — it runs it as ANONYMOUS,
        # against a different subject entirely. The typical expectation (401/403)
        # then still holds, so the case passes FOR THE WRONG REASON and the subject
        # under test is never exercised. Missing subject = misconfigured harness:
        # FAIL naming the variable, THEN SKIP — the sanctioned shape, identical to
        # gen.py::require_env_url. Dropping the header and sending anyway is NOT the
        # sanctioned shape: the step still travels, and every OTHER assertion it
        # carries is then scored against a principal the case never named.
        # `pm.execution.skipRequest()` skips exactly one request — its test script
        # does not run either — so nothing of this step is scored, while the
        # pre-request assertion above has ALREADY run and keeps the skip RECORDED as
        # a failure naming the variable, never a mute one. (`auth="anonymous"` is the
        # DELIBERATE anonymous case and takes the branch above — never affected.)
        f"  pm.test('harness config: {auth} is set (subject under test)', () => {{",
        f"    pm.expect.fail('{auth} is not set — the authz-fixture seed "
        "(tests/authz-fixtures/setup.sh) did not provide this subject. Running the step "
        "anonymously would test a DIFFERENT principal and pass for the wrong reason.');",
        "  });",
        "  pm.execution.skipRequest();",
        "}",
    ]


def step_to_postman(step: Step) -> Dict:
    item: Dict = {
        "name": step.name,
        "request": {
            "method": step.method,
            "header": [{"key": "Content-Type", "value": "application/json"}],
            "url": {
                "raw": "{{baseUrl}}" + step.path,
                "host": ["{{baseUrl}}"],
                "path": [p for p in step.path.strip("/").split("/") if p],
            },
        },
    }
    if step.insecure_tls:
        item["protocolProfileBehavior"] = {"strictSSL": False}
    if step.body is not None:
        item["request"]["body"] = {
            "mode": "raw",
            "raw": json.dumps(step.body, ensure_ascii=False),
            "options": {"raw": {"language": "json"}},
        }
    pre = list(step.pre_script)
    if step.auth is not None:
        pre = _auth_pre_script(step.auth) + pre
    # Страж адреса — ПОСЛЕДНИМ в пред-скрипте шага, а не в общем событии коллекции.
    #
    # Newman исполняет prerequest коллекции ДО prerequest шага, всегда. Пока страж
    # стоял там, он выносил вердикт о переменных адреса РАНЬШЕ, чем шаг успевал
    # присвоить те из них, которыми владеет сам. Шаг, который готовит переменную для
    # собственного адреса в своём же пред-скрипте, получал отказ на КАЖДОМ прогоне —
    # независимо от того, была ли переменная в действительности захвачена: в момент
    # проверки её ещё не существовало и существовать не могло.
    #
    # Предмет стража от переноса не меняется: он всё так же ловит запрос, который
    # ушёл бы литералом `{{…}}`. Меняется только момент — теперь после того, как
    # отработали все законные производители этого адреса, включая сам шаг.
    # Переменная, которую не задал НИКТО, по-прежнему находка.
    pre = pre + _URL_VAR_GUARD
    events = []
    if pre:
        events.append({"listen": "prerequest", "script": {"type": "text/javascript", "exec": pre}})
    if step.test_script:
        events.append({"listen": "test", "script": {"type": "text/javascript", "exec": step.test_script}})
    if events:
        item["event"] = events
    return item


# --- Класс: первый доступ к СВОЕМУ свежему ресурсу без ограниченного ретрая ---
#
# Обёртка `retry_until_authorized` ставилась ВРУЧНУЮ, поэтому её пропуск был
# неотличим от решения не оборачивать. Замер по артефактам прогона CI
# 31002239590 (8 суит, 82 отчёта, 15648 утверждений, 151 падение): из 68
# падений полосы видимости (403/404) **42** пришлись на шаги, у которых обёртки
# не было ВОВСЕ, при том что соседние шаги той же формы в тех же кейсах
# обёрнуты — то есть пропуск, а не замысел.
#
# Предикат ставит обёртку ПО СВОЙСТВУ шага, а не по списку имён, и потому
# закрывает класс, а не перечисленные экземпляры. Четыре условия — все
# обязательны:
#   1. шаг УТВЕРЖДАЕТ УСПЕХ — то есть 200 входит в набор исходов, которые он
#      принимает, а 403 в него НЕ входит. Набор читается и из `to.eql(200)`, и
#      из `to.be.oneOf([...])` над `pm.response.code`: уборка своего свежего
#      ресурса сплошь записана вторым способом («удалилось 200 ЛИБО состояние
#      не позволило 400»), и пока предикат смотрел на буквальное `to.eql(200)`,
#      такие шаги были ему невидимы ПО ПОСТРОЕНИЮ — в суите vpc это 77 записей
#      из 93. Шаг, принимающий 403 своим исходом (authz-first толерантность
#      негатива), не оборачивается никогда: там отказ и есть проверяемое, а
#      ретрай маскировал бы его (`testing.md` — «НЕ оборачивать: negatives,
#      cross-account deny»). Пережидаются ТОЛЬКО те коды полосы видимости,
#      которых шаг исходом не заявлял: если 404 заявлен («уже нет»), ретрай
#      идёт лишь по 403, иначе обёртка жгла бы бюджет на принятом исходе;
#   2. адрес шага ссылается на переменную, РОЖДЁННУЮ РАНЕЕ В ЭТОМ ЖЕ КЕЙСЕ
#      (её published предыдущий шаг). Чужой/заранее известный id предикату
#      неизвестен — значит absent-id-негативы остаются строгими;
#   3. у шага НЕТ собственной петли (`setNextRequest`) — поллер операции ведёт
#      свою и переименован под себя; вторая петля сломала бы резолв имени;
#   4. шаг ещё не обёрнут вручную (идемпотентность).
#
# Доказательство в обе стороны — `scripts/selftest_autowrap.py`: инъекция
# настоящего пропуска (краснеет без предиката) и ЧЕТЫРЕ законных близнеца
# (негатив, поллер, уже обёрнутый, чужой id), на которых предикат обязан
# молчать.
_FRESH_VAR_SET_RE = re.compile(
    r"pm\.(?:environment|collectionVariables|globals)\.set\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]"
)
_VAR_REF_RE = re.compile(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}")

# Набор HTTP-исходов, которые шаг ПРИНИМАЕТ. Оба выражения привязаны к
# `pm.response.code`, поэтому набор gRPC-кодов (`pm.expect(j.code, …).to.be
# .oneOf([5, 9])`) сюда не попадает: числа там из другого пространства и на
# полосу видимости не отображаются. Границей служит `;` — конец стейтмента.
_HTTP_EQ_RE = re.compile(r"pm\.response\.code[^;]*?\.to\.eql\((\d{3})\)")
_HTTP_ONEOF_RE = re.compile(r"pm\.response\.code[^;]*?\.to\.be\.oneOf\(\[([0-9,\s]+)\]\)")


def _accepted_http_codes(body: str) -> set:
    """HTTP-коды, объявленные шагом как приемлемый исход."""
    acc = set()
    for m in _HTTP_EQ_RE.finditer(body):
        acc.add(int(m.group(1)))
    for m in _HTTP_ONEOF_RE.finditer(body):
        for part in m.group(1).split(","):
            part = part.strip()
            if part:
                acc.add(int(part))
    return {c for c in acc if 100 <= c <= 599}


def _wrap_own_fresh_reads(steps: List[Step], rename: bool = True) -> List[Step]:
    """Обернуть положительные первые обращения к своему свежему ресурсу.

    Возвращает НОВЫЙ список шагов; исходные Step не мутируются.

    `rename=False` — для генератора, который САМ делает имена шагов глобально
    уникальными при сериализации (iam: `<case-id> :: <шаг>`) и переписывает
    буквальные переходы `setNextRequest('<сосед>')` по БАЗОВЫМ именам. Там
    переименование обёрткой сломало бы резолв такого перехода, а нужды в нём
    нет: `pm.info.requestName` резолвится в итоговое имя, уже уникальное.
    """
    fresh: set = set()
    out: List[Step] = []
    for st in steps:
        body = "\n".join(st.test_script)
        self_looped = "setNextRequest" in body
        already = "_authRetryCount" in body or "_absRetryCount" in body
        accepted = _accepted_http_codes(body) if st.test_script else set()
        # Ждать можно ТОЛЬКО код, который шаг исходом не заявлял, — тогда
        # ожидание ничего не маскирует по построению: если 403/404 названы
        # приемлемым исходом, шаг про них и спрашивает, и ретрай там запрещён.
        # Требования «шаг обязан ждать 200» больше нет: отрицательная проба
        # СВОЕГО СВЕЖЕГО ресурса («такой CIDR отвергается») тоже упирается в
        # окно видимости и получает 403 вместо ожидаемого 400 — то есть падает
        # не по своему предмету. Чужой аккаунт, посеянный и несуществующий id
        # под правило не подпадают: они не рождены в этом кейсе.
        # Шаг без единого утверждения ждёт только 403: у чтения/уборки 404
        # часто законное «уже нет», и жечь на нём бюджет незачем.
        retry_on = tuple(c for c in (403, 404) if c not in accepted)
        if not accepted:
            retry_on = (403,)
        if st.test_script and not self_looped and not already and 403 not in accepted and retry_on:
            if _VAR_REF_RE.findall(st.path) and (set(_VAR_REF_RE.findall(st.path)) & fresh):
                w = retry_until_authorized(st, retry_on=retry_on)
                st = replace(w, name=st.name) if not rename else w
                body = "\n".join(st.test_script)
        for name in _FRESH_VAR_SET_RE.findall(body):
            fresh.add(name)
        out.append(st)
    return out



def case_to_postman(case: Case) -> Dict:
    # Обёртка первого доступа к своему свежему ресурсу ставится ПЕРЕД любой
    # обработкой имён: `rename=False` — iam сам делает имена глобально
    # уникальными (`<case-id> :: <шаг>`) и переписывает буквальные переходы
    # по БАЗОВЫМ именам, поэтому переименование обёрткой сломало бы резолв.
    case = replace(case, steps=_wrap_own_fresh_reads(case.steps, rename=False))
    tags = [f"class:{c}" for c in case.classes] + [f"priority:{case.priority}"]

    # HARNESS FIX: step names MUST be globally UNIQUE across the whole collection.
    # Newman's `setNextRequest(<name>)`
    # resolves a name to the FIRST item with that name in the entire collection — so
    # when many cases reuse a shared reusable-helper step name (`poll-op`,
    # `get-after-delete`, `create`, `delete` …), a self-re-poll loop
    # (`setNextRequest(pm.info.requestName)`) jumps to the FIRST same-named step,
    # which lives in an EARLIER case. The runner then traverses forward from there,
    # SKIPPING the current case's own intervening steps (e.g. IAM-ACC-DL-CRUD-OK's
    # `delete` was never issued → the account was never deleted → get-after-delete
    # GET stayed 200 for all POLL_CAP retries). Same class of bug already fixed
    # case-locally in authz-deny.py; this is the collection-wide root-cause fix.
    #
    # We prefix every step name with the case id (globally unique). `pm.info.requestName`
    # is dynamic (always the CURRENT request) so the self-loops keep working. Any
    # INTRA-case literal `setNextRequest('<siblingStep>')` is rewritten to the prefixed
    # sibling name so cross-step jumps still resolve (the only literal targets are
    # intra-case: iam-access-binding `'create'`, authz-deny `'delete-ab-teardown'`).
    # Per-case occurrence index disambiguates a step name that repeats WITHIN one
    # case (e.g. a case with two `poll_operation_until_done()` steps both named
    # `poll-op`): the 2nd+ occurrence gets a `#N` suffix so every collection item is
    # globally unique (a self-loop `setNextRequest(pm.info.requestName)` is dynamic and
    # still resolves to the correct occurrence). The FIRST occurrence keeps the bare
    # name so intra-case literal `setNextRequest('<sibling>')` jumps (which only ever
    # target single-occurrence steps: `create`, `delete-ab-teardown`) still resolve.
    # First-occurrence unique name per bare step name — the target of any intra-case
    # literal `setNextRequest('<sibling>')` jump (those only target single-occurrence
    # steps such as `create` / `delete-ab-teardown`).
    def _first_uniq(step_name: str) -> str:
        return f"{case.id} :: {step_name}"

    # Assign the final, globally-unique collection name per step, suffixing the 2nd+
    # in-case occurrence of a repeated bare name with `#N`.
    _seen: Dict[str, int] = {}
    final_names: List[str] = []
    for s in case.steps:
        n = _seen.get(s.name, 0)
        suffix = "" if n == 0 else f" #{n + 1}"
        final_names.append(f"{case.id} :: {s.name}{suffix}")
        _seen[s.name] = n + 1

    sibling_names = {s.name for s in case.steps}

    def _rewrite_jumps(lines: List[str]) -> List[str]:
        out = []
        for ln in lines:
            for sib in sibling_names:
                # Match both single- and double-quoted literal setNextRequest targets.
                ln = ln.replace(f"setNextRequest('{sib}')", f"setNextRequest('{_first_uniq(sib)}')")
                ln = ln.replace(f'setNextRequest("{sib}")', f'setNextRequest("{_first_uniq(sib)}")')
            out.append(ln)
        return out

    items = []
    # AUTH_INHERIT_OP resolution — "poll the Operation as whoever MINTED it".
    #
    # Walk the case in execution order carrying a var → principal map of who captured
    # which operation id. A poll/assert step marked AUTH_INHERIT_OP takes the
    # principal of the nearest PRECEDING step that captured its `op_var`; with no
    # local producer (the id came from an earlier case / fixture) the historical
    # default applies. An `anonymous` step is never registered as a producer — an
    # anonymous mutation is a 401 negative that mints nothing, and inheriting it
    # would silently turn the poll into a second anonymous probe that passes for the
    # wrong reason.
    op_producer: Dict[str, str] = {}
    for idx, s in enumerate(case.steps):
        auth = s.auth
        if auth == AUTH_INHERIT_OP:
            auth = op_producer.get(s.op_var or "opId", DEFAULT_OP_POLL_AUTH)
        if s.auth and s.auth not in ("anonymous", AUTH_INHERIT_OP):
            for var in _captured_op_vars(s.test_script):
                op_producer[var] = s.auth
        # `replace` and NOT a field-by-field `Step(...)`: this rebuild used to
        # enumerate the fields it copied, so every field added to Step afterwards was
        # silently dropped here. `insecure_tls` was lost exactly that way — the case
        # asked for it, the generated collection did not carry it, and the request
        # failed on certificate verification with no hint that the setting had gone
        # missing in transit. Copy-by-default; name only what changes.
        s2 = replace(
            s,
            name=final_names[idx],
            pre_script=_rewrite_jumps(list(s.pre_script)),
            test_script=_rewrite_jumps(list(s.test_script)),
            auth=auth,
        )
        items.append(step_to_postman(s2))

    return {
        "name": f"{case.id} — {case.title}",
        "description": " | ".join(tags),
        "item": items,
    }


def build_collection(resource: str, cases: List[Case]) -> Dict:
    # Deterministic _postman_id (UUIDv5 over the resource name) so regen is
    # idempotent — a random uuid4 here rewrote the id on every run, producing
    # a spurious one-line diff in EVERY committed collection even when no case
    # changed (noise + false "stale collection" signals). Same input → same id.
    return {
        "info": {
            "_postman_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"kacho-iam/newman/{resource}")),
            "name": f"kacho-iam / newman / {resource}",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "event": [
            {"listen": "prerequest", "script": {"type": "text/javascript", "exec": PRE_GLOBAL}},
            {"listen": "test", "script": {"type": "text/javascript", "exec": POST_GLOBAL}},
        ],
        "item": [case_to_postman(c) for c in cases],
        "variable": [],
    }



# ---------------------------------------------------------------------------
# Страж класса: провизорный идентификатор обязан сниматься тем, кто первым узнал
# исход операции
# ---------------------------------------------------------------------------
#
# ЧТО ЗАПРЕЩАЕТСЯ. `metadata.<res>Id` доступен СРАЗУ, до `done`, и другого источника
# идентификатора до завершения операции нет — поэтому захват отменить нельзя. Но этот
# идентификатор ПРЕДВЫДЕЛЕН и приходит даже у операции, которая закончится ОШИБКОЙ.
# Тогда в переменной остаётся идентификатор ресурса, которого в базе нет. Он выглядит
# настоящим, поэтому кейс не падает на месте, а уезжает дальше и производит сотни
# производных отказов вокруг несуществующего объекта.
#
# ГДЕ ЕДИНСТВЕННОЕ МЕСТО СНЯТИЯ. Шаг опроса операции — первый момент, когда исход
# известен. Значит требование адресуется ему, а не автору кейса.
#
# ПОЧЕМУ СТРАЖ ЧИТАЕТ СГЕНЕРИРОВАННОЕ, А НЕ ИСХОДНИК. Поллеров в дереве два рода:
# общий (`poll_operation_until_done`) и рукописные, вшитые прямо в кейс. Проверка по
# исходникам видела бы только первый род — а промах жил ровно во втором. Исполняемая
# коллекция уравнивает оба.
#
# ПРЕДПОСЫЛКА СТРАЖА И ЕЁ ПРОВЕРКА. Страж опирается на два факта о дереве: (1) захват
# из метаданных РЕГИСТРИРУЕТ имя переменной в `_provisionalIds` (см.
# `save_from_response`) — если регистрация исчезнет, стражу нечего будет требовать и он
# обязан это заметить; (2) «ноль находок» обязано быть отличимо от «ноль прочитанного»,
# поэтому перепись осмотренного возвращается вместе с находками и вызывающий её печатает.

_JS_LINE_COMMENT = re.compile(r"//.*$", re.M)
_JS_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def _executable_js(lines: List[str]) -> str:
    """Скрипт без комментариев.

    Гейт по сырому тексту находит искомое слово в комментарии, ОБЪЯСНЯЮЩЕМ эту же
    защиту, и остаётся зелёным при снятой защите (testing.md, «гейт читает исполняемую
    часть, а не текст»). Строковые литералы здесь не вырезаются намеренно: имя
    переменной окружения — это и есть литерал, и он часть исполняемого смысла.
    """
    return _JS_LINE_COMMENT.sub(" ", _JS_BLOCK_COMMENT.sub(" ", "\n".join(lines)))


def _test_code(item: Dict) -> str:
    return "\n".join(_executable_js(ev.get("script", {}).get("exec", []))
                     for ev in item.get("event", []) or []
                     if ev.get("listen") == "test")


def _leaf_steps(node: Dict) -> List[Dict]:
    out: List[Dict] = []
    for it in node.get("item", []) or []:
        if "item" in it:
            out.extend(_leaf_steps(it))
        else:
            out.append(it)
    return out


def _url_raw(item: Dict) -> str:
    u = (item.get("request") or {}).get("url")
    return u.get("raw", "") if isinstance(u, dict) else (u or "")


def _drops_provisional(code: str) -> bool:
    """Скрипт снимает провизорные идентификаторы, когда операция кончилась ошибкой.

    Две законные формы: снятие общего реестра (`_provisionalIds` + `unset`) и адресное
    снятие именованной переменной внутри ветки `j.error`.
    """
    if "_provisionalIds" in code and "unset" in code:
        return True
    return re.search(r"j\.error\s*\)\s*\{?\s*pm\.environment\.unset\(", code) is not None


def audit_phantom_drop(collections_dir: Path) -> Dict:
    """Перепись + находки класса «фантомный идентификатор переживает ошибку операции».

    Возвращает словарь с переписью (сколько прочитано) и списком находок — папка кейса,
    которая РЕГИСТРИРУЕТ провизорный идентификатор, но чей опрос операции не снимает его
    на ошибке. Ничего не печатает: решение и печать — за вызывающим.
    """
    findings: List[str] = []
    census = {"collections": 0, "steps": 0, "folders": 0, "registering_folders": 0, "pollers": 0}
    collection_level_drop = 0
    for path in sorted(collections_dir.glob("*.json")):
        col = json.loads(path.read_text())
        census["collections"] += 1
        # Снятие может стоять на уровне КОЛЛЕКЦИИ — тогда оно исполняется после каждого
        # ответа и покрывает поллеры обоих родов разом.
        col_code = _test_code(col)
        col_covers = _drops_provisional(col_code)
        if col_covers:
            collection_level_drop += 1
        for folder in col.get("item", []) or []:
            if "item" not in folder:
                continue
            census["folders"] += 1
            steps = _leaf_steps(folder)
            census["steps"] += len(steps)
            codes = [(s, _test_code(s)) for s in steps]
            registers = any("_provisionalIds" in c and "push" in c for _, c in codes)
            if not registers:
                continue
            census["registering_folders"] += 1
            pollers = [(s, c) for s, c in codes
                       if "setNextRequest(pm.info.requestName)" in c and "/operations/" in _url_raw(s)]
            census["pollers"] += len(pollers)
            if col_covers:
                continue
            missing = [s["name"] for s, c in pollers if not _drops_provisional(c)]
            for name in missing:
                findings.append(f"{path.name} :: {name}")
    census["collection_level_drop"] = collection_level_drop
    return {"census": census, "findings": findings}


def assert_phantom_drop(collections_dir: Path, out=sys.stderr) -> int:
    """Печатает перепись и находки; 0 — чисто, 1 — есть находки либо ПРЕДПОСЫЛКА ЛОЖНА."""
    res = audit_phantom_drop(collections_dir)
    c, f = res["census"], res["findings"]
    print(f"[phantom-drop] осмотрено: коллекций {c['collections']}, папок {c['folders']}, "
          f"шагов {c['steps']}; регистрируют провизорный id — папок {c['registering_folders']}, "
          f"их поллеров {c['pollers']}; снятие на уровне коллекции — {c['collection_level_drop']}",
          file=out)
    if c["collections"] == 0 or c["steps"] == 0:
        print("[phantom-drop] FAIL — нечего было читать: ноль находок здесь означает "
              "ноль прочитанного, а не чистоту.", file=out)
        return 1
    if c["registering_folders"] == 0:
        print("[phantom-drop] FAIL — ПРЕДПОСЫЛКА СТРАЖА ЛОЖНА: ни один захват из метаданных "
              "не регистрирует переменную в `_provisionalIds`. Либо регистрация снята "
              "(тогда фантом снова некому снимать), либо изменилось её имя. Пока это так, "
              "страж не проверяет ничего.", file=out)
        return 1
    if f:
        print(f"[phantom-drop] FAIL — {len(f)} опрос(ов) операции не снимают провизорный "
              f"идентификатор на ошибке:", file=out)
        for name in f[:40]:
            print(f"    {name}", file=out)
        if len(f) > 40:
            print(f"    … ещё {len(f) - 40}", file=out)
        return 1
    print("[phantom-drop] OK", file=out)
    return 0


def reliable_delete(name: str, path: str, auth: str = "jwtAccountAdminA",
                    op_key: Optional[str] = None,
                    terminal_codes=(200, 404)) -> List[Step]:
    """RELIABLE teardown DELETE: retry PAST the 403 window, then AWAIT the operation.

    ONE implementation, shared — because six copies of this teardown existed and five of
    them carried the defect the sixth had already fixed. Duplication was the mechanism:
    the fix landed in the copy where the leak was observed, and the neighbours kept
    accepting a denial as cleanup.

    WHY 403 IS NOT AN ACCEPTABLE CLEANUP RESULT. The binding is created by the account
    admin, but the admin's `v_delete` on that fresh iam_access_binding OBJECT materialises
    a beat after Create→done. Under load the DELETE lands inside that window and answers
    403 — and an assertion phrased `oneOf([200, 404, 403])` DECLARES THAT A SUCCESS. The
    revoke never happened, so the binding stays ACTIVE in the SHARED account past the end
    of the run, and the next run's leak-guards see a subject that "has no access binding"
    yet is nonetheless allowed. testing.md names this exact failure mode for
    preclean-revoke: retry the DELETE on 403 until it succeeds, never fire-and-forget.

    Terminal states are 200 (revoked) and 404 (already gone). 403 is NOT terminal: if it
    persists past the retry budget the assertion fails HONESTLY — a cleanup that cannot
    run is a finding, not something to swallow. The revoke is async, so the second step
    awaits the Operation; without it the case can end while the revoke is still in flight
    and the binding is still ACTIVE for whoever runs next.
    """
    op_var = "_" + (op_key or re.sub(r"[^A-Za-z0-9]", "", name)) + "RevOp"
    return [
        poll_request_until_status(
            name=name,
            method="DELETE",
            path=path,
            auth=auth,
            expect_code=200,
            retry_on=(403,),
            test_script=[
                "let j; try { j = pm.response.json(); } catch (e) { j = null; }",
                f"pm.environment.unset('{op_var}');",
                "pm.test('teardown: removed or already gone — a persistent 403 means it SURVIVES the run', "
                f"() => pm.expect(pm.response.code, JSON.stringify(j)).to.be.oneOf([{', '.join(str(c) for c in terminal_codes)}]));",
                f"if (pm.response.code === 200 && j && j.id) pm.environment.set('{op_var}', j.id);",
            ],
        ),
        Step(
            name=f"{name}-await",
            method="GET",
            path="/operations/{{" + op_var + "}}",
            auth=auth,
            pre_script=[
                f"if (pm.environment.get('_{op_var}Started') !== pm.info.requestName) {{ pm.environment.set('_{op_var}Count', '0'); pm.environment.set('_{op_var}Started', pm.info.requestName); }}",
            ],
            test_script=[
                # Nothing to await when the DELETE reported 404 (already revoked).
                f"if (!pm.environment.get('{op_var}')) {{ return; }}",
                "let j; try { j = pm.response.json(); } catch (e) { j = null; }",
                f"const c = parseInt(pm.environment.get('_{op_var}Count') || '0', 10);",
                f"if (j && !j.done && c < {POLL_CAP}) {{",
                f"  pm.environment.set('_{op_var}Count', String(c + 1));",
                "  const _rd = Date.now(); while (Date.now() - _rd < 500) { /* inter-poll delay ~500ms */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                f"pm.environment.unset('_{op_var}Count'); pm.environment.unset('_{op_var}Started');",
                "pm.test('teardown: revoke operation committed', () => pm.expect(j && j.done, JSON.stringify(j)).to.eql(true));",
            ],
        ),
    ]


# ---------------------------------------------------------------------------
# Discovery + main
# ---------------------------------------------------------------------------

def load_cases_module(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    mod = importlib.util.module_from_spec(spec)
    # пробрасываем helpers в namespace модуля
    mod.Step = Step
    mod.Case = Case
    mod.assert_status = assert_status
    mod.assert_answered = assert_answered
    mod.assert_grpc_code = assert_grpc_code
    mod.assert_field_violation = assert_field_violation
    mod.assert_unscoped_rejected = assert_unscoped_rejected
    mod.assert_scoped_authz_deny = assert_scoped_authz_deny
    mod.save_from_response = save_from_response
    mod.assert_operation_envelope = assert_operation_envelope
    mod.assert_created_at_seconds = assert_created_at_seconds
    mod.require_env_url = require_env_url
    mod.poll_operation_until_done = poll_operation_until_done
    mod.retry_until_authorized = retry_until_authorized
    mod.retry_until_absent = retry_until_absent
    mod.get_until_gone = get_until_gone
    mod.poll_request_until_status = poll_request_until_status
    mod.reliable_delete = reliable_delete
    mod.POLL_CAP = POLL_CAP
    mod.assert_op_error = assert_op_error
    mod.assert_op_success = assert_op_success
    mod.list_page_block = list_page_block
    mod.name_validation_block = name_validation_block
    mod.labels_validation_block = labels_validation_block
    mod.description_validation_block = description_validation_block
    mod.filter_block = filter_block
    mod.security_injection_block = security_injection_block
    mod.http_method_block = http_method_block
    mod.malformed_body_block = malformed_body_block
    spec.loader.exec_module(mod)
    return mod


def main(argv: List[str]) -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    want = set(argv[1:])
    found = sorted(CASES_DIR.glob("*.py"))
    if not found:
        print(f"no case files in {CASES_DIR}")
        return 1
    rc = 0
    for f in found:
        res = f.stem
        if want and res not in want:
            continue
        mod = load_cases_module(f)
        cases = getattr(mod, "CASES", [])
        # Skip files where CASES has non-Case items (pseudo-code drafts
        # с dict-based кейсами не должны падать всю генерацию).
        bad = [type(c).__name__ for c in cases if not isinstance(c, Case)]
        if bad:
            sys.stderr.write(f"[{res}] SKIP — non-Case items in CASES ({bad[:3]}); convert to Case(...) constructors.\n")
            continue
        # детект дублей case-id — HARD-FAIL (case-id обязан быть уникален)
        ids = [c.id for c in cases]
        dups = {x for x in ids if ids.count(x) > 1}
        if dups:
            sys.stderr.write(f"[{res}] FAIL — duplicate case-id (должен быть уникален): {sorted(dups)}\n")
            return 1
        col = build_collection(res, cases)
        out = OUT_DIR / f"{res}.postman_collection.json"
        out.write_text(json.dumps(col, indent=2, ensure_ascii=False))
        print(f"[{res}] {len(cases)} cases → {out.relative_to(ROOT)}")
    # Страж класса исполняется ЗДЕСЬ, а не в отдельном тесте, который никто не зовёт:
    # генерация предшествует КАЖДОМУ прогону (deploy/scripts/newman-parallel.sh), значит
    # это единственное место, мимо которого нельзя пройти. Отказ роняет генерацию —
    # коллекция с непокрытым классом не должна попадать в прогон.
    if assert_phantom_drop(OUT_DIR) != 0:
        rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
