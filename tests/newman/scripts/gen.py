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
import sys
import uuid
import importlib.util
from pathlib import Path
from dataclasses import dataclass, field
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
    auth: Optional[str] = None


@dataclass
class Case:
    """Один тестовый кейс — может содержать несколько шагов."""
    id: str  # например DISK-CR-CRUD-OK
    title: str  # человеко-читаемое описание
    classes: List[str]  # CRUD / VAL / NEG / BVA / ...
    priority: str  # P0 / P1 / P2 / P3
    steps: List[Step]


# ---------------------------------------------------------------------------
# Глобальный prerequest (runId генерация + _suiteFolder* алиасы)
# ---------------------------------------------------------------------------

PRE_GLOBAL = [
    "if (!pm.environment.get('runId') || pm.environment.get('runId') === '') {",
    "  // runId формат: только [a-z0-9], без точки, начинается с буквы — чтобы проходить compute name regex",
    "  const t = Date.now().toString(36);",
    "  const r = Math.floor(Math.random() * 1e9).toString(36);",
    "  pm.environment.set('runId', ('r' + t + r).replace(/[^a-z0-9]/g, '').slice(0, 11));",
    "}",
    "pm.environment.set('_suiteFolderId', pm.environment.get('existingProjectId'));",
    "pm.environment.set('_suiteFolderCrossId', pm.environment.get('existingProjectCrossId'));",
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
# 50 round-trips at ~100-200 ms each gives ~6-10 s wall-clock — generous enough for
# the async Delete Operation to finish AND for the FGA owner-tuple removal to
# propagate before the get-after-delete assertion runs.
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


def assert_grpc_code(code: int, code_name: str) -> List[str]:
    return [
        f"pm.test('grpc code {code} ({code_name})', () => {{",
        "  const j = pm.response.json();",
        f"  pm.expect(j.code, JSON.stringify(j)).to.eql({code});",
        "});",
    ]


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


def save_from_response(jsonpath: str, env_var: str) -> List[str]:
    """Сохранить значение из response в env."""
    return [
        "try {",
        "  const j = pm.response.json();",
        f"  const v = ({jsonpath});",
        f"  if (v !== undefined && v !== null) pm.environment.set('{env_var}', String(v));",
        "} catch (e) {}",
    ]


def assert_operation_envelope() -> List[str]:
    return [
        "pm.test('Operation envelope returned', () => {",
        "  const j = pm.response.json();",
        "  pm.expect(j.id, 'operation.id').to.match(/^epd[a-z0-9]+$/);",
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


def poll_operation_until_done(auth: str = "jwtAccountAdminA") -> Step:
    """Reusable poll step: до POLL_CAP попыток (через setNextRequest), потом fail если done остался false.

    The auth parameter (default jwtAccountAdminA) lets the poll step send a
    valid Bearer token. Without auth the gateway exempts OperationService/Get
    but the IAM service's anti-anonymous interceptor still rejects
    unauthenticated callers with 401 UNAUTHENTICATED (code 16).

    The retry cap is POLL_CAP (single source of truth — see the constant above).
    At ~100-200 ms per round-trip Newman polls ~3-6 seconds before giving up,
    generous enough for the async worker to finish in dev/CI.

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
        pre_script=[
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
            "  postman.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            "pm.environment.unset('_pollCount');",
            "pm.environment.unset('_pollStarted');",
            "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
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
            "  postman.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            "pm.environment.unset('_goneCount');",
            "pm.environment.unset('_goneStarted');",
            f"pm.test('{label}: gone after delete — 404 or 403', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.be.oneOf([404, 403]));",
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
            "  postman.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            f"pm.environment.unset('{counter_var}');",
            f"pm.environment.unset('{started_var}');",
            # Terminal response: the case's real assertions run exactly once.
            *test_script,
        ],
    )


def assert_op_error(code: int, code_name: str, msg_substr: Optional[str] = None,
                    msg_regex: Optional[str] = None, auth: str = "jwtAccountAdminA",
                    op_var: str = "opId") -> Step:
    """Поллит /operations/{op_var} до done и проверяет, что operation завершилась с error.code == code.

    The auth parameter (default jwtAccountAdminA) carries a valid Bearer token.
    OperationService/Get is <exempt> in the catalog but IAM's anti-anonymous
    interceptor still blocks unauthenticated callers → 401. Steps must carry a
    valid JWT.

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
        "  postman.setNextRequest(pm.info.requestName);",
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
    return Step(name="assert-op-error", method="GET", path="/operations/{{" + op_var + "}}", auth=auth, test_script=body)


def assert_op_success(auth: str = "jwtAccountAdminA") -> Step:
    """The auth parameter ensures the step carries a valid Bearer token."""
    return Step(name="assert-op-success", method="GET", path="/operations/{{opId}}",
                auth=auth,
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
    base = f"{list_path}?projectId={{{{_suiteFolderId}}}}&" if folder_param else f"{list_path}?"
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
    base = lambda name: {"projectId": "{{_suiteFolderId}}", "name": name, **body_extra}
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
    base = lambda name, labels: {"projectId": "{{_suiteFolderId}}", "name": name, "labels": labels, **body_extra}
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
    base = lambda name, desc: {"projectId": "{{_suiteFolderId}}", "name": name, "description": desc, **body_extra}
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
                         path=f"{list_path}?projectId={{{{_suiteFolderId}}}}{sep}filter=name%3D%22foo%22",
                         test_script=[*assert_status(200)])]),
        Case(id=f"{prefix}-LST-FILTER-GARBAGE",
             title="List с garbage filter syntax → 200 или 400",
             classes=["FILTER", "VAL"], priority="P2",
             steps=[Step(name="flt-bad", method="GET",
                         path=f"{list_path}?projectId={{{{_suiteFolderId}}}}{sep}filter=this%20is%20not%20valid%20syntax",
                         test_script=["pm.test('200 or 400', () => pm.expect(pm.response.code).to.be.oneOf([200, 400]));"])]),
        Case(id=f"{prefix}-LST-FILTER-UNKNOWN-FIELD",
             title="List с filter на unsupported field → 200 или 400",
             classes=["FILTER", "VAL"], priority="P2",
             steps=[Step(name="flt-unk", method="GET",
                         path=f"{list_path}?projectId={{{{_suiteFolderId}}}}{sep}filter=nonexistent_field%3D%22x%22",
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
                        body={"projectId": "{{_suiteFolderId}}", "name": payload[:200], **body_extra},
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
                    path=f"{list_path}?projectId={{{{_suiteFolderId}}}}&filter=name%3D%22a%27%20OR%201%3D1--%22",
                    test_script=["pm.test('not 500', () => pm.expect(pm.response.code).to.not.eql(500));",
                                 "pm.test('handled', () => pm.expect(pm.response.code).to.be.oneOf([200, 400]));"])]))
    return out


def http_method_block(prefix, base_path):
    """HTTP method semantics: PUT / DELETE-on-list → 404|405|501."""
    return [
        Case(id=f"{prefix}-METHOD-PUT-NOT-ALLOWED",
             title="PUT на List endpoint → 404/405/501",
             classes=["VAL", "NEG"], priority="P3",
             steps=[Step(name="put-list", method="PUT", path=base_path, body={"projectId": "{{_suiteFolderId}}"},
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
        "  pm.request.headers.remove('Authorization');",
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
    if step.body is not None:
        item["request"]["body"] = {
            "mode": "raw",
            "raw": json.dumps(step.body, ensure_ascii=False),
            "options": {"raw": {"language": "json"}},
        }
    pre = list(step.pre_script)
    if step.auth is not None:
        pre = _auth_pre_script(step.auth) + pre
    events = []
    if pre:
        events.append({"listen": "prerequest", "script": {"type": "text/javascript", "exec": pre}})
    if step.test_script:
        events.append({"listen": "test", "script": {"type": "text/javascript", "exec": step.test_script}})
    if events:
        item["event"] = events
    return item


def case_to_postman(case: Case) -> Dict:
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
    for idx, s in enumerate(case.steps):
        s2 = Step(
            name=final_names[idx],
            method=s.method,
            path=s.path,
            body=s.body,
            pre_script=_rewrite_jumps(list(s.pre_script)),
            test_script=_rewrite_jumps(list(s.test_script)),
            auth=s.auth,
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
        ],
        "item": [case_to_postman(c) for c in cases],
        "variable": [],
    }


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
    mod.assert_grpc_code = assert_grpc_code
    mod.assert_field_violation = assert_field_violation
    mod.save_from_response = save_from_response
    mod.assert_operation_envelope = assert_operation_envelope
    mod.assert_created_at_seconds = assert_created_at_seconds
    mod.poll_operation_until_done = poll_operation_until_done
    mod.get_until_gone = get_until_gone
    mod.poll_request_until_status = poll_request_until_status
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
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
