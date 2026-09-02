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

Форму коллекции и вспомогательный слой собирает ОБЩИЙ модуль
`tests/newman/kacholib/gen_shared.py` — один на дерево (#1367, #1377, #1379,
#1474). Здесь объявлено только то, чем ЭТОТ набор отличается: решения формы
(дескриптор `Emit`), решения оркестрации (дескриптор `Run`), таблица впрыска
и собственные помощники набора.

Соседний генератор образцом НЕ является и сверяться с ним не надо: расхождение
между копиями было предметом сведения, а не способом его проверить.
"""
from __future__ import annotations

import functools
import json
import re
import subprocess
import sys
import uuid
import importlib.util
from pathlib import Path
from dataclasses import dataclass, field, replace
from typing import List, Dict, Optional

# --- общий слой генератора (задача #1367) ------------------------------------
# Помощники ниже общие для ВСЕХ наборов newman и живут в дереве в одном
# экземпляре: `tests/newman/kacholib/gen_shared.py`. До сведения каждый набор нёс
# свою копию, и правка помощника стоила восьми правок — «поправил у себя» было
# неотличимо от «поправил везде».
def _kacholib_dir() -> Path:
    """Каталог общего слоя, найденный ВВЕРХ ОТ ЭТОГО ФАЙЛА, а не от cwd.

    Генератор зовут из каталога набора (`python3 scripts/gen.py`), поэтому путь,
    выведенный из текущего каталога, был бы свойством того, ОТКУДА позвали, а не
    того, где лежит дерево.
    """
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "tests" / "newman" / "kacholib"
        if (candidate / "gen_shared.py").is_file():
            return candidate
    raise SystemExit(
        "общий слой генератора не найден: ожидается "
        "<корень>/tests/newman/kacholib/gen_shared.py.\n"
        "Это ОТКАЗ, а не пропуск: без общих помощников генератор собрал бы "
        "коллекции молча и не тем."
    )


sys.path.insert(0, str(_kacholib_dir()))

import gen_shared  # noqa: E402  — модуль нужен целиком: связывание опроса и его счётчик
from gen_shared import (  # noqa: E402  — импорт после провязки sys.path
    generate,
    Run,
    retry_until_authorized,
    retry_until_present,
    _RYA_SEQ,
    _accepted_http_codes,
    assert_created_at_seconds,
    _assert_delete_operation_outcome,
    assert_field_violation,
    assert_grpc_code,
    assert_op_refusal_message,
    assert_op_refusal_message_contains,
    assert_refusal_message,
    assert_refusal_message_contains,
    _assert_published_id_outcome,
    assert_status,
    _asserts_done,
    _asserts_outcome,
    _assigns_env_var,
    _body_text,
    build_collection,
    _carries_assertion,
    case_to_postman,
    _DELETE_ACCEPTED,
    Emit,
    _FRESH_VAR_SET_RE,
    _is_operation_id_var,
    _js_code_and_literals,
    js_comment,
    js_name,
    js_regex_src,
    js_str,
    load_cases_module,
    _MUTATION_METHODS,
    _OP_POLL_PATH,
    _PUB_ASSIGN_RE,
    _PUB_BIND_RE,
    _PUB_DECL_RE,
    _PUB_RESERVED,
    _PUB_SET_RE,
    _published_id_outcome_assert,
    _published_resource_vars,
    _REGEX_FLAGS,
    _regex_literal_must_contain_the_whole_pattern,
    _regex_must_parse_in_javascript,
    _REGEX_PARSE_CACHE,
    _reset_captured_operation_id,
    step_to_postman,
    _strip_js_comments,
    _VAR_REF_RE,
    _wrap_own_fresh_reads,
)


ROOT = Path(__file__).resolve().parents[1]
CASES_DIR = ROOT / "cases"
OUT_DIR = ROOT / "collections"


# ---------------------------------------------------------------------------
# Форма базового удостоверения — ЧИТАЕТСЯ ИЗ ОБЪЯВЛЕНИЯ, не выписывается (#1253)
# ---------------------------------------------------------------------------

# CREDENTIAL_SECRET_FORM — единственное объявление формы однострочного секрета.
# Его же читает `scripts/credsecretmint/form_test.go`, который сверяет образец с
# тем, что ЧЕКАНИТ ПРОДУКТ (`pkg/credsecret` вместе с `pkg/ids`).
CREDENTIAL_SECRET_FORM = ROOT / "credential-secret-form.json"

# Место подстановки вида удостоверения. Ровно одно; что оно одно — утверждает
# Go-проба, читающая то же объявление.
_CREDENTIAL_KIND_PLACEHOLDER = "<KIND_PREFIX>"

_credential_secret_form_cache: Dict[str, Dict] = {}


def credential_secret_pattern(kind: str, *, where: str) -> str:
    """Образец формы базового удостоверения для названного ВИДА.

    ПОЧЕМУ ИЗ ОБЪЯВЛЕНИЯ, А НЕ ИЗ КЕЙСА. Образец, выписанный в кейсе, — вторая
    копия предиката, и разойтись с продуктом она может молча. Один раз уже
    разошлась: образец ждал разделитель после префикса (`kacho_uoc_…`), тогда как
    `ids.NewID` чеканит префикс СЛИТНО с телом. Совпасть такое утверждение не
    могло НИ ПРИ КАКОМ ответе, и незаметно это было ровно потому, что
    положительного прохода не существовало вовсе — первым отвечал отказ в правах
    (задача #1253).

    Здесь копии нет: объявление одно, и вторая сторона, читающая его же, —
    `scripts/credsecretmint/form_test.go` — подставляет ОБА вида и требует, чтобы
    образец принимал значения, отчеканенные `credsecret.Mint`, и отвергал
    подделки. То есть форма проверена против ЗНАЧЕНИЯ ПРОДУКТА, а не против
    текста чужого исходника.

    Возвращает образец, уже прогнанный через `js_regex_src`: негодный роняет
    ГЕНЕРАЦИЮ с именем места, а не уезжает в коллекцию неисполнимым скриптом.
    """
    if not _credential_secret_form_cache:
        try:
            _credential_secret_form_cache.update(
                json.loads(CREDENTIAL_SECRET_FORM.read_text(encoding="utf-8")))
        except FileNotFoundError as exc:
            raise ValueError(
                f"{where}: объявления формы базового удостоверения нет "
                f"({CREDENTIAL_SECRET_FORM}). Это единственное место, где форма "
                f"объявлена; без него кейс утверждал бы её собственной копией "
                f"образца — тем, из-за чего заведена задача #1253") from exc
    decl = _credential_secret_form_cache

    prefixes = decl.get("idPrefixByKind") or {}
    if kind not in prefixes:
        raise ValueError(
            f"{where}: объявление формы не знает вида {kind!r}; названы "
            f"{sorted(prefixes)}. Вид не выдумывается здесь: он берётся из "
            f"констант продукта, и их согласие с объявлением держит "
            f"scripts/credsecretmint/form_test.go")

    template = decl.get("jsPatternTemplate") or ""
    if _CREDENTIAL_KIND_PLACEHOLDER not in template:
        raise ValueError(
            f"{where}: образец объявления не несёт места подстановки "
            f"{_CREDENTIAL_KIND_PLACEHOLDER} — вид не был бы назван, и секрет "
            f"чужого вида прошёл бы утверждение")
    pattern = template.replace(_CREDENTIAL_KIND_PLACEHOLDER, prefixes[kind])
    return js_regex_src(pattern, where=where)


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
    # (api-gateway.kacho.svc); a forwarded socket is reached as
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
# Глобальный prerequest (runId генерация + _suiteFolder* алиасы + страж подстановки)
# ---------------------------------------------------------------------------

# СТРАЖ НЕРАЗРЕШЁННОЙ ПОДСТАНОВКИ — в адресе И в теле.
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
#
# АДРЕС И ТЕЛО — ОДНА ПОВЕРХНОСТЬ, А НЕ ДВЕ (расширено по прогону 31951162447).
# Прежде страж читал только адрес, и предмет, названный ТЕЛОМ, уезжал литералом.
# Замер того прогона, шард iam, коллекция `label-revoke-nlb`: 63 запроса ушли с
# `{{_t31nLsn}}` в теле — создание слушателя было отвергнуто, и переменную никто
# не захватил. Два из этих запросов ОТЧИТАЛИСЬ ПРОЙДЕННЫМИ, и оба — отрицательные
# (`lsn-pre-grant-deny`, `lsn-post-revoke-deny`): они ждут отказа в доступе, а
# несуществующий объект отказывает и сам. То есть «запрет работает» и «проверять
# было нечего» выглядели одинаково — фикстура оказалась СНИСХОДИТЕЛЬНЕЕ продукта.
# Шаги того же кейса, называвшие слушателя ПУТЁМ, страж поймал: отсюда асимметрия
# три отказа стража против двух ложных зеленей в одном кейсе.
#
# ЧИТАЕТСЯ `raw` — И ЭТО ВСЯ ПОВЕРХНОСТЬ, А НЕ ЧАСТЬ ЕЁ. `step_to_postman` эмитит
# тело единственным режимом `raw` (см. ниже по файлу); режима, который страж не
# прочитал бы, генератор не производит. Появится второй режим — эта посылка станет
# ложной, поэтому она записана здесь, а не подразумевается.
_UNRESOLVED_VAR_GUARD = [
    "(function () {",
    "  var _u = '';",
    "  try { _u = pm.request.url.toString(); } catch (e) { return; }",
    "  try {",
    "    if (pm.request.body && pm.request.body.raw) { _u = _u + ' ' + pm.request.body.raw; }",
    "  } catch (e) { /* тела может не быть — это не находка */ }",
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
    # _UNRESOLVED_VAR_GUARD ЗДЕСЬ БОЛЬШЕ НЕ СТОИТ — он переехал в конец пред-скрипта КАЖДОГО
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
        f"    pm.expect(md.resource, JSON.stringify(j)).to.eql({js_str(unscoped_resource)});"
        if unscoped_resource else "    // resource anchor not pinned for this RPC"
    )
    out += [
        f"pm.test({js_str(f'the refusal is about the MISSING SCOPE on {action}, not some other rejection')}, () => {{",
        "  const j = pm.response.json();",
        "  if (pm.response.code === 403) {",
        "    const info = (j.details || []).find(d => (d['@type'] || '').includes('ErrorInfo'));",
        "    pm.expect(info, 'ErrorInfo detail: ' + JSON.stringify(j)).to.be.an('object');",
        "    pm.expect(info.reason, JSON.stringify(j)).to.eql('AUTHZ_DENIED');",
        "    const md = info.metadata || {};",
        f"    pm.expect(md.action, 'empty action = permission-catalog miss, not a scope refusal: ' "
        f"+ JSON.stringify(j)).to.eql({js_str(action)});",
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
        f"pm.test({js_str(f'deny is the scoped authz deny on {action}, not a permission-catalog miss')}, () => {{",
        "  const j = pm.response.json();",
        "  const info = (j.details || []).find(d => (d['@type'] || '').includes('ErrorInfo'));",
        "  pm.expect(info, 'ErrorInfo detail: ' + JSON.stringify(j)).to.be.an('object');",
        "  pm.expect(info.reason, JSON.stringify(j)).to.eql('AUTHZ_DENIED');",
        "  const md = info.metadata || {};",
        f"  pm.expect(md.action, 'empty action means the catalog had no entry for the method (misrouted path?): ' + JSON.stringify(j)).to.eql({js_str(action)});",
    ]
    if resource_expr:
        out.append(f"  pm.expect(md.resource, JSON.stringify(j)).to.eql({resource_expr});")
    out.append("});")
    return out


_ENV_SET_RE = re.compile(r"""pm\.environment\.set\(\s*['"](\w+)['"]""")


def _captured_op_vars(test_script: List[str]) -> List[str]:
    """Operation-id env vars this step WRITES.

    Recognises both the `save_from_response` helper and the hand-written
    `pm.environment.set('opId', j.id || '')` idiom several cases use inline — the
    producer of an operation id is whoever wrote the variable, however they wrote it."""
    return [v for v in _ENV_SET_RE.findall("\n".join(test_script)) if _is_operation_id_var(v)]


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
    reset = [f"pm.environment.unset({js_str(env_var)});"] if _is_operation_id_var(env_var) else []
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
            f"  if (_pv.indexOf({js_str(env_var)}) === -1) _pv.push({js_str(env_var)});",
            "  pm.environment.set('_provisionalIds', JSON.stringify(_pv));",
            "} catch (e) {}",
        ]
    return [
        *reset,
        "try {",
        "  const j = pm.response.json();",
        f"  const v = ({jsonpath});",
        f"  if (v !== undefined && v !== null) pm.environment.set({js_str(env_var)}, String(v));",
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
    `_UNRESOLVED_VAR_GUARD` still runs FIRST and still refuses to send a request whose
    original URL names a variable that is undefined in every scope, so "the
    variable was never captured" remains a reported failure and not a silent
    substitution of the empty string.
    """
    reason = f" — {why}" if why else ""
    return [
        f"// HARNESS-CONFIG GUARD — {js_comment(var)} is injected by the newman runner (--env-var).",
        "// Missing value = misconfigured harness, NOT a legal mode: FAIL, then skip.",
        f"const __cfgUrl = pm.environment.get({js_str(var)}) || pm.variables.get({js_str(var)}) || '';",
        "if (__cfgUrl) {",
        # replaceIn is identity on a template-free path; see the docstring above.
        f"  pm.request.url = __cfgUrl + pm.variables.replaceIn({js_str(path)});",
        "} else {",
        f"  pm.test({js_str(f'harness config: {var} is set{reason}')}, () => {{",
        "    pm.expect.fail(" + js_str(
            f"{var} is not set — the newman runner "
            "(deploy/scripts/newman-e2e.sh / newman-parallel.sh --env-var) did not inject it. "
            "This step cannot run, and a check that cannot run MUST NOT be silently dropped.") + ");",
        "  });",
        "  pm.execution.skipRequest();",
        "}",
    ]




# Окно видимости прав — РЕШЕНИЕ НАБОРА, а не общего слоя (#1379): путь
# материализации у доменов разный, и одно число за всех было бы решением
# за них. Здесь — iam материализует собственные привязки быстрее прочих. Величина видна
# на связывании, а не в прозе шапки: три копии из шести называли ЧУЖУЮ.
# Голова полосы — общая (#1477). Шаг, чей адрес собран из НЕЗАХВАЧЕННОЙ переменной,
# спрашивает не о ресурсе: окно видимости прав такой адрес не наполнит никогда, а
# отказ по нему приходит кодом ИЗ полосы ожидания — то есть шаг выжигает весь бюджет
# и падает, называя следствие вместо предмета.
_rya = functools.partial(retry_until_authorized,
                        budget=15, interval_ms=400, lane_head=True)

# То же окно у СПИСОЧНОГО ожидания — и то же правило: величину называет НАБОР,
# а не общий слой (#1379). Форма общая: до сведения ЭТОТ набор нёс ЧЕТВЁРТУЮ
# копию ожидания — кейс-локальную, вписанную прямо в тест-скрипт, — потому что в
# общем слое обёртки не было вовсе. Она отличалась от трёх остальных ещё и по
# существу: читала ОДНО поле ответа по имени вместо первого массива, не
# отсекала не-200 и не снимала свои счётчики. Здесь остаётся только величина.
_rup = functools.partial(retry_until_present,
                        budget=25, interval_ms=500)


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
            f"if (!pm.environment.get({js_str(op_var)})) {{ pm.execution.skipRequest(); }}",
        ]
    return [
        f"// OPERATION GUARD — '{js_comment(op_var)}' is captured by the mutation this poll follows.",
        "// Empty = that mutation returned no Operation. Report it (a skipped request",
        "// leaves no trace at all) and skip, rather than polling a literal template.",
        f"if (!pm.environment.get({js_str(op_var)})) {{",
        f"  pm.test({js_str(f'operation id {op_var} was captured (the mutation returned an Operation)')}, () => {{",
        "    pm.expect.fail(" + js_str(
            f"{op_var} is empty — the mutation this poll belongs to did not "
            "return an Operation (it was rejected, or its capture failed). Polling would hit an "
            "unresolved template; a previous case's operation is NOT a substitute.") + ");",
        "  });",
        "  pm.execution.skipRequest();",
        "}",
    ]


# Текст утверждения о снятии — ОДИН ИСТОЧНИК. Его же читает страж класса
# `audit_gone_principal`; выписанная там копия разошлась бы с этой молча, и страж
# перестал бы опознавать шаги, продолжая печатать «чисто».
_GONE_ASSERT_SUFFIX = ": gone after delete — 404 or 403"


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
            f"pm.test({json.dumps(label + _GONE_ASSERT_SUFFIX)}, () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.be.oneOf([404, 403]));",
        ],
    )


def poll_request_until_status(name: str, method: str, path: str, test_script: List[str],
                              auth: str = "jwtAccountAdminA",
                              expect_code: int = 200,
                              retry_on=(403, 404),
                              retry_predicate: Optional[str] = None,
                              body: Optional[Dict] = None,
                              pre_script: Optional[List[str]] = None) -> Step:
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

    pre_script (optional): extra PRE-request lines, prepended BEFORE the counter
    reset. Its one intended use is the sanctioned environment guard
    `require_env_url` — a step that must be re-addressed to the cluster-internal
    listener (`/iam/v1/internal/*` is served ONLY there) needs BOTH the URL rewrite
    and this poll loop, and the alternative was a fifth hand-written copy of the
    loop in a case file. Prepended, not appended, so the guard's
    `pm.execution.skipRequest()` runs before anything else happens.
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
            *(pre_script or []),
            "// poll-for-propagation counter reset on first entry (request-name-scoped);",
            "// re-invocations via setNextRequest skip the reset.",
            f"if (pm.environment.get({js_str(started_var)}) !== pm.info.requestName) {{",
            f"  pm.environment.set({js_str(counter_var)}, '0');",
            f"  pm.environment.set({js_str(started_var)}, pm.info.requestName);",
            "}",
        ],
        test_script=[
            f"const _p200c = parseInt(pm.environment.get({js_str(counter_var)}) || '0', 10);",
            f"const _p200retryCode = [{retry_set}].includes(pm.response.code);",
            (f"const _p200retryPred = (pm.response.code === {expect_code}) && ({retry_predicate});"
             if retry_predicate is not None else "const _p200retryPred = false;"),
            f"if ((_p200retryCode || _p200retryPred) && _p200c < {POLL_CAP}) {{",
            "  // access not yet visible at the authz gate (grant→FGA propagation window) — retry.",
            f"  pm.environment.set({js_str(counter_var)}, String(_p200c + 1));",
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
            f"pm.environment.unset({js_str(counter_var)});",
            f"pm.environment.unset({js_str(started_var)});",
            # Terminal response: the case's real assertions run exactly once.
            *test_script,
        ],
    )


def assert_op_error(code: int, code_name: str, msg_substr: Optional[str] = None,
                    msg_regex: Optional[str] = None, auth: str = AUTH_INHERIT_OP,
                    op_var: str = "opId", reason: Optional[str] = None,
                    msg_text: Optional[str] = None,
                    msg_text_contains: Optional[str] = None) -> Step:
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

    reason: признак полосы из `google.rpc.ErrorInfo.reason` в `error.details[]`.
    Пинить его ОБЯЗАТЕЛЬНО там, где один код отказа несёт несколько полос: код у
    них общий (`api-conventions.md` §by-lane code-split), тон сообщения стабилен,
    но НЕ парсибелен, поэтому машинно различает вызывающего только признак.
    Утверждение о признаке идёт В ПАРЕ с кодом, а не вместо него: по одному коду
    не отличить полосу, по одному признаку не заметить смену отображения.

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
        f"pm.test({js_str(f'error code {code} ({code_name})')}, () => pm.expect(j.error && j.error.code, JSON.stringify(j)).to.eql({code}));",
    ]
    if msg_substr is not None:
        body.append(f"pm.test({js_str(f'error text includes \"{msg_substr}\"')}, () => pm.expect((j.error && j.error.message || '').toLowerCase(), JSON.stringify(j)).to.include({js_str(msg_substr.lower())}));")
    if reason is not None:
        # ПАРА: код И машинный признак полосы. Код один на многие полосы
        # (FAILED_PRECONDITION отдают и предел, и состояние, и предусловие на
        # чужой ресурс), поэтому сам по себе он полосу не называет; признак
        # называет — и НЕ ЗАВИСИТ ОТ ЯЗЫКА прозы, тогда как проза есть контракт,
        # который меняется осознанно (`api-conventions.md` §By-lane code-split).
        #
        # Признак живёт в `Operation.error.details` — это `google.rpc.Status`, и
        # его `details` переживают хранение (`pkg/operations`: они кладутся
        # `proto.Marshal(Status)` и восстанавливаются на чтении). Пустой перечень
        # деталей — законный ответ БЕЗ признака, и он обязан быть красным: отказ,
        # потерявший признак, для клиента неотличим от чужой полосы.
        body.append(
            f"pm.test({js_str(f'error carries reason {reason}')}, () => {{"
            " const ds = (j.error && j.error.details) || [];"
            " const rs = ds.map(d => d && d.reason).filter(Boolean);"
            f" pm.expect(rs, JSON.stringify(j)).to.include({js_str(reason)}); }});")
    if msg_regex is not None:
        body.append(f"pm.test({js_str(f'error text matches /{msg_regex}/')}, () => pm.expect(j.error && j.error.message || '', JSON.stringify(j)).to.match(/{js_regex_src(msg_regex, where='iam/assert_op_error/msg_regex')}/));")
    if msg_text is not None:
        body.extend(assert_op_refusal_message(msg_text))
    if msg_text_contains is not None:
        body.extend(assert_op_refusal_message_contains(msg_text_contains))
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
        f"// per-step auth: bearer from env '{js_comment(auth)}'",
        f"const __t = pm.environment.get({js_str(auth)}) || pm.variables.get({js_str(auth)}) || '';",
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
        f"  pm.test({js_str(f'harness config: {auth} is set (subject under test)')}, () => {{",
        "    pm.expect.fail(" + js_str(
            f"{auth} is not set — the authz-fixture seed "
            "(tests/authz-fixtures/setup.sh) did not provide this subject. Running the step "
            "anonymously would test a DIFFERENT principal and pass for the wrong reason.") + ");",
        "  });",
        "  pm.execution.skipRequest();",
        "}",
    ]


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


# ---------------------------------------------------------------------------
# СТРАЖ КЛАССА: «ресурса нет» под предъявителем, который его НЕ ВИДЕЛ
# ---------------------------------------------------------------------------
#
# ЧТО ЗАПРЕЩАЕТСЯ. Пообъектные чтения `/Get` в iam СКРЫВАЮТ СУЩЕСТВОВАНИЕ:
# отказ в доступе отдаётся не как 403, а как `404 "<Resource> <id> not found"`,
# байт-в-байт равный настоящему промаху владельца (край:
# `CatalogEntry.HidesExistenceOnDeny` — `/Get` + `v_get` + пообъектная область;
# текст сверен с текстом владельца, иначе получился бы оракул существования).
#
# Следствие для пробы: шаг «ресурс исчез после удаления», заданный
# предъявителю, у которого доступа к ЭТОМУ объекту не было НИКОГДА, получает
# 404 и на ЖИВОМ объекте. Утверждение зеленеет независимо от того, сработало
# удаление или нет — форма проверки есть, содержания нет. Хуже отсутствующего
# кейса: слот занят, вердикт зелёный, уверенность ложная.
#
# ЧТО ТРЕБУЕТСЯ. Предъявитель шага «ушёл» обязан быть тем, кто РАНЬШЕ В ТОМ ЖЕ
# КЕЙСЕ получил 200 на ТОМ ЖЕ адресе. Тогда 404 после снятия отличим от 404 по
# скрытию существования: между двумя ответами менялось только состояние
# продукта, а не субъект.
#
# Две законные формы «видел», обе принимаются:
#   — чтение с 200 (сильнейшая: тот же глагол, что и после снятия);
#   — успешная мутация с 200 на том же адресе — удаление, отвергнутое авторизацией,
#     вернуло бы 403/404 и не дошло бы до конверта операции, поэтому 200 на нём
#     доказывает, что объект для этого предъявителя резолвился.
# `oneOf([200, 404])` формой «видел» НЕ является и не принимается by construction:
# такое утверждение проходит и на невидимом объекте.
#
# ПОЧЕМУ СТРАЖ ЖИВЁТ В ГЕНЕРАЦИИ, А НЕ В ОТДЕЛЬНОЙ ПРОБЕ. Генерация предшествует
# КАЖДОМУ прогону, значит мимо неё пройти нельзя (тот же довод, что у
# `assert_phantom_drop`). Отказ роняет генерацию: коллекция с вакуумным
# утверждением о снятии в прогон не попадает.
#
# Способность стража краснеть и молчать доказана инъекцией в обе стороны —
# `scripts/gone_principal_test.py`.


# Маркер выводится ИЗ ТОГО ЖЕ текста, что печатает helper, и в ТОЙ ЖЕ кодировке, в
# какой он попадает в коллекцию: `json.dumps` по умолчанию экранирует не-ASCII, поэтому
# тире уезжает в `\u2014`, и дословная копия строки в коде стража не нашла бы НИ ОДНОГО
# шага. Первая редакция стража так и сделала — и его собственная проверка предпосылки
# («опознано 0 утверждений») это поймала. Здесь копии нет by construction.
_GONE_MARK = json.dumps(_GONE_ASSERT_SUFFIX)[1:-1]

# Утверждение, ТРЕБУЮЩЕЕ ровно 200. `oneOf([...])` сюда не подходит намеренно:
# допуск, включающий 404, проходит и на объекте, которого предъявитель не видит.
_ASSERTS_200 = re.compile(r"to\.eql\(200\)|to\.equal\(200\)|to\.have\.status\(200\)")

_STEP_AUTH = re.compile(r"// per-step auth: bearer from env '([^']+)'")


def _step_principal(item: Dict) -> str:
    """Имя бэрера шага так, как его видит newman: env-переменная либо anonymous."""
    code = ""
    for ev in item.get("event", []) or []:
        if ev.get("listen") == "prerequest":
            code = "\n".join(ev["script"]["exec"])
            break
    m = _STEP_AUTH.search(code)
    if m:
        return m.group(1)
    if "per-step auth: anonymous step" in code:
        return "anonymous"
    return "<collection-default>"


def audit_gone_principal(collections_dir: Path) -> Dict:
    """Перепись + находки класса «утверждение о снятии под предъявителем без доступа».

    Ничего не печатает: решение и печать — за вызывающим (как у audit_phantom_drop).
    """
    findings: List[str] = []
    census = {"collections": 0, "folders": 0, "steps": 0, "gone_steps": 0, "with_witness": 0}
    for path in sorted(collections_dir.glob("*.json")):
        col = json.loads(path.read_text())
        census["collections"] += 1
        for folder in col.get("item", []) or []:
            if "item" not in folder:
                continue
            census["folders"] += 1
            steps = _leaf_steps(folder)
            census["steps"] += len(steps)
            for i, st in enumerate(steps):
                if _GONE_MARK not in _test_code(st):
                    continue
                census["gone_steps"] += 1
                url, who = _url_raw(st), _step_principal(st)
                witnesses = [
                    prev["name"] for prev in steps[:i]
                    if _url_raw(prev) == url
                    and _step_principal(prev) == who
                    and _ASSERTS_200.search(_test_code(prev))
                ]
                if witnesses:
                    census["with_witness"] += 1
                else:
                    findings.append(f"{path.name} :: {st['name']} — предъявитель "
                                    f"{who} нигде раньше в этом кейсе не получил 200 на {url}")
    return {"census": census, "findings": findings}


def assert_gone_principal(collections_dir: Path, out=sys.stderr) -> int:
    """Печатает перепись и находки; 0 — чисто, 1 — есть находки либо ПРЕДПОСЫЛКА ЛОЖНА."""
    res = audit_gone_principal(collections_dir)
    c, f = res["census"], res["findings"]
    print(f"[gone-principal] осмотрено: коллекций {c['collections']}, папок {c['folders']}, "
          f"шагов {c['steps']}; утверждений о снятии {c['gone_steps']}, "
          f"из них с доказанным доступом до снятия {c['with_witness']}", file=out)
    if c["collections"] == 0 or c["steps"] == 0:
        print("[gone-principal] FAIL — нечего было читать: ноль находок здесь означает "
              "ноль прочитанного, а не чистоту.", file=out)
        return 1
    if c["gone_steps"] == 0:
        print("[gone-principal] FAIL — ПРЕДПОСЫЛКА СТРАЖА ЛОЖНА: ни один шаг не опознан как "
              "утверждение о снятии. Либо утверждений больше нет вовсе, либо изменился их "
              "текст — и тогда страж молчит не потому, что чисто. Сверь `_GONE_MARK` с "
              "`get_until_gone`.", file=out)
        return 1
    if f:
        print(f"[gone-principal] FAIL — {len(f)} утверждени(е/я) о снятии заданы предъявителю, "
              f"который этого объекта НЕ ВИДЕЛ (скрытие существования отдаёт ему 404 и на "
              f"живом объекте, поэтому упасть они не могут):", file=out)
        for name in f[:40]:
            print(f"    {name}", file=out)
        if len(f) > 40:
            print(f"    … ещё {len(f) - 40}", file=out)
        return 1
    print("[gone-principal] OK", file=out)
    return 0


def reliable_delete(name: str, path: str, auth: str = "jwtAccountAdminA",
                    op_key: Optional[str] = None,
                    terminal_codes=(200, 404),
                    require_operation: bool = False) -> List[Step]:
    """RELIABLE teardown DELETE: retry PAST the 403 window, then AWAIT the operation.

    ONE implementation, shared — because six copies of this teardown existed and five of
    them carried the defect the sixth had already fixed. Duplication was the mechanism:
    the fix landed in the copy where the leak was observed, and the neighbours kept
    accepting a denial as cleanup.

    Седьмая копия нашлась позже — снаружи этого сведения, в кейс-файле, и несла тот же
    дефект в чистом виде: она утверждала `200 + Operation` под именем «revoke COMMITTED»
    и на этом заканчивалась. Приём запроса не есть исполнение мутации (мутации Kachō
    асинхронны), поэтому следующий шаг сносил роль, пока отзыв выдачи был ещё в полёте, и
    владелец честно отвечал `FAILED_PRECONDITION "role is in use by …"`. Гонка редкая:
    ловится примерно раз на прогон и выглядит как дефект продукта, каковым не является.

    `require_operation` — то единственное, что было у седьмой копии и чего не было
    здесь: при 200 потребовать саму операцию. Без него `200` без тела прошёл бы, а
    ожидание ниже смолчало бы по раннему выходу «нечего ждать» — то есть отсутствие
    отзыва читалось бы как отзыв.

    `terminal_codes=(200,)` — для полосы, где ресурс заводится ЭТИМ же кейсом под
    уникальным `runId` и сносится только этим шагом: там `404` означает не «уже нет», а
    сорванную фикстуру либо постороннего писателя, и принимать его нельзя.

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
                f"pm.environment.unset({js_str(op_var)});",
                "pm.test('teardown: removed or already gone — a persistent 403 means it SURVIVES the run', "
                f"() => pm.expect(pm.response.code, JSON.stringify(j)).to.be.oneOf([{', '.join(str(c) for c in terminal_codes)}]));",
            ] + ([
                "pm.test('teardown: DELETE вернул саму операцию (200 без неё = ждать нечего, "
                "и отсутствие отзыва прочиталось бы как отзыв)', "
                "() => pm.expect(j && j.id, JSON.stringify(j)).to.match(/^iop[a-z0-9]+$/));",
            ] if require_operation else []) + [
                f"if (pm.response.code === 200 && j && j.id) pm.environment.set({js_str(op_var)}, j.id);",
            ],
        ),
        Step(
            name=f"{name}-await",
            method="GET",
            path="/operations/{{" + op_var + "}}",
            auth=auth,
            pre_script=[
                f"if (pm.environment.get({js_str(f'_{op_var}Started')}) !== pm.info.requestName) {{ pm.environment.set({js_str(f'_{op_var}Count')}, '0'); pm.environment.set({js_str(f'_{op_var}Started')}, pm.info.requestName); }}",
            ],
            test_script=[
                # Nothing to await when the DELETE reported 404 (already revoked).
                f"if (!pm.environment.get({js_str(op_var)})) {{ return; }}",
                "let j; try { j = pm.response.json(); } catch (e) { j = null; }",
                f"const c = parseInt(pm.environment.get({js_str(f'_{op_var}Count')}) || '0', 10);",
                f"if (j && !j.done && c < {POLL_CAP}) {{",
                f"  pm.environment.set({js_str(f'_{op_var}Count')}, String(c + 1));",
                "  const _rd = Date.now(); while (Date.now() - _rd < 500) { /* inter-poll delay ~500ms */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                f"pm.environment.unset({js_str(f'_{op_var}Count')}); pm.environment.unset({js_str(f'_{op_var}Started')});",
                "pm.test('teardown: revoke operation committed', () => pm.expect(j && j.done, JSON.stringify(j)).to.eql(true));",
            ],
        ),
    ]


# ---------------------------------------------------------------------------
# Discovery + main
# ---------------------------------------------------------------------------

def _reset_step_name_counters() -> None:
    """Reset every counter that feeds a STEP NAME, before loading a case module.

    A step name must be a function of the CASE, never of the environment. These
    counters live at module scope and only ever grow, so without this reset a
    name would depend on how many case modules were loaded before this one, and
    `gen.py <module>` would emit different names than a full `gen.py` for the
    same case — leaving a tree the full run does not produce, and step names
    that do not match between runs when a red run is being diagnosed.

    Resetting is safe by construction: newman resolves setNextRequest by request
    name WITHIN the collection being run, and one case module produces exactly
    one collection — so uniqueness is only ever required within that scope.

    Held by internal/repohygiene TestGeneratedStepNamesDoNotDependOnHowManyModulesRan.
    """
    _RYA_SEQ[0] = 0



def _assert_after_all(out_dir: Path) -> int:
    """Проверки, которые нельзя решить по одной коллекции — решение iam (#1474).

    Генерация предшествует каждому прогону, поэтому коллекция с непокрытым
    классом и вакуумное утверждение о снятии принципала не доедут до прогона
    незамеченными. Оба стража считаются: отказ первого не отменяет второго —
    иначе вторая находка ждала бы починки первой.
    """
    rc = 0
    if assert_phantom_drop(out_dir) != 0:
        rc = 1
    if assert_gone_principal(out_dir) != 0:
        rc = 1
    return rc
# ─────────────────────────────────────────────────────────────────────────────
# РЕШЕНИЯ НАБОРА, от которых зависит форма коллекции (#1379). Форму собирает
# общий слой; здесь объявлено ТОЛЬКО то, чем этот набор от остальных отличается.
# ─────────────────────────────────────────────────────────────────────────────

def _iam_case_steps(case):
    """Конвейер шагов кейса iam — САМЫЙ ДЛИННЫЙ в дереве, и это осознанно.

    iam делает имена шагов ГЛОБАЛЬНО уникальными и переписывает буквальные
    переходы: newman резолвит `setNextRequest(<имя>)` на ПЕРВЫЙ элемент с этим
    именем во всей коллекции, поэтому самоповтор шага с общеупотребительным
    именем прыгал в ЧУЖОЙ, более ранний кейс, а промежуточные шаги текущего
    пропускались молча. Ни один другой набор этого слоя не несёт — расхождение
    названо здесь, а не спрятано в восьмой копии сериализации кейса.
    """
    # Обёртка первого доступа к своему свежему ресурсу ставится ПЕРЕД любой
    # обработкой имён: `rename=False` — iam сам делает имена глобально
    # уникальными (`<case-id> :: <шаг>`) и переписывает буквальные переходы
    # по БАЗОВЫМ именам, поэтому переименование обёрткой сломало бы резолв.
    case = replace(case, steps=_assert_published_id_outcome(
        _reset_captured_operation_id(_assert_delete_operation_outcome(
            _wrap_own_fresh_reads(case.steps, _rya, rename=False)))))

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

    items: List[Step] = []
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
        items.append(s2)
    return items


def _iam_item_hook(step, item):
    """Ослабленная проверка сертификата — по свойству шага, а не по умолчанию."""
    if step.insecure_tls:
        item["protocolProfileBehavior"] = {"strictSSL": False}


# Опрос операции: тело общее (#1475), решения набора — здесь. У iam их три, и
# каждое РЕШЕНО, а не унаследовано копированием:
#
#   * ИМЯ ШАГА фиксированное. Сериализация этого набора приписывает имени
#     идентификатор кейса, поэтому уникальность приходит оттуда, и суффикс-счётчик
#     дал бы второе имя одному предмету;
#   * СБРОС СЧЁТЧИКА В ПРЕДЗАПРОСЕ, по флагу с именем шага: при общем имени шага
#     счётчик иначе перетекал бы МЕЖДУ кейсами, и следующий кейс начинал бы петлю
#     в середине исчерпанного бюджета — число утверждений становилось бы
#     недетерминированным;
#   * СТРАЖ ПУСТОГО ИДЕНТИФИКАТОРА ДВУХ ФОРМ (`required`): у кейса под проверкой
#     отсутствие операции — ДЕФЕКТ и называется вслух, у уборки best-effort —
#     законный случай, и запрос просто не отправляется.
def poll_operation_until_done(auth: str = AUTH_INHERIT_OP, required: bool = True) -> Step:
    """Шаг опроса операции набора iam — общее тело плюс три его решения."""
    return gen_shared.op_poll_step(
        Step,
        auth=auth,
        budget=POLL_CAP,
        interval_ms=500,
        unique_name=False,
        pre_extra=[
            *_op_id_guard("opId", required),
            "// poll-counter reset on first entry (request-name-scoped flag);",
            "// re-invocations via setNextRequest skip the reset.",
            "if (pm.environment.get('_pollStarted') !== pm.info.requestName) {",
            "  pm.environment.set('_pollCount', '0');",
            "  pm.environment.set('_pollStarted', pm.info.requestName);",
            "}",
        ],
        step_extra={"op_var": "opId"},
    )


_EMIT = Emit(
    id_slug="kacho-iam",
    display_name="kacho-iam / newman",
    pre_global=lambda key: PRE_GLOBAL,
    post_global=POST_GLOBAL,
    steps_of=_iam_case_steps,
    auth_pre=_auth_pre_script,
    item_hook=_iam_item_hook,
    # Страж подстановки — ПОСЛЕДНИМ в пред-скрипте шага, а не в общем событии
    # коллекции. Newman исполняет пред-скрипт коллекции ДО пред-скрипта шага
    # ВСЕГДА, поэтому там страж выносил вердикт об адресных переменных РАНЬШЕ,
    # чем шаг успевал присвоить те из них, которыми владеет сам: шаг, готовящий
    # переменную для собственного адреса, получал отказ на КАЖДОМ прогоне.
    # Предмет стража от переноса не изменился — он всё так же ловит запрос,
    # который ушёл бы литералом подстановки; изменился только момент.
    pre_tail=tuple(_UNRESOLVED_VAR_GUARD),
)

# Помощники, доезжающие до модуля кейсов. Перечень — СЛОВАРЬ: он объявлен один
# раз и виден целиком, а не сорока строками `mod.X = X`, каждая из которых
# переживала снятие своего предмета молча.
_INJECTED = {
    "Step": Step,
    "Case": Case,
    "assert_status": assert_status,
    "assert_answered": assert_answered,
    "assert_grpc_code": assert_grpc_code,
    "assert_refusal_message": assert_refusal_message,
    "assert_refusal_message_contains": assert_refusal_message_contains,
    "assert_field_violation": assert_field_violation,
    "assert_unscoped_rejected": assert_unscoped_rejected,
    "assert_scoped_authz_deny": assert_scoped_authz_deny,
    "save_from_response": save_from_response,
    "assert_operation_envelope": assert_operation_envelope,
    "assert_created_at_seconds": assert_created_at_seconds,
    "require_env_url": require_env_url,
    "poll_operation_until_done": poll_operation_until_done,
    "retry_until_authorized": _rya,
    "retry_until_present": _rup,
    "get_until_gone": get_until_gone,
    "poll_request_until_status": poll_request_until_status,
    "reliable_delete": reliable_delete,
    "POLL_CAP": POLL_CAP,
    "assert_op_error": assert_op_error,
    "assert_op_success": assert_op_success,
    "js_regex_src": js_regex_src,
    "js_name": js_name,
    # СЕРИАЛИЗАТОР СТРОКИ — впрыскивается, потому что без него декларация не
    # может исполнить правило #1181 даже при желании автора: вклейка в литерал
    # остаётся ЕДИНСТВЕННОЙ доступной формой, и корпус растёт не по небрежности,
    # а по построению. Соседний набор (vpc) впрыскивает его давно и вклеек в
    # литерал строки почти не имеет; iam впрыскивал `js_name`/`js_regex_src` —
    # то есть помощников для ИМЕНИ и для ВЫРАЖЕНИЯ, — а помощника для самого
    # частого случая, строки, у автора кейса не было.
    "js_str": js_str,
    "credential_secret_pattern": credential_secret_pattern,
}


_RUN = Run(
    root=ROOT,
    cases_dir=CASES_DIR,
    out_dir=OUT_DIR,
    scripts_dir=Path(__file__).resolve().parent,
    emit=_EMIT,
    case_cls=Case,
    injected=_INJECTED,
    before=_reset_step_name_counters,
    stem_dashes_to_underscores=True,
    per_collection=None,
    after_all=_assert_after_all,
)

# Точка входа — связывание, а не своё тело (#1474). Оркестрация одна на дерево;
# здесь набор связывает СВОИ решения. Имя `main` сохранено: его импортирует
# тонкая обёртка края (`from gen import main`).
main = functools.partial(generate, _RUN)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
