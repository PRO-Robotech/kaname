# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set: InternalLimitService — resource-count ceilings (issue #291, stage S1).

WHAT THIS RESOURCE IS. The ceiling on how many resources of one KIND a tenant may
hold. Before it, the number of networks, subnets, addresses, interfaces, rule
groups, route tables, gateways and prefix sets one tenant creates was bounded by
nothing at all, and one project could make the platform unusable for everyone else
without breaking a single rule.

WHERE IT LIVES, AND WHY EVERY STEP GOES THERE. Stating a ceiling is an
administrative act about a tenant's share of a shared platform, so the surface is
an `Internal*` service on the cluster-internal listener, REST under
`/iam/v1/internal/limits` (ban #6). Every step below is therefore rewritten onto
{{internalBaseUrl}} in its pre-request through `gen.py::require_env_url` — the
sanctioned harness guard, which ASSERTS the variable by name before skipping. A
missing internalBaseUrl is a broken harness, not a legal mode: without the
assertion, losing the variable would delete this whole case-set and the suite
would still read GREEN.

WHO CALLS. `jwtBootstrap` — the cluster `system_admin` ServiceAccount. Two
independent reasons, and both are needed:

  * the catalog gates the five CRUD verbs on `system_admin` @ `cluster`, which no
    tenant-tier fixture subject holds;
  * `Create` / `Update` / `Delete` additionally declare `required_acr_min = "2"`,
    and the step-up floor is evaluated at the edge BEFORE authz. A machine
    principal is the only value that lifts that floor.

Coverage (acceptance `sub-phase-vpc-quota-resource-count`, §5 stage S1). The
scenario id is carried in the text so the trace runs both ways:

  IAM-LIM-CR-CRUD-OK          — VPCQ-01: create → Operation, then the resource's shape
  IAM-LIM-CR-VAL-NEG-VALUE    — VPCQ-02: a negative ceiling → 400 naming `value`, and NO row
  IAM-LIM-CR-VAL-KIND         — VPCQ-03: a kind outside the closed catalogue → 400 naming `kind`
  IAM-LIM-GT-NEG-ABSENT       — VPCQ-04: well-formed absent id → 404, contract tone (+ positive pair)
  IAM-LIM-GT-VAL-MALFORMED-ID — VPCQ-05: malformed id → 400, named resource (+ positive pair)
  IAM-LIM-CR-CONF-DUP-TRIPLE  — VPCQ-06: the triple is taken → 409, and NO second row
  IAM-LIM-CR-NEG-ABSENT-SCOPE — VPCQ-07: a ceiling for a project that is not there → 404
  IAM-LIM-RS-CRUD-PRECEDENCE  — VPCQ-08: PROJECT over ACCOUNT over DEFAULT, and the fallback back
  IAM-LIM-RS-SEC-NARROW-GATE  — VPCQ-09: the resolve relation is not satisfied by a tenant (+ positive pair)
  IAM-LIM-CS-CRUD-DELTA       — VPCQ-11: the delta reports changes and only changes
  IAM-LIM-DL-IDM-REPEAT       — withdrawal is idempotent, and the triple is free again

Not here, and each with its reason rather than a silence:

  VPCQ-10 (not reachable on the outside) — a pair belongs in the EXISTING census,
    `iam-internal-only-check.py`, not in a second one beside it. It is added there:
    two negatives on the advertised external listener plus the positive control on
    the internal one.
  VPCQ-12 (deleting a project takes its ceilings) — the delete of a project is a
    tenant-lifecycle act with its own fixtures, and the invariant is the DATABASE's
    (a BEFORE DELETE trigger, since a polymorphic reference has no foreign key).
    It is locked by the integration test
    `internal/repo/kacho/pg/limit_integration_test.go::TestLimit_12_ProjectDeleteWithdrawsItsLimits`,
    which asserts BOTH halves — the project's ceilings go, the account's and the
    platform's stay. Asserting it here would need a disposable project per run and
    would still not reach the second half.

Self-contained: every ceiling this file states is on a kind it also withdraws, and
the scope objects are the suite's existing ones, so a re-run does not collide with
itself on the partial UNIQUE over the triple.
"""

CASES = []

# ---------------------------------------------------------------------------
# Harness plumbing
# ---------------------------------------------------------------------------

LIMIT_PATH = "/iam/v1/internal/limits"


# The URL a step sends is BUILT BY THE PRE-SCRIPT: require_env_url replaces
# `pm.request.url` outright, so a query string left only in `path=` never travels.
# These two build the string ONCE and it is passed to both places — the shape that
# made the difference invisible is exactly the one that would drop a `?cursor=` and
# leave the delta silently reading from the beginning of time.
_RESOLVE_Q = LIMIT_PATH + ":resolve?scopeId={{existingProjectId}}&service=vpc"


def _CHANGED_Q(cursor):
    return LIMIT_PATH + ":changedSince?cursor=" + cursor


def _internal(path):
    """Point this step at the cluster-internal REST listener.

    `Internal*` RPCs are served ONLY there ({{internalBaseUrl}} = :18081 under the
    runner's port-forward); the public cmux does not route them, by design. The
    guard is gen.py::require_env_url — assert naming the variable, then skip —
    because a lost variable must make the suite RED rather than quietly smaller.
    """
    return require_env_url(
        "internalBaseUrl", path,
        "stating a resource-count ceiling is administrative surface and lives ONLY "
        "on the cluster-internal REST listener (ban #6)")


def _assert_status_one_of(codes, why):
    """Two defensible refusals of the SAME decision, and never a success.

    The tolerance is about ORDER, not about uncertainty: the edge decides authz
    BEFORE the body is judged, so a subject the caller cannot reach may be refused
    a step earlier than the backend would refuse it. Both listed codes are
    refusals; the assertion that carries the weight is that 2xx is not among them.
    """
    # Список кодов раскрывается ЗДЕСЬ, литералом, а не приходит выражением.
    #
    # Гейт смешанных исходов читает аргумент `oneOf` статически и отказывается
    # считать непрочитанное чистым — он прав: «не смог прочитать» неотличимо от
    # «чисто». Прежняя форма подставляла `{list(codes)!r}`, и предикат честно
    # объявлял место непроверенным.
    #
    # Оба допустимых списка — ОТКАЗЫ, и оба про ПОРЯДОК, а не про
    # неопределённость: край решает про доступ раньше, чем судит тело, поэтому
    # недостижимый субъект получает отказ на шаг раньше. Успех не входит ни в
    # один — это и есть несущее утверждение.
    if list(codes) == [403, 404]:
        rendered = "[403, 404]"
    else:  # предохранитель: новый список обязан быть назван здесь же
        raise AssertionError(
            f"неизвестный список кодов {list(codes)!r}: добавь его литералом в "
            "_assert_status_one_of, иначе гейт смешанных исходов не сможет его прочитать"
        )
    return [
        f"pm.test({repr(why)}, () => {{",
        f"  pm.expect(pm.response.code, pm.response.text()).to.be.oneOf({rendered});",
        "});",
    ]


def _create_step(name, body, test_script, auth="jwtBootstrap"):
    return Step(name=name, method="POST", path=LIMIT_PATH, body=body, auth=auth,
                pre_script=_internal(LIMIT_PATH), test_script=test_script)


def _get_step(name, id_var, test_script, auth="jwtBootstrap"):
    path = f"{LIMIT_PATH}/{{{{{id_var}}}}}"
    return Step(name=name, method="GET", path=path, auth=auth,
                pre_script=_internal(path), test_script=test_script)


def _delete_step(name, id_var, test_script=None, auth="jwtBootstrap"):
    path = f"{LIMIT_PATH}/{{{{{id_var}}}}}"
    return Step(name=name, method="DELETE", path=path, auth=auth,
                pre_script=_internal(path),
                test_script=test_script if test_script is not None else [
                    *assert_status(200),
                    *assert_operation_envelope(),
                    "pm.test('teardown withdrawal carried no operation error', () => {",
                    "  const j = pm.response.json();",
                    "  pm.expect(j.error, JSON.stringify(j.error || {})).to.be.undefined;",
                    "});",
                ])


def _list_step(name, query, test_script, auth="jwtBootstrap"):
    path = LIMIT_PATH + query
    return Step(name=name, method="GET", path=path, auth=auth,
                pre_script=_internal(path), test_script=test_script)


def _capture_created(id_var, op_var="opId"):
    """Assertions + captures shared by every successful Create.

    The id is read out of `metadata`, which is the ONLY source before the operation
    finishes — and it is PRE-ALLOCATED, so it arrives even on an operation that
    ends in error. `save_from_response` registers it as provisional for exactly
    that reason; the collection-level post-script drops it again the moment an
    operation is seen `done` WITH an error, so a phantom id can never travel on
    into the following steps.
    """
    return [
        *assert_status(200),
        *assert_operation_envelope(),
        "pm.test('Create metadata names the limit', () => {",
        "  const j = pm.response.json();",
        "  pm.expect(j.metadata && j.metadata.limitId, JSON.stringify(j.metadata))",
        "    .to.match(/^lim-[0-9a-hjkmnp-tv-z]{17}$/);",
        "});",
        *save_from_response("j.id", op_var),
        *save_from_response("j.metadata && j.metadata.limitId", id_var),
    ]


def _assert_invalid_argument(*substrings):
    """400 INVALID_ARGUMENT whose message carries each substring.

    The code alone is not the contract: `api-conventions.md` makes the TONE part of
    it, and a refusal that arrives with the right code and the wrong sentence is
    how a caller learns the wrong thing about which field it got wrong.
    """
    out = [
        *assert_status(400),
        *assert_grpc_code(3, "INVALID_ARGUMENT"),
    ]
    for s in substrings:
        out += [
            f"pm.test({repr('message carries ' + s)}, () => {{",
            "  const j = pm.response.json();",
            f"  pm.expect(String(j.message || ''), JSON.stringify(j)).to.include({repr(s)});",
            "});",
        ]
    return out


# ===========================================================================
# IAM-LIM-CR-CRUD-OK — VPCQ-01.
# ===========================================================================

CASES.append(Case(
    id="IAM-LIM-CR-CRUD-OK",
    title="State a ceiling for a project → Operation; the limit is observable with a lim- id, "
          "its scope, its subject, its kind and its value",
    classes=["CRUD"],
    priority="P0",
    steps=[
        _create_step(
            name="create-limit",
            body={
                "scope": "PROJECT",
                "scopeId": "{{existingProjectId}}",
                "kind": "vpc.network",
                "value": 4,
            },
            test_script=_capture_created("limCrudId"),
        ),
        poll_operation_until_done(),
        _get_step(
            name="get-limit",
            id_var="limCrudId",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('id is the hyphen-canon lim- form, 21 chars', () => {",
                "  pm.expect(j.id, JSON.stringify(j)).to.match(/^lim-[0-9a-hjkmnp-tv-z]{17}$/);",
                "  pm.expect(String(j.id).length).to.eql(21);",
                "});",
                "pm.test('scope round-trips', () => pm.expect(j.scope, JSON.stringify(j)).to.eql('PROJECT'));",
                "pm.test('scopeId names the project', () => "
                "pm.expect(j.scopeId, JSON.stringify(j)).to.eql(pm.environment.get('existingProjectId')));",
                "pm.test('kind round-trips', () => pm.expect(j.kind, JSON.stringify(j)).to.eql('vpc.network'));",
                # The value is read back as a number, not as whatever JSON happened to
                # carry: a ceiling that arrived as a string would compare unequal to
                # every count on the owner's side and refuse everything.
                "pm.test('value round-trips as 4', () => pm.expect(Number(j.value), JSON.stringify(j)).to.eql(4));",
                # The revision is assigned by the database, and the delta is keyed on
                # it. A zero here would mean no puller could ever see this limit.
                "pm.test('revision is assigned and non-zero', () => "
                "pm.expect(Number(j.revision || 0), JSON.stringify(j)).to.be.above(0));",
                *assert_created_at_seconds(),
            ],
        ),
        _delete_step(name="cleanup-crud-limit", id_var="limCrudId"),
    ],
))


# ===========================================================================
# IAM-LIM-CR-VAL-NEG-VALUE — VPCQ-02.
#
# The second half — "and no row was left behind" — is the load-bearing one. A
# refusal that still stored something would satisfy the status assertion alone and
# leave a ceiling nobody asked for standing over a tenant.
# ===========================================================================

CASES.append(Case(
    id="IAM-LIM-CR-VAL-NEG-VALUE",
    title="A negative ceiling is refused by name, synchronously, and states nothing",
    classes=["VAL", "NEG"],
    priority="P0",
    steps=[
        _create_step(
            name="create-limit-negative-value",
            body={
                "scope": "PROJECT",
                "scopeId": "{{existingProjectId}}",
                "kind": "vpc.subnet",
                "value": -1,
            },
            test_script=_assert_invalid_argument("value"),
        ),
        _list_step(
            name="list-after-negative-value",
            query="?scope=PROJECT&scopeId={{existingProjectId}}&kind=vpc.subnet",
            test_script=[
                *assert_status(200),
                "pm.test('the refused ceiling was not stated', () => {",
                "  const j = pm.response.json();",
                "  const items = j.limits === undefined ? [] : j.limits;",
                "  pm.expect(items, JSON.stringify(j)).to.be.an('array').with.lengthOf(0);",
                "});",
            ],
        ),
        # Positive control on the SAME triple: without it "the list is empty" would
        # be indistinguishable from "this list is always empty".
        _create_step(
            name="create-limit-value-control",
            body={
                "scope": "PROJECT",
                "scopeId": "{{existingProjectId}}",
                "kind": "vpc.subnet",
                "value": 8,
            },
            test_script=_capture_created("limValCtlId"),
        ),
        poll_operation_until_done(),
        _list_step(
            name="list-after-control",
            query="?scope=PROJECT&scopeId={{existingProjectId}}&kind=vpc.subnet",
            test_script=[
                *assert_status(200),
                "pm.test('a legal ceiling on the same triple IS stated', () => {",
                "  const j = pm.response.json();",
                "  const items = j.limits === undefined ? [] : j.limits;",
                "  pm.expect(items, JSON.stringify(j)).to.be.an('array').with.lengthOf(1);",
                "  pm.expect(Number(items[0].value)).to.eql(8);",
                "});",
            ],
        ),
        _delete_step(name="cleanup-value-control", id_var="limValCtlId"),
    ],
))


# ===========================================================================
# IAM-LIM-CR-VAL-KIND — VPCQ-03.
#
# A ceiling stated on a kind nobody counts is a field that is accepted and never
# applied: the administrator sees success and the tenant sees no effect. The
# refusal must therefore be synchronous and must name the field.
# ===========================================================================

CASES.append(Case(
    id="IAM-LIM-CR-VAL-KIND",
    title="A kind outside the closed catalogue is refused by name — a ceiling nobody counts "
          "would be accepted and never applied",
    classes=["VAL", "NEG"],
    priority="P0",
    steps=[
        _create_step(
            name="create-limit-misspelled-kind",
            body={
                "scope": "PROJECT",
                "scopeId": "{{existingProjectId}}",
                "kind": "vpc.netwrok",
                "value": 4,
            },
            test_script=_assert_invalid_argument("kind"),
        ),
        _create_step(
            name="create-limit-unknown-domain",
            body={
                "scope": "DEFAULT",
                "kind": "telephony.line",
                "value": 4,
            },
            test_script=_assert_invalid_argument("kind"),
        ),
        # Positive control — the same door with a catalogued kind.
        _create_step(
            name="create-limit-kind-control",
            body={
                "scope": "PROJECT",
                "scopeId": "{{existingProjectId}}",
                "kind": "vpc.cidrGroup",
                "value": 4,
            },
            test_script=_capture_created("limKindCtlId"),
        ),
        poll_operation_until_done(),
        _delete_step(name="cleanup-kind-control", id_var="limKindCtlId"),
    ],
))


# ===========================================================================
# IAM-LIM-GT-NEG-ABSENT — VPCQ-04.
# ===========================================================================

CASES.append(Case(
    id="IAM-LIM-GT-NEG-ABSENT",
    title="Read a well-formed but absent limit id → NOT_FOUND in the contract tone "
          "(+ the positive pair: a real id reads back)",
    classes=["NEG"],
    priority="P0",
    steps=[
        Step(
            name="get-absent-limit",
            method="GET",
            path=f"{LIMIT_PATH}/lim-00000000000000000",
            auth="jwtBootstrap",
            pre_script=_internal(f"{LIMIT_PATH}/lim-00000000000000000"),
            test_script=[
                *assert_status(404),
                *assert_grpc_code(5, "NOT_FOUND"),
                "pm.test('the tone is the contract one and names the id', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(String(j.message || ''), JSON.stringify(j))",
                "    .to.eql('Limit lim-00000000000000000 not found');",
                "});",
            ],
        ),
        # Positive pair — otherwise "404" is indistinguishable from "this route
        # always 404s", which is exactly what an unregistered RPC looks like.
        _create_step(
            name="create-limit-for-absent-control",
            body={
                "scope": "PROJECT",
                "scopeId": "{{existingProjectId}}",
                "kind": "vpc.gateway",
                "value": 2,
            },
            test_script=_capture_created("limAbsCtlId"),
        ),
        poll_operation_until_done(),
        _get_step(
            name="get-present-limit",
            id_var="limAbsCtlId",
            test_script=[
                *assert_status(200),
                "pm.test('a real id reads back', () => "
                "pm.expect(pm.response.json().kind).to.eql('vpc.gateway'));",
            ],
        ),
        _delete_step(name="cleanup-absent-control", id_var="limAbsCtlId"),
    ],
))


# ===========================================================================
# IAM-LIM-GT-VAL-MALFORMED-ID — VPCQ-05.
#
# Without the synchronous format check a malformed id reaches the store and comes
# back NOT_FOUND — an assertion about the absence of a resource the caller never
# named.
# ===========================================================================

CASES.append(Case(
    id="IAM-LIM-GT-VAL-MALFORMED-ID",
    title="Read a malformed limit id → INVALID_ARGUMENT naming the resource, not NOT_FOUND",
    classes=["VAL", "NEG"],
    priority="P0",
    steps=[
        Step(
            name="get-malformed-limit-id",
            method="GET",
            path=f"{LIMIT_PATH}/not-an-id",
            auth="jwtBootstrap",
            pre_script=_internal(f"{LIMIT_PATH}/not-an-id"),
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('the message names the resource and the offending value', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(String(j.message || ''), JSON.stringify(j))",
                "    .to.eql(\"invalid limit id 'not-an-id'\");",
                "});",
            ],
        ),
    ],
))


# ===========================================================================
# IAM-LIM-CR-CONF-DUP-TRIPLE — VPCQ-06.
#
# The uniqueness is the DATABASE's promise (a partial UNIQUE over the triple), not
# a read-then-write in the service, so the second Create must lose on the WRITE
# rather than on a check it could have raced. The case asserts the refusal AND the
# count: a refusal that still left a row behind would satisfy the first assertion
# alone, and the tenant would then have two ceilings in force with no rule about
# which one applies.
# ===========================================================================

CASES.append(Case(
    id="IAM-LIM-CR-CONF-DUP-TRIPLE",
    title="A second ceiling on the same (scope, subject, kind) → ALREADY_EXISTS, and exactly one "
          "ceiling remains in force for that triple",
    classes=["CONF", "NEG"],
    priority="P0",
    steps=[
        _create_step(
            name="create-first-triple",
            body={
                "scope": "PROJECT",
                "scopeId": "{{existingProjectId}}",
                "kind": "vpc.routeTable",
                "value": 4,
            },
            test_script=_capture_created("limDupId"),
        ),
        poll_operation_until_done(),
        _create_step(
            name="create-duplicate-triple",
            body={
                "scope": "PROJECT",
                "scopeId": "{{existingProjectId}}",
                "kind": "vpc.routeTable",
                "value": 9,
            },
            test_script=[
                *assert_status(409),
                *assert_grpc_code(6, "ALREADY_EXISTS"),
            ],
        ),
        _list_step(
            name="list-triple-after-duplicate",
            query="?scope=PROJECT&scopeId={{existingProjectId}}&kind=vpc.routeTable",
            test_script=[
                *assert_status(200),
                "pm.test('exactly one ceiling is in force for the triple, and it is the first', () => {",
                "  const j = pm.response.json();",
                "  const items = j.limits === undefined ? [] : j.limits;",
                "  pm.expect(items, JSON.stringify(j)).to.be.an('array').with.lengthOf(1);",
                "  pm.expect(Number(items[0].value), 'the refused write must not have applied').to.eql(4);",
                "});",
            ],
        ),
        _delete_step(name="cleanup-dup-limit", id_var="limDupId"),
        # The triple is free again once the ceiling is withdrawn — that is what
        # makes the index PARTIAL, and without this step a withdrawal by mistake
        # would be unrecoverable and nobody would notice until it happened.
        _create_step(
            name="restate-after-withdrawal",
            body={
                "scope": "PROJECT",
                "scopeId": "{{existingProjectId}}",
                "kind": "vpc.routeTable",
                "value": 9,
            },
            test_script=_capture_created("limDupAgainId"),
        ),
        poll_operation_until_done(),
        _delete_step(name="cleanup-dup-again", id_var="limDupAgainId"),
    ],
))


# ===========================================================================
# IAM-LIM-CR-NEG-ABSENT-SCOPE — VPCQ-07.
#
# The lane is DIRECT-READ, because the project belongs to iam. FAILED_PRECONDITION
# would be the answer for a peer's precondition, and there is no peer here.
# ===========================================================================

CASES.append(Case(
    id="IAM-LIM-CR-NEG-ABSENT-SCOPE",
    title="A ceiling for a well-formed but absent project → NOT_FOUND (own row, direct-read lane)",
    classes=["NEG"],
    priority="P0",
    steps=[
        _create_step(
            name="create-limit-absent-project",
            body={
                "scope": "PROJECT",
                "scopeId": "prj00000000000000000",
                "kind": "vpc.network",
                "value": 4,
            },
            test_script=[
                # Authz-first tolerance: the edge gates before the body is judged, so
                # a subject the caller cannot reach may be refused earlier. What must
                # never happen is a 2xx — that would be a ceiling standing over
                # nothing.
                *_assert_status_one_of([403, 404], "a ceiling for an absent project is refused, never accepted"),
                "pm.test('no ceiling was stated for a project that is not there', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.metadata, JSON.stringify(j)).to.be.undefined;",
                "});",
            ],
        ),
    ],
))


# ===========================================================================
# IAM-LIM-RS-CRUD-PRECEDENCE — VPCQ-08.
#
# The three scopes are resolved in ONE place, so an owner service never
# re-implements the rule. The fallback half matters as much as the override half:
# withdrawing a ceiling must hand the answer BACK, not leave the tenant with none.
# ===========================================================================

CASES.append(Case(
    id="IAM-LIM-RS-CRUD-PRECEDENCE",
    title="Resolve returns one row per countable kind of the service; PROJECT overrides ACCOUNT "
          "overrides DEFAULT, and a withdrawal hands the answer back one scope at a time",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="resolve-defaults-only",
            method="GET",
            path=_RESOLVE_Q,
            auth="jwtBootstrap",
            pre_script=_internal(_RESOLVE_Q),
            test_script=[
                *assert_status(200),
                # УТВЕРЖДАЕТСЯ СВОЙСТВО, А НЕ ЧИСЛО — и это записано, чтобы
                # следующий читатель не «починил» его обратно на число.
                #
                # Здесь стояло `lengthOf(8)`: восемь плоских видов vpc. Каталог
                # с тех пор вырос вложенными пределами (сколько подсетей в сети,
                # сколько интерфейсов в подсети), и ответ стал нести двенадцать.
                # Кейс покраснел на ЗАКОННОМ расширении — то есть число держало
                # не свойство, а момент времени.
                #
                # Держать точное число было бы правильно, будь чем: каталог живёт
                # в Go (`domain.countableKinds`), кейс — в Python, и общего
                # источника у них нет. Поэтому проверяются четыре свойства,
                # каждое из которых ломается на настоящем дефекте: чужой домен в
                # ответе, пропажа плоского вида, дубликат, пустой ответ.
                "pm.test('ответ несёт виды ТОЛЬКО этого домена, все плоские и без повторов', () => {",
                "  const j = pm.response.json();",
                "  const items = j.limits === undefined ? [] : j.limits;",
                "  pm.expect(items, JSON.stringify(j)).to.be.an('array');",
                "  const kinds = items.map(l => l.kind);",
                "  pm.expect(kinds.length, JSON.stringify(j)).to.be.at.least(8);",
                "  pm.expect(new Set(kinds).size, 'вид назван дважды: ' + JSON.stringify(kinds)).to.eql(kinds.length);",
                "  const alien = kinds.filter(k => !k.startsWith('vpc.'));",
                "  pm.expect(alien, 'резолв домена vpc вернул чужие виды').to.eql([]);",
                "  const flat = ['vpc.network','vpc.subnet','vpc.address','vpc.networkInterface',",
                "                'vpc.securityGroup','vpc.routeTable','vpc.gateway','vpc.cidrGroup'];",
                "  const missing = flat.filter(k => !kinds.includes(k));",
                "  pm.expect(missing, 'плоский вид пропал из ответа').to.eql([]);",
                "});",
                # The seeded platform default. It is asserted by VALUE because that
                # number lives in exactly one place — the iam seed — and a ceiling
                # read from anywhere else would mean a second source had appeared.
                "pm.test('with nothing stated for the tenant, vpc.network answers from the platform default', () => {",
                "  const j = pm.response.json();",
                "  const row = (j.limits || []).find(l => l.kind === 'vpc.network');",
                "  pm.expect(row, JSON.stringify(j)).to.be.an('object');",
                "  pm.expect(Number(row.value)).to.eql(16);",
                "  pm.expect(row.sourceScope).to.eql('DEFAULT');",
                "});",
            ],
        ),
        _create_step(
            name="state-project-ceiling",
            body={
                "scope": "PROJECT",
                "scopeId": "{{existingProjectId}}",
                "kind": "vpc.network",
                "value": 4,
            },
            test_script=_capture_created("limPrecId"),
        ),
        poll_operation_until_done(),
        Step(
            name="resolve-with-project-override",
            method="GET",
            path=_RESOLVE_Q,
            auth="jwtBootstrap",
            pre_script=_internal(_RESOLVE_Q),
            test_script=[
                *assert_status(200),
                "pm.test('the project overrides the platform default, and says so', () => {",
                "  const j = pm.response.json();",
                "  const row = (j.limits || []).find(l => l.kind === 'vpc.network');",
                "  pm.expect(row, JSON.stringify(j)).to.be.an('object');",
                "  pm.expect(Number(row.value)).to.eql(4);",
                "  pm.expect(row.sourceScope).to.eql('PROJECT');",
                "  pm.expect(row.sourceScopeId).to.eql(pm.environment.get('existingProjectId'));",
                "});",
                # A kind nobody stated anything for still answers — the resolution is
                # per KIND, not per tenant.
                "pm.test('an untouched kind still answers from the default', () => {",
                "  const j = pm.response.json();",
                "  const row = (j.limits || []).find(l => l.kind === 'vpc.subnet');",
                "  pm.expect(row, JSON.stringify(j)).to.be.an('object');",
                "  pm.expect(row.sourceScope).to.eql('DEFAULT');",
                "});",
            ],
        ),
        _delete_step(name="withdraw-project-ceiling", id_var="limPrecId"),
        Step(
            name="resolve-after-withdrawal",
            method="GET",
            path=_RESOLVE_Q,
            auth="jwtBootstrap",
            pre_script=_internal(_RESOLVE_Q),
            test_script=[
                *assert_status(200),
                "pm.test('the withdrawal hands the answer back to the platform default', () => {",
                "  const j = pm.response.json();",
                "  const row = (j.limits || []).find(l => l.kind === 'vpc.network');",
                "  pm.expect(row, JSON.stringify(j)).to.be.an('object');",
                "  pm.expect(Number(row.value)).to.eql(16);",
                "  pm.expect(row.sourceScope).to.eql('DEFAULT');",
                "});",
            ],
        ),
    ],
))


# ===========================================================================
# IAM-LIM-RS-SEC-NARROW-GATE — VPCQ-09.
#
# The relation guarding the two owner-facing reads must NOT be one a wildcard tuple
# satisfies. `viewer` on the cluster object is satisfied by `user:*` BY DESIGN (the
# global placement catalogue must be readable by every authenticated tenant), so a
# check against it would answer "yes" to everyone and look exactly like a gate.
#
# The positive pair is mandatory: without it "denied" is indistinguishable from
# "the RPC is not registered", and both produce a refusal.
# ===========================================================================

CASES.append(Case(
    id="IAM-LIM-RS-SEC-NARROW-GATE",
    title="Resolve is refused to an authenticated tenant with no cluster grant, and served to the "
          "principal that holds the narrow relation",
    classes=["SEC", "NEG"],
    priority="P0",
    steps=[
        Step(
            name="resolve-as-plain-tenant",
            method="GET",
            path=_RESOLVE_Q,
            auth="jwtAccountAdminA",
            pre_script=_internal(_RESOLVE_Q),
            test_script=[
                # 403 is the answer the catalog gate gives; 404 would be an
                # existence-hiding refusal of the same decision. What must never
                # happen is 200 — that would mean the relation is satisfied by
                # anybody authenticated.
                *_assert_status_one_of([403, 404], "a tenant without the narrow relation is refused, never served"),
                "pm.test('no ceiling value reaches a caller without the narrow relation', () => {",
                "  const body = pm.response.text();",
                "  pm.expect(body, body).to.not.match(/\"value\"\\s*:/);",
                "});",
            ],
        ),
        Step(
            name="resolve-as-authorised-principal",
            method="GET",
            path=_RESOLVE_Q,
            auth="jwtBootstrap",
            pre_script=_internal(_RESOLVE_Q),
            test_script=[
                *assert_status(200),
                "pm.test('the authorised principal is served', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.limits, JSON.stringify(j)).to.be.an('array').with.length.above(0);",
                "});",
            ],
        ),
    ],
))


# ===========================================================================
# IAM-LIM-CS-CRUD-DELTA — VPCQ-11.
#
# The negative half is the load-bearing one. A revision that advanced on every
# write would make an idempotent re-assignment — the ordinary shape of a
# configuration tool running twice — look like a change to every puller, and every
# owner's projection would be rebuilt for nothing.
# ===========================================================================

CASES.append(Case(
    id="IAM-LIM-CS-CRUD-DELTA",
    title="The delta reports what changed after the cursor, does NOT report a write that restated "
          "the same value, and refuses a cursor it did not produce",
    classes=["CRUD"],
    priority="P1",
    steps=[
        Step(
            name="delta-take-cursor",
            method="GET",
            path=f"{LIMIT_PATH}:changedSince",
            auth="jwtBootstrap",
            pre_script=_internal(f"{LIMIT_PATH}:changedSince"),
            test_script=[
                *assert_status(200),
                "pm.test('the cursor comes back even when the page is the last one', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(String(j.nextCursor || ''), JSON.stringify(j)).to.have.length.above(0);",
                "});",
                *save_from_response("j.nextCursor", "limCursor"),
            ],
        ),
        _create_step(
            name="state-ceiling-after-cursor",
            body={
                "scope": "PROJECT",
                "scopeId": "{{existingProjectId}}",
                "kind": "vpc.address",
                "value": 32,
            },
            test_script=_capture_created("limDeltaId"),
        ),
        poll_operation_until_done(),
        Step(
            name="delta-sees-the-new-ceiling",
            method="GET",
            path=_CHANGED_Q("{{limCursor}}"),
            auth="jwtBootstrap",
            pre_script=_internal(_CHANGED_Q("{{limCursor}}")),
            test_script=[
                *assert_status(200),
                "pm.test('the delta carries exactly the ceiling stated after the cursor', () => {",
                "  const j = pm.response.json();",
                "  const items = j.changes === undefined ? [] : j.changes;",
                "  const mine = items.filter(c => c.limit && c.limit.id === pm.environment.get('limDeltaId'));",
                "  pm.expect(mine, JSON.stringify(j)).to.have.lengthOf(1);",
                "  pm.expect(Number(mine[0].limit.value)).to.eql(32);",
                "  pm.expect(mine[0].withdrawn, 'a live ceiling is not withdrawn').to.not.eql(true);",
                "});",
                *save_from_response("j.nextCursor", "limCursor2"),
            ],
        ),
        Step(
            name="restate-the-same-value",
            method="PATCH",
            path=f"{LIMIT_PATH}/{{{{limDeltaId}}}}",
            auth="jwtBootstrap",
            pre_script=_internal(f"{LIMIT_PATH}/{{{{limDeltaId}}}}"),
            body={"updateMask": "value", "value": 32},
            test_script=[
                *assert_status(200),
                *assert_operation_envelope(),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="delta-ignores-the-restatement",
            method="GET",
            path=_CHANGED_Q("{{limCursor2}}"),
            auth="jwtBootstrap",
            pre_script=_internal(_CHANGED_Q("{{limCursor2}}")),
            test_script=[
                *assert_status(200),
                "pm.test('a write that restated the same value is not a change', () => {",
                "  const j = pm.response.json();",
                "  const items = j.changes === undefined ? [] : j.changes;",
                "  const mine = items.filter(c => c.limit && c.limit.id === pm.environment.get('limDeltaId'));",
                "  pm.expect(mine, JSON.stringify(j)).to.have.lengthOf(0);",
                "});",
            ],
        ),
        Step(
            name="raise-the-ceiling",
            method="PATCH",
            path=f"{LIMIT_PATH}/{{{{limDeltaId}}}}",
            auth="jwtBootstrap",
            pre_script=_internal(f"{LIMIT_PATH}/{{{{limDeltaId}}}}"),
            body={"updateMask": "value", "value": 64},
            test_script=[
                *assert_status(200),
                *assert_operation_envelope(),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="delta-sees-the-raise",
            method="GET",
            path=_CHANGED_Q("{{limCursor2}}"),
            auth="jwtBootstrap",
            pre_script=_internal(_CHANGED_Q("{{limCursor2}}")),
            test_script=[
                *assert_status(200),
                "pm.test('a real change IS a change, and carries the new value', () => {",
                "  const j = pm.response.json();",
                "  const items = j.changes === undefined ? [] : j.changes;",
                "  const mine = items.filter(c => c.limit && c.limit.id === pm.environment.get('limDeltaId'));",
                "  pm.expect(mine, JSON.stringify(j)).to.have.lengthOf(1);",
                "  pm.expect(Number(mine[0].limit.value)).to.eql(64);",
                "});",
            ],
        ),
        Step(
            name="delta-refuses-a-foreign-cursor",
            method="GET",
            path=_CHANGED_Q("not-a-cursor"),
            auth="jwtBootstrap",
            pre_script=_internal(_CHANGED_Q("not-a-cursor")),
            test_script=[
                # Reading garbage as "from the beginning" would replay the entire
                # history and look exactly like a healthy first run.
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
        _delete_step(name="cleanup-delta-limit", id_var="limDeltaId"),
    ],
))


# ===========================================================================
# IAM-LIM-DL-IDM-REPEAT — withdrawal is idempotent.
#
# The caller asked for the ceiling to be gone, and it is. A second withdrawal that
# answered differently would make a retry — the ordinary response to a lost
# connection — look like a failure.
# ===========================================================================

CASES.append(Case(
    id="IAM-LIM-DL-IDM-REPEAT",
    title="Withdrawing a ceiling twice succeeds both times, and the ceiling stays gone",
    classes=["IDM"],
    priority="P1",
    steps=[
        _create_step(
            name="create-limit-for-idempotent-withdrawal",
            body={
                "scope": "PROJECT",
                "scopeId": "{{existingProjectId}}",
                "kind": "vpc.securityGroup",
                "value": 4,
            },
            test_script=_capture_created("limIdmId"),
        ),
        poll_operation_until_done(),
        _delete_step(name="withdraw-once", id_var="limIdmId"),
        _delete_step(name="withdraw-again", id_var="limIdmId"),
        _get_step(
            name="get-withdrawn-limit",
            id_var="limIdmId",
            test_script=[
                *assert_status(404),
                *assert_grpc_code(5, "NOT_FOUND"),
            ],
        ),
    ],
))
