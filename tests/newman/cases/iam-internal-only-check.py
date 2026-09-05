# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set для iam-internal-only-check.

Проверка изоляции `Internal*` сервисов от external TLS endpoint
(Internal*-методы не публикуются на advertised external endpoint).

  InternalIAMService / InternalUserService /
  InternalBreakGlassService
  должны быть доступны ТОЛЬКО на cluster-internal listener — на api-gateway это
  выделенный `internal-rest` listener (:8081), в local/CI port-forward
  {{internalBaseUrl}} = http://localhost:18081. ПУБЛИЧНЫЙ cmux
  ({{baseUrl}} = http://localhost:18080) НЕ отдаёт /iam/v1/internal/* — 404 by
  design (ban #6). Те же пути должны быть недостижимы и на advertised external
  TLS listener ({{externalBaseUrl}}) — см. разбор ниже: часть путей доказывает
  это mux-промахом 404, часть — только fail-closed отказом, и кейс различает их.

Coverage:
  IAM-INT-NEG-EXT-REST-ALIVE           — CONTROL: external listener отдаёт REST (200 на публичном пути);
                                         без него любой 404 ниже ничего не значит
  IAM-INT-NEG-EXT-USER-UPSERT          — InternalUserService.UpsertFromIdentity → 404 mux-miss на external
  IAM-INT-NEG-EXT-IAM-LOOKUPSUBJECT    — InternalIAMService.LookupSubject → 404 mux-miss на external
  IAM-INT-NEG-EXT-IAM-CHECK            — InternalIAMService.Check → 404 mux-miss на external
  IAM-INT-NEG-EXT-UNBOUND-NEVER-SUCCEEDS
                                       — ReadTuples / SessionRevocations.{Revoke,IsRevoked,ListByUser} /
                                         ForceLogout / InternalUserService.Get: НИКОГДА не 2xx на
                                         external + пин к absent-path контролю. НЕ доказывает
                                         route-изоляцию (см. «TWO FAMILIES» ниже) и прямо это заявляет
  IAM-INT-OK-INT-USER-UPSERT           — UpsertFromIdentity → 200 на internal (positive control)
  IAM-INT-OK-INT-IAM-LOOKUPSUBJECT     — LookupSubject → РОВНО 200 на internal (positive control;
                                         `oneOf([200,404])` снят — 404 здесь и был бы дефектом)
  IAM-INT-OK-INT-IAM-LOOKUPSUBJECT-UNKNOWN
                                       — неизвестный external_id → 404 ВЛАДЕЛЬЦА: текст называет
                                         запрошенный ключ. Код 5 различителем НЕ является — его
                                         несёт и промах mux; на этом различии стоит классификатор
                                         посева церемонии
  IAM-INT-OK-INT-IAM-CHECK             — InternalIAMService.Check → 200 на internal
  IAM-INT-NEG-EXT-IC-LIST              — InternalInteractiveClientService.List → 404 mux-miss на external
  IAM-INT-NEG-EXT-IC-CREATE            — InternalInteractiveClientService.Create → 404 mux-miss на external
  IAM-INT-OK-INT-IC-LIST               — тот же путь на internal → 200 со списком (positive control)
  IAM-INT-NEG-EXT-LIMIT-LIST           — InternalLimitService.List → 404 mux-miss на external (VPCQ-10)
  IAM-INT-NEG-EXT-LIMIT-CREATE         — InternalLimitService.Create → 404 mux-miss на external (VPCQ-10)
  IAM-INT-OK-INT-LIMIT-LIST            — тот же путь на internal → 200 со списком и посеянными
                                         умолчаниями (positive control)

Why no black-box POSITIVE revoke→IsRevoked case:
  InternalSessionRevocationsService is gRPC-only on :9091 — the api-gateway does
  NOT front it on its REST mux (its callers are the api-gateway logout handler's
  gRPC client + the Hydra refresh-hook, both server-side). There is therefore no
  HTTP surface to drive revoke→IsRevoked black-box through Newman. The closed
  loop (Revoke writes session_revocations → refresh-hook IsRevoked denies) is
  covered white-box by the integration test
  internal/repo/kacho/pg/session_revocation_loop_integration_test.go. The
  black-box-feasible contract here is the external-isolation NEGATIVE: these
  internal RPCs must never appear on the advertised external TLS endpoint.

  Same applies to the USER-LEVEL revoke-all gate (ForceLogout /
  Revoke(revoke_all_user_tokens)): the refresh-hook compares the token's session
  auth_time against a per-user `user_token_revocations.revoke_before` cutoff —
  a server-side Hydra webhook with no public HTTP surface. It is covered
  white-box by unit tests (internal/handler/iamhooks/refresh_hook_handler_test.go
  user-level cases; internal/apps/.../{internal_iam,session_revocations}) and the
  integration test internal/repo/kacho/pg/user_token_revocations_repo_integration_test.go.
  The black-box contract that remains is the external-isolation NEGATIVE below
  (IAM-INT-NEG-EXT-UNBOUND-NEVER-SUCCEEDS — with the caveat recorded there that it
  witnesses fail-closed refusal, not route isolation).

Note: TrustPolicyService and OpaBundleService have been removed — the
corresponding negative cases (IAM-INT-NEG-EXT-TRUST-CREATE,
IAM-INT-NEG-EXT-OPA-GETBUNDLE) are deleted because the underlying RPCs no longer
exist anywhere.

Environment requirements:
  {{baseUrl}}          — PUBLIC api-gateway cmux (http://localhost:18080 in port-forward).
                         Used for the operations poll (public OpsProxy). Does NOT serve
                         /iam/v1/internal/* (404 by design).
  {{internalBaseUrl}}  — api-gateway dedicated cluster-internal REST listener
                         (`internal-rest` :8081; http://localhost:18081 in the CI
                         port-forward). The POSITIVE controls redirect here via
                         _internal_url_override — Internal* RPCs are served ONLY here. If
                         unset (local dev without the internal-rest port-forward) the
                         positive controls are skipped with a warning (local-dev fallback).
  {{externalBaseUrl}}  — the ADVERTISED EXTERNAL TLS LISTENER of the api-gateway
                         (`KACHO_API_GATEWAY_TLS_LISTEN_ADDR` = :8443, advertised as
                         api.kacho.local:443). deploy/scripts/newman-{e2e,parallel}.sh
                         forward it to https://127.0.0.1:18443 and inject it as
                         `--env-var externalBaseUrl`. Must NOT expose Internal* paths.

WHY externalBaseUrl IS THE :8443 LISTENER AND NOT THE INGRESS HOSTNAME
----------------------------------------------------------------------
This variable used to be the literal `https://api.kacho.local:443`, and every
step below silently did nothing:

  * `api.kacho.local` is not in the host's resolver, and putting it there needs
    root — a manual, privileged setup step the harness must not depend on;
  * even resolved, it would not connect: kind maps only node:80 → host:28080, so
    443 is not published off the node at all;
  * and even reached, it would prove nothing about REST. That Ingress carries
    `nginx.ingress.kubernetes.io/backend-protocol: GRPCS`, so it proxies gRPC —
    measured on the stand, EVERY REST path through it answers 502, public and
    internal alike. A "404 on external" assertion behind a uniform 502 is the
    same vacuity in a new costume.

Ban #6 is a property of the LISTENER — which routes it serves — not of the DNS
name used to find it. So the probes address the TLS listener directly, over a
forwarded port, exactly as the public and internal probes already do. The
certificate names the gateway's in-cluster identity and cannot match 127.0.0.1,
so those steps carry `insecure_tls=True` (per-item `strictSSL:false`, visible in
the generated collection) — the tunnel's trust chain is not the subject; the
route table is.

WHAT AN UNAUTHENTICATED PROBE CANNOT SEE (measured 2026-07-28 on kind-kacho)
---------------------------------------------------------------------------
On this listener authN and the authz catalog run BEFORE the REST mux. Without a
token EVERY path answers alike — `/zzz` and `/iam/v1/internal/iam:check` both
403 — so an unauthenticated probe cannot tell an isolated route from a typo, and
the 404 these cases assert can never arrive. All external probes therefore carry
a valid Bearer. That also makes the claim stronger: not merely "a stranger gets
nothing", but "an AUTHENTICATED external caller still cannot reach Internal*".

TWO FAMILIES, AND ONLY ONE OF THEM DISCRIMINATES
------------------------------------------------
Measured, authenticated, on the three listeners (internal :8081 / public :8080 /
external TLS :8443):

  BOUND REST paths — `/iam/v1/internal/users:upsertFromIdentity`,
  `iam:lookupSubject`, `iam:check`:
      internal 200 / 404-from-service / 400-from-service   (the route is real)
      public   404 {"code":5,"message":"Not Found"}         (mux miss)
      external 404 {"code":5,"message":"Not Found"}         (mux miss)
  These carry the evidence: the path demonstrably works somewhere, and is
  demonstrably absent from the external mux. The body is checked too — a mux miss
  is grpc-gateway's ROUTING error, the bare {code:5, message:"Not Found"}, and a
  service-level miss NAMES the resource and the id ("<Resource> <id> not found",
  contract tone). Conflating them would let a real 404-from-iam pass as isolation.

  The measurement above was re-taken after the hidden route stopped being answered
  by a SECOND producer. It used to reply "404 page not found" in text/plain while
  an ordinary miss replied JSON — so the CONTENT TYPE of a 404 told an outside
  caller whether an administrative path lived at that address, which is exactly
  the reconnaissance ban #6 exists to deny. The discriminator this case relies on
  is therefore the MESSAGE now, not the content type; a mux miss here is
  byte-identical to the nonsense-path control fired at the same listener.

  UNBOUND fully-qualified paths — InternalSessionRevocationsService/{Revoke,IsRevoked},
  InternalIAMService/ForceLogout, and GET /iam/v1/internal/users/{id}:
      403 on ALL THREE listeners, byte-identical to `/zzz`.
  They have no catalog entry, so the fail-closed authz gate answers before the
  mux is consulted — including on the listener where they are supposed to work.
  A "404 on external" assertion on these could never pass, and "not 404, so not
  exposed" would be indistinguishable from a misspelt path.

  The docstring here previously claimed these "are served ONLY by the
  cluster-internal sub-mux". They are served on no REST listener at all; they are
  gRPC-only on iam :9091, which the note about SessionRevocations further down
  already says. The block above them describes replacing an earlier set of
  invented paths that "404'd everywhere" — and the replacement 403s everywhere,
  which is the same class one step over.

  So family B asserts what it can actually witness — NEVER 2xx — and pins its
  code against a nonsense-path control fired at the same listener in the same
  case. That control is not decoration: it is the case admitting, in the report,
  that this family does not discriminate. If a route ever appears, the 2xx
  assertion fires; if the fail-closed behaviour changes, the pin fires.

  IAM-INT-NEG-EXT-REST-ALIVE is the other half. Without a positive control on the
  SAME endpoint proving it serves REST at all, every 404 below would be satisfied
  by an endpoint that was simply down — which is precisely how this file spent
  its time before.

Test-first note (strict TDD):
  Cases are written RED-first. Positive-control (internal) cases fail until the
  Internal* RPCs are implemented. Negative (external) cases pass only when the
  probe is ANSWERED and the answer is the expected one — an unreachable endpoint
  is a RED harness, never a green check. Do not weaken assertions, and in
  particular do not reintroduce `if (pm.response.code === undefined) return;`.
"""

CASES = []

# ---------------------------------------------------------------------------
# Unbound REST paths for Internal* RPCs that carry NO `google.api.http` binding.
#
# Only two InternalIAMService RPCs are annotated (`:lookupSubject`, `:check`);
# ReadTuples / SessionRevocations.Revoke / .IsRevoked / ForceLogout are not.
#
# The first of the four used to be InternalAuthorizeService/WriteTuples. That RPC
# was retired from the contract (#788, zero callers), and a probe aimed at a
# method that no longer exists asserts nothing: it would pass because there is no
# such method, not because ban #6 holds — the exact defect this block's own note
# below describes as "the form of an isolation check and none of its substance".
# ReadTuples is its live sibling on the same service, equally unbound.
# grpc-gateway is generated with `generate_unbound_methods=true`, so the route
# these four actually answer on is the fully-qualified default form below — and
# it is served ONLY by the cluster-internal sub-mux (ban #6).
#
# The earlier `/iam/v1/internal/authorize:writeTuples`-style paths were invented:
# no binding of that shape exists on ANY listener, so "404 on external" held for
# a path that 404s everywhere. The probe had the form of an isolation check and
# none of its substance. Same shape as the storage suite's *-EXTERNAL-ABSENT
# cases, which target this default form for exactly this reason.
# ---------------------------------------------------------------------------

# Путь InternalAuthorizeService/WriteTuples здесь БОЛЬШЕ НЕ ПРОБУЕТСЯ: службы
# администрирования хранилища отношений не существует (стадия S6 эпика #747 сняла
# её вместе с внешним движком прав). Проба по этому адресу стала бы дублем
# бессмысленного контроля `/zzz` — тем самым «утверждением, которое не может
# упасть», ради отличия от которого весь этот блок и написан.
_UNBOUND_SR_REVOKE = "/kacho.cloud.iam.v1.InternalSessionRevocationsService/Revoke"
_UNBOUND_SR_ISREVOKED = "/kacho.cloud.iam.v1.InternalSessionRevocationsService/IsRevoked"
_UNBOUND_SR_LISTBYUSER = "/kacho.cloud.iam.v1.InternalSessionRevocationsService/ListByUser"
_UNBOUND_FORCE_LOGOUT = "/kacho.cloud.iam.v1.InternalIAMService/ForceLogout"

# ---------------------------------------------------------------------------
# Helper: pre_script fragment that overrides the request URL to externalBaseUrl.
# Used for all "on external" negative checks.
# gen.py generates {{baseUrl}}<path>; this pre_script replaces it with
# {{externalBaseUrl}}<path> at request-time.
# ---------------------------------------------------------------------------

def _external_url_override(path: str):
    """Return a pre_script list that overrides the request URL to externalBaseUrl+path.

    externalBaseUrl is harness configuration: without it the external-isolation
    negative cannot be attempted at all. That is a broken harness, not a legal
    mode, so require_env_url ASSERTS it (naming the variable) before skipping —
    otherwise losing the variable would silently delete these checks and the
    suite would still read GREEN."""
    return require_env_url(
        "externalBaseUrl", path,
        "external-isolation negative — Internal* paths must not be reachable on "
        "the advertised external TLS listener")


# `_extIsolationStep` used to be set here, described as "used in test_script to
# handle DNS failures". No test script ever read it, and the DNS handling it
# referred to was the `code === undefined → PASS` escape that made these checks
# unfalsifiable. Both are gone.


def _external_step(name, method, path, body=None, auth="jwtAccountAdminA", test_script=None):
    """An external-endpoint probe: authenticated, TLS-verification off for the
    forwarded port, URL rewritten to {{externalBaseUrl}}, and always asserting it
    was ANSWERED before it asserts anything about the answer."""
    return Step(
        name=name,
        method=method,
        path=path,
        body=body,
        auth=auth,
        insecure_tls=True,
        pre_script=_external_url_override(path),
        test_script=test_script or [],
    )


# ===========================================================================
# CONTROL: the external endpoint SERVES REST at all
#
# Every negative below reads "this path is not there". That sentence is only
# worth something if the endpoint answers when a path IS there. Without this
# control, an endpoint that was simply down would satisfy all eight negatives —
# which is materially what happened while the advertised host did not resolve.
# ===========================================================================

CASES.append(Case(
    id="IAM-INT-NEG-EXT-REST-ALIVE",
    title="Control: the advertised external TLS listener serves REST (so a 404 below means 'not routed', not 'nothing there')",
    classes=["SEC"],
    priority="P0",
    steps=[
        _external_step(
            name="public-path-on-external",
            method="GET",
            path="/geo/v1/regions",
            test_script=[
                *assert_answered("EXT-ALIVE"),
                "// A PUBLIC path on the SAME listener as every negative below. If this is not",
                "// 200, the negatives prove nothing and must not be read as isolation.",
                "pm.test('EXT-ALIVE: public REST path answers 200 on the external listener', () =>",
                "  pm.expect(pm.response.code, pm.response.text()).to.eql(200));",
                "pm.test('EXT-ALIVE: and it is a real REST body, not an edge error page', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j, JSON.stringify(j)).to.have.property('regions');",
                "});",
            ],
        ),
    ],
))


# ===========================================================================
# FAMILY A — BOUND Internal* REST paths. These DISCRIMINATE.
#
# The path is proven real by the positive controls further down (same path, the
# internal-rest listener, 200 / service-level 4xx). Here it must be a
# grpc-gateway MUX MISS: status 404 AND grpc-gateway's own ROUTING body. The body
# matters — a service-level "not found" NAMES the resource and the id, and
# accepting it here would let a genuine iam 404 masquerade as route isolation.
# ===========================================================================

def _mux_miss_assertions(label: str, leak_expr: str = None, leak_desc: str = None):
    out = [
        *assert_answered(label),
        f"pm.test('{label}: status 404 — path is not routed on the external mux', () =>",
        f"  pm.expect(pm.response.code, pm.response.text()).to.eql(404));",
        "// Discriminate a MUX miss from a SERVICE miss. An unrouted path is answered by",
        "// grpc-gateway's ROUTING error — the bare {code:5, message:'Not Found'}, the same",
        "// answer a nonsense path gets on this listener. iam's own NOT_FOUND always names",
        "// the resource and the id ('<Resource> <id> not found', contract tone), so any",
        "// other message here would mean the request REACHED the service.",
        "//",
        "// This used to ask whether the body was JSON AT ALL, because the hidden route was",
        "// answered by a second producer in plain text. That difference was itself an",
        "// existence-oracle for the admin surface and has been removed; the discriminator",
        "// is the message, not the content type.",
        f"pm.test('{label}: 404 is a mux miss, not a service-level NOT_FOUND', () => {{",
        "  let j = null;",
        "  try { j = pm.response.json(); } catch (e) { j = null; }",
        "  pm.expect((j || {}).message, 'any other message here would mean the request REACHED the service')",
        "    .to.eql('Not Found');",
        "});",
    ]
    if leak_expr:
        out += [
            f"pm.test('{label}: no {leak_desc} in body', () => {{",
            "  let j = null;",
            "  try { j = pm.response.json(); } catch (e) { j = null; }",
            f"  pm.expect({leak_expr}, '{leak_desc} must not be in the response').to.be.undefined;",
            "});",
        ]
    return out


CASES.append(Case(
    id="IAM-INT-NEG-EXT-USER-UPSERT",
    title="InternalUserService.UpsertFromIdentity on the external TLS listener → 404 mux miss (internal-only, ban #6)",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        _external_step(
            name="upsert-on-external",
            method="POST",
            path="/iam/v1/internal/users:upsertFromIdentity",
            body={"externalId": "zit-isolation-{{runId}}", "email": "leak@kacho.local"},
            test_script=_mux_miss_assertions("EXT-UPSERT", "(j || {}).user && j.user.id", "user.id"),
        ),
    ],
))


CASES.append(Case(
    id="IAM-INT-NEG-EXT-IAM-LOOKUPSUBJECT",
    title="InternalIAMService.LookupSubject on the external TLS listener → 404 mux miss (internal-only, ban #6)",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        _external_step(
            name="lookup-subject-on-external",
            method="POST",
            path="/iam/v1/internal/iam:lookupSubject",
            body={"externalId": "zit-anything"},
            test_script=_mux_miss_assertions("EXT-LOOKUPSUBJ", "(j || {}).subjectId", "subjectId"),
        ),
    ],
))


CASES.append(Case(
    id="IAM-INT-NEG-EXT-IAM-CHECK",
    title="InternalIAMService.Check on the external TLS listener → 404 mux miss (internal-only, ban #6)",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        _external_step(
            name="iam-check-on-external",
            method="POST",
            # CheckRequest names the object field `object` and takes a TYPED FGA
            # string; there is no `objectId` (that belongs to ExpandAccessRequest).
            path="/iam/v1/internal/iam:check",
            body={"subjectId": "user:usr00000000000000abc", "relation": "viewer",
                  "object": "account:acc00000000000abc"},
            test_script=_mux_miss_assertions("EXT-IAM-CHECK", "(j || {}).allowed", "allowed verdict"),
        ),
    ],
))


# ===========================================================================
# FAMILY B — UNBOUND / by-id paths. These do NOT discriminate, and the case
# says so out loud rather than implying otherwise.
#
# Measured on all three listeners: 403, byte-identical to a nonsense path,
# because no catalog entry exists and the fail-closed authz gate answers before
# the mux. So the honest assertions are:
#   1. it was ANSWERED (else the harness is broken);
#   2. it NEVER succeeds — no 2xx, on the external listener, ever;
#   3. its code equals the nonsense-path control taken at the same listener in
#      the same case — the explicit admission that this family cannot tell
#      "isolated" from "misspelt", recorded where a reader will see it.
# If a route ever appears for these, (2) fires. If fail-closed changes, (3) fires.
# ===========================================================================

_UNBOUND_PROBES = [
    ("EXT-SR-REVOKE", "InternalSessionRevocationsService.Revoke", _UNBOUND_SR_REVOKE,
     {"userId": "usr00000000000000abc", "tokenJti": "leak-jti", "reason": "x"}),
    ("EXT-SR-ISREVOKED", "InternalSessionRevocationsService.IsRevoked", _UNBOUND_SR_ISREVOKED,
     {"tokenJti": "leak-jti"}),
    # ListByUser — единственный глагол этой службы, чей ОТВЕТ несёт сведения о
    # человеке (какие его сессии сняли, когда и почему), и до #1140 он один из
    # трёх здесь отсутствовал. Наблюдаемая арендатором поверхность у него ровно
    # одна — «снаружи недостижим», и утверждать надо именно её: REST-привязки у
    # службы нет by construction (`google.api.http` в её proto — ноль), поэтому
    # положительной чёрноящичной полосы для «человек видит свою историю» здесь
    # не существует, и подделывать её нельзя. Сужение круга держателей #1140
    # утверждается там, где оно происходит: гейтом модели
    # (authzmap/reading_a_persons_session_history_test.go) и вердиктом по
    # закоммиченным строкам (service/reading_a_persons_session_history_*).
    ("EXT-SR-LISTBYUSER", "InternalSessionRevocationsService.ListByUser", _UNBOUND_SR_LISTBYUSER,
     {"userId": "usr00000000000000abc", "pageSize": 10}),
    ("EXT-FORCELOGOUT", "InternalIAMService.ForceLogout", _UNBOUND_FORCE_LOGOUT,
     {"userId": "usr00000000000000abc", "reason": "x"}),
]

_unbound_steps = [
    # The control FIRST: its code is what the probes are pinned against.
    _external_step(
        name="nonsense-path-control-on-external",
        method="GET",
        path="/kacho-no-such-route-{{runId}}",
        test_script=[
            *assert_answered("EXT-CONTROL"),
            "// A path that certainly does not exist, on the same listener, with the same",
            "// credentials. Whatever the edge answers here is what 'unreachable' looks like",
            "// WITHOUT any isolation being involved — the baseline the probes below are",
            "// measured against.",
            "pm.test('EXT-CONTROL: a certainly-absent path does not succeed', () =>",
            "  pm.expect(pm.response.code, pm.response.text()).to.be.above(399));",
            "pm.environment.set('_extAbsentCode', String(pm.response.code));",
        ],
    ),
]

for _label, _rpc, _path, _body in _UNBOUND_PROBES:
    _unbound_steps.append(_external_step(
        name=f"{_label.lower()}-on-external",
        method="POST",
        path=_path,
        body=_body,
        test_script=[
            *assert_answered(_label),
            f"pm.test('{_label}: {_rpc} NEVER succeeds on the external listener', () => {{",
            "  pm.expect(pm.response.code, pm.response.text()).to.not.be.oneOf([200, 201, 202, 204]);",
            "});",
            f"pm.test('{_label}: indistinguishable from an absent path (this probe does NOT "
            f"prove route isolation — see the family-B note)', () => {{",
            "  const baseline = pm.environment.get('_extAbsentCode');",
            "  pm.expect(String(pm.response.code), 'diverged from the absent-path baseline: "
            "the edge changed behaviour and this probe needs re-deriving').to.eql(baseline);",
            "});",
        ],
    ))

_unbound_steps.append(_external_step(
    name="internal-user-get-by-id-on-external",
    method="GET",
    path="/iam/v1/internal/users/usr00000000000000abc",
    test_script=[
        *assert_answered("EXT-USER-GET"),
        "pm.test('EXT-USER-GET: InternalUserService.Get NEVER succeeds on the external listener', () => {",
        "  pm.expect(pm.response.code, pm.response.text()).to.not.be.oneOf([200, 201, 202, 204]);",
        "});",
        "pm.test('EXT-USER-GET: no user id leak', () => {",
        "  let j = null;",
        "  try { j = pm.response.json(); } catch (e) { j = null; }",
        "  pm.expect((j || {}).id, 'id must not be in the response').to.be.undefined;",
        "});",
        "pm.test('EXT-USER-GET: indistinguishable from an absent path (does NOT prove route isolation)', () => {",
        "  pm.expect(String(pm.response.code)).to.eql(pm.environment.get('_extAbsentCode'));",
        "});",
    ],
))

CASES.append(Case(
    id="IAM-INT-NEG-EXT-UNBOUND-NEVER-SUCCEEDS",
    title="Unbound Internal* RPCs never succeed on the external TLS listener (fail-closed; NOT a route-isolation proof — see case notes)",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=_unbound_steps,
))


def _internal_url_override(path: str):
    """Return a pre_script list that overrides the request URL to internalBaseUrl+path.

    The POSITIVE controls exercise Internal* RPCs (UpsertFromIdentity,
    InternalIAMService.LookupSubject/Check). These paths (/iam/v1/internal/*) are
    served ONLY by the api-gateway dedicated cluster-internal REST listener
    (`internal-rest` Service port, :8081) — NEVER by the public cmux (:8080), which
    404s them by design (ban #6). The premise `{{baseUrl}} is already the internal
    mux` is FALSE for the public port-forward: {{baseUrl}} (:18080) reaches the PUBLIC
    listener. So point these controls at {{internalBaseUrl}} (the internal-rest
    port-forward, http://localhost:18081 in CI). Mirrors _external_url_override:
    a missing internalBaseUrl is a broken harness, not a legal mode, so the guard
    ASSERTS it (RED, naming the variable) before skipping — see
    gen.py::require_env_url."""
    return require_env_url(
        "internalBaseUrl", path,
        "internal-mux positive control — Internal* paths live ONLY on the "
        "cluster-internal REST listener")


# ===========================================================================
# POSITIVE CONTROL: Internal-only paths ARE reachable on the internal listener
# These cases run against {{baseUrl}} (the internal mux; port 18080 in
# port-forward, or port 9091 cluster-internal).
# ===========================================================================

# ---------------------------------------------------------------------------
# IAM-INT-OK-INT-USER-UPSERT
# InternalUserService.UpsertFromIdentity on internal → 200
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-INT-OK-INT-USER-UPSERT",
    title="InternalUserService.UpsertFromIdentity on cluster-internal listener → 200, user.id has usr prefix",
    classes=["CRUD", "SEC"],
    priority="P1",
    steps=[
        Step(
            name="upsert-from-identity-on-internal",
            method="POST",
            path="/iam/v1/internal/users:upsertFromIdentity",
            body={
                "externalId": "zit-positive-{{runId}}",
                "email": "positive-{{runId}}@kacho.local",
                "displayName": "Positive Control {{runId}}",
            },
            # Reach the Internal* RPC on the api-gateway cluster-internal REST
            # listener ({{internalBaseUrl}} = :18081 in CI) — NOT the public cmux
            # ({{baseUrl}} = :18080), which 404s /iam/v1/internal/* by design (ban #6).
            pre_script=_internal_url_override("/iam/v1/internal/users:upsertFromIdentity"),
            # The internal-rest listener enforces authN on every request
            # (authn-everywhere invariant, security.md) — an unauthenticated call
            # is rejected 401 before reaching the <exempt> service. A valid JWT is
            # required; jwtAccountAdminA is deterministically seeded (not the flaky
            # bootstrap admin). UpsertFromIdentity is <exempt> at the gateway and
            # ungated for the end-user at the iam service, so the tier is irrelevant.
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('INT-UPSERT: user id has usr prefix', () => {",
                "  const j = pm.response.json();",
                "  // UpsertFromIdentity returns an Operation with metadata.userId.",
                "  // Fallbacks: j.user.id (direct User), j.id (older API).",
                "  const uid = (j.metadata && j.metadata.userId) || (j.user && j.user.id) || j.id;",
                "  pm.expect(uid, 'user id must start with usr').to.match(/^usr[a-z0-9]+$/);",
                "});",
                *save_from_response("j.id", "createdInternalUserOpId"),
                *save_from_response("(j.metadata && j.metadata.userId) || (j.user && j.user.id) || j.id", "createdInternalUserId"),
            ],
        ),
        # UpsertFromIdentity is async (operations.Run → LRO worker commits the user
        # row in a dispatcher goroutine). Poll the returned Operation to done so the
        # user is COMMITTED before the -IDEM re-upsert (same id) and the LOOKUPSUBJECT
        # cases run — otherwise resolveUserID on the re-upsert would not yet see the
        # ACTIVE row and could mint a second id (idempotency flake). Deterministic wait,
        # not time.Sleep.
        Step(
            name="upsert-poll-done",
            method="GET",
            path="/operations/{{createdInternalUserOpId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('upsert poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  const _ipd1 = Date.now(); while (Date.now() - _ipd1 < 500) void 0; /* real inter-poll delay: cap 30 x 500ms ~= 15s budget (testing.md) */",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "pm.test('INT-UPSERT: user committed (operation done, no error)', () => {",
                "  pm.expect(j.done, JSON.stringify(j)).to.eql(true);",
                "  pm.expect(j.error, JSON.stringify(j)).to.not.exist;",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-INT-OK-INT-USER-UPSERT-IDEM
# UpsertFromIdentity is idempotent — second call with same externalId returns
# the same user id (UPSERT semantics).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-INT-OK-INT-USER-UPSERT-IDEM",
    title="InternalUserService.UpsertFromIdentity — idempotent re-upsert → same user id",
    classes=["CRUD", "SEC"],
    priority="P2",
    steps=[
        Step(
            name="upsert-idem",
            method="POST",
            path="/iam/v1/internal/users:upsertFromIdentity",
            body={
                "externalId": "zit-positive-{{runId}}",
                "email": "positive-{{runId}}@kacho.local",
                "displayName": "Positive Control {{runId}} (re-upsert)",
            },
            # Internal* → internal-rest listener ({{internalBaseUrl}}, see UPSERT above).
            pre_script=_internal_url_override("/iam/v1/internal/users:upsertFromIdentity"),
            # internal-rest listener enforces authN — send a valid JWT (see UPSERT above).
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('INT-UPSERT-IDEM: same user id returned', () => {",
                "  const j = pm.response.json();",
                "  const uid = (j.metadata && j.metadata.userId) || (j.user && j.user.id) || j.id;",
                "  const prev = pm.environment.get('createdInternalUserId');",
                "  if (prev) {",
                "    pm.expect(uid, 'idempotent: same id on re-upsert').to.eql(prev);",
                "  } else {",
                "    pm.expect(uid).to.match(/^usr[a-z0-9]+$/);",
                "  }",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-INT-OK-INT-IAM-LOOKUPSUBJECT
# InternalIAMService.LookupSubject on internal → 200 or 404 (valid internal resp)
# If the user was just upserted, LookupSubject by externalId should return them.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-INT-OK-INT-IAM-LOOKUPSUBJECT",
    title="InternalIAMService.LookupSubject on cluster-internal listener — lookup just-upserted user → 200",
    classes=["CRUD", "SEC"],
    priority="P1",
    steps=[
        Step(
            name="lookup-subject-on-internal",
            method="POST",
            path="/iam/v1/internal/iam:lookupSubject",
            body={"externalId": "zit-positive-{{runId}}"},
            # Internal* → internal-rest listener ({{internalBaseUrl}}, see UPSERT above).
            pre_script=_internal_url_override("/iam/v1/internal/iam:lookupSubject"),
            # internal-rest listener enforces authN — send a valid JWT (see UPSERT above).
            auth="jwtAccountAdminA",
            test_script=[
                # Субъект был заведён шагами выше, и его операция upsert'а дождана до
                # done ПЕРЕД этим вызовом — значит строка закоммичена, состояние
                # активное, и поиск по внешнему идентификатору её находит. Исход один.
                #
                # Прежнее `oneOf([200, 404])` («оба ответа валидны для internal-сервиса»)
                # смешивало предмет кейса с его отрицанием: 404 означал бы, что только
                # что созданный субъект не резолвится, — то есть ровно тот дефект, ради
                # которого кейс и написан. Отличие сервисного 404 от mux-404 проверяет
                # соседний кейс на НЕизвестном идентификаторе, где 404 и есть предмет.
                *assert_status(200),
                "const j = pm.response.json();",
                "// LookupSubject returns {user: {id: '...', ...}} or {serviceAccount: {...}}.",
                "const subjectId = (j.user && j.user.id) || (j.serviceAccount && j.serviceAccount.id) || j.subjectId;",
                "pm.test('INT-LOOKUPSUBJ: subjectId present', () => pm.expect(subjectId, 'subject id must be set').to.be.a('string').with.length.greaterThan(0));",
                # Сверка с ранее созданным id — БЕЗУСЛОВНАЯ: если фикстура не записала
                # id, это провал фикстуры, а не повод пропустить сверку (прежде стояло
                # `if (prev)`, и пустая переменная тихо отменяла главное утверждение).
                "pm.test('INT-LOOKUPSUBJ: subjectId matches upserted user', () => {",
                "  const prev = pm.environment.get('createdInternalUserId');",
                "  pm.expect(prev, 'фикстура обязана была записать createdInternalUserId').to.be.a('string').and.not.empty;",
                "  pm.expect(subjectId).to.eql(prev);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-INT-OK-INT-IAM-LOOKUPSUBJECT-UNKNOWN
# LookupSubject for a nonexistent externalId → 404 from the SERVICE, not a
# mux-404 (path not found).
#
# Что здесь на самом деле различает одно от другого — ТЕКСТ, а не код. Прежняя
# редакция этого заголовка (и единственное утверждение под ним) объявляла
# различителем `code == 5`; замер по живому проводу того же прогона показывает,
# что промах маршрутизатора несёт РОВНО ТОТ ЖЕ код:
#   владелец      → {"code":5,"message":"subject not found by external_id=zit-…"}
#   маршрутизатор → {"code":5,"message":"Not Found","details":[]}
# Владелец называет в тексте наш ключ, потому что он его читал; маршрутизатор
# назвать его не может — тела он не видел. На этом различии стоит классификатор
# посева церемонии (`tests/authz-fixtures/prodseed_ceremony.py::_mirror_lookup`,
# исходы «нет-строки» против «не-дают-спросить»), и без утверждения ниже его
# предпосылка не была прибита ничем: постоянная ошибка настройки навсегда
# читалась бы как задержка (`security.md` §8).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-INT-OK-INT-IAM-LOOKUPSUBJECT-UNKNOWN",
    title="InternalIAMService.LookupSubject for unknown externalId → 404 ВЛАДЕЛЬЦА (текст называет запрошенный external_id; код 5 несёт и промах mux)",
    classes=["NEG", "SEC"],
    priority="P1",
    steps=[
        Step(
            name="lookup-unknown-on-internal",
            method="POST",
            path="/iam/v1/internal/iam:lookupSubject",
            body={"externalId": "zit-nonexistent-{{runId}}"},
            # Internal* → internal-rest listener ({{internalBaseUrl}}, see UPSERT above).
            pre_script=_internal_url_override("/iam/v1/internal/iam:lookupSubject"),
            # internal-rest listener enforces authN — send a valid JWT (see UPSERT above).
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('INT-LOOKUPSUBJ-UNK: status 404', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(404));",
                "const j = pm.response.json();",
                "pm.test('INT-LOOKUPSUBJ-UNK: grpc code 5 (NOT_FOUND, необходимое условие — но НЕ различитель)', () => pm.expect(j.code, JSON.stringify(j)).to.equal(5));",
                # РАЗЛИЧИТЕЛЬ: ответ владельца называет ЗАПРОШЕННЫЙ ключ, промах
                # маршрутизатора назвать его не может. Спрошенное берём из самого
                # запроса, а не из литерала: иначе утверждение начнёт проверять
                # чужую строку в тот день, когда литерал поменяют.
                "const asked = ((pm.request.body && pm.request.body.raw) ? JSON.parse(pm.request.body.raw).externalId : '');",
                "pm.test('INT-LOOKUPSUBJ-UNK: 404 ВЛАДЕЛЬЦА называет запрошенный external_id (mux-404 несёт тот же код 5, но нашего ключа не знает)', () => {",
                "  pm.expect(asked, 'кейс обязан знать, о чём спросил').to.be.a('string').and.not.empty;",
                "  pm.expect(j.message || '', JSON.stringify(j)).to.include(asked);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-INT-OK-INT-IAM-CHECK
# InternalIAMService.Check on internal → valid response (200 allowed/denied or 404 not found)
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-INT-OK-INT-IAM-CHECK",
    title="InternalIAMService.Check on cluster-internal listener → 200 (allowed=true or false)",
    classes=["CRUD", "SEC"],
    priority="P1",
    steps=[
        Step(
            name="iam-check-on-internal",
            method="POST",
            path="/iam/v1/internal/iam:check",
            # CheckRequest is an FGA triple: `subject_id` and `object` are TYPED
            # strings ("user:<usr…>" / "account:<acc…>"), and the object field is
            # named `object` — there is no `objectId`. The previous body sent
            # `objectId`, which the edge discards, so `object` arrived empty and the
            # required-check rejected the call: this "OK" probe never reached the PDP
            # at all, it only ever measured a 400 that the tolerant assertion accepted.
            body={
                "subjectId": "user:{{userAAAId}}",
                "relation": "viewer",
                "object": "account:{{accountAId}}",
            },
            # Internal* → internal-rest listener ({{internalBaseUrl}}, see UPSERT above).
            pre_script=_internal_url_override("/iam/v1/internal/iam:check"),
            # internal-rest listener enforces authN — send a valid JWT (see UPSERT above).
            auth="jwtAccountAdminA",
            test_script=[
                "// A well-formed triple always resolves: the PDP answers 200 with a boolean",
                "// verdict (allowed true or false). 4xx is NOT tolerated — tolerating 400 is",
                "// exactly what kept the discarded-key defect invisible.",
                "pm.test('INT-IAM-CHECK: status 200 (PDP answered)', () => pm.expect(pm.response.code, pm.response.text()).to.eql(200));",
                "const j = pm.response.json();",
                "pm.test('INT-IAM-CHECK: allowed is a boolean verdict', () => pm.expect(j.allowed, JSON.stringify(j)).to.be.a('boolean'));",
            ],
        ),
    ],
))



# ===========================================================================
# InternalInteractiveClientService — the interactive-login client, IAM-INT-1-11.
#
# WHAT KEEPS IT OFF THE OUTSIDE, STATED PRECISELY. The route IS mounted on both
# multiplexers: registration walks the pair in ONE loop, `Internal*` included.
# Isolation is the DISPATCHER's doing — `isInternalRoute` classifies the (method,
# path) pair and answers 404 on external origin, hiding existence. Saying "it is
# not mounted" would send the next reader to fix the registration instead of the
# classifier.
#
# WHY THE PROBE CARRIES `jwtBootstrap` AND NOT A TENANT SUBJECT. Bootstrap is the
# cluster `system_admin` ServiceAccount — the ONE principal that is authorised for
# this surface and acr-exempt for its mutations. Probing with anybody else would
# leave "not routed" indistinguishable from "not allowed", and the second is not
# what ban #6 is about. Refused for the RIGHT reason is the whole assertion.
#
# The three cases here are the newman half of scenario 11. The behavioural census
# on the tree side already carries the same pair — restmux/external_isolation_test.go
# holds `{"POST", "/iam/v1/internal/interactiveClients"}` — and this file is the
# black-box census; neither is a second copy of the other, and no third one is
# started beside them.
# ===========================================================================

_IC_PATH = "/iam/v1/internal/interactiveClients"

CASES.append(Case(
    id="IAM-INT-NEG-EXT-IC-LIST",
    title="InternalInteractiveClientService.List on the external TLS listener → 404 mux miss "
          "(internal-only, ban #6) — refused even to the principal authorised for it",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        _external_step(
            name="ic-list-on-external",
            method="GET",
            path=_IC_PATH,
            auth="jwtBootstrap",
            test_script=_mux_miss_assertions(
                "EXT-IC-LIST", "(j || {}).interactiveClients", "interactiveClients page"),
        ),
    ],
))


CASES.append(Case(
    id="IAM-INT-NEG-EXT-IC-CREATE",
    title="InternalInteractiveClientService.Create on the external TLS listener → 404 mux miss "
          "(internal-only, ban #6) — no client is registered at the provider from the outside",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        _external_step(
            name="ic-create-on-external",
            method="POST",
            path=_IC_PATH,
            auth="jwtBootstrap",
            body={
                "name": "iaclient-ext-{{runId}}",
                "redirectUris": ["https://api.kacho.local/auth/callback"],
            },
            # The leak expression is the Operation id: if one came back, a client was
            # registered at the identity provider through the advertised endpoint —
            # the outcome ban #6 exists to prevent, not merely a routing surprise.
            test_script=_mux_miss_assertions(
                "EXT-IC-CREATE", "(j || {}).metadata", "Operation metadata (a client was registered)"),
        ),
    ],
))


CASES.append(Case(
    id="IAM-INT-OK-INT-IC-LIST",
    title="InternalInteractiveClientService.List on the cluster-internal listener → 200 with a page "
          "(positive control: the two 404s above mean 'not routed here', not 'nowhere at all')",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        Step(
            name="ic-list-on-internal",
            method="GET",
            path=_IC_PATH,
            pre_script=_internal_url_override(_IC_PATH),
            # system_admin @ cluster — the catalog gate on all five RPCs. A tenant-tier
            # subject gets a correct 403 here, which would make this control assert
            # nothing about routing.
            auth="jwtBootstrap",
            test_script=[
                *assert_status(200),
                "pm.test('INT-IC-LIST: the internal listener serves the page', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j, JSON.stringify(j)).to.be.an('object');",
                "  // An empty cluster is a legal page: the assertion is that the ROUTE",
                "  // answers with the response message, not that anything was created.",
                "  const items = j.interactiveClients === undefined ? [] : j.interactiveClients;",
                "  pm.expect(items, 'interactiveClients must be a page, absent meaning empty').to.be.an('array');",
                "});",
            ],
        ),
    ],
))


# ===========================================================================
# InternalLimitService — resource-count ceilings, issue #291 S1 (VPCQ-10).
#
# The same three-case shape as the interactive-login client above, and for the
# same reason: the route IS mounted on both multiplexers, and isolation is the
# DISPATCHER's doing. Saying "it is not mounted" would send the next reader to fix
# the registration instead of the classifier.
#
# WHY THE PROBE CARRIES `jwtBootstrap`. It is the cluster `system_admin`
# ServiceAccount — the principal the five CRUD verbs are authorised for. Probing
# with anybody else would leave "not routed" indistinguishable from "not allowed",
# and only the first is what ban #6 is about.
#
# WHY THE LEAK EXPRESSION ON CREATE IS THE OPERATION METADATA. If one came back, a
# ceiling was STATED through the advertised endpoint — a change to how much of a
# shared resource a tenant may take, made from outside. That is the outcome, not
# merely a routing surprise.
# ===========================================================================

_LIMIT_PATH = "/iam/v1/internal/limits"

CASES.append(Case(
    id="IAM-INT-NEG-EXT-LIMIT-LIST",
    title="InternalLimitService.List on the external TLS listener → 404 mux miss "
          "(internal-only, ban #6) — refused even to the principal authorised for it",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        _external_step(
            name="limit-list-on-external",
            method="GET",
            path=_LIMIT_PATH,
            auth="jwtBootstrap",
            test_script=_mux_miss_assertions(
                "EXT-LIMIT-LIST", "(j || {}).limits", "limits page"),
        ),
    ],
))


CASES.append(Case(
    id="IAM-INT-NEG-EXT-LIMIT-CREATE",
    title="InternalLimitService.Create on the external TLS listener → 404 mux miss "
          "(internal-only, ban #6) — no ceiling is stated from the outside",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        _external_step(
            name="limit-create-on-external",
            method="POST",
            path=_LIMIT_PATH,
            auth="jwtBootstrap",
            body={
                "scope": "PROJECT",
                "scopeId": "{{existingProjectId}}",
                "kind": "vpc.network",
                "value": 4,
            },
            test_script=_mux_miss_assertions(
                "EXT-LIMIT-CREATE", "(j || {}).metadata",
                "Operation metadata (a ceiling was stated)"),
        ),
    ],
))


CASES.append(Case(
    id="IAM-INT-OK-INT-LIMIT-LIST",
    title="InternalLimitService.List on the cluster-internal listener → 200 with a page "
          "(positive control: the two 404s above mean 'not routed here', not 'nowhere at all')",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        Step(
            name="limit-list-on-internal",
            method="GET",
            path=_LIMIT_PATH,
            pre_script=_internal_url_override(_LIMIT_PATH),
            auth="jwtBootstrap",
            test_script=[
                *assert_status(200),
                "pm.test('INT-LIMIT-LIST: the internal listener serves the page', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j, JSON.stringify(j)).to.be.an('object');",
                "  const items = j.limits === undefined ? [] : j.limits;",
                "  pm.expect(items, 'limits must be a page, absent meaning empty').to.be.an('array');",
                "});",
                # The platform's defaults are seeded by a migration and are the ONE
                # place those numbers live. A page that came back without them would
                # mean the seed never ran — and then every tenant would be limited by
                # nothing, which is the state this whole change exists to end.
                "pm.test('INT-LIMIT-LIST: the seeded platform defaults are there', () => {",
                "  const j = pm.response.json();",
                "  const items = j.limits === undefined ? [] : j.limits;",
                "  const defs = items.filter(l => l.scope === 'DEFAULT');",
                "  pm.expect(defs.length, JSON.stringify(items)).to.be.above(0);",
                "});",
            ],
        ),
    ],
))
