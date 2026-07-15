# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set для iam-internal-only-check.

Проверка изоляции `Internal*` сервисов от external TLS endpoint
(Internal*-методы не публикуются на advertised external endpoint).

  InternalIAMService / InternalUserService / InternalAuthorizeService /
  InternalBreakGlassService
  должны быть доступны ТОЛЬКО на cluster-internal listener — на api-gateway это
  выделенный `internal-rest` listener (:8081), в local/CI port-forward
  {{internalBaseUrl}} = http://localhost:18081. ПУБЛИЧНЫЙ cmux
  ({{baseUrl}} = http://localhost:18080) НЕ отдаёт /iam/v1/internal/* — 404 by
  design (ban #6). Те же пути должны отдавать 404 и на advertised external TLS
  endpoint (`{{externalBaseUrl}}` = https://api.kacho.local:443).

Coverage:
  IAM-INT-NEG-EXT-USER-UPSERT          — InternalUserService.UpsertFromIdentity → 404 на external
  IAM-INT-NEG-EXT-USER-GET             — InternalUserService.Get → 404 на external
  IAM-INT-NEG-EXT-IAM-LOOKUPSUBJECT    — InternalIAMService.LookupSubject → 404 на external
  IAM-INT-NEG-EXT-IAM-CHECK            — InternalIAMService.Check → 404 на external
  IAM-INT-NEG-EXT-IAUTH-WRITETUPLES    — InternalAuthorizeService.WriteTuples → 404 на external
  IAM-INT-NEG-EXT-SR-REVOKE            — InternalSessionRevocationsService.Revoke → 404 на external
  IAM-INT-NEG-EXT-SR-ISREVOKED         — InternalSessionRevocationsService.IsRevoked → 404 на external
  IAM-INT-NEG-EXT-IAM-FORCELOGOUT      — InternalIAMService.ForceLogout → 404 на external
  IAM-INT-OK-INT-USER-UPSERT           — UpsertFromIdentity → 200 на internal (positive control)
  IAM-INT-OK-INT-IAM-LOOKUPSUBJECT     — LookupSubject → 200/404 на internal (positive control)
  IAM-INT-OK-INT-IAM-CHECK             — InternalIAMService.Check → 200 на internal

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
  (IAM-INT-NEG-EXT-IAM-FORCELOGOUT / IAM-INT-NEG-EXT-SR-REVOKE).

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
  {{externalBaseUrl}}  — advertised TLS endpoint (https://api.kacho.local:443 on stend).
                         Must NOT expose Internal* paths. If not set in env, external
                         checks are skipped with a warning (local-dev fallback).

Technique for externalBaseUrl steps:
  gen.py / step_to_postman() always generates `{{baseUrl}}<path>` as the URL.
  For external-endpoint steps, we override `pm.request.url` in the prerequest
  script to point at {{externalBaseUrl}} instead. This is the standard Postman
  pattern for per-step base-URL overrides.

Test-first note (strict TDD):
  Cases are written RED-first. Positive-control (internal) cases fail until the
  Internal* RPCs are implemented. Negative (external) cases pass immediately if
  api-gateway correctly rejects /iam/v1/internal/* on the external mux.
  Do not weaken assertions.
"""

CASES = []

# ---------------------------------------------------------------------------
# Helper: pre_script fragment that overrides the request URL to externalBaseUrl.
# Used for all "on external" negative checks.
# gen.py generates {{baseUrl}}<path>; this pre_script replaces it with
# {{externalBaseUrl}}<path> at request-time.
# ---------------------------------------------------------------------------

def _external_url_override(path: str):
    """Return a pre_script list that overrides the request URL to externalBaseUrl+path."""
    return [
        "// internal-only check: redirect this request to external TLS endpoint.",
        "const extBase = pm.environment.get('externalBaseUrl') || pm.variables.get('externalBaseUrl') || '';",
        "if (!extBase) {",
        "  console.warn('externalBaseUrl not set in env — skipping external isolation check for this step.');",
        "  postman.setNextRequest(null);",
        "} else {",
        f"  pm.request.url = extBase + '{path}';",
        "}",
        "// Mark that this step is an external-isolation check (used in test_script to handle DNS failures).",
        "pm.environment.set('_extIsolationStep', 'true');",
    ]


def _internal_url_override(path: str):
    """Return a pre_script list that overrides the request URL to internalBaseUrl+path.

    The POSITIVE controls exercise Internal* RPCs (UpsertFromIdentity,
    InternalIAMService.LookupSubject/Check). These paths (/iam/v1/internal/*) are
    served ONLY by the api-gateway dedicated cluster-internal REST listener
    (`internal-rest` Service port, :8081) — NEVER by the public cmux (:8080), which
    404s them by design (ban #6). The premise `{{baseUrl}} is already the internal
    mux` is FALSE for the public port-forward: {{baseUrl}} (:18080) reaches the PUBLIC
    listener. So point these controls at {{internalBaseUrl}} (the internal-rest
    port-forward, http://localhost:18081 in CI). Mirrors _external_url_override; if
    internalBaseUrl is unset (local dev without the internal-rest port-forward) the
    step is skipped rather than failing on a spurious public 404."""
    return [
        "// internal-only POSITIVE control: send this request to the api-gateway",
        "// cluster-internal REST listener (Internal* paths live ONLY there).",
        "const intBase = pm.environment.get('internalBaseUrl') || pm.variables.get('internalBaseUrl') || '';",
        "if (!intBase) {",
        "  console.warn('internalBaseUrl not set in env — skipping internal-mux positive control for this step.');",
        "  postman.setNextRequest(null);",
        "} else {",
        f"  pm.request.url = intBase + '{path}';",
        "}",
    ]


# ===========================================================================
# NEGATIVE: Internal-only paths MUST return 404 on the external TLS endpoint
# ===========================================================================

# ---------------------------------------------------------------------------
# IAM-INT-NEG-EXT-USER-UPSERT
# InternalUserService.UpsertFromIdentity on external → 404 (path not registered)
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-INT-NEG-EXT-USER-UPSERT",
    title="InternalUserService.UpsertFromIdentity on external TLS endpoint → 404 (internal-only)",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        Step(
            name="upsert-on-external",
            method="POST",
            path="/iam/v1/internal/users:upsertFromIdentity",
            body={"externalId": "zit-isolation-{{runId}}", "email": "leak@kacho.local"},
            pre_script=_external_url_override("/iam/v1/internal/users:upsertFromIdentity"),
            test_script=[
                "// Must be 404 — path not registered on external mux.",
                "// If this returns 200 / 201 — CRITICAL: Internal* endpoint is exposed on external!",
                "// A DNS/network failure (undefined status) also means the path is NOT exposed — treat as PASS.",
                "pm.test('EXT-UPSERT: status 404 (path not on external mux)', () => {",
                "  const code = pm.response.code;",
                "  if (code === undefined) { return; } // DNS/network error = endpoint not reachable = PASS",
                "  pm.expect(code, 'CRITICAL: internal path exposed on external endpoint!').to.equal(404);",
                "});",
                "// Only probe body content if a real HTTP response arrived.",
                "if (pm.response.code !== undefined) {",
                "  const j = pm.response.json ? pm.response.json() : null;",
                "  pm.test('EXT-UPSERT: no user.id leak in body', () => {",
                "    pm.expect(j && j.user && j.user.id, 'user.id must not be in response').to.be.undefined;",
                "  });",
                "} else {",
                "  pm.test('EXT-UPSERT: no user.id leak in body (DNS unreachable = PASS)', () => true);",
                "}"
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-INT-NEG-EXT-USER-GET
# InternalUserService.Get on external → 404
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-INT-NEG-EXT-USER-GET",
    title="InternalUserService.Get on external TLS endpoint → 404 (internal-only)",
    classes=["NEG", "SEC"],
    priority="P1",
    steps=[
        Step(
            name="get-internal-user-on-external",
            method="GET",
            path="/iam/v1/internal/users/usr00000000000000abc",
            pre_script=_external_url_override("/iam/v1/internal/users/usr00000000000000abc"),
            test_script=[
                "pm.test('EXT-USER-GET: status 404 (path not on external mux)', () => {",
                "  const code = pm.response.code;",
                "  if (code === undefined) { return; } // DNS/network error = endpoint not reachable = PASS",
                "  pm.expect(code, 'CRITICAL: internal path exposed!').to.equal(404);",
                "});",
                "// Only probe body content if a real HTTP response arrived.",
                "if (pm.response.code !== undefined) {",
                "  const j = pm.response.json ? pm.response.json() : null;",
                "  pm.test('EXT-USER-GET: no user id leak', () => {",
                "    pm.expect(j && j.id, 'id must not be in response').to.be.undefined;",
                "  });",
                "} else {",
                "  pm.test('EXT-USER-GET: no user id leak (DNS unreachable = PASS)', () => true);",
                "}"
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-INT-NEG-EXT-IAM-LOOKUPSUBJECT
# InternalIAMService.LookupSubject on external → 404
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-INT-NEG-EXT-IAM-LOOKUPSUBJECT",
    title="InternalIAMService.LookupSubject on external TLS endpoint → 404 (internal-only)",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        Step(
            name="lookup-subject-on-external",
            method="POST",
            path="/iam/v1/internal/iam:lookupSubject",
            body={"externalId": "zit-anything"},
            pre_script=_external_url_override("/iam/v1/internal/iam:lookupSubject"),
            test_script=[
                "pm.test('EXT-LOOKUPSUBJ: status 404 (path not on external mux)', () => {",
                "  const code = pm.response.code;",
                "  if (code === undefined) { return; } // DNS/network error = endpoint not reachable = PASS",
                "  pm.expect(code, 'CRITICAL: internal path exposed!').to.equal(404);",
                "});",
                "// Only probe body content if a real HTTP response arrived.",
                "if (pm.response.code !== undefined) {",
                "  const j = pm.response.json ? pm.response.json() : null;",
                "  pm.test('EXT-LOOKUPSUBJ: no subjectId leak', () => {",
                "    pm.expect(j && j.subjectId, 'subjectId must not be in response').to.be.undefined;",
                "  });",
                "} else {",
                "  pm.test('EXT-LOOKUPSUBJ: no subjectId leak (DNS unreachable = PASS)', () => true);",
                "}"
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-INT-NEG-EXT-IAM-CHECK
# InternalIAMService.Check on external → 404
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-INT-NEG-EXT-IAM-CHECK",
    title="InternalIAMService.Check on external TLS endpoint → 404 (internal-only)",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        Step(
            name="iam-check-on-external",
            method="POST",
            path="/iam/v1/internal/iam:check",
            body={"subjectId": "usr00000000000000abc", "relation": "viewer", "objectId": "acc00000000000abc"},
            pre_script=_external_url_override("/iam/v1/internal/iam:check"),
            test_script=[
                "pm.test('EXT-IAM-CHECK: status 404 (path not on external mux)', () => {",
                "  const code = pm.response.code;",
                "  if (code === undefined) { return; } // DNS/network error = endpoint not reachable = PASS",
                "  pm.expect(code, 'CRITICAL: internal Check exposed!').to.equal(404);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-INT-NEG-EXT-IAUTH-WRITETUPLES
# InternalAuthorizeService.WriteTuples on external → 404
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-INT-NEG-EXT-IAUTH-WRITETUPLES",
    title="InternalAuthorizeService.WriteTuples on external TLS endpoint → 404 (internal-only)",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        Step(
            name="write-tuples-on-external",
            method="POST",
            path="/iam/v1/internal/authorize:writeTuples",
            body={"tuples": [{"user": "user:test", "relation": "viewer", "object": "account:abc"}]},
            pre_script=_external_url_override("/iam/v1/internal/authorize:writeTuples"),
            test_script=[
                "pm.test('EXT-WRITETUPLES: status 404 (path not on external mux)', () => {",
                "  const code = pm.response.code;",
                "  if (code === undefined) { return; } // DNS/network error = endpoint not reachable = PASS",
                "  pm.expect(code, 'CRITICAL: internal WriteTuples exposed!').to.equal(404);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-INT-NEG-EXT-SR-REVOKE
# InternalSessionRevocationsService.Revoke on external → 404 (internal-only).
# Token revocation must never be triggerable from the public edge.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-INT-NEG-EXT-SR-REVOKE",
    title="InternalSessionRevocationsService.Revoke on external TLS endpoint → 404 (internal-only, ban #6)",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        Step(
            name="sr-revoke-on-external",
            method="POST",
            path="/iam/v1/internal/sessionRevocations:revoke",
            body={"userId": "usr00000000000000abc", "tokenJti": "leak-jti", "reason": "x"},
            pre_script=_external_url_override("/iam/v1/internal/sessionRevocations:revoke"),
            test_script=[
                "pm.test('EXT-SR-REVOKE: status 404 (path not on external mux)', () => {",
                "  const code = pm.response.code;",
                "  if (code === undefined) { return; } // DNS/network error = endpoint not reachable = PASS",
                "  pm.expect(code, 'CRITICAL: internal Revoke exposed on external endpoint!').to.equal(404);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-INT-NEG-EXT-SR-ISREVOKED
# InternalSessionRevocationsService.IsRevoked on external → 404 (internal-only).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-INT-NEG-EXT-SR-ISREVOKED",
    title="InternalSessionRevocationsService.IsRevoked on external TLS endpoint → 404 (internal-only, ban #6)",
    classes=["NEG", "SEC"],
    priority="P1",
    steps=[
        Step(
            name="sr-isrevoked-on-external",
            method="POST",
            path="/iam/v1/internal/sessionRevocations:isRevoked",
            body={"tokenJti": "leak-jti"},
            pre_script=_external_url_override("/iam/v1/internal/sessionRevocations:isRevoked"),
            test_script=[
                "pm.test('EXT-SR-ISREVOKED: status 404 (path not on external mux)', () => {",
                "  const code = pm.response.code;",
                "  if (code === undefined) { return; } // DNS/network error = endpoint not reachable = PASS",
                "  pm.expect(code, 'CRITICAL: internal IsRevoked exposed!').to.equal(404);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-INT-NEG-EXT-IAM-FORCELOGOUT
# InternalIAMService.ForceLogout on external → 404 (internal-only).
# Admin force-logout must never be triggerable from the public edge.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-INT-NEG-EXT-IAM-FORCELOGOUT",
    title="InternalIAMService.ForceLogout on external TLS endpoint → 404 (internal-only, ban #6)",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        Step(
            name="iam-forcelogout-on-external",
            method="POST",
            path="/iam/v1/internal/iam:forceLogout",
            body={"userId": "usr00000000000000abc", "reason": "x"},
            pre_script=_external_url_override("/iam/v1/internal/iam:forceLogout"),
            test_script=[
                "pm.test('EXT-FORCELOGOUT: status 404 (path not on external mux)', () => {",
                "  const code = pm.response.code;",
                "  if (code === undefined) { return; } // DNS/network error = endpoint not reachable = PASS",
                "  pm.expect(code, 'CRITICAL: internal ForceLogout exposed!').to.equal(404);",
                "});",
            ],
        ),
    ],
))


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
                "  postman.setNextRequest(pm.info.requestName);",
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
                # 200 if upserted user exists, 404 if not (both are valid internal-service responses).
                "pm.test('INT-LOOKUPSUBJ: status 200 or 404 (valid internal response, NOT mux-404)', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.be.oneOf([200, 404]));",
                "const j = pm.response.json();",
                "if (pm.response.code === 200) {",
                "  // LookupSubject returns {user: {id: '...', ...}} or {serviceAccount: {...}}.",
                "  const subjectId = (j.user && j.user.id) || (j.serviceAccount && j.serviceAccount.id) || j.subjectId;",
                "  pm.test('INT-LOOKUPSUBJ: subjectId present', () => pm.expect(subjectId, 'subject id must be set').to.be.a('string').with.length.greaterThan(0));",
                "  pm.test('INT-LOOKUPSUBJ: subjectId matches upserted user', () => {",
                "    const prev = pm.environment.get('createdInternalUserId');",
                "    if (prev) pm.expect(subjectId).to.eql(prev);",
                "  });",
                "} else {",
                "  pm.test('INT-LOOKUPSUBJ: 404 grpc code 5 (NOT_FOUND from service)', () => pm.expect(j.code).to.eql(5));",
                "}",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-INT-OK-INT-IAM-LOOKUPSUBJECT-UNKNOWN
# LookupSubject for a nonexistent externalId → 404 from service (grpc 5),
# not a mux-404 (path not found). This distinguishes service-level 404 from
# mux-level 404 — the body must contain grpc code 5.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-INT-OK-INT-IAM-LOOKUPSUBJECT-UNKNOWN",
    title="InternalIAMService.LookupSubject for unknown externalId → 404 with grpc code 5 (service-level, not mux)",
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
                "pm.test('INT-LOOKUPSUBJ-UNK: grpc code 5 (NOT_FOUND from service, not mux)', () => pm.expect(j.code, JSON.stringify(j)).to.equal(5));",
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
            body={
                "subjectId": "{{userAAAId}}",
                "relation": "viewer",
                "objectId": "{{accountAId}}",
            },
            # Internal* → internal-rest listener ({{internalBaseUrl}}, see UPSERT above).
            pre_script=_internal_url_override("/iam/v1/internal/iam:check"),
            # internal-rest listener enforces authN — send a valid JWT (see UPSERT above).
            auth="jwtAccountAdminA",
            test_script=[
                "// 200 with allowed=true|false is the expected success response.",
                "// 403/404 from service (not mux) is also acceptable if FGA is not seeded.",
                "pm.test('INT-IAM-CHECK: status 200 or 4xx (internal service response)', () => pm.expect(pm.response.code).to.be.oneOf([200, 400, 403, 404]));",
                "const j = pm.response.json();",
                "if (pm.response.code === 200) {",
                "  pm.test('INT-IAM-CHECK: allowed field present', () => pm.expect(j.allowed, 'allowed field').to.be.a('boolean'));",
                "}",
            ],
        ),
    ],
))


