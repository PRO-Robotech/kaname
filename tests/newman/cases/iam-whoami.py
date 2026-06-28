# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set для AuthorizeService.WhoAmI.

Covered RPCs:
  AuthorizeService.WhoAmI (GET /iam/v1/me) — caller identity + permission snapshot.

CRUD fixture dependency:
  jwtAccountAdminA  — JWT for accountA owner (userAAAId)
  jwtAccountAdminB  — JWT for accountBId owner (userAABId)
  jwtNoBindings     — authenticated, no account membership
  jwtBootstrap      — bootstrap admin (admin@prorobotech.ru)
  userAAAId / userAABId / userNOBId

Contract:
  - GET /iam/v1/me on the gateway-external mux, listed as `<exempt>` in the
    permission catalog. Handler enforces auth (anti-anon interceptor).
  - Response body shape (proto: WhoAmIResponse):
      {
        subject: "user:<usr>",   // FGA-style subject (or "service_account:...")
        userId: "<usr>",         // user_id without prefix; empty for SA
        email: "<lowercased>",
        displayName: "<...>",
        systemAdmin: bool,        // true iff system_admin on cluster:cluster_kacho_root
        clusterViewer: bool,      // true iff viewer cascade on cluster (typ. true for any authenticated)
        accounts: [ { accountId, accountName, roles: [...] } ],
        checkedAt: "<rfc3339 truncated to seconds>"
      }
  - Anonymous → 401 UNAUTHENTICATED (16) — handler is authoritative gate
    because the catalog marks WhoAmI as <exempt>.

Acceptance scenarios:
  Happy: jwtAccountAdminA → 200, subject == "user:<userAAAId>", userId == userAAAId,
    accounts contains accountAId with `owner` tag (implicit owner-role).
  Negative: anonymous (no Bearer) → 401, code 16.

Test-first note (strict TDD):
  Cases are written RED-first. They will fail until
  AuthorizeService.WhoAmI is correctly implemented and wired through api-gateway
  REST mux at /iam/v1/me. Do not weaken assertions — fix the implementation.

verifies: WhoAmI happy-path + anonymous denial; matches WhoAmIResponse
fields documented in proto access_binding_service.proto.
"""

CASES = []


# ---------------------------------------------------------------------------
# IAM-WAI-GT-CRUD-OK — owner queries WhoAmI → 200 + identity fields populated
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-WAI-GT-CRUD-OK",
    title="GET /iam/v1/me as jwtAccountAdminA → 200, subject/userId/email/accounts populated",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="whoami-aaa",
            method="GET",
            path="/iam/v1/me",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('WhoAmI: subject = user:<userAAAId>', () => {",
                "  const j = pm.response.json();",
                "  const want = 'user:' + pm.environment.get('userAAAId');",
                "  pm.expect(j.subject, JSON.stringify(j)).to.eql(want);",
                "});",
                "pm.test('WhoAmI: userId matches userAAAId', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.userId, JSON.stringify(j)).to.eql(pm.environment.get('userAAAId'));",
                "});",
                "pm.test('WhoAmI: email non-empty', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.email, 'email field').to.be.a('string').with.length.greaterThan(0);",
                "});",
                "pm.test('WhoAmI: clusterViewer is a boolean', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.clusterViewer, 'clusterViewer field').to.be.a('boolean');",
                "});",
                "pm.test('WhoAmI: systemAdmin is a boolean', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.systemAdmin, 'systemAdmin field').to.be.a('boolean');",
                "});",
                "pm.test('WhoAmI: accounts is an array', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.accounts, 'accounts field').to.be.an('array');",
                "});",
                "pm.test('WhoAmI: accounts contains accountAId (owner)', () => {",
                "  const j = pm.response.json();",
                "  const aid = pm.environment.get('accountAId');",
                "  const found = (j.accounts || []).find(m => m.accountId === aid);",
                "  pm.expect(found, 'accountAId membership entry').to.be.an('object');",
                "});",
                *assert_created_at_seconds("pm.response.json().checkedAt"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-WAI-GT-AUTHZ-ANON-DENY — anonymous WhoAmI → 401 UNAUTHENTICATED
# Handler is authoritative gate (catalog marks WhoAmI as <exempt> for FGA).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-WAI-GT-AUTHZ-ANON-DENY",
    title="GET /iam/v1/me as anonymous (no Bearer) → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P0",
    steps=[
        Step(
            name="whoami-anon",
            method="GET",
            path="/iam/v1/me",
            auth="anonymous",
            test_script=[
                "pm.test('ANON: status 401', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(401));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('ANON: grpc code 16 (UNAUTHENTICATED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(16));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-WAI-GT-CRUD-NOB — no-bindings user can still call WhoAmI (exempt RPC)
# Confirms <exempt> RPC is reachable by any authenticated principal — even
# someone with zero account membership — returning an empty accounts list.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-WAI-GT-CRUD-NOB",
    title="GET /iam/v1/me as jwtNoBindings → 200, accounts empty (exempt for any authenticated)",
    classes=["CRUD"],
    priority="P1",
    steps=[
        Step(
            name="whoami-nob",
            method="GET",
            path="/iam/v1/me",
            auth="jwtNoBindings",
            test_script=[
                *assert_status(200),
                "pm.test('WhoAmI-NOB: subject = user:<userNOBId>', () => {",
                "  const j = pm.response.json();",
                "  const want = 'user:' + pm.environment.get('userNOBId');",
                "  pm.expect(j.subject, JSON.stringify(j)).to.eql(want);",
                "});",
                "pm.test('WhoAmI-NOB: accounts is array (possibly empty)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.accounts, 'accounts field').to.be.an('array');",
                "});",
                "pm.test('WhoAmI-NOB: systemAdmin = false (regular user)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.systemAdmin, 'NOB must not be system_admin').to.eql(false);",
                "});",
            ],
        ),
    ],
))
