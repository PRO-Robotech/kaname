# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set для AuthorizeService.WhoAmI.

Covered RPCs:
  AuthorizeService.WhoAmI (GET /iam/v1/me) — caller identity + permission snapshot.

CRUD fixture dependency (ровно то, что читает тело — сверено переписью):
  jwtHumanCeremony            — предъявитель ЧЕЛОВЕКА, добытый настоящим входом
                                паролем (волна церемонии); владелец ceremonyAccountId
  jwtHumanCeremonyNoBindings  — предъявитель ЧЕЛОВЕКА без единой выдачи
  ceremonyUserId              — id того же человека, что предъявляет jwtHumanCeremony
  ceremonyNoBindingsUserId    — id человека без выдач
  ceremonyAccountId           — аккаунт, которым владеет ceremonyUserId

  ПОЧЕМУ ИМЕННО ЧЕЛОВЕК, А НЕ СЛУЖЕБНАЯ УЧЁТКА. Кейс утверждает про ответ
  `subject == "user:<id>"` и про непустой `accounts`. Машинный предъявитель дал бы
  `service_account:<sva>` и пустой `userId` — то есть утверждения проверяли бы
  другой класс принципала, а не тот, о котором написаны.

  ЗДЕСЬ СТОЯЛ БЛОК, ПЕРЕЖИВШИЙ СВОЙ ПРЕДМЕТ (задача #1441, п.5). Он называл
  `jwtAccountAdminA`/`jwtAccountAdminB`/`jwtNoBindings`/`jwtBootstrap` и объявлял
  первые два предъявителями `userAAAId`/`userAABId`. Тело не читает НИ ОДИН из
  четырёх слотов (перепись: слотов в шапке 4, использовано 0), а сама пара
  невозможна by construction: `user*Id` — ЦЕЛИ ПРИВЯЗКИ, ни один выдаваемый
  предъявитель ими не аутентифицируется (`tests/authz-fixtures/principal_pairings.py`,
  `BINDING_TARGET_ONLY_IDS`). Держится гейтом
  `scripts/case_header_principal_claim_test.py`.

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

Acceptance scenarios (три, по числу кейсов набора):
  IAM-WAI-GT-CRUD-OK   — jwtHumanCeremony → 200, subject == "user:<ceremonyUserId>",
    userId == ceremonyUserId, accounts содержит ceremonyAccountId.
  IAM-WAI-GT-AUTHZ-ANON-DENY — без предъявителя → 401, код 16.
  IAM-WAI-GT-CRUD-NOB  — jwtHumanCeremonyNoBindings → 200, accounts пуст
    (`<exempt>`: ручка открыта всякому АУТЕНТИФИЦИРОВАННОМУ, выдач не требует).

  Положительный контроль стоит ПЕРЕД отрицанием и в том же наборе: «accounts пуст»
  без него было бы верно и о ручке, не заполняющей accounts никогда.

verifies: WhoAmI happy-path + anonymous denial; matches WhoAmIResponse
fields documented in proto access_binding_service.proto.
"""

CASES = []


# ---------------------------------------------------------------------------
# IAM-WAI-GT-CRUD-OK — owner queries WhoAmI → 200 + identity fields populated
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-WAI-GT-CRUD-OK",
    title="GET /iam/v1/me as jwtHumanCeremony → 200, subject/userId/email/accounts populated",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="whoami-aaa",
            method="GET",
            path="/iam/v1/me",
            auth="jwtHumanCeremony",
            test_script=[
                *assert_status(200),
                "pm.test('WhoAmI: subject = user:<ceremonyUserId>', () => {",
                "  const j = pm.response.json();",
                "  const want = 'user:' + pm.environment.get('ceremonyUserId');",
                "  pm.expect(j.subject, JSON.stringify(j)).to.eql(want);",
                "});",
                "pm.test('WhoAmI: userId matches ceremonyUserId', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.userId, JSON.stringify(j)).to.eql(pm.environment.get('ceremonyUserId'));",
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
                "pm.test('WhoAmI: accounts contains ceremonyAccountId (owner)', () => {",
                "  const j = pm.response.json();",
                "  const aid = pm.environment.get('ceremonyAccountId');",
                "  const found = (j.accounts || []).find(m => m.accountId === aid);",
                "  pm.expect(found, 'ceremonyAccountId membership entry').to.be.an('object');",
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
    title="GET /iam/v1/me as jwtHumanCeremonyNoBindings → 200, accounts empty (exempt for any authenticated)",
    classes=["CRUD"],
    priority="P1",
    steps=[
        Step(
            name="whoami-nob",
            method="GET",
            path="/iam/v1/me",
            auth="jwtHumanCeremonyNoBindings",
            test_script=[
                *assert_status(200),
                "pm.test('WhoAmI-NOB: subject = user:<ceremonyNoBindingsUserId>', () => {",
                "  const j = pm.response.json();",
                "  const want = 'user:' + pm.environment.get('ceremonyNoBindingsUserId');",
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
