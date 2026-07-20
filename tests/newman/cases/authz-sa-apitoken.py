# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set authz-sa-apitoken для kacho-iam.

The SA/api-token ALLOW cases (service-account vpc-editor@project-A1: NET-GT-A1,
NET-CR-A1, APITOK-NET-GT-A1) require the fixture's vpc-editor grant on project-A1
to emit FGA tier-tuples. emitAnchorRule materializes a wildcard *.* anchor rule as
a tier-tuple on the bare account/project scope anchor (the permissions-path
grant), so these ALLOW cases pass (200).

Расширяет authz default-deny matrix двумя НЕ-человеческими классами субъектов
(модели 5-6):

  Модель 5 — Service Account
    SA — non-human principal. Получает токен через Hydra `client_credentials`
    grant (у SA есть OAuth client_id/secret, выданный
    `SAKeyService.Issue`). Итоговый Kachō-JWT несет `sub=<svaId>` +
    `kacho_principal_type=service_account` (token_hook augment).

  Модель 6 — API token
    Статический long-lived API-token. На стенде моделируется JWT, привязанным
    к principal + scope. Покрываются valid-in-scope / out-of-scope / revoked /
    expired / malformed-варианты.

Почему отдельный case-file (не расширение authz-deny.py):
  authz-deny.py содержит 6 JWT-subjects моделей 1-4, у которых единый
  token-acquisition flow (HS256 mint по `sub`). SA и API-token структурно
  отличаются flow получения токена (Hydra client_credentials / static token
  issuance + revoke / expiry). По convention из gen.py README — отдельный
  case-file, если subjects структурно отличаются acquisition-flow'ом.

Семантика assert'ов (parity с authz-deny.py):
  - DENY        → 403 + grpc 7 (PERMISSION_DENIED) + "permission denied"
  - ALLOW       → != 403 и != 16 (не PermissionDenied и не Unauthenticated)
  - UNAUTH      → 401 + grpc 16 (UNAUTHENTICATED) — revoked / expired / malformed
  - EMPTY       → 200 + list.length === 0 (membership-scoped scope-filter List,
                  e.g. IAM ServiceAccount.List for a non-member account)

  NOTE — List authz is NOT uniform across services. IAM membership-scoped Lists
  (ServiceAccount/User/Project/Group.List ?accountId=…) return 200-empty for a
  non-member (EMPTY). vpc.NetworkService.List ?projectId=… is a project-viewer-
  GATED List: a caller with no `viewer` on the queried project is hard-denied 403
  (anti-cross-project-enumeration, CWE-862, owned by kacho-vpc) — NOT 200-empty.
  So the no-project-grant NET-LS probes below are DENY (403), while the no-grant
  IAM SA-LS probe stays EMPTY (200).

Pre-conditions: `tests/authz-fixtures/setup.sh` (шаги 9-10: issue SA-key
через SAKeyService + Hydra OAuth client; mint SA-JWT; issue/revoke
API-token). Env-var'ы:
  jwtSAA            — Service Account A токен (Hydra client_credentials,
                      sub=<svaAId>, grant: vpc-editor on project-A1)
  jwtSANoGrant      — Service Account без grant'ов (sub=<svaNoGrantId>)
  apiTokenValid     — статический API-token, in-scope (vpc.* on project-A1)
  apiTokenRevoked   — API-token, revoked через SAKeyService.Revoke
  apiTokenMalformed — синтаксически битый токен (не JWS, 2 сегмента)
  svaAId / svaNoGrantId — id ServiceAccount'ов (для self-modify проб)

SA-keys → private_key_jwt — NOTE FOR SETUP HARNESS:
  IssueSAKeyResponse больше НЕ возвращает `client_secret`. Вместо этого:
  `{client_id, private_key_pem, public_key_pem, algorithm: "ES256", key_id}`.
  Setup-harness, которая минтит `jwtSAA` / `jwtSANoGrant`, должна:
    1. Принять `private_key_pem` из IssueSAKey response.
    2. Подписать JWT-assertion (RFC 7521/7523) — header `{alg:"ES256",
       kid:<key_id>}`, claims `{iss:<client_id>, sub:<client_id>,
       aud:<hydra-issuer>/oauth2/token, exp:now+60s, jti:<rand>}`.
    3. POST к Hydra `/oauth2/token` с
       `grant_type=client_credentials`,
       `client_id=<client_id>`,
       `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`,
       `client_assertion=<signed-JWT>`.
    4. Использовать выданный access_token как `jwtSAA`.
  Postman-CLI/newman нативно JWT ES256 не подписывает — нужна
  pre-request script с jsrsasign / отдельный CLI-helper в setup-harness'е.
  Кейсы остаются known-RED до миграции setup-harness'а на ES256-assertion flow.
"""

CASES = []

# System role ids — source of truth = migration 0008_role_catalog_kac122.sql
# (deterministic `rol` + substr(md5(<name>),1,17); the legacy
# `rol00000000000000<tail>` ids from migration 0001 are DELETEd by 0008). A
# binding with a non-existent role_id fails the worker FAILED_PRECONDITION —
#
ROLE_ADMIN = "rol21232f297a57a5a74"   # md5('admin')[:17] — global super-admin

# ---------------------------------------------------------------------------
# Субъекты моделей 5-6.
#   code  — короткий идентификатор (в case-id)
#   label — человекочитаемое имя
#   auth  — имя env-var с токеном (Step.auth)
# ---------------------------------------------------------------------------

SA_GRANTED = ("SAA", "service-account-A (vpc-editor on project-A1)", "jwtSAA")
SA_NOGRANT = ("SANG", "service-account-no-grant", "jwtSANoGrant")
API_VALID = ("APIV", "api-token-valid (in-scope vpc.* on project-A1)", "apiTokenValid")
API_REVOKED = ("APIR", "api-token-revoked", "apiTokenRevoked")
API_MALFORMED = ("APIM", "api-token-malformed", "apiTokenMalformed")


# ---------------------------------------------------------------------------
# Assert-блоки (parity с authz-deny.py — те же decision-классы).
# ---------------------------------------------------------------------------

def deny_asserts(case_id):
    return [
        f"pm.test('[{case_id}] DENY: status 403', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(403));",
        "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
        f"pm.test('[{case_id}] DENY: grpc code 7 (PERMISSION_DENIED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(7));",
        f"pm.test('[{case_id}] DENY: message contains permission denied', () => pm.expect((j && j.message || '').toLowerCase()).to.contain('permission denied'));",
    ]


def _is_single_resource_get(path):
    # Single-resource Get: last path segment is a concrete id (a `{{var}}` or a
    # literal resource id) with no ?query. A List (?projectId=…) is not a single
    # read and a denied List stays PermissionDenied (403), not hidden as 404.
    if "?" in path:
        return False
    last = path.rstrip("/").rsplit("/", 1)[-1]
    if last.startswith("{{") and last.endswith("}}"):
        return True
    return len(last) >= 20 and last[:3].isalpha() and last[3:].isalnum()


def read_deny_asserts(case_id):
    # BUG-2 hide-existence: a denied single-resource read (Get) on a verb-bearing
    # resource is surfaced as NotFound (404 / code 5), never PermissionDenied — no
    # enumeration / existence leak. Token-scope and cross-account read denials are
    # all FGA read-denies → 404.
    return [
        f"pm.test('[{case_id}] READ-DENY: status 404 (hide existence)', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(404));",
        "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
        f"pm.test('[{case_id}] READ-DENY: grpc code 5 (NOT_FOUND, not 7)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(5));",
        f"pm.test('[{case_id}] READ-DENY: no deny_reasons leak', () => pm.expect(JSON.stringify(j || {{}}).toLowerCase()).to.not.include('deny_reasons'));",
    ]


def allow_asserts(case_id):
    return [
        f"pm.test('[{case_id}] ALLOW: not 403 (PermissionDenied)', () => pm.expect(pm.response.code, 'unexpected 403: ' + pm.response.text()).to.not.equal(403));",
        "let _j; try { _j = pm.response.json(); } catch(e) { _j = null; }",
        f"pm.test('[{case_id}] ALLOW: not Unauthenticated (16)', () => pm.expect(_j && _j.code, JSON.stringify(_j)).to.not.equal(16));",
    ]


def unauth_asserts(case_id):
    return [
        f"pm.test('[{case_id}] UNAUTH: status 401', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(401));",
        "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
        f"pm.test('[{case_id}] UNAUTH: grpc code 16 (UNAUTHENTICATED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(16));",
    ]


def empty_asserts(case_id, list_key):
    return [
        f"pm.test('[{case_id}] EMPTY: status 200', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(200));",
        "const body = pm.response.json();",
        f"pm.test('[{case_id}] EMPTY: zero {list_key} (scope-filter)', () => pm.expect((body && body.{list_key} || []).length).to.equal(0));",
    ]


def emit(case_id, title, decision, method, path, body, subject, list_key="networks"):
    """Разворачивает один кейс. decision ∈ {DENY, ALLOW, UNAUTH, EMPTY}."""
    code, label, auth = subject
    if decision == "DENY":
        # BUG-2 hide-existence: a denied single-resource read (Get) → 404/code-5,
        # not 403. Mutations (Create/Delete) and List stay 403/code-7.
        asserts = read_deny_asserts(case_id) if (method == "GET" and _is_single_resource_get(path)) else deny_asserts(case_id)
        cls = ["AUTHZ", "NEG"]
    elif decision == "ALLOW":
        asserts = allow_asserts(case_id)
        cls = ["AUTHZ", "POS"]
    elif decision == "UNAUTH":
        asserts = unauth_asserts(case_id)
        cls = ["AUTHZ", "NEG", "AUTHN"]
    elif decision == "EMPTY":
        asserts = empty_asserts(case_id, list_key)
        cls = ["AUTHZ", "SCOPE"]
    else:
        raise ValueError(f"unknown decision {decision} for {case_id}")
    CASES.append(Case(
        id=case_id,
        title=f"[{decision}] {title} as {label}",
        classes=cls,
        priority="P1",
        steps=[Step(name=method.lower(), method=method, path=path,
                    body=body, auth=auth, test_script=asserts)],
    ))


# ===========================================================================
# МОДЕЛЬ 5 — Service Account (Hydra client_credentials, Class A workload id).
# ===========================================================================
#
# SA-A имеет AccessBinding(vpc-editor) на project-A1 (выдан в setup-фазе).
# SA-A токен получен через client_credentials → claims содержат
# kacho_principal_type=service_account, sub=<svaAId>.
#
# Decision table (SA-A — grant=vpc-editor@project-A1):
#   resource в project-A1 (own)         → ALLOW  (binding покрывает)
#   resource в project-A2 / project-B1  → DENY   (нет binding; per-resource Get/Create)
#   account-A / account-B уровень       → DENY   (project-scoped grant ≠ account)
#   list ?projectId=A1                  → ALLOW
#   list ?projectId=A2 / ?projectId=B1  → DENY   (vpc.NetworkService.List is a
#                                          project-viewer-GATED List RPC: the caller
#                                          must hold `viewer` on `project:<projectId>`
#                                          to enumerate its networks; no grant on the
#                                          queried project → 403 PermissionDenied, NOT a
#                                          200-empty scope-filter. This is a deliberate
#                                          anti-cross-project-enumeration gate owned by
#                                          kacho-vpc (permission_map.go NetworkService/List
#                                          required_relation=viewer@project; locked by the
#                                          CWE-862 regression test
#                                          permission_map_networklist_test.go). Only a
#                                          caller WITH project-viewer but no per-network
#                                          grant sees 200-empty — that is not this case.)
#   self-modify / escalate              → DENY   (SA не может grant'ить себе роли)
# ---------------------------------------------------------------------------

# SA-A-1: SA-A с grant → 200 на разрешенный ресурс в его Project (VPC Network GET).
emit("AUTHZ-SA-NET-GT-A1", "Get seed-network in project-A1 (granted resource)",
     "ALLOW", "GET", "/vpc/v1/networks/{{seedNetworkA1Id}}", None, SA_GRANTED)

# SA-A-2: SA-A list networks в своем Project → ALLOW.
emit("AUTHZ-SA-NET-LS-A1", "List networks ?projectId=A1 (own project)",
     "ALLOW", "GET", "/vpc/v1/networks?projectId={{projectA1Id}}", None, SA_GRANTED)

# SA-A-3: SA-A create network в своем Project → ALLOW (не PermissionDenied;
#         реальный код может быть 200-async — happy-path валидируют vpc-тесты).
emit("AUTHZ-SA-NET-CR-A1", "Create network in project-A1 (own project)",
     "ALLOW", "POST", "/vpc/v1/networks",
     {"projectId": "{{projectA1Id}}", "name": "authz-sa-net-{{runId}}"}, SA_GRANTED)

# SA-A-4: SA-A list networks в cross-project того же account (A2, без binding).
# vpc.NetworkService.List is project-viewer-GATED: the caller must hold `viewer`
# on `project:A2` to enumerate its networks. SA-A has viewer only on project-A1,
# so listing project-A2 → 403 PermissionDenied (anti-cross-project-enumeration,
# CWE-862; owned by kacho-vpc permission_map, not a 200-empty scope-filter). Same
# semantics as B1 below.
emit("AUTHZ-SA-NET-LS-A2-DENY", "List networks ?projectId=A2 (cross-project, no project-viewer) → 403 gated List",
     "DENY", "GET", "/vpc/v1/networks?projectId={{projectA2Id}}", None, SA_GRANTED)

# SA-A-5: SA-A без grant на ДРУГОЙ Project (B1, cross-account) → DENY.
emit("AUTHZ-SA-NET-GT-B1", "Get seed-network in project-B1 (cross-account, no grant)",
     "DENY", "GET", "/vpc/v1/networks/{{seedNetworkB1Id}}", None, SA_GRANTED)

emit("AUTHZ-SA-NET-CR-B1", "Create network in project-B1 (cross-account, no grant)",
     "DENY", "POST", "/vpc/v1/networks",
     {"projectId": "{{projectB1Id}}", "name": "authz-sa-net-{{runId}}"}, SA_GRANTED)

# SA-A-6: SA-A list networks в cross-account project (B1) — no project-viewer on B1
#         → 403 PermissionDenied (project-viewer-gated List, anti-enumeration),
#         НЕ список чужих networks и НЕ distinguishing 200-empty.
emit("AUTHZ-SA-NET-LS-B1-DENY", "List networks ?projectId=B1 (cross-account, no project-viewer) → 403 gated List",
     "DENY", "GET", "/vpc/v1/networks?projectId={{projectB1Id}}", None, SA_GRANTED)

# SA-A-7: project-scoped grant не дает account-уровневых прав → Get account-A DENY.
emit("AUTHZ-SA-ACCT-GT-A", "Get account-A (project-scoped grant ≠ account-level)",
     "DENY", "GET", "/iam/v1/accounts/{{accountAId}}", None, SA_GRANTED)

# SA-A-8: SA-A пытается изменить account-A → DENY.
emit("AUTHZ-SA-ACCT-UP-A", "Update account-A (no account-level grant)",
     "DENY", "PATCH", "/iam/v1/accounts/{{accountAId}}",
     {"name": "x", "updateMask": "name"}, SA_GRANTED)

# --- Negative: SA self-modify / privilege escalation ---

# SA-A-9: SA-A пытается выдать СЕБЕ iam.admin на account-A (escalation) → DENY.
emit("AUTHZ-SA-ESC-SELF-ADMIN", "Self-grant iam.admin on account-A (escalation)",
     "DENY", "POST", "/iam/v1/accessBindings",
     {"subjectType": "service_account", "subjectId": "{{svaAId}}",
      "roleId": ROLE_ADMIN,
      "scopeType":"iam.account","scopeId":"{{accountAId}}","target":{"allInScope":{}}}, SA_GRANTED)

# SA-A-10: SA-A пытается выдать себе vpc-admin на project-B1 (cross-account escalation).
emit("AUTHZ-SA-ESC-SELF-VPC-B1", "Self-grant vpc-admin on project-B1 (cross-account escalation)",
     "DENY", "POST", "/iam/v1/accessBindings",
     {"subjectType": "service_account", "subjectId": "{{svaAId}}",
      "roleId": ROLE_ADMIN,
      "scopeType":"iam.project","scopeId":"{{projectB1Id}}","target":{"allInScope":{}}}, SA_GRANTED)

# SA-A-11: SA-A пытается self-modify собственную SA-row (поднять привилегии
#          через rename / labels) — у SA нет iam-write на свой Account → DENY.
emit("AUTHZ-SA-ESC-SELF-MODIFY", "Self-modify own ServiceAccount row (escalation prep)",
     "DENY", "PATCH", "/iam/v1/serviceAccounts/{{svaAId}}",
     {"description": "escalated", "updateMask": "description"}, SA_GRANTED)

# SA-A-12: SA-A пытается выпустить себе НОВЫЙ SA-key (расширить доступы) → DENY.
#          SAKeyService.Issue требует iam-write на Account SA — у SA-A нет.
emit("AUTHZ-SA-ESC-ISSUE-KEY", "Issue new SA-key for self (escalation prep)",
     "DENY", "POST", "/iam/v1/serviceAccounts/{{svaAId}}/keys",
     {"serviceAccountId": "{{svaAId}}", "description": "self-issued",
      "createdByUserId": "{{userAAAId}}"}, SA_GRANTED)

# SA-A-13: SA-A пытается создать custom Role с broad rules → DENY
#          (cluster/account role-mutate недоступен SA-субъекту).
# RBAC rules model: authored field is `rules`. Module/resource
# wildcard `*` is system-only, so the legacy super-shaped iam.*.* / vpc.*.*
# intent is expressed as concrete resources with verb-wildcard `verbs:["*"]` —
# still a broad/escalation-shaped role. authz (SA cannot role-mutate) DENYs first.
emit("AUTHZ-SA-ESC-CUSTOM-ROLE", "Create custom Role with broad iam/vpc rules (escalation prep)",
     "DENY", "POST", "/iam/v1/roles",
     {"accountId": "{{accountAId}}", "name": "sa-hack-role-{{runId}}",
      "rules": [
          {"module": "iam", "resources": ["user", "role", "account"], "verbs": ["*"]},
          {"module": "vpc", "resources": ["network", "subnet"], "verbs": ["*"]},
      ]}, SA_GRANTED)

# --- SA without any grant (SANG) — должен быть полностью DENY ---

# SA-NG-1: SA без grant'ов на own-project ресурс → DENY.
emit("AUTHZ-SANG-NET-GT-A1", "Get seed-network in project-A1 (no grants at all)",
     "DENY", "GET", "/vpc/v1/networks/{{seedNetworkA1Id}}", None, SA_NOGRANT)

# SA-NG-2: SA без grant'ов — list networks project-A1: no project-viewer → 403
#          (project-viewer-gated List; a no-grant SA cannot even enumerate the project).
emit("AUTHZ-SANG-NET-LS-A1-DENY", "List networks ?projectId=A1 (no grants, no project-viewer) → 403 gated List",
     "DENY", "GET", "/vpc/v1/networks?projectId={{projectA1Id}}", None, SA_NOGRANT)

# SA-NG-3: SA без grant'ов — create network → DENY.
emit("AUTHZ-SANG-NET-CR-A1", "Create network in project-A1 (no grants)",
     "DENY", "POST", "/vpc/v1/networks",
     {"projectId": "{{projectA1Id}}", "name": "authz-sang-net-{{runId}}"}, SA_NOGRANT)

# SA-NG-4: SA без grant'ов — list serviceAccounts ?accountId → EMPTY.
emit("AUTHZ-SANG-SA-LS-A-EMPTY", "List serviceAccounts ?accountId=A (no grants) → scope-filter empty",
     "EMPTY", "GET", "/iam/v1/serviceAccounts?accountId={{accountAId}}", None, SA_NOGRANT,
     list_key="serviceAccounts")


# ===========================================================================
# МОДЕЛЬ 6 — API token (static long-lived; valid / out-of-scope / revoked /
#            expired / malformed).
# ===========================================================================
#
# apiTokenValid — статический API-token, scope = vpc.* on project-A1.
#   in-scope ресурс  → ALLOW
#   out-of-scope     → DENY (token валиден, но scope не покрывает)
# apiTokenRevoked   — отозван через SAKeyService.Revoke → 401 UNAUTHENTICATED
# apiTokenMalformed — синтаксически битый → 401 UNAUTHENTICATED
# (expired-вариант — apiTokenExpired, минтится setup'ом с exp в прошлом.)
# ---------------------------------------------------------------------------

# API-1: API-token valid + in-scope → 200 OK (не PermissionDenied/Unauthenticated).
emit("AUTHZ-APITOK-NET-GT-A1", "Get seed-network in project-A1 (valid, in-scope token)",
     "ALLOW", "GET", "/vpc/v1/networks/{{seedNetworkA1Id}}", None, API_VALID)

# API-2: API-token valid + in-scope list → ALLOW.
emit("AUTHZ-APITOK-NET-LS-A1", "List networks ?projectId=A1 (valid, in-scope token)",
     "ALLOW", "GET", "/vpc/v1/networks?projectId={{projectA1Id}}", None, API_VALID)

# API-3: API-token valid но out-of-scope ресурс (project-B1) → DENY.
emit("AUTHZ-APITOK-NET-GT-B1", "Get seed-network in project-B1 (valid token, out-of-scope)",
     "DENY", "GET", "/vpc/v1/networks/{{seedNetworkB1Id}}", None, API_VALID)

# API-4: API-token valid но out-of-scope domain — IAM account (scope только vpc.*) → DENY.
emit("AUTHZ-APITOK-ACCT-GT-A", "Get account-A (valid token, scope=vpc.* only)",
     "DENY", "GET", "/iam/v1/accounts/{{accountAId}}", None, API_VALID)

# API-5: API-token valid but out-of-scope — list ?projectId=B1: token scope is
#        vpc.* on project-A1, no viewer on project-B1 → 403 PermissionDenied
#        (project-viewer-gated List, anti-cross-project-enumeration).
emit("AUTHZ-APITOK-NET-LS-B1-DENY", "List networks ?projectId=B1 (out-of-scope, no project-viewer) → 403 gated List",
     "DENY", "GET", "/vpc/v1/networks?projectId={{projectB1Id}}", None, API_VALID)

# API-6: API-token revoked → 401 UNAUTHENTICATED (на in-scope ресурсе — revoke
#        бьет authn-слой раньше authz).
emit("AUTHZ-APITOK-REVOKED-GT-A1", "Get seed-network in project-A1 (revoked token)",
     "UNAUTH", "GET", "/vpc/v1/networks/{{seedNetworkA1Id}}", None, API_REVOKED)

# API-7: API-token revoked — list тоже 401 (не EMPTY: revoke = authn-fail).
emit("AUTHZ-APITOK-REVOKED-LS-A1", "List networks ?projectId=A1 (revoked token)",
     "UNAUTH", "GET", "/vpc/v1/networks?projectId={{projectA1Id}}", None, API_REVOKED)

# API-8: API-token malformed (битый JWS) → 401 UNAUTHENTICATED.
emit("AUTHZ-APITOK-MALFORMED-GT-A1", "Get seed-network in project-A1 (malformed token)",
     "UNAUTH", "GET", "/vpc/v1/networks/{{seedNetworkA1Id}}", None, API_MALFORMED)

# API-9: API-token expired → 401 UNAUTHENTICATED (exp в прошлом).
emit("AUTHZ-APITOK-EXPIRED-GT-A1", "Get seed-network in project-A1 (expired token)",
     "UNAUTH", "GET", "/vpc/v1/networks/{{seedNetworkA1Id}}", None,
     ("APIE", "api-token-expired", "apiTokenExpired"))

# API-10: API-token revoked пытается мутировать → 401 (authn-fail раньше authz).
emit("AUTHZ-APITOK-REVOKED-CR", "Create network with revoked token",
     "UNAUTH", "POST", "/vpc/v1/networks",
     {"projectId": "{{projectA1Id}}", "name": "authz-rev-net-{{runId}}"}, API_REVOKED)

# API-11: malformed token пытается мутировать → 401.
emit("AUTHZ-APITOK-MALFORMED-CR", "Create network with malformed token",
     "UNAUTH", "POST", "/vpc/v1/networks",
     {"projectId": "{{projectA1Id}}", "name": "authz-mal-net-{{runId}}"}, API_MALFORMED)

# --- Negative: API-token escalation ---

# API-12: valid API-token пытается выдать себе расширенный grant → DENY
#         (token scope vpc.* не включает iam.accessBinding.create).
emit("AUTHZ-APITOK-ESC-SELF-ADMIN", "Self-grant iam.admin via valid API token (escalation)",
     "DENY", "POST", "/iam/v1/accessBindings",
     {"subjectType": "service_account", "subjectId": "{{svaAId}}",
      "roleId": ROLE_ADMIN,
      "scopeType":"iam.account","scopeId":"{{accountAId}}","target":{"allInScope":{}}}, API_VALID)
