# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set: PermissionCatalogService.ListPermissionCatalog.

The backend-driven grantable role-rule catalog — a PUBLIC sync read on the
external api-gateway mux (GET /iam/v1/permissionCatalog). It is platform
metadata (grantable-token taxonomy: modules → resources + editor flags + the
closed verb set + wildcard policy), NOT per-tenant data and NOT infra-sensitive
— so it lives on the PUBLIC listener with an authenticated floor: any
authenticated principal may read it, anonymous is fail-closed.

Source of truth (the catalog projects EXACTLY this — never more):
  kacho-iam authzmap.objectTypes (module.resource keys) + TypeHasVerbRelations
  + domain.ClosedVerbs + a curated hasListEndpoint table. No DB, no migration.

Covered scenarios:
  - authenticated GET → 200, modules[]/resources[]/closedVerbs/wildcardPolicy
    present, camelCase on the wire.
  - anonymous → 401 UNAUTHENTICATED (no taxonomy leaks pre-auth, no-leak body).
  - each resource carries labelSelectable (camelCase); vpc.subnet=true
    (mirror-fed), vpc.addressPool=false (not fed) — the ARM_LABELS feed-gate flag
    (domain.IsLabelSelectableType).

Auth mechanism (same as the existing authenticated iam/geo suites):
  Bearer {{jwtBootstrap}} — the shared authz-fixtures HS256 dev token for
  admin@prorobotech.ru; the catalog gates an authenticated floor (system_viewer
  tier), which this subject trivially satisfies. The catalog is NOT scope-
  filtered per-tenant (one platform-wide taxonomy), so a member and an
  admin would receive an identical catalog (asserted black-box only at the
  authenticated-floor level here; the per-tenant-identity parity is covered by
  the iam integration test TestListPermissionCatalog_AuthenticatedFloor).

Test-design techniques:
  - CONF (conformance): response shape vs the ListPermissionCatalogResponse
    contract — camelCase modules/resources/closedVerbs/wildcardPolicy; resources
    carry hasVerbRelations + hasListEndpoint booleans.
  - ECP (equivalence): authenticated (valid) vs anonymous (invalid) input class.
  - error-guessing: anonymous must 401 at the gateway authz interceptor and must
    NOT leak any module/resource taxonomy in the error body.
  - state-transition is N/A — sync read, no Operation envelope.

Test-first (strict TDD): authored RED before the iam handler exists; goes
GREEN once kacho-iam registers PermissionCatalogService on the public listener
AND kacho-api-gateway registers GET /iam/v1/permissionCatalog on the public mux.
"""

CASES = []


# ---------------------------------------------------------------------------
# CONF-G-01-catalog-happy — authenticated GET /iam/v1/permissionCatalog → 200
# with the grantable taxonomy.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="CONF-G-01-catalog-happy",
    title="GET /iam/v1/permissionCatalog as jwtBootstrap → 200, modules[]/closedVerbs/wildcardPolicy (camelCase)",
    classes=["CONF", "CRUD"],
    priority="P0",
    steps=[
        Step(
            name="list-permission-catalog-auth",
            method="GET",
            path="/iam/v1/permissionCatalog",
            auth="jwtBootstrap",
            test_script=[
                *assert_status(200),
                "pm.test('modules is a non-empty array', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.modules, JSON.stringify(j)).to.be.an('array');",
                "  pm.expect(j.modules.length, 'modules non-empty').to.be.greaterThan(0);",
                "});",
                "pm.test('modules include iam/vpc/compute/loadbalancer', () => {",
                "  const j = pm.response.json();",
                "  const names = (j.modules || []).map(m => m.module);",
                "  ['iam','vpc','compute','loadbalancer'].forEach(want => {",
                "    pm.expect(names, 'module ' + want + ' present in ' + JSON.stringify(names)).to.include(want);",
                "  });",
                "});",
                "pm.test('each resource carries camelCase hasVerbRelations + hasListEndpoint', () => {",
                "  const j = pm.response.json();",
                "  const iam = (j.modules || []).find(m => m.module === 'iam');",
                "  pm.expect(iam, 'iam module present').to.be.an('object');",
                "  pm.expect(iam.resources, 'iam.resources array').to.be.an('array');",
                "  const role = iam.resources.find(r => r.resource === 'role');",
                "  pm.expect(role, 'iam.role present in catalog').to.be.an('object');",
                "  pm.expect(role).to.have.property('hasVerbRelations');",
                "  pm.expect(role).to.have.property('hasListEndpoint');",
                "  pm.expect(role.hasVerbRelations, 'iam.role is verb-bearing').to.equal(true);",
                "});",
                "pm.test('closedVerbs == [get,list,create,update,delete] (fixed order)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.closedVerbs, JSON.stringify(j)).to.eql(['get','list','create','update','delete']);",
                "});",
                "pm.test('wildcardPolicy flags present (verb-* allowed; module/resource-* system-only)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.wildcardPolicy, JSON.stringify(j)).to.be.an('object');",
                "  pm.expect(j.wildcardPolicy.verbWildcardAllowedCustom, 'verb-* allowed in custom').to.equal(true);",
                "  pm.expect(j.wildcardPolicy.moduleResourceWildcardSystemOnly, 'module/resource-* system-only').to.equal(true);",
                "});",
                "pm.test('vpc.addressPool grantable+verb-bearing but hasListEndpoint=false (Internal-only List)', () => {",
                "  const j = pm.response.json();",
                "  const vpc = (j.modules || []).find(m => m.module === 'vpc');",
                "  pm.expect(vpc, 'vpc module present').to.be.an('object');",
                "  const ap = (vpc.resources || []).find(r => r.resource === 'addressPool');",
                "  pm.expect(ap, 'vpc.addressPool present in catalog').to.be.an('object');",
                "  pm.expect(ap.hasVerbRelations, 'addressPool verb-bearing').to.equal(true);",
                "  pm.expect(ap.hasListEndpoint, 'addressPool List is Internal-only → false').to.equal(false);",
                "});",
                "pm.test('labelSelectable present + vpc.subnet=true, vpc.addressPool=false (ARM_LABELS feed-gate)', () => {",
                "  const j = pm.response.json();",
                "  const vpc = (j.modules || []).find(m => m.module === 'vpc');",
                "  pm.expect(vpc, 'vpc module present').to.be.an('object');",
                "  const subnet = (vpc.resources || []).find(r => r.resource === 'subnet');",
                "  pm.expect(subnet, 'vpc.subnet present').to.be.an('object');",
                "  pm.expect(subnet).to.have.property('labelSelectable');",
                "  pm.expect(subnet.labelSelectable, 'vpc.subnet is mirror-fed → label-selectable').to.equal(true);",
                "  const ap = (vpc.resources || []).find(r => r.resource === 'addressPool');",
                "  pm.expect(ap, 'vpc.addressPool present').to.be.an('object');",
                "  pm.expect(ap).to.have.property('labelSelectable');",
                "  pm.expect(ap.labelSelectable, 'vpc.addressPool NOT fed → not label-selectable').to.equal(false);",
                "});",
                "pm.test('no `geo` module (geo.* not grantable)', () => {",
                "  const j = pm.response.json();",
                "  const names = (j.modules || []).map(m => m.module);",
                "  pm.expect(names, 'geo NOT in modules: ' + JSON.stringify(names)).to.not.include('geo');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# NEG-G-02-catalog-anonymous-unauthenticated — anonymous GET → 401, no leak.
# Matched negative for CONF-G-01-catalog-happy.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="NEG-G-02-catalog-anonymous-unauthenticated",
    title="GET /iam/v1/permissionCatalog as anonymous (no Bearer) → 401 Unauthenticated, no taxonomy leak",
    classes=["AUTHZ", "NEG", "SEC"],
    priority="P1",
    steps=[
        Step(
            name="list-permission-catalog-anon",
            method="GET",
            path="/iam/v1/permissionCatalog",
            auth="anonymous",
            test_script=[
                "pm.test('status 401', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(401));",
                "let j; try { j = pm.response.json(); } catch (e) { j = null; }",
                "pm.test('grpc code 16 (UNAUTHENTICATED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(16));",
                "pm.test('no taxonomy leaks pre-auth (no modules in error body)', () => {",
                "  pm.expect(j, JSON.stringify(j)).to.not.have.property('modules');",
                "});",
            ],
        ),
    ],
))
