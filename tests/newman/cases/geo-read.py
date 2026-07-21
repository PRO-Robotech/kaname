# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set: AUTHENTICATED kacho-geo public reads through the api-gateway.

These cases exercise the kacho-geo public read RPCs through the shared
api-gateway REST endpoint (port-forward :18080) using the authz-fixtures dev
HS256 JWTs. Registered in run.sh so the e2e green-gate
(scripts/assert-suites-green.sh) discovers out/geo-read.json.

Covered RPCs (public, sync read — gated `viewer`@`cluster:cluster_kacho_root`):
  geo.v1.ZoneService.List    GET /geo/v1/zones    → ListZonesResponse{zones[]}
  geo.v1.RegionService.List  GET /geo/v1/regions  → ListRegionsResponse{regions[]}

verifies: gateway→geo "no children to pick from" 503 regression — the
  api-gateway must dial the kacho-geo backend over mTLS at the correct host
  with the gateway→geo mTLS edge enabled.

The bug — and why no existing case caught it:
  The api-gateway dialed the kacho-geo gRPC backend at the wrong DNS host
  (`geo.kacho.svc.cluster.local` — NXDOMAIN; the Service is `kacho-geo`) AND the
  gateway→geo mTLS edge was disabled. So every AUTHENTICATED /geo/v1/* request
  reached an empty sub-conn balancer → grpc UNAVAILABLE (code 14)
  "no children to pick from" → REST 503. It slipped through because the suite had
  NO authenticated geo read: an UNAUTHENTICATED probe returns 401 at the gateway
  authz interceptor BEFORE the broken backend dial, masking the failure. These
  cases are the missing authenticated reads — they go RED on the 503 (and on a
  code-14 body), GREEN once the host + mTLS edge are correct.

Auth mechanism (same as the existing authenticated iam suites):
  Bearer {{jwtBootstrap}} — the shared authz-fixtures HS256 dev token for
  admin@prorobotech.ru, seeded `system_viewer`@`cluster:cluster_kacho_root`
  (tests/authz-fixtures/setup.sh). Geo public read gates `viewer`@cluster, and
  the FGA cluster type defines `viewer = ... or system_viewer or any_admin`
  (openfga-model-stub-configmap.yaml), so this subject satisfies the viewer floor.
  jwtBootstrap is patched into environments/local.postman_environment.json by the
  fixture bootstrap (patch-env.py).

Seeded geography (provisioned by the umbrella for e2e): at least one region
with zones (each carrying id + status). The concrete ids are an umbrella-seed
detail, so these reads assert response shape + reachability, not exact ids.

Test-design techniques:
  - CONF (conformance): response shape vs geo ListZonesResponse/ListRegionsResponse
    contract — camelCase `zones`/`regions` array of flat resources, seeded ids present.
  - ECP (equivalence): authenticated-viewer (valid) vs anonymous (invalid) input class.
  - error-guessing: the regression assertion is NEGATIVE about the failure mode —
    status MUST NOT be 503 and the body MUST NOT carry grpc code 14
    ("no children to pick from"); these are the exact signatures of the dial bug.
  - state-transition is N/A — reads are sync, no Operation envelope.

Per positive (authenticated read) there is a matched negative (anonymous → 401):
  the anonymous case both documents the masking interceptor and guards that geo
  reads stay authN-gated (not accidentally exempted).

Test-first (strict TDD): authored to go RED on the 503 before the dial fix.
Test-only — no prod code touched.
"""

CASES = []


# ---------------------------------------------------------------------------
# Shared regression guard — the two assertions that go RED on the dial bug.
# Asserted on EVERY authenticated geo read: status is NOT the 503 the broken
# backend returned, and the body (when JSON) does NOT carry grpc code 14
# (UNAVAILABLE "no children to pick from").
# ---------------------------------------------------------------------------

def assert_not_no_children_503():
    return [
        "pm.test('REGRESSION: not 503 (gateway->geo no-children)', () => {",
        "  pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.not.equal(503);",
        "});",
        "pm.test('REGRESSION: body not grpc code 14 (UNAVAILABLE no-children)', () => {",
        "  let j; try { j = pm.response.json(); } catch (e) { j = null; }",
        "  // A successful read has no top-level grpc `code`; only an error body does.",
        "  if (j && typeof j.code !== 'undefined') {",
        "    pm.expect(j.code, JSON.stringify(j)).to.not.equal(14);",
        "  }",
        "});",
    ]


# ---------------------------------------------------------------------------
# GEO-ZON-GT-CONF-OK — authenticated GET /geo/v1/zones → 200 + seeded zones.
# The primary regression: this request would have hit the broken backend dial
# (503 code 14) before the host + mTLS fix.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="GEO-ZON-GT-CONF-OK",
    title="GET /geo/v1/zones as jwtBootstrap → 200, zones[] non-empty + well-formed, not 503/code14",
    classes=["CONF", "CRUD"],
    priority="P0",
    steps=[
        Step(
            name="list-zones-auth",
            method="GET",
            path="/geo/v1/zones",
            auth="jwtBootstrap",
            test_script=[
                *assert_status(200),
                *assert_not_no_children_503(),
                "pm.test('zones is a non-empty array', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.zones, JSON.stringify(j)).to.be.an('array');",
                "  pm.expect(j.zones.length, 'zones non-empty').to.be.greaterThan(0);",
                "});",
                "pm.test('zones are well-formed (id + regionId present)', () => {",
                "  const j = pm.response.json();",
                "  (j.zones || []).forEach(z => {",
                "    pm.expect(z.id, 'zone id present: ' + JSON.stringify(z)).to.be.a('string').and.not.empty;",
                "    // NB: raw `status` is Internal-only (two-projection, security.md geo note) —",
                "    // the PUBLIC ZoneService projection omits it. Assert regionId (public) instead.",
                "    pm.expect(z.regionId, 'zone regionId present: ' + JSON.stringify(z)).to.be.a('string').and.not.empty;",
                "  });",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# GEO-REG-GT-CONF-OK — authenticated GET /geo/v1/regions → 200 + seeded region.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="GEO-REG-GT-CONF-OK",
    title="GET /geo/v1/regions as jwtBootstrap → 200, regions[] non-empty + well-formed, not 503/code14",
    classes=["CONF", "CRUD"],
    priority="P0",
    steps=[
        Step(
            name="list-regions-auth",
            method="GET",
            path="/geo/v1/regions",
            auth="jwtBootstrap",
            test_script=[
                *assert_status(200),
                *assert_not_no_children_503(),
                "pm.test('regions is a non-empty array', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.regions, JSON.stringify(j)).to.be.an('array');",
                "  pm.expect(j.regions.length, 'regions non-empty').to.be.greaterThan(0);",
                "});",
                "pm.test('regions are well-formed (id present)', () => {",
                "  const j = pm.response.json();",
                "  (j.regions || []).forEach(r => {",
                "    pm.expect(r.id, 'region id present: ' + JSON.stringify(r)).to.be.a('string').and.not.empty;",
                "  });",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# GEO-ZON-GT-AUTHZ-ANON-DENY — anonymous GET /geo/v1/zones → 401 UNAUTHENTICATED.
# Matched negative for GEO-ZON-GT-CONF-OK. This is the exact path that MASKED the
# 503 bug: the gateway authz interceptor rejects the anonymous caller (401, code
# 16) BEFORE the backend is ever dialed, so an unauthenticated probe never
# surfaced the broken host/mTLS edge. Guards geo read stays authN-gated.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="GEO-ZON-GT-AUTHZ-ANON-DENY",
    title="GET /geo/v1/zones as anonymous (no Bearer) → 401 Unauthenticated (masked the 503)",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="list-zones-anon",
            method="GET",
            path="/geo/v1/zones",
            auth="anonymous",
            test_script=[
                "pm.test('ANON: status 401', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(401));",
                "let j; try { j = pm.response.json(); } catch (e) { j = null; }",
                "pm.test('ANON: grpc code 16 (UNAUTHENTICATED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(16));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# GEO-REG-GT-AUTHZ-ANON-DENY — anonymous GET /geo/v1/regions → 401 UNAUTHENTICATED.
# Matched negative for GEO-REG-GT-CONF-OK.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="GEO-REG-GT-AUTHZ-ANON-DENY",
    title="GET /geo/v1/regions as anonymous (no Bearer) → 401 Unauthenticated (masked the 503)",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="list-regions-anon",
            method="GET",
            path="/geo/v1/regions",
            auth="anonymous",
            test_script=[
                "pm.test('ANON: status 401', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(401));",
                "let j; try { j = pm.response.json(); } catch (e) { j = null; }",
                "pm.test('ANON: grpc code 16 (UNAUTHENTICATED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(16));",
            ],
        ),
    ],
))
