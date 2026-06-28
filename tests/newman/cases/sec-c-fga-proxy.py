# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set для IAM FGA-proxy (RegisterResource / UnregisterResource).

Internal FGA-proxy RPCs (cluster-internal listener :9091) that let
resource-owning modules (vpc/compute/nlb) register an owner-hierarchy tuple in
FGA *through IAM* instead of writing FGA directly. The intent is
enqueued into kacho_iam.fga_outbox in one writer-tx and applied by the drainer
(idempotent: already_exists→OK, missing-delete→OK — fga_applier.go).

REST internal mux (here we hit the internal listener {{baseUrl}} directly, which
is the internal mux in port-forward):
  POST /iam/v1/internal:registerResource
  POST /iam/v1/internal:unregisterResource

Body (camelCase; RegisterResourceRequest):
  { "subjectId": "project:prj-1", "relation": "parent",
    "object": "vpc_network:enp00000000000000001", "traceId": "..." }

Authz: exempt in proto + ReBAC `fga_writer@iam_fgaproxy:system`,
enforced in the IAM handler against the mTLS client-cert→SA identity. Over HTTP
through api-gateway (no mTLS cert) the dev-mode path applies; the ReBAC deny
matrix is covered at the integration level (fgaproxy_test.go) where a cert
identity can be injected deterministically.

Coverage:
  SEC-C-A-01  register happy → 200/OK, idempotent contract.
  SEC-C-A-02  register repeat → OK (NOT AlreadyExists).
  SEC-C-A-03  unregister happy → 200/OK.
  SEC-C-A-04  unregister absent tuple → OK (NOT NotFound).
  SEC-C-A-05  invalid arg (empty object) → InvalidArgument (3).
  SEC-C-A-09a register on external TLS endpoint → 404 (internal-only).

Test-first note (strict TDD):
  These cases are written RED-first — they fail until RegisterResource /
  UnregisterResource are implemented in kacho-iam AND registered on the
  api-gateway internal mux. Do not weaken assertions.

Known-RED (covered at the integration level):
  RegisterResource / UnregisterResource are cluster-internal :9091-only with NO
  google.api.http mapping — grpc-gateway emits no REST handler, so the
  api-gateway public endpoint returns 403 `catalog: no entry for method`. These
  cases are therefore NOT runnable as black-box REST; the behaviour is covered
  at the integration level (internal/.../fgaproxy_test.go). The suite is run by
  run.sh (so a report EXISTS — no `(no-report)` phantom) and whitelisted as
  known-RED in newman-e2e.yml by parent.name prefix `SEC-C-A-`. A future change
  may drop this REST suite or re-target it to grpcurl on :9091.
"""

CASES = []

REGISTER_PATH = "/iam/v1/internal:registerResource"
UNREGISTER_PATH = "/iam/v1/internal:unregisterResource"


def _ok_or_empty():
    # RegisterResourceResponse is empty {} on success → expect 200.
    return [
        "pm.test('status 200 (OK)', () => pm.expect(pm.response.code).to.eql(200));",
    ]


def _external_url_override(path: str):
    return [
        "const extBase = pm.environment.get('externalBaseUrl') || pm.variables.get('externalBaseUrl') || '';",
        "if (!extBase) {",
        "  console.warn('externalBaseUrl not set — skipping external isolation check.');",
        "  postman.setNextRequest(null);",
        "} else {",
        f"  pm.request.url = extBase + '{path}';",
        "}",
    ]


# ---------------------------------------------------------------------------
# SEC-C-A-01 — register happy path.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="SEC-C-A-01-REGISTER-OK",
    title="RegisterResource (happy) → 200; owner-tuple enqueued via fga_outbox",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        Step(
            name="register",
            method="POST",
            path=REGISTER_PATH,
            body={
                "subjectId": "project:prj-secc-{{runId}}",
                "relation": "parent",
                "object": "vpc_network:enpsecc{{runId}}",
                "traceId": "secc-a01-{{runId}}",
            },
            test_script=_ok_or_empty(),
        ),
    ],
))

# ---------------------------------------------------------------------------
# SEC-C-A-02 — register repeat → OK, not AlreadyExists.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="SEC-C-A-02-REGISTER-IDEMPOTENT",
    title="RegisterResource repeat with identical tuple → OK (NOT AlreadyExists)",
    classes=["IDM", "SEC"],
    priority="P0",
    steps=[
        Step(name="register-1", method="POST", path=REGISTER_PATH,
             body={"subjectId": "project:prj-idm-{{runId}}", "relation": "parent",
                   "object": "vpc_network:enpidm{{runId}}"},
             test_script=_ok_or_empty()),
        Step(name="register-2", method="POST", path=REGISTER_PATH,
             body={"subjectId": "project:prj-idm-{{runId}}", "relation": "parent",
                   "object": "vpc_network:enpidm{{runId}}"},
             test_script=[
                 "pm.test('repeat register is OK (200), never AlreadyExists (6)', () => {",
                 "  pm.expect(pm.response.code).to.eql(200);",
                 "});",
             ]),
    ],
))

# ---------------------------------------------------------------------------
# SEC-C-A-03 — unregister happy.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="SEC-C-A-03-UNREGISTER-OK",
    title="UnregisterResource (happy) → 200; revoke-tuple enqueued",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        Step(name="register", method="POST", path=REGISTER_PATH,
             body={"subjectId": "project:prj-unreg-{{runId}}", "relation": "parent",
                   "object": "vpc_network:enpunreg{{runId}}"},
             test_script=_ok_or_empty()),
        Step(name="unregister", method="POST", path=UNREGISTER_PATH,
             body={"subjectId": "project:prj-unreg-{{runId}}", "relation": "parent",
                   "object": "vpc_network:enpunreg{{runId}}"},
             test_script=_ok_or_empty()),
    ],
))

# ---------------------------------------------------------------------------
# SEC-C-A-04 — unregister absent tuple → OK, not NotFound.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="SEC-C-A-04-UNREGISTER-IDEMPOTENT",
    title="UnregisterResource of never-registered tuple → OK (NOT NotFound)",
    classes=["IDM", "SEC"],
    priority="P0",
    steps=[
        Step(name="unregister-absent", method="POST", path=UNREGISTER_PATH,
             body={"subjectId": "project:prj-absent-{{runId}}", "relation": "parent",
                   "object": "vpc_network:enpabsent{{runId}}"},
             test_script=[
                 "pm.test('unregister absent is OK (200), never NotFound (5)', () => {",
                 "  pm.expect(pm.response.code).to.eql(200);",
                 "});",
             ]),
    ],
))

# ---------------------------------------------------------------------------
# SEC-C-A-05 — invalid arg (empty object) → InvalidArgument.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="SEC-C-A-05-NEG-INVALID-INPUT",
    title="RegisterResource with empty object → InvalidArgument (3)",
    classes=["NEG", "VAL"],
    priority="P0",
    steps=[
        Step(name="register-empty-object", method="POST", path=REGISTER_PATH,
             body={"subjectId": "project:prj-1", "relation": "parent", "object": ""},
             test_script=[
                 "pm.test('status 400', () => pm.expect(pm.response.code).to.eql(400));",
                 "pm.test('grpc code 3 (InvalidArgument)', () => {",
                 "  const j = pm.response.json();",
                 "  pm.expect(j.code, JSON.stringify(j)).to.eql(3);",
                 "});",
             ]),
    ],
))

# ---------------------------------------------------------------------------
# SEC-C-A-09a — RegisterResource on external TLS endpoint → 404 (ban #6).
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="SEC-C-A-09-NEG-EXT-INTERNAL-ONLY",
    title="RegisterResource on external TLS endpoint → 404 (internal-only, ban #6)",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        Step(name="register-on-external", method="POST", path=REGISTER_PATH,
             body={"subjectId": "project:prj-1", "relation": "parent",
                   "object": "vpc_network:enp1"},
             pre_script=_external_url_override(REGISTER_PATH),
             test_script=[
                 "pm.test('internal-only: 404 on external endpoint', () => {",
                 "  pm.expect([404, 501]).to.include(pm.response.code);",
                 "});",
             ]),
    ],
))
