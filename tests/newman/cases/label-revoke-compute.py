# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Cross-service ARM_LABELS revoke-on-label-change, compute resources (e2e).

Same mechanic as label-revoke-vpc.py — see that file's module docstring for the
full clean-subject / assignability / v_list-probe / umbrella-only rationale. This
file is the compute table (disk / image / snapshot), each of which had the
emit-on-Update gap (a label removed on Update must revoke the matching grant).

verifies: removing the matching label on a compute resource Update revokes the
ARM_LABELS grant (Check v_list flips True→False).

Per resource: create resource{tier:treska} → grant ARM_LABELS{module:compute,
matchLabels:tier=treska} account-scoped → pre/post-grant Check(v_list) → Update
labels={} → visibility converges to DENY. compute fga types: compute_disk /
compute_image / compute_snapshot (authzmap/fga_types.go).

Seed chain: image + snapshot require a source disk_id, so a single base disk is
created first and reused as the source for the image and snapshot cases. Each
label-selectable resource carries its OWN {tier:treska} label and its OWN grant
subject + role (independent cases).

DEPLOYMENT SCOPE — full-umbrella stack: requires kacho-compute (+ kacho-geo for
zone) deployed behind the gateway so compute→iam RegisterResource feeds
resource_mirror. The umbrella e2e brings up the full stack and runs this shared
iam suite, so these execute against a complete deployment.

ZONE DISCOVERY (no env-fixture dependency). The shared kacho-iam newman env
(environments/local.postman_environment.json, patched by authz-fixtures) carries
ONLY iam ids — it does NOT define existingZoneId / existingDiskTypeId (those are
kacho-compute-suite env vars, absent in the iam harness the umbrella runs). A disk
Create with the unsubstituted literal "{{existingZoneId}}" failed async with
`Zone {{existingZoneId}} not found` (code 3) → no disk → image/snapshot
source-disk cascade broke → grant never materialized → false-RED. Fix: each
disk-creating case first GETs the geo-seeded zones via the PUBLIC read
GET /geo/v1/zones (idempotent — same source geo-read.py asserts) and stashes the
first zone id into a
suite-local env var {{_t31cZoneId}}, used as zoneId. typeId is OMITTED — compute
defaults it to network-ssd (disk.py DISK-CR-CRUD-OK pins the default), so no
diskType fixture is needed either.

Fixtures: jwtBootstrap, jwtAccountAdminA, accountAId. The zone is DISCOVERED at
runtime (see above), and — mirroring that same discipline — the PROJECT is now
self-seeded per case (create_suite_project → {{_t31cProj}}) instead of read from the
shared {{projectA1Id}} fixture. That fixture var could resolve to a PHANTOM project
(an id whose IAM row never committed — ensure_project extracts metadata.projectId even
from a Create Operation that finished WITH an error), so the cross-service peer-check
compute DiskService.Create → iam project-resolve returned `Folder with id <id> not
found` and every case cascaded RED. A freshly-created, op-poll-confirmed project is
guaranteed to exist for the peer-check. Test-design: same as vpc file (state-transition,
ECP, error-guessing). One thought per pm.test().
"""

CASES = []

POLL_CAP = 30

DISKS = "/compute/v1/disks"
IMAGES = "/compute/v1/images"
SNAPSHOTS = "/compute/v1/snapshots"
_DISK_SIZE = "4294967296"  # 4 GiB — comfortably over the image min_disk_size floor


def poll_op_done(op_var, auth="jwtAccountAdminA", out_id_var=None):
    capture = ""
    if out_id_var:
        capture = (f"if (j.response && j.response.id && !pm.environment.get('{out_id_var}')) "
                   f"{{ pm.environment.set('{out_id_var}', j.response.id); }}")
    return [
        "const j = pm.response.json();",
        "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
        "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
        f"if (!j.done && pc < {POLL_CAP}) {{",
        "  pm.environment.set('_pollCount', String(pc + 1));",
        "  pm.execution.setNextRequest(pm.info.requestName);",
        "  return;",
        "}",
        "pm.environment.unset('_pollCount');",
        "pm.environment.unset('_pollStarted');",
        capture,
        "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
        "pm.test('operation no error', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
    ]


def _internal_url_override(path):
    """Redirect this request to the api-gateway cluster-internal REST listener
    ({{internalBaseUrl}} = :18081 in CI). Internal* paths (/iam/v1/internal/*) are
    served ONLY there — the public cmux ({{baseUrl}} = :18080) 404s them by design
    (ban #6). gen.py emits {{baseUrl}}<path>; without this override the FGA-Check
    probe hits the public port → 404 page-not-found → JSONError on the first
    pm.response.json(). Mirrors iam-internal-only-check.py::_internal_url_override.
    internalBaseUrl is injected at runtime by deploy/scripts/newman-e2e.sh."""
    return [
        "// internal-only Check probe → api-gateway cluster-internal REST listener.",
        "const intBase = pm.environment.get('internalBaseUrl') || pm.variables.get('internalBaseUrl') || '';",
        "if (!intBase) {",
        "  console.warn('internalBaseUrl not set — skipping internal Check probe for this step.');",
        "  pm.execution.setNextRequest(null);",
        "} else {",
        f"  pm.request.url = intBase + '{path}';",
        "}",
    ]


def check_step(name, subject, relation, obj, expect_allowed, auth="jwtBootstrap", poll=False):
    retry = []
    if poll:
        retry = [
            "if (pm.environment.get('_ckStarted') !== pm.info.requestName) { pm.environment.set('_ckCount', '0'); pm.environment.set('_ckStarted', pm.info.requestName); }",
            "const cc = parseInt(pm.environment.get('_ckCount') || '0', 10);",
            f"if (!(pm.response.code === 200 && j.allowed === {str(expect_allowed).lower()}) && cc < {POLL_CAP}) {{",
            "  pm.environment.set('_ckCount', String(cc + 1));",
            # Real inter-poll delay (~500ms): newman fires setNextRequest before any
            # setTimeout, so a busy-wait is the ONLY way to actually space out the polls.
            # POLL_CAP*0.5s (~15s) then covers the grant/revoke FGA-materialization window
            # under PARALLEL load instead of hammering ~30 back-to-back Checks in <2s (which
            # never waits for the tuple to (dis)appear → the revoke-deny / grant-allow flake).
            "  const _ckd = Date.now(); while (Date.now() - _ckd < 500) { /* inter-poll materialization wait ~500ms */ }",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            "pm.environment.unset('_ckCount');",
            "pm.environment.unset('_ckStarted');",
        ]
    if expect_allowed:
        verdict = [
            f"pm.test('{name}: allowed == true', () => {{",
            "  pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200);",
            "  pm.expect(j.allowed, JSON.stringify(j)).to.eql(true);",
            "});",
        ]
    else:
        verdict = [
            f"pm.test('{name}: Check denies (allowed !== true)', () => {{",
            "  pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200);",
            "  pm.expect(j.allowed, JSON.stringify(j)).to.not.eql(true);",
            "});",
        ]
    return Step(name=name, method="POST", path="/iam/v1/internal/iam:check",
                auth=auth, body={"subjectId": subject, "relation": relation, "object": obj},
                pre_script=_internal_url_override("/iam/v1/internal/iam:check"),
                test_script=["const j = pm.response.json();", *retry, *verdict])


def create_fresh_sa(sa_var, name_suffix):
    return [
        Step(name=f"create-sa-{name_suffix}", method="POST", path="/iam/v1/serviceAccounts",
             body={"accountId": "{{accountAId}}", "name": f"t31c-sa-{name_suffix}-{{{{runId}}}}",
                   "description": "newman compute label-revoke clean subject"},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200),
                          *save_from_response("j.metadata && j.metadata.serviceAccountId", sa_var),
                          *save_from_response("j.id", f"_op_{sa_var}")]),
        Step(name=f"poll-sa-{name_suffix}", method="GET", path=f"/operations/{{{{_op_{sa_var}}}}}",
             auth="jwtAccountAdminA", test_script=poll_op_done(f"_op_{sa_var}", out_id_var=sa_var)),
    ]


def create_label_role(role_var, resource, name_suffix):
    rules = [{"module": "compute", "resources": [resource], "verbs": ["get", "list"],
              "matchLabels": {"tier": "treska"}}]
    return [
        Step(name=f"create-role-{name_suffix}", method="POST", path="/iam/v1/roles",
             body={"accountId": "{{accountAId}}", "name": f"t31c_{name_suffix}_{{{{runId}}}}",
                   "description": "newman compute ARM_LABELS probe role", "rules": rules},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200),
                          *save_from_response("j.metadata && j.metadata.roleId", role_var),
                          *save_from_response("j.id", f"_op_{role_var}")]),
        Step(name=f"poll-role-{name_suffix}", method="GET", path=f"/operations/{{{{_op_{role_var}}}}}",
             auth="jwtAccountAdminA", test_script=poll_op_done(f"_op_{role_var}", out_id_var=role_var)),
    ]


def assert_bind_succeeded(name):
    return [
        "const j = pm.response.json();",
        "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
        "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
        f"if (!j.done && pc < {POLL_CAP}) {{",
        "  pm.environment.set('_pollCount', String(pc + 1));",
        "  pm.execution.setNextRequest(pm.info.requestName);",
        "  return;",
        "}",
        "pm.environment.unset('_pollCount');",
        "pm.environment.unset('_pollStarted');",
        f"pm.test('{name}: bind operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
        f"pm.test('{name}: bind operation no error', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
        f"pm.test('{name}: bind NOT FailedPrecondition (assignable)', () => {{",
        "  const code = j.error && j.error.code;",
        "  pm.expect(code, JSON.stringify(j)).to.not.eql(9);",
        "});",
    ]


def bind_role_on_account(role_var, bind_op_var, subject_var, name_suffix):
    return [
        Step(name=f"bind-{name_suffix}", method="POST", path="/iam/v1/accessBindings",
             body={"subjectType": "service_account", "subjectId": f"{{{{{subject_var}}}}}",
                   "roleId": f"{{{{{role_var}}}}}", "resourceType": "account",
                   "resourceId": "{{accountAId}}"},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200), *save_from_response("j.id", bind_op_var)]),
        Step(name=f"poll-bind-{name_suffix}", method="GET", path=f"/operations/{{{{{bind_op_var}}}}}",
             auth="jwtAccountAdminA", test_script=assert_bind_succeeded(f"bind-{name_suffix}")),
    ]


def discover_zone(suffix):
    """GET /geo/v1/zones (public read, jwtBootstrap viewer@cluster floor) and stash
    the first seeded zone id into {{_t31cZoneId}}. The iam newman env has no
    existingZoneId; the geo migration seeds region-1-a/b/d (always present in the
    umbrella), so the first id is a valid Create input. Idempotent — only the first
    discover-zone-* step in a run sets it; later cases reuse the same value."""
    return Step(
        name=f"discover-zone-{suffix}", method="GET", path="/geo/v1/zones",
        auth="jwtBootstrap",
        test_script=[
            "const j = pm.response.json();",
            "pm.test('geo zones list reachable (zone discovery)', () => {",
            "  pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200);",
            "  pm.expect(j.zones, JSON.stringify(j)).to.be.an('array');",
            "  pm.expect(j.zones.length, 'at least one seeded zone').to.be.greaterThan(0);",
            "});",
            "if (j.zones && j.zones.length > 0) { pm.environment.set('_t31cZoneId', j.zones[0].id); }",
        ])


def create_suite_project(suffix):
    """Self-contained project seed — create a FRESH project under account-A at
    runtime and stash its id into {{_t31cProj}} (replacing the shared {{projectA1Id}}
    fixture dependency; same rationale as the runtime zone-discovery above). Prepended
    to every case so each owns a project GUARANTEED to exist for the cross-service
    peer-check (compute → iam project-resolve). The op-poll asserts done + NO error, so
    a project that ever fails to materialise fails LOUDLY here (not as an opaque
    downstream 'Folder with id <id> not found'). accountAId stays the shared-tenant
    anchor: the ARM_LABELS role is account-scoped on account:accountAId and containment
    matches resources whose parent_account_id == accountAId — a project under account-A
    satisfies it. Project.Create is authz-gated by editor@account:accountAId, which
    jwtAccountAdminA (account owner ⊇ editor) holds stably; the fresh-project OWNER-tuple
    lag is absorbed by create_base_disk's retry_until_authorized on the first disk Create."""
    return [
        Step(name=f"create-proj-{suffix}", method="POST", path="/iam/v1/projects",
             body={"accountId": "{{accountAId}}",
                   "name": f"t31c-prj-{suffix}-{{{{runId}}}}",
                   "description": "newman compute label-revoke self-contained project seed"},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200),
                          *save_from_response("j.metadata && j.metadata.projectId", "_t31cProj"),
                          *save_from_response("j.id", f"_op_proj_{suffix}")]),
        Step(name=f"poll-proj-{suffix}", method="GET", path=f"/operations/{{{{_op_proj_{suffix}}}}}",
             auth="jwtAccountAdminA", test_script=poll_op_done(f"_op_proj_{suffix}")),
    ]


def create_base_disk(disk_var, suffix, labels):
    # typeId is OMITTED — compute defaults to network-ssd (no diskType fixture
    # needed). zoneId comes from the runtime-discovered {{_t31cZoneId}}.
    return [
        discover_zone(suffix),
        # Bounded read-your-writes retry over AAA's create-authz materialization window:
        # DiskService.Create needs the caller's editor/creator on project:projectA1 (fixture
        # grant), whose cross-service FGA-cascade tuple can still be draining at umbrella
        # cold-start → the first Create 403s at the gateway authz gate. Retry SELF on 403
        # (403-create materialized nothing) until authorized; fail-closed at the budget.
        retry_until_authorized(
            Step(name=f"create-disk-{suffix}", method="POST", path=DISKS,
                 body={"projectId": "{{_t31cProj}}", "name": f"t31c-disk-{suffix}-{{{{runId}}}}",
                       "zoneId": "{{_t31cZoneId}}", "size": _DISK_SIZE, "labels": labels},
                 auth="jwtAccountAdminA",
                 test_script=[*assert_status(200),
                              *save_from_response("j.metadata && j.metadata.diskId", disk_var),
                              *save_from_response("j.id", f"_op_{disk_var}")]),
            budget=30, interval_ms=500, retry_on=(403,)),
        Step(name=f"poll-disk-{suffix}", method="GET", path=f"/operations/{{{{_op_{disk_var}}}}}",
             auth="jwtAccountAdminA", test_script=poll_op_done(f"_op_{disk_var}", out_id_var=disk_var)),
    ]


def revoke_case(case_id, title, fga_type, resource_kind, base_path,
                create_steps, body_id_var):
    """Build one disk/image/snapshot revoke case. create_steps already produced
    body_id_var (the resource id). The Update zeroes labels via an explicit
    STRING updateMask ("labels") — protojson serializes FieldMask as a
    comma-separated string, NOT a {paths:[...]} object (the object form 400s, so
    the op id is never saved and the poll/revoke asserts fail). The resource id
    is bound from the PATCH path; it MUST NOT appear in the body (mirrors the
    working iam-account.py update form). An explicit "labels" mask touches only
    labels, so name/other fields are left intact (no full-PATCH zeroing)."""
    sfx = resource_kind
    return Case(
        id=case_id, title=title,
        classes=["T31", "LABELS", "REVOKE", "FGA", "AUTHZ", "STATE", "COMPUTE"],
        priority="P0",
        steps=[
            *create_suite_project(sfx),
            *create_fresh_sa(f"_t31cSa{sfx}", sfx),
            *create_steps,
            check_step(f"{sfx}-pre-grant-deny", f"service_account:{{{{_t31cSa{sfx}}}}}", "v_list",
                       f"{fga_type}:{{{{{body_id_var}}}}}", expect_allowed=False),
            *create_label_role(f"_t31cRole{sfx}", resource_kind, sfx),
            *bind_role_on_account(f"_t31cRole{sfx}", f"_t31cBind{sfx}", f"_t31cSa{sfx}", sfx),
            check_step(f"{sfx}-post-grant-allow", f"service_account:{{{{_t31cSa{sfx}}}}}", "v_list",
                       f"{fga_type}:{{{{{body_id_var}}}}}", expect_allowed=True, poll=True),
            # label-remove on Update.
            Step(name=f"update-{sfx}-labels", method="PATCH",
                 path=f"{base_path}/{{{{{body_id_var}}}}}",
                 body={"updateMask": "labels", "labels": {}},
                 auth="jwtAccountAdminA",
                 test_script=[*assert_status(200), *save_from_response("j.id", f"_opu{sfx}")]),
            Step(name=f"poll-update-{sfx}", method="GET", path=f"/operations/{{{{_opu{sfx}}}}}",
                 auth="jwtAccountAdminA", test_script=poll_op_done(f"_opu{sfx}")),
            check_step(f"{sfx}-post-revoke-deny", f"service_account:{{{{_t31cSa{sfx}}}}}", "v_list",
                       f"{fga_type}:{{{{{body_id_var}}}}}", expect_allowed=False, poll=True),
        ],
    )


# ─────────────────────────────────────────────────────────────────────────────
# revoke03_disk.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(revoke_case(
    case_id="T31-LBLREVOKE-COMPUTE-DISK-03",
    title="revoke03_disk: compute.disk label-remove on Update revokes ARM_LABELS grant (Check v_list True→False)",
    fga_type="compute_disk", resource_kind="disk", base_path=DISKS,
    create_steps=create_base_disk("_t31cDisk", "disk", {"tier": "treska"}),
    body_id_var="_t31cDisk",
))


# ─────────────────────────────────────────────────────────────────────────────
# revoke03_snapshot. Snapshot needs a source disk_id.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(revoke_case(
    case_id="T31-LBLREVOKE-COMPUTE-SNAPSHOT-03",
    title="revoke03_snapshot: compute.snapshot label-remove on Update revokes ARM_LABELS grant (Check v_list True→False)",
    fga_type="compute_snapshot", resource_kind="snapshot", base_path=SNAPSHOTS,
    create_steps=[
        # source disk (unlabeled — its labels are irrelevant to the snapshot grant).
        *create_base_disk("_t31cSnapSrcDisk", "snapsrc", {}),
        # Bounded read-your-writes retry over AAA's create-authz materialization window
        # (same cold-start FGA-cascade lag as create-disk); retry SELF on 403 until authorized.
        retry_until_authorized(
            Step(name="create-snapshot", method="POST", path=SNAPSHOTS,
                 body={"projectId": "{{_t31cProj}}", "diskId": "{{_t31cSnapSrcDisk}}",
                       "name": "t31c-snap-{{runId}}", "labels": {"tier": "treska"}},
                 auth="jwtAccountAdminA",
                 test_script=[*assert_status(200),
                              *save_from_response("j.metadata && j.metadata.snapshotId", "_t31cSnap"),
                              *save_from_response("j.id", "_op_t31cSnap")]),
            budget=30, interval_ms=500, retry_on=(403,)),
        Step(name="poll-snapshot", method="GET", path="/operations/{{_op_t31cSnap}}",
             auth="jwtAccountAdminA", test_script=poll_op_done("_op_t31cSnap", out_id_var="_t31cSnap")),
    ],
    body_id_var="_t31cSnap",
))


# ─────────────────────────────────────────────────────────────────────────────
# revoke03_image. Image needs a source (disk_id here).
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(revoke_case(
    case_id="T31-LBLREVOKE-COMPUTE-IMAGE-03",
    title="revoke03_image: compute.image label-remove on Update revokes ARM_LABELS grant (Check v_list True→False)",
    fga_type="compute_image", resource_kind="image", base_path=IMAGES,
    create_steps=[
        *create_base_disk("_t31cImgSrcDisk", "imgsrc", {}),
        # Bounded read-your-writes retry over AAA's create-authz materialization window
        # (same cold-start FGA-cascade lag as create-disk); retry SELF on 403 until authorized.
        retry_until_authorized(
            Step(name="create-image", method="POST", path=IMAGES,
                 body={"projectId": "{{_t31cProj}}", "name": "t31c-img-{{runId}}",
                       "diskId": "{{_t31cImgSrcDisk}}", "labels": {"tier": "treska"}},
                 auth="jwtAccountAdminA",
                 test_script=[*assert_status(200),
                              *save_from_response("j.metadata && j.metadata.imageId", "_t31cImg"),
                              *save_from_response("j.id", "_op_t31cImg")]),
            budget=30, interval_ms=500, retry_on=(403,)),
        Step(name="poll-image", method="GET", path="/operations/{{_op_t31cImg}}",
             auth="jwtAccountAdminA", test_script=poll_op_done("_op_t31cImg", out_id_var="_t31cImg")),
    ],
    body_id_var="_t31cImg",
))
