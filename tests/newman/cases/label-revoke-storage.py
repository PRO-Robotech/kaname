# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Cross-service ARM_LABELS revoke-on-label-change, storage resources (e2e).

Same mechanic as label-revoke-compute.py / label-revoke-vpc.py — see the vpc file's
module docstring for the full clean-subject / assignability / v_list-probe rationale.
This file is the STORAGE table (volume / snapshot / image), the block-storage owner.

verifies: removing the matching label on a storage resource Update revokes the
ARM_LABELS grant (Check v_list flips True→False).

WHY THIS FILE EXISTS — it is the storage half of a check that once existed only for
the compute duplicate. Block storage is owned by kacho-storage; compute used to carry
a live Disk/Image/Snapshot duplicate, and the label-revoke evidence lived ENTIRELY on
the compute side (label-revoke-compute.py). Retiring the duplicate would have taken
with it the only executable proof that a label removal revokes access to a block-
storage object — leaving the storage FGA types (storage_volume / storage_snapshot /
storage_image) with no revoke coverage at all, and the removal itself invisible. The
duplicate is now retired on both sides (compute resources, then iam roles/vocabularies/
model types); this file is what carries the invariant forward.

CLOSED-TABLE NAMES ARE PLURAL FOR STORAGE. The rule's `resources` entries are the
second segment of the closed dotted key in authzmap: compute registers
`compute.instance` (SINGULAR) while storage registers `storage.volumes` /
`storage.snapshots` / `storage.images` (PLURAL, matching
the permission-catalog form storage.volumes.*). Copying the compute file's singular
resource names would produce a rule the domain rejects (`unknown module` is not the
failure here — the module is known; the pair simply is not in the table), so the
plural form is deliberate, not a typo.

Per resource: create resource{tier:treska} → grant ARM_LABELS{module:storage,
matchLabels:tier=treska} account-scoped → pre/post-grant Check(v_list) → Update
labels={} → visibility converges to DENY.

Seed chain: snapshot and image both require a SOURCE VOLUME, so each of those cases
first creates its own base volume and reuses it as the source. Each label-selectable
resource carries its OWN {tier:treska} label and its OWN grant subject + role
(independent cases). The source volumes are deliberately UNLABELLED — their labels
must not participate in the grant under test.

DEPLOYMENT SCOPE — full-umbrella stack: requires kacho-storage (+ kacho-geo for zone
and region) deployed behind the gateway so storage→iam RegisterResource feeds
resource_mirror. The umbrella e2e brings up the full stack and runs this shared iam
suite, so these execute against a complete deployment.

RUNTIME DISCOVERY (no env-fixture dependency). The shared kaname newman env carries
ONLY iam ids — it does NOT define existingZoneId / existingRegionId / existingDiskTypeId
(those are per-service suite vars, absent in the iam harness). Each case therefore
discovers what it needs from PUBLIC reads at runtime: GET /geo/v1/zones, GET
/geo/v1/regions, GET /storage/v1/diskTypes. Unlike compute (where typeId may be
omitted and defaulted), storage Volume.Create REQUIRES diskTypeId, so it is discovered
rather than defaulted. The PROJECT is self-seeded per case (create_suite_project →
{{_t31sProj}}) rather than read from the shared {{projectA1Id}} fixture, which could
resolve to a phantom project id — same discipline as the compute file.

Fixtures: jwtBootstrap, jwtAccountAdminA, accountAId.

CURRENT STATUS — GREEN, AND NOT WHITELISTED. When these cases were written the revoke
half was red and said so here: storage told the authority holding the label selector
what a resource's labels were at creation and again at deletion, and nothing in
between, so a removal never reached the selector and the grant outlived the label it
came from. That was fixed the same day, and this docstring outlived the fix — the note
saying otherwise stood for a day after the behaviour it described was gone.

Verified 2026-07-28 on the live umbrella: 87/87 assertions, 0 failed, all three
*-post-revoke-deny steps included. These cases are NOT whitelisted and must never be.
What they hold is an over-GRANT shape — access surviving the removal of the label it
was granted through — and that is the one shape a suite must never learn to tolerate.
A red here is a product finding, not a poll budget to widen. See docs/RESULTS.md,
section "Resolved — label-remove on storage revokes".
"""

CASES = []

POLL_CAP = 30

VOLUMES = "/storage/v1/volumes"
SNAPSHOTS = "/storage/v1/snapshots"
IMAGES = "/storage/v1/images"
_VOL_SIZE = 10737418240  # 10 GiB


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
        # Real inter-poll delay: newman fires setNextRequest before any setTimeout,
        # so a busy-wait is the only way to actually space the polls out.
        "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll wait ~500ms */ }",
        "  pm.execution.setNextRequest(pm.info.requestName);",
        "  return;",
        "}",
        "pm.environment.unset('_pollCount');",
        "pm.environment.unset('_pollStarted');",
        capture,
        "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
        # op.error is asserted BEFORE any id from metadata is used downstream: an
        # Operation carries a pre-allocated resource id even when it finished WITH an
        # error, so skipping this turns every later step into a probe against a phantom.
        "pm.test('operation no error', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
    ]


def _internal_url_override(path):
    """Redirect this request to the api-gateway cluster-internal REST listener.
    Internal* paths (/iam/v1/internal/*) are served ONLY there — the public mux 404s
    them by design (ban #6). A missing internalBaseUrl is a BROKEN HARNESS, not a
    legal skip, so require_env_url asserts it instead of silently dropping the probe."""
    return require_env_url(
        "internalBaseUrl", path,
        "internal-only Check probe — /iam/v1/internal/* is served ONLY by the "
        "cluster-internal REST listener")


def check_step(name, subject, relation, obj, expect_allowed, auth="jwtBootstrap", poll=False):
    retry = []
    if poll:
        retry = [
            "if (pm.environment.get('_ckStarted') !== pm.info.requestName) { pm.environment.set('_ckCount', '0'); pm.environment.set('_ckStarted', pm.info.requestName); }",
            "const cc = parseInt(pm.environment.get('_ckCount') || '0', 10);",
            f"if (!(pm.response.code === 200 && j.allowed === {str(expect_allowed).lower()}) && cc < {POLL_CAP}) {{",
            "  pm.environment.set('_ckCount', String(cc + 1));",
            # Real inter-poll delay (~500ms) — see poll_op_done. POLL_CAP*0.5s (~15s)
            # covers the grant/revoke FGA-materialization window under parallel load.
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
    """A CLEAN subject: a brand-new service account with no bindings whatsoever, so a
    post-grant ALLOW can only come from the ARM_LABELS grant under test."""
    return [
        Step(name=f"create-sa-{name_suffix}", method="POST", path="/iam/v1/serviceAccounts",
             body={"accountId": "{{accountAId}}", "name": f"t31s-sa-{name_suffix}-{{{{runId}}}}",
                   "description": "newman storage label-revoke clean subject"},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200),
                          *save_from_response("j.metadata && j.metadata.serviceAccountId", sa_var),
                          *save_from_response("j.id", f"_op_{sa_var}")]),
        Step(name=f"poll-sa-{name_suffix}", method="GET", path=f"/operations/{{{{_op_{sa_var}}}}}",
             auth="jwtAccountAdminA", test_script=poll_op_done(f"_op_{sa_var}", out_id_var=sa_var)),
    ]


def create_label_role(role_var, resource, name_suffix):
    # `resource` is the SECOND segment of the closed dotted key — PLURAL for storage
    # (storage.volumes / storage.snapshots / storage.images). See module docstring.
    rules = [{"module": "storage", "resources": [resource], "verbs": ["get", "list"],
              "matchLabels": {"tier": "treska"}}]
    return [
        Step(name=f"create-role-{name_suffix}", method="POST", path="/iam/v1/roles",
             body={"accountId": "{{accountAId}}", "name": f"t31s_{name_suffix}_{{{{runId}}}}",
                   "description": "newman storage ARM_LABELS probe role", "rules": rules},
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
        "  const _bd = Date.now(); while (Date.now() - _bd < 500) { /* inter-poll wait ~500ms */ }",
        "  pm.execution.setNextRequest(pm.info.requestName);",
        "  return;",
        "}",
        "pm.environment.unset('_pollCount');",
        "pm.environment.unset('_pollStarted');",
        f"pm.test('{name}: bind operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
        f"pm.test('{name}: bind operation no error', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
        # A role whose rules the model cannot project is not assignable: the bind comes
        # back FailedPrecondition. Asserting the ABSENCE of code 9 is what makes this a
        # statement about the RECEIVING side (the grant was accepted), not merely about
        # the emitting side (a role was written).
        f"pm.test('{name}: bind NOT FailedPrecondition (assignable)', () => {{",
        "  const code = j.error && j.error.code;",
        "  pm.expect(code, JSON.stringify(j)).to.not.eql(9);",
        "});",
    ]


def bind_role_on_account(role_var, bind_op_var, subject_var, name_suffix):
    return [
        Step(name=f"bind-{name_suffix}", method="POST", path="/iam/v1/accessBindings",
             body={"subjectType": "service_account", "subjectId": f"{{{{{subject_var}}}}}",
                   "roleId": f"{{{{{role_var}}}}}", "scopeType": "iam.account",
                   "scopeId": "{{accountAId}}", "target": {"allInScope": {}}},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200), *save_from_response("j.id", bind_op_var)]),
        Step(name=f"poll-bind-{name_suffix}", method="GET", path=f"/operations/{{{{{bind_op_var}}}}}",
             auth="jwtAccountAdminA", test_script=assert_bind_succeeded(f"bind-{name_suffix}")),
    ]


def discover_placement(suffix):
    """GET the geo + storage catalogs (public reads) and stash a zone, its region and a
    disk type into suite-local vars. The iam env defines none of them; the migrations
    seed all three, so the first entry of each is a valid Create input. Idempotent —
    only the first discovery in a run sets the values.

    The region is taken from the CHOSEN ZONE's own regionId, not from the first entry
    of the region list. The volume this suite creates lives in that zone and the image
    it captures is regional, and the two must be placement-coherent — picking the two
    independently made the fixture coherent only by the accident of both lists being
    ordered the same way. It is also the only correct way to obtain a zone's region:
    the owner of Geography reports it, it is never inferred from a name."""
    return [
        Step(name=f"discover-zone-{suffix}", method="GET", path="/geo/v1/zones",
             auth="jwtBootstrap",
             test_script=[
                 "const j = pm.response.json();",
                 "pm.test('geo zones list reachable (zone discovery)', () => {",
                 "  pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200);",
                 "  pm.expect(j.zones, JSON.stringify(j)).to.be.an('array');",
                 "  pm.expect(j.zones.length, 'at least one seeded zone').to.be.greaterThan(0);",
                 "});",
                 "pm.test('the seeded zone names its region (placement coherence needs it)', () => {",
                 "  pm.expect(j.zones[0].regionId, JSON.stringify(j.zones[0])).to.be.a('string').and.not.empty;",
                 "});",
                 "if (j.zones && j.zones.length > 0) {",
                 "  pm.environment.set('_t31sZoneId', j.zones[0].id);",
                 "  pm.environment.set('_t31sRegionId', j.zones[0].regionId);",
                 "}",
             ]),
        Step(name=f"discover-region-{suffix}", method="GET", path="/geo/v1/regions",
             auth="jwtBootstrap",
             test_script=[
                 "const j = pm.response.json();",
                 "pm.test('geo regions list reachable (region discovery)', () => {",
                 "  pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200);",
                 "  pm.expect(j.regions, JSON.stringify(j)).to.be.an('array');",
                 "  pm.expect(j.regions.length, 'at least one seeded region').to.be.greaterThan(0);",
                 "});",
                 "pm.test('the zone-derived region is in the catalog', () => {",
                 "  const want = pm.environment.get('_t31sRegionId');",
                 "  pm.expect(j.regions.map(r => r.id), JSON.stringify(j)).to.include(want);",
                 "});",
             ]),
        Step(name=f"discover-disktype-{suffix}", method="GET", path="/storage/v1/diskTypes",
             auth="jwtBootstrap",
             test_script=[
                 "const j = pm.response.json();",
                 "pm.test('storage diskTypes list reachable (diskType discovery)', () => {",
                 "  pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200);",
                 "  pm.expect(j.diskTypes, JSON.stringify(j)).to.be.an('array');",
                 "  pm.expect(j.diskTypes.length, 'at least one seeded diskType').to.be.greaterThan(0);",
                 "});",
                 "if (j.diskTypes && j.diskTypes.length > 0) { pm.environment.set('_t31sDiskTypeId', j.diskTypes[0].id); }",
             ]),
    ]


def create_suite_project(suffix):
    """Self-contained project seed — a FRESH project under account-A, created at
    runtime and stashed in {{_t31sProj}}. The op-poll asserts done + NO error, so a
    project that fails to materialise fails LOUDLY here instead of surfacing later as
    an opaque cross-service 'project not found'. The ARM_LABELS role is account-scoped
    on account:accountAId and containment matches resources whose parent account is
    accountAId — a project under account-A satisfies it."""
    return [
        Step(name=f"create-proj-{suffix}", method="POST", path="/iam/v1/projects",
             body={"accountId": "{{accountAId}}",
                   "name": f"t31s-prj-{suffix}-{{{{runId}}}}",
                   "description": "newman storage label-revoke self-contained project seed"},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200),
                          *save_from_response("j.metadata && j.metadata.projectId", "_t31sProj"),
                          *save_from_response("j.id", f"_op_proj_{suffix}")]),
        Step(name=f"poll-proj-{suffix}", method="GET", path=f"/operations/{{{{_op_proj_{suffix}}}}}",
             auth="jwtAccountAdminA", test_script=poll_op_done(f"_op_proj_{suffix}")),
    ]


def create_base_volume(vol_var, suffix, labels):
    """A READY volume. Serves both as the resource under test (labelled) and as the
    source for the snapshot / image cases (unlabelled)."""
    return [
        *discover_placement(suffix),
        # Bounded read-your-writes retry over the create-authz materialization window:
        # Volume.Create needs the caller's editor on the freshly-created project, whose
        # cross-service tuple can still be draining → the first Create 403s at the
        # gateway authz gate. Retry SELF on 403 (a 403-create materialized nothing).
        retry_until_authorized(
            Step(name=f"create-volume-{suffix}", method="POST", path=VOLUMES,
                 body={"projectId": "{{_t31sProj}}", "name": f"t31s-vol-{suffix}-{{{{runId}}}}",
                       "zoneId": "{{_t31sZoneId}}", "diskTypeId": "{{_t31sDiskTypeId}}",
                       "sizeBytes": _VOL_SIZE, "labels": labels},
                 auth="jwtAccountAdminA",
                 test_script=[*assert_status(200),
                              *save_from_response("j.metadata && j.metadata.volumeId", vol_var),
                              *save_from_response("j.id", f"_op_{vol_var}")]),
            budget=30, interval_ms=500, retry_on=(403,)),
        Step(name=f"poll-volume-{suffix}", method="GET", path=f"/operations/{{{{_op_{vol_var}}}}}",
             auth="jwtAccountAdminA", test_script=poll_op_done(f"_op_{vol_var}", out_id_var=vol_var)),
    ]


def revoke_case(case_id, title, fga_type, resource_kind, base_path,
                create_steps, body_id_var):
    """Build one volume/snapshot/image revoke case. create_steps has already produced
    body_id_var (the resource id). The Update zeroes labels via an explicit STRING
    updateMask ("labels") — protojson serializes FieldMask as a comma-separated string,
    NOT a {paths:[...]} object. The resource id is bound from the PATCH path and MUST
    NOT appear in the body. An explicit "labels" mask touches only labels, so name and
    other fields are left intact (no full-PATCH zeroing)."""
    sfx = resource_kind
    return Case(
        id=case_id, title=title,
        classes=["T31", "LABELS", "REVOKE", "FGA", "AUTHZ", "STATE", "STORAGE"],
        priority="P0",
        steps=[
            *create_suite_project(sfx),
            *create_fresh_sa(f"_t31sSa{sfx}", sfx),
            *create_steps,
            check_step(f"{sfx}-pre-grant-deny", f"service_account:{{{{_t31sSa{sfx}}}}}", "v_list",
                       f"{fga_type}:{{{{{body_id_var}}}}}", expect_allowed=False),
            *create_label_role(f"_t31sRole{sfx}", f"{resource_kind}s", sfx),
            *bind_role_on_account(f"_t31sRole{sfx}", f"_t31sBind{sfx}", f"_t31sSa{sfx}", sfx),
            check_step(f"{sfx}-post-grant-allow", f"service_account:{{{{_t31sSa{sfx}}}}}", "v_list",
                       f"{fga_type}:{{{{{body_id_var}}}}}", expect_allowed=True, poll=True),
            # label-remove on Update — the event under test.
            Step(name=f"update-{sfx}-labels", method="PATCH",
                 path=f"{base_path}/{{{{{body_id_var}}}}}",
                 body={"updateMask": "labels", "labels": {}},
                 auth="jwtAccountAdminA",
                 test_script=[*assert_status(200), *save_from_response("j.id", f"_opu{sfx}")]),
            Step(name=f"poll-update-{sfx}", method="GET", path=f"/operations/{{{{_opu{sfx}}}}}",
                 auth="jwtAccountAdminA", test_script=poll_op_done(f"_opu{sfx}")),
            check_step(f"{sfx}-post-revoke-deny", f"service_account:{{{{_t31sSa{sfx}}}}}", "v_list",
                       f"{fga_type}:{{{{{body_id_var}}}}}", expect_allowed=False, poll=True),
        ],
    )


# ─────────────────────────────────────────────────────────────────────────────
# revoke03_volume — storage.volumes / storage_volume.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(revoke_case(
    case_id="T31-LBLREVOKE-STORAGE-VOLUME-03",
    title="revoke03_volume: storage.volumes label-remove on Update revokes ARM_LABELS grant (Check v_list True→False)",
    fga_type="storage_volume", resource_kind="volume", base_path=VOLUMES,
    create_steps=create_base_volume("_t31sVol", "volume", {"tier": "treska"}),
    body_id_var="_t31sVol",
))


# ─────────────────────────────────────────────────────────────────────────────
# revoke03_snapshot — storage.snapshots / storage_snapshot. Needs a source volume.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(revoke_case(
    case_id="T31-LBLREVOKE-STORAGE-SNAPSHOT-03",
    title="revoke03_snapshot: storage.snapshots label-remove on Update revokes ARM_LABELS grant (Check v_list True→False)",
    fga_type="storage_snapshot", resource_kind="snapshot", base_path=SNAPSHOTS,
    create_steps=[
        # source volume (unlabelled — its labels are irrelevant to the snapshot grant).
        *create_base_volume("_t31sSnapSrcVol", "snapsrc", {}),
        retry_until_authorized(
            Step(name="create-snapshot", method="POST", path=SNAPSHOTS,
                 body={"projectId": "{{_t31sProj}}", "sourceVolumeId": "{{_t31sSnapSrcVol}}",
                       "name": "t31s-snap-{{runId}}", "labels": {"tier": "treska"}},
                 auth="jwtAccountAdminA",
                 test_script=[*assert_status(200),
                              *save_from_response("j.metadata && j.metadata.snapshotId", "_t31sSnap"),
                              *save_from_response("j.id", "_op_t31sSnap")]),
            budget=30, interval_ms=500, retry_on=(403,)),
        Step(name="poll-snapshot", method="GET", path="/operations/{{_op_t31sSnap}}",
             auth="jwtAccountAdminA", test_script=poll_op_done("_op_t31sSnap", out_id_var="_t31sSnap")),
    ],
    body_id_var="_t31sSnap",
))


# ─────────────────────────────────────────────────────────────────────────────
# revoke03_image — storage.images / storage_image. Needs a source volume; the image
# is REGIONAL (anycast), so it carries regionId rather than zoneId.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(revoke_case(
    case_id="T31-LBLREVOKE-STORAGE-IMAGE-03",
    title="revoke03_image: storage.images label-remove on Update revokes ARM_LABELS grant (Check v_list True→False)",
    fga_type="storage_image", resource_kind="image", base_path=IMAGES,
    create_steps=[
        *create_base_volume("_t31sImgSrcVol", "imgsrc", {}),
        retry_until_authorized(
            Step(name="create-image", method="POST", path=IMAGES,
                 body={"projectId": "{{_t31sProj}}", "regionId": "{{_t31sRegionId}}",
                       "sourceVolumeId": "{{_t31sImgSrcVol}}", "name": "t31s-img-{{runId}}",
                       "labels": {"tier": "treska"}},
                 auth="jwtAccountAdminA",
                 test_script=[*assert_status(200),
                              *save_from_response("j.metadata && j.metadata.imageId", "_t31sImg"),
                              *save_from_response("j.id", "_op_t31sImg")]),
            budget=30, interval_ms=500, retry_on=(403,)),
        Step(name="poll-image", method="GET", path="/operations/{{_op_t31sImg}}",
             auth="jwtAccountAdminA", test_script=poll_op_done("_op_t31sImg", out_id_var="_t31sImg")),
    ],
    body_id_var="_t31sImg",
))
