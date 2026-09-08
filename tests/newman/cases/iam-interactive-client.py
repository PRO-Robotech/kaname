# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set: InternalInteractiveClientService — the interactive-login client (IAM-INT-1, S1).

WHAT THIS RESOURCE IS. The OAuth2 client through which a HUMAN completes an
interactive sign-in ceremony and ends up holding a bearer the edge accepts.
Before it existed every client the identity provider knew had been registered by
one of three iam use-cases, and all three hard-code `client_credentials` /
`jwt-bearer` — so the platform could issue a bearer to a MACHINE and could not
issue one to a HUMAN. This service is the missing creator.

WHERE IT LIVES, AND WHY THE STEPS GO THERE. Registering a client at the provider
decides where an authorization code — a credential — may be delivered, so the
surface is admin-only: an `Internal*` service on the cluster-internal listener,
REST under `/iam/v1/internal/interactiveClients` (ban #6). Every step below is
therefore rewritten onto {{internalBaseUrl}} in its pre-request, through
`gen.py::require_env_url` — the sanctioned harness guard, which ASSERTS the
variable by name before skipping. A missing internalBaseUrl is a broken harness,
not a legal mode: without the assertion, losing the variable would delete this
whole case-set and the suite would still read GREEN.

WHO CALLS. `jwtBootstrap` — the cluster `system_admin` ServiceAccount bearer.
Two independent reasons, and BOTH are needed:

  * the catalog gates all five RPCs on `system_admin` @ `cluster`, which no
    tenant-tier fixture subject holds;
  * `Create` / `Update` / `Delete` additionally declare `required_acr_min = "2"`,
    and the step-up floor is evaluated at the edge BEFORE authz. A machine
    principal (`kaname_principal_type = service_account`) is the ONLY value that
    lifts that floor — there was never a ceremony to have an `acr` from.

  That second reason is also the shape of scenario 12's POSITIVE half, asserted
  in IAM-IC-CR-CRUD-OK: creating the client a human signs in through does NOT
  itself require an interactive sign-in, so the capability has no ring in it.
  Scenario 12's NEGATIVE half — a human at level 1 refused with `401
  insufficient_user_authentication` — is NOT written here, and the reason is a
  measurement rather than a preference: no human principal exists on any stand
  today. `jwtAccountAdminAStepUp` is declared unforgeable by the seed itself
  (tests/authz-fixtures/prodseed_matrix.py), and every other `jwt*` fixture is a
  ServiceAccount token, i.e. acr-exempt — so a probe written now could not tell
  "the floor held" from "the subject was never presented". It belongs to the
  ceremony wave (S2), where a human bearer is produced by the ceremony itself.

Coverage (acceptance sub-phase-IAM-INT-1, §3 / §8). The scenario ID is carried in
the text so the trace runs both ways — §3 states it must appear in the names of
the integration and newman cases that lock each scenario:

  IAM-IC-CR-CRUD-OK            — IAM-INT-1-01 (+ IAM-INT-1-12 positive half):
                                 create → Operation, then the resource's shape
  IAM-IC-CR-CONF-DUP-NAME      — IAM-INT-1-02: the name is taken → ALREADY_EXISTS, and NO second row
  IAM-IC-CR-VAL-REDIRECT-URIS  — IAM-INT-1-03: redirect targets required and https-only (+ positive pair)
  IAM-IC-GT-NEG-ABSENT         — IAM-INT-1-04: well-formed absent id → NOT_FOUND, contract tone (+ positive pair)
  IAM-IC-GT-VAL-MALFORMED-ID   — IAM-INT-1-05: malformed id → INVALID_ARGUMENT, named resource (+ positive pair)
  IAM-IC-UP-VAL-IMMUTABLE-MASK — IAM-INT-1-06: an immutable field in the mask is refused BY NAME (+ positive pair)
  IAM-IC-UP-VAL-UNKNOWN-MASK   — IAM-INT-1-07: an unknown field in the mask is refused; empty mask is a full PATCH
  IAM-IC-DL-IDM-REPEAT         — IAM-INT-1-09: delete is idempotent, and the row stays gone

Not here, and each with its reason rather than a silence:

  IAM-INT-1-08 (provider unreachable → UNAVAILABLE, no row left behind) — §8 assigns it
    "integration + newman happy". Making the provider's administrative hop
    unreachable is not expressible through the edge, so the black-box half of 08
    IS the happy path (IAM-IC-CR-CRUD-OK); the fail-closed half is pinned by the
    integration test, which can substitute a failing provider port.
  IAM-INT-1-11 (not reachable on the outside) — a pair belongs in the EXISTING census,
    `iam-internal-only-check.py`, not in a second one beside it. It is added
    there: a negative on the advertised external listener plus the positive
    control on the internal one.
  the `ErrorInfo.reason` tokens named by IAM-INT-1-04/05 (`RESOURCE_NOT_FOUND`,
    `INVALID_RESOURCE_ID`) — the product emits NO such token anywhere in the
    tree today (measured: zero non-test occurrences outside registry comments).
    Asserting one here would be asserting a capability that does not exist, and
    §8 puts the reason-token half at the unit level anyway. The TONE, which IS
    the contract today, is asserted in full below.
    Note (2026-08-09): two OTHER tokens of the same closed dictionary —
    `PEER_RESOURCE_MISSING` and `PEER_UNAVAILABLE` — ARE emitted now, on the
    peer-validate lane, by five services. That does not change the sentence
    above: it is about these two tokens on the iam direct-read lane, and they
    still have no producer. Read it as "these two", not as "no tokens at all".

Self-contained: every client this file creates carries {{runId}} in its name and
is deleted by the case that made it, so a re-run does not collide with itself on
the cluster-wide UNIQUE(name).
"""

CASES = []

# ---------------------------------------------------------------------------
# Harness plumbing
# ---------------------------------------------------------------------------

IC_PATH = "/iam/v1/internal/interactiveClients"

# A redirect target that satisfies the contract: absolute, https, host-bearing,
# fragment-free. It does not have to resolve — what is under test is which
# targets the platform will AGREE to deliver a code to, not whether anything
# listens there.
GOOD_REDIRECT = "https://api.kacho.local/auth/callback"
GOOD_REDIRECT_2 = "https://api.kacho.local/auth/callback2"


def _internal(path):
    """Point this step at the cluster-internal REST listener.

    `Internal*` RPCs are served ONLY there ({{internalBaseUrl}} = :18081 under the
    runner's port-forward); the public cmux does not route them, by design. The
    guard is gen.py::require_env_url — assert naming the variable, then skip —
    because a lost variable must make the suite RED rather than quietly smaller.
    """
    return require_env_url(
        "internalBaseUrl", path,
        "interactive-login client lifecycle is Internal-only and lives ONLY on "
        "the cluster-internal REST listener (ban #6)")


def _create_step(name, body, test_script, auth="jwtBootstrap"):
    return Step(name=name, method="POST", path=IC_PATH, body=body, auth=auth,
                pre_script=_internal(IC_PATH), test_script=test_script)


def _capture_created(id_var, op_var="opId"):
    """Assertions + captures shared by every successful Create.

    The id is read out of `metadata`, which is the ONLY source before the
    operation finishes — and it is PRE-ALLOCATED, so it arrives even on an
    operation that ends in error. `save_from_response` registers it as
    provisional for exactly that reason; the collection-level post-script drops
    it again the moment an operation is seen `done` WITH an error, so a phantom
    id can never travel on into the following steps.
    """
    return [
        *assert_status(200),
        *assert_operation_envelope(),
        f"pm.test('Create metadata names the interactive client', () => {{",
        "  const j = pm.response.json();",
        "  pm.expect(j.metadata && j.metadata.interactiveClientId, JSON.stringify(j.metadata))",
        "    .to.match(/^ic-[0-9a-hjkmnp-tv-z]{17}$/);",
        "});",
        *save_from_response("j.id", op_var),
        *save_from_response("j.metadata && j.metadata.interactiveClientId", id_var),
    ]


def _get_step(name, id_var, test_script, auth="jwtBootstrap"):
    path = f"{IC_PATH}/{{{{{id_var}}}}}"
    return Step(name=name, method="GET", path=path, auth=auth,
                pre_script=_internal(path), test_script=test_script)


def _delete_step(name, id_var, test_script=None, auth="jwtBootstrap"):
    path = f"{IC_PATH}/{{{{{id_var}}}}}"
    return Step(name=name, method="DELETE", path=path, auth=auth,
                pre_script=_internal(path),
                test_script=test_script if test_script is not None else [
                    *assert_status(200),
                    *assert_operation_envelope(),
                    "pm.test('teardown delete carried no operation error', () => {",
                    "  const j = pm.response.json();",
                    "  pm.expect(j.error, JSON.stringify(j.error || {})).to.be.undefined;",
                    "});",
                ])


def _patch_step(name, id_var, body, test_script, auth="jwtBootstrap"):
    path = f"{IC_PATH}/{{{{{id_var}}}}}"
    return Step(name=name, method="PATCH", path=path, body=body, auth=auth,
                pre_script=_internal(path), test_script=test_script)


def _assert_invalid_argument(*substrings):
    """400 INVALID_ARGUMENT whose message carries each substring.

    The code alone is not the contract: `api-conventions.md` makes the TONE part
    of it, and a refusal that arrives with the right code and the wrong sentence
    is how a caller learns the wrong thing about which field it got wrong.
    """
    out = [
        *assert_status(400),
        *assert_grpc_code(3, "INVALID_ARGUMENT"),
    ]
    for s in substrings:
        out += [
            f"pm.test({repr('message carries ' + s)}, () => {{",
            "  const j = pm.response.json();",
            f"  pm.expect(String(j.message || ''), JSON.stringify(j)).to.include({repr(s)});",
            "});",
        ]
    return out


# ===========================================================================
# IAM-IC-CR-CRUD-OK — scenario 01, and the positive half of scenario 12.
# ===========================================================================

CASES.append(Case(
    id="IAM-IC-CR-CRUD-OK",
    title="Create interactive-login client → Operation; the client is observable with an ic- id, "
          "a provider client id, exactly one https audience and the authorization_code grant",
    classes=["CRUD"],
    priority="P0",
    steps=[
        _create_step(
            name="create-interactive-client",
            body={
                "name": "iaclient-crud-{{runId}}",
                "description": "IAM-INT-1 scenario 01",
                "labels": {"suite": "iam-int-1"},
                "redirectUris": [GOOD_REDIRECT],
            },
            test_script=_capture_created("icCrudId"),
        ),
        poll_operation_until_done(),
        _get_step(
            name="get-interactive-client",
            id_var="icCrudId",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('id is the hyphen-canon ic- form, 20 chars', () => {",
                "  pm.expect(j.id, JSON.stringify(j)).to.match(/^ic-[0-9a-hjkmnp-tv-z]{17}$/);",
                "  pm.expect(String(j.id).length).to.eql(20);",
                "});",
                "pm.test('name round-trips', () => "
                "pm.expect(j.name).to.eql('iaclient-crud-' + pm.environment.get('runId')));",
                # The provider-side handle. Without it nothing can start a ceremony
                # against this client, so an empty value would mean the row exists and
                # the capability does not.
                "pm.test('clientId is assigned by the provider and non-empty', () => "
                "pm.expect(String(j.clientId || ''), JSON.stringify(j)).to.have.length.above(0));",
                # Decision Р2: the audience is stamped by iam from its own config and is
                # NOT a request field. "Exactly one" is the assertion that can be made
                # from outside the cluster — the edge's own domain is not visible to the
                # harness (baseUrl is a forwarded port). That the value is the one the
                # EDGE expects is proved by the edge ACCEPTING a bearer minted through
                # this client, which is scenario 14 and belongs to the ceremony wave.
                "pm.test('exactly one audience, an absolute https URL (stamped by iam, never by the caller)', () => {",
                "  pm.expect(j.audiences, JSON.stringify(j)).to.be.an('array').with.lengthOf(1);",
                "  pm.expect(String(j.audiences[0])).to.match(/^https:\\/\\/[^\\s/]+/);",
                "});",
                "pm.test('grantTypes carry authorization_code', () => {",
                "  pm.expect(j.grantTypes, JSON.stringify(j)).to.be.an('array');",
                "  pm.expect(j.grantTypes).to.include('authorization_code');",
                "});",
                # A public client with proof of possession: no secret is minted, so
                # there is no secret to return or leak (acceptance invariant 6).
                "pm.test('token endpoint auth method is none — a public client has no secret to leak', () => "
                "pm.expect(j.tokenEndpointAuthMethod, JSON.stringify(j)).to.eql('none'));",
                "pm.test('no client secret anywhere in the response', () => "
                "pm.expect(JSON.stringify(j)).to.not.match(/client_secret|clientSecret/));",
                "pm.test('redirectUris round-trip', () => "
                f"pm.expect(j.redirectUris, JSON.stringify(j)).to.eql([{GOOD_REDIRECT!r}]));",
                "pm.test('status ACTIVE', () => pm.expect(j.status, JSON.stringify(j)).to.eql('ACTIVE'));",
                *assert_created_at_seconds(),
            ],
        ),
        _delete_step(name="cleanup-crud-client", id_var="icCrudId"),
    ],
))


# ===========================================================================
# IAM-IC-CR-CONF-DUP-NAME — scenario 02.
#
# The uniqueness is the DATABASE's promise (a UNIQUE constraint), not a
# read-then-write in the service, so the second Create must lose on the write
# rather than on a check it could have raced. The case asserts the refusal AND
# the count: a refusal that still left a row behind would satisfy the first
# assertion alone.
# ===========================================================================

CASES.append(Case(
    id="IAM-IC-CR-CONF-DUP-NAME",
    title="Create a second interactive-login client under a taken name → ALREADY_EXISTS, "
          "and the list still holds exactly one client under that name",
    classes=["CONF", "NEG"],
    priority="P0",
    steps=[
        _create_step(
            name="create-first",
            body={
                "name": "iaclient-dup-{{runId}}",
                "redirectUris": [GOOD_REDIRECT],
            },
            test_script=_capture_created("icDupId"),
        ),
        poll_operation_until_done(),
        _create_step(
            name="create-duplicate-name",
            body={
                "name": "iaclient-dup-{{runId}}",
                "redirectUris": [GOOD_REDIRECT],
            },
            test_script=[
                *assert_status(409),
                *assert_grpc_code(6, "ALREADY_EXISTS"),
                "pm.test('message names the resource and the taken name', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(String(j.message || ''), JSON.stringify(j))",
                "    .to.include('InteractiveClient iaclient-dup-' + pm.environment.get('runId'));",
                "  pm.expect(String(j.message || '')).to.include('already exists');",
                "});",
                # The refusal must not have leaked what the database calls its own
                # constraint — that is schema reconnaissance, not a tenant-facing fact.
                "pm.test('no constraint or SQLSTATE text leaked', () => {",
                "  const m = String(pm.response.json().message || '');",
                "  pm.expect(m).to.not.match(/_uk\\b|_ck\\b|constraint|SQLSTATE|pq:|pgx/i);",
                "});",
            ],
        ),
        Step(
            name="list-by-taken-name",
            method="GET",
            path=IC_PATH + "?filter=name%3Diaclient-dup-{{runId}}",
            auth="jwtBootstrap",
            pre_script=_internal(IC_PATH + "?filter=name%3Diaclient-dup-{{runId}}"),
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('exactly one client carries that name — the refusal left no row', () => {",
                "  const items = j.interactiveClients || [];",
                "  const want = 'iaclient-dup-' + pm.environment.get('runId');",
                "  pm.expect(items.filter(c => c.name === want).length, JSON.stringify(j)).to.eql(1);",
                "});",
                "pm.test('the surviving row is the FIRST one (the winner was not replaced)', () => {",
                "  const items = (j.interactiveClients || [])",
                "    .filter(c => c.name === 'iaclient-dup-' + pm.environment.get('runId'));",
                "  pm.expect(items[0] && items[0].id, JSON.stringify(j))",
                "    .to.eql(pm.environment.get('icDupId'));",
                "});",
            ],
        ),
        _delete_step(name="cleanup-dup-client", id_var="icDupId"),
    ],
))


# ===========================================================================
# IAM-IC-CR-VAL-REDIRECT-URIS — scenario 03.
#
# A redirect target is where the authorization code is delivered, so the two
# negatives are about a credential's destination, not about tidiness. The
# POSITIVE step is not decoration: an assertion that a shape is refused is
# indistinguishable from a create path that refuses everything, and only the pair
# tells them apart.
# ===========================================================================

CASES.append(Case(
    id="IAM-IC-CR-VAL-REDIRECT-URIS",
    title="Create without redirect targets, and with a plaintext one → INVALID_ARGUMENT naming "
          "redirect_uris; the same request with an https target is accepted",
    classes=["VAL", "NEG"],
    priority="P0",
    steps=[
        _create_step(
            name="create-without-redirect-uris",
            body={
                "name": "iaclient-nored-{{runId}}",
                "redirectUris": [],
            },
            test_script=_assert_invalid_argument("redirect_uris: required"),
        ),
        _create_step(
            name="create-with-plaintext-redirect",
            body={
                "name": "iaclient-httpred-{{runId}}",
                "redirectUris": ["http://example.org/cb"],
            },
            test_script=_assert_invalid_argument(
                "redirect_uris", "must be an absolute https:// URL"),
        ),
        _create_step(
            name="create-with-fragment-redirect",
            body={
                "name": "iaclient-fragred-{{runId}}",
                "redirectUris": ["https://api.kacho.local/auth/callback#tok"],
            },
            # A fragment is never sent to the server, so a target carrying one cannot
            # receive the code it was registered for — the platform refuses the target
            # rather than registering one that can only fail at ceremony time.
            test_script=_assert_invalid_argument("redirect_uris", "fragment"),
        ),
        # POSITIVE PAIR — the same call with a legal target is accepted, so the three
        # refusals above are the rule doing its job and not a dead create path.
        _create_step(
            name="create-with-https-redirect",
            body={
                "name": "iaclient-okred-{{runId}}",
                "redirectUris": [GOOD_REDIRECT],
            },
            test_script=_capture_created("icRedId"),
        ),
        poll_operation_until_done(),
        _delete_step(name="cleanup-red-client", id_var="icRedId"),
    ],
))


# ===========================================================================
# IAM-IC-GT-NEG-ABSENT — scenario 04.
#
# `ic-00000000000000000` is WELL-FORMED (20 chars, canon prefix, crockford body)
# and names nothing. This is the direct-read lane — iam's OWN resource — so the
# answer is NOT_FOUND in the contract tone, never a peer-lane code.
# ===========================================================================

_ABSENT_ID = "ic-00000000000000000"

CASES.append(Case(
    id="IAM-IC-GT-NEG-ABSENT",
    title="Get a well-formed but absent interactive-client id → NOT_FOUND in the contract tone; "
          "the same call on a live id answers 200",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="get-absent-well-formed-id",
            method="GET",
            path=f"{IC_PATH}/{_ABSENT_ID}",
            auth="jwtBootstrap",
            pre_script=_internal(f"{IC_PATH}/{_ABSENT_ID}"),
            test_script=[
                *assert_status(404),
                *assert_grpc_code(5, "NOT_FOUND"),
                "pm.test('message is the contract tone, with the id the caller named', () => {",
                "  const j = pm.response.json();",
                f"  pm.expect(String(j.message || ''), JSON.stringify(j))"
                f".to.eql('InteractiveClient {_ABSENT_ID} not found');",
                "});",
            ],
        ),
        # POSITIVE PAIR. Without it the negative above is satisfied just as well by a
        # route that answers 404 to everything, including a client that exists.
        _create_step(
            name="create-live-client",
            body={
                "name": "iaclient-absent-{{runId}}",
                "redirectUris": [GOOD_REDIRECT],
            },
            test_script=_capture_created("icAbsentId"),
        ),
        poll_operation_until_done(),
        _get_step(
            name="get-live-client",
            id_var="icAbsentId",
            test_script=[
                *assert_status(200),
                "pm.test('the live id resolves to its own row', () => "
                "pm.expect(pm.response.json().id).to.eql(pm.environment.get('icAbsentId')));",
            ],
        ),
        _delete_step(name="cleanup-absent-client", id_var="icAbsentId"),
    ],
))


# ===========================================================================
# IAM-IC-GT-VAL-MALFORMED-ID — scenario 05.
#
# A malformed id is refused SYNCHRONOUSLY, by the first statement of the RPC.
# Without that check it would travel to the store and come back NOT_FOUND, which
# asserts the absence of a resource the caller never named.
# ===========================================================================

CASES.append(Case(
    id="IAM-IC-GT-VAL-MALFORMED-ID",
    title="Get with a malformed interactive-client id → INVALID_ARGUMENT naming the resource kind "
          "and echoing the id, never NOT_FOUND; a well-formed id still reaches the store",
    classes=["VAL", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="get-malformed-id-ascii",
            method="GET",
            path=f"{IC_PATH}/not-an-id",
            auth="jwtBootstrap",
            pre_script=_internal(f"{IC_PATH}/not-an-id"),
            test_script=[
                *_assert_invalid_argument("invalid interactive client id 'not-an-id'"),
                # The whole point of the sync format check: this must NOT be the
                # absence answer. Pinning the code it must not be is what keeps a
                # later refactor from moving the check behind the store.
                "pm.test('this is NOT the not-found lane', () => "
                "pm.expect(pm.response.code).to.not.eql(404));",
            ],
        ),
        Step(
            name="get-malformed-id-non-ascii",
            method="GET",
            path=f"{IC_PATH}/%D0%BD%D0%B5-%D0%B8%D0%B4%D0%B5%D0%BD%D1%82%D0%B8%D1%84%D0%B8%D0%BA%D0%B0%D1%82%D0%BE%D1%80",
            auth="jwtBootstrap",
            pre_script=_internal(
                f"{IC_PATH}/%D0%BD%D0%B5-%D0%B8%D0%B4%D0%B5%D0%BD%D1%82%D0%B8%D1%84%D0%B8%D0%BA%D0%B0%D1%82%D0%BE%D1%80"),
            test_script=[
                *_assert_invalid_argument("invalid interactive client id"),
                "pm.test('the refusal echoes the id the caller actually sent', () => "
                "pm.expect(String(pm.response.json().message || '')).to.include('не-идентификатор'));",
            ],
        ),
        # POSITIVE PAIR — a well-formed id is NOT refused by the format check; it
        # reaches the store and gets the store's answer (absence, here). Without this
        # the two negatives would also pass against a route that refuses every id.
        Step(
            name="well-formed-id-passes-the-format-check",
            method="GET",
            path=f"{IC_PATH}/{_ABSENT_ID}",
            auth="jwtBootstrap",
            pre_script=_internal(f"{IC_PATH}/{_ABSENT_ID}"),
            test_script=[
                *assert_status(404),
                *assert_grpc_code(5, "NOT_FOUND"),
                "pm.test('a well-formed id is not answered by the format check', () => "
                "pm.expect(String(pm.response.json().message || '')).to.not.include('invalid interactive client id'));",
            ],
        ),
    ],
))


# ===========================================================================
# IAM-IC-UP-VAL-IMMUTABLE-MASK — scenario 06.
#
# The immutable check must run BEFORE the known-set check. The known-set does not
# contain the immutable fields, so a generic "unknown field" would fire first and
# the caller would never learn that the field exists and simply cannot be
# changed. The two assertions below pin exactly that ordering by pinning the
# sentence.
# ===========================================================================

CASES.append(Case(
    id="IAM-IC-UP-VAL-IMMUTABLE-MASK",
    title="Update naming an output-only field in the mask → INVALID_ARGUMENT that names the field "
          "as immutable (not as unknown); a mask naming redirect_uris is applied",
    classes=["VAL", "NEG"],
    priority="P0",
    steps=[
        _create_step(
            name="create-for-immutable-mask",
            body={
                "name": "iaclient-imm-{{runId}}",
                "redirectUris": [GOOD_REDIRECT],
            },
            test_script=_capture_created("icImmId"),
        ),
        poll_operation_until_done(),
        _patch_step(
            name="update-mask-audiences",
            id_var="icImmId",
            body={"updateMask": "audiences"},
            test_script=_assert_invalid_argument(
                "audiences is immutable after InteractiveClient.Create"),
        ),
        _patch_step(
            name="update-mask-client-id",
            id_var="icImmId",
            body={"updateMask": "clientId"},
            test_script=_assert_invalid_argument(
                "client_id is immutable after InteractiveClient.Create"),
        ),
        # POSITIVE PAIR — a MUTABLE field named in the mask is applied. Without it the
        # two refusals above would be satisfied by an Update that refuses every mask.
        _patch_step(
            name="update-mask-redirect-uris",
            id_var="icImmId",
            body={"updateMask": "redirectUris", "redirectUris": [GOOD_REDIRECT_2]},
            test_script=[
                *assert_status(200),
                *assert_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        _get_step(
            name="get-after-mutable-update",
            id_var="icImmId",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('the mutable field really changed', () => "
                f"pm.expect(j.redirectUris, JSON.stringify(j)).to.eql([{GOOD_REDIRECT_2!r}]));",
                "pm.test('the output-only fields are untouched by the update', () => {",
                "  pm.expect(j.audiences, JSON.stringify(j)).to.be.an('array').with.lengthOf(1);",
                "  pm.expect(String(j.clientId || '')).to.have.length.above(0);",
                "});",
            ],
        ),
        _delete_step(name="cleanup-imm-client", id_var="icImmId"),
    ],
))


# ===========================================================================
# IAM-IC-UP-VAL-UNKNOWN-MASK — scenario 07.
# ===========================================================================

CASES.append(Case(
    id="IAM-IC-UP-VAL-UNKNOWN-MASK",
    title="Update with an unknown field in the mask → INVALID_ARGUMENT against the known-set; "
          "an EMPTY mask is a full-object PATCH over the mutable fields",
    classes=["VAL", "NEG"],
    priority="P1",
    steps=[
        _create_step(
            name="create-for-unknown-mask",
            body={
                "name": "iaclient-unk-{{runId}}",
                "description": "before",
                "labels": {"phase": "before"},
                "redirectUris": [GOOD_REDIRECT],
            },
            test_script=_capture_created("icUnkId"),
        ),
        poll_operation_until_done(),
        _patch_step(
            name="update-mask-unknown-field",
            id_var="icUnkId",
            body={"updateMask": "nonexistentField"},
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                # The known-set check answers through the BadRequest detail, not the
                # message — `pkg/validate` puts the field name in `fieldViolations` and
                # leaves the message generic. Asserting only the code would accept any
                # 400 at all, including the immutable one below.
                *assert_field_violation("update_mask"),
                # The field is named in the SERVICE's spelling, not the caller's: a
                # REST mask arrives camelCase and is normalised to snake_case before
                # the known-set is consulted, so both doors give the same answer.
                # Pinning the normalised form is what keeps that normalisation from
                # being dropped later without anybody noticing.
                "pm.test('the violation names the field that is not in the known set', () => {",
                "  const j = pm.response.json();",
                "  const det = (j.details || []).find(d => (d['@type']||'').includes('BadRequest'));",
                "  const fv = ((det || {}).fieldViolations || []).find(v => v.field === 'update_mask');",
                "  pm.expect(String((fv || {}).description || ''), JSON.stringify(j))",
                "    .to.include('unknown field in update_mask: nonexistent_field');",
                "});",
                # The sentence must NOT be the immutable one: an unknown field and a
                # field that exists-but-cannot-change are different findings, and the
                # caller acts on them differently.
                "pm.test('refused as unknown, not as immutable', () => "
                "pm.expect(String(pm.response.json().message || '')).to.not.include('is immutable after'));",
            ],
        ),
        # POSITIVE PAIR — an EMPTY mask is a legal full-object PATCH, so the refusal
        # above is about the named field and not about masks in general.
        _patch_step(
            name="update-with-empty-mask",
            id_var="icUnkId",
            body={
                "name": "iaclient-unk2-{{runId}}",
                "description": "after",
                "labels": {"phase": "after"},
                "redirectUris": [GOOD_REDIRECT_2],
            },
            test_script=[
                *assert_status(200),
                *assert_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        _get_step(
            name="get-after-full-patch",
            id_var="icUnkId",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('every mutable field of the body was applied', () => {",
                "  pm.expect(j.name, JSON.stringify(j)).to.eql('iaclient-unk2-' + pm.environment.get('runId'));",
                "  pm.expect(j.description).to.eql('after');",
                "  pm.expect(j.labels && j.labels.phase).to.eql('after');",
                f"  pm.expect(j.redirectUris).to.eql([{GOOD_REDIRECT_2!r}]);",
                "});",
                "pm.test('the output-only fields survived the full PATCH', () => {",
                "  pm.expect(j.id, JSON.stringify(j)).to.eql(pm.environment.get('icUnkId'));",
                "  pm.expect(j.grantTypes).to.include('authorization_code');",
                "  pm.expect(j.audiences).to.be.an('array').with.lengthOf(1);",
                "});",
            ],
        ),
        _delete_step(name="cleanup-unk-client", id_var="icUnkId"),
    ],
))


# ===========================================================================
# IAM-IC-DL-IDM-REPEAT — scenario 09.
#
# The caller asked for the client to be gone. On the repeat it already is, and
# the answer must not differ by code — otherwise a retry after a lost response
# reads as a failure and the caller "fixes" a state that is already correct.
# ===========================================================================

CASES.append(Case(
    id="IAM-IC-DL-IDM-REPEAT",
    title="Delete an interactive-login client, then delete it again → same code, and the row "
          "stays gone with the contract not-found tone in between",
    classes=["IDM", "CRUD"],
    priority="P0",
    steps=[
        _create_step(
            name="create-for-delete",
            body={
                "name": "iaclient-del-{{runId}}",
                "redirectUris": [GOOD_REDIRECT],
            },
            test_script=_capture_created("icDelId"),
        ),
        poll_operation_until_done(),
        _delete_step(
            name="delete-first",
            id_var="icDelId",
            test_script=[
                *assert_status(200),
                *assert_operation_envelope(),
                "pm.test('first delete carried no operation error', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.error, JSON.stringify(j.error || {})).to.be.undefined;",
                "});",
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        _get_step(
            name="get-after-first-delete",
            id_var="icDelId",
            test_script=[
                *assert_status(404),
                *assert_grpc_code(5, "NOT_FOUND"),
                "pm.test('gone, in the same tone an id that never existed gets', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(String(j.message || ''), JSON.stringify(j))",
                "    .to.eql('InteractiveClient ' + pm.environment.get('icDelId') + ' not found');",
                "});",
            ],
        ),
        _delete_step(
            name="delete-second",
            id_var="icDelId",
            test_script=[
                # Idempotent: the SECOND delete is not a different outcome.
                *assert_status(200),
                *assert_operation_envelope(),
                "pm.test('the repeat carried no operation error either', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.error, JSON.stringify(j.error || {})).to.be.undefined;",
                "});",
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        _get_step(
            name="get-after-second-delete",
            id_var="icDelId",
            test_script=[
                *assert_status(404),
                *assert_grpc_code(5, "NOT_FOUND"),
                "pm.test('still gone — the repeat did not resurrect a row', () => "
                "pm.expect(String(pm.response.json().message || ''))"
                ".to.eql('InteractiveClient ' + pm.environment.get('icDelId') + ' not found'));",
            ],
        ),
    ],
))
