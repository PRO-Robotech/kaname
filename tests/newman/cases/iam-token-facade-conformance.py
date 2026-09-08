# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set: iam is the SINGLE FACADE to the token-signing provider (#59, Phase C).

WHAT PROPERTY THIS FILE PINS
============================
`.claude/rules/security.md` §«Production-mode обязателен ВЕЗДЕ» п.4 states the rule
this suite exists to keep true:

    iam is the ONLY facade to the signing provider. Clients, services and e2e go to
    iam — signature verification through its JWKS-proxy, token issuance/lifecycle
    through its RPCs, the docker token through its handle, claim enrichment through
    its hook. Dialling the provider directly, around iam, breaks the unification.
    Exactly one direct path stays legitimate: the final standard client-assertion →
    token exchange.

Four lanes and one exception. THREE of them are probed here; the fourth — the
docker lane, IBT-14 — lives in the registry suite
(`services/registry/tests/newman/cases/registry-docker-facade-lane.py`) and is
named here so the rule is not read as three-quarters covered:

    Every lane below dials CORE only — api-gateway, iam, the signing provider —
    and every stand carries those. The docker lane dials the registry DATA PLANE,
    a shard-gated component that `deploy/e2e-shards.json` deploys on the `edge`
    shard alone; the iam suite runs on the shard that deliberately removes it.
    Written here, that lane asked for a service its own runner does not deploy —
    and the shape it took was worse than a red case: the runner opened the
    port-forward unconditionally, a forward to a service that is not there exits,
    and the run was declared INVALID before the first suite started (four shards
    of five, `0/16 collections`, run 31344367968). It now lives with its subject.
    The pairing is asserted, not remembered: `deploy/scripts/assert-shard-coverage.py`
    check 9 requires that a suite dialling a component transport runs only on
    shards declaring that component.

Three lanes and the negatives that make each of them mean something:

  verification  IBT-04 — the Bearer the edge accepts is verified by key material the
                         FACADE serves (its `kid` is published by exactly one of the
                         facade's key-set records), and the edge answers 200 — neither
                         401 nor 403.
                IBT-12 — the MIRROR record is faithful to the provider's public keyset
                         (same kids, same moduli): on that record iam proxies, iam
                         mints nothing.
  issuance      IBT-05 — a credential is issued AND revoked through iam's own RPCs
                         (SAKeyService.Issue/Revoke, UserTokenService.Issue/Revoke),
                         and the acr-exempt service principal is not step-up-challenged.
  enrichment    IBT-13 — the platform principal the edge reports for a machine token
                         is the one the FACADE's claim composition named. Without the
                         composition the credential carries no `kaname_*` claim at all
                         and names nobody on this platform.
  negatives     IBT-06 — the bootstrap mint has no REST door on any api-gateway listener.
                IBT-15 — the provider's own surfaces (admin client registration, token
                         endpoint, JWKS) are not reachable through the platform edge,
                         so a bypass client cannot be provisioned from outside.
                IBT-10 — only a facade-issued RS256 Bearer is accepted: anonymous is
                         401, and an alg-confusion HS256 forgery over the SAME payload,
                         keyed with the public modulus, is 401.

WHERE THE IDS COME FROM, AND WHERE THE ACCEPTANCE TEXT DIVERGES FROM THE TREE
=============================================================================
IBT-04/05/06/10 are the four e2e-conformance scenarios named in the acceptance
(`docs/specs/sub-phase-IAM-BOOTSTRAP-TOKEN-acceptance.md`, Traceability rows
"e2e-conformance (Phase C)") and in issue #59's Scope. IBT-12/13/14/15 are new
numbers in the same family (IBT-01..IBT-11 + IBT-A1..A3 + IBT-T5 are taken): the
acceptance was written about the BOOTSTRAP MINT, so it has no scenario for the
mirror, the hook, the docker handle or the provider surfaces — the four lanes the
facade rule names. Following the tree over the text, three divergences are recorded
here rather than papered over:

  1. IBT-06 predicts `404 Not Found` for the mint on both listeners, "additionally
     blocked by the dispatcher on external". MEASURED on the production-posture stand
     (2026-08-09, all probes authenticated with a facade-issued Bearer): every probe
     of the mint — the grpc-gateway unbound form AND the custom path the acceptance
     spells — answers `403 {"code":7}` with a `PreconditionFailure` violation of type
     `authz.catalog` and an EMPTY `ErrorInfo.metadata.action`, on the public listener
     AND on the internal one, in the same shape as a nonsense path fired at the same
     listener. The reason is structural: the mint carries no `google.api.http` binding
     at all, so there is no route to miss, and the fail-closed authz gate answers
     before the mux is consulted. 404 can never arrive, so a case asserting it could
     never pass — it would be a check that cannot run, reported as one that did.
     What this case asserts instead is what can actually be witnessed: NEVER 2xx, in
     the same REFUSAL SHAPE as a typo, with a positive control proving the same
     listeners DO serve routes (`iam:lookupSubject` answers 200 on internal and a 404
     mux-miss on public). This is the "family B" shape and the honesty note of
     `cases/iam-internal-only-check.py`, applied here for the same reason.
     Not BYTE-identity: the refusal body echoes the requested path back in
     `ErrorInfo.metadata.fqn`, so two different addresses always differ in that one
     field and a byte comparison would be red on a correct platform. The comparison
     is over the normalised shape (http · code · reason · violation type · action);
     see `_REFUSAL_SHAPE_JS` below for why the empty `action` is the load-bearing part.
  2. The advertised external TLS listener (:8443) is NOT probed. Measured on the same
     stand: it requests a client certificate, completes the handshake, opens the HTTP/2
     stream and then answers nothing — with no client cert AND with the gateway's own
     client cert; no request of that kind reaches the gateway's access log. A probe
     that cannot be answered must not be written as a passing check, so the isolation
     statements here are made on the two listeners that do answer. `externalBaseUrl`
     is deliberately NOT referenced by this file.
  3. IBT-05's acceptance text drives `UserTokenService.Issue` for the SEED. This case
     drives it for the CONTRACT: issue → poll → the credential material is returned →
     revoke. It deliberately does NOT exchange the user credential for a Bearer: a
     user client-credentials token carries no `acr` and the user-token client is
     provisioned without the api audience, so that exchange cannot authenticate the
     edge (issue #59, comment of 2026-07-22). That limit is #59's remaining open item
     (the interactive principal), not something this file can assert around.
  4. THE ACCEPTANCE HAS ONE ISSUING LANE; THE PLATFORM NOW HAS TWO. The acceptance
     was written when every Bearer on this platform came from the external provider,
     and its scenario names carry that world: IBT-10 says "RS256", IBT-13 says "the
     FACADE hook". The platform since grew its own signer, and the bootstrap
     credential these cases present is minted by it — asymmetric still, but ES256,
     issued by iam, with the composed claims placed FLAT rather than nested, and with
     the principal itself as `sub`.
     The case IDS ARE KEPT, because they are the acceptance's scenario numbers and
     renaming them would silently break the traceability rows that cite them. What
     changed is what the cases assert: every lane-specific literal (one algorithm,
     one key-set record, one claim placement, `sub` is not the principal) is replaced
     by the property that holds across BOTH lanes, and each case comment says which
     literal it replaced and why the replacement is not a relaxation.
     This is not hypothetical tidiness. Written for one lane, this file went red
     against a correct platform in FIVE of its seven cases at once — two on the key
     material (the algorithm, and the record the kid is looked up in), one on the
     claim form, and two more purely as a cascade, where the step that failed was
     doing exactly the right thing with a value the suite had failed to capture.

WHAT IS DELIBERATELY *NOT* ASSERTED, SO NOBODY LOOKS FOR IT HERE
================================================================
The legitimate direct path — the final OAuth2 `client_assertion` → token exchange at
the provider — is not exercised as a black-box case: signing an ES256 assertion needs
the private key handed out once by Issue, and a Postman script signing JOSE would be a
second implementation of `tests/authz-fixtures/mint_rs256.py` that could drift from it
silently.

It used to be exercised on every run anyway, one level down — the Bearer these cases
carry was produced by exactly that exchange. That is no longer true on a stand where
the bootstrap credential is minted by the platform's own signer, and saying otherwise
would be claiming a lane is covered when nothing here reaches it. What IBT-04 witnesses
is what it says: the credential this suite presents is accepted, and the key that
verifies it is published by the facade — whichever of its records published it.

HOW THE PROBES REACH WHAT THEY PROBE
====================================
Two endpoints of this stand are not the api-gateway and are addressed through their
own base-URL variables, injected by the newman runner (`--env-var`) exactly like
`internalBaseUrl`. A missing variable is a BROKEN HARNESS, never a legal mode:
`require_env_url` fails naming the variable and only then skips, so losing one turns
the suite RED instead of silently deleting a lane.

Both belong to CORE, which is why they are addressable on every shard. The two
addresses of the docker lane (iam's :9096 handle and the registry data plane)
moved out with IBT-14 and are declared by the registry suite instead — the second
of them reaches a shard-gated component, and that is precisely why the lane could
not stay here.

  {{iamJwksBaseUrl}}          iam key-publisher listener (:9097). Cluster-internal,
                              server-TLS with an internal-CA leaf → the steps carry
                              `insecure_tls` (the tunnel's trust chain is not the
                              subject; WHAT IS SERVED is). TWO paths are read on it,
                              one per accepted issuer: the mirror of the provider and
                              the platform's own key-set record. Both are declared as
                              module constants next to `_jwks_step`, and each fetch
                              asserts 200 — a record that moved makes this suite name
                              the address it asked for, never pass having read nothing.
  {{providerPublicBaseUrl}}   the signing provider's PUBLIC endpoint (:4444). Read by
                              the TEST as an oracle for the mirror comparison — this
                              is the one place a direct provider read is legitimate,
                              and it is legitimate because it is the measurement, not
                              a client path.

Idempotence: every fixture this file creates carries `{{runId}}` in its name and is
torn down by the case that made it (SA created → key issued → key revoked → SA
deleted). The one credential issued against a pre-seeded subject (the user token) is
revoked in the same case. Nothing is left behind for the next run to collide with.

Test-first note (strict TDD): these cases are written to FAIL when the facade property
is violated, and that was demonstrated by injection rather than asserted — see
`docs/RESULTS.md` (IBT conformance) for the pair of runs: with a forged HS256 Bearer
substituted for the facade-issued one, IBT-04/IBT-13 go RED naming the lane; with the
real Bearer they are GREEN. Do not weaken an assertion here; a red case means the
property moved.
"""

import json  # only for safely quoting case text into JS string literals

CASES = []


# ---------------------------------------------------------------------------
# Shared JS: base64url ↔ text, and reading the credential the STEP ACTUALLY SENT.
#
# The header is read from `pm.request.headers`, not from the environment variable
# it came from: what this suite is about is the credential presented to the edge.
# Reading the variable instead would still pass if some later change stopped the
# header from being attached at all.
# ---------------------------------------------------------------------------

_JOSE_HELPERS = [
    "function _b64urlToText(s) {",
    "  var t = String(s).replace(/-/g, '+').replace(/_/g, '/');",
    "  while (t.length % 4 !== 0) { t += '='; }",
    "  return CryptoJS.enc.Base64.parse(t).toString(CryptoJS.enc.Utf8);",
    "}",
    "function _b64urlFromText(s) {",
    "  return CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(s))",
    "    .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');",
    "}",
    "function _sentBearer() {",
    "  var h = pm.request.headers.get('Authorization') || '';",
    "  return h.replace(/^Bearer\\s+/i, '');",
    "}",
]


# ---------------------------------------------------------------------------
# THE COMPOSED CLAIMS ARE READ IN BOTH FORMS, AND THE READER IS EXTENDED — NOT
# REPLACED.
#
# The claim SET is produced by ONE declaration for every issuing lane
# (`saClaims` / `userTokenClaims` in the enrichment service), so the NAMES are
# the same everywhere. What differs is WHERE the set is placed in the payload,
# and that is a property of the signer, not of the composition:
#
#   top level            our own issuer signs the composed claims flat, as
#                        ordinary claims of the token (the platform's own
#                        signer merges them into the claim set before iss/sub/
#                        aud/exp are stamped).
#   ext.ext_claims       the external provider nests them; its access token
#                        carries the map under `ext`, and additionally mirrors
#                        it at the top-level key `ext_claims`.
#   ext_claims           that same mirror, read on its own.
#
# BOTH lanes are live on this platform, so this suite reads BOTH. Reading only
# the nested form is how this file went red against a correct platform: the
# lookup resolved to `{}`, the presence assertions failed, and the two ids the
# suite publishes for later steps were never captured — turning one form
# mismatch into a cascade of "precondition not captured" in three other cases.
#
# `_claimForm` exists so a failure can NAME what was searched: "none" is then
# distinguishable from "found, but empty", and a message that says which form
# answered tells the reader which lane produced the credential.
# ---------------------------------------------------------------------------

_CLAIM_READER = [
    "function _claimForm(pl) {",
    "  if (!pl || typeof pl !== 'object') { return 'none'; }",
    "  if (pl.kaname_principal_id) { return 'top-level'; }",
    "  if (pl.ext && pl.ext.ext_claims && pl.ext.ext_claims.kaname_principal_id) { return 'ext.ext_claims'; }",
    "  if (pl.ext_claims && pl.ext_claims.kaname_principal_id) { return 'ext_claims'; }",
    "  return 'none';",
    "}",
    "function _claim(pl, k) {",
    "  if (pl && pl[k] !== undefined && pl[k] !== null && pl[k] !== '') { return pl[k]; }",
    "  const _nested = (pl && pl.ext && pl.ext.ext_claims) || (pl && pl.ext_claims) || {};",
    "  return _nested[k];",
    "}",
]


# ---------------------------------------------------------------------------
# WHAT THE FACADE PUBLISHES, AND WHERE.
#
# The publisher on the facade listener carries one record PER ACCEPTED ISSUER,
# each on its own DECLARED path — the union of the two is "the key material this
# facade serves". Merging them into one document is what the platform refuses to
# do, and for the reason this suite exists to keep true: a key of one issuer
# would then verify a token declaring another.
#
#   `_MIRROR_JWKS_PATH`  the byte-faithful mirror of the external provider's
#                        public keyset. IBT-12 compares it against the provider.
#   `_OWN_JWKS_PATH`     the platform's OWN record — a projection of its keyring.
#                        Declared by the deployment profile
#                        (`config.authn.tokenSigning.keySetPath`) and defaulted
#                        by the service itself; both name this value.
#
# A hard-coded path is a second place about one subject, so it is written so that
# disagreement CANNOT be silent: the step asserts 200 on it. Move the record and
# this suite goes red naming the path it asked for — never green having measured
# a keyset that is not there.
# ---------------------------------------------------------------------------

_MIRROR_JWKS_PATH = "/.well-known/jwks.json"
_OWN_JWKS_PATH = "/.well-known/kaname/jwks.json"


def _jwks_step(name, why, path=_MIRROR_JWKS_PATH, record="mirror",
               kids_var="_facadeKids", by_kid_var="_facadeByKid"):
    """A GET of ONE record of the FACADE's key publisher, at its own listener.

    Every case that needs the served key material fetches it ITSELF instead of
    reading a variable another case left behind: a case whose precondition is
    produced by a different case cannot be run alone (`--folder`), and when it is
    run alone it does not fail — it passes on a stale value or skips. Fetching is
    two hundred bytes; depending on a neighbour is a silent hole.

    WHY THE PER-KEY ASSERTIONS ARE KEY-TYPE-AWARE AND NOT "RSA/RS256"
    ----------------------------------------------------------------
    They used to demand `kty=RSA` + `alg=RS256` of every key of every record.
    That was a statement about ONE issuer's key choice, and it stopped being a
    statement about the FACADE the moment the publisher grew a second record:
    the platform's own keyring is EC/ES256, so the old form was red on correct
    key material.

    What replaces it is not looser — it is a different, stronger axis. Each key
    must declare a key type this platform publishes, its `alg` must be the one
    that key type implies, and the public half must be COMPLETE for that type.
    A symmetric key (`oct`) fails on the first clause: publishing one would mean
    publishing a SIGNING SECRET, which is the same defect the private-member
    check below is written for, arriving by another door. A key whose header
    algorithm and key type disagree fails on the second — that is the shape an
    alg-confusion forgery needs, seen from the publishing side.

    What the mirror record ALSO holds — that it is byte-faithful to the provider,
    keyset for keyset — is asserted by IBT-12, which is the case whose subject
    that is.
    """
    from_gen = require_env_url("iamJwksBaseUrl", path, why)
    return Step(
        name=name,
        method="GET",
        path=path,
        auth="anonymous",
        insecure_tls=True,
        pre_script=from_gen,
        test_script=[
            *assert_answered(name),
            # 200 IS the guard on the declared path. A record that moved answers
            # 404 here and this suite says which address it asked for — the one
            # outcome a hard-coded path must never have is a silent green.
            *assert_status(200),
            *_JOSE_HELPERS,
            f"const _record = {json.dumps(record)};",
            "const _jwks = pm.response.json();",
            "pm.test('facade JWKS [' + _record + ']: keys is a non-empty array', () => {",
            "  pm.expect(_jwks.keys, JSON.stringify(_jwks)).to.be.an('array');",
            "  pm.expect(_jwks.keys.length, 'a facade record serving zero keys verifies nothing')",
            "    .to.be.greaterThan(0);",
            "});",
            # The closed table of what this platform publishes. `oct` is absent by
            # construction, and that absence is the point.
            "const _KTY_ALG = {RSA: 'RS256', EC: 'ES256', OKP: 'EdDSA'};",
            "const _KTY_MEMBERS = {RSA: ['n', 'e'], EC: ['crv', 'x', 'y'], OKP: ['crv', 'x']};",
            "pm.test('facade JWKS [' + _record + ']: every key is ASYMMETRIC verification material — "
            "kty and alg agree, and the public half is complete', () => {",
            "  (_jwks.keys || []).forEach(k => {",
            "    pm.expect(Object.keys(_KTY_ALG), 'kty ' + k.kty + ' of ' + k.kid +",
            "      ' — a facade publishing a symmetric key is publishing a SIGNING SECRET')",
            "      .to.include(k.kty);",
            "    pm.expect(k.alg, 'alg of ' + k.kid + ' against its key type ' + k.kty +",
            "      ' — a key whose header algorithm its material cannot support is the "
            "alg-confusion shape seen from the publishing side').to.eql(_KTY_ALG[k.kty]);",
            "    pm.expect(k.kid, JSON.stringify(k)).to.be.a('string').with.length.greaterThan(0);",
            "    (_KTY_MEMBERS[k.kty] || []).forEach(m => pm.expect(k[m], 'member ' + m + ' of ' + k.kid +",
            "      ' — an incomplete public half verifies nothing').to.be.a('string').with.length.greaterThan(0));",
            "  });",
            "});",
            # Private JWK members on this surface would leak the signing key —
            # of the provider on the mirror record, of the platform on its own.
            "pm.test('facade JWKS [' + _record + ']: carries PUBLIC material only (no d/p/q/dp/dq/qi)', () => {",
            "  const priv = ['d', 'p', 'q', 'dp', 'dq', 'qi'];",
            "  (_jwks.keys || []).forEach(k => {",
            "    priv.forEach(m => pm.expect(k[m], 'private JWK member ' + m +",
            "      ' on the facade: what is published is what VERIFIES, never what signs').to.be.undefined);",
            "  });",
            "});",
            f"pm.environment.set({json.dumps(kids_var)}, "
            "JSON.stringify((_jwks.keys || []).map(k => k.kid)));",
            f"pm.environment.set({json.dumps(by_kid_var)}, "
            "JSON.stringify((_jwks.keys || []).reduce((a, k) => {",
            "  a[k.kid] = {kty: k.kty, alg: k.alg, n: k.n, e: k.e, crv: k.crv, x: k.x, y: k.y};",
            "  return a;", "}, {})));",
        ],
    )


def _own_record_step(name, why):
    """The facade's OWN key-set record — the platform's keyring, published."""
    return _jwks_step(name, why, path=_OWN_JWKS_PATH, record="own",
                      kids_var="_facadeOwnKids", by_kid_var="_facadeOwnByKid")


# Reading the public half of a published key, whatever its type. The RSA
# modulus is the textbook alg-confusion key (CWE-347); for an EC key the
# analogous public material is the point, for OKP the encoded public key. What
# matters for the forgery below is that the HMAC key is material the FACADE
# ITSELF publishes — an invented secret would prove nothing about pinning.
_PUBLIC_MATERIAL_JS = [
    "function _publicMaterial(k) {",
    "  if (!k) { return ''; }",
    "  if (k.n) { return k.n; }",
    "  if (k.x && k.y) { return k.x + k.y; }",
    "  if (k.x) { return k.x; }",
    "  return '';",
    "}",
    "function _facadeKeyByKid(kid) {",
    "  const _m = JSON.parse(pm.environment.get('_facadeByKid') || '{}');",
    "  const _o = JSON.parse(pm.environment.get('_facadeOwnByKid') || '{}');",
    "  return _m[kid] || _o[kid] || null;",
    "}",
]


# ===========================================================================
# IBT-04 — the edge accepts the facade-issued Bearer, and the key that verifies
#          it is served BY THE FACADE.
#
# Two halves, and neither alone is the property. "The edge answered 200" says the
# token was good; it does not say WHOSE key material proved it. "The publisher
# serves keys" says material exists; it does not say anything verifies with it.
# Together they close the verification lane: this exact credential's `kid` is one
# the facade publishes, and the edge admits it.
#
# BOTH RECORDS ARE READ, AND THAT IS THE PROPERTY — NOT A CONVENIENCE.
# The publisher carries one record per accepted issuer. Asking only the mirror
# was the same mistake as reading only the nested claim form: it asserted a
# property of ONE lane while the platform runs two, and it was red on correct key
# material the moment the bootstrap credential moved to the platform's own signer.
# Reading both lets the case say something the single-record form could not: the
# kid is served by EXACTLY ONE record. A kid appearing in both would mean one
# issuer's key verifies another issuer's token — the very thing the publisher
# refuses to do by keeping the records apart.
#
# The algorithm assertion moved from "RS256" to "asymmetric, and the same
# algorithm the publishing record declares for that kid". It is not weaker: the
# literal named one issuer's key choice, while the pair names the two things that
# make a signature mean anything — that the presenter could not have produced it
# with a shared secret, and that the header did not choose an algorithm the key
# material does not support.
# ===========================================================================

CASES.append(Case(
    id="IBT-04-FACADE-VERIFIES-THE-BEARER-THE-EDGE-ACCEPTS",
    title="The facade publishes — in exactly one of its key-set records — the kid that signs the accepted Bearer, under the algorithm its header names; edge answers 200 (not 401, not 403)",
    classes=["SEC", "CONF"],
    priority="P0",
    steps=[
        _jwks_step(
            "facade-jwks",
            "verification lane — the key material the edge verifies with is served by iam",
        ),
        _own_record_step(
            "facade-own-key-set",
            "verification lane — the OWN record of the facade; the platform signs with its own "
            "keyring and publishes the verifying half here",
        ),
        Step(
            name="bearer-accepted-at-edge",
            method="GET",
            path="/iam/v1/me",
            auth="jwtBootstrap",
            test_script=[
                *assert_answered("edge acceptance"),
                *_JOSE_HELPERS,
                # ОДНО утверждение, а не три. Прежде рядом со `status 200` стояли «не
                # 401» и «не 403», объяснённые тем, что голое равенство не называет
                # сломавшуюся полосу. Довод верен, средство — нет: оба отрицания
                # подчинены утверждению о статусе (401 и 403 роняют его первыми) и
                # ОТДЕЛЬНО упасть не могут, а сами по себе проходят на 500 и 503.
                # Полосы теперь названы В СООБЩЕНИИ утверждения — диагностика та же,
                # а мёртвых строк нет. verifies #668.
                "pm.test('edge accepted the presented Bearer: HTTP 200', () => pm.expect(pm.response.code,",
                "  '401 here means the facade-signed token failed verification; 403 on an <exempt> RPC'",
                "  + ' means the principal did not resolve; any other code means the edge never reached'",
                "  + ' this lane. Body: ' + pm.response.text()).to.eql(200));",
                "const _sent = _sentBearer();",
                "pm.test('a Bearer was actually presented (an unauthenticated 200 would prove nothing)',",
                "  () => pm.expect(_sent, 'Authorization header').to.be.a('string').with.length.greaterThan(0));",
                "const _hdr = JSON.parse(_b64urlToText(_sent.split('.')[0]));",
                "pm.test('presented Bearer is signed with an ASYMMETRIC algorithm (never HS*, never none)',",
                "  () => pm.expect(['RS256', 'ES256', 'EdDSA'], JSON.stringify(_hdr) +",
                "    ' — a symmetric or unsigned header means the presenter could have made this'",
                "    + ' credential itself, and \"the edge answered 200\" would say nothing about the facade')",
                "    .to.include(_hdr.alg));",
                "pm.test('presented Bearer names a kid', () => {",
                "  pm.expect(_hdr.kid, JSON.stringify(_hdr)).to.be.a('string').with.length.greaterThan(0);",
                "});",
                # THE SUBSTANCE OF THE LANE.
                "const _mirrorByKid = JSON.parse(pm.environment.get('_facadeByKid') || '{}');",
                "const _ownByKid = JSON.parse(pm.environment.get('_facadeOwnByKid') || '{}');",
                "pm.test('BOTH facade records were captured (an empty keyset is satisfied by nothing)', () => {",
                "  pm.expect(Object.keys(_mirrorByKid).length, 'mirror record, captured by the jwks step')",
                "    .to.be.greaterThan(0);",
                "  pm.expect(Object.keys(_ownByKid).length, 'own record, captured by the jwks step')",
                "    .to.be.greaterThan(0);",
                "});",
                "pm.test('the kid that signed the accepted Bearer is SERVED BY THE FACADE — by EXACTLY "
                "ONE of its records', () => {",
                "  const _serving = [];",
                "  if (_mirrorByKid[_hdr.kid]) { _serving.push('mirror'); }",
                "  if (_ownByKid[_hdr.kid]) { _serving.push('own'); }",
                "  pm.expect(_serving, 'kid ' + _hdr.kid + ' — served by [' + _serving.join(',') + '];'",
                "    + ' none means the edge verifies against key material this facade does not publish,'",
                "    + ' both means the key of one issuer would verify the token of another'",
                "    + ' (records read: mirror=' + Object.keys(_mirrorByKid).length"
                " + ', own=' + Object.keys(_ownByKid).length + ')').to.have.lengthOf(1);",
                "});",
                "pm.test('the publishing record declares the SAME algorithm the Bearer header names', () => {",
                "  const _k = _mirrorByKid[_hdr.kid] || _ownByKid[_hdr.kid];",
                "  pm.expect(_k, 'no facade key published for kid ' + _hdr.kid).to.be.an('object');",
                "  pm.expect(_k.alg, 'header alg ' + _hdr.alg + ' against the alg the facade publishes for '",
                "    + _hdr.kid + ' — a header naming an algorithm the key material does not support is'",
                "    + ' the alg-confusion shape').to.eql(_hdr.alg);",
                "});",
                "const _pl = JSON.parse(_b64urlToText(_sent.split('.')[1]));",
                "pm.test('presented Bearer carries an issuer and an audience', () => {",
                "  pm.expect(_pl.iss, JSON.stringify(_pl)).to.be.a('string').with.length.greaterThan(0);",
                "  const aud = [].concat(_pl.aud || []);",
                "  pm.expect(aud.length, 'aud claim: an audience-less token is not edge-addressed')",
                "    .to.be.greaterThan(0);",
                "});",
            ],
        ),
    ],
))


# ===========================================================================
# IBT-12 — the facade's JWKS is a MIRROR of the provider's, not a second keyset.
#
# Why this is a separate case and not an extra assertion on IBT-04: IBT-04 holds
# just as well if iam started signing tokens with its own keys and serving its own
# JWKS — every kid would match, the edge would accept, and the platform would have
# quietly grown a second issuer. What forbids that is the mirror property, and the
# only way to witness it black-box is to read both and compare.
#
# The BOTH-NON-EMPTY assertion is not decoration: two empty keysets compare equal,
# and an "equal" that is satisfied by nothing is the classic vacuous negative.
# ===========================================================================

CASES.append(Case(
    id="IBT-12-FACADE-JWKS-MIRRORS-THE-PROVIDER",
    title="iam's JWKS-proxy is byte-faithful to the provider's public JWKS (same kids, same moduli) — iam proxies, never mints",
    classes=["SEC", "CONF"],
    priority="P0",
    steps=[
        _jwks_step(
            "facade-jwks-for-mirror",
            "mirror comparison — the facade side of the pair",
        ),
        Step(
            name="provider-jwks",
            method="GET",
            path="/.well-known/jwks.json",
            auth="anonymous",
            pre_script=require_env_url(
                "providerPublicBaseUrl", "/.well-known/jwks.json",
                "mirror comparison — the provider side of the pair, read by the TEST as an "
                "oracle (this is the measurement, not a client path)"),
            test_script=[
                *assert_answered("provider JWKS"),
                *assert_status(200),
                "const _up = pm.response.json();",
                "const _mirror = JSON.parse(pm.environment.get('_facadeByKid') || '{}');",
                "pm.test('both keysets are non-empty (an equality satisfied by nothing is not an equality)', () => {",
                "  pm.expect((_up.keys || []).length, 'provider keys').to.be.greaterThan(0);",
                "  pm.expect(Object.keys(_mirror).length, 'facade keys').to.be.greaterThan(0);",
                "});",
                "const _upBy = (_up.keys || []).reduce((a, k) => { a[k.kid] = k; return a; }, {});",
                "pm.test('kid sets are identical in BOTH directions', () => {",
                "  const up = Object.keys(_upBy).sort();",
                "  const mi = Object.keys(_mirror).sort();",
                "  pm.expect(mi, 'facade kids vs provider kids: a kid the facade serves and the '",
                "    + 'provider does not is a key iam minted itself').to.eql(up);",
                "});",
                "pm.test('every mirrored key is the provider key value-for-value (kty/alg/n/e)', () => {",
                "  Object.keys(_mirror).forEach(kid => {",
                "    const u = _upBy[kid];",
                "    pm.expect(u, 'provider has no key ' + kid).to.be.an('object');",
                "    pm.expect(_mirror[kid].kty, 'kty of ' + kid).to.eql(u.kty);",
                "    pm.expect(_mirror[kid].alg, 'alg of ' + kid).to.eql(u.alg);",
                "    pm.expect(_mirror[kid].n, 'modulus of ' + kid + ' differs — the facade is not '",
                "      + 'mirroring this key, it is publishing another one').to.eql(u.n);",
                "    pm.expect(_mirror[kid].e, 'exponent of ' + kid).to.eql(u.e);",
                "  });",
                "});",
            ],
        ),
        # WHY THE NARROWNESS OF THE PROXY IS ASSERTED IN *THIS* CASE.
        #
        # A comparison of two fetches is evidence only if the two are different
        # things. Point `iamJwksBaseUrl` at the provider by mistake and every
        # assertion above still passes — the provider is trivially a faithful mirror
        # of itself — so the mirror lane would report GREEN having measured nothing.
        # These two steps make that mis-set observable: the facade JWKS listener
        # serves ITS ONE PATH and 404s everything else, while the provider serves its
        # discovery document and its token endpoint at the same origin (measured
        # 2026-08-09: facade 404/404, provider 200 on discovery).
        #
        # It is not merely a guard against a harness mistake. It is a property worth
        # holding on its own: the mirror is a narrow, single-purpose proxy, not a
        # general passthrough that would park the provider's whole surface behind an
        # iam address.
        Step(
            name="facade-jwks-listener-is-a-narrow-proxy-discovery",
            method="GET",
            path="/.well-known/openid-configuration",
            auth="anonymous",
            insecure_tls=True,
            pre_script=require_env_url(
                "iamJwksBaseUrl", "/.well-known/openid-configuration",
                "mirror lane — the facade listener must NOT be a general provider passthrough, "
                "and this is what tells the facade apart from the provider"),
            test_script=[
                *assert_answered("facade listener, provider discovery document"),
                "pm.test('the facade JWKS listener does NOT serve the provider discovery document "
                "(if it did, this variable points at the provider and the comparison above "
                "compared the provider with itself)',",
                "  () => pm.expect(pm.response.code, pm.response.text()).to.eql(404));",
            ],
        ),
        Step(
            name="facade-jwks-listener-is-a-narrow-proxy-token-endpoint",
            method="POST",
            path="/oauth2/token",
            auth="anonymous",
            insecure_tls=True,
            pre_script=require_env_url(
                "iamJwksBaseUrl", "/oauth2/token",
                "mirror lane — the facade listener must not expose the provider token endpoint"),
            test_script=[
                *assert_answered("facade listener, provider token endpoint"),
                "pm.test('the facade JWKS listener does NOT expose the provider token endpoint',",
                "  () => pm.expect(pm.response.code, pm.response.text()).to.eql(404));",
            ],
        ),
    ],
))


# ===========================================================================
# IBT-05 — issuance AND lifecycle go through iam's own RPCs.
#
# The acceptance's IBT-05 is about the seed reaching 200 instead of a step-up 401.
# That half is here (the service principal is acr-exempt, so an `required_acr_min=2`
# RPC must not challenge it). The other half is the word "lifecycle" in the rule:
# a facade that can only MINT is not the lifecycle owner. So each credential issued
# here is also REVOKED here — which doubles as the case's own teardown.
#
# The ServiceAccount is created by this case and deleted by it. The user is NOT:
# a freshly-upserted user acquires a personal account and bindings, and
# `UserService.Delete` then refuses it ("has active access bindings"), so creating
# one would leak a tenant per run. The user token is issued against the seeded
# subject and revoked, which leaves the tree exactly as it was found.
# ===========================================================================

_ACCOUNT_FROM_CALLER = [
    # The account and the caller's own principal id are read out of the presented
    # Bearer's composed claims rather than an environment variable: they are
    # properties OF THE CREDENTIAL under test, and taking them from anywhere else
    # would let the case pass while describing a different principal.
    #
    # Read in BOTH forms (`_CLAIM_READER`). A reader that knows only the nested
    # one resolves to `{}` on a credential of the platform's own lane, publishes
    # nothing, and turns a form mismatch into "precondition not captured" three
    # cases later — where the step that fails is the one doing exactly what it
    # should when its subject does not exist.
    *_CLAIM_READER,
    "const _b = (pm.environment.get('jwtBootstrap') || '').split('.');",
    "if (_b.length === 3) {",
    "  try {",
    "    var _t = _b[1].replace(/-/g, '+').replace(/_/g, '/');",
    "    while (_t.length % 4 !== 0) { _t += '='; }",
    "    const _c = JSON.parse(CryptoJS.enc.Base64.parse(_t).toString(CryptoJS.enc.Utf8));",
    "    pm.environment.set('ibtCallerClaimForm', _claimForm(_c));",
    "    const _acct = _claim(_c, 'kaname_account_id');",
    "    const _pid = _claim(_c, 'kaname_principal_id');",
    "    const _ptype = _claim(_c, 'kaname_principal_type');",
    "    if (_acct) pm.environment.set('ibtAccountId', _acct);",
    "    if (_pid) pm.environment.set('ibtCallerPrincipalId', _pid);",
    "    if (_ptype) pm.environment.set('ibtCallerPrincipalType', _ptype);",
    "  } catch (e) { /* asserted in the test script, not swallowed */ }",
    "}",
]

CASES.append(Case(
    id="IBT-05-CREDENTIAL-LIFECYCLE-THROUGH-FACADE-RPCS",
    title="SAKeyService.Issue/Revoke and UserTokenService.Issue/Revoke serve the acr-exempt service principal with 200 + credential material (no step-up challenge)",
    classes=["SEC", "CONF", "CRUD"],
    priority="P0",
    steps=[
        Step(
            name="create-conformance-sa",
            method="POST",
            path="/iam/v1/serviceAccounts",
            auth="jwtBootstrap",
            pre_script=_ACCOUNT_FROM_CALLER,
            body={"accountId": "{{ibtAccountId}}", "name": "ibt05-{{runId}}",
                  "description": "IBT-05 facade-conformance fixture"},
            test_script=[
                *assert_answered("create SA fixture"),
                # THE PRODUCER ASSERTS EVERYTHING IT PUBLISHES. Two of these three
                # values are read by IBT-06, and when only the account was asserted
                # the other two went missing silently — the failure then surfaced in
                # a different case, on a step that was behaving correctly for an
                # input nobody had captured.
                "pm.test('the caller Bearer carried the composed claims this suite reads', () => {",
                "  const _form = pm.environment.get('ibtCallerClaimForm') || 'none';",
                "  pm.expect(_form, 'no kaname_* claims in ANY of the three declared forms"
                " (top-level / ext.ext_claims / ext_claims)').to.not.eql('none');",
                "  pm.expect(pm.environment.get('ibtAccountId'), 'kaname_account_id claim (form: ' + _form + ')')",
                "    .to.be.a('string').with.length.greaterThan(0);",
                "  pm.expect(pm.environment.get('ibtCallerPrincipalId'),",
                "    'kaname_principal_id claim (form: ' + _form + ') — read by IBT-06')",
                "    .to.be.a('string').with.length.greaterThan(0);",
                "  pm.expect(pm.environment.get('ibtCallerPrincipalType'),",
                "    'kaname_principal_type claim (form: ' + _form + ')')",
                "    .to.be.a('string').with.length.greaterThan(0);",
                "});",
                *assert_status(200),
                *assert_operation_envelope(),
                *save_from_response("pm.response.json().id", "opId"),
                *save_from_response("pm.response.json().metadata.serviceAccountId", "ibtSvaId"),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="issue-sa-key",
            method="POST",
            path="/iam/v1/serviceAccounts/{{ibtSvaId}}/keys",
            auth="jwtBootstrap",
            body={"serviceAccountId": "{{ibtSvaId}}",
                  "description": "IBT-05 facade-conformance {{runId}}",
                  "audience": ["https://api.kacho.cloud"]},
            test_script=[
                *assert_answered("SAKeyService.Issue"),
                # `SAKeyService.Issue` carries required_acr_min="2". A SERVICE principal
                # is acr-exempt (O-1); a 401 here would mean the exemption is gone and
                # every non-interactive seed on this platform stops working.
                "pm.test('acr-gated Issue does NOT step-up-challenge the service principal (401 would break every machine seed)',",
                "  () => pm.expect(pm.response.code, pm.response.text()).to.not.eql(401));",
                *assert_status(200),
                *assert_operation_envelope(),
                *save_from_response("pm.response.json().id", "opId"),
                *save_from_response("pm.response.json().metadata.keyId", "ibtSaKeyId"),
            ],
        ),
        Step(
            name="poll-issue-sa-key",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtBootstrap",
            op_var="opId",
            pre_script=[
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) {",
                "  pm.environment.set('_pollCount', '0');",
                "  pm.environment.set('_pollStarted', pm.info.requestName);",
                "}",
            ],
            test_script=[
                "pm.test('poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                f"if (!j.done && pc < {POLL_CAP}) {{",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                # A REAL inter-poll wait. newman runs the test script synchronously and
                # fires setNextRequest before any setTimeout callback, so a busy-wait is
                # the only way to actually space polls out; without it a 50-iteration
                # loop covers a fraction of a second and "the poller gave up" would mean
                # "the probe never waited".
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "pm.test('Issue operation reached done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                # OUTCOME BEFORE MATERIAL. The operation carries a pre-allocated keyId in
                # `metadata` even when it ends in error; reading the response without
                # asserting the outcome first publishes a credential id for a credential
                # that does not exist, and the revoke below would then fail somewhere else.
                "pm.test('Issue operation SUCCEEDED (outcome asserted before any id is used)',",
                "  () => pm.expect(j.error && JSON.stringify(j.error), 'operation.error').to.eql(undefined));",
                "const r = (j.response || {});",
                "pm.test('facade returned the client identity for the issued key',",
                "  () => pm.expect(r.clientId, JSON.stringify(r)).to.be.a('string').with.length.greaterThan(0));",
                "pm.test('facade returned the private key ONCE, in PEM', () => {",
                "  pm.expect(r.privateKeyPem, 'privateKeyPem').to.be.a('string');",
                "  pm.expect((r.privateKeyPem || '').indexOf('-----BEGIN'), 'PEM preamble').to.eql(0);",
                "});",
                "pm.test('issued key is ES256 and names the kid the assertion must carry', () => {",
                "  pm.expect(r.algorithm, JSON.stringify(r)).to.eql('ES256');",
                "  pm.expect(r.keyId, 'keyId').to.be.a('string').with.length.greaterThan(0);",
                "});",
                "pm.test('the issued credential is bound to the requested api audience', () => {",
                "  pm.expect([].concat(r.audiences || []), JSON.stringify(r))",
                "    .to.include('https://api.kacho.cloud');",
                "});",
            ],
        ),
        Step(
            name="revoke-sa-key",
            method="DELETE",
            path="/iam/v1/serviceAccounts/{{ibtSvaId}}/keys/{{ibtSaKeyId}}",
            auth="jwtBootstrap",
            test_script=[
                *assert_answered("SAKeyService.Revoke"),
                "pm.test('acr-gated Revoke does NOT step-up-challenge the service principal',",
                "  () => pm.expect(pm.response.code, pm.response.text()).to.not.eql(401));",
                *assert_status(200),
                *assert_operation_envelope(),
                *save_from_response("pm.response.json().id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="issue-user-token",
            method="POST",
            path="/iam/v1/users/{{userAAAId}}/tokens",
            auth="jwtBootstrap",
            body={"userId": "{{userAAAId}}",
                  "description": "IBT-05 facade-conformance {{runId}}",
                  "createdByUserId": "{{userAAAId}}",
                  "name": "ibt05-{{runId}}"},
            test_script=[
                *assert_answered("UserTokenService.Issue"),
                "pm.test('acr-gated user-token Issue does NOT step-up-challenge the service principal',",
                "  () => pm.expect(pm.response.code, pm.response.text()).to.not.eql(401));",
                *assert_status(200),
                *assert_operation_envelope(),
                *save_from_response("pm.response.json().id", "opId"),
                *save_from_response("pm.response.json().metadata.keyId", "ibtUserTokenId"),
            ],
        ),
        Step(
            name="poll-issue-user-token",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtBootstrap",
            op_var="opId",
            pre_script=[
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) {",
                "  pm.environment.set('_pollCount', '0');",
                "  pm.environment.set('_pollStarted', pm.info.requestName);",
                "}",
            ],
            test_script=[
                "pm.test('poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                f"if (!j.done && pc < {POLL_CAP}) {{",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "pm.test('user-token Issue operation reached done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "pm.test('user-token Issue SUCCEEDED (outcome asserted before any id is used)',",
                "  () => pm.expect(j.error && JSON.stringify(j.error), 'operation.error').to.eql(undefined));",
                "const r = (j.response || {});",
                "pm.test('facade returned the user credential material (clientId + PEM + ES256 kid)', () => {",
                "  pm.expect(r.clientId, JSON.stringify(r)).to.be.a('string').with.length.greaterThan(0);",
                "  pm.expect((r.privateKeyPem || '').indexOf('-----BEGIN'), 'PEM preamble').to.eql(0);",
                "  pm.expect(r.algorithm, JSON.stringify(r)).to.eql('ES256');",
                "  pm.expect(r.keyId, 'keyId').to.be.a('string').with.length.greaterThan(0);",
                "});",
            ],
        ),
        Step(
            name="revoke-user-token",
            method="DELETE",
            path="/iam/v1/users/{{userAAAId}}/tokens/{{ibtUserTokenId}}",
            auth="jwtBootstrap",
            test_script=[
                *assert_answered("UserTokenService.Revoke"),
                *assert_status(200),
                *assert_operation_envelope(),
                *save_from_response("pm.response.json().id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="delete-conformance-sa",
            method="DELETE",
            path="/iam/v1/serviceAccounts/{{ibtSvaId}}",
            auth="jwtBootstrap",
            test_script=[
                *assert_answered("teardown: delete the conformance SA"),
                *assert_status(200),
                *save_from_response("pm.response.json().id", "opId"),
            ],
        ),
        poll_operation_until_done(),
    ],
))


# ===========================================================================
# IBT-13 — the principal the platform reports is the one the FACADE's composition
#          named.
#
# WHAT THE COMPOSITION IS, AND WHY THE OLD NAME NO LONGER DESCRIBES IT.
# The claim set is assembled by ONE declaration in iam for every issuing lane.
# On the external provider's lane iam is reached through the token hook, and the
# provider nests the result in the token. On the platform's own lane there is no
# call back at all: the same declaration composes the set, and iam's own signer
# puts it in the token it signs. The mechanism named in this case's id — "the
# FACADE hook" — is therefore one lane's transport, not the property. The
# property is that a credential names a Kachō principal only because the FACADE
# composed the claims that say so. The id is kept because it is the acceptance's
# scenario number (see divergence 4 in the module docstring); the title and this
# comment say what is actually asserted.
#
# WHAT REPLACED THE ANTI-TAUTOLOGY CONTROL, AND WHY IT IS NOT A RELAXATION.
# The case used to require `sub !== kaname_principal_id`, reasoning that if they
# were equal the case could not tell an enriched token from a bare one. That
# control was a property of the provider's lane, where `sub` is an OAuth client
# id. The platform's own signer makes the principal the subject BY CONSTRUCTION,
# so on that lane the old control is false about a correct world — and a control
# that must be false to pass is not a control.
#
# The replacement asserts the same thing the old one was reaching for, on an
# axis both lanes share: the composition put values in this token that the
# SUBJECT cannot supply. `kaname_sa_key_id` is the id of the credential-registry
# row; `kaname_account_id` is the owning account. A bare client-credentials token
# — the artefact of the exchange without the composition — carries neither, and
# neither is a restatement of `sub`. The case asserts they are present, and that
# `kaname_sa_key_id` differs from BOTH `sub` and `kaname_principal_id`: a
# composition that merely echoed the subject back would fail there.
#
# WHAT IS NO LONGER WITNESSABLE HERE, SAID PLAINLY SO "GREEN" IS NOT READ WIDER.
# On the platform's own lane `sub` and `kaname_principal_id` are the same string,
# so no black-box case can prove the platform resolved the caller FROM THE CLAIMS
# rather than from `sub` — the two inputs are indistinguishable in the answer.
# That half is held one level down, by the probes over the claim composer and the
# signer in the service itself. What this case still witnesses end-to-end: the
# credential carries the full composed set, the set is internally consistent, and
# the platform reports exactly the principal that set names.
# ===========================================================================

CASES.append(Case(
    id="IBT-13-PRINCIPAL-CLAIMS-STAMPED-BY-THE-FACADE-HOOK",
    title="The machine Bearer carries the facade-composed kaname_* claims — in either lane's form — and they resolve to exactly the subject the platform reports for the caller",
    classes=["SEC", "CONF"],
    priority="P0",
    steps=[
        Step(
            name="whoami-with-facade-token",
            method="GET",
            path="/iam/v1/me",
            auth="jwtBootstrap",
            test_script=[
                *assert_answered("WhoAmI with the facade-issued token"),
                *assert_status(200),
                *_JOSE_HELPERS,
                *_CLAIM_READER,
                "const _sent = _sentBearer();",
                "const _pl = JSON.parse(_b64urlToText(_sent.split('.')[1]));",
                "const _form = _claimForm(_pl);",
                "pm.test('the presented token carries the facade-composed platform claims', () => {",
                "  pm.expect(_form, 'no kaname_* claim in ANY of the three declared forms"
                " (top-level / ext.ext_claims / ext_claims) — this credential was signed without the'",
                "    + ' facade composition, and on its own it names nobody on this platform')",
                "    .to.not.eql('none');",
                "  pm.expect(_claim(_pl, 'kaname_principal_type'), 'kaname_principal_type (form: ' + _form + ')')",
                "    .to.be.a('string').with.length.greaterThan(0);",
                "  pm.expect(_claim(_pl, 'kaname_principal_id'), 'kaname_principal_id (form: ' + _form + ')')",
                "    .to.be.a('string').with.length.greaterThan(0);",
                "});",
                # THE ANTI-TAUTOLOGY CONTROL. Read the case comment before touching it:
                # it replaced `sub !== kaname_principal_id`, which the platform's own
                # signer makes false by construction, with the axis both lanes share.
                "pm.test('the composition carried values the SUBJECT cannot supply — this is what "
                "tells an enriched credential from a bare one', () => {",
                "  pm.expect(_pl.sub, JSON.stringify(_pl)).to.be.a('string').with.length.greaterThan(0);",
                "  const _keyId = _claim(_pl, 'kaname_sa_key_id');",
                "  const _acct = _claim(_pl, 'kaname_account_id');",
                "  const _pid = _claim(_pl, 'kaname_principal_id');",
                "  pm.expect(_keyId, 'kaname_sa_key_id (form: ' + _form + ') — the credential-registry"
                " row this token was issued against; a bare client-credentials token has no such claim')",
                "    .to.be.a('string').with.length.greaterThan(0);",
                "  pm.expect(_acct, 'kaname_account_id (form: ' + _form + ') — the owning account;"
                " it is resolved by the composition, not carried by the exchange')",
                "    .to.be.a('string').with.length.greaterThan(0);",
                "  pm.expect(_keyId, 'kaname_sa_key_id equals kaname_principal_id — the composition"
                " restated the principal and added nothing, so this case could no longer tell an"
                " enriched credential from a bare one').to.not.eql(_pid);",
                "  pm.expect(_keyId, 'kaname_sa_key_id equals sub — same reason, on the other side:"
                " the composition would be a restatement of the subject').to.not.eql(_pl.sub);",
                "});",
                "const _j = pm.response.json();",
                "pm.test('the platform reports EXACTLY the principal the composition names', () => {",
                "  const want = _claim(_pl, 'kaname_principal_type') + ':' + _claim(_pl, 'kaname_principal_id');",
                "  pm.expect(_j.subject, JSON.stringify(_j) + ' vs claims ' + want).to.eql(want);",
                "});",
                "pm.test('the reported subject is a platform id, not an OAuth client id', () => {",
                "  pm.expect(_j.subject, JSON.stringify(_j)).to.match(/^(user|service_account):(usr|sva)[a-z0-9-]+$/);",
                "});",
                *assert_created_at_seconds("pm.response.json().checkedAt"),
            ],
        ),
    ],
))


# ===========================================================================
# IBT-06 — the bootstrap mint has no REST door on any api-gateway listener.
#
# READ THE DIVERGENCE NOTE IN THE MODULE DOCSTRING BEFORE CHANGING THIS CASE.
# The acceptance predicts 404; the stand answers 403 `authz.catalog`, identically
# on both listeners and identically to a nonsense path, because the RPC carries no
# HTTP binding at all — there is no route to miss, and the fail-closed authz gate
# answers before the mux is consulted. A "404 on external" assertion here could
# never pass; asserting it would be a check that cannot run, reported as one that did.
#
# So the case asserts what is witnessable, and carries the controls that give it
# meaning:
#   * the internal listener DOES serve Internal* RPCs           (positive control)
#   * the public listener DOES answer 404 for an Internal* route it lacks
#     (so a 404 is a shape this suite could observe if it ever arrived)
#   * the mint answers NEVER 2xx on both, indistinguishably from nonsense
# The credential used is a valid system-admin Bearer — the strong form of the
# claim: not "a stranger gets nothing" but "the most privileged caller on the
# platform still has no REST door to the mint".
# ===========================================================================

_MINT_UNBOUND = "/kaname.cloud.iam.v1.InternalBootstrapTokenService/MintBootstrapToken"
_MINT_ACCEPTANCE_PATH = "/iam/v1/internal/bootstrapToken:mint"


# NORMALISED REFUSAL SHAPE — why not a byte comparison against the control.
#
# The first draft of this helper compared `code + response body` against the
# nonsense control and required them equal. Measured on the stand, that can never
# hold: the refusal body echoes the requested path back in `ErrorInfo.metadata.fqn`,
# so two different addresses always differ in exactly that field and an assertion
# of byte-identity would be red on a correct platform. What IS comparable — and what
# actually carries the meaning — is the SHAPE of the refusal:
#
#   code 7 · reason AUTHZ_DENIED · violation type authz.catalog · EMPTY action
#
# The empty `action` is the discriminator the rest of this suite already relies on
# (`gen.py::assert_scoped_authz_deny`): the gateway fills `action` from the
# permission-catalog entry of the resolved method, so an empty one means there was
# no entry — the address is not a gated RPC, it is nothing. A real, routed,
# catalogued endpoint refusing this caller would carry a NON-empty action and this
# assertion would go red, which is precisely the regression worth locking.
_REFUSAL_SHAPE_JS = [
    "function _refusalShape(resp) {",
    "  var j = null; try { j = resp.json(); } catch (e) { return String(resp.code) + ' non-json'; }",
    "  var info = ((j && j.details) || []).find(d => (d['@type'] || '').includes('ErrorInfo')) || {};",
    "  var pf = ((j && j.details) || []).find(d => (d['@type'] || '').includes('PreconditionFailure')) || {};",
    "  var v = ((pf.violations || [])[0] || {});",
    "  return JSON.stringify({",
    "    http: resp.code, code: j && j.code, reason: info.reason,",
    "    violation: v.type, action: (info.metadata || {}).action",
    "  });",
    "}",
]


def _never_2xx(label, control_var=None):
    out = [
        *assert_answered(label),
        *_REFUSAL_SHAPE_JS,
        f"pm.test({json.dumps(label + ': NEVER 2xx — there is no door here')}, () => {{",
        "  pm.expect(pm.response.code, pm.response.text()).to.not.be.within(200, 299);",
        "});",
    ]
    if control_var:
        out += [
            f"pm.test({json.dumps(label + ': refused with the SAME SHAPE as a nonsense path on the same listener — i.e. the address is not a routed endpoint at all')}, () => {{",
            f"  const ctl = pm.environment.get('{control_var}');",
            "  pm.expect(ctl, 'control shape not captured — the control step did not run')"
            ".to.be.a('string');",
            "  pm.expect(_refusalShape(pm.response),",
            "    'this address answers DIFFERENTLY from a typo on the same listener: something '",
            "    + 'is routed here. Body: ' + pm.response.text()).to.eql(ctl);",
            "});",
            f"pm.test({json.dumps(label + ': the refusal carries an EMPTY action — no permission-catalog entry, so no such RPC is exposed')}, () => {{",
            "  const j = pm.response.json();",
            "  const info = (j.details || []).find(d => (d['@type'] || '').includes('ErrorInfo'));",
            "  pm.expect(info, JSON.stringify(j)).to.be.an('object');",
            "  pm.expect((info.metadata || {}).action, 'a NON-empty action means this path resolved "
            "to a catalogued RPC — it is exposed. ' + JSON.stringify(j)).to.eql('');",
            "});",
        ]
    return out


CASES.append(Case(
    id="IBT-06-BOOTSTRAP-MINT-HAS-NO-REST-DOOR",
    title="MintBootstrapToken is unreachable over REST on both api-gateway listeners, for a system-admin caller, indistinguishably from a nonsense path",
    classes=["SEC", "NEG", "CONF"],
    priority="P0",
    steps=[
        # ---- controls first: the listeners answer, and they DO route Internal* ----
        Step(
            name="control-internal-listener-serves-internal-rpcs",
            method="POST",
            path="/iam/v1/internal/iam:lookupSubject",
            auth="jwtBootstrap",
            pre_script=require_env_url(
                "internalBaseUrl", "/iam/v1/internal/iam:lookupSubject",
                "IBT-06 positive control — the internal listener must be shown to serve "
                "Internal* routes, else the absence of the mint says nothing") + _ACCOUNT_FROM_CALLER,
            body={"id": "{{ibtCallerPrincipalId}}"},
            test_script=[
                *assert_answered("internal listener control"),
                "pm.test('the internal listener SERVES Internal* RPCs (200 for a subject that exists)',",
                "  () => pm.expect(pm.response.code, pm.response.text()).to.eql(200));",
                "pm.test('and it answered about the caller principal, not something else', () => {",
                "  const j = pm.response.json();",
                "  const who = (j.serviceAccount && j.serviceAccount.id) || (j.user && j.user.id) || '';",
                "  pm.expect(who, JSON.stringify(j)).to.eql(pm.environment.get('ibtCallerPrincipalId'));",
                "});",
            ],
        ),
        Step(
            name="control-public-listener-404s-an-internal-route-it-lacks",
            method="POST",
            path="/iam/v1/internal/iam:lookupSubject",
            auth="jwtBootstrap",
            body={"id": "{{ibtCallerPrincipalId}}"},
            test_script=[
                *assert_answered("public listener isolation control"),
                # This control does double duty: it is the ban #6 statement for a route
                # that exists (Internal* is not on the public mux) AND the proof that a
                # 404 is a shape this suite could observe — so the mint's 403 below is a
                # measured fact about the mint, not a property of the harness.
                "pm.test('an Internal* route bound on the internal mux is a 404 mux-miss on the "
                "public one', () => pm.expect(pm.response.code, pm.response.text()).to.eql(404));",
                "pm.test('and the 404 is the ROUTING miss, not a service-level not-found', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.code, JSON.stringify(j)).to.eql(5);",
                "  pm.expect(j.message, JSON.stringify(j)).to.eql('Not Found');",
                "});",
            ],
        ),
        Step(
            name="control-nonsense-path-public",
            method="POST",
            path="/ibt-nonsense-{{runId}}",
            auth="jwtBootstrap",
            body={},
            test_script=[
                *assert_answered("public nonsense control"),
                *_REFUSAL_SHAPE_JS,
                "pm.test('nonsense control answered (its refusal shape is the yardstick for the mint probes)',",
                "  () => pm.expect(pm.response.code).to.be.a('number'));",
                "pm.environment.set('_ibtCtlPublic', _refusalShape(pm.response));",
            ],
        ),
        Step(
            name="control-nonsense-path-internal",
            method="POST",
            path="/ibt-nonsense-{{runId}}",
            auth="jwtBootstrap",
            body={},
            pre_script=require_env_url(
                "internalBaseUrl", "/ibt-nonsense-{{runId}}",
                "IBT-06 control — how the internal listener answers a typo"),
            test_script=[
                *assert_answered("internal nonsense control"),
                *_REFUSAL_SHAPE_JS,
                "pm.test('nonsense control answered on the internal listener',",
                "  () => pm.expect(pm.response.code).to.be.a('number'));",
                "pm.environment.set('_ibtCtlInternal', _refusalShape(pm.response));",
            ],
        ),
        # ---- the probes ----
        Step(
            name="mint-unbound-form-on-public",
            method="POST",
            path=_MINT_UNBOUND,
            auth="jwtBootstrap",
            body={},
            test_script=_never_2xx("mint (grpc-gateway unbound form) on the public listener",
                                   "_ibtCtlPublic"),
        ),
        Step(
            name="mint-unbound-form-on-internal",
            method="POST",
            path=_MINT_UNBOUND,
            auth="jwtBootstrap",
            body={},
            pre_script=require_env_url(
                "internalBaseUrl", _MINT_UNBOUND,
                "IBT-06 — the mint must have no door on the internal listener either"),
            test_script=_never_2xx("mint (grpc-gateway unbound form) on the internal listener",
                                   "_ibtCtlInternal"),
        ),
        Step(
            name="mint-acceptance-named-path-on-public",
            method="POST",
            path=_MINT_ACCEPTANCE_PATH,
            auth="jwtBootstrap",
            body={},
            test_script=_never_2xx("mint (the path the acceptance spells) on the public listener",
                                   "_ibtCtlPublic"),
        ),
        Step(
            name="mint-acceptance-named-path-on-internal",
            method="POST",
            path=_MINT_ACCEPTANCE_PATH,
            auth="jwtBootstrap",
            body={},
            pre_script=require_env_url(
                "internalBaseUrl", _MINT_ACCEPTANCE_PATH,
                "IBT-06 — the acceptance-named path on the internal listener"),
            test_script=_never_2xx("mint (the path the acceptance spells) on the internal listener",
                                   "_ibtCtlInternal"),
        ),
    ],
))


# ===========================================================================
# IBT-15 — the provider's own surfaces are not reachable through the platform edge.
#
# The facade rule is only enforceable if going around it is not offered. Three
# addresses matter, and each is a different way around:
#   /admin/clients            registering an OAuth client without iam — the one move
#                             that would manufacture a principal the platform never
#                             provisioned;
#   /oauth2/token             the exchange, reachable through the edge would make the
#                             "direct only for the final exchange" exception a
#                             platform-published endpoint rather than a provider one;
#   /.well-known/jwks.json    the verification material. The facade serves it on a
#                             CLUSTER-INTERNAL listener by documented decision
#                             (security.md, iam JWKS-route exception). Publishing it
#                             at the edge would not be a vulnerability — it is public
#                             material — but it would move the surface, and the
#                             decision is that it does not live there.
#
# The positive control is what makes the third statement real rather than empty:
# IBT-04 and IBT-12 both fetch that exact path successfully at the facade listener,
# so "not 2xx here" is isolation, not a typo. Fired against a nonsense control on
# each listener for the same reason as IBT-06.
# ===========================================================================

_PROVIDER_SURFACES = [
    ("admin-client-registration", "/admin/clients", "POST"),
    ("provider-token-endpoint", "/oauth2/token", "POST"),
    ("provider-jwks-at-the-edge", "/.well-known/jwks.json", "GET"),
]


def _provider_surface_steps():
    steps = []
    for label, path, method in _PROVIDER_SURFACES:
        steps.append(Step(
            name=f"{label}-on-public",
            method=method,
            path=path,
            auth="jwtBootstrap",
            body={} if method == "POST" else None,
            test_script=_never_2xx(f"{path} on the public listener", "_ibtCtlPublic2"),
        ))
        steps.append(Step(
            name=f"{label}-on-internal",
            method=method,
            path=path,
            auth="jwtBootstrap",
            body={} if method == "POST" else None,
            pre_script=require_env_url(
                "internalBaseUrl", path,
                "IBT-15 — a provider surface must not be reachable on the internal "
                "listener either"),
            test_script=_never_2xx(f"{path} on the internal listener", "_ibtCtlInternal2"),
        ))
    return steps


CASES.append(Case(
    id="IBT-15-PROVIDER-SURFACES-NOT-REACHABLE-THROUGH-THE-EDGE",
    title="Provider admin-client registration, token endpoint and JWKS are not served by any api-gateway listener (the facade cannot be routed around)",
    classes=["SEC", "NEG", "CONF"],
    priority="P0",
    steps=[
        _jwks_step(
            "control-facade-serves-the-jwks-path",
            "IBT-15 positive control — the JWKS path IS served, at the facade listener, "
            "so NOT-at-the-edge is isolation and not a misspelling",
        ),
        Step(
            name="control-nonsense-path-public",
            method="POST",
            path="/ibt-nonsense2-{{runId}}",
            auth="jwtBootstrap",
            body={},
            test_script=[
                *assert_answered("public nonsense control"),
                *_REFUSAL_SHAPE_JS,
                "pm.test('nonsense control answered', () => pm.expect(pm.response.code).to.be.a('number'));",
                "pm.environment.set('_ibtCtlPublic2', _refusalShape(pm.response));",
            ],
        ),
        Step(
            name="control-nonsense-path-internal",
            method="POST",
            path="/ibt-nonsense2-{{runId}}",
            auth="jwtBootstrap",
            body={},
            pre_script=require_env_url(
                "internalBaseUrl", "/ibt-nonsense2-{{runId}}",
                "IBT-15 control — how the internal listener answers a typo"),
            test_script=[
                *assert_answered("internal nonsense control"),
                *_REFUSAL_SHAPE_JS,
                "pm.test('nonsense control answered', () => pm.expect(pm.response.code).to.be.a('number'));",
                "pm.environment.set('_ibtCtlInternal2', _refusalShape(pm.response));",
            ],
        ),
        *_provider_surface_steps(),
    ],
))


# ===========================================================================
# IBT-10 — ONLY a facade-published asymmetric Bearer is accepted (regression lock).
#
# The negatives here are built FROM the accepted credential rather than invented:
# same payload, same kid, only the algorithm changed. That is deliberate. An
# invented HS256 token could be refused for a dozen uninteresting reasons — wrong
# issuer, wrong audience, expired — and the case would pass without ever exercising
# algorithm confusion. Re-signing the ACCEPTED payload leaves exactly one difference
# between the 200 and the 401: which algorithm the edge was willing to verify with.
#
# The HMAC key is the PUBLIC material the facade itself publishes for that kid —
# the textbook alg-confusion attack (CWE-347). If the edge ever took `alg` from the
# token header instead of pinning it to the key, this forgery would be
# indistinguishable from the real Bearer and would authenticate as a cluster
# system-admin.
#
# WHY THE MATERIAL IS READ BY KEY TYPE AND NOT AS "the modulus".
# The publisher carries a record per accepted issuer, and their key types differ —
# the mirror is RSA, the platform's own keyring is EC. Reading `n` alone found
# nothing for an EC key, so the forgery could not be built at all: the case then
# failed on its own precondition, which is the correct behaviour of a probe that
# refuses to report a passing refusal for a forgery it never made — and exactly
# why that guard is kept below. What was wrong was the lookup, not the guard.
# `_publicMaterial` reads the public half of whichever key type published the kid,
# so the HMAC key stays "material the facade itself serves" on both lanes.
#
# The case id keeps the acceptance's scenario number even though "RS256" in it now
# names one lane of two; see divergence 4 in the module docstring.
#
# The positive control in the first step is not ceremony: without it, all three
# refusals below are satisfied by an edge that refuses everything.
# ===========================================================================

CASES.append(Case(
    id="IBT-10-ONLY-FACADE-ISSUED-RS256-IS-ACCEPTED",
    title="Anonymous, alg=none and an HS256 alg-confusion forgery of the SAME payload keyed with the facade's own published material are all 401; the untouched facade Bearer is 200",
    classes=["SEC", "NEG", "CONF"],
    priority="P0",
    steps=[
        _jwks_step(
            "facade-jwks-for-forgery",
            "IBT-10 — the public material used as the HMAC key of the alg-confusion forgery, "
            "mirror record",
        ),
        _own_record_step(
            "facade-own-key-set-for-forgery",
            "IBT-10 — the same, for the OWN record of the facade: the kid that signed the "
            "accepted Bearer may be published by either",
        ),
        Step(
            name="positive-control-real-bearer",
            method="GET",
            path="/iam/v1/me",
            auth="jwtBootstrap",
            test_script=[
                *assert_answered("positive control"),
                "pm.test('the untouched facade Bearer is ACCEPTED (without this, every refusal "
                "below is satisfied by an edge that refuses everything)',",
                "  () => pm.expect(pm.response.code, pm.response.text()).to.eql(200));",
                *_JOSE_HELPERS,
                "const _sent = _sentBearer();",
                "pm.environment.set('_ibtRealBearer', _sent);",
            ],
        ),
        Step(
            name="anonymous-is-rejected",
            method="GET",
            path="/iam/v1/me",
            auth="anonymous",
            test_script=[
                *assert_answered("anonymous"),
                "pm.test('anonymous is 401 (production posture: no unauthenticated access)',",
                "  () => pm.expect(pm.response.code, pm.response.text()).to.eql(401));",
                *assert_grpc_code(16, "UNAUTHENTICATED"),
            ],
        ),
        Step(
            name="alg-none-forgery-is-rejected",
            method="GET",
            path="/iam/v1/me",
            auth="anonymous",
            pre_script=[
                *_JOSE_HELPERS,
                "const _real = pm.environment.get('_ibtRealBearer') || '';",
                "const _p = _real.split('.');",
                "if (_p.length === 3) {",
                "  const h = JSON.parse(_b64urlToText(_p[0]));",
                "  const h2 = _b64urlFromText(JSON.stringify({alg: 'none', kid: h.kid, typ: 'JWT'}));",
                "  pm.request.headers.upsert({key: 'Authorization', value: 'Bearer ' + h2 + '.' + _p[1] + '.'});",
                "} else {",
                "  pm.test('precondition: the positive control captured a three-part Bearer', () => {",
                "    pm.expect.fail('_ibtRealBearer is not a JWT — the forgery cannot be built, and a "
                "forgery that was not built must not report a passing refusal.');",
                "  });",
                "  pm.execution.skipRequest();",
                "}",
            ],
            test_script=[
                *assert_answered("alg=none forgery"),
                "pm.test('an unsigned token over the ACCEPTED payload is 401',",
                "  () => pm.expect(pm.response.code, pm.response.text()).to.eql(401));",
                *assert_grpc_code(16, "UNAUTHENTICATED"),
            ],
        ),
        Step(
            name="hs256-alg-confusion-forgery-is-rejected",
            method="GET",
            path="/iam/v1/me",
            auth="anonymous",
            pre_script=[
                *_JOSE_HELPERS,
                *_PUBLIC_MATERIAL_JS,
                "const _real = pm.environment.get('_ibtRealBearer') || '';",
                "const _p = _real.split('.');",
                "const _kid = _p.length === 3 ? JSON.parse(_b64urlToText(_p[0])).kid : '';",
                "const _key = _facadeKeyByKid(_kid);",
                "const _mat = _publicMaterial(_key);",
                "if (_p.length === 3 && _mat) {",
                "  const h2 = _b64urlFromText(JSON.stringify({alg: 'HS256', kid: _kid, typ: 'JWT'}));",
                "  const signing = h2 + '.' + _p[1];",
                "  const mac = CryptoJS.HmacSHA256(signing, _mat).toString(CryptoJS.enc.Base64)",
                "    .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');",
                "  pm.request.headers.upsert({key: 'Authorization', value: 'Bearer ' + signing + '.' + mac});",
                "} else {",
                "  pm.test('precondition: real Bearer and the facade material for its kid are both "
                "available', () => {",
                "    pm.expect.fail('cannot build the alg-confusion forgery (bearer parts=' + _p.length +",
                "      ', kid=' + _kid + ', key published by the facade=' + (_key ? _key.kty : 'NONE') +",
                "      ', public material=' + (_mat ? 'present' : 'MISSING') +",
                "      '). A forgery that was not built must not report a passing refusal.');",
                "  });",
                "  pm.execution.skipRequest();",
                "}",
            ],
            test_script=[
                *assert_answered("HS256 alg-confusion forgery"),
                "pm.test('HS256 forgery of the SAME payload, keyed with the public modulus, is 401 "
                "(RS256 is pinned; the header does not choose the algorithm)',",
                "  () => pm.expect(pm.response.code, pm.response.text()).to.eql(401));",
                *assert_grpc_code(16, "UNAUTHENTICATED"),
                "pm.test('the forgery did not become a principal', () => {",
                "  let j = null; try { j = pm.response.json(); } catch (e) { j = null; }",
                "  pm.expect(j && j.subject, JSON.stringify(j)).to.be.oneOf([undefined, null]);",
                "});",
            ],
        ),
    ],
))
