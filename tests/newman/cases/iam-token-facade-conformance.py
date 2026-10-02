# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set: iam is the SINGLE FACADE to the token signer (#59, Phase C).

WHAT PROPERTY THIS FILE PINS
============================
`.claude/rules/security.md` §«Production-mode обязателен ВЕЗДЕ» п.4 states the rule
this suite exists to keep true:

    iam is the ONLY facade to token signing. Clients, services and e2e go to iam —
    signature verification through the key material it publishes, token issuance
    and lifecycle through its RPCs, claim composition by iam itself. Going around
    iam breaks the unification.

WHERE THIS RUNS, AND WHY HERE (e2e-flow.md §7а; kaname#415)
=========================================================
Every lane below is PRODUCED BY THE SERVICE: its own public REST front verifies the
presented Bearer, its own key publisher serves the verifying half, its own RPCs
issue and revoke credentials, its own signer places the composed claims. So the
module runs where those producers live — on the autonomous stand of this
repository, job `stand` of `.github/workflows/e2e-newman.yml`, every step on
`{{ownRestBaseUrl}}` (`address_own_front` at the end of the module) except the
key-set reads, which go to the publisher listener `{{iamJwksBaseUrl}}`. Both
addresses and the bootstrap Bearer are minted by the machine seed of that stand
(`tests/authz-fixtures/seed_own_stand.py`).

The module was written for the api-gateway of the platform. Splitting it by
producer (kaname#415) left here what the service produces and named, for every
lane that left, who holds it now:

  verification  IBT-04 — the Bearer the front accepts is verified by key material the
                         FACADE serves (its `kid` is published by the facade's own
                         key-set record), and the front answers 200 — neither 401 nor
                         403. That the EDGE accepts the same Bearer is the edge's
                         subject: PRO-Robotech/kacho:gateway/tests/newman/cases/authn_edge.py.
  issuance      IBT-05 — a credential is issued AND revoked through iam's own RPCs
                         (SAKeyService.Issue/Revoke, UserTokenService.Issue/Revoke),
                         and the acr-exempt service principal is not step-up-challenged.
  enrichment    IBT-13 — the platform principal the front reports for a machine token
                         is the one the FACADE's claim composition named.
  negatives     IBT-10 — only a facade-issued asymmetric Bearer is accepted by the
                         front: anonymous is 401, an unsigned token over the accepted
                         payload is 401, and an alg-confusion HS256 forgery over the
                         SAME payload, keyed with the published public material, is
                         401. The edge's own rubezh is held by the same platform
                         module as IBT-04.

Lanes that LEFT this module, each with its holder:

  IBT-06 — "the bootstrap mint has no REST door on any api-gateway listener". Its
           subject is the route table of a listener, and it is held by
           REGISTRATION, which is stronger than an e2e 404 (a 404 also answers a
           typo): on the service side by `cmd/kaname/bootstrap_token_internal_only_test.go`,
           on the edge side by
           PRO-Robotech/kacho:gateway/internal/restmux/bootstrap_token_no_rest_route_test.go.
  IBT-15 — "the provider's own surfaces are not reachable through the edge". Two of
           its three addresses were surfaces of the external provider, and the
           provider is gone from the product together with its mirror record
           (kaname#424, kaname#361): there is nothing left to route around. The third
           — where the facade key set is published — is a statement about the route
           table of the edge, the platform's subject; on the service side the record
           is served by the publisher listener, which IBT-04 below reads.
  IBT-12 — RETIRED with its subject earlier (kaname#361); its number is not reused.
  IBT-14 — the docker lane; it lives with its subject in the platform's registry suite.

WHERE THE IDS COME FROM
=======================
IBT-04/05/06/10 are the e2e-conformance scenarios named in the acceptance
(`docs/specs/sub-phase-IAM-BOOTSTRAP-TOKEN-acceptance.md`, Traceability rows
"e2e-conformance (Phase C)"); IBT-12/13/14/15 are new numbers in the same family.
The case IDS ARE KEPT, because they are the acceptance's scenario numbers and
renaming them would silently break the traceability rows that cite them — even
where an id still says EDGE or RS256: what the case asserts is said by its title
and its comment.

Two divergences from the acceptance text, recorded rather than papered over:

  1. IBT-05's acceptance text drives `UserTokenService.Issue` for the SEED. This case
     drives it for the CONTRACT: issue → poll → the credential material is returned →
     revoke. It deliberately does NOT exchange the user credential for a Bearer: a
     user client-credentials token carries no `acr`, so that exchange cannot stand
     in for an interactive principal (issue #59).
  2. THE ACCEPTANCE HAS ONE ISSUING LANE, AND SO DOES THE PRODUCT NOW. The
     acceptance was written when every Bearer came from the external provider; the
     platform then grew its own signer, and the provider has since left the product
     (kaname#424). Every lane-specific literal (one algorithm, one key-set record,
     one claim placement, `sub` is not the principal) was replaced by the property
     that holds for any asymmetric signer, and each case comment says which literal
     it replaced and why the replacement is not a relaxation. The claim reader still
     NAMES the nested forms the provider used, so that a failure says which form it
     searched — the stand produces the flat one.

WHAT IS DELIBERATELY *NOT* ASSERTED, SO NOBODY LOOKS FOR IT HERE
================================================================
The final OAuth2 `client_assertion` → token exchange is not exercised as a
black-box case: signing an ES256 assertion needs the private key handed out once by
Issue, and a Postman script signing JOSE would be a second implementation of the
seed's own exchange that could drift from it silently. The Bearer this suite carries
is produced by that very exchange in the seed of the stand.

HOW THE PROBES REACH WHAT THEY PROBE
====================================
  {{ownRestBaseUrl}}          the service's own public REST front (`address_own_front`);
  {{iamJwksBaseUrl}}          the service's key-publisher listener. ONE path is read
                              on it — the platform's own key-set record, declared as a
                              module constant next to `_jwks_step` — and each fetch
                              asserts 200: a record that moved makes this suite name
                              the address it asked for, never pass having read nothing.

A missing variable is a BROKEN HARNESS, never a legal mode: `require_env_url` fails
naming the variable, so losing one turns the suite RED instead of silently deleting
a lane.

Idempotence: every fixture this file creates carries `{{runId}}` in its name and is
torn down by the case that made it (SA created → key issued → key revoked → SA
deleted). The one credential issued against a pre-seeded subject (the user token) is
revoked in the same case.

Test-first note (strict TDD): these cases are written to FAIL when the facade property
is violated, and that is demonstrated by injection rather than asserted —
`scripts/selftest_token_facade_forms.py` feeds the real generated collection a
defective world per axis and requires each to go red naming itself. Do not weaken an
assertion here; a red case means the property moved.

Техники: классы эквивалентности предъявителя (подлинный · без удостоверения · без
подписи · подделка смешением алгоритма), переходы состояний удостоверения (выдан →
отозван), угадывание ошибок (симметричный ключ в записи публикатора, приватный член
ключа, запись переехала).
"""

# ДОМ МОДУЛЯ — репозиторий его ПРЕДМЕТА (e2e-flow.md §7а, решение владельца
# 2026-09-12). Сверяется с деревом гейтом `scripts/case_home_test.py`: домены
# выводятся из REST-путей этого же модуля, и объявление обязано с ними сходиться.
HOME = "kaname"

import json  # only for safely quoting case text into JS string literals

CASES = []


# ---------------------------------------------------------------------------
# Shared JS: base64url ↔ text, and reading the credential the STEP ACTUALLY SENT.
#
# The header is read from `pm.request.headers`, not from the environment variable
# it came from: what this suite is about is the credential presented to the front.
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
# The publisher on the facade listener carries ONE record — ours — on its
# DECLARED path: that record IS "the key material this facade serves". The
# mirror record of the provider's public keyset stood beside it until the
# provider was retired (kaname#361); the publisher now refuses a second record
# at start, for the reason this suite exists to keep true: a key of one issuer
# would otherwise sit beside the keys of another.
#
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

_OWN_JWKS_PATH = "/.well-known/kaname/jwks.json"


def _jwks_step(name, why, path=_OWN_JWKS_PATH, record="own",
               kids_var="_facadeOwnKids", by_kid_var="_facadeOwnByKid"):
    """A GET of the record of the FACADE's key publisher, at its own listener.

    Every case that needs the served key material fetches it ITSELF instead of
    reading a variable another case left behind: a case whose precondition is
    produced by a different case cannot be run alone (`--folder`), and when it is
    run alone it does not fail — it passes on a stale value or skips. Fetching is
    two hundred bytes; depending on a neighbour is a silent hole.

    WHY THE PER-KEY ASSERTIONS ARE KEY-TYPE-AWARE AND NOT "RSA/RS256"
    ----------------------------------------------------------------
    They used to demand `kty=RSA` + `alg=RS256` of every key of every record.
    That was a statement about ONE issuer's key choice, and it stopped being a
    statement about the FACADE the moment the platform's own record appeared:
    its keyring is EC/ES256, so the old form was red on correct key material.

    What replaces it is not looser — it is a different, stronger axis. Each key
    must declare a key type this platform publishes, its `alg` must be the one
    that key type implies, and the public half must be COMPLETE for that type.
    A symmetric key (`oct`) fails on the first clause: publishing one would mean
    publishing a SIGNING SECRET, which is the same defect the private-member
    check below is written for, arriving by another door. A key whose header
    algorithm and key type disagree fails on the second — that is the shape an
    alg-confusion forgery needs, seen from the publishing side.
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
            # Private JWK members on this surface would leak the platform's
            # signing key.
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
    "  const _o = JSON.parse(pm.environment.get('_facadeOwnByKid') || '{}');",
    "  return _o[kid] || null;",
    "}",
]


# ===========================================================================
# IBT-04 — the front accepts the facade-issued Bearer, and the key that verifies
#          it is served BY THE FACADE.
#
# Two halves, and neither alone is the property. "The front answered 200" says the
# token was good; it does not say WHOSE key material proved it. "The publisher
# serves keys" says material exists; it does not say anything verifies with it.
# Together they close the verification lane: this exact credential's `kid` is one
# the facade publishes, and the front admits it.
#
# THE RECORD READ IS OURS, AND IT IS THE ONLY ONE.
# The publisher used to carry a record per accepted issuer, and this case read
# both and required the kid to sit in EXACTLY ONE of them. The provider's mirror
# record left together with the provider (kaname#361): the publisher now carries
# one record and refuses a second at start, so the kid of an accepted Bearer is
# required to be served by OUR record — a kid the facade does not publish means
# the front verifies against key material that is not the platform's.
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
    title="The facade publishes — in its own key-set record — the kid that signs the accepted Bearer, under the algorithm its header names; the service's own front answers 200 (not 401, not 403)",
    classes=["SEC", "CONF"],
    priority="P0",
    steps=[
        _jwks_step(
            "facade-own-key-set",
            "verification lane — the OWN record of the facade; the platform signs with its own "
            "keyring and publishes the verifying half here",
        ),
        Step(
            name="bearer-accepted-at-the-front",
            method="GET",
            path="/iam/v1/me",
            auth="jwtBootstrap",
            test_script=[
                *assert_answered("front acceptance"),
                *_JOSE_HELPERS,
                # ОДНО утверждение, а не три. Прежде рядом со `status 200` стояли «не
                # 401» и «не 403», объяснённые тем, что голое равенство не называет
                # сломавшуюся полосу. Довод верен, средство — нет: оба отрицания
                # подчинены утверждению о статусе (401 и 403 роняют его первыми) и
                # ОТДЕЛЬНО упасть не могут, а сами по себе проходят на 500 и 503.
                # Полосы теперь названы В СООБЩЕНИИ утверждения — диагностика та же,
                # а мёртвых строк нет. verifies #668.
                "pm.test('the front accepted the presented Bearer: HTTP 200', () => pm.expect(pm.response.code,",
                "  '401 here means the facade-signed token failed verification; 403 on an <exempt> RPC'",
                "  + ' means the principal did not resolve; any other code means the front never reached'",
                "  + ' this lane. Body: ' + pm.response.text()).to.eql(200));",
                "const _sent = _sentBearer();",
                "pm.test('a Bearer was actually presented (an unauthenticated 200 would prove nothing)',",
                "  () => pm.expect(_sent, 'Authorization header').to.be.a('string').with.length.greaterThan(0));",
                "const _hdr = JSON.parse(_b64urlToText(_sent.split('.')[0]));",
                "pm.test('presented Bearer is signed with an ASYMMETRIC algorithm (never HS*, never none)',",
                "  () => pm.expect(['RS256', 'ES256', 'EdDSA'], JSON.stringify(_hdr) +",
                "    ' — a symmetric or unsigned header means the presenter could have made this'",
                "    + ' credential itself, and \"the front answered 200\" would say nothing about the facade')",
                "    .to.include(_hdr.alg));",
                "pm.test('presented Bearer names a kid', () => {",
                "  pm.expect(_hdr.kid, JSON.stringify(_hdr)).to.be.a('string').with.length.greaterThan(0);",
                "});",
                # THE SUBSTANCE OF THE LANE.
                "const _ownByKid = JSON.parse(pm.environment.get('_facadeOwnByKid') || '{}');",
                "pm.test('the facade record was captured (an empty keyset is satisfied by nothing)', () => {",
                "  pm.expect(Object.keys(_ownByKid).length, 'own record, captured by the jwks step')",
                "    .to.be.greaterThan(0);",
                "});",
                "pm.test('the kid that signed the accepted Bearer is SERVED BY THE FACADE — by its OWN "
                "key-set record', () => {",
                "  pm.expect(_ownByKid[_hdr.kid], 'kid ' + _hdr.kid + ' — not in the facade record'",
                "    + ' (keys read: ' + Object.keys(_ownByKid).length + '): the front verifies against'",
                "    + ' key material this facade does not publish').to.be.an('object');",
                "});",
                "pm.test('the publishing record declares the SAME algorithm the Bearer header names', () => {",
                "  const _k = _ownByKid[_hdr.kid];",
                "  pm.expect(_k, 'no facade key published for kid ' + _hdr.kid).to.be.an('object');",
                "  pm.expect(_k.alg, 'header alg ' + _hdr.alg + ' against the alg the facade publishes for '",
                "    + _hdr.kid + ' — a header naming an algorithm the key material does not support is'",
                "    + ' the alg-confusion shape').to.eql(_hdr.alg);",
                "});",
                "const _pl = JSON.parse(_b64urlToText(_sent.split('.')[1]));",
                "pm.test('presented Bearer carries an issuer and an audience', () => {",
                "  pm.expect(_pl.iss, JSON.stringify(_pl)).to.be.a('string').with.length.greaterThan(0);",
                "  const aud = [].concat(_pl.aud || []);",
                "  pm.expect(aud.length, 'aud claim: an audience-less token is not addressed to the API')",
                "    .to.be.greaterThan(0);",
                "});",
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
                # values were read by IBT-06 when it lived here, and when only the
                # account was asserted the other two went missing silently — the
                # failure then surfaced in a different case, on a step that was
                # behaving correctly for an input nobody had captured. The three
                # claims ARE the composition this case presents, so they stay
                # asserted after IBT-06 left (see the module docstring).
                "pm.test('the caller Bearer carried the composed claims this suite reads', () => {",
                "  const _form = pm.environment.get('ibtCallerClaimForm') || 'none';",
                "  pm.expect(_form, 'no kaname_* claims in ANY of the three declared forms"
                " (top-level / ext.ext_claims / ext_claims)').to.not.eql('none');",
                "  pm.expect(pm.environment.get('ibtAccountId'), 'kaname_account_id claim (form: ' + _form + ')')",
                "    .to.be.a('string').with.length.greaterThan(0);",
                "  pm.expect(pm.environment.get('ibtCallerPrincipalId'),",
                "    'kaname_principal_id claim (form: ' + _form + ')')",
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
# IBT-10 — ONLY a facade-published asymmetric Bearer is accepted (regression lock).
#
# The negatives here are built FROM the accepted credential rather than invented:
# same payload, same kid, only the algorithm changed. That is deliberate. An
# invented HS256 token could be refused for a dozen uninteresting reasons — wrong
# issuer, wrong audience, expired — and the case would pass without ever exercising
# algorithm confusion. Re-signing the ACCEPTED payload leaves exactly one difference
# between the 200 and the 401: which algorithm the front was willing to verify with.
#
# The HMAC key is the PUBLIC material the facade itself publishes for that kid —
# the textbook alg-confusion attack (CWE-347). If the front ever took `alg` from the
# token header instead of pinning it to the key, this forgery would be
# indistinguishable from the real Bearer and would authenticate as a cluster
# system-admin.
#
# WHY THE MATERIAL IS READ BY KEY TYPE AND NOT AS "the modulus".
# The publisher carried a record per accepted issuer, and their key types differed
# — the provider's mirror was RSA, the platform's own keyring is EC. Reading `n`
# alone found nothing for an EC key, so the forgery could not be built at all: the case then
# failed on its own precondition, which is the correct behaviour of a probe that
# refuses to report a passing refusal for a forgery it never made — and exactly
# why that guard is kept below. What was wrong was the lookup, not the guard.
# `_publicMaterial` reads the public half of whichever key type published the kid,
# so the HMAC key stays "material the facade itself serves" whatever key type the
# keyring holds. The mirror record is gone (kaname#361); the facade material is
# read from its one record.
#
# The case id keeps the acceptance's scenario number even though "RS256" in it now
# names one lane of two; see divergence 4 in the module docstring.
#
# The positive control in the first step is not ceremony: without it, all three
# refusals below are satisfied by a front that refuses everything.
# ===========================================================================

CASES.append(Case(
    id="IBT-10-ONLY-FACADE-ISSUED-RS256-IS-ACCEPTED",
    title="Anonymous, alg=none and an HS256 alg-confusion forgery of the SAME payload keyed with the facade's own published material are all 401; the untouched facade Bearer is 200",
    classes=["SEC", "NEG", "CONF"],
    priority="P0",
    steps=[
        _jwks_step(
            "facade-own-key-set-for-forgery",
            "IBT-10 — the public material used as the HMAC key of the alg-confusion forgery, "
            "from the OWN record of the facade",
        ),
        Step(
            name="positive-control-real-bearer",
            method="GET",
            path="/iam/v1/me",
            auth="jwtBootstrap",
            test_script=[
                *assert_answered("positive control"),
                "pm.test('the untouched facade Bearer is ACCEPTED (without this, every refusal "
                "below is satisfied by a front that refuses everything)',",
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


# ДОМ И ПОВЕРХНОСТЬ (e2e-flow.md §7а; kaname#415): производитель каждого
# утверждения модуля — сама служба, поэтому каждый шаг идёт на её собственный
# публичный фронт. Шаги, уже адресованные публикатору ключей (`iamJwksBaseUrl`,
# `require_env_url` в их пред-скрипте), помощник не трогает.
CASES = address_own_front(CASES, "собственный публичный REST-фронт службы; без него у "
                                 "полос фасада нет производителя — рубеж, выдачу и состав "
                                 "утверждений производит служба на этом фронте")
