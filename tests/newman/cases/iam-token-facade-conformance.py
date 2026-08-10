# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

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

Four lanes and one exception, therefore four positive lanes and the negatives that
make each of them mean something:

  verification  IBT-04 — the Bearer the edge accepts is verified by key material the
                         FACADE serves (its `kid` is in iam's JWKS), and the edge
                         answers 200 — neither 401 nor 403.
                IBT-12 — that JWKS is a faithful MIRROR of the provider's public one
                         (same kids, same moduli): iam proxies, iam mints nothing.
  issuance      IBT-05 — a credential is issued AND revoked through iam's own RPCs
                         (SAKeyService.Issue/Revoke, UserTokenService.Issue/Revoke),
                         and the acr-exempt service principal is not step-up-challenged.
  enrichment    IBT-13 — the platform principal the edge reports for a machine token
                         is the one iam's token-hook stamped into its claims. Without
                         the hook the `sub` is a raw OAuth client id and resolves to
                         nothing.
  docker token  IBT-14 — the data-plane's own WWW-Authenticate challenge names the
                         FACADE handle (`/iam/token`), not the provider's
                         `/oauth2/token`; and that handle is a live gate, not a hole.
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

WHAT IS DELIBERATELY *NOT* ASSERTED, SO NOBODY LOOKS FOR IT HERE
================================================================
The legitimate direct path — the final OAuth2 `client_assertion` → token exchange at
the provider — is not exercised as a black-box case: signing an ES256 assertion needs
the private key handed out once by Issue, and a Postman script signing JOSE would be a
second implementation of `tests/authz-fixtures/mint_rs256.py` that could drift from it
silently. It is exercised on EVERY run of this suite anyway, one level down: the
Bearer these cases carry was produced by exactly that exchange. IBT-04 asserting that
Bearer is accepted therefore already witnesses the exception working.

HOW THE PROBES REACH WHAT THEY PROBE
====================================
Four endpoints of this stand are not the api-gateway and are addressed through their
own base-URL variables, injected by the newman runner (`--env-var`) exactly like
`internalBaseUrl`. A missing variable is a BROKEN HARNESS, never a legal mode:
`require_env_url` fails naming the variable and only then skips, so losing one turns
the suite RED instead of silently deleting a lane.

  {{iamJwksBaseUrl}}          iam JWKS-proxy listener (:9097). Cluster-internal,
                              server-TLS with an internal-CA leaf → the steps carry
                              `insecure_tls` (the tunnel's trust chain is not the
                              subject; WHAT IS SERVED is).
  {{providerPublicBaseUrl}}   the signing provider's PUBLIC endpoint (:4444). Read by
                              the TEST as an oracle for the mirror comparison — this
                              is the one place a direct provider read is legitimate,
                              and it is legitimate because it is the measurement, not
                              a client path.
  {{iamRegistryTokenBaseUrl}} iam docker-token handle listener (:9096), server-TLS.
  {{registryDataPlaneBaseUrl}} the registry data plane (:8080), whose challenge must
                              name the facade handle.

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


def _jwks_step(name, why):
    """A GET of the FACADE's JWKS, addressed at its own listener.

    Every case that needs the served key material fetches it ITSELF instead of
    reading a variable another case left behind: a case whose precondition is
    produced by a different case cannot be run alone (`--folder`), and when it is
    run alone it does not fail — it passes on a stale value or skips. Fetching is
    two hundred bytes; depending on a neighbour is a silent hole.
    """
    from_gen = require_env_url("iamJwksBaseUrl", "/.well-known/jwks.json", why)
    return Step(
        name=name,
        method="GET",
        path="/.well-known/jwks.json",
        auth="anonymous",
        insecure_tls=True,
        pre_script=from_gen,
        test_script=[
            *assert_answered(name),
            *assert_status(200),
            *_JOSE_HELPERS,
            "const _jwks = pm.response.json();",
            "pm.test('facade JWKS: keys is a non-empty array', () => {",
            "  pm.expect(_jwks.keys, JSON.stringify(_jwks)).to.be.an('array');",
            "  pm.expect(_jwks.keys.length, 'a facade serving zero keys verifies nothing')",
            "    .to.be.greaterThan(0);",
            "});",
            "pm.test('facade JWKS: every key is an RS256 verification key with kid/n/e', () => {",
            "  (_jwks.keys || []).forEach(k => {",
            "    pm.expect(k.kty, JSON.stringify(k)).to.eql('RSA');",
            "    pm.expect(k.alg, JSON.stringify(k)).to.eql('RS256');",
            "    pm.expect(k.kid, JSON.stringify(k)).to.be.a('string').with.length.greaterThan(0);",
            "    pm.expect(k.n, JSON.stringify(k)).to.be.a('string').with.length.greaterThan(0);",
            "    pm.expect(k.e, JSON.stringify(k)).to.be.a('string').with.length.greaterThan(0);",
            "  });",
            "});",
            # The facade PROXIES; it holds no keyset of its own. Private JWK members
            # on this surface would mean iam had started signing — the exact thing
            # the rule says it must not do — and would leak the signing key besides.
            "pm.test('facade JWKS: carries PUBLIC material only (no d/p/q/dp/dq/qi)', () => {",
            "  const priv = ['d', 'p', 'q', 'dp', 'dq', 'qi'];",
            "  (_jwks.keys || []).forEach(k => {",
            "    priv.forEach(m => pm.expect(k[m], 'private JWK member ' + m +",
            "      ' on the proxy: the facade must mirror, never mint').to.be.undefined);",
            "  });",
            "});",
            "pm.environment.set('_facadeKids', JSON.stringify((_jwks.keys || []).map(k => k.kid)));",
            "pm.environment.set('_facadeByKid', JSON.stringify((_jwks.keys || []).reduce((a, k) => {",
            "  a[k.kid] = {kty: k.kty, alg: k.alg, n: k.n, e: k.e}; return a;", "}, {})));",
        ],
    )


# ===========================================================================
# IBT-04 — the edge accepts the facade-issued Bearer, and the key that verifies
#          it is served BY THE FACADE.
#
# Two halves, and neither alone is the property. "The edge answered 200" says the
# token was good; it does not say WHOSE key material proved it. "The proxy serves
# keys" says material exists; it does not say anything verifies with it. Together
# they close the verification lane: this exact credential's `kid` is one the facade
# publishes, and the edge admits it.
# ===========================================================================

CASES.append(Case(
    id="IBT-04-FACADE-VERIFIES-THE-BEARER-THE-EDGE-ACCEPTS",
    title="Facade JWKS-proxy serves the RS256 kid that signs the accepted Bearer; edge answers 200 (not 401, not 403)",
    classes=["SEC", "CONF"],
    priority="P0",
    steps=[
        _jwks_step(
            "facade-jwks",
            "verification lane — the key material the edge verifies with is served by iam",
        ),
        Step(
            name="bearer-accepted-at-edge",
            method="GET",
            path="/iam/v1/me",
            auth="jwtBootstrap",
            test_script=[
                *assert_answered("edge acceptance"),
                *_JOSE_HELPERS,
                # Named separately from `status 200` on purpose. The acceptance says
                # "NOT 401, NOT 403"; a bare equality assertion reports "expected 403
                # to equal 200" and leaves the reader to work out which lane broke.
                "pm.test('edge did NOT reject authN (401 would mean the facade-signed token failed verification)',",
                "  () => pm.expect(pm.response.code, pm.response.text()).to.not.eql(401));",
                "pm.test('edge did NOT reject authZ (403 on an <exempt> RPC would mean the principal did not resolve)',",
                "  () => pm.expect(pm.response.code, pm.response.text()).to.not.eql(403));",
                *assert_status(200),
                "const _sent = _sentBearer();",
                "pm.test('a Bearer was actually presented (an unauthenticated 200 would prove nothing)',",
                "  () => pm.expect(_sent, 'Authorization header').to.be.a('string').with.length.greaterThan(0));",
                "const _hdr = JSON.parse(_b64urlToText(_sent.split('.')[0]));",
                "pm.test('presented Bearer is RS256 (asymmetric, provider-signed)',",
                "  () => pm.expect(_hdr.alg, JSON.stringify(_hdr)).to.eql('RS256'));",
                "pm.test('presented Bearer names a kid', () => {",
                "  pm.expect(_hdr.kid, JSON.stringify(_hdr)).to.be.a('string').with.length.greaterThan(0);",
                "});",
                # THE SUBSTANCE OF THE LANE.
                "pm.test('the kid that signed the accepted Bearer is SERVED BY THE FACADE proxy', () => {",
                "  const kids = JSON.parse(pm.environment.get('_facadeKids') || '[]');",
                "  pm.expect(kids, 'facade kids captured by the previous step').to.be.an('array')",
                "    .with.length.greaterThan(0);",
                "  pm.expect(kids, 'kid ' + _hdr.kid + ' is not among the kids iam publishes — the edge is'",
                "    + ' verifying against key material this facade does not serve').to.include(_hdr.kid);",
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
    # Bearer's enrichment claims rather than an environment variable: they are
    # properties OF THE CREDENTIAL under test, and taking them from anywhere else
    # would let the case pass while describing a different principal.
    "const _b = (pm.environment.get('jwtBootstrap') || '').split('.');",
    "if (_b.length === 3) {",
    "  try {",
    "    var _t = _b[1].replace(/-/g, '+').replace(/_/g, '/');",
    "    while (_t.length % 4 !== 0) { _t += '='; }",
    "    const _c = JSON.parse(CryptoJS.enc.Base64.parse(_t).toString(CryptoJS.enc.Utf8));",
    "    const _x = (_c.ext && _c.ext.ext_claims) || _c.ext_claims || {};",
    "    if (_x.kacho_account_id) pm.environment.set('ibtAccountId', _x.kacho_account_id);",
    "    if (_x.kacho_principal_id) pm.environment.set('ibtCallerPrincipalId', _x.kacho_principal_id);",
    "    if (_x.kacho_principal_type) pm.environment.set('ibtCallerPrincipalType', _x.kacho_principal_type);",
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
                "pm.test('the caller Bearer carried the enrichment claims this case reads', () => {",
                "  pm.expect(pm.environment.get('ibtAccountId'), 'kacho_account_id claim')",
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
# IBT-13 — the principal the platform reports is the one the FACADE's hook stamped.
#
# A machine token out of the client-credentials exchange has `sub` = the OAuth
# client id and, on its own, names nobody on this platform. It becomes a Kachō
# principal only because the provider calls iam's token hook and iam stamps
# `kacho_principal_type` / `kacho_principal_id` into the claims. So: read those two
# claims out of the credential actually presented, then ask the platform who it
# thinks the caller is, and require the two to be THE SAME SUBJECT.
#
# What makes this falsifiable rather than tautological: `/iam/v1/me` resolves the
# principal from the token's claims through iam's own subject lookup. If the hook
# stopped enriching, the claims would be absent and this case fails on the claims;
# if the hook enriched with something the platform cannot resolve, it fails on the
# comparison. Either way the enrichment lane is what breaks the case.
# ===========================================================================

CASES.append(Case(
    id="IBT-13-PRINCIPAL-CLAIMS-STAMPED-BY-THE-FACADE-HOOK",
    title="The machine Bearer's kacho_principal_* enrichment claims resolve to exactly the subject the platform reports for the caller",
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
                "const _sent = _sentBearer();",
                "const _pl = JSON.parse(_b64urlToText(_sent.split('.')[1]));",
                "const _x = (_pl.ext && _pl.ext.ext_claims) || _pl.ext_claims || {};",
                "pm.test('the presented token carries the facade hook enrichment claims', () => {",
                "  pm.expect(_x.kacho_principal_type, 'kacho_principal_type — absent means the '",
                "    + 'provider issued this token WITHOUT calling the facade token-hook')",
                "    .to.be.a('string').with.length.greaterThan(0);",
                "  pm.expect(_x.kacho_principal_id, 'kacho_principal_id')",
                "    .to.be.a('string').with.length.greaterThan(0);",
                "});",
                "pm.test('the raw OAuth subject is NOT a platform principal id (so the claims are '",
                "  + 'what makes this token addressable)', () => {",
                "  pm.expect(_pl.sub, JSON.stringify(_pl)).to.be.a('string');",
                "  pm.expect(_pl.sub, 'sub happens to equal kacho_principal_id — then this case '",
                "    + 'cannot tell an enriched token from a bare one; re-seed with a machine token')",
                "    .to.not.eql(_x.kacho_principal_id);",
                "});",
                "const _j = pm.response.json();",
                "pm.test('the platform reports EXACTLY the principal the hook stamped', () => {",
                "  const want = _x.kacho_principal_type + ':' + _x.kacho_principal_id;",
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
# IBT-14 — the docker lane is addressed at the FACADE handle.
#
# A docker client never chooses its token server: it follows the `realm` in the
# data plane's WWW-Authenticate challenge. So the black-box statement of "the
# docker token goes through iam's handle" is exactly: the challenge names the
# handle, and the handle is a live gate at that address.
#
# The negative half is the point. A challenge naming the provider's `/oauth2/token`
# would route every docker client around the facade — with no error anywhere, since
# the provider would happily answer.
# ===========================================================================

CASES.append(Case(
    id="IBT-14-DOCKER-CHALLENGE-NAMES-THE-FACADE-HANDLE",
    title="Registry data-plane 401 challenge advertises the iam /iam/token handle (never the provider token endpoint), and that handle is a live gate",
    classes=["SEC", "CONF", "NEG"],
    priority="P0",
    steps=[
        Step(
            name="dataplane-anonymous-challenge",
            method="GET",
            path="/v2/",
            auth="anonymous",
            pre_script=require_env_url(
                "registryDataPlaneBaseUrl", "/v2/",
                "docker lane — the challenge a docker client actually follows"),
            test_script=[
                *assert_answered("registry data-plane challenge"),
                "pm.test('anonymous /v2/ is challenged with 401 (a 200 here would mean the data '",
                "  + 'plane needs no token at all)', () => pm.expect(pm.response.code, pm.response.text()).to.eql(401));",
                "const _wa = pm.response.headers.get('WWW-Authenticate') || '';",
                "pm.test('the challenge is a Bearer token-auth challenge', () => {",
                "  pm.expect(_wa, 'WWW-Authenticate header').to.match(/^Bearer /);",
                "  pm.expect(_wa, _wa).to.match(/service=\"[^\"]+\"/);",
                "});",
                "const _m = _wa.match(/realm=\"([^\"]+)\"/);",
                "pm.test('the challenge names a realm', () => pm.expect(_m && _m[1], _wa).to.be.a('string'));",
                "const _realm = (_m && _m[1]) || '';",
                "const _path = _realm.replace(/^[a-z]+:\\/\\/[^/]+/i, '');",
                "pm.test('the realm PATH is the facade docker-token handle', () => {",
                "  pm.expect(_path, 'realm ' + _realm + ' — the docker client follows this address; "
                "it must be iam\\'s handle').to.eql('/iam/token');",
                "});",
                "pm.test('the realm is NOT the provider token endpoint (that would route every '",
                "  + 'docker client around the facade, silently)', () => {",
                "  pm.expect(_realm.toLowerCase(), _realm).to.not.contain('/oauth2/');",
                "});",
                "pm.environment.set('ibtRealmPath', _path);",
            ],
        ),
        Step(
            name="facade-token-handle-is-a-gate",
            method="GET",
            path="/iam/token?service=registry.kacho.local&scope=repository:ibt/{{runId}}:pull",
            auth="anonymous",
            insecure_tls=True,
            pre_script=require_env_url(
                "iamRegistryTokenBaseUrl",
                "/iam/token?service=registry.kacho.local&scope=repository:ibt/{{runId}}:pull",
                "docker lane — the facade handle the challenge points at"),
            test_script=[
                *assert_answered("facade docker-token handle"),
                # 401 and not 404 is the whole assertion: 404 would mean the handle the
                # data plane advertises is not served at that address at all, and every
                # docker client would fail with a confusing "not found" instead of a
                # credential prompt.
                "pm.test('the handle EXISTS and refuses an anonymous caller (404 = advertised but '",
                "  + 'not served; 200 = anonymous issuance)', () => pm.expect(pm.response.code, pm.response.text()).to.eql(401));",
                "const _wa = pm.response.headers.get('WWW-Authenticate') || '';",
                "pm.test('the handle re-challenges with its own realm, and it is the same handle', () => {",
                "  const m = _wa.match(/realm=\"([^\"]+)\"/);",
                "  pm.expect(m && m[1], _wa).to.be.a('string');",
                "  const p = (m && m[1] || '').replace(/^[a-z]+:\\/\\/[^/]+/i, '');",
                "  pm.expect(p, 'the facade advertises ' + p + ' while the data plane advertises '",
                "    + pm.environment.get('ibtRealmPath')).to.eql(pm.environment.get('ibtRealmPath'));",
                "});",
            ],
        ),
        Step(
            name="facade-token-handle-rejects-garbage-credentials",
            method="GET",
            path="/iam/token?service=registry.kacho.local&scope=repository:ibt/{{runId}}:pull",
            auth="anonymous",
            insecure_tls=True,
            pre_script=require_env_url(
                "iamRegistryTokenBaseUrl",
                "/iam/token?service=registry.kacho.local&scope=repository:ibt/{{runId}}:pull",
                "docker lane — the handle must verify credentials, not merely accept them") + [
                # Deliberately unmistakable as a real credential: a plausible-looking one
                # would make a passing substitution indistinguishable from a correct flow
                # ([[realistic-fixture-hides-the-defect-it-feeds]]).
                "pm.request.headers.upsert({key: 'Authorization', value: 'Basic ' +",
                "  CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(",
                "    'ibt-not-a-real-key:ibt-not-a-real-secret'))});",
            ],
            test_script=[
                *assert_answered("facade docker-token handle, garbage credentials"),
                "pm.test('unverifiable credentials are refused, never brokered into a token',",
                "  () => pm.expect(pm.response.code, pm.response.text()).to.eql(401));",
                "pm.test('no token was handed out', () => {",
                "  let j = null; try { j = pm.response.json(); } catch (e) { j = null; }",
                "  pm.expect(j && j.token, JSON.stringify(j)).to.be.oneOf([undefined, null]);",
                "});",
            ],
        ),
        Step(
            name="facade-token-listener-serves-only-its-handle",
            method="GET",
            path="/ibt-nonsense-{{runId}}",
            auth="anonymous",
            insecure_tls=True,
            pre_script=require_env_url(
                "iamRegistryTokenBaseUrl", "/ibt-nonsense-{{runId}}",
                "docker lane — control proving the 401s above are the HANDLE answering, "
                "not a listener that refuses everything"),
            test_script=[
                *assert_answered("facade token listener, nonsense path"),
                # Without this control, "401 on /iam/token" is satisfied by a listener
                # that 401s every path, including ones that do not exist — i.e. by a
                # handle that is not there.
                "pm.test('a path that is NOT the handle is 404, so the 401s above came from the "
                "handle itself', () => pm.expect(pm.response.code, pm.response.text()).to.eql(404));",
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

_MINT_UNBOUND = "/kacho.cloud.iam.v1.InternalBootstrapTokenService/MintBootstrapToken"
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
# IBT-10 — ONLY a facade-issued RS256 Bearer is accepted (regression lock).
#
# The negatives here are built FROM the accepted credential rather than invented:
# same payload, same kid, only the algorithm changed. That is deliberate. An
# invented HS256 token could be refused for a dozen uninteresting reasons — wrong
# issuer, wrong audience, expired — and the case would pass without ever exercising
# algorithm confusion. Re-signing the ACCEPTED payload leaves exactly one difference
# between the 200 and the 401: which algorithm the edge was willing to verify with.
#
# The HMAC key is the public modulus from the facade's own JWKS — the textbook
# RS256→HS256 confusion (CWE-347). If the edge ever verified `alg` from the token
# header instead of pinning RS256, this forgery would be indistinguishable from the
# real Bearer and would authenticate as a cluster system-admin.
#
# The positive control in the first step is not ceremony: without it, all three
# refusals below are satisfied by an edge that refuses everything.
# ===========================================================================

CASES.append(Case(
    id="IBT-10-ONLY-FACADE-ISSUED-RS256-IS-ACCEPTED",
    title="Anonymous, alg=none and an HS256 alg-confusion forgery of the SAME payload are all 401; the untouched facade Bearer is 200",
    classes=["SEC", "NEG", "CONF"],
    priority="P0",
    steps=[
        _jwks_step(
            "facade-jwks-for-forgery",
            "IBT-10 — the public modulus used as the HMAC key of the alg-confusion forgery",
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
                "const _real = pm.environment.get('_ibtRealBearer') || '';",
                "const _by = JSON.parse(pm.environment.get('_facadeByKid') || '{}');",
                "const _p = _real.split('.');",
                "const _kid = _p.length === 3 ? JSON.parse(_b64urlToText(_p[0])).kid : '';",
                "const _mod = (_by[_kid] || {}).n || '';",
                "if (_p.length === 3 && _mod) {",
                "  const h2 = _b64urlFromText(JSON.stringify({alg: 'HS256', kid: _kid, typ: 'JWT'}));",
                "  const signing = h2 + '.' + _p[1];",
                "  const mac = CryptoJS.HmacSHA256(signing, _mod).toString(CryptoJS.enc.Base64)",
                "    .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');",
                "  pm.request.headers.upsert({key: 'Authorization', value: 'Bearer ' + signing + '.' + mac});",
                "} else {",
                "  pm.test('precondition: real Bearer and its facade modulus are both available', () => {",
                "    pm.expect.fail('cannot build the alg-confusion forgery (bearer parts=' + _p.length +",
                "      ', kid=' + _kid + ', modulus=' + (_mod ? 'present' : 'MISSING') +",
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
