// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"
	"net/url"
	"strings"

	"go.uber.org/multierr"
)

// Validate checks Config invariants (pure function — no logger, no
// side-effects).
//
// Returns a multierr containing ALL detected problems at once.
//
// Checks base fields + (in production modes) the required AuthN secrets +
// production-strict TLS invariants.
func (c Config) Validate() error {
	var errs error

	errs = multierr.Append(errs, c.validateMode())

	// logger.level must be a known level so a typo fails fast at boot rather
	// than silently degrading observability. SlogLevel reports the allowed set.
	if _, err := c.Logger.SlogLevel(); err != nil {
		errs = multierr.Append(errs, err)
	}

	if listenAddress(c.APIServer.Endpoint) == "" {
		errs = multierr.Append(errs,
			fmt.Errorf("api-server.endpoint is empty"))
	}
	if listenAddress(c.APIServer.InternalEndpoint) == "" {
		errs = multierr.Append(errs,
			fmt.Errorf("api-server.internal-endpoint is empty"))
	}

	switch strings.ToLower(c.Repository.Postgres.SSLMode) {
	case "disable", "require", "verify-ca", "verify-full":
	case "":
		// permitted — baseDSN will substitute "disable"
	default:
		errs = multierr.Append(errs,
			fmt.Errorf("repository.postgres.ssl-mode=%q (allowed: disable, require, verify-ca, verify-full)",
				c.Repository.Postgres.SSLMode))
	}

	if strings.TrimSpace(c.Repository.Postgres.URL) == "" {
		errs = multierr.Append(errs,
			fmt.Errorf("repository.postgres.url is empty"))
	}

	if c.AuthN.Mode.IsProduction() {
		errs = multierr.Append(errs, c.validateProductionAuthNSecrets())
		errs = multierr.Append(errs, c.validateProductionBootstrapMint())
		errs = multierr.Append(errs, c.validateProductionTrustedForwarders())
		errs = multierr.Append(errs, c.validateProductionProviderAdminHop())
		errs = multierr.Append(errs, c.validateProductionProviderPublicHops())

		// DB-TLS gate — applies to EVERY production variant, not strict-only. All
		// IAM data (user/SA records, session-revocation + token rows, the
		// transient SA-key client_secret briefly staged in operations.response_data
		// before redaction) traverses this link; a plaintext connection
		// (sslmode=disable, or the empty default baseDSN substitutes with
		// "disable") is a boot-time misconfiguration in production, exactly like a
		// missing mTLS listener. A network-adjacent attacker on a plaintext DB link
		// can passively read credentials and IAM rows (CWE-319). Dev mode is
		// unaffected — see InsecureDevWarnings.
		switch strings.ToLower(c.Repository.Postgres.SSLMode) {
		case "require", "verify-ca", "verify-full":
			// OK
		default:
			errs = multierr.Append(errs,
				fmt.Errorf("production mode: repository.postgres.ssl-mode must be one of require|verify-ca|verify-full (got %q)",
					c.Repository.Postgres.SSLMode))
		}
		// (production-strict adds no DB-TLS requirement beyond this gate; any
		// future extapi.openfga.tls.* strict-only checks go under a
		// c.AuthN.Mode == ModeProductionStrict branch here.)
	}

	return errs
}

// validateProductionBootstrapMint refuses to start a production binary whose
// bootstrap-admin token mint is ENABLED (the signing key is present, so the RPC
// will actually issue tokens) but has NO caller allow-list.
//
// MintBootstrapToken returns a Hydra-signed cluster `system_admin` Bearer. It
// carries no ReBAC gate by construction (it exists to obtain the FIRST token,
// before any relation exists), so the ONLY thing standing between a caller and
// full control-plane takeover is the client-certificate SPIFFE allow-list
// enforced by authzguard.CallerPolicy. With that list empty the runtime already
// denies everyone — but shipping an enabled-yet-uncallable mint is a
// misconfiguration whose usual "fix" is to reopen the hole, so it fails at boot
// with a message naming the setting (core rule #16: no WARN-and-continue guard).
//
// Scoped to the ENABLED mint: a deployment that never supplies a signing key does
// not use the mint at all and boots unchanged.
//
// Only the PRESENCE of the key is read — never its value, and the value never
// appears in the error (security.md).
func (c Config) validateProductionBootstrapMint() error {
	if !c.AuthN.BootstrapMint.Enabled() {
		return nil
	}
	if len(c.AuthN.BootstrapMint.AllowedSANs()) > 0 {
		return nil
	}
	return fmt.Errorf(
		"production mode: authn.bootstrap-mint.allowed-client-sans is empty while the bootstrap mint is enabled (%s is set) — "+
			"MintBootstrapToken issues a cluster system_admin token and must be restricted to explicit client-certificate SPIFFE SANs; "+
			"set the allow-list or unset the signing key",
		c.AuthN.BootstrapMint.ResolveSigningKeyEnv())
}

// validateProductionTrustedForwarders refuses to start a production binary that
// has not narrowed the circle of senders permitted to FORWARD an end-user
// identity.
//
// Both listeners build CertIdentityExtract →
// TrustedPrincipalExtract(WithTrustedForwarders(cfg.AuthN.TrustedForwarders())).
// The corelib contract (pkg/grpcsrv principalIsTrusted) narrows that circle ONLY
// on a non-empty list; on an empty one it answers "trusted" for ANY peer that
// passed client-certificate verification, and the forwarded metadata identity
// becomes the subject of every authorization decision iam then makes. Both ports
// are ordinary Services in the namespace, the TLS layer checks the issuing
// authority rather than the name, and the only NetworkPolicy that selects the iam
// pod covers the internal port and is off outside production — so this list is the
// only thing that narrows.
//
// The consequence is not abstract: on :9090 iam deliberately does NOT re-ReBAC
// the end user (the api-gateway is the single authZ front door), so a neighbour
// with its own legitimate certificate would read and mutate any tenant's
// accounts, projects, groups, roles and grants, and mint personal tokens and
// service-account keys, as the named victim.
//
// The guard asks the SAME object and the SAME predicate the wiring and the
// self-report ask (grpcsrv.TrustedForwarders.IsNarrowed), not the raw field
// length: blank entries are dropped in the very place the narrowing happens, so
// `SANS=","` must not pass the guard and hand back the hole.
//
// dev deliberately tolerates empty (in-process fixtures) — and only there: on a
// DEPLOYED stand the dev posture is forbidden by a separate rule
// (production-mode EVERYWHERE).
func (c Config) validateProductionTrustedForwarders() error {
	if c.AuthN.TrustedForwarders().IsNarrowed() {
		return nil
	}
	return fmt.Errorf(
		"production mode: authn.trusted-forwarder-sans is empty (env override " +
			"KACHO_IAM_AUTHN__TRUSTED_FORWARDER_SANS) — an empty list lets ANY certificate-verified peer " +
			"forward an end-user identity, so a neighbouring service can act as any tenant; " +
			"pin the api-gateway SAN plus the peers that legitimately speak for a user")
}

// validateProductionProviderAdminHop refuses to start a production binary whose
// route to the identity provider's ADMIN API is GUESSED, or carries the
// administrative bearer in the clear.
//
// iam is the platform's sole facade to the provider: registering the OAuth2
// client behind a personal token or a service-account key, recording a trust
// grant, tearing down a login session — all of it goes over this hop, with the
// administrative bearer attached. The provider's admin API authenticates nobody;
// being able to reach it IS the authorization. So both properties below are
// load-bearing, and they fail for different reasons.
//
// DECLARED, NOT DERIVED. The address falls back to a derivation from the issuer
// ("hydra.X" → "hydra-admin.X", else "https://hydra-admin.<domain>"). A derived
// address is never empty, so the facade reads as configured on a profile that
// never declared it — and the derivation yields the PUBLIC ingress hostname,
// which does not resolve inside the cluster. Every call then fails, or worse,
// eventually resolves to whatever answers on that public name and receives the
// administrative bearer. Requiring the declaration is the platform rule that a
// security-relevant dependency address is never worked out from a neighbour's.
//
// NOT IN THE CLEAR. Same reason the edge gateway's hop is held to it: the bearer
// is readable by anything on the path, and it opens an API that asks for nothing
// else.
//
// Only the explicit sources count as declared — the YAML setting and its ENV
// override — because those are the two an operator actually writes. dev keeps the
// derivation and tolerates plaintext: an in-process fixture has no provider, and
// a developer stand may run one without a certificate.
func (c Config) validateProductionProviderAdminHop() error {
	declared := c.AuthN.DeclaredHydraAdminURL()
	if declared == "" {
		return fmt.Errorf(
			"production mode: authn.hydra-admin-url is not declared (env override " +
				"KACHO_IAM_HYDRA_ADMIN_URL) — it then falls back to a name DERIVED from the " +
				"issuer, which is the public ingress host and does not resolve inside the " +
				"cluster; the derivation is never empty, so the facade reads as configured " +
				"while addressing a host nobody chose. Name the cluster-internal admin " +
				"Service explicitly")
	}
	u, err := url.Parse(declared)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf(
			"production mode: authn.hydra-admin-url is not an absolute http(s) URL (got %q)",
			declared)
	}
	if u.Scheme != "https" {
		return fmt.Errorf(
			"production mode: authn.hydra-admin-url is plaintext (%q) — every OAuth2 client "+
				"registration, trust grant and session teardown carries the administrative "+
				"bearer over this hop, and the admin API it opens authenticates nobody, so "+
				"anything on the path can read the credential and use it; address the admin "+
				"listener over https",
			declared)
	}
	// TLS without an anchor is not a partial improvement here. The provider's
	// in-cluster certificate is issued by the internal CA and this process trusts
	// the system roots, so every call would fail on an unknown authority — after
	// the address already reads as hardened.
	if c.AuthN.ResolveHydraAdminCAFile() == "" {
		return fmt.Errorf(
			"production mode: authn.hydra-admin-url is https (%q) but authn.hydra-admin-ca-file "+
				"is empty (env KACHO_IAM_HYDRA_ADMIN_CA_FILE) — the provider's in-cluster "+
				"certificate is issued by the internal CA and this process trusts the system "+
				"roots, so every call on the hop fails with an unknown authority; pin the "+
				"bundle together with the address",
			declared)
	}
	return nil
}

// providerPublicHop — one of iam's hops to the identity provider's PUBLIC
// listener, as the boot guard sees it: what an operator declared, what anchor was
// pinned with it, and the names to put in a refusal so a stand can be fixed
// without reading this file.
type providerPublicHop struct {
	setting     string
	env         string
	declared    string
	caSetting   string
	caEnv       string
	caFile      string
	whatItISFor string
}

// validateProductionProviderPublicHops holds the two hops to the provider's
// PUBLIC listener to the same discipline the ADMIN hop already has: the address
// is DECLARED, never worked out from a neighbour's, and TLS is never claimed
// without something to verify the peer against.
//
// DECLARED, NOT DERIVED. Both addresses fall back to a derivation from the issuer
// — `<issuer>/.well-known/jwks.json` and `<issuer>/oauth2/token`. A derivation is
// never empty, so the facade reads as configured on a profile that declared
// neither, while addressing the PUBLIC ingress hostname: in-cluster that name
// usually does not resolve at all (the JWKS mirror then fail-closes 502 and every
// docker pull gets a 401, with no line at start-up naming why), and where it does
// resolve it is not the process the operator meant. This is the platform rule that
// the address of a dependency an access decision rests on is never derived.
//
// WHAT EACH HOP CARRIES, because the two are not interchangeable:
//   - the JWKS upstream is the ONLY thing that decides which signatures the
//     data-plane accepts. iam re-serves the fetched keyset verbatim on its
//     cluster-internal mirror, so whatever answers this address chooses the
//     platform's verification keys.
//   - the token endpoint carries a signed client assertion out and the minted
//     bearer back in the response body.
//
// TRANSPORT IS NOT ASSERTED HERE, and that is a boundary, not an oversight. The
// provider serves its public listener in plain http on every profile, and the
// per-listener TLS override this version does NOT support was measured false on
// 2026-07-30 — see the note in
// deploy/helm/umbrella/templates/hydra-admin-certificate.yaml. Moving the public
// listener moves the ingress, the JWKS mirror and the token endpoint together; it
// is its own change with its own acceptance. Requiring https here would only add a
// second reason for the same stand not to boot, and the fix for it would not be
// this guard's.
//
// WHAT IS ASSERTED IS THE HALF THAT CAN BE GOT WRONG SILENTLY: the moment a
// profile writes https, an anchor must be pinned with it. Without one the process
// verifies against the SYSTEM roots, which an internal-CA certificate never chains
// to — so the address reads as hardened while every fetch fails on an unknown
// authority, and the JWKS mirror answers 502 to the whole data-plane.
//
// Only the explicit sources count as declared — the YAML setting and its ENV
// override — because those are the two an operator actually writes. dev keeps the
// derivation and tolerates anything: an in-process fixture has no provider.
func (c Config) validateProductionProviderPublicHops() error {
	hops := []providerPublicHop{
		{
			setting:   "authn.hydra-jwks-url",
			env:       "KACHO_IAM_HYDRA_JWKS_URL",
			declared:  c.AuthN.DeclaredHydraJWKSURL(),
			caSetting: "authn.hydra-jwks-ca-file",
			caEnv:     "KACHO_IAM_HYDRA_JWKS_CA_FILE",
			caFile:    c.AuthN.ResolveHydraJWKSCAFile(),
			whatItISFor: "the keyset this process mirrors on its cluster-internal listener is the " +
				"data-plane's only anchor for deciding whether a token was signed by the provider",
		},
		{
			setting:   "authn.hydra-token-url",
			env:       "KACHO_IAM_HYDRA_TOKEN_URL",
			declared:  c.AuthN.DeclaredHydraTokenURL(),
			caSetting: "authn.hydra-token-ca-file",
			caEnv:     "KACHO_IAM_HYDRA_TOKEN_CA_FILE",
			caFile:    c.AuthN.ResolveHydraTokenCAFile(),
			whatItISFor: "the exchange posts a signed client assertion to this address and reads the " +
				"minted bearer back out of the response body",
		},
	}
	var errs error
	for _, h := range hops {
		if h.declared == "" {
			errs = multierr.Append(errs, fmt.Errorf(
				"production mode: %s is not declared (env override %s) — it then falls back to a "+
					"name DERIVED from the issuer, which is the public ingress host and does not "+
					"resolve inside the cluster; the derivation is never empty, so the facade reads "+
					"as configured while addressing a host nobody chose. %s. Name the cluster-internal "+
					"Service explicitly", h.setting, h.env, h.whatItISFor))
			continue
		}
		u, err := url.Parse(h.declared)
		if err != nil || u.Scheme == "" || u.Host == "" {
			errs = multierr.Append(errs, fmt.Errorf(
				"production mode: %s is not an absolute http(s) URL (got %q)", h.setting, h.declared))
			continue
		}
		if u.Scheme == "https" && h.caFile == "" {
			errs = multierr.Append(errs, fmt.Errorf(
				"production mode: %s is https (%q) but %s is empty (env %s) — the provider's "+
					"in-cluster certificate is issued by the internal CA and this process trusts the "+
					"system roots, so every call on the hop fails with an unknown authority while the "+
					"address reads as hardened; pin the bundle together with the address",
				h.setting, h.declared, h.caSetting, h.caEnv))
		}
	}
	return errs
}

// validateMode ensures Mode is a known ENUM value.
func (c Config) validateMode() error {
	switch c.AuthN.Mode {
	case ModeDev, ModeProduction, ModeProductionStrict:
		return nil
	default:
		return fmt.Errorf("authn.mode invalid (got %s)", c.AuthN.Mode)
	}
}

// validateProductionAuthNSecrets requires the AuthN secrets the binary needs to
// authenticate the Ory hooks. In dev mode these may legitimately be empty (the
// hook handlers accept calls without a Bearer); in any production mode a missing
// secret is a boot-time misconfiguration that would otherwise only surface as a
// runtime fail-closed (availability risk).
//
// The JWKS encryption key is still demanded here even though nothing decrypts
// with it any more: its store (oidc_jwks_keys) was dropped in migration 0065 and
// its rotator in 713f7e1. The requirement is KEPT deliberately — relaxing it
// changes production start-up behaviour and is a separate decision.
//
// Secrets resolve from the YAML field OR the ENV indirection
// (hook-shared-secret-env / jwks-encryption-key-hex-env) — the same precedence
// the composition root uses (cmd/kacho-iam/hooks_mux.go). Only os.Getenv is read
// (no other side-effects), consistent with the Resolve* methods.
//
// Errors name WHICH setting is missing — never the secret value (security.md).
//
// OpenFGA store-id is intentionally NOT validated here: it is provisioned at
// runtime by the openfga-bootstrap-job (which then re-rolls the pod), so an
// empty store-id on first boot is a deliberate, documented fail-closed state
// (a loud WARN + Check-deny in cmd/kacho-iam/env.go), required for the helm
// `--wait` install ordering. Failing Validate on it would break that boot
// sequence.
func (c Config) validateProductionAuthNSecrets() error {
	var errs error
	if strings.TrimSpace(c.AuthN.ResolveHookSharedSecret()) == "" {
		errs = multierr.Append(errs, fmt.Errorf(
			"production mode: authn.hook-shared-secret is empty (set authn.hook-shared-secret-env / KACHO_IAM_HOOK_TOKEN)"))
	}
	if _, err := c.AuthN.ResolveJWKSEncryptionKey(); err != nil {
		// ResolveJWKSEncryptionKey already reports WHICH setting / what shape is
		// wrong (empty, bad hex, wrong length) without echoing the value.
		errs = multierr.Append(errs, fmt.Errorf(
			"production mode: authn.jwks-encryption-key-hex invalid: %w", err))
	}
	return errs
}

// InsecureDevWarnings returns a list of non-blocking warnings about
// insecure dev-defaults. Returns nil in production mode.
func (c Config) InsecureDevWarnings() []string {
	if c.AuthN.Mode.IsProduction() {
		return nil
	}
	var out []string
	mode := strings.ToLower(c.Repository.Postgres.SSLMode)
	if mode == "" || mode == "disable" {
		out = append(out,
			"repository.postgres.ssl-mode=disable — DB plaintext (dev only)")
	}
	return out
}
