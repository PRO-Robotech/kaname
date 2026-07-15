// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"go.uber.org/multierr"
)

// ServiceAccountOAuthClient — Class A workload identity (Hydra static client).
//
// private_key_jwt mode: kacho-iam mints an ECDSA P-256 keypair per SA
// key, registers the public JWK with Hydra (`token_endpoint_auth_method =
// private_key_jwt`), and returns the private PEM to the caller exactly once.
// Hydra stores only the JWK; kacho-iam keeps the SPKI public PEM (for
// rotation diagnostics) plus the algorithm. The legacy
// `client_secret_basic` flow is dropped: no secret ever exists.
//
// 1:1 SA→client.
type ServiceAccountOAuthClient struct {
	ID              SAOAuthClientID
	SvaID           ServiceAccountID
	OAuthClientID   OAuthClientID
	Description     Description
	CreatedByUserID UserID
	CreatedAt       time.Time
	ExpiresAt       *time.Time
	LastUsedAt      *time.Time

	// PublicKeyPEM — SPKI-encoded ECDSA P-256 public key registered with
	// Hydra as a JWK. Empty for legacy rows that pre-date the private_key_jwt
	// mode (migrated with DEFAULT '') AND for FEDERATED rows where the
	// key material lives in the external IdP rather than kacho-iam.
	PublicKeyPEM string
	// KeyAlgorithm — JOSE alg of the registered key. One of {"ES256",
	// "RS256", "EdDSA"}. Empty for legacy rows; new private_key_jwt keys
	// always set "ES256"; federated rows leave it empty.
	KeyAlgorithm string

	// TrustedSubjects — federated mode (Federation IN). When non-empty, this SA
	// uses the RFC 7521/7523 jwt-bearer grant with an EXTERNAL IdP rather
	// than the private_key_jwt flow: kacho-iam holds no key
	// material, the Hydra OAuth2 client is registered for
	// `urn:ietf:params:oauth:grant-type:jwt-bearer` with
	// `token_endpoint_auth_method=none`, and Hydra validates incoming
	// assertions against the configured global trusted issuers
	// (helm umbrella `hydra.config.oauth2.grant.jwt` + admin trust-grants).
	// Each entry restricts which external `(iss, sub)` tuples may assert
	// this client. Empty slice = private_key_jwt mode.
	TrustedSubjects []TrustedSubject

	// Name — человекочитаемое имя ключа, выставляется на Issue (create-only,
	// immutable — ресурс несёт только Issue/List/Revoke). Пусто для legacy-строк.
	Name OAuthClientName
	// Labels — произвольные метки ключа, выставляются на Issue (create-only,
	// immutable). Пусто для legacy-строк.
	Labels Labels
}

// TrustedSubject — one (issuer, subject) tuple permitted to assert a federated
// ServiceAccountOAuthClient. `Issuer` MUST match the external OIDC `iss` claim
// verbatim; `SubjectPattern` is a LITERAL-anchored exact subject (`^<literal>$`,
// no regex metacharacters).
//
// The literal-anchored form is required because the enforcement point is Hydra's
// native jwt-bearer trust-grant, which matches an EXACT subject (`allow_any_
// subject=false`) — not a per-client regex engine. kacho-iam is off the request
// path (the pod exchanges its projected token with Hydra directly), so a wildcard
// pattern could not be enforced and is rejected up front (any pod of the cluster
// would otherwise obtain a token). Per-subject wildcard federation would require a
// kacho-side enforcer on the request path.
type TrustedSubject struct {
	Issuer         string
	SubjectPattern string
}

// literalSubjectRe — a subject_pattern anchored with `^…$` around a run of
// characters that are NOT regex metacharacters (so the enclosed text is a literal
// subject, matched exactly by the Hydra trust-grant).
var literalSubjectRe = regexp.MustCompile(`^\^[^.\\*+?()\[\]{}|^$]+\$$`)

// LiteralSubject returns the exact subject enclosed by a valid literal-anchored
// pattern (`^<literal>$` → `<literal>`), and false when the pattern is not a
// literal-anchored subject (wildcard / unanchored / regex metacharacters).
func (ts TrustedSubject) LiteralSubject() (string, bool) {
	if !literalSubjectRe.MatchString(ts.SubjectPattern) {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(ts.SubjectPattern, "^"), "$"), true
}

// Validate — Issuer must be an https URL to a public host (anti-SSRF on the
// trust-config: no non-https / loopback / private / link-local host);
// SubjectPattern must be a literal-anchored exact subject. Length caps mirror the
// proto (≤512 each).
func (ts TrustedSubject) Validate() error {
	var errs error
	switch {
	case ts.Issuer == "":
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument issuer: required"))
	case len(ts.Issuer) > 512:
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument issuer: length must be <=512"))
	case !isPublicHTTPSIssuer(ts.Issuer):
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument issuer: must be an https URL to a public host"))
	}
	switch {
	case ts.SubjectPattern == "":
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument subject_pattern: required"))
	case len(ts.SubjectPattern) > 512:
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument subject_pattern: length must be <=512"))
	default:
		if _, ok := ts.LiteralSubject(); !ok {
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument subject_pattern: must be a literal anchored subject (^...$, no wildcards)"))
		}
	}
	return errs
}

// isPublicHTTPSIssuer — true when raw parses as an https URL whose host is not a
// loopback / private / link-local / unspecified IP and not `localhost`. A DNS
// hostname (including cluster-internal FQDNs like `kube.cluster.local`) passes;
// an IP literal is admitted only when it is a routable public address.
func isPublicHTTPSIssuer(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return false
	}
	host := u.Hostname()
	if host == "" || strings.EqualFold(host, "localhost") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return false
		}
	}
	return true
}

func (c ServiceAccountOAuthClient) Validate() error {
	var errs error
	errs = multierr.Append(errs, c.ID.Validate())
	errs = multierr.Append(errs, c.OAuthClientID.Validate())
	errs = multierr.Append(errs, c.Description.Validate())
	if c.SvaID == "" {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument sva_id: required"))
	}
	if c.CreatedByUserID == "" {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument created_by_user_id: required"))
	}
	if c.ExpiresAt != nil && !c.CreatedAt.IsZero() && !c.ExpiresAt.After(c.CreatedAt) {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument expires_at: must be > created_at"))
	}
	switch c.KeyAlgorithm {
	case "", "ES256", "RS256", "EdDSA":
		// allowed; empty kept for legacy rows AND for federated rows.
	default:
		errs = multierr.Append(errs,
			fmt.Errorf("Illegal argument key_algorithm: must be one of {ES256,RS256,EdDSA}"))
	}
	errs = multierr.Append(errs, c.Name.Validate())
	errs = multierr.Append(errs, c.Labels.Validate())
	for i, ts := range c.TrustedSubjects {
		if err := ts.Validate(); err != nil {
			errs = multierr.Append(errs, fmt.Errorf("trusted_subjects[%d]: %w", i, err))
		}
	}
	// A federated row (TrustedSubjects non-empty) must NOT carry private-key
	// material; conversely a private_key_jwt row must carry public PEM. The
	// reverse direction (legacy rows with empty PublicKeyPEM AND no trusted
	// subjects) is permitted for backwards-compat on baseline DEFAULT '' rows.
	if len(c.TrustedSubjects) > 0 && (c.PublicKeyPEM != "" || c.KeyAlgorithm != "") {
		errs = multierr.Append(errs, fmt.Errorf(
			"Illegal argument: federated SA-key (trusted_subjects set) must not carry public_key_pem / key_algorithm"))
	}
	return errs
}

// SAOAuthClientID — новый формат `soc<17-crockford>` (corelib `ids.NewID`, без
// подчёркивания). id существующих строк immutable (id = Hydra client id + JWK
// kid), поэтому валидатор принимает и legacy `soc_<17-crockford>`.
type SAOAuthClientID string

var socIDRe = regexp.MustCompile(`^soc_?[0-9a-hjkmnp-tv-z]{17}$`)

func (id SAOAuthClientID) Validate() error {
	if !socIDRe.MatchString(string(id)) {
		return fmt.Errorf("Illegal argument id: must match ^soc_?[0-9a-hjkmnp-tv-z]{17}$")
	}
	return nil
}

// OAuthClientID — opaque hydra client id (length 1..128, [A-Za-z0-9._:-]).
type OAuthClientID string

var oauthClientIDRe = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

func (h OAuthClientID) Validate() error {
	s := string(h)
	if len(s) < 1 || len(s) > 128 {
		return fmt.Errorf("Illegal argument hydra_client_id: length must be 1..128")
	}
	if !oauthClientIDRe.MatchString(s) {
		return fmt.Errorf("Illegal argument hydra_client_id: must match [A-Za-z0-9._:-]+")
	}
	return nil
}
