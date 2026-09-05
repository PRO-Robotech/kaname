// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_hop_tls.go — one implementation of "verify this hop against the anchor
// the operator pinned, and against nothing else", shared by every hop iam makes to
// the identity provider.
//
// It exists because there were three hops and one of them had the property. The
// admin hop was moved to TLS with a pinned anchor and a boot guard; the two hops to
// the provider's PUBLIC listener — the token exchange and the JWKS upstream — were
// still built as `&http.Client{Timeout: …}`, i.e. with no way to be given an anchor
// at all. That is not merely a missing knob: it made the obvious fix impossible,
// because flipping such an address to https lands on the SYSTEM roots, which an
// internal-CA certificate never chains to. So "cannot be done" was true of the
// code and read as true of the platform.
//
// Keeping one implementation is the point. The next hop added to the facade gets
// the property by construction instead of by whoever remembers to copy it.
package clients

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Settings naming each hop's trust anchor. Held as constants so a refusal names
// the thing an operator edits, in both the YAML and the ENV spelling.
const (
	adminHopCASetting = "authn.hydra-admin-ca-file (env KACHO_IAM_HYDRA_ADMIN_CA_FILE)"
	// #nosec G101 -- the name of a setting an operator edits, not a credential.
	// The value is a CA *file path* setting for the token-exchange hop; the rule
	// matches on the identifier containing "token". Same class, and same treatment,
	// as the header/metadata key names in gateway/internal/principalmeta/keys.go.
	tokenHopCASetting = "authn.hydra-token-ca-file (env KACHO_IAM_HYDRA_TOKEN_CA_FILE)"
	// JWKSHopCASetting is exported because the JWKS upstream client is assembled
	// at the composition root (the mirror handler takes an injected client), so
	// the refusal has to be able to name the setting from there.
	JWKSHopCASetting = "authn.hydra-jwks-ca-file (env KACHO_IAM_HYDRA_JWKS_CA_FILE)"
)

// ProviderHopHTTPClient builds the HTTP client for one hop to the identity
// provider: a per-call timeout always, and the pinned anchor when one is
// configured.
//
// caFile empty ⇒ the default transport, unchanged. That is not an oversight: an
// in-cluster listener served over plaintext http needs no anchor, and inventing
// one would refuse a stand deliberately configured that way. The production boot
// guard (config.Validate) is what forbids claiming https without one.
//
// caFile set ⇒ the returned client trusts that bundle ALONE. Not "in addition to
// the system roots": an internal-CA hop has no business accepting a publicly
// issued certificate for the same name, and narrowing the anchor is the whole
// point of pinning it.
//
// An anchor that cannot be read, or that holds no certificate, is an ERROR rather
// than a fallback. Continuing on the system roots would produce the one state
// nobody can see — the operator has configured verification against the internal
// CA, the process is not doing it, and everything works until a certificate
// rotates.
func ProviderHopHTTPClient(timeout time.Duration, caFile, setting string) (*http.Client, error) {
	c := &http.Client{Timeout: timeout}
	if strings.TrimSpace(caFile) == "" {
		return c, nil
	}

	// #nosec G304 -- путь к корневому сертификату задаёт оператор в настройках процесса;
	// на вход запроса он не приходит. Пустой путь отсечён выше, нечитаемый — отказ старта.
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf(
			"%s=%q cannot be read (%w) — refusing: continuing on the system root store "+
				"would leave the hop to the identity provider unverified against the internal "+
				"CA while reading as configured", setting, caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf(
			"%s=%q holds no PEM certificate — refusing: the resulting trust store would "+
				"be EMPTY, so every handshake on this hop to the identity provider would "+
				"fail permanently", setting, caFile)
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	c.Transport = tr
	return c, nil
}
