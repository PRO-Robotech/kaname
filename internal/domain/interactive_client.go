// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.uber.org/multierr"
)

// InteractiveClientID — id of an InteractiveClient. Hyphen canon `ic-<17>`
// (ids.PrefixInteractiveClientHyphen), immutable for the life of the resource
// and the only externally addressable identity (core rule #15).
type InteractiveClientID string

// InteractiveClientName — cluster-unique cosmetic label. Judged by the single
// resource-name form of the tree, so the DB CHECK and this validator agree.
type InteractiveClientName string

// Validate — единственная форма имени (`pkg/validate/nameform`).
func (n InteractiveClientName) Validate() error { return validateResourceName("name", string(n)) }

// InteractiveClientStatus — lifecycle status.
type InteractiveClientStatus string

// InteractiveClientStatus values. Mirrored by a DB CHECK.
const (
	InteractiveClientActive   InteractiveClientStatus = "ACTIVE"
	InteractiveClientDeleting InteractiveClientStatus = "DELETING"
)

// Validate — the status is one of the two named values.
func (s InteractiveClientStatus) Validate() error {
	switch s {
	case InteractiveClientActive, InteractiveClientDeleting:
		return nil
	default:
		return fmt.Errorf("Illegal argument status: must be ACTIVE or DELETING")
	}
}

// InteractiveClient — the OAuth2 client through which a HUMAN completes an
// interactive sign-in ceremony.
//
// Provider-side fields (ClientID, Audiences, GrantTypes, TokenEndpointAuthMethod)
// are OUTPUT-ONLY: they are decided by iam and the identity provider, never by
// the caller. Audiences in particular is a decision, not an omission — see Р2 in
// the acceptance: a field that can be set but cannot be set CORRECTLY is a field
// without a reader, and one that can be set incorrectly breaks the edge silently.
type InteractiveClient struct {
	ID          InteractiveClientID
	CreatedAt   time.Time
	Name        InteractiveClientName
	Description Description
	Labels      Labels

	// RedirectURIs — where the provider may deliver an authorization code.
	// At least one, every one an absolute https:// URL.
	RedirectURIs []string
	// PostLogoutRedirectURIs — optional; same https:// rule when present.
	PostLogoutRedirectURIs []string

	// ClientID — provider-side client id (output-only).
	ClientID string
	// Audiences — stamped by iam from its own configuration (output-only).
	Audiences []string
	// GrantTypes — always exactly authorization_code + refresh_token (output-only).
	GrantTypes []string
	// TokenEndpointAuthMethod — provider-side auth method (output-only).
	TokenEndpointAuthMethod string

	Status InteractiveClientStatus
}

// Validate — self-validating domain entity.
func (c InteractiveClient) Validate() error {
	var errs error
	errs = multierr.Append(errs, c.Name.Validate())
	errs = multierr.Append(errs, c.Description.Validate())
	errs = multierr.Append(errs, c.Labels.Validate())
	errs = multierr.Append(errs, c.Status.Validate())
	errs = multierr.Append(errs, ValidateRedirectURIs("redirect_uris", c.RedirectURIs, true))
	errs = multierr.Append(errs, ValidateRedirectURIs("post_logout_redirect_uris", c.PostLogoutRedirectURIs, false))
	return errs
}

// maxRedirectURIs — a client with an unbounded target list is a stored
// amplification surface: every entry is somewhere a credential may be sent, and
// the whole list travels to the provider on every write. The cap is stated here
// and mirrored by a DB CHECK so no writer can exceed it.
const maxRedirectURIs = 16

// maxRedirectURILen — bound per entry, mirrored by the same DB CHECK.
const maxRedirectURILen = 512

// ValidateRedirectURIs — the redirect rule, exported because both the Create and
// the Update path must apply exactly the same one (api-conventions: a mutable
// field is validated on Update by the same rules as on Create).
//
// WHY https IS NOT COSMETIC. A redirect target is where the authorization code —
// a credential — is delivered. A plaintext target hands it to anyone on the
// path; a relative or opaque one lets the provider's own matching rules decide
// where it lands. Both are rejected here rather than left to the provider,
// because the provider's answer arrives too late to be a contract: the caller
// would see a peer error instead of a named field.
func ValidateRedirectURIs(field string, uris []string, required bool) error {
	if len(uris) == 0 {
		if required {
			return fmt.Errorf("%s: required", field)
		}
		return nil
	}
	if len(uris) > maxRedirectURIs {
		return fmt.Errorf("Illegal argument %s: at most %d entries", field, maxRedirectURIs)
	}
	seen := make(map[string]struct{}, len(uris))
	var errs error
	for _, raw := range uris {
		if raw == "" {
			errs = multierr.Append(errs, fmt.Errorf("Illegal argument %s: entry must not be empty", field))
			continue
		}
		if len(raw) > maxRedirectURILen {
			errs = multierr.Append(errs, fmt.Errorf("Illegal argument %s: entry longer than %d chars", field, maxRedirectURILen))
			continue
		}
		if _, dup := seen[raw]; dup {
			errs = multierr.Append(errs, fmt.Errorf("Illegal argument %s: duplicate entry", field))
			continue
		}
		seen[raw] = struct{}{}

		u, err := url.Parse(raw)
		if err != nil {
			errs = multierr.Append(errs, fmt.Errorf("Illegal argument %s: entry is not a valid URL", field))
			continue
		}
		if u.Scheme != "https" {
			errs = multierr.Append(errs, fmt.Errorf("Illegal argument %s: entry must be an absolute https:// URL", field))
			continue
		}
		if u.Host == "" {
			errs = multierr.Append(errs, fmt.Errorf("Illegal argument %s: entry must name a host", field))
			continue
		}
		// A fragment is never sent to the server, so a target carrying one
		// cannot receive the code it was registered for.
		if u.Fragment != "" || strings.Contains(raw, "#") {
			errs = multierr.Append(errs, fmt.Errorf("Illegal argument %s: entry must not carry a fragment", field))
			continue
		}
	}
	return errs
}
