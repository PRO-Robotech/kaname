// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"strings"
	"testing"
)

// interactive_client_test.go — IAM-INT-1 scenario 03 (the redirect rule), at the
// layer that owns it.
//
// Every case below is PAIRED. A rejection test alone cannot distinguish "the
// rule holds" from "the validator rejects everything", and a acceptance test
// alone cannot distinguish "the rule holds" from "the validator accepts
// everything" — so each family states both halves.

func TestValidateRedirectURIs_RequiredHalf(t *testing.T) {
	// Negative: an empty required list is refused BY FIELD NAME. The message is
	// contract tone (api-conventions "<field>: required"), not prose.
	if err := ValidateRedirectURIs("redirect_uris", nil, true); err == nil {
		t.Fatal("empty required redirect_uris accepted — a client with no target cannot receive a code")
	} else if err.Error() != "redirect_uris: required" {
		t.Errorf("message %q: want exactly %q (contract tone)", err.Error(), "redirect_uris: required")
	}

	// Positive control: the SAME emptiness is legitimate when the list is
	// optional. Without this half the test above would still pass if the
	// validator refused every empty list, required or not.
	if err := ValidateRedirectURIs("post_logout_redirect_uris", nil, false); err != nil {
		t.Errorf("empty OPTIONAL list rejected: %v", err)
	}
}

func TestValidateRedirectURIs_SchemeHalf(t *testing.T) {
	// Negative: plaintext is where the credential leaks.
	if err := ValidateRedirectURIs("redirect_uris", []string{"http://example.org/cb"}, true); err == nil {
		t.Fatal("http:// redirect accepted — the authorization code would travel in clear")
	} else if !strings.Contains(err.Error(), "redirect_uris") {
		t.Errorf("message %q does not name the field", err.Error())
	}

	// Positive: the legitimate form of the very same input is accepted.
	if err := ValidateRedirectURIs("redirect_uris", []string{"https://example.org/cb"}, true); err != nil {
		t.Errorf("https:// redirect rejected: %v", err)
	}
}

func TestValidateRedirectURIs_RejectsShapesThatCannotReceiveACode(t *testing.T) {
	for name, uri := range map[string]string{
		"relative":     "/auth/callback",
		"no host":      "https:///cb",
		"fragment":     "https://example.org/cb#frag",
		"not a scheme": "example.org/cb",
		"empty entry":  "",
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateRedirectURIs("redirect_uris", []string{uri}, true); err == nil {
				t.Errorf("accepted %q — this target cannot receive the code it would be registered for", uri)
			}
		})
	}
}

func TestValidateRedirectURIs_BoundsArePaired(t *testing.T) {
	mk := func(n int) []string {
		out := make([]string, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, "https://example.org/cb"+strings.Repeat("x", i+1))
		}
		return out
	}
	// At the cap — accepted.
	if err := ValidateRedirectURIs("redirect_uris", mk(maxRedirectURIs), true); err != nil {
		t.Errorf("exactly %d entries rejected: %v", maxRedirectURIs, err)
	}
	// One past the cap — refused.
	if err := ValidateRedirectURIs("redirect_uris", mk(maxRedirectURIs+1), true); err == nil {
		t.Errorf("%d entries accepted — the cap is not enforced", maxRedirectURIs+1)
	}
	// Duplicates are refused: the same target twice is not two targets, and it
	// would be silently deduplicated by the provider — a stored list that does
	// not match what was asked for.
	if err := ValidateRedirectURIs("redirect_uris", []string{"https://a.example/cb", "https://a.example/cb"}, true); err == nil {
		t.Error("duplicate entries accepted")
	}
}

func TestInteractiveClient_ValidateCoversEveryField(t *testing.T) {
	good := InteractiveClient{
		Name:         "console-a",
		RedirectURIs: []string{"https://api.example/auth/callback"},
		Status:       InteractiveClientActive,
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("well-formed client rejected: %v", err)
	}

	// Each mutation below must be caught. The positive above is what makes these
	// meaningful: it proves the validator is not simply refusing everything.
	for name, mutate := range map[string]func(*InteractiveClient){
		"bad name":     func(c *InteractiveClient) { c.Name = "A" },
		"no redirects": func(c *InteractiveClient) { c.RedirectURIs = nil },
		"http redirect": func(c *InteractiveClient) {
			c.RedirectURIs = []string{"http://api.example/cb"}
		},
		"unset status": func(c *InteractiveClient) { c.Status = "" },
		"bogus status": func(c *InteractiveClient) { c.Status = "PENDING" },
		"bad post-logout": func(c *InteractiveClient) {
			c.PostLogoutRedirectURIs = []string{"http://api.example/out"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := good
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Errorf("Validate accepted a client with %s", name)
			}
		})
	}
}
