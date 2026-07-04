// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// service_account_oauth_client_test.go — domain validation for the
// private_key_jwt shape and the federation-IN (trusted_subjects) shape of the
// SA-OAuth-client mapping.
package domain

import (
	"strings"
	"testing"
)

func TestTrustedSubject_Validate(t *testing.T) {
	tests := []struct {
		name    string
		in      TrustedSubject
		wantErr string // substring; "" = expect nil
	}{
		{
			name:    "ok literal anchored k8s subject",
			in:      TrustedSubject{Issuer: "https://kube.cluster.local", SubjectPattern: "^system:serviceaccount:ci:deployer$"},
			wantErr: "",
		},
		{
			name:    "ok literal anchored ci subject",
			in:      TrustedSubject{Issuer: "https://token.actions.githubusercontent.com", SubjectPattern: "^repo:acme/app:ref:refs/heads/main$"},
			wantErr: "",
		},
		{
			name:    "empty issuer",
			in:      TrustedSubject{Issuer: "", SubjectPattern: "^x$"},
			wantErr: "issuer: required",
		},
		{
			name:    "non-url issuer",
			in:      TrustedSubject{Issuer: "not-a-url", SubjectPattern: "^x$"},
			wantErr: "https URL to a public host",
		},
		{
			name:    "non-https issuer",
			in:      TrustedSubject{Issuer: "http://x.example", SubjectPattern: "^x$"},
			wantErr: "https URL to a public host",
		},
		{
			name:    "loopback issuer (anti-SSRF)",
			in:      TrustedSubject{Issuer: "https://127.0.0.1", SubjectPattern: "^x$"},
			wantErr: "https URL to a public host",
		},
		{
			name:    "localhost issuer (anti-SSRF)",
			in:      TrustedSubject{Issuer: "https://localhost", SubjectPattern: "^x$"},
			wantErr: "https URL to a public host",
		},
		{
			name:    "private-ip issuer (anti-SSRF)",
			in:      TrustedSubject{Issuer: "https://10.1.2.3", SubjectPattern: "^x$"},
			wantErr: "https URL to a public host",
		},
		{
			name:    "empty pattern",
			in:      TrustedSubject{Issuer: "https://x.example", SubjectPattern: ""},
			wantErr: "subject_pattern: required",
		},
		{
			name:    "unanchored pattern",
			in:      TrustedSubject{Issuer: "https://x.example", SubjectPattern: "system:serviceaccount:ci:deployer"},
			wantErr: "literal anchored subject",
		},
		{
			name:    "missing closing anchor",
			in:      TrustedSubject{Issuer: "https://x.example", SubjectPattern: "^system:serviceaccount:ci:deployer"},
			wantErr: "literal anchored subject",
		},
		{
			name:    "wildcard .* pattern",
			in:      TrustedSubject{Issuer: "https://x.example", SubjectPattern: "^system:serviceaccount:ci:.*$"},
			wantErr: "literal anchored subject",
		},
		{
			name:    "glob star pattern",
			in:      TrustedSubject{Issuer: "https://x.example", SubjectPattern: "^system:serviceaccount:ci:*$"},
			wantErr: "literal anchored subject",
		},
		{
			name:    "bare wildcard",
			in:      TrustedSubject{Issuer: "https://x.example", SubjectPattern: ".*"},
			wantErr: "literal anchored subject",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.in.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("want nil, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want err containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

// TestTrustedSubject_LiteralSubject — a valid literal-anchored pattern yields the
// unanchored literal (the exact subject the Hydra trust-grant enforces); a
// non-literal / non-anchored pattern is not extractable.
func TestTrustedSubject_LiteralSubject(t *testing.T) {
	ok := TrustedSubject{Issuer: "https://kube.cluster.local", SubjectPattern: "^system:serviceaccount:ci:deployer$"}
	lit, ok2 := ok.LiteralSubject()
	if !ok2 {
		t.Fatalf("expected literal-anchored pattern to be extractable")
	}
	if lit != "system:serviceaccount:ci:deployer" {
		t.Fatalf("literal = %q; want the unanchored subject", lit)
	}

	bad := TrustedSubject{Issuer: "https://kube.cluster.local", SubjectPattern: "^system:serviceaccount:ci:.*$"}
	if _, ok3 := bad.LiteralSubject(); ok3 {
		t.Fatalf("wildcard pattern must NOT yield a literal subject")
	}
}

func TestSAOAuthClient_Validate_FederatedVsPrivateKey(t *testing.T) {
	base := ServiceAccountOAuthClient{
		ID:              "soc_01abcdefghjkmnpqr",
		SvaID:           "sva_01",
		OAuthClientID:   "hydra-cli",
		CreatedByUserID: "usr_01",
	}

	// Federated row with public_key set → must reject.
	bad := base
	bad.TrustedSubjects = []TrustedSubject{{Issuer: "https://x.example", SubjectPattern: "^x$"}}
	bad.PublicKeyPEM = "fake-pem"
	bad.KeyAlgorithm = "ES256"
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "must not carry public_key_pem") {
		t.Fatalf("want federated/public_key conflict, got %v", err)
	}

	// Federated row clean — must pass.
	ok := base
	ok.TrustedSubjects = []TrustedSubject{{Issuer: "https://x.example", SubjectPattern: "^x$"}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("clean federated must pass, got %v", err)
	}

	// private_key_jwt row — must pass.
	pk := base
	pk.PublicKeyPEM = "fake-spki"
	pk.KeyAlgorithm = "ES256"
	if err := pk.Validate(); err != nil {
		t.Fatalf("private_key_jwt must pass, got %v", err)
	}
}
