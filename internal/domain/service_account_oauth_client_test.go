// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// service_account_oauth_client_test.go — domain validation for Phase 3a
// (private_key_jwt) and Phase 3b (federation IN) shapes of the SA-OAuth-
// client mapping.
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
			name:    "ok github",
			in:      TrustedSubject{Issuer: "https://token.actions.githubusercontent.com", SubjectPattern: "^repo:acme/.+:ref:refs/heads/main$"},
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
			wantErr: "absolute URL",
		},
		{
			name:    "empty pattern",
			in:      TrustedSubject{Issuer: "https://x.example", SubjectPattern: ""},
			wantErr: "subject_pattern: required",
		},
		{
			name:    "bad regex",
			in:      TrustedSubject{Issuer: "https://x.example", SubjectPattern: "(["},
			wantErr: "invalid RE2 regex",
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

	// Phase 3a private_key_jwt row — must pass.
	pk := base
	pk.PublicKeyPEM = "fake-spki"
	pk.KeyAlgorithm = "ES256"
	if err := pk.Validate(); err != nil {
		t.Fatalf("private_key_jwt must pass, got %v", err)
	}
}
