// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// oauth_client_name_test.go — доменная валидация имени токена (OAuthClientName):
// имя опционально (пустое допустимо — токен может нести только description), а
// непустое обязано следовать той же kebab-конвенции, что и остальные iam-имена
// (`^[a-z][-a-z0-9]{2,62}$`).
package domain

import (
	"strings"
	"testing"
)

func TestOAuthClientName_Validate(t *testing.T) {
	tests := []struct {
		name    string
		in      OAuthClientName
		wantErr string // substring; "" = expect nil
	}{
		{name: "empty is allowed (description-only token)", in: "", wantErr: ""},
		{name: "valid kebab", in: "prod-ci-key", wantErr: ""},
		{name: "valid kebab with digits", in: "token-2026", wantErr: ""},
		{name: "min length 3", in: "abc", wantErr: ""},
		{name: "uppercase rejected", in: "My-Token", wantErr: "Illegal argument name"},
		{name: "leading digit rejected", in: "1token", wantErr: "Illegal argument name"},
		{name: "underscore rejected", in: "my_token", wantErr: "Illegal argument name"},
		{name: "space rejected", in: "My Token", wantErr: "Illegal argument name"},
		{name: "too short (2 chars)", in: "ab", wantErr: "Illegal argument name"},
		{name: "leading dash rejected", in: "-token", wantErr: "Illegal argument name"},
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

// TestSAOAuthClient_Validate_NameKebab — имя интегрировано в self-validating
// инвариант SA-token: пустое проходит, валидный kebab проходит, невалидный
// (uppercase/underscore) — отвергается по единому текстовому контракту.
func TestSAOAuthClient_Validate_NameKebab(t *testing.T) {
	base := ServiceAccountOAuthClient{
		ID:              "soc01abcdefghjkmnpqr",
		SvaID:           "sva_01",
		OAuthClientID:   "hydra-cli",
		CreatedByUserID: "usr_01",
	}

	empty := base // имя опущено
	if err := empty.Validate(); err != nil {
		t.Fatalf("empty name must pass, got %v", err)
	}

	ok := base
	ok.Name = "prod-ci-key"
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid kebab name must pass, got %v", err)
	}

	bad := base
	bad.Name = "Bad_Name"
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "Illegal argument name") {
		t.Fatalf("want name kebab rejection, got %v", err)
	}
}

// TestUserOAuthClient_Validate_NameKebab — то же для user-token.
func TestUserOAuthClient_Validate_NameKebab(t *testing.T) {
	base := UserOAuthClient{
		ID:              "uoc01abcdefghjkmnpqr",
		UserID:          "usr_01",
		OAuthClientID:   "hydra-cli",
		CreatedByUserID: "usr_01",
	}

	empty := base
	if err := empty.Validate(); err != nil {
		t.Fatalf("empty name must pass, got %v", err)
	}

	ok := base
	ok.Name = "laptop-token"
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid kebab name must pass, got %v", err)
	}

	bad := base
	bad.Name = "Laptop Token"
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "Illegal argument name") {
		t.Fatalf("want name kebab rejection, got %v", err)
	}
}
