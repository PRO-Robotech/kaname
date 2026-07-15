// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// oauth_client_id_test.go — доменная валидация id токенов после перехода на
// конвенцию corelib `ids.NewID` (3-char prefix + 17-char crockford, БЕЗ
// подчёркивания). id существующих строк immutable (id = Hydra client id + JWK
// kid), поэтому валидатор обязан принимать ОБА формата: legacy `<prefix>_<17>` и
// новый `<prefix><17>`.
package domain

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/ids"
)

func TestSAOAuthClientID_Validate_BothFormats(t *testing.T) {
	tests := []struct {
		name    string
		id      SAOAuthClientID
		wantErr bool
	}{
		{name: "new corelib format (no underscore)", id: SAOAuthClientID(ids.NewID(PrefixSAOAuthClient)), wantErr: false},
		{name: "new format literal", id: "soc0123456789abcdefg", wantErr: false},
		{name: "legacy underscore format", id: "soc_0123456789abcdefg", wantErr: false},
		{name: "wrong prefix", id: "uoc0123456789abcdefg", wantErr: true},
		{name: "uppercase body", id: "socABCDEFGHJKMNPQRST", wantErr: true},
		{name: "excluded crockford char i", id: "soc0123456789abcdefi", wantErr: true},
		{name: "too short new format", id: "soc0123456789abcde", wantErr: true},
		{name: "empty", id: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.id.Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("id %q: want error, got nil", tt.id)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("id %q: want nil, got %v", tt.id, err)
			}
		})
	}
}

func TestUserOAuthClientID_Validate_BothFormats(t *testing.T) {
	tests := []struct {
		name    string
		id      UserOAuthClientID
		wantErr bool
	}{
		{name: "new corelib format (no underscore)", id: UserOAuthClientID(ids.NewID(PrefixUserOAuthClient)), wantErr: false},
		{name: "new format literal", id: "uoc0123456789abcdefg", wantErr: false},
		{name: "legacy underscore format", id: "uoc_0123456789abcdefg", wantErr: false},
		{name: "wrong prefix", id: "soc0123456789abcdefg", wantErr: true},
		{name: "uppercase body", id: "uocABCDEFGHJKMNPQRST", wantErr: true},
		{name: "empty", id: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.id.Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("id %q: want error, got nil", tt.id)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("id %q: want nil, got %v", tt.id, err)
			}
		})
	}
}

// TestNewIDGeneratesConformingTokenID — свежесгенерированный id соответствует
// corelib-конвенции (20 символов, без подчёркивания) И проходит доменную
// валидацию соответствующего newtype.
func TestNewIDGeneratesConformingTokenID(t *testing.T) {
	socID := ids.NewID(PrefixSAOAuthClient)
	if strings.Contains(socID, "_") {
		t.Fatalf("new SA token id %q must NOT contain underscore", socID)
	}
	if len(socID) != 20 {
		t.Fatalf("new SA token id %q must be 20 chars, got %d", socID, len(socID))
	}
	if err := SAOAuthClientID(socID).Validate(); err != nil {
		t.Fatalf("freshly-generated SA token id %q must pass domain validate, got %v", socID, err)
	}

	uocID := ids.NewID(PrefixUserOAuthClient)
	if strings.Contains(uocID, "_") {
		t.Fatalf("new user token id %q must NOT contain underscore", uocID)
	}
	if len(uocID) != 20 {
		t.Fatalf("new user token id %q must be 20 chars, got %d", uocID, len(uocID))
	}
	if err := UserOAuthClientID(uocID).Validate(); err != nil {
		t.Fatalf("freshly-generated user token id %q must pass domain validate, got %v", uocID, err)
	}
}
