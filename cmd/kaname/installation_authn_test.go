// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/clientassertion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallationCredentialPrivateClosedInput(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	c := installationCredential{ClientID: "client", KeyID: "key", PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))}
	good, _ := json.Marshal(c)
	for _, tc := range []struct {
		name  string
		body  []byte
		mode  os.FileMode
		valid bool
	}{
		{"private valid", good, 0600, true},
		{"public readable", good, 0644, false},
		{"unknown identity", []byte(`{"principal":"admin"}`), 0600, false},
		{"extra identity", append(append([]byte(nil), good[:len(good)-1]...), []byte(`,"principal":"admin"}`)...), 0600, false},
		{"trailing document", append(append([]byte(nil), good...), []byte(` {}`)...), 0600, false},
		{"oversized", []byte(strings.Repeat(" ", 65537)), 0600, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "installer.json")
			if err := os.WriteFile(path, tc.body, tc.mode); err != nil {
				t.Fatal(err)
			}
			_, _, err := loadInstallationCredential(path)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
			if err != nil && strings.Contains(err.Error(), c.PrivateKeyPEM) {
				t.Fatal("private material exposed")
			}
		})
	}
	if _, _, err := loadInstallationCredential(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("missing credential accepted")
	}
}

func TestInstallationProofFailureClasses(t *testing.T) {
	for _, tc := range []struct {
		outcome clientassertion.Outcome
		code    codes.Code
	}{
		{clientassertion.OutcomeRegistryUnavailable, codes.Unavailable},
		{clientassertion.OutcomeReplayStoreUnavailable, codes.Unavailable},
		{clientassertion.Outcome("bad-signature"), codes.Unauthenticated},
	} {
		if got := status.Code(installationProofFailure(tc.outcome)); got != tc.code {
			t.Fatalf("%s: %v", tc.outcome, got)
		}
	}
}

func TestInstallationResultNeverCarriesDriverOrCredentialCause(t *testing.T) {
	cause := errors.New("driver SQL password=secret privateKeyPem")
	err := failInstallation(quietLogger(), "delegation", "", "account", "delegate", 1, cause)
	var failed *installationFailure
	if !errors.As(err, &failed) || failed.result.CompletedPairs != 1 || failed.result.Code != "INTERNAL" {
		t.Fatalf("result: %v", err)
	}
	if strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "privateKeyPem") {
		t.Fatal("cause exposed")
	}
	if !errors.Is(err, cause) {
		t.Fatal("cause lost for internal diagnostics")
	}
}

func TestInstallationVerifiedContextPreservesParentCancellation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	verified := context.WithValue(context.Background(), installationContextTestKey{}, "verified")
	ctx := installationVerifiedContext{Context: parent, values: verified}
	if ctx.Value(installationContextTestKey{}) != "verified" {
		t.Fatal("verified values lost")
	}
	cancel()
	if ctx.Err() != context.Canceled {
		t.Fatal("parent cancellation lost")
	}
}

type installationContextTestKey struct{}

func TestInstallationScopeIsExplicit(t *testing.T) {
	for _, tc := range []struct {
		scope, target string
		valid         bool
	}{
		{"single-account", "acc00000000000000001", true},
		{"all-accounts", "", true},
		{"single-account", "", false},
		{"all-accounts", "acc00000000000000001", false},
		{"", "", false}, {"arbitrary", "", false},
	} {
		err := validateInstallationScope(config.InstallationConfig{Scope: tc.scope, TargetAccountID: tc.target})
		if (err == nil) != tc.valid {
			t.Fatalf("scope=%q,target=%q: %v", tc.scope, tc.target, err)
		}
	}
}
