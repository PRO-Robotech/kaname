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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/clientassertion"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
			// Фикстура задаёт точные права: umask не должен скрывать публичное чтение.
			if err := os.Chmod(path, tc.mode); err != nil {
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

func TestInstallationTargetPresence(t *testing.T) {
	empty := ""
	malformed := "not-an-account"
	for _, tc := range []struct {
		name   string
		target *string
		valid  bool
	}{
		{"omitted all accounts", nil, true}, {"explicit empty", &empty, false}, {"malformed", &malformed, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateInstallationInput(config.ModuleSeedInstallerConfig{TenantAccountID: tc.target})
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
		})
	}
}

func TestInstallationPaceWaitHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := status.Code(waitInstallationExchange(ctx, time.Hour)); got != codes.Canceled {
		t.Fatalf("cancel: %v", got)
	}
	if got := status.Code(waitInstallationExchange(context.Background(), 0)); got != codes.ResourceExhausted {
		t.Fatalf("invalid retry: %v", got)
	}
	start := time.Now()
	if err := waitInstallationExchange(context.Background(), 5*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 5*time.Millisecond {
		t.Fatal("retry-after ignored")
	}
}

// Узкий контроль границы ошибки: база данных здесь не заменяется и не имитируется.
// Зависимости изменения nil делают вход в операцию GD после неудачной переписи фатальным.
type installationCensusError struct {
	installationReadSource
	cause error
}

func (r installationCensusError) InstallationAccounts(context.Context, string, int) ([]domain.AccountID, domain.AccountID, error) {
	return nil, "", r.cause
}
func TestInstallationCensusFailureCoordinatesBeforeOperation(t *testing.T) {
	cause := errors.New("driver secret-value")
	err := applyInstallationDelegations(context.Background(), quietLogger(), nil, nil, installationCensusError{cause: cause}, nil, nil, nil, nil, "", 2, []*manifest.Manifest{{Seed: &manifest.Seed{GrantDelegations: []manifest.GrantDelegation{{}}}}})
	var failed *installationFailure
	if !errors.As(err, &failed) {
		t.Fatalf("result: %v", err)
	}
	if failed.result.Stage != "census" || failed.result.Field != "accounts" || failed.result.Code != "INTERNAL" || failed.result.CompletedPairs != 0 {
		t.Fatalf("result: %+v", failed.result)
	}
	if strings.Contains(err.Error(), "secret-value") {
		t.Fatal("driver value exposed")
	}
}
