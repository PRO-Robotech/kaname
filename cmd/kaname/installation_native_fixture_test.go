// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	"github.com/stretchr/testify/require"
)

// installationNativeWorld is the actual F0→O→C→full-delivery path. Its only
// inserted Given is the previously approved initial user/session/client. No
// model/seed/bootstrap helper executes in the test process: all those steps run
// inside the frozen native production executable using its real listener chain.
type installationNativeWorld struct {
	given            *ceremonyWorld
	stand            *installruntime.NativeStand
	session          *installruntime.Session
	wire             *installruntime.Wire
	operator         *installruntime.VerifiedOperator
	creator          *installruntime.StandingCreator
	base             *installruntime.Process
	secrets          []string
	baseline         nativeBaseline
	tenantID         string
	credentialDigest [32]byte
}

func newInstallationNativeWorld(t *testing.T) *installationNativeWorld {
	t.Helper()
	requireNativeManifestPremise(t)
	deadline, ok := t.Deadline()
	require.True(t, ok, "bounded Go test deadline required for native lifecycle")
	ctx, cancelLifetime := context.WithDeadline(context.Background(), deadline)
	t.Cleanup(cancelLifetime)
	root, err := filepath.Abs("../..")
	require.NoError(t, err)
	evidenceRoot := os.Getenv("KANAME_RID_EVIDENCE")
	require.True(t, filepath.IsAbs(evidenceRoot), "FIXTURE_INCOMPLETE: private absolute RID evidence directory required")
	evidence, err := installruntime.EvidenceDirectory(evidenceRoot, t.Name())
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(evidenceRoot, 0700))
	stand := installruntime.PrepareNativeStand(t, ctx, root, evidence, false)
	identity, err := json.Marshal(map[string]string{"testIdentity": t.Name()})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(evidence, "test-identity.json"), identity, 0600))
	environment, err := stand.Environment(nil)
	require.NoError(t, err)
	require.NoError(t, stand.RunMigrator(ctx, os.Getenv("KANAME_RID_MIGRATOR"), environment))
	pool, err := coredb.NewPool(ctx, fmt.Sprintf("postgres://kaname:stand@127.0.0.1:%s/kaname?sslmode=require&options=-c%%20search_path%%3Dkaname%%2Cpublic&pool_max_conns=2", stand.PGPort))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	// Reuse exactly the established ceremony Given writers, without building its
	// in-process token surface, signer, permission model or bootstrap admin.
	w := &ceremonyWorld{t: t, id: "RID-NATIVE-F0", ctx: ctx, pool: pool, logs: &lockedBuffer{}, clientAudiences: []string{"https://kaname.local"}}
	w.requireStorePremise()
	baseline := readNativeBaseline(t, w)
	require.Len(t, baseline.ServiceAccounts, 2, "stock bootstrap and gateway identities remain")
	require.Len(t, baseline.AdminGrants, 1, "stock bootstrap admin is part of F0")
	require.Contains(t, baseline.ServiceAccounts, "svab91854890de887e6d")
	require.Contains(t, baseline.ServiceAccounts, "sva3e9556e76be67f816")
	requireNativeAuthority(t, w, "service_account", "svab91854890de887e6d", 1)
	requireNativeNoDelivery(t, w)
	var tenantsBefore int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.accounts WHERE id<>$1`, baseline.SystemID).Scan(&tenantsBefore))
	require.Zero(t, tenantsBefore)
	writeNativeBaseline(t, evidence, baseline)
	w.seedPerson()
	w.markPerson()
	w.session = w.seedSession("2")
	w.ic1 = w.seedClient("rid-native-operator", domain.InteractiveClientActive, []string{lineA1R})
	baseline.requirePreserved(t, w, 0, 0)
	require.NotEqual(t, baseline.SystemOwner, string(w.user))
	requireNativeAuthority(t, w, "user", string(w.user), 0)
	requireNativeNoDelivery(t, w)
	var tenantID string
	require.NoError(t, pool.QueryRow(ctx, `SELECT id FROM kaname.accounts WHERE owner_user_id=$1`, string(w.user)).Scan(&tenantID))
	tenants, system, err := kanamepg.NewInstallationReader(pool).InstallationAccounts(ctx, "", 2)
	require.NoError(t, err)
	require.Equal(t, baseline.SystemID, string(system))
	require.Equal(t, []domain.AccountID{domain.AccountID(tenantID)}, tenants, "actual initial snapshot contains only O's tenant")
	// The only changed startup fact is O's email. Audience, issuer, authority,
	// lifetime and gateway policy remain the ordinary stand profile.
	environment, err = stand.Environment(map[string]string{"KANAME_BOOTSTRAP_ROOT_EMAIL": w.email})
	require.NoError(t, err)
	stand.StartMailbox(t, ctx, environment)
	wire, err := installruntime.NewWire(filepath.Join(evidence, "pki"), "https://localhost:9098", "https://localhost:9096", "https://localhost:9097")
	require.NoError(t, err)
	t.Cleanup(wire.Close)
	session := &installruntime.Session{Binary: os.Getenv("KANAME_RID_BINARY"), BinarySHA256: os.Getenv("KANAME_RID_BINARY_SHA256"),
		Environment: environment, Root: evidence, Probe: wire.ListenersReady}
	f := &installationNativeWorld{given: w, stand: stand, session: session, wire: wire, secrets: []string{w.ic1.secret, w.session.bearer.CookieValue()}, baseline: baseline, tenantID: tenantID}
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := session.Stop(stop); err != nil {
			t.Errorf("native shutdown: %v", err)
		}
		for _, process := range session.History {
			require.NoError(t, process.CheckSecretAbsence(f.secrets...))
		}
	})
	base, err := session.StartBase(ctx)
	require.NoError(t, err)
	require.NoError(t, base.OwnsListeners(9090, 9091, 9095, 9096, 9097, 9098, 9099, 9100))
	f.base = base
	f.renewOperator(t, ctx)
	authority, cancelAuthority := context.WithTimeout(ctx, 60*time.Second)
	err = wire.AwaitOperatorAdmin(authority, f.operator)
	cancelAuthority()
	require.NoError(t, err, "actual asynchronous bootstrap must grant O before provisioning C")
	requireNativeAuthority(t, w, "user", string(w.user), 1)
	baseline.requirePreserved(t, w, 0, 1)
	requireNativeNoDelivery(t, w)
	f.creator, err = wire.ProvisionStandingCreator(ctx, f.operator, string(system), filepath.Join(evidence, "standing-creator.json"))
	require.NoError(t, err)
	f.secrets = append(f.secrets, f.creator.SecretMaterial()...)
	credential, err := os.ReadFile(f.creator.CredentialFile)
	require.NoError(t, err)
	f.credentialDigest = sha256.Sum256(credential)
	info, err := os.Stat(f.creator.CredentialFile)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	require.NotEqual(t, string(w.user), f.creator.ID)
	require.NotContains(t, baseline.ServiceAccounts, f.creator.ID)
	require.Equal(t, baseline.SystemID, f.creator.AccountID)
	requireNativeAuthority(t, w, "service_account", f.creator.ID, 1)
	baseline.requirePreserved(t, w, 1, 2)
	requireNativeNoDelivery(t, w)
	operations := []installruntime.Operation{f.creator.CreateOperation, f.creator.GrantOperation, f.creator.KeyOperation}
	seen := map[string]bool{}
	for _, op := range operations {
		require.NotEmpty(t, op.ID)
		require.False(t, seen[op.ID])
		seen[op.ID] = true
		require.True(t, op.Done)
		require.Nil(t, op.Error)
	}
	return f
}

func (f *installationNativeWorld) renewOperator(t *testing.T, ctx context.Context) {
	t.Helper()
	var err error
	f.operator, err = f.wire.ExchangeOperator(ctx, installruntime.OperatorGiven{UserID: string(f.given.user),
		SessionBearer: f.given.session.bearer.CookieValue(), ClientID: f.given.ic1.rec.ClientID,
		ClientSecret: f.given.ic1.secret, RedirectURI: lineA1R})
	require.NoError(t, err)
	f.secrets = append(f.secrets, f.operator.Bearer())
}

func (f *installationNativeWorld) apply(t *testing.T, input installruntime.DeliveryInput) *installruntime.Process {
	t.Helper()
	stop, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	require.NoError(t, f.session.Stop(stop))
	cancel()
	require.NoError(t, f.base.CheckSecretAbsence(append(f.creator.SecretMaterial(), f.operator.Bearer(), f.given.ic1.secret, f.given.session.bearer.CookieValue())...))
	process, err := f.session.StartDelivery(f.given.ctx, input)
	require.NoError(t, err)
	ready, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	require.NoError(t, process.AwaitReady(ready, f.wire.ListenersReady))
	require.NoError(t, process.OwnsListeners(9090, 9091, 9095, 9096, 9097, 9098, 9099, 9100))
	require.NoError(t, process.CheckSecretAbsence(append(f.creator.SecretMaterial(), f.operator.Bearer())...))
	return process
}

// This predicate asserts only the full native installation path. Subsequent
// RID01 predicates separately assert complete axes, expiry and failure twins.
func ridNativeFirstInstall(t *testing.T) {
	f := newInstallationNativeWorld(t)
	process := f.apply(t, installruntime.DeliveryInput{Manifests: installruntime.NewRIDDeliveryFixture(), CredentialFile: f.creator.CredentialFile})
	results, err := process.Results()
	require.NoError(t, err)
	require.Len(t, results, 1, "actual full serve must publish exactly one structured installation result")
	var result installationResult
	require.NoError(t, json.Unmarshal(results[0], &result))
	require.Equal(t, "delegation", result.Stage)
	require.Equal(t, "OK", result.Code)
	require.Equal(t, 2, result.CompletedPairs)
	f.requireDeliveredPairs(t)
	credential, err := os.ReadFile(f.creator.CredentialFile)
	require.NoError(t, err)
	require.True(t, f.credentialDigest == sha256.Sum256(credential), "full serve retains the same standing credential")
	// Keep real process/state available to the identity assertions while proving
	// that O's ceremony still works after the full delivery restart.
	f.renewOperator(t, t.Context())
}
