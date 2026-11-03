// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	given    *ceremonyWorld
	stand    *installruntime.NativeStand
	session  *installruntime.Session
	wire     *installruntime.Wire
	operator *installruntime.VerifiedOperator
	creator  *installruntime.StandingCreator
	base     *installruntime.Process
	secrets  []string
}

func newInstallationNativeWorld(t *testing.T) *installationNativeWorld {
	t.Helper()
	deadline, ok := t.Deadline()
	require.True(t, ok, "bounded Go test deadline required for native lifecycle")
	ctx, cancelLifetime := context.WithDeadline(context.Background(), deadline)
	t.Cleanup(cancelLifetime)
	root, err := filepath.Abs("../..")
	require.NoError(t, err)
	evidenceRoot := os.Getenv("KANAME_RID_EVIDENCE")
	require.True(t, filepath.IsAbs(evidenceRoot), "FIXTURE_INCOMPLETE: private absolute RID evidence directory required")
	require.NoError(t, os.MkdirAll(evidenceRoot, 0700))
	evidence := filepath.Join(evidenceRoot, strings.ReplaceAll(t.Name(), "/", "-"))
	stand := installruntime.PrepareNativeStand(t, ctx, root, evidence, false)
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
	w.seedPerson()
	w.markPerson()
	w.session = w.seedSession("2")
	w.ic1 = w.seedClient("rid-native-operator", domain.InteractiveClientActive, []string{lineA1R})
	var admins, delegations, issuers int
	require.NoError(t, pool.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM kaname.cluster_admin_grants),
 (SELECT count(*) FROM kaname.grant_delegations),
 (SELECT count(*) FROM kaname.service_accounts WHERE name IN ('svc-ridfirst','svc-ridsecond'))`).Scan(&admins, &delegations, &issuers))
	require.Zero(t, admins, "O must have no admin grant before actual startup bootstrap")
	require.Zero(t, delegations)
	require.Zero(t, issuers)
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
	f := &installationNativeWorld{given: w, stand: stand, session: session, wire: wire, secrets: []string{w.ic1.secret, w.session.bearer.CookieValue()}}
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
	_, system, err := kanamepg.NewInstallationReader(pool).InstallationAccounts(ctx, "", 2)
	require.NoError(t, err)
	f.creator, err = wire.ProvisionStandingCreator(ctx, f.operator, string(system), filepath.Join(evidence, "standing-creator.json"))
	require.NoError(t, err)
	f.secrets = append(f.secrets, f.creator.SecretMaterial()...)
	require.NotEqual(t, string(w.user), f.creator.ID)
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
	var count int
	require.NoError(t, f.given.pool.QueryRow(t.Context(), `SELECT count(*) FROM kaname.grant_delegations WHERE status='ACTIVE' AND module IN ('ridfirst','ridsecond')`).Scan(&count))
	require.Equal(t, 2, count, "one initial tenant and two delivered issuer pairs")
	// Keep real process/state available to the identity assertions while proving
	// that O's ceremony still works after the full delivery restart.
	f.renewOperator(t, t.Context())
}
