// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"gopkg.in/yaml.v3"
)

// Only declared URL replaces split address knobs; this is ordinary documented
// config. application_name gives independent DB attribution to each serve PID.
// ReplicaBudget=2 declares the actual deployment, not a pool/admission override.
func nativeConcurrentEnvironment(t *testing.T, f *installationNativeWorld, ports installruntime.NativePorts, label string) []string {
	t.Helper()
	values := map[string]string{}
	for _, entry := range f.session.Environment {
		k, v, _ := strings.Cut(entry, "=")
		values[k] = v
	}
	for _, key := range []string{"KANAME_DB_HOST", "KANAME_DB_PORT", "KANAME_DB_USER", "KANAME_DB_NAME"} {
		delete(values, key)
	}
	overrides, err := ports.EnvironmentOverrides()
	require.NoError(t, err)
	for k, v := range overrides {
		values[k] = v
	}
	values["KANAME_REPOSITORY__POSTGRES__URL"] = fmt.Sprintf("postgres://kaname@127.0.0.1:%s/kaname?sslmode=require&application_name=%s", f.stand.PGPort, label)
	values["KANAME_REPOSITORY__POSTGRES__REPLICA_BUDGET"] = "2"
	names := make([]string, 0, len(values))
	for k := range values {
		names = append(names, k)
	}
	sort.Strings(names)
	result := make([]string, 0, len(names))
	for _, k := range names {
		result = append(result, k+"="+values[k])
	}
	return result
}

func nativeWithoutDelegations(t *testing.T, in installruntime.RIDDeliveryFixture) installruntime.RIDDeliveryFixture {
	t.Helper()
	strip := func(raw []byte) []byte {
		var doc map[string]any
		require.NoError(t, yaml.Unmarshal(raw, &doc))
		seed, ok := doc["seed"].(map[string]any)
		require.True(t, ok)
		delete(seed, "grantDelegations")
		changed, err := yaml.Marshal(doc)
		require.NoError(t, err)
		return changed
	}
	return installruntime.RIDDeliveryFixture{First: strip(in.First), Second: strip(in.Second)}
}

// Initial ceremony consumes one admission. Exactly two ordinary public creates
// complete S2; no other owner, fake identity, SQL writer or window adjustment.
func (f *installationNativeWorld) createRID02Accounts(t *testing.T) []string {
	t.Helper()
	f.renewOperator(t, f.given.ctx)
	ids := []string{f.tenantID}
	for _, name := range []string{"rid02-b", "system-tenant"} {
		var op installruntime.Operation
		code, err := f.wire.JSON(f.given.ctx, http.MethodPost, "/iam/v1/accounts", f.operator.Bearer(), map[string]string{"name": name}, &op)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
		op, err = f.wire.AwaitOperation(f.given.ctx, f.operator.Bearer(), op)
		require.NoError(t, err)
		var account struct {
			ID          string `json:"id"`
			OwnerUserID string `json:"ownerUserId"`
		}
		require.NoError(t, json.Unmarshal(op.Response, &account))
		require.NotEmpty(t, account.ID)
		var got iamv1.Account
		f.publicRead(t, "/iam/v1/accounts/"+account.ID, &got)
		require.Equal(t, account.ID, got.Id)
		var owner string
		require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, account.ID).Scan(&owner))
		require.Equal(t, string(f.given.user), owner)
		ids = append(ids, account.ID)
	}
	sort.Strings(ids)
	actual, _, err := kanamepg.NewInstallationReader(f.given.pool).InstallationAccounts(f.given.ctx, "", 2)
	require.NoError(t, err)
	want := make([]domain.AccountID, len(ids))
	for i, id := range ids {
		want[i] = domain.AccountID(id)
	}
	require.Equal(t, want, actual)
	return ids
}

func ridNativeConcurrentAbsentPair(t *testing.T) []nativeInstallationOperationObservation {
	var observed []nativeInstallationOperationObservation
	for _, mode := range []string{"S1", "S2"} {
		require.True(t, t.Run(mode, func(t *testing.T) { observed = append(observed, runNativeConcurrentAbsentPair(t, mode)...) }))
	}
	return observed
}

func runNativeConcurrentAbsentPair(t *testing.T, mode string) []nativeInstallationOperationObservation {
	var observed []nativeInstallationOperationObservation
	f := newInstallationNativeWorld(t)
	accounts := []string{f.tenantID}
	if mode == "S2" {
		accounts = f.createRID02Accounts(t)
	}
	full := installruntime.NewRIDDeliveryFixture()
	// Normal full module seed establishes I via production. No pair/history is
	// supplied by setup, and this staging run is not counted as F6 acceptance.
	staging := f.apply(t, installruntime.DeliveryInput{Manifests: nativeWithoutDelegations(t, full), CredentialFile: f.creator.CredentialFile})
	results, err := staging.Results()
	require.NoError(t, err)
	require.Empty(t, results)
	var count int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.grant_delegations`).Scan(&count))
	require.Zero(t, count)
	var delegate string
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT id FROM kaname.service_accounts WHERE name='svc-ridfirst' AND account_id=$1`, f.baseline.SystemID).Scan(&delegate))
	stop, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	require.NoError(t, f.session.Stop(stop))
	cancel()
	barrier, err := holdNativeAbsentPair(f.given.ctx, f.given.pool, accounts[0], delegate)
	require.NoError(t, err)
	t.Cleanup(func() { _ = barrier.Release(context.Background()) })
	type participant struct {
		session *installruntime.Session
		wire    *installruntime.Wire
		process *installruntime.Process
		ports   installruntime.NativePorts
		label   string
	}
	participants := []participant{{ports: installruntime.DefaultNativePorts(), label: "rid02-a"}, {ports: installruntime.SecondNativePorts(), label: "rid02-b"}}
	for i := range participants {
		p := &participants[i]
		p.wire, err = installruntime.NewWireAtPorts(filepath.Join(f.session.Root, "pki"), p.ports)
		require.NoError(t, err)
		t.Cleanup(p.wire.Close)
		root := filepath.Join(f.session.Root, p.label)
		require.NoError(t, os.Mkdir(root, 0700))
		p.session = &installruntime.Session{Binary: f.session.Binary, BinarySHA256: f.session.BinarySHA256, Environment: nativeConcurrentEnvironment(t, f, p.ports, p.label), Root: root, Probe: p.wire.ProductionReady}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if err := p.session.Stop(ctx); err != nil {
				t.Errorf("owned concurrent serve shutdown: %v", err)
			}

			// Cleanup runs on success AND any fatal assertion; Stop has reaped the
			// process before inspecting both complete raw streams from every start.
			for _, process := range p.session.History {
				// Stop can return immediately after its forced Kill. Wait separately so
				// no failure-path scan races a remaining writer or an unreaped child.
				reapCtx, reapCancel := context.WithTimeout(context.Background(), 10*time.Second)
				_ = process.Wait(reapCtx)
				if reapCtx.Err() != nil {
					t.Error("concurrent native reap incomplete; stream audit is not final")
				}
				reapCancel()

			}
			// A Start failure after OS launch may reap internally before Session can
			// append History. Enumerate this participant's owned process directories
			// as well, so those failure streams cannot escape the same audit.
			dirs, globErr := filepath.Glob(filepath.Join(p.session.Root, "serve-*", "process"))
			if globErr != nil {
				t.Error("concurrent stream census unavailable")
			}
			for _, dir := range dirs {
				rid02CheckStreams(t, []string{filepath.Join(dir, "stdout.jsonl"), filepath.Join(dir, "stderr.jsonl")}, rid02WorldSecretMaterial(t, f))
			}
		})
		in := installruntime.DeliveryInput{Manifests: full, CredentialFile: f.creator.CredentialFile}
		if mode == "S1" {
			in.TenantAccountID = &f.tenantID
		}
		p.process, err = p.session.StartDelivery(f.given.ctx, in)
		require.NoError(t, err)
	}
	// Production pair statement timeout is 30s; fail before it rather than hide
	// a missed overlap behind retries. Both processes are already running.
	overlap, cancel := context.WithTimeout(f.given.ctx, 20*time.Second)
	pids, err := barrier.AwaitTwo(overlap)
	cancel()
	require.NoError(t, err)
	require.Len(t, pids, 2)
	rows, err := f.given.pool.Query(f.given.ctx, `SELECT application_name FROM pg_stat_activity WHERE pid=ANY($1::int[]) ORDER BY application_name`, pids)
	require.NoError(t, err)
	var labels []string
	for rows.Next() {
		var label string
		require.NoError(t, rows.Scan(&label))
		labels = append(labels, label)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.Equal(t, []string{"rid02-a", "rid02-b"}, labels, "both exact serve participants arrived, not two helper connections")
	meta, _ := anypb.New(&iamv1.CreateGrantDelegationMetadata{})
	rows, err = f.given.pool.Query(f.given.ctx, `SELECT id,resource_id,done FROM kaname.operations WHERE account_id=$1 AND principal_type='service_account' AND principal_id=$2 AND metadata_type=$3 ORDER BY id`, accounts[0], f.creator.ID, meta.TypeUrl)
	require.NoError(t, err)
	var opIDs, proposed []string
	for rows.Next() {
		var id, resource string
		var done bool
		require.NoError(t, rows.Scan(&id, &resource, &done))
		require.False(t, done)
		opIDs = append(opIDs, id)
		proposed = append(proposed, resource)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.Len(t, opIDs, 2)
	require.NotEqual(t, opIDs[0], opIDs[1])
	require.NotEqual(t, proposed[0], proposed[1])
	observation, err := json.Marshal(map[string]any{"pairAccount": accounts[0], "delegate": delegate, "waitingBackendPIDs": pids, "applications": labels, "operations": opIDs, "proposedIDs": proposed})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(f.session.Root, "actual-two-arrivals.json"), observation, 0600))
	require.NoError(t, barrier.Release(f.given.ctx))
	for i := range participants {
		p := &participants[i]
		ready, cancel := context.WithTimeout(f.given.ctx, 90*time.Second)
		require.NoError(t, p.process.AwaitReady(ready, p.wire.ProductionReady))
		cancel()
		require.NoError(t, p.process.OwnsListeners(p.ports.All()...))
		requireNativeOK(t, p.process, 2*len(accounts))
	}
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.grant_delegations`).Scan(&count))
	require.Equal(t, 2*len(accounts), count)
	for _, account := range accounts {
		for _, module := range []string{"ridfirst", "ridsecond"} {
			var winner, creator, status string
			require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT id,delegated_by_id,status FROM kaname.grant_delegations WHERE account_id=$1 AND module=$2`, account, module).Scan(&winner, &creator, &status))
			require.Equal(t, f.creator.ID, creator)
			require.Equal(t, "ACTIVE", status)
			rows, err = f.given.pool.Query(f.given.ctx, `SELECT id FROM kaname.operations WHERE resource_id=$1 AND metadata_type=$2 ORDER BY id`, winner, meta.TypeUrl)
			require.NoError(t, err)
			var winners []string
			for rows.Next() {
				var id string
				require.NoError(t, rows.Scan(&id))
				winners = append(winners, id)
			}
			require.NoError(t, rows.Err())
			rows.Close()
			require.Len(t, winners, 2)
			for _, id := range winners {
				observed = append(observed, requireNativeInstallationOperation(t, f.given.ctx, f.given.pool, id, account, f.creator.ID, winner))
			}
			var audits int
			require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.grant_delegation.created' AND payload->>'delegation_id'=$1`, winner).Scan(&audits))
			require.Equal(t, 1, audits)
		}
	}
	// Independent O publicly lists/gets each tenant through one of the actual
	// live participants. New O exchange and /me remain the normal public path.
	original := f.tenantID
	for _, account := range accounts {
		f.tenantID = account
		f.requirePublicDeliveredPairs(t, "ridfirst", "ridsecond")
	}
	f.tenantID = original
	f.requireSameCredential(t)
	// Stop both explicitly to make exit0 part of the test body. Cleanup retries
	// still own the processes if an earlier assertion aborts.
	for i := range participants {
		p := &participants[i]
		stop, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		require.NoError(t, p.session.Stop(stop))
		cancel()
		require.NoError(t, p.process.CheckSecretAbsence(f.secrets...))
	}
	return observed
}
