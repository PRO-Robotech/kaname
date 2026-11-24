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

// Только заявленный URL заменяет отдельные настройки адреса; это штатная документированная
// конфигурация. application_name даёт независимую атрибуцию БД каждому PID serve.
// ReplicaBudget=2 объявляет настоящее развёртывание, не подменяя пул/допуск.
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

// Начальная церемония расходует один допуск. Ровно два штатных публичных создания
// завершают S2; без другого владельца, поддельной идентичности, записи SQL или изменения окна.
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
	// Штатный полный посев модуля устанавливает I через производственный код. Пара/история
	// не подставляются подготовкой, и этот подготовительный запуск не считается приёмкой F6.
	staging := f.apply(t, installruntime.DeliveryInput{RegistrationWriters: f.writerPlan, Manifests: nativeWithoutDelegations(t, full), CredentialFile: f.creator.CredentialFile})
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
		wire  *installruntime.Wire
		child *rid02OwnedChild
		ports installruntime.NativePorts
		label string
	}
	participants := []participant{{ports: installruntime.DefaultNativePorts(), label: "rid02-a"}, {ports: installruntime.SecondNativePorts(), label: "rid02-b"}}
	for i := range participants {
		p := &participants[i]
		p.wire, err = installruntime.NewWireAtPorts(filepath.Join(f.session.Root, "pki"), p.ports)
		require.NoError(t, err)
		t.Cleanup(p.wire.Close)
		root := filepath.Join(f.session.Root, p.label+"-config")
		require.NoError(t, os.Mkdir(root, 0700))
		manifestDir := filepath.Join(root, "delivery")
		_, err := full.Write(manifestDir, false)
		require.NoError(t, err)
		installer := map[string]any{"credentialFile": f.creator.CredentialFile}
		if mode == "S1" {
			installer["tenantAccountId"] = f.tenantID
		}
		raw, err := installruntime.FullStartupConfig(map[string]any{
			"manifests":           map[string]any{"dir": manifestDir, "required": true},
			"moduleSeedInstaller": installer,
		}, f.writerPlan)
		require.NoError(t, err)
		configPath := filepath.Join(root, "config.yaml")
		require.NoError(t, os.WriteFile(configPath, raw, 0600))
		ridRegistrationStartupProof(t, root, raw, f.writerPlan)
		p.child = startRIDInstallationChild(t, f, p.label, rid06ChildInput{
			ConfigPath: configPath, Creator: f.creator.ID, Account: accounts[0],
			PairOrdinal: 1, ConcurrentPair: true,
		}, nativeConcurrentEnvironment(t, f, p.ports, p.label), rid06ChildInputEnv, "TestRID06OwnedFullStartupChild", "4m")
		parentGroup, err := os.ReadFile("/proc/self/cgroup")
		require.NoError(t, err)
		childGroup, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", p.child.cmd.Process.Pid))
		require.NoError(t, err)
		require.Equal(t, parentGroup, childGroup, "owned concurrent startup inherits bounded job cgroup")
	}
	// Оба полных запуска должны зафиксировать Operation до открытия Writer. Иначе
	// второй запуск может попасть в граф блокировок ещё на этапе посева модуля.
	beforeWriter, cancel := context.WithTimeout(f.given.ctx, 20*time.Second)
	defer cancel()
	for _, p := range participants {
		p.child.await(t, beforeWriter, "before-concurrent-pair")
	}
	meta, err := anypb.New(&iamv1.CreateGrantDelegationMetadata{})
	require.NoError(t, err)
	opIDs, proposed := nativeConcurrentPendingPair(t, beforeWriter, f, accounts[0], meta.TypeUrl)
	cancel()
	for _, p := range participants {
		p.child.release(t, "continue")
	}
	overlap, cancel := context.WithTimeout(f.given.ctx, 20*time.Second)
	defer cancel()
	pids, err := barrier.AwaitTwo(overlap, []string{participants[0].label, participants[1].label})
	require.NoError(t, err)
	require.Len(t, pids, 2)
	rows, err := f.given.pool.Query(overlap, `SELECT application_name FROM pg_stat_activity WHERE pid=ANY($1::int[]) ORDER BY application_name`, pids)
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
	waitingOps, waitingProposed := nativeConcurrentPendingPair(t, overlap, f, accounts[0], meta.TypeUrl)
	require.Equal(t, opIDs, waitingOps)
	require.Equal(t, proposed, waitingProposed)
	cancel()
	observation, err := json.Marshal(map[string]any{"pairAccount": accounts[0], "delegate": delegate, "waitingBackendPIDs": pids, "pairAnchoredWaitGraph": true, "applications": labels, "operations": opIDs, "proposedIDs": proposed})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(f.session.Root, "actual-two-arrivals.json"), observation, 0600))
	require.NoError(t, barrier.Release(f.given.ctx))
	for _, p := range participants {
		require.True(t, waitNativeConcurrentReady(f.given.ctx, p.child, p.wire), "owned concurrent startup did not reach readiness")
		require.NoError(t, installruntime.CheckOwnedListeners(p.child.cmd.Process.Pid, p.child.dir, p.ports.All()...))
		rid06ReadResult(t, p.child, installationResult{Stage: "delegation", Code: "OK", CompletedPairs: 2 * len(accounts)})
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
			require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.grant_delegation.created' AND event_payload->>'delegation_id'=$1`, winner).Scan(&audits))
			require.Equal(t, 1, audits)
		}
	}
	// Независимый O публично перечисляет/читает каждого тенанта через одного из настоящих
	// живых участников. Новый обмен O и /me остаются штатным публичным путём.
	original := f.tenantID
	for _, account := range accounts {
		f.tenantID = account
		f.requirePublicDeliveredPairs(t, "ridfirst", "ridsecond")
	}
	f.tenantID = original
	f.requireSameCredential(t)
	// Явно останавливаем оба процесса, делая exit0 частью тела теста. Повторы очистки
	// по-прежнему владеют процессами, если раннее утверждение прервёт выполнение.
	for _, p := range participants {
		rid06GracefulStop(t, p.child)
	}
	return observed
}

func nativeConcurrentPendingPair(t *testing.T, ctx context.Context, f *installationNativeWorld, account, metadataType string) ([]string, []string) {
	t.Helper()
	rows, err := f.given.pool.Query(ctx, `SELECT id,resource_id,done FROM kaname.operations WHERE account_id=$1 AND principal_type='service_account' AND principal_id=$2 AND metadata_type=$3 ORDER BY id`, account, f.creator.ID, metadataType)
	require.NoError(t, err)
	defer rows.Close()
	var opIDs, proposed []string
	for rows.Next() {
		var id, resource string
		var done bool
		require.NoError(t, rows.Scan(&id, &resource, &done))
		require.False(t, done)
		require.NotEmpty(t, id)
		require.NotEmpty(t, resource)
		opIDs = append(opIDs, id)
		proposed = append(proposed, resource)
	}
	require.NoError(t, rows.Err())
	require.Len(t, opIDs, 2)
	require.NotEqual(t, opIDs[0], opIDs[1])
	require.NotEqual(t, proposed[0], proposed[1])
	return opIDs, proposed
}

func waitNativeConcurrentReady(ctx context.Context, child *rid02OwnedChild, wire *installruntime.Wire) bool {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		attempt, stop := context.WithTimeout(ctx, time.Second)
		err := wire.ProductionReady(attempt)
		stop()
		if err == nil {
			return ctx.Err() == nil
		}
		select {
		case <-child.exited:
			return false
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}
