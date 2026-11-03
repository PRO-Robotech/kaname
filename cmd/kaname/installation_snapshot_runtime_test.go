// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"gopkg.in/yaml.v3"
)

func rid08Stage(t *testing.T, f *installationNativeWorld) {
	t.Helper()
	before := rid08PrimaryAccounts(t, f)
	gd := rid08PrimaryGD(t, f)
	ops := rid08GDOperations(t, f)
	require.JSONEq(t, "[]", gd)
	require.Empty(t, ops)
	f.requireSameCredential(t)
	requireNativeAuthority(t, f.given, "user", string(f.given.user), 1)
	requireNativeAuthority(t, f.given, "service_account", f.creator.ID, 1)
	// Штатная подготовка поставляет точные каталог/I M1/M2, опуская ТОЛЬКО объявления GD.
	// Проверяемая последующая полная нагрузка всегда содержит оба объявления GD.
	p := f.apply(t, installruntime.DeliveryInput{Manifests: nativeWithoutDelegations(t, installruntime.NewRIDDeliveryFixture()), CredentialFile: f.creator.CredentialFile})
	results, err := p.Results()
	require.NoError(t, err)
	require.Empty(t, results, "setup is not claimed as completed installation apply")
	require.Equal(t, before, rid08PrimaryAccounts(t, f))
	require.Equal(t, gd, rid08PrimaryGD(t, f))
	require.Equal(t, ops, rid08GDOperations(t, f))
	f.renewOperator(t, f.given.ctx)
	require.Equal(t, string(f.given.user), f.operator.UserID())
	f.requireSameCredential(t)
	requireNativeAuthority(t, f.given, "user", string(f.given.user), 1)
	requireNativeAuthority(t, f.given, "service_account", f.creator.ID, 1)
	f.baseline.requirePreserved(t, f.given, 3, 2)
	rid08Write(t, f.session.Root, "ordinary-no-GD-staging", map[string]any{"setupOnly": true, "accountsBeforeAndAfter": before, "GDHistory": gd, "installationOperations": ops, "creator": f.creator.ID, "operator": f.operator.UserID()})
}
func rid08Start(t *testing.T, f *installationNativeWorld, label string, pause, fault bool) *rid02OwnedChild {
	t.Helper()
	configRoot := filepath.Join(f.session.Root, label+"-config")
	require.NoError(t, os.Mkdir(configRoot, 0700))
	deliveryDir := filepath.Join(configRoot, "delivery")
	_, err := installruntime.NewRIDDeliveryFixture().Write(deliveryDir, false)
	require.NoError(t, err)
	raw, err := yaml.Marshal(map[string]any{"manifests": map[string]any{"dir": deliveryDir, "required": true}, "moduleSeedInstaller": map[string]any{"credentialFile": f.creator.CredentialFile}})
	require.NoError(t, err)
	configPath := filepath.Join(configRoot, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, raw, 0600))
	digest := rid06HashExecutable(t)
	c := startRIDInstallationChild(t, f, label, rid08ChildInput{ConfigPath: configPath, EvidenceDir: filepath.Join(f.session.Root, label), PauseSnapshot: pause, FaultSecondPage: fault}, nativeConcurrentEnvironment(t, f, installruntime.SecondNativePorts(), "rid08-full-root"), rid08ChildInputEnv, "TestRID08OwnedSnapshotStartupChild", "3m")
	parent, err := os.ReadFile("/proc/self/cgroup")
	require.NoError(t, err)
	child, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", c.cmd.Process.Pid))
	require.NoError(t, err)
	require.True(t, bytes.Equal(parent, child))
	memory, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	require.NoError(t, err)
	require.Equal(t, "4294967296", string(bytes.TrimSpace(memory)))
	swap, err := os.ReadFile("/sys/fs/cgroup/memory.swap.max")
	require.NoError(t, err)
	require.Equal(t, "0", string(bytes.TrimSpace(swap)))
	cpu, err := os.ReadFile("/sys/fs/cgroup/cpu.max")
	require.NoError(t, err)
	t.Cleanup(func() { require.Equal(t, digest, rid06HashExecutable(t), "owned test executable changed during run") })
	rid08Write(t, c.dir, "full-root-provenance", map[string]any{"instrumentedTestExecutableSHA256": digest, "productionAppSHA256": f.session.BinarySHA256, "pid": c.cmd.Process.Pid, "starttime": c.start, "cgroup": string(child), "pageSize": 2, "cpuMax": string(bytes.TrimSpace(cpu)), "faultSecondPage": fault, "pauseAfterCompletedRealSnapshot": pause})
	return c
}
func rid08AwaitEvent(t *testing.T, f *installationNativeWorld, c *rid02OwnedChild, stage string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.given.ctx, 45*time.Second)
	defer cancel()
	check := func(e rid02ChildEvent) {
		c.seenEvent = true
		require.Equal(t, stage, e.Stage)
		require.Equal(t, c.cmd.Process.Pid, e.PID)
		require.Empty(t, e.Operation, "snapshot/fault is BEFORE any delegation Operation")
	}
	select {
	case e := <-c.events:
		check(e)
	case err := <-c.decodeError:
		select {
		case e := <-c.events:
			check(e)
		default:
			t.Fatalf("owned snapshot IPC failed before %s: %v", stage, err)
		}
	case <-ctx.Done():
		t.Fatal("owned full startup did not reach canonical snapshot boundary")
	}
}
func rid08ReadSnapshot(t *testing.T, c *rid02OwnedChild) rid08SnapshotObservation {
	t.Helper()
	var snapshot rid08SnapshotObservation
	raw, err := os.ReadFile(filepath.Join(c.dir, "canonical-snapshot.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &snapshot))
	require.True(t, snapshot.ContextLive)
	require.Equal(t, 2, snapshot.PageSize)
	for page := 1; page <= snapshot.Pages; page++ {
		var observed rid08PageObservation
		raw, err = os.ReadFile(filepath.Join(c.dir, fmt.Sprintf("page-%02d.json", page)))
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &observed))
		require.Equal(t, page, observed.Page)
		require.True(t, observed.ContextLive)
		require.True(t, observed.ReadOnlyRepeatableRead)
		require.False(t, observed.Fault)
		require.False(t, observed.ObservedAt.After(snapshot.CompletedAt))
	}
	return snapshot
}
func rid08Ready(t *testing.T, f *installationNativeWorld, c *rid02OwnedChild, wire *installruntime.Wire, want int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.given.ctx, 45*time.Second)
	defer cancel()
	timer := time.NewTicker(25 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-c.exited:
			t.Fatal("owned full snapshot startup exited before readiness")
		default:
		}
		attempt, stop := context.WithTimeout(ctx, time.Second)
		err := wire.ProductionReady(attempt)
		stop()
		if err == nil {
			require.NoError(t, ctx.Err())
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("owned snapshot startup readiness deadline")
		case <-timer.C:
		}
	}
	require.NoError(t, installruntime.CheckOwnedListeners(c.cmd.Process.Pid, c.dir, installruntime.SecondNativePorts().All()...))
	rid06ReadResult(t, c, installationResult{Stage: "delegation", Code: "OK", CompletedPairs: want})
}
func rid08Wire(t *testing.T, f *installationNativeWorld) *installruntime.Wire {
	t.Helper()
	wire, err := installruntime.NewWireAtPorts(filepath.Join(f.session.Root, "pki"), installruntime.SecondNativePorts())
	require.NoError(t, err)
	t.Cleanup(wire.Close)
	return wire
}
func rid08FaultExit(t *testing.T, f *installationNativeWorld, c *rid02OwnedChild, watch *installruntime.ReadinessWatch, spawned time.Time) {
	t.Helper()
	rid06WaitExit(t, c, 1)
	observations := watch.Stop()
	require.NotEmpty(t, observations)
	require.False(t, observations[0].FinishedAt.After(spawned))
	require.True(t, observations[0].TransportFailed)
	for _, o := range observations {
		require.NotEqual(t, http.StatusOK, o.HTTPStatus)
	}
	rid08Write(t, c.dir, "readiness-observations", observations)
	rid06ReadResult(t, c, installationResult{Stage: "census", Field: "accounts", Code: "INTERNAL", CompletedPairs: 0})
	var returned rid08ReturnedStatus
	returnedPath := filepath.Join(c.dir, "actual-returned-status.json")
	info, err := os.Stat(returnedPath)
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular())
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	safeStatus, err := os.ReadFile(returnedPath)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(safeStatus, &returned))
	require.True(t, returned.ErrorPresent, "actual runServe error receipt is mandatory")
	require.Equal(t, int32(codes.Internal), returned.Code)
	require.True(t, returned.MessageMatches, "actual runServe message must be exactly internal error")
	var one, two rid08PageObservation
	for i, out := range []*rid08PageObservation{&one, &two} {
		raw, err := os.ReadFile(filepath.Join(c.dir, fmt.Sprintf("page-%02d.json", i+1)))
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, out))
		require.True(t, out.ContextLive)
		require.True(t, out.ReadOnlyRepeatableRead)
		require.Equal(t, i+1, out.Page)
	}
	require.False(t, one.Fault)
	require.True(t, two.Fault)
	_, err = os.Stat(filepath.Join(c.dir, "page-03.json"))
	require.True(t, os.IsNotExist(err), "no later page after injected unknown failure")
	_, err = os.Stat(filepath.Join(c.dir, "canonical-snapshot.json"))
	require.True(t, os.IsNotExist(err), "incomplete census must never be observed as empty success")
	// Ожидание завершения настоящего потомка окончено; координатор или транзакция записи его не переживают.
	closed, cancel := context.WithTimeout(f.given.ctx, 5*time.Second)
	defer cancel()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		var connections int
		require.NoError(t, f.given.pool.QueryRow(closed, `SELECT count(*) FROM pg_stat_activity WHERE application_name='rid08-full-root'`).Scan(&connections))
		if connections == 0 {
			require.NoError(t, closed.Err())
			break
		}
		select {
		case <-closed.Done():
			t.Fatal("real failed census connections did not close")
		case <-tick.C:
		}
	}
}
