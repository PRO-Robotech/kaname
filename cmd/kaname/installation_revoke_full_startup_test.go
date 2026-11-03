// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"gopkg.in/yaml.v3"
)

func rid06Revoke(t *testing.T, w *ridLifecycleWorld, id string) string {
	t.Helper()
	// This normal public mutation must finish inside the child's20s pause. It is
	// not a fake commit, SQL state change or same pair-advisory-lock deadlock.
	ctx, cancel := context.WithTimeout(w.f.given.ctx, 15*time.Second)
	defer cancel()
	var op installruntime.Operation
	code, err := w.f.wire.JSON(ctx, http.MethodPost, "/iam/v1/grantDelegations/"+id+":revoke", w.f.operator.Bearer(), map[string]any{}, &op)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code)
	op, err = w.f.wire.AwaitOperation(ctx, w.f.operator.Bearer(), op)
	require.NoError(t, err)
	require.True(t, op.Done)
	require.Nil(t, op.Error)
	var response anypb.Any
	require.NoError(t, protojson.Unmarshal(op.Response, &response))
	var gd iamv1.GrantDelegation
	require.NoError(t, response.UnmarshalTo(&gd))
	require.Equal(t, id, gd.Id)
	require.Equal(t, iamv1.GrantDelegation_REVOKED, gd.Status)
	var got iamv1.GrantDelegation
	var raw json.RawMessage
	code, err = w.f.wire.JSON(ctx, http.MethodGet, "/iam/v1/grantDelegations/"+id, w.f.operator.Bearer(), nil, &raw)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code)
	require.NoError(t, protojson.Unmarshal(raw, &got))
	require.NoError(t, ctx.Err())
	require.True(t, proto.Equal(&gd, &got))
	return op.ID
}

func rid06Grant(t *testing.T, w *ridLifecycleWorld) *iamv1.AccessBinding {
	t.Helper()
	subject := w.f.ridSA(t, w.f.tenantID, "rid06-old-grantee")
	return w.grant(t, w.bindingInput("service_account", subject, w.pull, "registry.registries", w.object))
}

func rid06RequireRevoked(t *testing.T, w *ridLifecycleWorld, previous *iamv1.GrantDelegation, g *iamv1.AccessBinding) {
	t.Helper()
	var gd iamv1.GrantDelegation
	w.f.publicRead(t, "/iam/v1/grantDelegations/"+previous.Id, &gd)
	require.Equal(t, iamv1.GrantDelegation_REVOKED, gd.Status)
	require.Equal(t, previous.Id, gd.Id)
	require.Equal(t, previous.AccountId, gd.AccountId)
	require.True(t, proto.Equal(previous.Delegate, gd.Delegate))
	require.True(t, proto.Equal(previous.DelegatedBy, gd.DelegatedBy))
	require.True(t, proto.Equal(previous.CreatedAt, gd.CreatedAt))
	require.Equal(t, previous.RoleIds, gd.RoleIds)
	require.Equal(t, previous.TargetTypes, gd.TargetTypes)
	require.Equal(t, previous.SubjectTypes, gd.SubjectTypes)
	var binding iamv1.AccessBinding
	w.f.publicRead(t, "/iam/v1/accessBindings/"+g.Id, &binding)
	require.Equal(t, iamv1.AccessBinding_REVOKED, binding.Status)
	require.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_DELEGATION_REVOKED, binding.GetRevocationReason())
	require.Equal(t, previous.Id, binding.DelegationId)
	require.Equal(t, g.Id, binding.Id)
	require.Equal(t, g.RoleId, binding.RoleId)
	require.True(t, proto.Equal(g.CreatedAt, binding.CreatedAt))
	require.True(t, proto.Equal(g.Target, binding.Target))
	require.Equal(t, g.ScopeType, binding.ScopeType)
	require.Equal(t, g.ScopeId, binding.ScopeId)
	require.Len(t, binding.Subjects, len(g.Subjects))
	for i := range g.Subjects {
		require.True(t, proto.Equal(g.Subjects[i], binding.Subjects[i]))
	}
	var active int
	require.NoError(t, w.f.given.pool.QueryRow(w.f.given.ctx, `SELECT count(*) FROM kaname.grant_delegations WHERE account_id=$1 AND delegate_id=$2 AND status='ACTIVE'`, w.f.tenantID, w.issuer.ID).Scan(&active))
	require.Zero(t, active, "reinstall cannot replace revoked history")
	for _, account := range w.accounts {
		list := w.delegations(t, account)
		require.Len(t, list, 1)
		if account == w.f.tenantID {
			require.Equal(t, previous.Id, list[0].Id)
			require.Equal(t, iamv1.GrantDelegation_REVOKED, list[0].Status)
		} else {
			require.Equal(t, iamv1.GrantDelegation_ACTIVE, list[0].Status)
		}
	}
}

func rid06Result(w *ridLifecycleWorld) installationResult {
	completed := 0
	for i, a := range w.accounts {
		if a == w.f.tenantID {
			completed = i
		}
	}
	return installationResult{Stage: "delegation", Code: "FAILED_PRECONDITION", AccountID: w.f.tenantID, DelegateID: w.issuer.ID, CompletedPairs: completed}
}

func rid06HashExecutable(t *testing.T) string {
	t.Helper()
	f, err := os.Open(os.Args[0])
	require.NoError(t, err)
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(h, f)
	require.NoError(t, err)
	return hex.EncodeToString(h.Sum(nil))
}

// Reuse the complete native config/manifest inputs, changing only ordinary
// listener addresses and declared two-replica DB allocation. No test flag enters
// Config. The instrumentation is in the owned test executable only.
func rid06Start(t *testing.T, w *ridLifecycleWorld, label string) *rid02OwnedChild {
	t.Helper()
	f := w.f
	root := filepath.Join(f.session.Root, label+"-config")
	require.NoError(t, os.Mkdir(root, 0700))
	manifestDir := filepath.Join(root, "delivery")
	_, err := w.delivery.Manifests.Write(manifestDir, w.delivery.Reverse)
	require.NoError(t, err)
	require.Empty(t, w.delivery.ExtraConfig, "RID06 uses the exact default lifecycle profile")
	installer := map[string]any{"credentialFile": w.delivery.CredentialFile}
	if w.delivery.TenantAccountID != nil {
		installer["tenantAccountId"] = *w.delivery.TenantAccountID
	}
	raw, err := yaml.Marshal(map[string]any{"manifests": map[string]any{"dir": manifestDir, "required": true}, "moduleSeedInstaller": installer})
	require.NoError(t, err)
	configPath := filepath.Join(root, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, raw, 0600))
	ordinal := int64(rid06Result(w).CompletedPairs + 1)
	digest := rid06HashExecutable(t)
	c := startRIDInstallationChild(t, f, label, rid06ChildInput{ConfigPath: configPath, Creator: f.creator.ID, PairOrdinal: ordinal}, nativeConcurrentEnvironment(t, f, installruntime.SecondNativePorts(), "rid06-full-root"), rid06ChildInputEnv, "TestRID06OwnedFullStartupChild", "2m")
	parentGroup, err := os.ReadFile("/proc/self/cgroup")
	require.NoError(t, err)
	childGroup, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", c.cmd.Process.Pid))
	require.NoError(t, err)
	require.True(t, bytes.Equal(parentGroup, childGroup), "owned full root inherits bounded job cgroup")
	memory, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	require.NoError(t, err)
	require.Equal(t, "4294967296", strings.TrimSpace(string(memory)))
	swap, err := os.ReadFile("/sys/fs/cgroup/memory.swap.max")
	require.NoError(t, err)
	require.Equal(t, "0", strings.TrimSpace(string(swap)))
	cpu, err := os.ReadFile("/sys/fs/cgroup/cpu.max")
	require.NoError(t, err)
	proof, err := json.Marshal(map[string]any{"provenance": "instrumented test executable running actual complete startup", "testExecutableSHA256": digest, "productionAppSHA256": f.session.BinarySHA256, "pid": c.cmd.Process.Pid, "starttime": c.start, "cgroup": strings.TrimSpace(string(childGroup)), "memoryMax": strings.TrimSpace(string(memory)), "swapMax": strings.TrimSpace(string(swap)), "cpuMax": strings.TrimSpace(string(cpu))})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(c.dir, "full-root-provenance.json"), proof, 0600))
	t.Cleanup(func() { require.Equal(t, digest, rid06HashExecutable(t), "owned test executable changed during run") })
	return c
}

// Read-only identical full history oracle, bounded while the owned writer is paused.
func rid06BoundarySnapshot(t *testing.T, w *ridLifecycleWorld) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(w.f.given.ctx, 2*time.Second)
	defer cancel()
	var snapshot string
	require.NoError(t, w.f.given.pool.QueryRow(ctx, `SELECT jsonb_build_array(COALESCE((SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM kaname.grant_delegations g),'[]'),COALESCE((SELECT jsonb_agg(to_jsonb(b) ORDER BY id) FROM kaname.access_bindings b),'[]'))::text`).Scan(&snapshot))
	require.NoError(t, ctx.Err())
	return snapshot
}

func rid06CheckPending(t *testing.T, w *ridLifecycleWorld, c *rid02OwnedChild, event rid02ChildEvent, before []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(w.f.given.ctx, 3*time.Second)
	defer cancel()
	require.NotContains(t, before, event.Operation)
	op, err := operations.NewRepo(w.f.given.pool, "kaname").Get(ctx, event.Operation)
	require.NoError(t, err)
	require.False(t, op.Done)
	require.Nil(t, op.Error)
	require.Nil(t, op.Response)
	require.Equal(t, operations.Principal{Type: "service_account", ID: w.f.creator.ID, DisplayName: w.f.creator.ID}, op.Principal)
	require.NotNil(t, op.Metadata)
	var meta iamv1.CreateGrantDelegationMetadata
	require.NoError(t, op.Metadata.UnmarshalTo(&meta))
	require.Equal(t, w.f.tenantID, meta.AccountId)
	require.NotEmpty(t, meta.GrantDelegationId)
	require.NotEqual(t, w.gd.Id, meta.GrantDelegationId)
	var mt, resource, account string
	var data []byte
	require.NoError(t, w.f.given.pool.QueryRow(ctx, `SELECT metadata_type,metadata_data,resource_id,account_id FROM kaname.operations WHERE id=$1`, event.Operation).Scan(&mt, &data, &resource, &account))
	require.Equal(t, op.Metadata.TypeUrl, mt)
	require.Equal(t, op.Metadata.Value, data)
	require.Equal(t, meta.GrantDelegationId, resource)
	require.Equal(t, meta.AccountId, account)
	var backend int32
	require.NoError(t, w.f.given.pool.QueryRow(ctx, `SELECT pid FROM pg_stat_activity WHERE application_name='rid06-full-root' AND state='idle in transaction' AND query LIKE '%FROM kaname.operations%' AND query LIKE '%FOR UPDATE%'`).Scan(&backend))
	require.Positive(t, backend)
	require.NoError(t, w.f.wire.ProductionReady(ctx), "independent ordinary O listener remains live")
	proof, err := json.Marshal(map[string]any{"childPID": c.cmd.Process.Pid, "writerBackendPID": backend, "operation": event.Operation, "account": account, "proposedID": resource, "boundary": "pending Operation locked, before pair advisory acquisition"})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(c.dir, "pending-before-pair.json"), proof, 0600))
}

func rid06WaitExit(t *testing.T, c *rid02OwnedChild, want int) {
	t.Helper()
	select {
	case <-c.exited:
	case <-time.After(20 * time.Second):
		t.Fatal("owned full startup did not exit")
	}
	c.afterReap(t)
	if want == 0 {
		require.NoError(t, c.waitErr)
		return
	}
	var exit *exec.ExitError
	require.ErrorAs(t, c.waitErr, &exit)
	require.Equal(t, want, exit.ExitCode())
}
func rid06GracefulStop(t *testing.T, c *rid02OwnedChild) {
	t.Helper()
	start, err := rid02ProcessStart(c.cmd.Process.Pid)
	require.NoError(t, err)
	require.Equal(t, c.start, start)
	argv, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", c.cmd.Process.Pid))
	require.NoError(t, err)
	require.True(t, bytes.Equal(c.argv, argv))
	pgid, err := syscall.Getpgid(c.cmd.Process.Pid)
	require.NoError(t, err)
	require.Equal(t, c.cmd.Process.Pid, pgid)
	require.NoError(t, c.cmd.Process.Signal(syscall.SIGTERM))
	rid06WaitExit(t, c, 0)
}
func rid06ReadResult(t *testing.T, c *rid02OwnedChild, want installationResult) {
	t.Helper()
	p := &installruntime.Process{StdoutPath: filepath.Join(c.dir, "stdout"), StderrPath: filepath.Join(c.dir, "stderr")}
	results, err := p.Results()
	require.NoError(t, err)
	require.Len(t, results, 1)
	var got installationResult
	require.NoError(t, json.Unmarshal(results[0], &got))
	require.Equal(t, want, got)
}

// The sole varied action between these overlap worlds is ordinary O Revoke.
// Arrival is actual full startup, not a helper ExecuteInstallation invocation.
func rid06Overlap(t *testing.T, w *ridLifecycleWorld, g *iamv1.AccessBinding, revoke bool) {
	t.Helper()
	f := w.f
	f.ridAuthorityMaterialized(t, f.creator.ID, true)
	before := w.snapshot(t)
	_, opsBefore := w.grantIdentityCensus(t)
	wire, err := installruntime.NewWireAtPorts(filepath.Join(f.session.Root, "pki"), installruntime.SecondNativePorts())
	require.NoError(t, err)
	defer wire.Close()
	watch := wire.StartReadinessWatch(f.given.ctx)
	defer watch.Stop()
	spawned := time.Now().UTC()
	c := rid06Start(t, w, "rid06-overlap")
	ctx, cancel := context.WithTimeout(f.given.ctx, 20*time.Second)
	event := c.await(t, ctx, "before-pair")
	cancel()
	arrived := time.Now().UTC()
	rid06CheckPending(t, w, c, event, opsBefore)
	require.Equal(t, before, rid06BoundarySnapshot(t, w), "no pair mutation before observed boundary")
	revokeOp := ""
	if revoke {
		revokeOp = rid06Revoke(t, w, w.gd.Id)
	}
	committed := time.Now().UTC()
	afterAction := rid06BoundarySnapshot(t, w)
	if !revoke {
		require.Equal(t, before, afterAction)
	}
	// The authorized Revoke is an independent ordinary Operation, excluded from
	// installer-operation delta; every installer Operation remains checked.
	if revoke {
		opsBefore = append(opsBefore, revokeOp)
	}
	released := time.Now().UTC()
	c.release(t, "continue")
	proof, err := json.Marshal(map[string]any{"spawned": spawned, "arrivalObserved": arrived, "revoke": revoke, "revokeOperation": revokeOp, "actionCommittedObserved": committed, "release": released, "pendingOperation": event.Operation})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(c.dir, "temporal-order.json"), proof, 0600))
	if revoke {
		rid06WaitExit(t, c, 1)
		samples := watch.Stop()
		require.NotEmpty(t, samples)
		require.False(t, samples[0].FinishedAt.After(spawned))
		require.True(t, samples[0].TransportFailed)
		for _, sample := range samples {
			require.NotEqual(t, 200, sample.HTTPStatus)
		}
		raw, err := json.Marshal(samples)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(c.dir, "readiness-observations.json"), raw, 0600))
		rid06ReadResult(t, c, rid06Result(w))
	} else {
		ready, stop := context.WithTimeout(f.given.ctx, 45*time.Second)
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-c.exited:
				t.Fatal("full-startup twin exited before readiness")
			default:
			}
			attempt, finish := context.WithTimeout(ready, time.Second)
			err := wire.ProductionReady(attempt)
			finish()
			if err == nil {
				require.NoError(t, ready.Err())
				break
			}
			select {
			case <-ready.Done():
				stop()
				t.Fatal("full-startup twin readiness deadline")
			case <-ticker.C:
			}
		}
		stop()
		require.NoError(t, installruntime.CheckOwnedListeners(c.cmd.Process.Pid, c.dir, installruntime.SecondNativePorts().All()...))
		rid06ReadResult(t, c, installationResult{Stage: "delegation", Code: "OK", CompletedPairs: len(w.accounts)})
		rid06GracefulStop(t, c)
	}
	require.Equal(t, afterAction, w.snapshot(t), "installer leaves exact pair/grant history after the independent action")
	rid07CheckApplyOperations(t, w, opsBefore, !revoke)
	if revoke {
		rid06RequireRevoked(t, w, w.gd, g)
	} else {
		rid07BindingUnchanged(t, w, g)
		var same iamv1.GrantDelegation
		f.publicRead(t, "/iam/v1/grantDelegations/"+w.gd.Id, &same)
		require.True(t, proto.Equal(w.gd, &same))
	}
}

func ridNativeRevokeBeforePair(t *testing.T) {
	rid03BothModes(t, false, func(t *testing.T, w *ridLifecycleWorld) { g := rid06Grant(t, w); rid06Overlap(t, w, g, true) })
}
func ridNativeRevokeOverlapAndSequential(t *testing.T) {
	rid03BothModes(t, false, func(t *testing.T, w *ridLifecycleWorld) {
		g := rid06Grant(t, w)
		rid06Overlap(t, w, g, true)
		before := w.snapshot(t)
		_, ops := w.grantIdentityCensus(t)
		w.refusedApply(t, rid06Result(w))
		require.Equal(t, before, w.snapshot(t))
		rid07CheckApplyOperations(t, w, ops, false)
		rid06RequireRevoked(t, w, w.gd, g)
	})
}
func ridNativeNoRevokeOverlapTwin(t *testing.T) {
	rid03BothModes(t, false, func(t *testing.T, w *ridLifecycleWorld) { g := rid06Grant(t, w); rid06Overlap(t, w, g, false) })
}
func ridNativeRevokeExplicitRecovery(t *testing.T) {
	rid03BothModes(t, false, func(t *testing.T, w *ridLifecycleWorld) {
		g := rid06Grant(t, w)
		old := proto.Clone(w.gd).(*iamv1.GrantDelegation)
		rid06Overlap(t, w, g, true)
		var revokedGD iamv1.GrantDelegation
		w.f.publicRead(t, "/iam/v1/grantDelegations/"+old.Id, &revokedGD)
		var revokedG iamv1.AccessBinding
		w.f.publicRead(t, "/iam/v1/accessBindings/"+g.Id, &revokedG)
		token := w.f.ridToken(t, w.f.creator)
		priorPairs := w.delegations(t, w.f.tenantID)
		_, priorOperations := w.grantIdentityCensus(t)
		op := w.f.ridOperation(t, "POST", "/iam/v1/grantDelegations", token, w.gdCreateBody(w.f.tenantID, w.issuer.ID), 0)
		id := ridResponseID(t, op)
		require.NotContains(t, priorOperations, op.ID)
		for _, previous := range priorPairs {
			require.NotEqual(t, previous.Id, id, "explicit recovery creates a new pair history row")
		}
		require.NotEqual(t, old.Id, id)
		requireNativeInstallationOperation(t, w.f.given.ctx, w.f.given.pool, op.ID, w.f.tenantID, w.f.creator.ID, id)
		var next iamv1.GrantDelegation
		w.f.publicRead(t, "/iam/v1/grantDelegations/"+id, &next)
		var responseAny anypb.Any
		require.NoError(t, protojson.Unmarshal(op.Response, &responseAny))
		var response iamv1.GrantDelegation
		require.NoError(t, responseAny.UnmarshalTo(&response))
		require.True(t, proto.Equal(&response, &next), "explicit Create response and ordinary public Get agree in full")
		require.Equal(t, iamv1.GrantDelegation_ACTIVE, next.Status)
		require.Equal(t, old.AccountId, next.AccountId)
		require.True(t, proto.Equal(old.Delegate, next.Delegate))
		require.True(t, proto.Equal(old.DelegatedBy, next.DelegatedBy))
		require.Equal(t, old.RoleIds, next.RoleIds)
		require.Equal(t, old.TargetTypes, next.TargetTypes)
		require.Equal(t, old.SubjectTypes, next.SubjectTypes)
		w.gd = &next
		history := w.snapshot(t)
		_, ops := w.grantIdentityCensus(t)
		requireNativeOK(t, w.f.apply(t, w.delivery), len(w.accounts))
		w.f.renewOperator(t, w.f.given.ctx)
		require.Equal(t, history, w.snapshot(t))
		rid07CheckApplyOperations(t, w, ops, true)
		var got iamv1.GrantDelegation
		w.f.publicRead(t, "/iam/v1/grantDelegations/"+old.Id, &got)
		require.True(t, proto.Equal(&revokedGD, &got))
		rid07BindingUnchanged(t, w, &revokedG)
		subject := w.f.ridSA(t, w.f.tenantID, "rid06-recovered-grantee")
		w.issuerToken = w.f.ridToken(t, w.issuer)
		newGrant := w.grant(t, w.bindingInput("service_account", subject, w.pull, "registry.registries", w.object))
		require.Equal(t, id, newGrant.DelegationId)
		w.f.publicRead(t, "/iam/v1/grantDelegations/"+old.Id, &got)
		require.True(t, proto.Equal(&revokedGD, &got))
		rid07BindingUnchanged(t, w, &revokedG)
	})
}
