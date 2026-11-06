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
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

type rid10FailureOperation struct {
	ID, Account, Proposed, Creator, MetadataType, Resource string
	Metadata                                               []byte
	Done                                                   bool
	Code                                                   int32
	MessageMatches                                         bool
}
type rid10Proof struct {
	Mode                                    string
	Twin                                    bool
	Accounts                                []string
	System, NamedSystem                     string
	First                                   nativeInstallationOperationObservation
	FirstGD, FirstG, FirstRow               string
	AtBoundary, AfterFailure, AfterRecovery []string
	Failure                                 *rid10FailureOperation
	Returned                                rid10Returned
	PairIDs                                 map[string]string
	Created                                 map[string]time.Time
	Recovery                                []nativeInstallationOperationObservation
}

func rid10Start(t *testing.T, x *rid10World, mode string) *rid02OwnedChild {
	t.Helper()
	f := x.w.f
	configRoot := filepath.Join(f.session.Root, "rid10-config")
	require.NoError(t, os.Mkdir(configRoot, 0700))
	manifestDir := filepath.Join(configRoot, "delivery")
	_, err := x.w.delivery.Manifests.Write(manifestDir, false)
	require.NoError(t, err)
	raw, err := yaml.Marshal(map[string]any{"manifests": map[string]any{"dir": manifestDir, "required": true}, "moduleSeedInstaller": map[string]any{"credentialFile": f.creator.CredentialFile}})
	require.NoError(t, err)
	configPath := filepath.Join(configRoot, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, raw, 0600))
	digest := rid06HashExecutable(t)
	child := startRIDInstallationChild(t, f, "rid10-child", rid10ChildInput{ConfigPath: configPath, EvidenceDir: filepath.Join(f.session.Root, "rid10-child"), Creator: f.creator.ID, Mode: mode}, nativeConcurrentEnvironment(t, f, installruntime.SecondNativePorts(), "rid10-full-root"), rid10ChildEnv, "TestRID10OwnedMidrunStartupChild", "4m")
	parentCG, err := os.ReadFile("/proc/self/cgroup")
	require.NoError(t, err)
	childCG, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", child.cmd.Process.Pid))
	require.NoError(t, err)
	require.True(t, bytes.Equal(parentCG, childCG))
	memory, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	require.NoError(t, err)
	require.Equal(t, "4294967296", strings.TrimSpace(string(memory)))
	swap, err := os.ReadFile("/sys/fs/cgroup/memory.swap.max")
	require.NoError(t, err)
	require.Equal(t, "0", strings.TrimSpace(string(swap)))
	rid08Write(t, child.dir, "provenance", map[string]any{"instrumentedCompleteStartup": true, "testBinarySHA256": digest, "productionAppSHA256": f.session.BinarySHA256, "pid": child.cmd.Process.Pid, "starttime": child.start, "cgroup": string(childCG), "memoryMax": string(memory), "swapMax": string(swap)})
	t.Cleanup(func() { require.Equal(t, digest, rid06HashExecutable(t)) })
	// Закрытое рукопожатие владения НЕ ДОЛЖНО утверждать аутентификацию или выдачу токенов.
	ctx, cancel := context.WithTimeout(f.given.ctx, 10*time.Second)
	defer cancel()
	var event rid02ChildEvent
	select {
	case event = <-child.events:
	case <-child.exited:
		t.Fatal("midrun child exited before ownership")
	case <-child.decodeError:
		t.Fatal("midrun preauth handshake failed")
	case <-ctx.Done():
		t.Fatal("midrun preauth deadline")
	}
	require.Equal(t, "midrun-preauth-armed", event.Stage)
	require.Equal(t, child.cmd.Process.Pid, event.PID)
	require.Empty(t, event.Operation)
	require.False(t, child.seenEvent)
	start, err := rid02ProcessStart(event.PID)
	require.NoError(t, err)
	require.Equal(t, child.start, start)
	argv, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", event.PID))
	require.NoError(t, err)
	require.True(t, bytes.Equal(child.argv, argv))
	group, err := syscall.Getpgid(event.PID)
	require.NoError(t, err)
	require.Equal(t, event.PID, group)
	require.NoError(t, syscall.Kill(event.PID, 0))
	rid10Release(t, ctx, child, "start")
	require.False(t, child.seenEvent)
	return child
}
func rid10Release(t *testing.T, ctx context.Context, c *rid02OwnedChild, action string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	require.NoError(t, c.control.SetWriteDeadline(deadline))
	require.NoError(t, json.NewEncoder(c.control).Encode(action))
	require.NoError(t, ctx.Err())
	require.NoError(t, c.control.SetWriteDeadline(time.Time{}))
}
func rid10Read(t *testing.T, c *rid02OwnedChild, name string, out any) {
	t.Helper()
	path := filepath.Join(c.dir, name+".json")
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular() && info.Mode().Perm() == 0600)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, out))
}
func rid10FirstBoundary(t *testing.T, x *rid10World, c *rid02OwnedChild, p *rid10Proof) {
	t.Helper()
	w := x.w
	f := w.f
	ctx, cancel := context.WithTimeout(f.given.ctx, 45*time.Second)
	defer cancel()
	event := c.await(t, ctx, "first-pair-done")
	var receipt installationCompletedPair
	rid10Read(t, c, "first-completed-pair", &receipt)
	require.Equal(t, 1, receipt.CompletedPairs)
	require.Equal(t, event.Operation, receipt.OperationID)
	require.Equal(t, w.accounts[0], receipt.AccountID)
	require.Equal(t, w.issuer.ID, receipt.DelegateID)
	p.AtBoundary = rid08GDOperations(t, f)
	require.Equal(t, []string{receipt.OperationID}, p.AtBoundary)
	// В каноническом порядке одна публично видимая пара ACTIVE, без скрытой поздней пары.
	for _, account := range append(append([]string{}, w.accounts...), f.baseline.SystemID) {
		got := w.delegations(t, account)
		if account == w.accounts[0] {
			require.Len(t, got, 1)
			w.gd = got[0]
		} else {
			require.Empty(t, got)
		}
	}
	require.NotNil(t, w.gd)
	require.Equal(t, iamv1.GrantDelegation_ACTIVE, w.gd.Status)
	require.Equal(t, w.issuer.ID, w.gd.Delegate.Id)
	require.Equal(t, f.creator.ID, w.gd.DelegatedBy.Id)
	require.Equal(t, "service_account", w.gd.DelegatedBy.Type)
	require.Equal(t, []string{w.pull}, w.gd.RoleIds)
	require.Equal(t, []string{"registry.registries"}, w.gd.TargetTypes)
	require.Equal(t, []iamv1.SubjectType{iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT}, w.gd.SubjectTypes)
	p.First = requireNativeInstallationOperation(t, ctx, f.given.pool, receipt.OperationID, receipt.AccountID, f.creator.ID, w.gd.Id)
	p.FirstGD = rid08PrimaryGD(t, f)
	require.NoError(t, f.given.pool.QueryRow(ctx, `SELECT to_jsonb(g)::text FROM kaname.grant_delegations g WHERE id=$1`, w.gd.Id).Scan(&p.FirstRow))
	var held int
	require.NoError(t, f.given.pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE application_name='rid10-full-root' AND xact_start IS NOT NULL AND state='idle in transaction'`).Scan(&held))
	require.Zero(t, held, "between-pair callback must hold no writer/snapshot transaction")
	// Настоящий ранее существовавший G создаётся через I при видимом первом GD и
	// до сбоя/отзыва. Его точная строка/история должна пережить каждую последующую фазу.
	g := x.grantFirst(t)
	require.Equal(t, w.gd.Id, g.DelegationId)
	require.Equal(t, iamv1.AccessBinding_ACTIVE, g.Status)
	p.FirstG = g.Id
	require.Equal(t, p.FirstGD, rid08PrimaryGD(t, f))
	require.Equal(t, p.AtBoundary, rid08GDOperations(t, f))
	require.NoError(t, ctx.Err())
	rid08Write(t, c.dir, "boundary-observed-by-O", map[string]any{"completedPairs": 1, "first": p.First, "accounts": w.accounts, "firstGD": w.gd.Id, "actualG": g.Id, "pendingWriterTransactions": held, "normalGDOperations": p.AtBoundary})
}
func rid10Pending(t *testing.T, x *rid10World, c *rid02OwnedChild, p *rid10Proof) string {
	t.Helper()
	f := x.w.f
	ctx, cancel := context.WithTimeout(f.given.ctx, 15*time.Second)
	defer cancel()
	var event rid02ChildEvent
	select {
	case event = <-c.events:
	case <-c.exited:
		t.Fatal("child exited before second writer observation")
	case <-c.decodeError:
		t.Fatal("second writer IPC failed")
	case <-ctx.Done():
		t.Fatal("second writer boundary deadline")
	}
	require.Equal(t, "second-writer-before-begin", event.Stage)
	require.Equal(t, c.cmd.Process.Pid, event.PID)
	require.Empty(t, event.Operation)
	require.True(t, c.seenEvent)
	ids := rid08GDOperations(t, f)
	require.Len(t, ids, 2)
	var id string
	for _, candidate := range ids {
		if candidate != p.First.ID {
			id = candidate
		}
	}
	require.NotEmpty(t, id)
	op, err := operations.NewRepo(f.given.pool, "kaname").Get(ctx, id)
	require.NoError(t, err)
	require.False(t, op.Done)
	require.Nil(t, op.Error)
	require.Nil(t, op.Response)
	require.Equal(t, operations.Principal{Type: "service_account", ID: f.creator.ID, DisplayName: f.creator.ID}, op.Principal)
	require.NotNil(t, op.Metadata)
	var meta iamv1.CreateGrantDelegationMetadata
	require.NoError(t, op.Metadata.UnmarshalTo(&meta))
	require.Equal(t, x.w.accounts[1], meta.AccountId)
	require.NotEmpty(t, meta.GrantDelegationId)
	require.NotEqual(t, p.First.Winner, meta.GrantDelegationId)
	var mt, account, resource string
	var data []byte
	require.NoError(t, f.given.pool.QueryRow(ctx, `SELECT metadata_type,metadata_data,account_id,resource_id FROM kaname.operations WHERE id=$1`, id).Scan(&mt, &data, &account, &resource))
	require.Equal(t, op.Metadata.TypeUrl, mt)
	require.Equal(t, op.Metadata.Value, data)
	require.Equal(t, meta.AccountId, account)
	require.Equal(t, meta.GrantDelegationId, resource)
	require.Equal(t, p.FirstGD, rid08PrimaryGD(t, f))
	p.Failure = &rid10FailureOperation{ID: id, Account: account, Proposed: resource, Creator: op.Principal.ID, MetadataType: mt, Metadata: data, Resource: resource}
	rid08Write(t, c.dir, "actual-second-normal-operation-before-fault", p.Failure)
	require.NoError(t, ctx.Err())
	return id
}
func rid10CheckFailedOperation(t *testing.T, x *rid10World, p *rid10Proof) {
	t.Helper()
	f := x.w.f
	require.NotNil(t, p.Failure)
	op, err := operations.NewRepo(f.given.pool, "kaname").Get(f.given.ctx, p.Failure.ID)
	require.NoError(t, err)
	require.True(t, op.Done)
	require.NotNil(t, op.Error)
	require.EqualValues(t, codes.Internal, op.Error.Code)
	require.True(t, op.Error.Message == "internal error", "operation error message must match the public safe contract")
	require.Nil(t, op.Response)
	require.NotNil(t, op.Metadata)
	require.Equal(t, p.Failure.MetadataType, op.Metadata.TypeUrl)
	require.Equal(t, p.Failure.Metadata, op.Metadata.Value)
	require.Equal(t, operations.Principal{Type: "service_account", ID: f.creator.ID, DisplayName: f.creator.ID}, op.Principal)
	var mt, account, resource string
	var data []byte
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT metadata_type,metadata_data,account_id,resource_id FROM kaname.operations WHERE id=$1`, op.ID).Scan(&mt, &data, &account, &resource))
	require.Equal(t, p.Failure.MetadataType, mt)
	require.Equal(t, p.Failure.Metadata, data)
	require.Equal(t, p.Failure.Account, account)
	require.Equal(t, p.Failure.Resource, resource)
	p.Failure.Done = true
	p.Failure.Code = int32(op.Error.Code)
	p.Failure.MessageMatches = true
}
func rid10Pairs(t *testing.T, x *rid10World, p *rid10Proof) {
	t.Helper()
	w := x.w
	f := w.f
	p.PairIDs = map[string]string{}
	p.Created = map[string]time.Time{}
	for _, account := range w.accounts {
		list := w.delegations(t, account)
		require.Len(t, list, 1)
		gd := list[0]
		require.Equal(t, iamv1.GrantDelegation_ACTIVE, gd.Status)
		require.Equal(t, w.issuer.ID, gd.Delegate.Id)
		require.Equal(t, iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT, gd.Delegate.Type)
		require.Equal(t, f.creator.ID, gd.DelegatedBy.Id)
		require.Equal(t, "service_account", gd.DelegatedBy.Type)
		require.Equal(t, []string{w.pull}, gd.RoleIds)
		require.Equal(t, []string{"registry.registries"}, gd.TargetTypes)
		require.Equal(t, []iamv1.SubjectType{iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT}, gd.SubjectTypes)
		p.PairIDs[account] = gd.Id
		var created time.Time
		require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT created_at FROM kaname.grant_delegations WHERE id=$1`, gd.Id).Scan(&created))
		p.Created[account] = created
	}
	require.Empty(t, w.delegations(t, f.baseline.SystemID))
	require.Len(t, p.PairIDs, 3)
	require.Equal(t, p.First.Winner, p.PairIDs[w.accounts[0]])
	require.Equal(t, p.First.CreatedAt, p.Created[w.accounts[0]])
	var total int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.grant_delegations`).Scan(&total))
	require.Equal(t, 3, total)
	require.Equal(t, x.accountsBefore, rid08PrimaryAccounts(t, f))
	var got iamv1.GrantDelegation
	f.publicRead(t, "/iam/v1/grantDelegations/"+p.First.Winner, &got)
	require.True(t, proto.Equal(w.gd, &got))
	var firstRow string
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT to_jsonb(g)::text FROM kaname.grant_delegations g WHERE id=$1`, p.First.Winner).Scan(&firstRow))
	require.Equal(t, p.FirstRow, firstRow, "entire original GD row remains exact after repeat/recovery")
}
func rid10OnlyFirst(t *testing.T, x *rid10World, p *rid10Proof) {
	t.Helper()
	require.Equal(t, p.FirstGD, rid08PrimaryGD(t, x.w.f))
	for _, account := range append(append([]string{}, x.w.accounts...), x.w.f.baseline.SystemID) {
		got := x.w.delegations(t, account)
		if account == p.First.Account {
			require.Len(t, got, 1)
			require.True(t, proto.Equal(x.w.gd, got[0]))
		} else {
			require.Empty(t, got)
		}
	}
	require.Equal(t, p.First, requireNativeInstallationOperation(t, x.w.f.given.ctx, x.w.f.given.pool, p.First.ID, p.First.Account, p.First.Creator, p.First.Winner))
}

func rid10CheckOldG(t *testing.T, x *rid10World, p *rid10Proof, rows string) {
	t.Helper()
	require.Equal(t, rows, rid10BindingRows(t, x.w))
	var g iamv1.AccessBinding
	x.w.f.publicRead(t, "/iam/v1/accessBindings/"+p.FirstG, &g)
	require.Equal(t, iamv1.AccessBinding_ACTIVE, g.Status)
	require.Equal(t, p.First.Winner, g.DelegationId)
}
func rid10Run(t *testing.T, mode string, twin bool) *rid10Proof {
	t.Helper()
	x := rid10Prepare(t)
	w := x.w
	f := w.f
	childMode := mode
	if twin {
		childMode = "twin"
	}
	wire := rid08Wire(t, f)
	watch := wire.StartReadinessWatch(f.given.ctx)
	t.Cleanup(func() { watch.Stop() })
	// Завершаем неудачную транспортную пробу до запуска принадлежащего фикстуре второго слушателя.
	// Первое наблюдение StartReadinessWatch синхронно (существующий RID08).
	spawned := time.Now()
	child := rid10Start(t, x, childMode)
	p := &rid10Proof{Mode: mode, Twin: twin, Accounts: append([]string{}, w.accounts...), System: f.baseline.SystemID, NamedSystem: x.namedSystem}
	rid10FirstBoundary(t, x, child, p)
	oldG := rid10BindingRows(t, w)
	newmanHistory := rid10NewmanBaseline(t, x, p)
	if mode == "retirement" && !twin {
		f.ridAdmin(t, f.creator.ID, false)
		requireNativeAuthority(t, f.given, "service_account", f.creator.ID, 0)
		requireNativeAuthority(t, f.given, "user", f.operator.UserID(), 1)
		require.Equal(t, p.AtBoundary, rid08GDOperations(t, f))
		require.Equal(t, p.FirstGD, rid08PrimaryGD(t, f))
		rid10CheckOldG(t, x, p, oldG)
		rid08Write(t, child.dir, "revoke-materialized-before-next-pair", map[string]any{"creator": f.creator.ID, "activeAdmin": false, "independentO": f.operator.UserID(), "normalGDOperations": p.AtBoundary})
	}
	rid10Release(t, f.given.ctx, child, "continue")
	if mode == "fault" && !twin {
		rid10Pending(t, x, child, p)
		rid10Release(t, f.given.ctx, child, "continue")
	}
	if twin {
		rid08Ready(t, f, child, wire, 3)
		watch.Stop()
		rid10Pairs(t, x, p)
		rid10CheckOldG(t, x, p, oldG)
		rid08NewOperations(t, f, nil, 3)
		rid10NewmanPhase(t, x, p, newmanHistory, "twin")
		rid06GracefulStop(t, child)
		rid10Read(t, child, "actual-return", &p.Returned)
		require.True(t, p.Returned.ControlOK && p.Returned.CaptureOK && p.Returned.MessageMatches)
		require.EqualValues(t, codes.OK, p.Returned.Code)
		require.Equal(t, 3, p.Returned.Completed)
		require.False(t, p.Returned.FaultInjected)
	} else {
		rid06WaitExit(t, child, 1)
		observations := watch.Stop()
		require.NotEmpty(t, observations)
		require.False(t, observations[0].FinishedAt.After(spawned))
		require.True(t, observations[0].TransportFailed)
		for _, o := range observations {
			require.NotEqual(t, http.StatusOK, o.HTTPStatus)
		}
		rid08Write(t, child.dir, "no-readiness", observations)
		want := codes.Internal
		resultCode := "INTERNAL"
		if mode == "retirement" {
			want = codes.PermissionDenied
			resultCode = "PERMISSION_DENIED"
		}
		stage := "delegation"
		if mode == "retirement" {
			stage = "authority"
		}
		rid06ReadResult(t, child, installationResult{Stage: stage, Code: resultCode, AccountID: w.accounts[1], DelegateID: w.issuer.ID, CompletedPairs: 1})
		rid10Read(t, child, "actual-return", &p.Returned)
		require.True(t, p.Returned.ControlOK && p.Returned.CaptureOK && p.Returned.MessageMatches)
		require.EqualValues(t, want, p.Returned.Code)
		require.Equal(t, 1, p.Returned.Completed)
		p.AfterFailure = rid08GDOperations(t, f)
		if mode == "fault" {
			require.Len(t, p.AfterFailure, 2)
			require.True(t, p.Returned.FaultInjected && p.Returned.FaultContextLive)
			var fault struct {
				Ordinal                int64
				ContextLive            bool
				Creator                string
				FreshUnknown, Sentinel bool
			}
			rid10Read(t, child, "fresh-writer-fault", &fault)
			require.EqualValues(t, 2, fault.Ordinal)
			require.True(t, fault.ContextLive && fault.FreshUnknown)
			require.False(t, fault.Sentinel)
			require.Equal(t, f.creator.ID, fault.Creator)
			require.EqualValues(t, 2, p.Returned.WriterArrivals)
			rid10CheckFailedOperation(t, x, p)
		} else {
			require.Equal(t, p.AtBoundary, p.AfterFailure)
			require.False(t, p.Returned.FaultInjected)
			require.EqualValues(t, 1, p.Returned.WriterArrivals)
		}
		rid10OnlyFirst(t, x, p)
		rid10CheckOldG(t, x, p, oldG)
		rid10NewmanPhase(t, x, p, newmanHistory, "partial")
		// Настоящий неудачный запуск завершился. Восстановление использует штатный выпущенный
		// исполняемый файл НОВОГО интегрированного исходника с той же поставкой/ключом.
		if mode == "retirement" {
			f.ridAdmin(t, f.creator.ID, true)
		}
		requireNativeAuthority(t, f.given, "service_account", f.creator.ID, 1)
		f.requireSameCredential(t)
		requireNativeOK(t, f.apply(t, w.delivery), 3)
		f.renewOperator(t, f.given.ctx)
		rid10Pairs(t, x, p)
		rid10CheckOldG(t, x, p, oldG)
		p.AfterRecovery = rid08GDOperations(t, f)
		rid08NewOperations(t, f, p.AfterFailure, 3)
		for _, id := range p.AfterRecovery {
			found := false
			for _, old := range p.AfterFailure {
				if id == old {
					found = true
				}
			}
			if found {
				continue
			}
			op, e := operations.NewRepo(f.given.pool, "kaname").Get(f.given.ctx, id)
			require.NoError(t, e)
			require.NotNil(t, op.Response)
			var gd iamv1.GrantDelegation
			require.NoError(t, op.Response.UnmarshalTo(&gd))
			p.Recovery = append(p.Recovery, requireNativeInstallationOperation(t, f.given.ctx, f.given.pool, id, gd.AccountId, f.creator.ID, gd.Id))
		}
		require.Len(t, p.Recovery, 3)
		require.Equal(t, p.First, requireNativeInstallationOperation(t, f.given.ctx, f.given.pool, p.First.ID, p.First.Account, p.First.Creator, p.First.Winner))
		if mode == "fault" {
			rid10CheckFailedOperation(t, x, p)
		}
		rid10NewmanPhase(t, x, p, newmanHistory, "recovered")
	}
	require.Equal(t, x.accountsBefore, rid08PrimaryAccounts(t, f))
	f.requireSameCredential(t)
	rid08Write(t, f.session.Root, "rid10-complete", p)
	return p
}
