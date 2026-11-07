// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	gdapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/grant_delegation"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/operationresolver"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
)

// Чтение намеренно отвергает маршрут реплики; первичное чтение всегда передаётся
// настоящему производственному репозиторию. Этот шов не подставляет значение ресурса.
type rid02PrimaryObserver struct {
	kanamerepo.Repository
	primary atomic.Int64
}

func (r *rid02PrimaryObserver) Reader(context.Context) (kanamerepo.Reader, error) {
	return nil, fmt.Errorf("recovery attempted non-primary reader")
}
func (r *rid02PrimaryObserver) ReaderFromPrimary(ctx context.Context) (kanamerepo.Reader, error) {
	actual, ok := r.Repository.(interface {
		ReaderFromPrimary(context.Context) (kanamerepo.Reader, error)
	})
	if !ok {
		return nil, fmt.Errorf("missing actual primary reader")
	}
	r.primary.Add(1)
	return actual.ReaderFromPrimary(ctx)
}
func rid02Recovery(t *testing.T, f *installationNativeWorld) (*operations.Reconciler, *operationresolver.Resolver, *rid02PrimaryObserver) {
	t.Helper()
	repo := &rid02PrimaryObserver{Repository: kanamepg.New(f.given.pool, nil)}
	resolver := operationresolver.New(repo, nil, kanamepg.NewAccessKeyRepo(f.given.pool))
	// Не задаём OrphanGrace: используем настоящий производственный пятиминутный период по умолчанию.
	return operations.NewReconciler(f.given.pool, resolver, operations.ReconcilerConfig{Schema: "kaname"}), resolver, repo
}
func rid02StageCrashWorld(t *testing.T) (*installationNativeWorld, []rid02ChildInput) {
	t.Helper()
	f := newInstallationNativeWorld(t)
	accounts := f.createRID02Accounts(t)
	full := installruntime.NewRIDDeliveryFixture()
	f.apply(t, installruntime.DeliveryInput{RegistrationWriters: f.writerPlan, Manifests: nativeWithoutDelegations(t, full), CredentialFile: f.creator.CredentialFile})
	var count int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.grant_delegations`).Scan(&count))
	require.Zero(t, count)
	dir := filepath.Join(f.session.Root, "child-full-delivery")
	_, err := full.Write(dir, false)
	require.NoError(t, err)
	var inputs []rid02ChildInput
	for _, module := range []string{"ridfirst", "ridsecond"} {
		delegate, roles, err := kanamepg.NewInstallationReader(f.given.pool).InstallationReferences(f.given.ctx, "system", "svc-"+module, []string{module + ".reader"})
		require.NoError(t, err)
		for _, account := range accounts {
			inputs = append(inputs, rid02ChildInput{CredentialFile: f.creator.CredentialFile, ManifestDir: dir, Creator: f.creator.ID, Input: gdapp.CreateInput{AccountID: account, DelegateType: "SUBJECT_TYPE_SERVICE_ACCOUNT", DelegateID: string(delegate), RoleIDs: roles, TargetTypes: []string{module + ".objects"}, SubjectTypes: []string{"SUBJECT_TYPE_SERVICE_ACCOUNT"}}})
		}
	}
	// Фоновый механизм сведения serve не должен обработать намеренно осиротевшие строки.
	stop, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	require.NoError(t, f.session.Stop(stop))
	return f, inputs
}

type rid02CrashRecord struct {
	Input        rid02ChildInput
	Operation    string
	Proposed     string
	Modified     time.Time
	Committed    bool
	ResourceJSON string
	MetadataType string
	Metadata     []byte
}

func rid02Pending(t *testing.T, f *installationNativeWorld, input rid02ChildInput, id string, committed bool) rid02CrashRecord {
	t.Helper()
	op, err := operations.NewRepo(f.given.pool, "kaname").Get(f.given.ctx, id)
	require.NoError(t, err)
	require.False(t, op.Done)
	require.Nil(t, op.Error)
	require.Nil(t, op.Response)
	require.Equal(t, operations.Principal{Type: "service_account", ID: f.creator.ID, DisplayName: f.creator.ID}, op.Principal)
	var m iamv1.CreateGrantDelegationMetadata
	require.NoError(t, op.Metadata.UnmarshalTo(&m))
	require.Equal(t, input.Input.AccountID, m.AccountId)
	var idxAccount, idxResource, typ string
	var value []byte
	var modified time.Time
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT account_id,resource_id,metadata_type,metadata_data,modified_at FROM kaname.operations WHERE id=$1`, id).Scan(&idxAccount, &idxResource, &typ, &value, &modified))
	require.Equal(t, m.AccountId, idxAccount)
	require.Equal(t, m.GrantDelegationId, idxResource)
	require.Equal(t, op.Metadata.TypeUrl, typ)
	require.Equal(t, op.Metadata.Value, value)
	var count int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.grant_delegations WHERE account_id=$1 AND delegate_id=$2`, input.Input.AccountID, input.Input.DelegateID).Scan(&count))
	if committed {
		require.Equal(t, 1, count)
		var id string
		require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT id FROM kaname.grant_delegations WHERE account_id=$1 AND delegate_id=$2`, input.Input.AccountID, input.Input.DelegateID).Scan(&id))
		require.Equal(t, m.GrantDelegationId, id)
	} else {
		require.Zero(t, count)
	}
	resourceJSON := ""
	if committed {
		require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT to_jsonb(g)::text FROM kaname.grant_delegations g WHERE id=$1`, m.GrantDelegationId).Scan(&resourceJSON))
	}
	return rid02CrashRecord{Input: input, Operation: id, Proposed: m.GrantDelegationId, Modified: modified, Committed: committed, ResourceJSON: resourceJSON, MetadataType: op.Metadata.TypeUrl, Metadata: append([]byte(nil), op.Metadata.Value...)}
}
func rid02WaitOrphanGrace(t *testing.T, f *installationNativeWorld, records []rid02CrashRecord) {
	t.Helper()
	require.NotEmpty(t, records)
	until := records[0].Modified.Add(5*time.Minute + time.Second)
	for _, r := range records {
		if end := r.Modified.Add(5*time.Minute + time.Second); end.After(until) {
			until = end
		}
	}
	started := time.Now()
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-f.given.ctx.Done():
		t.Fatal(f.given.ctx.Err())
	}
	require.False(t, time.Now().Before(until))
	raw, err := json.Marshal(map[string]any{"started": started, "completed": time.Now(), "lastModifiedPlusDefaultGrace": until, "defaultOrphanGraceSeconds": 300, "operations": records})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(f.session.Root, "actual-orphan-grace.json"), raw, 0600))
}
func ridNativeCrashPrimaryRecovery(t *testing.T) {
	f, inputs := rid02StageCrashWorld(t)
	normal := operations.NewRepo(f.given.pool, "kaname")
	stages := []string{"before-writer", "before-commit", "after-commit-before-terminal"}
	var records []rid02CrashRecord
	for i, stage := range stages {
		input := inputs[i]
		input.Boundary = stage
		child := startRID02Child(t, f, "crash-"+stage, input)
		bounded, cancel := context.WithTimeout(f.given.ctx, 25*time.Second)
		event := child.await(t, bounded, stage)
		cancel()
		records = append(records, rid02Pending(t, f, input, event.Operation, i == 2))
		require.NoError(t, child.kill())
		child.wait(t, true)
		// Независимая первичная видимость после настоящей смерти процесса ОС/отката соединения.
		rid02Pending(t, f, input, event.Operation, i == 2)
	}
	reconciler, resolver, observer := rid02Recovery(t, f)
	for _, record := range records {
		op, err := normal.Get(f.given.ctx, record.Operation)
		require.NoError(t, err)
		result, err := resolver.Resolve(f.given.ctx, *op)
		require.NoError(t, err)
		if record.Committed {
			require.Equal(t, operations.OutcomeDone, result.Outcome)
			var got iamv1.GrantDelegation
			require.NoError(t, result.Response.UnmarshalTo(&got))
			require.Equal(t, record.Proposed, got.Id)
		} else {
			require.Equal(t, operations.OutcomeInterrupted, result.Outcome)
		}
	}
	require.EqualValues(t, 3, observer.primary.Load())
	n, err := reconciler.Sweep(f.given.ctx)
	require.NoError(t, err)
	require.Zero(t, n, "normal grace must not recover immature Operations")
	rid02WaitOrphanGrace(t, f, records)
	n, err = reconciler.Sweep(f.given.ctx)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	for _, record := range records {
		op, err := normal.Get(f.given.ctx, record.Operation)
		require.NoError(t, err)
		require.True(t, op.Done)
		require.Equal(t, record.MetadataType, op.Metadata.TypeUrl)
		require.Equal(t, record.Metadata, op.Metadata.Value)
		if record.Committed {
			requireNativeInstallationOperation(t, f.given.ctx, f.given.pool, record.Operation, record.Input.Input.AccountID, f.creator.ID, record.Proposed)
			var row string
			require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT to_jsonb(g)::text FROM kaname.grant_delegations g WHERE id=$1`, record.Proposed).Scan(&row))
			require.Equal(t, record.ResourceJSON, row, "recovery preserves all committed GD fields including createdAt")
		} else {
			require.NotNil(t, op.Error)
			require.Equal(t, int32(codes.Internal), op.Error.Code)
			require.Equal(t, "operation interrupted before completion", op.Error.Message)
			require.Nil(t, op.Response)
		}
		again, err := resolver.Resolve(f.given.ctx, *op)
		require.NoError(t, err)
		if record.Committed {
			require.True(t, proto.Equal(op.Response, again.Response))
		}
	}
	n, err = reconciler.Sweep(f.given.ctx)
	require.NoError(t, err)
	require.Zero(t, n, "terminal recovery is idempotent")
	rid02PublicRecoveredCensus(t, f, records)
}
