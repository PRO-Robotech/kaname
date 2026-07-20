// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package project

// create_test.go — unit-тесты CreateProjectUseCase (без БД). Покрывают
// sync-validation: required fields, name regex, invalid id, immutable mask.

import (
	"context"
	stderrors "errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	gstatus "google.golang.org/genproto/googleapis/rpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
	repoproject "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// ── account_id required ────────────────────────────────────────────────────
func TestCreateProject_Sync_RequireAccount(t *testing.T) {
	uc := NewCreateProjectUseCase(newFakeProjRepo(), newFakeOpsRepoProj())
	op, err := uc.Execute(operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: "test-principal"}), domain.Project{
		Name: "prj-x",
	})
	require.Error(t, err)
	assert.Nil(t, op)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, err.Error(), "account_id")
}

// ── account_id malformed → InvalidArg ──────────────────────────────────────
func TestCreateProject_Sync_InvalidAccountIDFormat(t *testing.T) {
	uc := NewCreateProjectUseCase(newFakeProjRepo(), newFakeOpsRepoProj())
	op, err := uc.Execute(operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: "test-principal"}), domain.Project{
		AccountID: "wrong-prefix-id",
		Name:      "prj-x",
	})
	require.Error(t, err)
	assert.Nil(t, op)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// ── invalid name → InvalidArg ──────────────────────────────────────────────
func TestCreateProject_Sync_InvalidName(t *testing.T) {
	uc := NewCreateProjectUseCase(newFakeProjRepo(), newFakeOpsRepoProj())
	op, err := uc.Execute(operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: "test-principal"}), domain.Project{
		AccountID: "acc0000000000000abcd",
		Name:      "Bad_Name",
	})
	require.Error(t, err)
	assert.Nil(t, op)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// ── happy: Operation возвращен + worker дошел до Insert ────────────────────
func TestCreateProject_Sync_OK_OpReturned(t *testing.T) {
	repo := newFakeProjRepo()
	opsRepo := newFakeOpsRepoProj()
	uc := NewCreateProjectUseCase(repo, opsRepo)
	op, err := uc.Execute(operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: "test-principal"}), domain.Project{
		AccountID: "acc0000000000000abcd",
		Name:      "prj-ok",
	})
	require.NoError(t, err)
	require.NotNil(t, op)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(ctx))
	assert.Equal(t, 1, repo.insertCalls())
}

// ── UpdateProject: immutable account_id в mask → InvalidArg ────────────────
func TestUpdateProject_Sync_ImmutableAccountID(t *testing.T) {
	uc := NewUpdateProjectUseCase(newFakeProjRepo(), newFakeOpsRepoProj())
	op, err := uc.Execute(operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: "test-principal"}), UpdateProjectInput{
		ID:         "prj0000000000000xxxx",
		UpdateMask: []string{"account_id"},
	})
	require.Error(t, err)
	assert.Nil(t, op)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	// redesign-2026 F3: camelCase contract text (no Move RPC).
	assert.Contains(t, err.Error(), "accountId is immutable after Project.Create")
}

// ── UpdateProject: unknown mask field → InvalidArg ─────────────────────────
func TestUpdateProject_Sync_UnknownMaskField(t *testing.T) {
	uc := NewUpdateProjectUseCase(newFakeProjRepo(), newFakeOpsRepoProj())
	op, err := uc.Execute(operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: "test-principal"}), UpdateProjectInput{
		ID:         "prj0000000000000xxxx",
		UpdateMask: []string{"unknown_field"},
	})
	require.Error(t, err)
	assert.Nil(t, op)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// ── SEC-L: Create writes the cluster parent-tuple ──────────────────────

// projSpyFGA records WriteTuples calls.
type projSpyFGA struct {
	mu    sync.Mutex
	wrote []clients.RelationTuple
}

func (s *projSpyFGA) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}
func (s *projSpyFGA) WriteTuples(_ context.Context, t []clients.RelationTuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wrote = append(s.wrote, t...)
	return nil
}
func (s *projSpyFGA) DeleteTuples(context.Context, []clients.RelationTuple) error { return nil }

func (s *projSpyFGA) snapshot() []clients.RelationTuple {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]clients.RelationTuple, len(s.wrote))
	copy(cp, s.wrote)
	return cp
}

// TestCreateProject_SECL_EmitsHierarchyAndClusterTupleInTx: the freshly-created
// project must co-commit project→account hierarchy AND the SEC-L cluster
// parent-pointer as fga_outbox INTENTS in the SAME writer-tx — NOT best-effort
// post-commit through RelationStore.WriteTuples.
func TestCreateProject_SECL_EmitsHierarchyAndClusterTupleInTx(t *testing.T) {
	repo := newFakeProjRepo()
	opsRepo := newFakeOpsRepoProj()
	fga := &projSpyFGA{}
	uc := NewCreateProjectUseCase(repo, opsRepo).WithRelationStore(fga, nil)

	op, err := uc.Execute(operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "test-principal"}),
		domain.Project{AccountID: "acc0000000000000abcd", Name: "prj-secl"})
	require.NoError(t, err)
	require.NotNil(t, op)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(ctx))

	var accSeen, clusterSeen bool
	for _, tup := range repo.fgaTuples() {
		if tup.Relation == "account" && tup.User == "account:acc0000000000000abcd" &&
			strings.HasPrefix(tup.Object, "project:") {
			accSeen = true
		}
		if tup.Relation == "cluster" && tup.User == "cluster:cluster_kacho_root" &&
			strings.HasPrefix(tup.Object, "project:") {
			clusterSeen = true
		}
	}
	assert.True(t, accSeen, "project→account hierarchy intent co-committed in-tx")
	assert.True(t, clusterSeen,
		"SEC-L: project:<id>#cluster@cluster:cluster_kacho_root must be co-committed in-tx")
	assert.Empty(t, fga.snapshot(),
		"create path must NOT write tuples post-commit via RelationStore (now in-tx outbox)")
}

// ── in-memory fake Repo + ops ──────────────────────────────────────────────

type fakeProjRepo struct {
	mu           sync.Mutex
	insertCount  int
	currentAccID domain.AccountID
	fgaEmitted   []service.RelationTuple
}

func newFakeProjRepo() *fakeProjRepo { return &fakeProjRepo{} }

func (f *fakeProjRepo) insertCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.insertCount
}

// fgaTuples — snapshot of the FGA hierarchy owner-tuple intents emitted in-tx.
func (f *fakeProjRepo) fgaTuples() []service.RelationTuple {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]service.RelationTuple, len(f.fgaEmitted))
	copy(cp, f.fgaEmitted)
	return cp
}

func (f *fakeProjRepo) Reader(ctx context.Context) (kachorepo.Reader, error) {
	return &fakeProjReader{parent: f}, nil
}
func (f *fakeProjRepo) Writer(ctx context.Context) (kachorepo.Writer, error) {
	return &fakeProjWriter{parent: f}, nil
}
func (f *fakeProjRepo) Close() {}

type fakeProjReader struct {
	parent *fakeProjRepo
}

func (r *fakeProjReader) Accounts() account.ReaderIface                { return nil }
func (r *fakeProjReader) Projects() repoproject.ReaderIface            { return &fakeProjPRdr{parent: r.parent} }
func (r *fakeProjReader) Users() user.ReaderIface                      { return nil }
func (r *fakeProjReader) ServiceAccounts() service_account.ReaderIface { return nil }
func (r *fakeProjReader) Groups() group.ReaderIface                    { return nil }
func (r *fakeProjReader) Roles() role.ReaderIface                      { return nil }
func (r *fakeProjReader) AccessBindings() access_binding.ReaderIface   { return nil }
func (r *fakeProjReader) Commit(context.Context) error                 { return nil }
func (r *fakeProjReader) Rollback(context.Context) error               { return nil }

type fakeProjWriter struct {
	fakeProjReader
	parent *fakeProjRepo
}

func (w *fakeProjWriter) Accounts() account.ReaderIface { return nil }
func (w *fakeProjWriter) Projects() repoproject.ReaderIface {
	return &fakeProjPRdr{parent: w.parent}
}
func (w *fakeProjWriter) Users() user.ReaderIface                      { return nil }
func (w *fakeProjWriter) ServiceAccounts() service_account.ReaderIface { return nil }
func (w *fakeProjWriter) Groups() group.ReaderIface                    { return nil }
func (w *fakeProjWriter) Roles() role.ReaderIface                      { return nil }
func (w *fakeProjWriter) AccessBindings() access_binding.ReaderIface   { return nil }
func (w *fakeProjWriter) Commit(context.Context) error                 { return nil }
func (w *fakeProjWriter) Rollback(context.Context) error               { return nil }

func (w *fakeProjWriter) AccountsW() account.WriterIface                           { return nil }
func (w *fakeProjWriter) ProjectsW() repoproject.WriterIface                       { return &fakeProjPWtr{parent: w.parent} }
func (w *fakeProjWriter) UsersW() user.WriterIface                                 { return nil }
func (w *fakeProjWriter) ServiceAccountsW() service_account.WriterIface            { return nil }
func (w *fakeProjWriter) GroupsW() group.WriterIface                               { return nil }
func (w *fakeProjWriter) RolesW() role.WriterIface                                 { return nil }
func (w *fakeProjWriter) AccessBindingsW() access_binding.WriterIface              { return nil }
func (w *fakeProjWriter) EmitAuditEvent(context.Context, service.AuditEvent) error { return nil }
func (w *fakeProjWriter) EmitFGARelationWrite(_ context.Context, tuples []service.RelationTuple) error {
	w.parent.mu.Lock()
	w.parent.fgaEmitted = append(w.parent.fgaEmitted, tuples...)
	w.parent.mu.Unlock()
	return nil
}
func (w *fakeProjWriter) EmitFGARelationDelete(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *fakeProjWriter) InsertRecoveryCompletion(context.Context, domain.RecoveryCompletion) (domain.RecoveryCompletion, bool, error) {
	return domain.RecoveryCompletion{}, false, nil
}
func (w *fakeProjWriter) UpsertUserTokenRevokeAll(context.Context, domain.UserTokenRevocation, domain.UserID) error {
	return nil
}
func (w *fakeProjWriter) Savepoint(context.Context, string) error           { return nil }
func (w *fakeProjWriter) RollbackToSavepoint(context.Context, string) error { return nil }
func (w *fakeProjWriter) ReleaseSavepoint(context.Context, string) error    { return nil }
func (w *fakeProjWriter) AdvisoryXactLock(context.Context, string) error    { return nil }

type fakeProjPRdr struct {
	parent *fakeProjRepo
}

func (r *fakeProjPRdr) Get(_ context.Context, id domain.ProjectID) (domain.Project, error) {
	if r.parent.currentAccID == "" {
		return domain.Project{}, stderrors.New("fake.Get not stubbed")
	}
	return domain.Project{
		ID:        id,
		AccountID: r.parent.currentAccID,
		Name:      "fake-name",
		CreatedAt: time.Now().UTC(),
	}, nil
}
func (r *fakeProjPRdr) List(context.Context, repoproject.ListFilter) ([]domain.Project, string, error) {
	return nil, "", nil
}
func (r *fakeProjPRdr) CountByAccount(context.Context, domain.AccountID) (int64, error) {
	return 0, nil
}

type fakeProjPWtr struct {
	fakeProjPRdr
	parent *fakeProjRepo
}

func (w *fakeProjPWtr) Insert(_ context.Context, p domain.Project) (domain.Project, error) {
	w.parent.mu.Lock()
	w.parent.insertCount++
	w.parent.mu.Unlock()
	p.CreatedAt = time.Now().UTC()
	return p, nil
}
func (w *fakeProjPWtr) Update(_ context.Context, p domain.Project, _ []string) (domain.Project, error) {
	return p, nil
}
func (w *fakeProjPWtr) Delete(context.Context, domain.ProjectID) error { return nil }

// fake ops repo (parity с account-tests).
type fakeOpsRepoProj struct {
	mu  sync.Mutex
	ops map[string]*operations.Operation
}

func newFakeOpsRepoProj() *fakeOpsRepoProj {
	return &fakeOpsRepoProj{ops: map[string]*operations.Operation{}}
}

func (r *fakeOpsRepoProj) Create(_ context.Context, op operations.Operation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := op
	r.ops[op.ID] = &cp
	return nil
}
func (r *fakeOpsRepoProj) CreateWithPrincipal(_ context.Context, op operations.Operation, _ operations.Principal) error {
	return r.Create(context.Background(), op)
}
func (r *fakeOpsRepoProj) Get(_ context.Context, id string) (*operations.Operation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	op, ok := r.ops[id]
	if !ok {
		return nil, operations.ErrNotFound
	}
	cp := *op
	return &cp, nil
}
func (r *fakeOpsRepoProj) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}
func (r *fakeOpsRepoProj) MarkDone(_ context.Context, id string, resp *anypb.Any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
		op.Response = resp
	}
	return nil
}
func (r *fakeOpsRepoProj) MarkError(_ context.Context, id string, st *gstatus.Status) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
		op.Error = st
	}
	return nil
}
func (r *fakeOpsRepoProj) Cancel(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
	}
	return nil
}

// EmitReconcileEvent — no-op stub (fake does not exercise the iam-direct reconcile trigger).
func (w *fakeProjWriter) EmitReconcileEvent(context.Context, string, string, string) error {
	return nil
}
