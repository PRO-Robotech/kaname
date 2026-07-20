// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package user

// user_test.go — unit-тесты sync-валидации user use-cases (без БД).
//
// Покрытие:
//   - Get: invalid id format → InvalidArgument.
//   - Delete: invalid id format → InvalidArgument.
//   - UpsertFromIdentity: required external_id; invalid email format.

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

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/operations"
	gstatus "google.golang.org/genproto/googleapis/rpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
	repouser "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

func TestGetUser_Sync_InvalidID(t *testing.T) {
	uc := NewGetUserUseCase(newFakeUserRepo())
	_, err := uc.Execute(context.Background(), "bad-id-x")
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDeleteUser_Sync_InvalidID(t *testing.T) {
	uc := NewDeleteUserUseCase(newFakeUserRepo(), newFakeOpsRepoUser())
	op, err := uc.Execute(context.Background(), "bad-id")
	require.Error(t, err)
	assert.Nil(t, op)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestUpsertFromIdentity_Sync_RequireExternalID(t *testing.T) {
	uc := NewUpsertFromIdentityUseCase(newFakeUserRepo(), newFakeOpsRepoUser())
	op, err := uc.Execute(context.Background(), UpsertFromIdentityInput{
		Email: "u@example.com",
	})
	require.Error(t, err)
	assert.Nil(t, op)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, err.Error(), "external_id")
}

func TestUpsertFromIdentity_Sync_InvalidEmail(t *testing.T) {
	uc := NewUpsertFromIdentityUseCase(newFakeUserRepo(), newFakeOpsRepoUser())
	op, err := uc.Execute(context.Background(), UpsertFromIdentityInput{
		ExternalID: "ext-1",
		Email:      "not-an-email",
	})
	require.Error(t, err)
	assert.Nil(t, op)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestUpsertFromIdentity_Sync_OK_OpReturned(t *testing.T) {
	repo := newFakeUserRepo()
	uc := NewUpsertFromIdentityUseCase(repo, newFakeOpsRepoUser())
	op, err := uc.Execute(context.Background(), UpsertFromIdentityInput{
		ExternalID:  "zit-ok",
		Email:       "ok@example.com",
		DisplayName: "OK",
	})
	require.NoError(t, err)
	require.NotNil(t, op)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(ctx))
	assert.Equal(t, 1, repo.upsertCalls(), "upsert called by worker")
}

// TestUpsertFromIdentity_Metadata_ExistingUserID.
// Когда по external_id уже есть ACTIVE-row, Operation.metadata.user_id обязан
// нести id СУЩЕСТВУЮЩЕГО row (а не throwaway ids.NewID()), и created=false.
func TestUpsertFromIdentity_Metadata_ExistingUserID(t *testing.T) {
	const existingID = "usr0000000000existng"
	repo := newFakeUserRepo()
	repo.existingActive = []domain.User{{
		ID:           domain.UserID(existingID),
		ExternalID:   "zit-existing",
		Email:        "exist@example.com",
		DisplayName:  "Existing",
		InviteStatus: domain.InviteStatusActive,
	}}
	uc := NewUpsertFromIdentityUseCase(repo, newFakeOpsRepoUser())

	op, err := uc.Execute(context.Background(), UpsertFromIdentityInput{
		ExternalID:  "zit-existing",
		Email:       "exist@example.com",
		DisplayName: "Existing",
	})
	require.NoError(t, err)
	require.NotNil(t, op)

	meta, err := operations.MetadataFor[*iamv1.UpsertFromIdentityMetadata](op)
	require.NoError(t, err)
	assert.Equal(t, existingID, meta.GetUserId(),
		"metadata.user_id must be the existing row id, not a throwaway id")
	assert.False(t, meta.GetCreated(), "created=false when user already exists")
}

// TestUpsertFromIdentity_Metadata_NewUserID (bootstrap-path).
// Когда identity новая (нет ACTIVE/PENDING-row), metadata.user_id — новый id,
// created=true, и тот же id используется bootstrap-row'ом.
func TestUpsertFromIdentity_Metadata_NewUserID(t *testing.T) {
	repo := newFakeUserRepo() // existingActive nil → bootstrap path
	uc := NewUpsertFromIdentityUseCase(repo, newFakeOpsRepoUser())

	op, err := uc.Execute(context.Background(), UpsertFromIdentityInput{
		ExternalID:  "zit-fresh",
		Email:       "fresh@example.com",
		DisplayName: "Fresh",
	})
	require.NoError(t, err)
	require.NotNil(t, op)

	meta, err := operations.MetadataFor[*iamv1.UpsertFromIdentityMetadata](op)
	require.NoError(t, err)
	assert.NotEmpty(t, meta.GetUserId())
	assert.True(t, meta.GetCreated(), "created=true for fresh bootstrap identity")
}

// ── SEC-L: signup/bootstrap path writes the cluster parent-tuples ───────────

// spyFGA records WriteTuples calls so the test can assert the SEC-L cluster
// parent-pointer tuples are emitted on the bootstrap path. Mirrors the spyFGA
// helper in account/create_test.go and satisfies clients.RelationStore.
type spyFGA struct {
	mu    sync.Mutex
	wrote []clients.RelationTuple
}

func (s *spyFGA) Check(context.Context, string, string, string) (bool, error) { return false, nil }
func (s *spyFGA) WriteTuples(_ context.Context, t []clients.RelationTuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wrote = append(s.wrote, t...)
	return nil
}
func (s *spyFGA) DeleteTuples(context.Context, []clients.RelationTuple) error { return nil }

func (s *spyFGA) snapshot() []clients.RelationTuple {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]clients.RelationTuple, len(s.wrote))
	copy(cp, s.wrote)
	return cp
}

// TestUpsertFromIdentity_SECL_BootstrapEmitsClusterParentTuplesInTx — 1.4-10b
// (S2-iam): the signup/identity-bootstrap path that provisions a NEW account +
// default project must co-commit the WHOLE bootstrap-graph (owner self-grant +
// admin self-grants + hierarchy + SEC-L cluster parent-pointer tuples) as
// fga_outbox INTENTS in the SAME bootstrap-tx — NOT best-effort post-commit
// through RelationStore.WriteTuples (which lost them on any FGA outage). The
// owner self-grant is D-4 non-reconstructible, so the in-tx emit is the only
// guarantee.
func TestUpsertFromIdentity_SECL_BootstrapEmitsClusterParentTuplesInTx(t *testing.T) {
	repo := newFakeUserRepo() // existingActive nil → bootstrap path
	fga := &spyFGA{}
	uc := NewUpsertFromIdentityUseCase(repo, newFakeOpsRepoUser()).WithRelationStore(fga, nil)

	op, err := uc.Execute(context.Background(), UpsertFromIdentityInput{
		ExternalID:  "zit-bootstrap-secl",
		Email:       "bootstrap-secl@example.com",
		DisplayName: "Bootstrap SEC-L",
	})
	require.NoError(t, err)
	require.NotNil(t, op)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(ctx))

	var accountClusterSeen, projectClusterSeen, ownerSeen bool
	for _, tup := range repo.fgaTuples() {
		if tup.Relation == "cluster" && tup.User == "cluster:cluster_kacho_root" {
			if strings.HasPrefix(tup.Object, "account:") {
				accountClusterSeen = true
			}
			if strings.HasPrefix(tup.Object, "project:") {
				projectClusterSeen = true
			}
		}
		if tup.Relation == "owner" && strings.HasPrefix(tup.User, "user:") &&
			strings.HasPrefix(tup.Object, "account:") {
			ownerSeen = true
		}
	}
	assert.True(t, ownerSeen,
		"bootstrap owner self-grant intent must be co-committed in-tx (D-4: not reconstructible)")
	assert.True(t, accountClusterSeen,
		"SEC-L: bootstrap must co-commit account:<id>#cluster@cluster:cluster_kacho_root in-tx")
	assert.True(t, projectClusterSeen,
		"SEC-L: bootstrap must co-commit project:<id>#cluster@cluster:cluster_kacho_root in-tx")
	assert.Empty(t, fga.snapshot(),
		"bootstrap must NOT write tuples post-commit via RelationStore (now in-tx outbox)")
}

// ── fakes ────────────────────────────────────────────────────────────────

type fakeUserRepo struct {
	mu          sync.Mutex
	upsertCount int
	// existingActive — ACTIVE-row'ы, возвращаемые FindActiveByExternalID
	// (для проверки resolveUserID).
	existingActive []domain.User
	fgaEmitted     []service.RelationTuple
}

func newFakeUserRepo() *fakeUserRepo { return &fakeUserRepo{} }

func (f *fakeUserRepo) upsertCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.upsertCount
}

// fgaTuples — snapshot of the bootstrap FGA owner-tuple intents emitted in-tx.
func (f *fakeUserRepo) fgaTuples() []service.RelationTuple {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]service.RelationTuple, len(f.fgaEmitted))
	copy(cp, f.fgaEmitted)
	return cp
}

func (f *fakeUserRepo) Reader(ctx context.Context) (kachorepo.Reader, error) {
	return &fakeURdr{parent: f}, nil
}
func (f *fakeUserRepo) Writer(ctx context.Context) (kachorepo.Writer, error) {
	return &fakeUWtr{fakeURdr: fakeURdr{parent: f}, parent: f}, nil
}
func (f *fakeUserRepo) Close() {}

type fakeURdr struct{ parent *fakeUserRepo }

func (fakeURdr) Accounts() account.ReaderIface                { return fakeUserAccR{} }
func (fakeURdr) Projects() project.ReaderIface                { return nil }
func (r fakeURdr) Users() repouser.ReaderIface                { return fakeUserUR{parent: r.parent} }
func (fakeURdr) ServiceAccounts() service_account.ReaderIface { return nil }
func (fakeURdr) Groups() group.ReaderIface                    { return nil }
func (fakeURdr) Roles() role.ReaderIface                      { return nil }
func (fakeURdr) AccessBindings() access_binding.ReaderIface   { return nil }
func (fakeURdr) Commit(context.Context) error                 { return nil }
func (fakeURdr) Rollback(context.Context) error               { return nil }

// fakeUserAccR — account-reader stub for the RC-5 owns-zero-accounts gate. These
// unit tests drive the genuinely-new-identity bootstrap path, where the resolved
// user owns no account → CountAccountsByOwner returns 0 so bootstrap fires.
type fakeUserAccR struct{}

func (fakeUserAccR) Get(context.Context, domain.AccountID) (domain.Account, error) {
	return domain.Account{}, stderrors.New("not stubbed")
}
func (fakeUserAccR) List(context.Context, account.ListFilter) ([]domain.Account, string, error) {
	return nil, "", nil
}
func (fakeUserAccR) ExistsByName(context.Context, domain.AccountName) (bool, error) {
	return false, nil
}
func (fakeUserAccR) CountAccountsByOwner(context.Context, domain.UserID) (int, error) {
	return 0, nil
}

type fakeUWtr struct {
	fakeURdr
	parent *fakeUserRepo
}

func (w *fakeUWtr) AccountsW() account.WriterIface { return fakeAccW{} }
func (w *fakeUWtr) ProjectsW() project.WriterIface { return fakePrjW{} }
func (w *fakeUWtr) UsersW() repouser.WriterIface {
	return &fakeUserUW{fakeUserUR: fakeUserUR{parent: w.parent}, parent: w.parent}
}
func (w *fakeUWtr) ServiceAccountsW() service_account.WriterIface            { return nil }
func (w *fakeUWtr) GroupsW() group.WriterIface                               { return nil }
func (w *fakeUWtr) RolesW() role.WriterIface                                 { return nil }
func (w *fakeUWtr) AccessBindingsW() access_binding.WriterIface              { return fakeABW{} }
func (w *fakeUWtr) EmitAuditEvent(context.Context, service.AuditEvent) error { return nil }
func (w *fakeUWtr) EmitFGARelationWrite(_ context.Context, tuples []service.RelationTuple) error {
	w.parent.mu.Lock()
	w.parent.fgaEmitted = append(w.parent.fgaEmitted, tuples...)
	w.parent.mu.Unlock()
	return nil
}
func (w *fakeUWtr) EmitFGARelationDelete(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *fakeUWtr) InsertRecoveryCompletion(context.Context, domain.RecoveryCompletion) (domain.RecoveryCompletion, bool, error) {
	return domain.RecoveryCompletion{}, false, nil
}
func (w *fakeUWtr) UpsertUserTokenRevokeAll(context.Context, domain.UserTokenRevocation, domain.UserID) error {
	return nil
}
func (w *fakeUWtr) Savepoint(context.Context, string) error           { return nil }
func (w *fakeUWtr) RollbackToSavepoint(context.Context, string) error { return nil }
func (w *fakeUWtr) ReleaseSavepoint(context.Context, string) error    { return nil }
func (w *fakeUWtr) AdvisoryXactLock(context.Context, string) error    { return nil }

// Stubs нужные для bootstrap-path (InsertActive + Account.Insert +
// Project.Insert + AB.Insert). Возвращают входной argument как success.

type fakeAccW struct{}

func (fakeAccW) Insert(_ context.Context, a domain.Account) (domain.Account, error) {
	a.CreatedAt = time.Now().UTC()
	return a, nil
}
func (fakeAccW) Update(_ context.Context, a domain.Account, _ []string) (domain.Account, error) {
	return a, nil
}
func (fakeAccW) Delete(context.Context, domain.AccountID) error { return nil }

type fakePrjW struct{}

func (fakePrjW) Insert(_ context.Context, p domain.Project) (domain.Project, error) {
	p.CreatedAt = time.Now().UTC()
	return p, nil
}
func (fakePrjW) Update(_ context.Context, p domain.Project, _ []string) (domain.Project, error) {
	return p, nil
}
func (fakePrjW) Delete(context.Context, domain.ProjectID) error { return nil }

type fakeABW struct{}

func (fakeABW) Insert(_ context.Context, b domain.AccessBinding) (domain.AccessBinding, error) {
	b.CreatedAt = time.Now().UTC()
	return b, nil
}
func (fakeABW) Delete(context.Context, domain.AccessBindingID) error        { return nil }
func (fakeABW) DeleteGuarded(context.Context, domain.AccessBindingID) error { return nil }
func (fakeABW) RevokeGuarded(context.Context, domain.AccessBindingID, domain.UserID) (domain.AccessBinding, error) {
	return domain.AccessBinding{}, nil
}
func (fakeABW) SetDeletionProtection(context.Context, domain.AccessBindingID, bool) (domain.AccessBinding, error) {
	return domain.AccessBinding{}, nil
}
func (fakeABW) UpdateLabels(context.Context, domain.AccessBindingID, domain.Labels) (domain.AccessBinding, error) {
	return domain.AccessBinding{}, nil
}
func (fakeABW) TransitionStatus(
	_ context.Context, _ domain.AccessBindingID, _ []domain.AccessBindingStatus,
	_ domain.AccessBindingStatus, _ *domain.UserID,
) (domain.AccessBinding, error) {
	return domain.AccessBinding{}, nil
}
func (fakeABW) EmitSubjectChangeEvent(context.Context, access_binding.SubjectChangeEvent) error {
	return nil
}
func (fakeABW) EmitRelationWrite(context.Context, []access_binding.RelationTuple) error  { return nil }
func (fakeABW) EmitRelationDelete(context.Context, []access_binding.RelationTuple) error { return nil }
func (fakeABW) EmitAuditEvent(context.Context, access_binding.AuditEvent) error          { return nil }
func (fakeABW) InsertEmittedTuples(context.Context, domain.AccessBindingID, []access_binding.RelationTuple) error {
	return nil
}
func (fakeABW) ReplaceEmittedTuples(context.Context, domain.AccessBindingID, []access_binding.RelationTuple) error {
	return nil
}
func (fakeABW) InsertSubjects(context.Context, domain.AccessBindingID, []domain.Subject) error {
	return nil
}
func (fakeABW) DeleteSubject(context.Context, domain.AccessBindingID, domain.Subject) (bool, error) {
	return false, nil
}

type fakeUserUR struct{ parent *fakeUserRepo }

func (fakeUserUR) Get(context.Context, domain.UserID) (domain.User, error) {
	return domain.User{}, stderrors.New("not stubbed")
}
func (fakeUserUR) GetByExternalID(context.Context, domain.ExternalSubject) (domain.User, error) {
	return domain.User{}, stderrors.New("not stubbed")
}
func (fakeUserUR) GetByEmail(context.Context, domain.Email) (domain.User, error) {
	return domain.User{}, stderrors.New("not stubbed")
}
func (fakeUserUR) GetByAccountEmail(context.Context, domain.AccountID, domain.Email) (domain.User, error) {
	return domain.User{}, stderrors.New("not stubbed")
}
func (fakeUserUR) FindPendingByEmail(context.Context, domain.Email) ([]domain.User, error) {
	return nil, nil
}
func (r fakeUserUR) FindActiveByExternalID(_ context.Context, ext domain.ExternalSubject) ([]domain.User, error) {
	if r.parent == nil {
		return nil, nil
	}
	var out []domain.User
	for _, u := range r.parent.existingActive {
		if u.ExternalID == ext {
			out = append(out, u)
		}
	}
	return out, nil
}
func (r fakeUserUR) FindByExternalIDInStatuses(_ context.Context, ext domain.ExternalSubject, _ []domain.InviteStatus) ([]domain.User, error) {
	if r.parent == nil {
		return nil, nil
	}
	var out []domain.User
	for _, u := range r.parent.existingActive {
		if u.ExternalID == ext {
			out = append(out, u)
		}
	}
	return out, nil
}
func (r fakeUserUR) FindActiveByEmail(_ context.Context, email domain.Email) ([]domain.User, error) {
	if r.parent == nil {
		return nil, nil
	}
	var out []domain.User
	for _, u := range r.parent.existingActive {
		if strings.EqualFold(string(u.Email), string(email)) {
			out = append(out, u)
		}
	}
	return out, nil
}
func (fakeUserUR) ListAccountsForUser(context.Context, domain.UserID) ([]domain.AccountID, error) {
	return nil, nil
}
func (fakeUserUR) List(context.Context, repouser.ListFilter) ([]domain.User, string, error) {
	return nil, "", nil
}

type fakeUserUW struct {
	fakeUserUR
	parent *fakeUserRepo
}

func (w *fakeUserUW) Upsert(_ context.Context, u domain.User) (domain.User, bool, error) {
	w.parent.mu.Lock()
	w.parent.upsertCount++
	w.parent.mu.Unlock()
	u.CreatedAt = time.Now().UTC()
	return u, true, nil
}
func (w *fakeUserUW) InsertPending(_ context.Context, u domain.User) (domain.User, bool, error) {
	u.CreatedAt = time.Now().UTC()
	return u, true, nil
}
func (w *fakeUserUW) ActivateInvite(_ context.Context, userID domain.UserID, ext domain.ExternalSubject, dn domain.DisplayName) (domain.User, error) {
	return domain.User{ID: userID, ExternalID: ext, DisplayName: dn, InviteStatus: domain.InviteStatusActive}, nil
}

// InsertActive — bootstrap-path; для совместимости с старым тестом
// `TestUpsertFromIdentity_Sync_OK_OpReturned` (он считает Upsert-calls) этот
// fake инкрементит тот же счетчик: legacy Upsert и new InsertActive семантически
// эквивалентны для admin-tooling-stub-теста (оба фиксируют «row создана через
// upsert-from-identity worker»).
func (w *fakeUserUW) InsertActive(_ context.Context, u domain.User) (domain.User, error) {
	w.parent.mu.Lock()
	w.parent.upsertCount++
	w.parent.mu.Unlock()
	u.CreatedAt = time.Now().UTC()
	return u, nil
}
func (w *fakeUserUW) ReEnable(_ context.Context, id domain.UserID) (domain.User, bool, error) {
	return domain.User{ID: id, InviteStatus: domain.InviteStatusActive}, false, nil
}
func (w *fakeUserUW) Delete(context.Context, domain.UserID) error { return nil }
func (w *fakeUserUW) UpdateLabels(_ context.Context, id domain.UserID, _ domain.Labels) (domain.User, error) {
	return domain.User{ID: id}, nil
}

// fake ops
type fakeOpsRepoUser struct {
	mu  sync.Mutex
	ops map[string]*operations.Operation
}

func newFakeOpsRepoUser() *fakeOpsRepoUser {
	return &fakeOpsRepoUser{ops: map[string]*operations.Operation{}}
}

func (r *fakeOpsRepoUser) Create(_ context.Context, op operations.Operation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := op
	r.ops[op.ID] = &cp
	return nil
}
func (r *fakeOpsRepoUser) CreateWithPrincipal(_ context.Context, op operations.Operation, _ operations.Principal) error {
	return r.Create(context.Background(), op)
}
func (r *fakeOpsRepoUser) Get(_ context.Context, id string) (*operations.Operation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	op, ok := r.ops[id]
	if !ok {
		return nil, operations.ErrNotFound
	}
	cp := *op
	return &cp, nil
}
func (r *fakeOpsRepoUser) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}
func (r *fakeOpsRepoUser) MarkDone(_ context.Context, id string, resp *anypb.Any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
		op.Response = resp
	}
	return nil
}
func (r *fakeOpsRepoUser) MarkError(_ context.Context, id string, st *gstatus.Status) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
		op.Error = st
	}
	return nil
}
func (r *fakeOpsRepoUser) Cancel(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
	}
	return nil
}

// EmitReconcileEvent — T3/Q2 no-op stub (fake does not exercise the iam-direct reconcile trigger).
func (w *fakeUWtr) EmitReconcileEvent(context.Context, string, string, string) error {
	return nil
}
