// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package group

// account_id_metadata_test.go — GroupService Create + AddMember + RemoveMember
// must stamp the owning account_id into the emitted *Metadata so corelib's
// exact-name extractAccountID denormalizes it into operations.account_id → the
// account-scoped module list includes group CRUD AND member-change operations.
//
// Create stamps from the input g.AccountID. AddMember/RemoveMember stamp from
// the group loaded synchronously for authz (g.AccountID is in scope at op-build
// — add_member.go:56,61 / remove_member.go:55,60).

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	gstatus "google.golang.org/genproto/googleapis/rpc/status"

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

const (
	metaAcc   = "acc0000000000000abcd"
	metaOwner = "usr0000000000000ownr"
	metaGrp   = "grp0000000000000gggg"
)

// ── ctx with principal == account owner so RequireOwnerMatchesPrincipal passes ─
func ownerCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: metaOwner})
}

func firstOp(t *testing.T, r *fakeGrpOps) operations.Operation {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	require.Len(t, r.ops, 1, "exactly one operation must be created")
	for _, op := range r.ops {
		return *op
	}
	return operations.Operation{}
}

func TestCreateGroup_StampsAccountID(t *testing.T) {
	opsRepo := newFakeGrpOps()
	uc := NewCreateGroupUseCase(newFakeGrpRepo(), opsRepo)
	op, err := uc.Execute(ownerCtx(), domain.Group{AccountID: metaAcc, Name: "grp-ok"})
	require.NoError(t, err)
	require.NotNil(t, op)

	md := &iamv1.CreateGroupMetadata{}
	require.NoError(t, firstOp(t, opsRepo).Metadata.UnmarshalTo(md))
	assert.Equal(t, metaAcc, md.GetAccountId(), "CreateGroupMetadata.account_id from input AccountID")
}

func TestAddGroupMember_StampsAccountID(t *testing.T) {
	opsRepo := newFakeGrpOps()
	uc := NewAddMemberUseCase(newFakeGrpRepo(), opsRepo)
	op, err := uc.Execute(ownerCtx(), AddMemberInput{
		GroupID: metaGrp, MemberType: domain.SubjectTypeUser, MemberID: "usr0000000000000mmmm",
	})
	require.NoError(t, err)
	require.NotNil(t, op)

	md := &iamv1.AddGroupMemberMetadata{}
	require.NoError(t, firstOp(t, opsRepo).Metadata.UnmarshalTo(md))
	assert.Equal(t, metaAcc, md.GetAccountId(),
		"AddGroupMemberMetadata.account_id from loaded g.AccountID (BLOCK-1 1.2-11e)")
}

func TestRemoveGroupMember_StampsAccountID(t *testing.T) {
	opsRepo := newFakeGrpOps()
	uc := NewRemoveMemberUseCase(newFakeGrpRepo(), opsRepo)
	op, err := uc.Execute(ownerCtx(), RemoveMemberInput{
		GroupID: metaGrp, MemberType: domain.SubjectTypeUser, MemberID: "usr0000000000000mmmm",
	})
	require.NoError(t, err)
	require.NotNil(t, op)

	md := &iamv1.RemoveGroupMemberMetadata{}
	require.NoError(t, firstOp(t, opsRepo).Metadata.UnmarshalTo(md))
	assert.Equal(t, metaAcc, md.GetAccountId(),
		"RemoveGroupMemberMetadata.account_id from loaded g.AccountID (BLOCK-1 1.2-11e)")
}

// ── compact fake Repo (Groups + Accounts populated; rest nil) ───────────────

type fakeGrpRepo struct{}

func newFakeGrpRepo() *fakeGrpRepo { return &fakeGrpRepo{} }

func (f *fakeGrpRepo) Reader(context.Context) (kachorepo.Reader, error) { return &fakeGrpReader{}, nil }
func (f *fakeGrpRepo) Writer(context.Context) (kachorepo.Writer, error) { return &fakeGrpWriter{}, nil }
func (f *fakeGrpRepo) Close()                                           {}

type fakeGrpReader struct{}

func (r *fakeGrpReader) Accounts() account.ReaderIface                { return &fakeAccRdr{} }
func (r *fakeGrpReader) Projects() repoproject.ReaderIface            { return nil }
func (r *fakeGrpReader) Users() user.ReaderIface                      { return nil }
func (r *fakeGrpReader) ServiceAccounts() service_account.ReaderIface { return nil }
func (r *fakeGrpReader) Groups() group.ReaderIface                    { return &fakeGrpRdr{} }
func (r *fakeGrpReader) Roles() role.ReaderIface                      { return nil }
func (r *fakeGrpReader) AccessBindings() access_binding.ReaderIface   { return nil }
func (r *fakeGrpReader) Commit(context.Context) error                 { return nil }
func (r *fakeGrpReader) Rollback(context.Context) error               { return nil }

type fakeGrpWriter struct{ fakeGrpReader }

func (w *fakeGrpWriter) AccountsW() account.WriterIface                           { return nil }
func (w *fakeGrpWriter) ProjectsW() repoproject.WriterIface                       { return nil }
func (w *fakeGrpWriter) UsersW() user.WriterIface                                 { return nil }
func (w *fakeGrpWriter) ServiceAccountsW() service_account.WriterIface            { return nil }
func (w *fakeGrpWriter) GroupsW() group.WriterIface                               { return &fakeGrpWtr{} }
func (w *fakeGrpWriter) RolesW() role.WriterIface                                 { return nil }
func (w *fakeGrpWriter) AccessBindingsW() access_binding.WriterIface              { return nil }
func (w *fakeGrpWriter) EmitAuditEvent(context.Context, service.AuditEvent) error { return nil }
func (w *fakeGrpWriter) EmitFGARelationWrite(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *fakeGrpWriter) EmitFGARelationDelete(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *fakeGrpWriter) InsertRecoveryCompletion(context.Context, domain.RecoveryCompletion) (domain.RecoveryCompletion, bool, error) {
	return domain.RecoveryCompletion{}, false, nil
}
func (w *fakeGrpWriter) UpsertUserTokenRevokeAll(context.Context, domain.UserTokenRevocation, domain.UserID) error {
	return nil
}
func (w *fakeGrpWriter) Savepoint(context.Context, string) error           { return nil }
func (w *fakeGrpWriter) RollbackToSavepoint(context.Context, string) error { return nil }
func (w *fakeGrpWriter) ReleaseSavepoint(context.Context, string) error    { return nil }
func (w *fakeGrpWriter) AdvisoryXactLock(context.Context, string) error    { return nil }

type fakeAccRdr struct{}

func (r *fakeAccRdr) Get(_ context.Context, id domain.AccountID) (domain.Account, error) {
	return domain.Account{ID: id, OwnerUserID: domain.UserID(metaOwner), CreatedAt: time.Now().UTC()}, nil
}
func (r *fakeAccRdr) List(context.Context, account.ListFilter) ([]domain.Account, string, error) {
	return nil, "", nil
}
func (r *fakeAccRdr) ExistsByName(context.Context, domain.AccountName) (bool, error) {
	return false, nil
}
func (r *fakeAccRdr) CountAccountsByOwner(context.Context, domain.UserID) (int, error) {
	return 0, nil
}

type fakeGrpRdr struct{}

func (r *fakeGrpRdr) Get(_ context.Context, id domain.GroupID) (domain.Group, error) {
	return domain.Group{ID: id, AccountID: metaAcc, Name: "fake-grp", CreatedAt: time.Now().UTC()}, nil
}
func (r *fakeGrpRdr) List(context.Context, group.ListFilter) ([]domain.Group, string, error) {
	return nil, "", nil
}
func (r *fakeGrpRdr) ListMembers(context.Context, domain.GroupID) ([]domain.GroupMember, error) {
	return nil, nil
}
func (r *fakeGrpRdr) IsMember(context.Context, domain.GroupID, domain.SubjectType, domain.SubjectID) (bool, error) {
	return false, nil
}

type fakeGrpWtr struct{ fakeGrpRdr }

func (w *fakeGrpWtr) Insert(_ context.Context, g domain.Group) (domain.Group, error) {
	g.CreatedAt = time.Now().UTC()
	return g, nil
}
func (w *fakeGrpWtr) Update(_ context.Context, g domain.Group, _ []string) (domain.Group, error) {
	return g, nil
}
func (w *fakeGrpWtr) Delete(context.Context, domain.GroupID) error        { return nil }
func (w *fakeGrpWtr) AddMember(context.Context, domain.GroupMember) error { return nil }
func (w *fakeGrpWtr) RemoveMember(context.Context, domain.GroupID, domain.SubjectType, domain.SubjectID) error {
	return nil
}

// ── fake ops repo (captures the emitted Metadata) ───────────────────────────

type fakeGrpOps struct {
	mu  sync.Mutex
	ops map[string]*operations.Operation
}

func newFakeGrpOps() *fakeGrpOps { return &fakeGrpOps{ops: map[string]*operations.Operation{}} }

func (r *fakeGrpOps) Create(_ context.Context, op operations.Operation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := op
	r.ops[op.ID] = &cp
	return nil
}
func (r *fakeGrpOps) CreateWithPrincipal(_ context.Context, op operations.Operation, _ operations.Principal) error {
	return r.Create(context.Background(), op)
}
func (r *fakeGrpOps) Get(_ context.Context, id string) (*operations.Operation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	op, ok := r.ops[id]
	if !ok {
		return nil, operations.ErrNotFound
	}
	cp := *op
	return &cp, nil
}
func (r *fakeGrpOps) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}
func (r *fakeGrpOps) MarkDone(_ context.Context, id string, resp *anypb.Any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
		op.Response = resp
	}
	return nil
}
func (r *fakeGrpOps) MarkError(_ context.Context, id string, st *gstatus.Status) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
		op.Error = st
	}
	return nil
}
func (r *fakeGrpOps) Cancel(_ context.Context, id string) error { return nil }

// EmitReconcileEvent — T3/Q2 no-op stub (fake does not exercise the iam-direct reconcile trigger).
func (w *fakeGrpWriter) EmitReconcileEvent(context.Context, string, string, string) error {
	return nil
}
