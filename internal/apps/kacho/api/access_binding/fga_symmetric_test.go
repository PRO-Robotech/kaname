// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// fga_symmetric_test.go — symmetric FGA grant/revoke regression test.
//
// Contract: the production path enqueues tuples via EmitRelationWrite /
// EmitRelationDelete in the writer-tx (drainer applies async). Both Create and
// Delete emit identical tuple sets so that grant and revoke are byte-symmetric.
//
// The fake repo's EmitRelationWrite/EmitRelationDelete capture the async
// fga_outbox set. Create's sync FGA path runs through the reconciler (unwired in
// this unit harness), so the recordingFGA's WriteTuples stays empty. Delete, by
// contrast, applies the SAME persisted emitted-set to OpenFGA synchronously after
// commit (relations.DeleteTuples) — revoke ≈ grant latency — so the recordingFGA's
// DeleteTuples now mirrors the async revoke set (asserted symmetric below).
//
// The test does NOT use testcontainers (no Postgres required). It wires
// in-memory fakes for the Repository and operations.Repo, exercises the full
// Create→Delete round-trip through both use-cases, and asserts:
//
//  1. Create emits ≥2 tuples (role-relation + hierarchy for project-scoped).
//  2. Delete emits exactly the same set (grant is fully revoked).
//  3. For account-scoped binding: Create emits 1 tuple, Delete emits 1 tuple.

import (
	"context"
	stderrors "errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	ab_repo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	acct_repo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
	proj_repo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
	role_repo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
	sa_repo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
	user_repo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// ─── Symmetric FGA grant/revoke ────────────────────────────────────────────

// TestFGASymmetric_CreateWritesTuples_DeleteRevokesSameSet asserts the
// fga_outbox emit-in-tx contract — the tuple set emitted by Create
// (EmitRelationWrite) is byte-identical to the tuple set emitted by Delete
// (EmitRelationDelete). Drainer then applies them to OpenFGA asynchronously
// (covered by fga_applier integration tests).
func TestFGASymmetric_CreateWritesTuples_DeleteRevokesSameSet(t *testing.T) {
	const (
		roleID     = "rol_viewer_test_001"
		roleName   = "kacho.view" // legacy name kept for context; mapping is permission-based
		subjectID  = "usr_test_subject"
		resourceID = "prj_test_project"
		ownerID    = "usr_test_owner"
		accountID  = "acc_test_account"
	)

	// Viewer-class permissions → relation "viewer" via PermissionsToRelations.
	perms := domain.Permissions{"iam.access_bindings.get", "iam.access_bindings.list"}
	repo := newABFakeRepo(ownerID, accountID, resourceID, roleID, roleName, perms)
	opsRepo := newFakeOpsRepo()
	fga := newRecordingFGA() // still wired via WithRelationStore for backwards-compat surface

	// Context with the account owner as principal → passes requireGrantAuthority.
	ctx := newOwnerContext(ownerID)

	// ── Create ────────────────────────────────────────────────────────────────
	createUC := NewCreateAccessBindingUseCase(repo, opsRepo).
		WithRelationStore(fga, nil)

	binding := domain.AccessBinding{
		SubjectType:  "user",
		SubjectID:    domain.SubjectID(subjectID),
		RoleID:       domain.RoleID(roleID),
		ResourceType: "project",
		ResourceID:   resourceID,
	}
	opCreate, err := createUC.Execute(ctx, binding)
	require.NoError(t, err, "Create.Execute must succeed")
	require.NotNil(t, opCreate)

	// Wait for async worker.
	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx), "async Create worker must complete")

	// fga_outbox emits captured via the writer-iface fake, NOT via
	// recordingFGA (which is no longer called sync).
	writtenTuples := repo.drainFGAWritten()
	require.GreaterOrEqual(t, len(writtenTuples), 2,
		"Create must emit ≥2 fga_outbox tuples (role-relation + hierarchy)")

	// Sanity-check: sync path NOT invoked — recordingFGA's WriteTuples must
	// have received nothing.
	require.Empty(t, fga.drainWritten(),
		"sync u.fga.WriteTuples MUST NOT be called (post-commit Warn pattern removed)")

	// Verify role-relation tuple.
	assert.Contains(t, writtenTuples, ab_repo.RelationTuple{
		User:     "user:" + subjectID,
		Relation: "viewer",
		Object:   "project:" + resourceID,
	}, "Create must emit the role-relation tuple to fga_outbox")

	// Verify hierarchy tuple (required for Get/Delete authz cascade).
	abID := repo.lastInsertedID()
	require.NotEmpty(t, abID, "repo must record the inserted AB id")
	assert.Contains(t, writtenTuples, ab_repo.RelationTuple{
		User:     "project:" + resourceID,
		Relation: "project",
		Object:   "iam_access_binding:" + string(abID),
	}, "Create must emit the hierarchy tuple to fga_outbox")

	// ── Delete ────────────────────────────────────────────────────────────────
	deleteUC := NewDeleteAccessBindingUseCase(repo, opsRepo).
		WithRelationStore(fga, nil)

	subjectCtx := newOwnerContext(subjectID)
	opDelete, err := deleteUC.Execute(subjectCtx, abID)
	require.NoError(t, err, "Delete.Execute must succeed")
	require.NotNil(t, opDelete)

	waitCtx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	require.NoError(t, operations.Wait(waitCtx2), "async Delete worker must complete")

	deletedTuples := repo.drainFGADeleted()

	require.Equal(t, len(writtenTuples), len(deletedTuples),
		"Delete must emit the same number of fga_outbox tuples as Create did")

	for _, w := range writtenTuples {
		assert.Contains(t, deletedTuples, w,
			"Delete must emit revoke tuple {User:%q Relation:%q Object:%q}",
			w.User, w.Relation, w.Object)
	}

	// Synchronous revoke (revoke ≈ grant latency): doDelete applies the SAME
	// persisted emitted-set to OpenFGA synchronously after commit (relations.
	// DeleteTuples), so the deny is observable at Operation-done. The async
	// EmitRelationDelete + drainer remain the at-least-once idempotent backstop.
	syncDeleted := fga.drainDeleted()
	require.Equal(t, len(writtenTuples), len(syncDeleted),
		"Delete must SYNCHRONOUSLY remove the same tuple set Create granted")
	for _, w := range writtenTuples {
		assert.Contains(t, syncDeleted,
			clients.RelationTuple{User: w.User, Relation: w.Relation, Object: w.Object},
			"sync revoke must remove tuple {User:%q Relation:%q Object:%q}", w.User, w.Relation, w.Object)
	}
}

// TestFGASymmetric_AccountBinding_RoleRelationAndHierarchyTuple —
// account-scoped bindings emit the role-relation tuple PLUS the
// `account`-parent hierarchy tuple to fga_outbox, so the FGA model's
// `viewer from account` cascade makes the binding object readable by the
// account owner (Get/List/Delete). Without the hierarchy tuple every
// account-scoped binding 403'd on read (newman-e2e iam-access-binding cascade).
func TestFGASymmetric_AccountBinding_RoleRelationAndHierarchyTuple(t *testing.T) {
	const (
		roleID    = "rol_admin_test_002"
		roleName  = "admin"
		subjectID = "usr_test_admin"
		resID     = "acc_target_account"
		ownerID   = "usr_test_owner"
		accountID = "acc_test_account"
	)

	// Admin-class wildcard permissions → relation "admin".
	perms := domain.Permissions{"iam.access_bindings.admin"}
	repo := newABFakeRepo(ownerID, accountID, resID, roleID, roleName, perms)
	opsRepo := newFakeOpsRepo()
	fga := newRecordingFGA()
	ctx := newOwnerContext(ownerID)

	createUC := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(fga, nil)
	binding := domain.AccessBinding{
		SubjectType:  "user",
		SubjectID:    domain.SubjectID(subjectID),
		RoleID:       domain.RoleID(roleID),
		ResourceType: "account", // NOT project → no hierarchy tuple
		ResourceID:   resID,
	}
	_, err := createUC.Execute(ctx, binding)
	require.NoError(t, err)
	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	written := repo.drainFGAWritten()
	require.Len(t, written, 2,
		"account-scoped binding: role-relation tuple + account-parent hierarchy tuple")
	assert.Contains(t, written, ab_repo.RelationTuple{
		User:     "user:" + subjectID,
		Relation: "admin",
		Object:   "account:" + resID,
	}, "must emit the role-relation tuple")
	assert.Contains(t, written, ab_repo.RelationTuple{
		User:     "account:" + resID,
		Relation: "account",
		Object:   "iam_access_binding:" + string(repo.lastInsertedID()),
	}, "must emit the account-parent hierarchy tuple (cascade readability)")

	deleteUC := NewDeleteAccessBindingUseCase(repo, opsRepo).WithRelationStore(fga, nil)
	subjectCtx := newOwnerContext(subjectID)
	_, err = deleteUC.Execute(subjectCtx, repo.lastInsertedID())
	require.NoError(t, err)
	waitCtx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	require.NoError(t, operations.Wait(waitCtx2))

	deleted := repo.drainFGADeleted()
	require.Equal(t, written, deleted, "Delete must emit the same single tuple Create emitted")

	// Create's sync FGA write goes through the reconciler (unwired here) — the
	// recordingFGA's WriteTuples stays empty. Delete, however, removes the same
	// persisted emitted-set from OpenFGA synchronously (relations.DeleteTuples) so
	// the deny is observable at Operation-done (revoke ≈ grant latency).
	require.Empty(t, fga.drainWritten(), "sync FGA write must not be called at Create")
	syncDeleted := fga.drainDeleted()
	require.Len(t, syncDeleted, len(written),
		"Delete must SYNCHRONOUSLY remove the same set Create granted")
	for _, w := range written {
		assert.Contains(t, syncDeleted,
			clients.RelationTuple{User: w.User, Relation: w.Relation, Object: w.Object},
			"sync revoke must remove tuple {User:%q Relation:%q Object:%q}", w.User, w.Relation, w.Object)
	}
}

// ─── recording FGA client ────────────────────────────────────────────────────

type recordingFGA struct {
	mu      sync.Mutex
	written []clients.RelationTuple
	deleted []clients.RelationTuple
}

func newRecordingFGA() *recordingFGA { return &recordingFGA{} }

func (r *recordingFGA) Check(_ context.Context, _, _, _ string) (bool, error) { return true, nil }

func (r *recordingFGA) WriteTuples(_ context.Context, tuples []clients.RelationTuple) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.written = append(r.written, tuples...)
	return nil
}

func (r *recordingFGA) DeleteTuples(_ context.Context, tuples []clients.RelationTuple) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleted = append(r.deleted, tuples...)
	return nil
}

func (r *recordingFGA) drainWritten() []clients.RelationTuple {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]clients.RelationTuple, len(r.written))
	copy(out, r.written)
	r.written = nil
	return out
}

func (r *recordingFGA) drainDeleted() []clients.RelationTuple {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]clients.RelationTuple, len(r.deleted))
	copy(out, r.deleted)
	r.deleted = nil
	return out
}

var _ clients.RelationStore = (*recordingFGA)(nil)

// ─── in-memory fake Repository ───────────────────────────────────────────────

type abFakeRepo struct {
	mu              sync.Mutex
	ownerUserID     string
	accountID       string
	projectID       string
	roleID          string
	roleName        string
	rolePermissions domain.Permissions
	// roleRules — when set, the fake Roles().Get returns a RULES-role (RBAC
	// rules-model) so the create + reconcile exercise the
	// type-scoped scope_grant emit path (rulesBindingTuples), not the legacy
	// whole-role anchor collapse. Empty ⇒ legacy permission-only role.
	roleRules domain.Rules
	ab        *domain.AccessBinding // last inserted
	// Captured fga_outbox emit-in-tx tuples (mirror what
	// drainer would apply to OpenFGA).
	fgaWritten []ab_repo.RelationTuple
	fgaDeleted []ab_repo.RelationTuple
	// Captured audit_outbox compliance events emitted in the writer-tx.
	auditEvents []ab_repo.AuditEvent
	// groupMembers — backing store for the IsMember adapter.
	// Map key: "<groupID>|<memberType>|<memberID>". Presence ⇒ membership.
	// Test helpers AddGroupMember / removeGroupMember mutate it.
	groupMembers map[string]struct{}
	// lbaRows — fixture rows returned by ListByAccount. Seed via
	// seedABListByAccount; used by ListByAccountUseCase unit tests.
	lbaRows []domain.AccessBinding
	// lbsRows — fixture rows returned by ListByScope. Seed via seedABListByScope;
	// used by the viewer ∪ v_list union-floor unit tests.
	lbsRows []domain.AccessBinding
	// reconcileObjs — object ids for which a reconcile-event was emitted in the
	// writer-tx (labels co-commit). Drained via drainReconcileObjects.
	reconcileObjs []string
	// users / serviceAccounts / groups — id→accountID store backing the fake
	// Users()/ServiceAccounts()/Groups() readers (existence +
	// home-account resolution for ListSubjectPrivileges). Absence ⇒ ErrNotFound.
	users           map[string]string
	serviceAccounts map[string]string
	groups          map[string]string
	// spRows — fixture rows returned by AccessBindings().ListSubjectPrivileges.
	// Seed via seedSubjectPrivileges; used by ListSubjectPrivilegesUseCase tests.
	spRows []domain.SubjectPrivilege
	// roleIsCustom — when true the fake Roles().Get returns a CUSTOM role
	// (IsSystem=false, AccountID=accountID) so Role.Update account-owner
	// authority + assignability gates pass (reconcile fan-out tests).
	roleIsCustom bool
	// abSubjects — access_binding_subjects backing store, keyed by
	// binding id → ordered subjects. Mutated by InsertSubjects/DeleteSubject.
	abSubjects map[domain.AccessBindingID][]domain.Subject
	// forceGetErr — when set, fakeABRdr.Get returns this error unconditionally
	// instead of the normal found/not-found lookup. Used by
	// get_error_mapping_test.go to simulate a transient (non-not-found) Reader
	// failure on the Update/Delete existence-check Get.
	forceGetErr error
	// emittedTuples — persisted exact emitted-set per binding
	// (access_binding_emitted_tuples), keyed by binding id. Co-committing
	// the grant tuples here lets revoke/Role.Update use the stored set
	// (not a re-derive from the mutable role). Set semantics on the tuple
	// (dedupe), but INSERTION ORDER is preserved on read-back: the real pg repo
	// returns a deterministic `ORDER BY relation, object, fga_user` and the
	// symmetric-revoke contract is set-based (drainer applies a set to OpenFGA),
	// yet TestFGASymmetric asserts byte-equality of the write-set vs the
	// delete-set. Insertion order makes SelectEmittedTuples deterministic AND
	// equal to the order EmitRelationWrite captured (create.go feeds the SAME
	// `tuples` slice to EmitRelationWrite and InsertEmittedTuples), so the
	// round-trip is order-stable without an unordered Go-map shuffle. A plain
	// `map[tuple]struct{}` iterates in random order ⇒ require.Equal flakes/fails.
	emittedTuples map[domain.AccessBindingID]*orderedTupleSet
}

// AddUser — test helper. Registers a User id with its home account so the fake
// Users() reader resolves it (existence + account_id for the 1.3 authz gate).
func (r *abFakeRepo) AddUser(userID, accountID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.users == nil {
		r.users = map[string]string{}
	}
	r.users[userID] = accountID
}

// AddServiceAccount — test helper. Registers a ServiceAccount id with its home
// account so the fake ServiceAccounts() reader resolves it.
func (r *abFakeRepo) AddServiceAccount(saID, accountID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.serviceAccounts == nil {
		r.serviceAccounts = map[string]string{}
	}
	r.serviceAccounts[saID] = accountID
}

// AddGroup — test helper. Registers a Group id with its home account so the
// fake Groups() reader resolves it (existence + account_id for the 1.3b authz
// gate on subject_type=group).
func (r *abFakeRepo) AddGroup(groupID, accountID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.groups == nil {
		r.groups = map[string]string{}
	}
	r.groups[groupID] = accountID
}

// seedSubjectPrivileges — test helper. Replaces the fixture rows returned by
// the fake AccessBindings().ListSubjectPrivileges.
func (r *abFakeRepo) seedSubjectPrivileges(rows []domain.SubjectPrivilege) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.spRows = append(r.spRows[:0], rows...)
}

// seedABListByAccount — test helper. Replaces the fixture rows returned by
// the fake fakeABRdr.ListByAccount.
func (r *abFakeRepo) seedABListByAccount(rows []domain.AccessBinding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lbaRows = append(r.lbaRows[:0], rows...)
}

// AddGroupMember — test helper. Stores membership triple so
// the use-case's requireGroupMembership lookup returns true for this caller.
func (r *abFakeRepo) AddGroupMember(groupID, memberType, memberID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.groupMembers == nil {
		r.groupMembers = map[string]struct{}{}
	}
	r.groupMembers[groupID+"|"+memberType+"|"+memberID] = struct{}{}
}

func newABFakeRepo(ownerUserID, accountID, projectID, roleID, roleName string, perms domain.Permissions) *abFakeRepo {
	return &abFakeRepo{
		ownerUserID:     ownerUserID,
		accountID:       accountID,
		projectID:       projectID,
		roleID:          roleID,
		roleName:        roleName,
		rolePermissions: perms,
	}
}

// drainFGAWritten — captured fga_outbox grant emits since last drain.
func (r *abFakeRepo) drainFGAWritten() []ab_repo.RelationTuple {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]ab_repo.RelationTuple, len(r.fgaWritten))
	copy(out, r.fgaWritten)
	r.fgaWritten = nil
	return out
}

// drainFGADeleted — captured fga_outbox revoke emits since last drain.
func (r *abFakeRepo) drainFGADeleted() []ab_repo.RelationTuple {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]ab_repo.RelationTuple, len(r.fgaDeleted))
	copy(out, r.fgaDeleted)
	r.fgaDeleted = nil
	return out
}

// drainAuditEvents — captured audit_outbox compliance events since last drain.
func (r *abFakeRepo) drainAuditEvents() []ab_repo.AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]ab_repo.AuditEvent, len(r.auditEvents))
	copy(out, r.auditEvents)
	r.auditEvents = nil
	return out
}

func (r *abFakeRepo) lastInsertedID() domain.AccessBindingID {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ab == nil {
		return ""
	}
	return r.ab.ID
}

func (r *abFakeRepo) Reader(_ context.Context) (kachorepo.Reader, error) {
	return &abFakeReader{repo: r}, nil
}
func (r *abFakeRepo) Writer(_ context.Context) (kachorepo.Writer, error) {
	return &abFakeWriter{abFakeReader: abFakeReader{repo: r}}, nil
}
func (r *abFakeRepo) Close() {}

var _ kachorepo.Repository = (*abFakeRepo)(nil)

// abFakeReader implements kachorepo.Reader.
type abFakeReader struct{ repo *abFakeRepo }

func (rd *abFakeReader) Accounts() acct_repo.ReaderIface      { return &fakeAcctRdr{repo: rd.repo} }
func (rd *abFakeReader) Projects() proj_repo.ReaderIface      { return &fakeProjRdr{repo: rd.repo} }
func (rd *abFakeReader) Users() user_repo.ReaderIface         { return &fakeUserRdr{repo: rd.repo} }
func (rd *abFakeReader) ServiceAccounts() sa_repo.ReaderIface { return &fakeSARdr{repo: rd.repo} }
func (rd *abFakeReader) Groups() group.ReaderIface            { return &fakeGroupRdr{repo: rd.repo} }
func (rd *abFakeReader) Roles() role_repo.ReaderIface         { return &fakeRoleRdr{repo: rd.repo} }
func (rd *abFakeReader) AccessBindings() ab_repo.ReaderIface  { return &fakeABRdr{repo: rd.repo} }
func (rd *abFakeReader) Commit(_ context.Context) error       { return nil }
func (rd *abFakeReader) Rollback(_ context.Context) error     { return nil }

// abFakeWriter implements kachorepo.Writer.
type abFakeWriter struct {
	abFakeReader
}

func (w *abFakeWriter) AccountsW() acct_repo.WriterIface                         { return nil }
func (w *abFakeWriter) ProjectsW() proj_repo.WriterIface                         { return nil }
func (w *abFakeWriter) UsersW() user_repo.WriterIface                            { return nil }
func (w *abFakeWriter) ServiceAccountsW() sa_repo.WriterIface                    { return nil }
func (w *abFakeWriter) GroupsW() group.WriterIface                               { return nil }
func (w *abFakeWriter) RolesW() role_repo.WriterIface                            { return &fakeRoleWtr{repo: w.repo} }
func (w *abFakeWriter) AccessBindingsW() ab_repo.WriterIface                     { return &fakeABWtr{repo: w.repo} }
func (w *abFakeWriter) EmitAuditEvent(context.Context, service.AuditEvent) error { return nil }
func (w *abFakeWriter) EmitFGARelationWrite(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *abFakeWriter) EmitFGARelationDelete(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *abFakeWriter) InsertRecoveryCompletion(context.Context, domain.RecoveryCompletion) (domain.RecoveryCompletion, bool, error) {
	return domain.RecoveryCompletion{}, false, nil
}
func (w *abFakeWriter) UpsertUserTokenRevokeAll(context.Context, domain.UserTokenRevocation, domain.UserID) error {
	return nil
}
func (w *abFakeWriter) Savepoint(context.Context, string) error           { return nil }
func (w *abFakeWriter) RollbackToSavepoint(context.Context, string) error { return nil }
func (w *abFakeWriter) ReleaseSavepoint(context.Context, string) error    { return nil }
func (w *abFakeWriter) AdvisoryXactLock(context.Context, string) error    { return nil }

// fakeAcctRdr — account Reader; returns Account with the configured owner.
type fakeAcctRdr struct{ repo *abFakeRepo }

func (a *fakeAcctRdr) Get(_ context.Context, id domain.AccountID) (domain.Account, error) {
	return domain.Account{
		ID:          id,
		OwnerUserID: domain.UserID(a.repo.ownerUserID),
	}, nil
}
func (a *fakeAcctRdr) List(_ context.Context, _ acct_repo.ListFilter) ([]domain.Account, string, error) {
	return nil, "", nil
}
func (a *fakeAcctRdr) ExistsByName(_ context.Context, _ domain.AccountName) (bool, error) {
	return false, nil
}
func (a *fakeAcctRdr) CountAccountsByOwner(_ context.Context, _ domain.UserID) (int, error) {
	return 0, nil
}

// fakeProjRdr — project Reader; returns Project pointing to the fake account.
type fakeProjRdr struct{ repo *abFakeRepo }

func (p *fakeProjRdr) Get(_ context.Context, id domain.ProjectID) (domain.Project, error) {
	return domain.Project{
		ID:        id,
		AccountID: domain.AccountID(p.repo.accountID),
	}, nil
}
func (p *fakeProjRdr) List(_ context.Context, _ proj_repo.ListFilter) ([]domain.Project, string, error) {
	return nil, "", nil
}
func (p *fakeProjRdr) CountByAccount(_ context.Context, _ domain.AccountID) (int64, error) {
	return 0, nil
}

// fakeRoleRdr — role Reader; returns the configured role for the configured id.
type fakeRoleRdr struct{ repo *abFakeRepo }

func (r *fakeRoleRdr) Get(_ context.Context, id domain.RoleID) (domain.Role, error) {
	r.repo.mu.Lock()
	defer r.repo.mu.Unlock()
	if string(id) == r.repo.roleID {
		// Permission-based mapping. Populate Permissions[]
		// so PermissionsToRelations can derive the FGA tier.
		if r.repo.roleIsCustom {
			// CUSTOM role: owned by the account so Role.Update
			// account-owner authority + assignability gates pass; the
			// reconcile fan-out exercises the live permissions.
			return domain.Role{
				ID:          id,
				Name:        domain.RoleName(r.repo.roleName),
				AccountID:   domain.AccountID(r.repo.accountID),
				IsSystem:    false,
				Permissions: r.repo.rolePermissions,
				Rules:       r.repo.roleRules,
			}, nil
		}
		// Default: IsSystem so the scope-enforcement
		// (domain.IsRoleAssignable) treats it as assignable on any resource —
		// the symmetric suite exercises FGA tuple symmetry, not role-scope.
		return domain.Role{
			ID:          id,
			Name:        domain.RoleName(r.repo.roleName),
			ClusterID:   domain.ClusterID(domain.ClusterSingletonID),
			IsSystem:    true,
			Permissions: r.repo.rolePermissions,
			Rules:       r.repo.roleRules,
		}, nil
	}
	return domain.Role{}, stderrors.New("role not found in fake")
}
func (r *fakeRoleRdr) GetWithVersion(ctx context.Context, id domain.RoleID) (domain.Role, string, error) {
	role, err := r.Get(ctx, id)
	return role, "v-fake", err
}
func (r *fakeRoleRdr) List(_ context.Context, _ role_repo.ListFilter) ([]domain.Role, string, error) {
	return nil, "", nil
}
func (r *fakeRoleRdr) ListAssignable(_ context.Context, _, _ string, _ role_repo.ListFilter) ([]domain.Role, string, error) {
	return nil, "", nil
}

// fakeABRdr — access_binding Reader; returns last-inserted AB by id.
type fakeABRdr struct{ repo *abFakeRepo }

func (a *fakeABRdr) Get(_ context.Context, id domain.AccessBindingID) (domain.AccessBinding, error) {
	a.repo.mu.Lock()
	defer a.repo.mu.Unlock()
	if a.repo.forceGetErr != nil {
		return domain.AccessBinding{}, a.repo.forceGetErr
	}
	if a.repo.ab != nil && a.repo.ab.ID == id {
		return *a.repo.ab, nil
	}
	return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
}
func (a *fakeABRdr) ListByScope(_ context.Context, _ domain.ResourceType, _ string, _ ab_repo.PageFilter) ([]domain.AccessBinding, string, error) {
	a.repo.mu.Lock()
	defer a.repo.mu.Unlock()
	if a.repo.lbsRows == nil {
		return nil, "", nil
	}
	out := make([]domain.AccessBinding, len(a.repo.lbsRows))
	copy(out, a.repo.lbsRows)
	return out, "", nil
}
func (a *fakeABRdr) ListBySubject(_ context.Context, _ domain.SubjectType, _ domain.SubjectID, _ ab_repo.PageFilter) ([]domain.AccessBinding, string, error) {
	return nil, "", nil
}
func (a *fakeABRdr) ListByAccount(_ context.Context, _ domain.AccountID, _ ab_repo.AccountPageFilter) ([]domain.AccessBinding, string, error) {
	a.repo.mu.Lock()
	defer a.repo.mu.Unlock()
	if a.repo.lbaRows == nil {
		return nil, "", nil
	}
	out := make([]domain.AccessBinding, len(a.repo.lbaRows))
	copy(out, a.repo.lbaRows)
	return out, "", nil
}

func (a *fakeABRdr) ListSubjectPrivileges(_ context.Context, _ domain.SubjectType, _ domain.SubjectID, _ ab_repo.PageFilter) ([]domain.SubjectPrivilege, string, error) {
	a.repo.mu.Lock()
	defer a.repo.mu.Unlock()
	if len(a.repo.spRows) == 0 {
		return nil, "", nil
	}
	out := make([]domain.SubjectPrivilege, len(a.repo.spRows))
	copy(out, a.repo.spRows)
	return out, "", nil
}

// fakeUserRdr — minimal user.ReaderIface for ListSubjectPrivileges existence +
// home-account resolution. Only Get is exercised.
type fakeUserRdr struct{ repo *abFakeRepo }

func (u *fakeUserRdr) Get(_ context.Context, id domain.UserID) (domain.User, error) {
	u.repo.mu.Lock()
	defer u.repo.mu.Unlock()
	acc, ok := u.repo.users[string(id)]
	if !ok {
		return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", id)
	}
	return domain.User{ID: id, AccountID: domain.AccountID(acc)}, nil
}
func (u *fakeUserRdr) GetByExternalID(_ context.Context, _ domain.ExternalSubject) (domain.User, error) {
	return domain.User{}, stderrors.New("not implemented in fake")
}
func (u *fakeUserRdr) GetByEmail(_ context.Context, _ domain.Email) (domain.User, error) {
	return domain.User{}, stderrors.New("not implemented in fake")
}
func (u *fakeUserRdr) List(_ context.Context, _ user_repo.ListFilter) ([]domain.User, string, error) {
	return nil, "", nil
}
func (u *fakeUserRdr) GetByAccountEmail(_ context.Context, _ domain.AccountID, _ domain.Email) (domain.User, error) {
	return domain.User{}, stderrors.New("not implemented in fake")
}
func (u *fakeUserRdr) FindPendingByEmail(_ context.Context, _ domain.Email) ([]domain.User, error) {
	return nil, nil
}
func (u *fakeUserRdr) FindActiveByExternalID(_ context.Context, _ domain.ExternalSubject) ([]domain.User, error) {
	return nil, nil
}
func (u *fakeUserRdr) FindByExternalIDInStatuses(_ context.Context, _ domain.ExternalSubject, _ []domain.InviteStatus) ([]domain.User, error) {
	return nil, nil
}
func (u *fakeUserRdr) FindActiveByEmail(_ context.Context, _ domain.Email) ([]domain.User, error) {
	return nil, nil
}
func (u *fakeUserRdr) ListAccountsForUser(_ context.Context, _ domain.UserID) ([]domain.AccountID, error) {
	return nil, nil
}

// fakeSARdr — minimal service_account.ReaderIface for ListSubjectPrivileges.
type fakeSARdr struct{ repo *abFakeRepo }

func (s *fakeSARdr) Get(_ context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error) {
	s.repo.mu.Lock()
	defer s.repo.mu.Unlock()
	acc, ok := s.repo.serviceAccounts[string(id)]
	if !ok {
		return domain.ServiceAccount{}, iamerr.Wrapf(iamerr.ErrNotFound, "ServiceAccount %s not found", id)
	}
	return domain.ServiceAccount{ID: id, AccountID: domain.AccountID(acc)}, nil
}
func (s *fakeSARdr) List(_ context.Context, _ sa_repo.ListFilter) ([]domain.ServiceAccount, string, error) {
	return nil, "", nil
}

// fakeGroupRdr — fake Groups reader supporting IsMember lookups.
// Minimal group.ReaderIface implementation backing IsMember-based
// authorisation in ListAccessBindingsBySubject. Other methods unused.
type fakeGroupRdr struct{ repo *abFakeRepo }

func (g *fakeGroupRdr) Get(_ context.Context, id domain.GroupID) (domain.Group, error) {
	g.repo.mu.Lock()
	defer g.repo.mu.Unlock()
	acc, ok := g.repo.groups[string(id)]
	if !ok {
		return domain.Group{}, iamerr.Wrapf(iamerr.ErrNotFound, "Group %s not found", id)
	}
	return domain.Group{ID: id, AccountID: domain.AccountID(acc)}, nil
}
func (g *fakeGroupRdr) List(_ context.Context, _ group.ListFilter) ([]domain.Group, string, error) {
	return nil, "", nil
}
func (g *fakeGroupRdr) ListMembers(_ context.Context, _ domain.GroupID) ([]domain.GroupMember, error) {
	return nil, nil
}
func (g *fakeGroupRdr) IsMember(_ context.Context, groupID domain.GroupID, memberType domain.SubjectType, memberID domain.SubjectID) (bool, error) {
	g.repo.mu.Lock()
	defer g.repo.mu.Unlock()
	if g.repo.groupMembers == nil {
		return false, nil
	}
	_, ok := g.repo.groupMembers[string(groupID)+"|"+string(memberType)+"|"+string(memberID)]
	return ok, nil
}

// fakeABWtr — access_binding Writer; stores Insert result, clears on Delete.
type fakeABWtr struct{ repo *abFakeRepo }

func (w *fakeABWtr) Insert(_ context.Context, b domain.AccessBinding) (domain.AccessBinding, error) {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	if b.ID == "" {
		b.ID = "acbc_fake_ab_test01"
	}
	cp := b
	w.repo.ab = &cp
	return b, nil
}

func (w *fakeABWtr) Delete(_ context.Context, id domain.AccessBindingID) error {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	if w.repo.ab != nil && w.repo.ab.ID == id {
		w.repo.ab = nil
		return nil
	}
	return stderrors.New("access binding not found for delete in fake")
}

func (w *fakeABWtr) DeleteGuarded(_ context.Context, id domain.AccessBindingID) error {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	if w.repo.ab != nil && w.repo.ab.ID == id {
		if w.repo.ab.DeletionProtection {
			return iamerr.Wrapf(iamerr.ErrFailedPrecondition,
				"access binding %s has deletion_protection enabled; clear it via Update before Delete", id)
		}
		w.repo.ab = nil
		return nil
	}
	return iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
}

func (w *fakeABWtr) SetDeletionProtection(_ context.Context, id domain.AccessBindingID, protected bool) (domain.AccessBinding, error) {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	if w.repo.ab != nil && w.repo.ab.ID == id {
		w.repo.ab.DeletionProtection = protected
		return *w.repo.ab, nil
	}
	return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
}

func (w *fakeABWtr) UpdateLabels(_ context.Context, id domain.AccessBindingID, labels domain.Labels) (domain.AccessBinding, error) {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	if w.repo.ab != nil && w.repo.ab.ID == id {
		w.repo.ab.Labels = labels
		return *w.repo.ab, nil
	}
	return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
}

func (w *fakeABWtr) EmitSubjectChangeEvent(_ context.Context, _ ab_repo.SubjectChangeEvent) error {
	return nil
}

// Capture emitted FGA tuples for the symmetric test below.
func (w *fakeABWtr) EmitRelationWrite(_ context.Context, tuples []ab_repo.RelationTuple) error {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	w.repo.fgaWritten = append(w.repo.fgaWritten, tuples...)
	return nil
}

func (w *fakeABWtr) EmitRelationDelete(_ context.Context, tuples []ab_repo.RelationTuple) error {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	w.repo.fgaDeleted = append(w.repo.fgaDeleted, tuples...)
	return nil
}

// EmitAuditEvent captures the audit_outbox compliance event for assertions.
func (w *fakeABWtr) EmitAuditEvent(_ context.Context, ev ab_repo.AuditEvent) error {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	w.repo.auditEvents = append(w.repo.auditEvents, ev)
	return nil
}

func (w *fakeABWtr) TransitionStatus(
	_ context.Context,
	_ domain.AccessBindingID,
	_ []domain.AccessBindingStatus,
	_ domain.AccessBindingStatus,
	_ *domain.UserID,
) (domain.AccessBinding, error) {
	return domain.AccessBinding{}, stderrors.New("TransitionStatus: not implemented in fake")
}

// ─── fake operations.Repo ───────────────────────────────────────────────────

type fakeOpsRepo struct {
	mu  sync.Mutex
	ops map[string]*operations.Operation
}

func newFakeOpsRepo() *fakeOpsRepo {
	return &fakeOpsRepo{ops: map[string]*operations.Operation{}}
}

func (r *fakeOpsRepo) Create(_ context.Context, op operations.Operation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := op
	r.ops[op.ID] = &cp
	return nil
}

func (r *fakeOpsRepo) CreateWithPrincipal(_ context.Context, op operations.Operation, _ operations.Principal) error {
	return r.Create(context.Background(), op)
}

func (r *fakeOpsRepo) Get(_ context.Context, id string) (*operations.Operation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	op, ok := r.ops[id]
	if !ok {
		return nil, operations.ErrNotFound
	}
	cp := *op
	return &cp, nil
}

func (r *fakeOpsRepo) List(_ context.Context, _ operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}

func (r *fakeOpsRepo) MarkDone(_ context.Context, id string, resp *anypb.Any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
		op.Response = resp
	}
	return nil
}

func (r *fakeOpsRepo) MarkError(_ context.Context, id string, st *gstatus.Status) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
		op.Error = st
	}
	return nil
}

func (r *fakeOpsRepo) Cancel(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
	}
	return nil
}

var _ operations.Repo = (*fakeOpsRepo)(nil)

// ─── context helper ──────────────────────────────────────────────────────────

// newOwnerContext returns a context carrying the owner user as the authenticated
// principal (passes requireGrantAuthority IsSelf/owner check).
func newOwnerContext(ownerID string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{
		ID:   ownerID,
		Type: "user",
	})
}

// EmitReconcileEvent — records the (objectType, objectID) so the labels
// co-commit can be asserted (iam.accessBinding reconcile trigger on a label change).
func (w *abFakeWriter) EmitReconcileEvent(_ context.Context, _, objectType, objectID string) error {
	if objectType == "iam.accessBinding" {
		w.repo.mu.Lock()
		w.repo.reconcileObjs = append(w.repo.reconcileObjs, objectID)
		w.repo.mu.Unlock()
	}
	return nil
}

// drainReconcileObjects returns the object ids for which a reconcile-event was
// emitted in the writer-tx (labels co-commit assertion).
func (r *abFakeRepo) drainReconcileObjects() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.reconcileObjs))
	copy(out, r.reconcileObjs)
	r.reconcileObjs = nil
	return out
}
