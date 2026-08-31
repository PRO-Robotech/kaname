// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// fga_symmetric_test.go — symmetric grant/revoke regression test.
//
// Contract: the production path states tuples via EmitRelationWrite /
// EmitRelationDelete IN THE WRITER-TX. Both Create and Delete state identical tuple
// sets, so grant and revoke are byte-symmetric — a revoke that removed a different
// set than the grant added would leave access behind or strip access it never gave.
//
// # What "in the writer-tx" now means, and why this file lost its second half
//
// The journal `kacho_iam.fga_outbox` used to be an at-least-once queue toward an
// EXTERNAL relation engine, drained asynchronously. Because that drain lagged, the
// use-cases additionally removed the same set from the engine SYNCHRONOUSLY after
// commit, through clients.RelationStore.DeleteTuples, and this file asserted both
// halves.
//
// Stage S6 removed the engine. The journal stayed and changed role: a database
// trigger (`relation_fact_follows_journal`, migrations 0098/0100) folds every journal
// row into `kacho_iam.relation_fact` — the table a verdict is read from — IN THE SAME
// TRANSACTION as the INSERT. So the revoke is effective at commit, which is earlier
// and stricter than "synchronously, just after commit"; and the port through which
// the second half was asserted no longer carries DeleteTuples at all.
//
// Keeping those assertions would have made them true by construction of the fake's
// own type: with no method to call, "the set was not removed" could never go red for
// a product reason. They are dropped, the reason is written here rather than deleted,
// and what remains is the half that has a producer — the set stated in the writer-tx.
//
// The test does NOT use testcontainers (no Postgres required). It wires in-memory
// fakes for the Repository and operations.Repo, exercises the full Create→Delete
// round-trip through both use-cases, and asserts:
//
//  1. Create states ≥2 tuples (role-relation + hierarchy for project-scoped).
//  2. Delete states exactly the same set (grant is fully revoked).
//  3. For an account-scoped binding: Create states 1 tuple, Delete states 1 tuple.

import (
	"context"
	stderrors "errors"
	"sort"
	"strings"
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
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/visibility"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// ─── Symmetric FGA grant/revoke ────────────────────────────────────────────

// TestFGASymmetric_CreateWritesTuples_DeleteRevokesSameSet asserts the
// emit-in-tx contract — the tuple set stated by Create (EmitRelationWrite) is
// byte-identical to the set stated by Delete (EmitRelationDelete). The projection
// of those rows into the fact table a verdict is read from is exercised against a
// real Postgres by the relverdict integration suite.
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
	fga := newRecordingFGA() // wired via WithRelationStore: the READ side (grant-authority)

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

	// Journal rows captured via the writer-iface fake.
	writtenTuples := repo.drainFGAWritten()
	require.GreaterOrEqual(t, len(writtenTuples), 2,
		"Create must state ≥2 journal tuples (role-relation + hierarchy)")

	// Verify role-relation tuple.
	assert.Contains(t, writtenTuples, ab_repo.RelationTuple{
		User:     "user:" + subjectID,
		Relation: "viewer",
		Object:   "project:" + resourceID,
	}, "Create must state the role-relation tuple in the journal")

	// Verify hierarchy tuple (required for Get/Delete authz cascade).
	abID := repo.lastInsertedID()
	require.NotEmpty(t, abID, "repo must record the inserted AB id")
	assert.Contains(t, writtenTuples, ab_repo.RelationTuple{
		User:     "project:" + resourceID,
		Relation: "project",
		Object:   "iam_access_binding:" + string(abID),
	}, "Create must state the hierarchy tuple in the journal")

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
		"Delete must state the same number of journal tuples as Create did")

	for _, w := range writtenTuples {
		assert.Contains(t, deletedTuples, w,
			"Delete must state revoke tuple {User:%q Relation:%q Object:%q}",
			w.User, w.Relation, w.Object)
	}
}

// TestFGASymmetric_AccountBinding_RoleRelationAndHierarchyTuple —
// account-scoped bindings state the role-relation tuple PLUS the
// `account`-parent hierarchy tuple in the journal, so the model's
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

	// Admin-class permissions → relation "admin". The permission NAMES the account
	// on purpose: level 3 on an account anchor is only emitted when the role covers
	// iam.account, because account:<A>#admin is a cascade source (see
	// tuples.go::capSynthesizedAccountAdmin). The subject of this test is the
	// create/delete symmetry of the emitted set, so it wants the strongest tier —
	// authored rather than synthesized.
	perms := domain.Permissions{"iam.account.admin"}
	repo := newABFakeRepo(ownerID, accountID, resID, roleID, roleName, perms)
	opsRepo := newFakeOpsRepo()
	fga := newRecordingFGA()
	ctx := newOwnerContext(ownerID)

	createUC := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(fga, nil)
	binding := domain.AccessBinding{
		SubjectType:  "user",
		SubjectID:    domain.SubjectID(subjectID),
		RoleID:       domain.RoleID(roleID),
		ResourceType: "account", // account anchor — states its own `account`-parent pointer
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
	}, "must state the role-relation tuple")
	assert.Contains(t, written, ab_repo.RelationTuple{
		User:     "account:" + resID,
		Relation: "account",
		Object:   "iam_access_binding:" + string(repo.lastInsertedID()),
	}, "must state the account-parent hierarchy tuple (cascade readability)")

	deleteUC := NewDeleteAccessBindingUseCase(repo, opsRepo).WithRelationStore(fga, nil)
	subjectCtx := newOwnerContext(subjectID)
	_, err = deleteUC.Execute(subjectCtx, repo.lastInsertedID())
	require.NoError(t, err)
	waitCtx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	require.NoError(t, operations.Wait(waitCtx2))

	deleted := repo.drainFGADeleted()
	require.Equal(t, written, deleted, "Delete must state the same single tuple Create stated")
}

// ─── relation-store stub ─────────────────────────────────────────────────────

// recordingFGA — clients.RelationStore for the READ side of these use-cases:
// requireGrantAuthority asks it whether the caller may hand out this grant, and it
// answers yes so a fixture can get past that gate and reach the subject under test.
//
// # It no longer records anything, and the name is a debt this change did not pay
//
// It carried WriteTuples/DeleteTuples with the sets they were handed, because
// clients.RelationStore declared them: the port stood for someone ELSE'S storage,
// and a revoke reached that storage through it. Stage S6 removed the external
// engine; the port kept only the question (Check). There is nowhere to write any
// more — a grant becomes an answer by the SAME COMMIT that records it (journal →
// trigger `relation_fact_follows_journal` → `relation_fact`).
//
// The recording side is removed rather than left in place. A method standing for a
// port method that no longer exists has no caller: nothing can exercise it, so
// nothing asserted about it can ever go red for a product reason, and a fake that
// offers it looks like it stands for a wider surface than it does.
//
// The NAME stays because eight files of this package name this type or its
// constructor and they are not this change's subject; renaming it here would edit
// them. What was false was what the type DID, and that is what is corrected —
// with the mismatch written down rather than left for the next reader to discover.
type recordingFGA struct{}

func newRecordingFGA() *recordingFGA { return &recordingFGA{} }

func (r *recordingFGA) Check(_ context.Context, _, _, _ string) (bool, error) { return true, nil }

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
	// Captured journal (`kacho_iam.fga_outbox`) emit-in-tx tuples — the rows a
	// trigger folds into `kacho_iam.relation_fact` inside the same transaction.
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
	// used by the viewer ∪ v_list union-floor unit tests. Also the source rows for
	// the unified List fake.
	lbsRows []domain.AccessBinding
	// lbsubRows — фикстурные строки чтения ListBySubject. Засеваются
	// seedABListBySubject. До #1352 это чтение отдавало пустоту всегда, и дублёр
	// отвечал тем же — на пустом ответе сужение утверждать нечем: «чужого нет»
	// зеленело бы на полностью сломанной полосе.
	lbsubRows []domain.AccessBinding
	// lastListFilter — the ListFilter the unified List last received (F11 tests
	// assert the use-case's VisibleIDs push-down + predicate mapping).
	lastListFilter ab_repo.ListFilter
	// materializedAt — reconciler-ledger fixture backing
	// ListMaterializedAtForBindings (AccessBinding.materialized_at). Seed via
	// seedMaterializedAt; an absent binding reports nothing (= not yet live).
	materializedAt map[domain.AccessBindingID]time.Time
	// lastByScopeType / lastByScopeID — the scope anchor ListByScope last received.
	// The handler resolves the canonical dotted `scope_type` (or the legacy bare
	// `resource_type`) to the bare within-service kind BEFORE the use-case, so these
	// pin that resolution (scope_coordinate_test.go).
	lastByScopeType domain.ResourceType
	lastByScopeID   string
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
	// membersOfGroupsErr — отказ чтения состава групп. Ручка нужна, потому что
	// «полнота перечисления» держится ТОЛЬКО тем, что отказ соседа отказывает
	// запросу: проглоченный отказ даёт тихо усечённый ответ, неотличимый от
	// честного «в группах никого» (#914).
	membersOfGroupsErr error
	// groupsReaderNil — непровязанный читатель групп. Отдельная полоса от
	// отказа: «мне нечем ответить» и «ответ пуст» — разные факты, и второй не
	// вправе производиться первым.
	groupsReaderNil bool
	// incompleteGroups — перечень групп, чей состав дублёр объявляет неполным.
	// Настоящий читатель объявляет это, упершись в предел выборки; дублёру
	// предел ни к чему, а признак нужен — иначе путь его переноса не проверен.
	incompleteGroups []domain.GroupID
	// emittedTuples — persisted exact emitted-set per binding
	// (access_binding_emitted_tuples), keyed by binding id. Co-committing
	// the grant tuples here lets revoke/Role.Update use the stored set
	// (not a re-derive from the mutable role). Set semantics on the tuple
	// (dedupe), but INSERTION ORDER is preserved on read-back: the real pg repo
	// returns a deterministic `ORDER BY relation, object, fga_user` and the
	// symmetric-revoke contract is set-based (the journal's projection applies a set),
	// yet TestFGASymmetric asserts byte-equality of the write-set vs the
	// delete-set. Insertion order makes SelectEmittedTuples deterministic AND
	// equal to the order EmitRelationWrite captured (create.go feeds the SAME
	// `tuples` slice to EmitRelationWrite and InsertEmittedTuples), so the
	// round-trip is order-stable without an unordered Go-map shuffle. A plain
	// `map[tuple]struct{}` iterates in random order ⇒ require.Equal flakes/fails.
	emittedTuples map[domain.AccessBindingID]*orderedTupleSet
	// claimedByOthers — the tuples some OTHER *ACTIVE* binding also recorded in its
	// own ledger row (the emitted-tuple ledger is keyed per binding, while the
	// materialized fact is one row per (object, relation, subject) and is NOT
	// refcounted). Backs the fake
	// SelectTuplesClaimedByOtherActiveBindings probe; seeded per test via
	// seedTuplesClaimedByOtherActiveBindings. Empty ⇒ nothing else claims anything.
	claimedByOthers []ab_repo.RelationTuple
	// txOps — ordered trace of the writer-tx port calls that carry a DB-level
	// serialization contract (advisory-lock / ledger-read / status-CAS). Lets a
	// unit test pin the ORDER those statements are issued in, which is what makes
	// the revoke critical-section race-free (ban #10) — see revoke_test.go.
	txOps []string
}

// recordTxOp appends one writer-tx port call to the ordered trace.
func (r *abFakeRepo) recordTxOp(op string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.txOps = append(r.txOps, op)
}

// resetTxOpTrace drops the marks recorded so far, so a probe whose subject is ONE
// transaction is not reading another one's. Without it a fixture that grants before
// it revokes cannot tell the two transactions apart in a single flat trace.
func (r *abFakeRepo) resetTxOpTrace() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.txOps = nil
}

// txOpTrace returns a copy of the recorded writer-tx port-call order.
func (r *abFakeRepo) txOpTrace() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.txOps))
	copy(out, r.txOps)
	return out
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

// seedMaterializedAt — test helper. Records the instant a binding's per-object
// access became live, as the reconciler ledger would.
func (r *abFakeRepo) seedMaterializedAt(id domain.AccessBindingID, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.materializedAt == nil {
		r.materializedAt = map[domain.AccessBindingID]time.Time{}
	}
	r.materializedAt[id] = at
}

// seedABListByAccount — test helper. Replaces the fixture rows returned by
// the fake fakeABRdr.ListByAccount.
// seedABListBySubject replaces the fixture rows returned by the fake
// ListBySubject.
func seedABListBySubject(r *abFakeRepo, rows []domain.AccessBinding) {
	r.mu.Lock()
	r.lbsubRows = rows
	r.mu.Unlock()
}

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
func (rd *abFakeReader) Groups() group.ReaderIface {
	rd.repo.mu.Lock()
	nilReader := rd.repo.groupsReaderNil
	rd.repo.mu.Unlock()
	if nilReader {
		return nil
	}
	return &fakeGroupRdr{repo: rd.repo}
}
func (rd *abFakeReader) Roles() role_repo.ReaderIface        { return &fakeRoleRdr{repo: rd.repo} }
func (rd *abFakeReader) AccessBindings() ab_repo.ReaderIface { return &fakeABRdr{repo: rd.repo} }
func (rd *abFakeReader) Commit(_ context.Context) error      { return nil }
func (rd *abFakeReader) Rollback(_ context.Context) error    { return nil }

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
func (w *abFakeWriter) AdvisoryXactLock(_ context.Context, key string) error {
	w.repo.recordTxOp("advisory_xact_lock:" + key)
	return nil
}

// Commit closes the writer-tx and marks the trace, so a probe can tell what was
// stated INSIDE the transaction from what happened after it. abFakeReader.Commit is
// shadowed deliberately: the reader's commit is not the boundary anything here is
// about.
func (w *abFakeWriter) Commit(_ context.Context) error {
	w.repo.recordTxOp("commit")
	return nil
}

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
	// Fidelity with the real pg role repo (role_repo.go): an absent role is the
	// canonical wrapped ErrNotFound with the contract text, so use-case gates that
	// branch on iamerr.ErrNotFound behave as they do in production.
	return domain.Role{}, iamerr.Wrapf(iamerr.ErrNotFound, "Role %s not found", id)
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

// ListActiveHoldingMembership — предмета этой пробы не касается: она не исключает
// человека из аккаунта. Пустой перечень — ЗАКОННЫЙ ответ (мешающих выдач нет), а
// не заглушка «ответить нечем»: дублёр обязан выполнять контракт настоящего, и
// молчаливо шире его не отвечать.
func (a *fakeABRdr) ListActiveHoldingMembership(context.Context, domain.UserID, domain.AccountID, int) ([]string, int, error) {
	return nil, 0, nil
}

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
func (a *fakeABRdr) List(_ context.Context, f ab_repo.ListFilter) ([]domain.AccessBinding, string, error) {
	a.repo.mu.Lock()
	defer a.repo.mu.Unlock()
	a.repo.lastListFilter = f
	// No visibility predicate: read visibility is applied by the use-case to the
	// rows this returns (internal/authzfilter), mirroring the pg repo.
	var out []domain.AccessBinding
	for _, b := range a.repo.lbsRows {
		if f.SubjectID != "" && string(b.SubjectID) != f.SubjectID {
			continue
		}
		if f.RoleID != "" && string(b.RoleID) != f.RoleID {
			continue
		}
		if f.ScopeType != "" && string(b.ResourceType) != f.ScopeType {
			continue
		}
		if f.ScopeID != "" && b.ResourceID != f.ScopeID {
			continue
		}
		out = append(out, b)
	}
	return out, "", nil
}
func (a *fakeABRdr) ListByScope(_ context.Context, resourceType domain.ResourceType, resourceID string, _ ab_repo.PageFilter) ([]domain.AccessBinding, string, error) {
	a.repo.mu.Lock()
	defer a.repo.mu.Unlock()
	a.repo.lastByScopeType = resourceType
	a.repo.lastByScopeID = resourceID
	if a.repo.lbsRows == nil {
		return nil, "", nil
	}
	out := make([]domain.AccessBinding, len(a.repo.lbsRows))
	copy(out, a.repo.lbsRows)
	return out, "", nil
}
func (a *fakeABRdr) ListBySubject(_ context.Context, _ domain.SubjectType, _ domain.SubjectID, _ ab_repo.PageFilter) ([]domain.AccessBinding, string, error) {
	a.repo.mu.Lock()
	defer a.repo.mu.Unlock()
	if a.repo.lbsubRows == nil {
		return nil, "", nil
	}
	out := make([]domain.AccessBinding, len(a.repo.lbsubRows))
	copy(out, a.repo.lbsubRows)
	return out, "", nil
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
func (g *fakeGroupRdr) ListMembers(_ context.Context, _ domain.GroupID, _ group.MemberPage) ([]domain.GroupMember, string, error) {
	return nil, "", nil
}

// MembersOfGroups — дублёр отвечает ИЗ ТОГО ЖЕ хранилища, что и IsMember.
// Дублёр, отвечающий пусто там, где настоящий отвечает составом, сделал бы
// невидимым ровно тот недоответ, ради которого пробу и пишут.
func (g *fakeGroupRdr) MembersOfGroups(_ context.Context, groupIDs []domain.GroupID) ([]domain.GroupMember, []domain.GroupID, error) {
	g.repo.mu.Lock()
	defer g.repo.mu.Unlock()
	if g.repo.membersOfGroupsErr != nil {
		return nil, nil, g.repo.membersOfGroupsErr
	}
	want := make(map[string]struct{}, len(groupIDs))
	for _, id := range groupIDs {
		want[string(id)] = struct{}{}
	}
	keys := make([]string, 0, len(g.repo.groupMembers))
	for k := range g.repo.groupMembers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []domain.GroupMember
	for _, k := range keys {
		parts := strings.SplitN(k, "|", 3)
		if len(parts) != 3 {
			continue
		}
		if _, ok := want[parts[0]]; !ok {
			continue
		}
		out = append(out, domain.GroupMember{
			GroupID:    domain.GroupID(parts[0]),
			MemberType: domain.SubjectType(parts[1]),
			MemberID:   domain.SubjectID(parts[2]),
		})
	}
	// Дублёр отдаёт состав целиком и говорит об этом пустым перечнем неполных:
	// снисходительнее настоящего он быть не вправе, но и усечения, которого не
	// было, объявлять не должен.
	return out, g.repo.incompleteGroups, nil
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

func (w *fakeABWtr) RevokeGuarded(_ context.Context, id domain.AccessBindingID, revokedBy domain.UserID) (domain.AccessBinding, error) {
	w.repo.recordTxOp("revoke_guarded:" + string(id))
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	if w.repo.ab == nil || w.repo.ab.ID != id {
		return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
	}
	if w.repo.ab.DeletionProtection {
		return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"access binding %s has deletion_protection enabled; clear it via Update before revoke", id)
	}
	if w.repo.ab.Status != domain.AccessBindingStatusActive {
		return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"access binding %s is not active (status %s); cannot revoke", id, w.repo.ab.Status)
	}
	now := time.Now().UTC()
	rb := revokedBy
	w.repo.ab.Status = domain.AccessBindingStatusRevoked
	w.repo.ab.RevokedAt = &now
	w.repo.ab.RevokedByUserID = &rb
	return *w.repo.ab, nil
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

// EmitRelationDelete also leaves a mark in the writer-tx trace.
//
// The mark is what lets a probe assert WHEN the revoke set is stated, and "when" is
// the whole property now: the trigger on the journal applies the row to the fact
// table inside the same transaction, so a set stated BEFORE the commit is denied
// AT the commit — whereas a set stated after it would be a second, separate write
// that could be lost between the two. Without the mark the ordering is invisible to
// every probe in this package, and a move of the emit out of the transaction would
// keep every set-equality assertion green.
func (w *fakeABWtr) EmitRelationDelete(_ context.Context, tuples []ab_repo.RelationTuple) error {
	w.repo.recordTxOp("emit_relation_delete")
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

// Visibility — структурные факты о вызывающем, объявленные НЕСУЖЁННЫМИ.
//
// Это НАМЕРЕННО снисходительнее продукта, и цена названа вслух, а не умолчана:
// строк выдачи у этой фикстуры нет вовсе (её гранты живут только в дублёре стора
// отношений), поэтому назвать кандидатов она не может — а сузив набор до пустого,
// она вернула бы пустую страницу везде и стёрла бы ровно то, о чём эти пробы
// спрашивают.
//
// Отсюда граница: предмет проб этого пакета — ВЕРДИКТ (каким отношением судится
// строка страницы, ведёт ли сверх-гейт администратора облака к нефильтрованной
// выдаче, что происходит на отказе стора). ОТБОР кандидатов они не проверяют и
// проверять не могут; он проверяется на настоящем Postgres и настоящей модели
// прав — services/iam/internal/apps/kacho/api/listvisibility, где снисходительного
// дублёра нет ни с одной стороны именно потому, что предмет там — ПОРЯДОК между
// страницей и сужением.
//
// Прежде здесь стоял nil с комментарием «списочный use-case обязан ОТКАЗАТЬ».
// Он и отказывает — ровно поэтому дублёру пришлось начать отвечать: nil означает
// «сузить нечем», а эта фикстура сузить может (ничем не сужая), и это разные
// утверждения.
func (rd *abFakeReader) Visibility() visibility.ReaderIface { return unrestrictedVisibility{} }

// unrestrictedVisibility — «кандидаты не сужаются». Ровно то, что означает
// visibility.Scope{Unrestricted: true}: Candidates(...) вернёт nil, и репозиторий
// не получит ни одного предиката отбора.
type unrestrictedVisibility struct{}

func (unrestrictedVisibility) ScopeOf(_ context.Context, _ visibility.Subject) (visibility.Scope, error) {
	return visibility.Scope{Unrestricted: true, GrantedObjects: map[string][]string{}}, nil
}

// Visibility — дублёр структурных фактов о вызывающем не несёт: они читаются
// живой БД, и пробы, которые их проверяют, гоняют настоящий Postgres
// (services/iam/internal/apps/kacho/api/listvisibility). nil здесь означает
// «сузить нечем», и списочный use-case обязан на нём ОТКАЗАТЬ, а не листать
// ненаречённое.
func (r *abFakeWriter) Visibility() visibility.ReaderIface { return nil }

// MembershipExists — дублёр не отвечает на вопрос о членстве: предмет этой
// пробы другой, и подставной ответ был бы утверждением, которого никто не
// делал. Единственный прод-вызывающий — разрешение осиротевшей операции
// исключения из аккаунта (#1127).
func (*fakeUserRdr) MembershipExists(context.Context, domain.UserID, domain.AccountID) (bool, error) {
	return false, nil
}
