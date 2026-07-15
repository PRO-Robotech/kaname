// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package account

// create_test.go — unit-тесты CreateAccountUseCase (без БД).
//
// Покрытие:
//   - TestCreate_Sync_InvalidName     — sync InvalidArgument (без Operation),
//     invalid name (subset).
//   - TestCreate_Sync_RequireOwner    — sync InvalidArgument (owner_user_id required).
//   - TestCreate_Sync_OK_OpReturned   — happy path до async-фазы (Operation
//     возвращен, async worker не падает).
//
// Использует in-memory fakes для operations.Repo и Repository (не testcontainers).
// Реальный CRUD round-trip — в integration-тестах (см. pg/account_integration_test.go).

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
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// ── invalid name → sync InvalidArgument ─────────────────────────────────────
func TestCreate_Sync_InvalidName(t *testing.T) {
	cases := []struct {
		name string
		val  domain.AccountName
	}{
		{"empty", ""},
		{"length<3", "ab"},
		{"uppercase", "Acme"},
		{"underscore", "acme_x"},
		{"too_long", domain.AccountName(strings.Repeat("a", 64))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uc := NewCreateAccountUseCase(newFakeRepo(), newFakeOpsRepo())
			a := domain.Account{
				Name:        tc.val,
				OwnerUserID: "usr00000000000000abcd",
			}
			op, err := uc.Execute(operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: "usr00000000000000abcd"}), a)
			require.Error(t, err)
			assert.Nil(t, op, "Operation не должна создаваться при sync-ошибке")
			st, ok := status.FromError(err)
			require.True(t, ok, "ожидаем grpc status; err=%v", err)
			assert.Equal(t, codes.InvalidArgument, st.Code())
		})
	}
}

// ── owner_user_id required → sync InvalidArgument ───────────────────────────
func TestCreate_Sync_RequireOwner(t *testing.T) {
	uc := NewCreateAccountUseCase(newFakeRepo(), newFakeOpsRepo())
	op, err := uc.Execute(operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: "usr00000000000000abcd"}), domain.Account{
		Name: "acme",
	})
	require.Error(t, err)
	assert.Nil(t, op)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, err.Error(), "owner_user_id")
}

// ── happy path: sync OK → Operation возвращен ───────────────────────────────
func TestCreate_Sync_OK_OpReturned(t *testing.T) {
	repo := newFakeRepo()
	opsRepo := newFakeOpsRepo()
	uc := NewCreateAccountUseCase(repo, opsRepo)

	a := domain.Account{
		Name:        "acme-ok",
		Description: "happy",
		Labels:      domain.Labels{"env": "prod"},
		OwnerUserID: "usr00000000000000abcd",
	}
	// Anti-hijacking: principal.ID must == OwnerUserID.
	op, err := uc.Execute(operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: "usr00000000000000abcd"}), a)
	require.NoError(t, err)
	require.NotNil(t, op)
	assert.True(t, strings.HasPrefix(op.ID, domain.PrefixOperationIAM), "operation id prefix iop")
	assert.Contains(t, op.Description, "Create account acme-ok")
	assert.False(t, op.Done, "первый ответ — done=false")

	// Дожидаемся async worker'а через operations.Wait (default registry).
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(ctx))

	// Проверяем, что fake repo получил Insert (worker дошел до доp.логики).
	assert.Equal(t, 1, repo.insertCalls(), "Insert должен быть вызван 1 раз worker'ом")
}

// ── Create writes the cluster parent-tuple ──────────────────────────────────

// spyFGA records WriteTuples calls so the test can assert the cluster
// parent-tuple is emitted alongside the owner-tuple.
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

// TestCreate_SECL_EmitsOwnerAndClusterTupleInTx — the freshly-created account
// must co-commit its owner self-grant (user:<owner>#owner@account:<id>) AND the
// cluster parent-pointer (cluster:cluster_kacho_root#cluster@account:<id>) as
// fga_outbox INTENTS in the SAME writer-tx — NOT best-effort post-commit through
// RelationStore.WriteTuples (which lost the tuple on any FGA outage). The owner
// self-grant is non-reconstructible, so the in-tx emit is the only guarantee.
func TestCreate_SECL_EmitsOwnerAndClusterTupleInTx(t *testing.T) {
	repo := newFakeRepo()
	opsRepo := newFakeOpsRepo()
	// spyFGA wired for backwards-compat WithRelationStore; the owner-tuple is no
	// longer written through it (in-tx emit feeds the drainer instead).
	fga := &spyFGA{}
	uc := NewCreateAccountUseCase(repo, opsRepo).WithRelationStore(fga, nil)

	a := domain.Account{Name: "acme-secl", OwnerUserID: "usr00000000000000abcd"}
	op, err := uc.Execute(operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr00000000000000abcd"}), a)
	require.NoError(t, err)
	require.NotNil(t, op)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(ctx))

	var ownerSeen, clusterSeen bool
	for _, tup := range repo.fgaTuples() {
		if tup.Relation == "owner" && tup.User == "user:usr00000000000000abcd" &&
			strings.HasPrefix(tup.Object, "account:") {
			ownerSeen = true
		}
		if tup.Relation == "cluster" && tup.User == "cluster:cluster_kacho_root" &&
			strings.HasPrefix(tup.Object, "account:") {
			clusterSeen = true
		}
	}
	assert.True(t, ownerSeen,
		"owner self-grant intent must be co-committed in-tx (not reconstructible)")
	assert.True(t, clusterSeen,
		"account:<id>#cluster@cluster:cluster_kacho_root must be co-committed in-tx")
	// The owner-tuple is no longer pushed sync through RelationStore.WriteTuples.
	assert.Empty(t, fga.snapshot(),
		"create path must NOT write tuples post-commit via RelationStore (now in-tx outbox)")
}

// TestCreate_EmitsOwnerBindingHierarchyTuple — no-access-loss. The owner
// AccessBinding co-committed by Account.Create MUST also co-commit the
// binding-OBJECT hierarchy parent-pointer
// (account:<A>#account@iam_access_binding:<ownerBindingID>) — exactly as a regular
// AccessBinding.Create does via tuplesForBinding/hierarchyParentTuple. Without it the
// owner holds NO viewer/editor path to the owner-binding object itself, so a Get or
// Delete on it is authz-DENIED (403) instead of resolving the FAILED_PRECONDITION
// deletion_protection guard — the failure observed in e2e (Get/Delete owner-binding
// → 403). Reconcile materializes per-object CONTENT, not this binding-lifecycle
// hierarchy pointer; so it must be emitted in-tx.
func TestCreate_EmitsOwnerBindingHierarchyTuple(t *testing.T) {
	repo := newFakeRepo()
	opsRepo := newFakeOpsRepo()
	uc := NewCreateAccountUseCase(repo, opsRepo)

	a := domain.Account{Name: "acme-owner-hier", OwnerUserID: "usr00000000000000abcd"}
	op, err := uc.Execute(operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr00000000000000abcd"}), a)
	require.NoError(t, err)
	require.NotNil(t, op)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(ctx))

	// Resolve the owner-binding id the use-case assigned (captured by the fake AB
	// writer) so we can assert the hierarchy pointer targets THAT binding object.
	owners := repo.ownerBindingsSnapshot()
	require.Len(t, owners, 1, "exactly one owner-binding co-committed")
	bindingID := string(owners[0].ID)
	require.NotEmpty(t, bindingID)
	wantObject := "iam_access_binding:" + bindingID

	var hierSeen bool
	for _, tup := range repo.fgaTuples() {
		if tup.Relation == "account" &&
			strings.HasPrefix(tup.User, "account:") &&
			tup.Object == wantObject {
			hierSeen = true
		}
	}
	assert.True(t, hierSeen,
		"owner-binding hierarchy parent-pointer account:<A>#account@%s must be co-committed "+
			"in-tx so the owner can Get/Delete the binding object (no-access-loss)", wantObject)
}

// TestCreate_RecordsOwnerBindingTuplesInLedger — symmetric revoke.
// The owner self-grant (user:<owner>#owner@account:<A>) and the owner-binding OBJECT
// hierarchy parent-pointer (account:<A>#account@iam_access_binding:<id>) must be
// recorded in the access_binding_emitted_tuples ledger for the owner-binding. A
// regular AccessBinding.Create records its hierarchy pointer into the ledger
// (InsertEmittedTuples) so delete.go's SYMMETRIC revoke (SelectEmittedTuples)
// removes it. Without it, revoking the owner-binding orphans the `owner` tuple — and
// since the FGA model derives account admin from owner (`define admin: … or owner`),
// the revoked owner retains effective admin (standing privilege). The owner-binding
// records BOTH binding-lifecycle tuples into the ledger in the same writer-tx.
//
// NOTE: the cluster pointer (cluster:cluster_kacho_root#cluster@account:<A>) is
// ACCOUNT-lifecycle (mirrored by Project.Create / user upsert; survives owner-binding
// revoke) and is DELIBERATELY NOT recorded in the owner-binding ledger.
func TestCreate_RecordsOwnerBindingTuplesInLedger(t *testing.T) {
	repo := newFakeRepo()
	opsRepo := newFakeOpsRepo()
	uc := NewCreateAccountUseCase(repo, opsRepo)

	a := domain.Account{Name: "acme-owner-ledger", OwnerUserID: "usr00000000000000abcd"}
	op, err := uc.Execute(operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr00000000000000abcd"}), a)
	require.NoError(t, err)
	require.NotNil(t, op)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(ctx))

	owners := repo.ownerBindingsSnapshot()
	require.Len(t, owners, 1, "exactly one owner-binding co-committed")
	bindingID := string(owners[0].ID)
	require.NotEmpty(t, bindingID)

	ledger := repo.emittedTuplesSnapshot()

	var ownerSelfGrantRecorded, hierarchyRecorded, clusterRecorded bool
	for _, t := range ledger {
		if t.Relation == "owner" && t.User == "user:usr00000000000000abcd" &&
			strings.HasPrefix(t.Object, "account:") {
			ownerSelfGrantRecorded = true
		}
		if t.Relation == "account" && strings.HasPrefix(t.User, "account:") &&
			t.Object == "iam_access_binding:"+bindingID {
			hierarchyRecorded = true
		}
		if t.Relation == "cluster" && t.User == "cluster:cluster_kacho_root" {
			clusterRecorded = true
		}
	}

	assert.True(t, ownerSelfGrantRecorded,
		"owner self-grant (user:<owner>#owner@account:<A>) MUST be in the emitted-tuple ledger "+
			"so revoke is symmetric (FGA derives admin from owner → standing privilege otherwise)")
	assert.True(t, hierarchyRecorded,
		"owner-binding hierarchy parent-pointer MUST be in the emitted-tuple ledger so revoke removes it")
	assert.False(t, clusterRecorded,
		"cluster pointer is ACCOUNT-lifecycle — it must NOT be in the owner-binding ledger (survives revoke)")
}

// TestCreate_OwnerBindingIsSelfValidating — self-validating domain.
// The owner AccessBinding co-committed by Account.Create is constructed internally
// (not user input), but doCreate runs ownerBinding.Validate() BEFORE Insert —
// mirroring the public AccessBinding.Create path — so any future field drift that
// makes the internally-built binding malformed fails the worker (rollback) rather
// than persisting an invalid row. This test pins the contract: the binding handed to
// the writer is well-formed AND carries a non-empty granter (actor is provably
// non-empty on this authenticated path).
func TestCreate_OwnerBindingIsSelfValidating(t *testing.T) {
	repo := newFakeRepo()
	opsRepo := newFakeOpsRepo()
	uc := NewCreateAccountUseCase(repo, opsRepo)

	a := domain.Account{Name: "acme-owner-valid", OwnerUserID: "usr00000000000000abcd"}
	op, err := uc.Execute(operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr00000000000000abcd"}), a)
	require.NoError(t, err)
	require.NotNil(t, op)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(ctx))

	owners := repo.ownerBindingsSnapshot()
	require.Len(t, owners, 1, "exactly one owner-binding co-committed")
	ownerBinding := owners[0]

	// The internally-built owner-binding must satisfy domain validation (the same
	// invariant doCreate now asserts before Insert).
	require.NoError(t, ownerBinding.Validate(),
		"owner-binding handed to Insert must be self-validating")
	// Granter is recorded (actor is the verified principal, never empty on this path).
	assert.Equal(t, domain.UserID("usr00000000000000abcd"), ownerBinding.GrantedByUserID,
		"owner-binding records the verified creator as granter")
}

// ── in-memory fakes ─────────────────────────────────────────────────────────

// fakeRepo — минимальный fake kacho.Repository.
type fakeRepo struct {
	mu          sync.Mutex
	insertCount int
	fgaEmitted  []service.RelationTuple
	// ownerBindings records the owner AccessBinding(s) co-committed by
	// Account.Create.
	ownerBindings []domain.AccessBinding
	// emittedTuples records the emitted-tuple LEDGER rows co-committed by
	// Account.Create (symmetric revoke). Keyed by binding id.
	emittedTuples []access_binding.RelationTuple
}

func newFakeRepo() *fakeRepo { return &fakeRepo{} }

func (f *fakeRepo) insertCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.insertCount
}

// fgaTuples — snapshot of the FGA owner-tuple intents emitted in-tx.
func (f *fakeRepo) fgaTuples() []service.RelationTuple {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]service.RelationTuple, len(f.fgaEmitted))
	copy(cp, f.fgaEmitted)
	return cp
}

// ownerBindingsSnapshot — snapshot of the owner AccessBinding(s) co-committed by
// Account.Create, so a test can resolve the assigned binding id.
func (f *fakeRepo) ownerBindingsSnapshot() []domain.AccessBinding {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]domain.AccessBinding, len(f.ownerBindings))
	copy(cp, f.ownerBindings)
	return cp
}

// emittedTuplesSnapshot — snapshot of the emitted-tuple LEDGER rows co-committed by
// Account.Create (symmetric revoke depends on these being in the ledger).
func (f *fakeRepo) emittedTuplesSnapshot() []access_binding.RelationTuple {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]access_binding.RelationTuple, len(f.emittedTuples))
	copy(cp, f.emittedTuples)
	return cp
}

func (f *fakeRepo) Reader(ctx context.Context) (kachorepo.Reader, error) {
	return &fakeReader{}, nil
}
func (f *fakeRepo) Writer(ctx context.Context) (kachorepo.Writer, error) {
	return &fakeWriter{repo: f}, nil
}
func (f *fakeRepo) Close() {}

type fakeReader struct{}

func (fakeReader) Accounts() account.ReaderIface                { return fakeAcctReader{} }
func (fakeReader) Projects() project.ReaderIface                { return nil }
func (fakeReader) Users() user.ReaderIface                      { return nil }
func (fakeReader) ServiceAccounts() service_account.ReaderIface { return nil }
func (fakeReader) Groups() group.ReaderIface                    { return nil }
func (fakeReader) Roles() role.ReaderIface                      { return nil }
func (fakeReader) AccessBindings() access_binding.ReaderIface   { return nil }
func (fakeReader) Commit(context.Context) error                 { return nil }
func (fakeReader) Rollback(context.Context) error               { return nil }

type fakeWriter struct {
	fakeReader
	repo *fakeRepo
}

// fgaEmitted records the FGA owner-tuple intents co-committed in-tx via
// EmitFGARelationWrite. The cluster-tuple test asserts the owner + cluster
// parent-pointer tuples are emitted in the writer-tx (no longer best-effort
// post-commit through RelationStore.WriteTuples).
func (w *fakeWriter) EmitFGARelationWrite(_ context.Context, tuples []service.RelationTuple) error {
	w.repo.mu.Lock()
	w.repo.fgaEmitted = append(w.repo.fgaEmitted, tuples...)
	w.repo.mu.Unlock()
	return nil
}
func (w *fakeWriter) EmitFGARelationDelete(context.Context, []service.RelationTuple) error {
	return nil
}

func (w *fakeWriter) AccountsW() account.WriterIface {
	return &fakeAcctWriter{parent: w.repo}
}
func (w *fakeWriter) ProjectsW() project.WriterIface                { return nil }
func (w *fakeWriter) UsersW() user.WriterIface                      { return nil }
func (w *fakeWriter) ServiceAccountsW() service_account.WriterIface { return nil }
func (w *fakeWriter) GroupsW() group.WriterIface                    { return nil }
func (w *fakeWriter) RolesW() role.WriterIface                      { return nil }
func (w *fakeWriter) AccessBindingsW() access_binding.WriterIface {
	return &fakeAccountABWriter{parent: w.repo}
}
func (w *fakeWriter) EmitAuditEvent(context.Context, service.AuditEvent) error { return nil }
func (w *fakeWriter) InsertRecoveryCompletion(context.Context, domain.RecoveryCompletion) (domain.RecoveryCompletion, bool, error) {
	return domain.RecoveryCompletion{}, false, nil
}
func (w *fakeWriter) UpsertUserTokenRevokeAll(context.Context, domain.UserTokenRevocation, domain.UserID) error {
	return nil
}
func (w *fakeWriter) Savepoint(context.Context, string) error           { return nil }
func (w *fakeWriter) RollbackToSavepoint(context.Context, string) error { return nil }
func (w *fakeWriter) ReleaseSavepoint(context.Context, string) error    { return nil }
func (w *fakeWriter) AdvisoryXactLock(context.Context, string) error    { return nil }

type fakeAcctReader struct{}

func (fakeAcctReader) Get(context.Context, domain.AccountID) (domain.Account, error) {
	return domain.Account{}, stderrors.New("fakeAcctReader.Get not stubbed")
}
func (fakeAcctReader) List(context.Context, account.ListFilter) ([]domain.Account, string, error) {
	return nil, "", nil
}
func (fakeAcctReader) ExistsByName(context.Context, domain.AccountName) (bool, error) {
	return false, nil
}
func (fakeAcctReader) CountAccountsByOwner(context.Context, domain.UserID) (int, error) {
	return 0, nil
}

type fakeAcctWriter struct {
	fakeAcctReader
	parent *fakeRepo
}

func (w *fakeAcctWriter) Insert(ctx context.Context, a domain.Account) (domain.Account, error) {
	w.parent.mu.Lock()
	w.parent.insertCount++
	w.parent.mu.Unlock()
	a.CreatedAt = time.Now().UTC()
	return a, nil
}
func (w *fakeAcctWriter) Update(context.Context, domain.Account, []string) (domain.Account, error) {
	return domain.Account{}, stderrors.New("fakeAcctWriter.Update not stubbed")
}
func (w *fakeAcctWriter) Delete(context.Context, domain.AccountID) error {
	return stderrors.New("fakeAcctWriter.Delete not stubbed")
}

// fakeAccountABWriter — minimal access_binding.WriterIface for the owner
// auto-binding co-commit. Only Insert / InsertSubjects / EmitAuditEvent are
// exercised by Account.Create.doCreate; the rest panic via the nil embedded
// interface if unexpectedly called (fail-loud, not silently wrong).
type fakeAccountABWriter struct {
	access_binding.WriterIface
	parent *fakeRepo
}

func (w *fakeAccountABWriter) Insert(_ context.Context, b domain.AccessBinding) (domain.AccessBinding, error) {
	w.parent.mu.Lock()
	w.parent.ownerBindings = append(w.parent.ownerBindings, b)
	w.parent.mu.Unlock()
	b.CreatedAt = time.Now().UTC()
	return b, nil
}

func (w *fakeAccountABWriter) InsertSubjects(context.Context, domain.AccessBindingID, []domain.Subject) error {
	return nil
}

// InsertEmittedTuples records the owner-binding ledger rows co-committed by
// Account.Create (so the symmetric revoke in delete.go removes them).
func (w *fakeAccountABWriter) InsertEmittedTuples(_ context.Context, _ domain.AccessBindingID, tuples []access_binding.RelationTuple) error {
	w.parent.mu.Lock()
	w.parent.emittedTuples = append(w.parent.emittedTuples, tuples...)
	w.parent.mu.Unlock()
	return nil
}

func (w *fakeAccountABWriter) EmitAuditEvent(context.Context, access_binding.AuditEvent) error {
	return nil
}

// ── fake operations.Repo ────────────────────────────────────────────────────

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
func (r *fakeOpsRepo) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
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

// EmitReconcileEvent — no-op stub (fake does not exercise the iam-direct reconcile trigger).
func (w *fakeWriter) EmitReconcileEvent(context.Context, string, string, string) error {
	return nil
}
