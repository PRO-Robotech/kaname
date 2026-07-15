// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// update_labels_test.go — unit-тесты UpdateRoleUseCase для own-resource labels
// (T3.3 unify IAM label-scope, chunk 2).
//
// Покрывает:
//   - T3.3-VAL-01/discipline: labels — mutable поле (в update_mask разрешено);
//     immutable identity-поле (account_id/is_system) в mask → sync INVALID_ARGUMENT;
//     unknown поле в mask → sync INVALID_ARGUMENT. Эти reject — sync pre-checks
//     ДО repo, поэтому nil-repo use-case безопасен.
//   - T3.3-UPD-01/REVOKE-01 (через фейк): labels-change co-commit'ит reconcile-event
//     "iam.role" в writer-tx; no-op когда labels не изменились.
//
// Реальный round-trip + iam-direct материализация — в integration
// (pg/role_labels_integration_test.go).

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

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

const (
	rlUpdRoleID    = "rol0000000000000targ"
	rlUpdAccountID = "acc0000000000000updt"
	rlUpdOwnerID   = "usr0000000000000ownr"
)

var rlErrNotFound = stderrors.New("not found")

// ownerCtx — authenticated owner principal (passes RequireOwnerMatchesPrincipal).
func ownerCtx() context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{
		Type: "user", ID: rlUpdOwnerID, DisplayName: "owner",
	})
}

// ── sync mask-discipline reject paths (nil repo — pre-checks) ────────────────────

func TestUpdateRole_T33_LabelsMutable_ImmutableFieldRejected(t *testing.T) {
	uc := &UpdateRoleUseCase{} // nil deps: mask-discipline is a sync pre-check
	roleName := domain.RoleName("x")
	_, err := uc.Execute(ownerCtx(), UpdateRoleInput{
		ID:         rlUpdRoleID,
		Name:       &roleName,
		UpdateMask: []string{"account_id"}, // immutable identity field
	})
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code(),
		"account_id in update_mask → INVALID_ARGUMENT (immutable)")
}

func TestUpdateRole_T33_UnknownMaskField_Rejected(t *testing.T) {
	uc := &UpdateRoleUseCase{}
	_, err := uc.Execute(ownerCtx(), UpdateRoleInput{
		ID:         rlUpdRoleID,
		UpdateMask: []string{"bogus_field"},
	})
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code(),
		"unknown field in update_mask → INVALID_ARGUMENT")
}

// labels is in the mutable set — a labels-only mask reaches the repo (NOT rejected
// by the mask-discipline pre-check). Verified through the happy-path fake below.

// ── happy-path: labels-change co-commits reconcile-event "iam.role" ──────────────

func TestUpdateRole_T33UPD01_LabelsChangeEmitsReconcileEvent(t *testing.T) {
	repo := newRlUpdRepo(domain.Labels{"team": "billing"})
	uc := NewUpdateRoleUseCase(repo, newRlFakeOps())

	_, err := uc.Execute(ownerCtx(), UpdateRoleInput{
		ID:         rlUpdRoleID,
		Labels:     domain.Labels{"team": "payments"},
		UpdateMask: []string{"labels"},
	})
	require.NoError(t, err)
	waitOps(t)

	assert.Equal(t, domain.Labels{"team": "payments"}, repo.labelsSnapshot(),
		"labels applied through the mask-driven Update writer")
	assert.Contains(t, repo.reconcileSnapshot(), rlUpdRoleID,
		"labels change co-commits a reconcile-event on iam.role (forward/eager re-materialization)")
}

func TestUpdateRole_T33UPD01_LabelsUnchanged_NoReconcileEvent(t *testing.T) {
	repo := newRlUpdRepo(domain.Labels{"team": "payments"})
	uc := NewUpdateRoleUseCase(repo, newRlFakeOps())

	_, err := uc.Execute(ownerCtx(), UpdateRoleInput{
		ID:         rlUpdRoleID,
		Labels:     domain.Labels{"team": "payments"}, // identical → no-op
		UpdateMask: []string{"labels"},
	})
	require.NoError(t, err)
	waitOps(t)

	assert.Empty(t, repo.reconcileSnapshot(),
		"unchanged labels → no reconcile-event (no membership flip)")
}

func waitOps(t *testing.T) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))
}

// ── compact fake repo ────────────────────────────────────────────────────────────

type rlUpdRepo struct {
	role     domain.Role
	updated  domain.Labels
	reconcil []string
}

func newRlUpdRepo(initial domain.Labels) *rlUpdRepo {
	return &rlUpdRepo{
		role: domain.Role{
			ID: rlUpdRoleID, AccountID: rlUpdAccountID, Name: "targ",
			Description: "role under test", IsSystem: false, Labels: initial,
			Rules: domain.Rules{{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"}}},
		},
	}
}

func (r *rlUpdRepo) labelsSnapshot() domain.Labels { return r.updated }
func (r *rlUpdRepo) reconcileSnapshot() []string   { return append([]string{}, r.reconcil...) }
func (r *rlUpdRepo) Reader(context.Context) (kachorepo.Reader, error) {
	return &rlUpdReader{parent: r}, nil
}
func (r *rlUpdRepo) Writer(context.Context) (kachorepo.Writer, error) {
	return &rlUpdWriter{rlUpdReader: rlUpdReader{parent: r}}, nil
}
func (r *rlUpdRepo) Close() {}

type rlUpdReader struct{ parent *rlUpdRepo }

func (r *rlUpdReader) Accounts() account.ReaderIface                { return &rlAcctRdr{parent: r.parent} }
func (r *rlUpdReader) Projects() project.ReaderIface                { return nil }
func (r *rlUpdReader) Users() user.ReaderIface                      { return nil }
func (r *rlUpdReader) ServiceAccounts() service_account.ReaderIface { return nil }
func (r *rlUpdReader) Groups() group.ReaderIface                    { return nil }
func (r *rlUpdReader) Roles() role.ReaderIface                      { return &rlRoleRdr{parent: r.parent} }
func (r *rlUpdReader) AccessBindings() access_binding.ReaderIface   { return nil }
func (r *rlUpdReader) Commit(context.Context) error                 { return nil }
func (r *rlUpdReader) Rollback(context.Context) error               { return nil }

type rlRoleRdr struct{ parent *rlUpdRepo }

func (r *rlRoleRdr) Get(_ context.Context, id domain.RoleID) (domain.Role, error) {
	if id != r.parent.role.ID {
		return domain.Role{}, rlErrNotFound
	}
	return r.parent.role, nil
}
func (r *rlRoleRdr) GetWithVersion(_ context.Context, id domain.RoleID) (domain.Role, string, error) {
	if id != r.parent.role.ID {
		return domain.Role{}, "", rlErrNotFound
	}
	return r.parent.role, "v-fake", nil
}
func (r *rlRoleRdr) List(context.Context, role.ListFilter) ([]domain.Role, string, error) {
	return nil, "", nil
}
func (r *rlRoleRdr) ListAssignable(context.Context, string, string, role.ListFilter) ([]domain.Role, string, error) {
	return nil, "", nil
}

type rlAcctRdr struct{ parent *rlUpdRepo }

func (a *rlAcctRdr) Get(_ context.Context, id domain.AccountID) (domain.Account, error) {
	return domain.Account{ID: id, Name: "acct", OwnerUserID: rlUpdOwnerID}, nil
}
func (a *rlAcctRdr) List(context.Context, account.ListFilter) ([]domain.Account, string, error) {
	return nil, "", nil
}
func (a *rlAcctRdr) CountAccountsByOwner(context.Context, domain.UserID) (int, error) { return 0, nil }
func (a *rlAcctRdr) ExistsByName(context.Context, domain.AccountName) (bool, error) {
	return false, nil
}

type rlUpdWriter struct{ rlUpdReader }

func (w *rlUpdWriter) AccountsW() account.WriterIface                { return nil }
func (w *rlUpdWriter) ProjectsW() project.WriterIface                { return nil }
func (w *rlUpdWriter) UsersW() user.WriterIface                      { return nil }
func (w *rlUpdWriter) ServiceAccountsW() service_account.WriterIface { return nil }
func (w *rlUpdWriter) GroupsW() group.WriterIface                    { return nil }
func (w *rlUpdWriter) RolesW() role.WriterIface                      { return &rlRoleWtr{parent: w.parent} }
func (w *rlUpdWriter) AccessBindingsW() access_binding.WriterIface   { return nil }

func (w *rlUpdWriter) EmitAuditEvent(context.Context, service.AuditEvent) error { return nil }
func (w *rlUpdWriter) EmitFGARelationWrite(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *rlUpdWriter) EmitFGARelationDelete(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *rlUpdWriter) EmitReconcileEvent(_ context.Context, _, objectType, objectID string) error {
	if objectType == "iam.role" {
		w.parent.reconcil = append(w.parent.reconcil, objectID)
	}
	return nil
}
func (w *rlUpdWriter) InsertRecoveryCompletion(context.Context, domain.RecoveryCompletion) (domain.RecoveryCompletion, bool, error) {
	return domain.RecoveryCompletion{}, false, nil
}
func (w *rlUpdWriter) UpsertUserTokenRevokeAll(context.Context, domain.UserTokenRevocation, domain.UserID) error {
	return nil
}
func (w *rlUpdWriter) Savepoint(context.Context, string) error           { return nil }
func (w *rlUpdWriter) RollbackToSavepoint(context.Context, string) error { return nil }
func (w *rlUpdWriter) ReleaseSavepoint(context.Context, string) error    { return nil }
func (w *rlUpdWriter) AdvisoryXactLock(context.Context, string) error    { return nil }
func (w *rlUpdWriter) Commit(context.Context) error                      { return nil }
func (w *rlUpdWriter) Rollback(context.Context) error                    { return nil }

type rlRoleWtr struct{ parent *rlUpdRepo }

func (w *rlRoleWtr) Insert(_ context.Context, r domain.Role) (domain.Role, error) { return r, nil }
func (w *rlRoleWtr) Update(_ context.Context, r domain.Role, mask []string) (domain.Role, error) {
	for _, m := range mask {
		if m == "labels" {
			w.parent.updated = r.Labels
			w.parent.role.Labels = r.Labels
		}
	}
	return w.parent.role, nil
}
func (w *rlRoleWtr) UpdateCAS(ctx context.Context, r domain.Role, mask []string, _ string) (domain.Role, error) {
	return w.Update(ctx, r, mask)
}
func (w *rlRoleWtr) Delete(context.Context, domain.RoleID) error { return nil }
func (w *rlRoleWtr) ReplaceRuleSelectors(context.Context, domain.RoleID, []domain.RuleSelector) error {
	return nil
}

// ── fake ops repo (no-op; the worker runs via operations.Run + Wait) ─────────────

type rlFakeOps struct{}

func newRlFakeOps() *rlFakeOps { return &rlFakeOps{} }

func (o *rlFakeOps) Create(context.Context, operations.Operation) error { return nil }
func (o *rlFakeOps) CreateWithPrincipal(context.Context, operations.Operation, operations.Principal) error {
	return nil
}
func (o *rlFakeOps) Get(context.Context, string) (*operations.Operation, error) {
	return &operations.Operation{}, nil
}
func (o *rlFakeOps) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}
func (o *rlFakeOps) MarkDone(context.Context, string, *anypb.Any) error       { return nil }
func (o *rlFakeOps) MarkError(context.Context, string, *gstatus.Status) error { return nil }
func (o *rlFakeOps) Cancel(context.Context, string) error                     { return nil }
