// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"errors"
	stderrors "errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/project"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/service_account"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
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
	uc := &UpdateRoleUseCase{cat: catalogfixture.Source()} // nil deps: mask-discipline is a sync pre-check
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
	uc := &UpdateRoleUseCase{cat: catalogfixture.Source()}
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
	uc := NewUpdateRoleUseCase(repo, newRlFakeOps(), catalogfixture.Source())

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
	uc := NewUpdateRoleUseCase(repo, newRlFakeOps(), catalogfixture.Source())

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
	// reconcilAll — ПОЛНАЯ тройка каждого со-коммитнутого события реконсайла
	// («вид|тип|идентификатор»). Заведена рядом с `reconcil`, а не вместо неё:
	// прежние пробы спрашивают про идентификатор на `iam.role`, а проба
	// симметрии снятия (kacho#2055) — про ВИД события, и вид отбрасывался.
	// Дублёр, отбрасывающий то, о чём спрашивают, делает невидимым ровно тот
	// путь, ради которого его ставят.
	reconcilAll []string
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
func (r *rlUpdRepo) Reader(context.Context) (kanamerepo.Reader, error) {
	return &rlUpdReader{parent: r}, nil
}
func (r *rlUpdRepo) Writer(context.Context) (kanamerepo.Writer, error) {
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
func (w *rlUpdWriter) EmitReconcileEvent(_ context.Context, eventType, objectType, objectID string) error {
	w.parent.reconcilAll = append(w.parent.reconcilAll,
		fmt.Sprintf("%s|%s|%s", eventType, objectType, objectID))
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
func (w *rlUpdWriter) AdvisoryXactLock(context.Context, string) error { return nil }
func (w *rlUpdWriter) Commit(context.Context) error                   { return nil }
func (w *rlUpdWriter) Rollback(context.Context) error                 { return nil }

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

// ReplaceRoleVerbs — дублёр умеет то же, что настоящий писатель: проекция
// глаголов пишется рядом с селекторами. Дублёр, не умеющий метода, делает
// невидимым ровно тот путь, ради которого его ставят.
func (w *rlRoleWtr) ReplaceRoleVerbs(context.Context, domain.RoleID, []domain.RoleVerb) error {
	return nil
}

// ReplaceRuleRefs — ТРЕТЬЯ сторона того же правила (kacho#1030). Дублёр умеет и
// её по тому же доводу: не умеющий делает невидимым путь, ради которого стоит.
// UpsertSystemRole — писатель СИСТЕМНОЙ строки. Дублёр её не производит: путь
// этих проб к кластерному ярусу не ведёт, и молча вернуть «записано» значило бы
// сделать дублёра снисходительнее продукта.
func (w *rlRoleWtr) UpsertSystemRole(context.Context, domain.Role) (domain.Role, bool, error) {
	return domain.Role{}, false, errors.New("дублёр системную роль не пишет")
}

func (w *rlRoleWtr) ReplaceRuleRefs(context.Context, domain.RoleID, []domain.RoleRuleRef) error {
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

// Visibility — дублёр структурных фактов о вызывающем не несёт: они читаются
// живой БД, и пробы, которые их проверяют, гоняют настоящий Postgres
// (services/iam/internal/apps/kaname/api/listvisibility). nil здесь означает
// «сузить нечем», и списочный use-case обязан на нём ОТКАЗАТЬ, а не листать
// ненаречённое.
func (r *rlUpdReader) Visibility() visibility.ReaderIface { return nil }

// Visibility — дублёр структурных фактов о вызывающем не несёт: они читаются
// живой БД, и пробы, которые их проверяют, гоняют настоящий Postgres
// (services/iam/internal/apps/kaname/api/listvisibility). nil здесь означает
// «сузить нечем», и списочный use-case обязан на нём ОТКАЗАТЬ, а не листать
// ненаречённое.
func (r *rlUpdWriter) Visibility() visibility.ReaderIface { return nil }

// EmitInviteMail — порт со-коммита намерения отправить письмо приглашения.
// Дублёр не глотает того, что настоящий отвергает: пустой адресат и пустой ключ
// партиции отвергаются здесь так же, как ограничением миграции, — иначе фикстура
// была бы снисходительнее продукта и скрыла бы ровно тот дефект, ради которого её
// подставляют.
func (w *rlUpdWriter) EmitInviteMail(_ context.Context, userID, _, to, _ string) error {
	if to == "" {
		return fmt.Errorf("invite mail: recipient required")
	}
	if userID == "" {
		return fmt.Errorf("invite mail: user id required")
	}
	return nil
}

// UnresolvedSegments — дублёр ОТКАЗЫВАЕТ, а не отвечает «неразрешённых нет»:
// заглушка, возвращающая пустое, была бы снисходительнее продукта и молча
// зеленила бы утверждения о деградации роли. Целость в этих пробах не предмет,
// поэтому её путь здесь исполняться не должен — а если исполнится, проба упадёт.
func (r *rlRoleRdr) UnresolvedSegments(context.Context, []domain.RoleSegment) (map[domain.RoleID][]domain.RoleSegment, error) {
	return nil, stderrors.New("UnresolvedSegments не предмет этих проб")
}

// WithdrawnGrants — дублёр ОТКАЗЫВАЕТ, а не отвечает «отобранного нет»:
// заглушка, возвращающая пустое, была бы снисходительнее продукта. Ведомость
// в этих пробах не предмет, поэтому её путь исполняться не должен — а если
// исполнится, проба упадёт.
func (r *rlRoleRdr) WithdrawnGrants(context.Context, []domain.RoleID) (map[domain.RoleID][]domain.WithdrawnGrant, error) {
	return nil, stderrors.New("WithdrawnGrants не предмет этих проб")
}

// PrunedSelectorTypes — дублёр ОТКАЗЫВАЕТ по тому же доводу, что и сосед выше:
// заглушка, возвращающая пустое, была бы снисходительнее продукта и молча
// прятала бы лишний вопрос к ведомости.
func (r *rlRoleRdr) PrunedSelectorTypes(context.Context, []domain.RoleID) (map[domain.RoleID][]domain.PrunedSelectorType, error) {
	return nil, stderrors.New("PrunedSelectorTypes не предмет этих проб")
}

// Lifecycles — дублёр: жизненное состояние ролей этот путь не спрашивает.
// Пустая карта означает «не вычислено», и вызывающий оставляет нулевое
// состояние — ровно то, что дублёр обязан отдавать о величине, которой не
// владеет.
func (*rlRoleRdr) Lifecycles(_ context.Context, _ []domain.RoleID) (
	map[domain.RoleID]domain.RoleLifecycle, error) {
	return nil, nil
}

// LiveSystemRoles / RetireRole / ReviveRole — дублёр: отзыв роли этот путь не
// исполняет. Отдаётся пустое, а не правдоподобное: дублёр, отвечающий «снял»,
// сделал бы невидимым ровно тот дефект, ради которого его подставляют.
func (*rlRoleWtr) LiveSystemRoles(_ context.Context) ([]domain.Role, error) { return nil, nil }

func (*rlRoleWtr) RetireRole(_ context.Context, _ domain.RoleID, _, _, _ string) (
	domain.RoleRetirement, error) {
	return domain.RoleRetirement{}, nil
}

func (*rlRoleWtr) ReviveRole(_ context.Context, _ domain.RoleID) (bool, error) { return false, nil }
