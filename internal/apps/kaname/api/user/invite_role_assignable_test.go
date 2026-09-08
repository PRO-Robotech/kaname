// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// invite_role_assignable_test.go — an invitation may not bind a role that belongs to
// another account.
//
// The invitation flow is the second writer of the access-binding table, and it wrote
// without asking the question the first writer asks: is this role assignable on this
// scope? The role identifier is supplied by the caller and stays valid for the life of
// the role, so anyone who ever saw one — a former member of the other account, for
// instance — could name it here.
//
// The access it gains is none: the binding's scope is the inviter's own project, so
// the role's verbs only ever materialise over the inviter's own objects. What it takes
// is the ROLE'S LIFECYCLE. The reference is restrict-on-delete, so the binding pins the
// role in the other account for ever; its owner is refused deletion, and the listing
// that would show them the cause filters that binding out because it sits in a scope
// they hold no authority over. A permanent refusal with no attributable cause.
//
// The refusal is enforced in the database for every writer (migration 0072). This test
// is about the other half: the caller must be told WHY, in the platform's tone, rather
// than meeting a constraint violation.

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/project"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/service_account"
	repouser "github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
)

const (
	inviterAccount = "acc0000000000000invA"
	foreignAccount = "acc0000000000000invB"
	inviteProject  = "prj0000000000000inv1"
	inviterUser    = "usr0000000000000invU"
)

// inviteRoleRepo — the reader the invitation gate needs: one project and one role.
type inviteRoleRepo struct{ role domain.Role }

func (f *inviteRoleRepo) Reader(context.Context) (kanamerepo.Reader, error) {
	return &inviteRoleReader{parent: f}, nil
}
func (f *inviteRoleRepo) Writer(context.Context) (kanamerepo.Writer, error) {
	return nil, stderrors.New("the gate must refuse before any writer is opened")
}
func (f *inviteRoleRepo) Close() {}

type inviteRoleReader struct{ parent *inviteRoleRepo }

func (r *inviteRoleReader) Accounts() account.ReaderIface                { return nil }
func (r *inviteRoleReader) Projects() project.ReaderIface                { return inviteProjectReader{} }
func (r *inviteRoleReader) Users() repouser.ReaderIface                  { return nil }
func (r *inviteRoleReader) ServiceAccounts() service_account.ReaderIface { return nil }
func (r *inviteRoleReader) Groups() group.ReaderIface                    { return nil }
func (r *inviteRoleReader) Roles() role.ReaderIface                      { return inviteRoleReaderRoles{parent: r.parent} }
func (r *inviteRoleReader) AccessBindings() access_binding.ReaderIface   { return nil }
func (r *inviteRoleReader) Commit(context.Context) error                 { return nil }
func (r *inviteRoleReader) Rollback(context.Context) error               { return nil }

type inviteProjectReader struct{}

func (inviteProjectReader) Get(_ context.Context, id domain.ProjectID) (domain.Project, error) {
	if string(id) != inviteProject {
		return domain.Project{}, iamerr.Wrapf(iamerr.ErrNotFound, "Project %s not found", id)
	}
	return domain.Project{ID: id, AccountID: inviterAccount, CreatedAt: time.Now().UTC()}, nil
}
func (inviteProjectReader) List(context.Context, project.ListFilter) ([]domain.Project, string, error) {
	return nil, "", nil
}
func (inviteProjectReader) ExistsByName(context.Context, domain.AccountID, domain.ProjectName) (bool, error) {
	return false, nil
}
func (inviteProjectReader) CountByAccount(context.Context, domain.AccountID) (int64, error) {
	return 0, nil
}

type inviteRoleReaderRoles struct{ parent *inviteRoleRepo }

func (r inviteRoleReaderRoles) Get(_ context.Context, id domain.RoleID) (domain.Role, error) {
	if r.parent.role.ID != id {
		return domain.Role{}, iamerr.Wrapf(iamerr.ErrNotFound, "Role %s not found", id)
	}
	return r.parent.role, nil
}
func (r inviteRoleReaderRoles) GetWithVersion(ctx context.Context, id domain.RoleID) (domain.Role, string, error) {
	got, err := r.Get(ctx, id)
	return got, "v1", err
}
func (inviteRoleReaderRoles) List(context.Context, role.ListFilter) ([]domain.Role, string, error) {
	return nil, "", nil
}
func (inviteRoleReaderRoles) ListAssignable(context.Context, string, string, role.ListFilter) ([]domain.Role, string, error) {
	return nil, "", nil
}
func (inviteRoleReaderRoles) ExistsByName(context.Context, domain.AccountID, domain.RoleName) (bool, error) {
	return false, nil
}

// allowChecker — the invitation permission gate says yes, so the role question is the
// only one left.
type allowChecker struct{}

func (allowChecker) Check(context.Context, string, string, string) (bool, error) {
	return true, nil
}

func inviteCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: inviterUser})
}

func inviteWith(r domain.Role) (*operations.Operation, error) {
	uc := NewInviteUserUseCase(&inviteRoleRepo{role: r}, nil, allowChecker{})
	return uc.Execute(inviteCtx(), InviteUserInput{
		AccountID: inviterAccount,
		Email:     "invitee@example.test",
		ProjectID: inviteProject,
		RoleID:    "irl0000000000000role",
	})
}

// A role defined by another account is refused — and refused the way a role that does
// not exist is refused, so the invitation cannot be used to find out which roles the
// other account has.
func TestInvite_ForeignAccountRole_IsRefusedAndIndistinguishableFromAbsent(t *testing.T) {
	_, err := inviteWith(domain.Role{
		ID: "irl0000000000000role", Name: "b_only", AccountID: foreignAccount,
	})
	require.Error(t, err, "an invitation must not bind a role of another account")
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "not found",
		"a foreign account's role must not be distinguishable from one that does not exist")
}

// Controls. They call the gate directly rather than the whole flow: past the gate the
// invitation opens a writer, and what is being asserted here is only that the gate
// does not refuse what it must not refuse — a boundary check that also rejects valid
// bindings would be found by an outage, not by a test.
func TestInvite_AssignableRoles_PassTheGate(t *testing.T) {
	for _, tc := range []struct {
		name string
		role domain.Role
	}{
		{"role of the inviter's own account", domain.Role{ID: "irl0000000000000role", Name: "own", AccountID: inviterAccount}},
		{"role of the invited project itself", domain.Role{ID: "irl0000000000000role", Name: "prj", ProjectID: inviteProject}},
		{"system role", domain.Role{ID: "irl0000000000000role", Name: "viewer", IsSystem: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uc := NewInviteUserUseCase(&inviteRoleRepo{role: tc.role}, nil, allowChecker{})
			err := uc.assertRoleAssignableOnProject(
				context.Background(), "irl0000000000000role", inviteProject, inviterAccount)
			require.NoError(t, err, "an assignable role must pass the gate")
		})
	}
}

// A role that does not exist at all is refused with the same text as a foreign one —
// which is what makes the two indistinguishable.
func TestInvite_AbsentRole_IsRefusedWithTheSameText(t *testing.T) {
	uc := NewInviteUserUseCase(&inviteRoleRepo{role: domain.Role{ID: "irl0000000000000othr"}}, nil, allowChecker{})
	err := uc.assertRoleAssignableOnProject(
		context.Background(), "irl0000000000000role", inviteProject, inviterAccount)
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "not found")
}

// Visibility — дублёр структурных фактов о вызывающем не несёт: они читаются
// живой БД, и пробы, которые их проверяют, гоняют настоящий Postgres
// (services/iam/internal/apps/kaname/api/listvisibility). nil здесь означает
// «сузить нечем», и списочный use-case обязан на нём ОТКАЗАТЬ, а не листать
// ненаречённое.
func (r *inviteRoleReader) Visibility() visibility.ReaderIface { return nil }

// UnresolvedSegments — см. довод у соседних дублёров: отказ, а не «всё в порядке».
// WithdrawnGrants — дублёр ОТКАЗЫВАЕТ, а не отвечает «отобранного нет»:
// заглушка, возвращающая пустое, была бы снисходительнее продукта. Ведомость
// в этих пробах не предмет, поэтому её путь исполняться не должен — а если
// исполнится, проба упадёт.
func (inviteRoleReaderRoles) WithdrawnGrants(context.Context, []domain.RoleID) (map[domain.RoleID][]domain.WithdrawnGrant, error) {
	return nil, stderrors.New("WithdrawnGrants не предмет этих проб")
}

// PrunedSelectorTypes — дублёр ОТКАЗЫВАЕТ по тому же доводу, что и сосед выше:
// заглушка, возвращающая пустое, была бы снисходительнее продукта и молча
// прятала бы лишний вопрос к ведомости.
func (inviteRoleReaderRoles) PrunedSelectorTypes(context.Context, []domain.RoleID) (map[domain.RoleID][]domain.PrunedSelectorType, error) {
	return nil, stderrors.New("PrunedSelectorTypes не предмет этих проб")
}

func (inviteRoleReaderRoles) UnresolvedSegments(context.Context, []domain.RoleSegment) (map[domain.RoleID][]domain.RoleSegment, error) {
	return nil, stderrors.New("UnresolvedSegments не предмет этих проб")
}

// Lifecycles — дублёр: жизненное состояние ролей этот путь не спрашивает.
// Пустая карта означает «не вычислено», и вызывающий оставляет нулевое
// состояние — ровно то, что дублёр обязан отдавать о величине, которой не
// владеет.
func (inviteRoleReaderRoles) Lifecycles(_ context.Context, _ []domain.RoleID) (
	map[domain.RoleID]domain.RoleLifecycle, error) {
	return nil, nil
}
