// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// invite_inviter_principal_test.go — `users.invited_by` names the USER who
// invited, and only a user can be named there.
//
// The column is a foreign key into `users(id)` (migration 0001,
// `users_invited_by_fk`). The invitation flow stamped it from the caller's
// principal id with no regard for the principal's TYPE:
//
//	invitedBy := domain.UserID(principal.ID)
//
// A service-account caller therefore wrote `sva…` into a column that only ever
// holds `usr…`, and the insert died on the foreign key. The failure surfaced as
// an operation error carrying the UNMAPPED-FK fallback text ("referenced
// resource not found or still in use"), which names neither the column nor the
// cause — so the invitation looked like a missing account, project or role.
//
// Why this only became reachable recently: until service accounts were named by
// their real type in the authz model, a machine caller was refused at the
// permission gate and never reached the insert. Widening the gate moved the
// same wrong assumption one layer down, where it was no longer guarded. The
// type of the caller is decided in ONE place for the model
// (`authzguard.SubjectFromPrincipal`); this is the identity-stamping half of the
// same question.
//
// What is asserted here is the VALUE HANDED TO THE WRITER, not merely that the
// call succeeds: a test that only required "no error" would stay green against
// a fake writer that ignores the column, which is exactly how the defect
// survived. Both directions are covered — a human caller must still be
// recorded, or "never stamp anything" would pass the negative half and silently
// drop attribution for every real invitation.
//
// Attribution for machine callers is not lost: the Operation carries
// `principalType` / `principalId`, which is where a non-user actor belongs.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
	repoproject "github.com/PRO-Robotech/kaname/internal/repo/kaname/project"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/service_account"
	repouser "github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
	"github.com/PRO-Robotech/kaname/internal/service"
)

const (
	invPrincAccount = "acc0000000000000invp"
	invPrincEmail   = "invitee-principal@kacho.local"
)

// inviteStamped runs one invitation under the given principal and returns the
// `InvitedBy` the use-case handed to the user writer.
func inviteStamped(t *testing.T, p operations.Principal) domain.UserID {
	t.Helper()

	repo := &invPrincRepo{}
	ops := newFakeUsrOps()
	uc := NewInviteUserUseCase(repo, ops, invPrincAllowAll{})

	ctx := operations.WithPrincipal(context.Background(), p)
	op, err := uc.Execute(ctx, InviteUserInput{
		AccountID: domain.AccountID(invPrincAccount),
		Email:     domain.Email(invPrincEmail),
	})
	require.NoError(t, err, "the invitation itself must be accepted")
	require.NotNil(t, op)

	// The insert happens on the async continuation; wait for it deterministically.
	require.Eventually(t, func() bool {
		repo.mu.Lock()
		defer repo.mu.Unlock()
		return repo.inserted
	}, 5*time.Second, 10*time.Millisecond,
		"the invitation must reach the user writer")

	repo.mu.Lock()
	defer repo.mu.Unlock()
	return repo.gotInvitedBy
}

// A machine caller has no inviting USER, so nothing may be stamped: the column
// is a foreign key into users(id) and `sva…` is not a row there.
func TestInvite_ServiceAccountPrincipal_LeavesInvitedByUnset(t *testing.T) {
	got := inviteStamped(t, operations.Principal{
		Type: "service_account", ID: "sva0000000000000bot1",
	})
	assert.Empty(t, string(got),
		"users.invited_by is a FK into users(id); a service-account caller has no "+
			"inviting user, so the column must be left NULL rather than stamped "+
			"with the machine's own id (which the FK rejects)")
}

// Positive control: a human caller IS recorded. Without this, "never stamp
// anything" would satisfy the assertion above while quietly dropping the
// attribution the column exists for.
func TestInvite_UserPrincipal_StampsInvitedBy(t *testing.T) {
	const inviter = "usr0000000000000invp"
	got := inviteStamped(t, operations.Principal{Type: "user", ID: inviter})
	assert.Equal(t, inviter, string(got),
		"a human inviter must still be recorded in users.invited_by")
}

// ── fakes ───────────────────────────────────────────────────────────────────

type invPrincAllowAll struct{}

func (invPrincAllowAll) Check(context.Context, string, string, string) (bool, error) {
	return true, nil
}

type invPrincRepo struct {
	mu           sync.Mutex
	inserted     bool
	gotInvitedBy domain.UserID
	// emitted — строки журнала, со-коммиченные транзакцией приглашения.
	// Дублёр ОБЯЗАН их запоминать, а не глотать: подставной писатель,
	// принимающий больше настоящего, делает невидимым ровно тот дефект, ради
	// которого его подставляют — путь мог не эмитить ничего.
	emitted []service.RelationTuple
	// mailIntents — намерения отправить письмо приглашения, со-коммиченные ТОЙ
	// ЖЕ транзакцией. Запоминаются по той же причине, что и строки журнала выше:
	// путь мог не эмитить ничего, и дублёр, глотающий вызов, сделал бы это
	// невидимым.
	mailIntents []mailIntent
}

func (f *invPrincRepo) Reader(context.Context) (kanamerepo.Reader, error) {
	return &invPrincReader{}, nil
}
func (f *invPrincRepo) Writer(context.Context) (kanamerepo.Writer, error) {
	return &invPrincWriter{parent: f}, nil
}
func (f *invPrincRepo) Close() {}

type invPrincReader struct{}

func (r *invPrincReader) Accounts() account.ReaderIface                { return nil }
func (r *invPrincReader) Projects() repoproject.ReaderIface            { return nil }
func (r *invPrincReader) Users() repouser.ReaderIface                  { return invPrincUserRdr{} }
func (r *invPrincReader) ServiceAccounts() service_account.ReaderIface { return nil }
func (r *invPrincReader) Groups() group.ReaderIface                    { return nil }
func (r *invPrincReader) Roles() role.ReaderIface                      { return nil }
func (r *invPrincReader) AccessBindings() access_binding.ReaderIface   { return nil }
func (r *invPrincReader) Commit(context.Context) error                 { return nil }
func (r *invPrincReader) Rollback(context.Context) error               { return nil }

type invPrincUserRdr struct{}

func (invPrincUserRdr) Get(_ context.Context, id domain.UserID) (domain.User, error) {
	return domain.User{ID: id}, nil
}
func (invPrincUserRdr) GetByEmail(context.Context, domain.Email) (domain.User, error) {
	return domain.User{}, iamerr.ErrNotFound
}
func (invPrincUserRdr) List(context.Context, repouser.ListFilter) ([]domain.User, string, error) {
	return nil, "", nil
}
func (invPrincUserRdr) GetByAccountEmail(context.Context, domain.AccountID, domain.Email) (domain.User, error) {
	return domain.User{}, iamerr.ErrNotFound
}
func (invPrincUserRdr) FindPendingByEmail(context.Context, domain.Email) ([]domain.User, error) {
	return nil, nil
}
func (invPrincUserRdr) FindActiveByExternalID(context.Context, domain.ExternalSubject) ([]domain.User, error) {
	return nil, nil
}
func (invPrincUserRdr) FindByExternalIDInStatuses(context.Context, domain.ExternalSubject, []domain.InviteStatus) ([]domain.User, error) {
	return nil, nil
}
func (invPrincUserRdr) FindActiveByEmail(context.Context, domain.Email) ([]domain.User, error) {
	return nil, nil
}
func (invPrincUserRdr) ListAccountsForUser(context.Context, domain.UserID) ([]domain.AccountID, error) {
	return nil, nil
}

type invPrincWriter struct {
	invPrincReader
	parent *invPrincRepo
}

func (w *invPrincWriter) AccountsW() account.WriterIface     { return nil }
func (w *invPrincWriter) ProjectsW() repoproject.WriterIface { return nil }
func (w *invPrincWriter) UsersW() repouser.WriterIface {
	return &invPrincUserWtr{parent: w.parent}
}
func (w *invPrincWriter) ServiceAccountsW() service_account.WriterIface            { return nil }
func (w *invPrincWriter) GroupsW() group.WriterIface                               { return nil }
func (w *invPrincWriter) RolesW() role.WriterIface                                 { return nil }
func (w *invPrincWriter) AccessBindingsW() access_binding.WriterIface              { return nil }
func (w *invPrincWriter) EmitAuditEvent(context.Context, service.AuditEvent) error { return nil }
func (w *invPrincWriter) EmitFGARelationWrite(_ context.Context, tuples []service.RelationTuple) error {
	w.parent.mu.Lock()
	w.parent.emitted = append(w.parent.emitted, tuples...)
	w.parent.mu.Unlock()
	return nil
}
func (w *invPrincWriter) EmitFGARelationDelete(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *invPrincWriter) InsertRecoveryCompletion(context.Context, domain.RecoveryCompletion) (domain.RecoveryCompletion, bool, error) {
	return domain.RecoveryCompletion{}, false, nil
}
func (w *invPrincWriter) UpsertUserTokenRevokeAll(context.Context, domain.UserTokenRevocation, domain.UserID) error {
	return nil
}
func (w *invPrincWriter) AdvisoryXactLock(context.Context, string) error { return nil }
func (w *invPrincWriter) EmitReconcileEvent(context.Context, string, string, string) error {
	return nil
}

type invPrincUserWtr struct {
	invPrincUserRdr
	parent *invPrincRepo
}

// InsertPending is the observation point: it records the stamped value instead
// of asserting on a side effect the fake could not have.
func (w *invPrincUserWtr) InsertPending(_ context.Context, u domain.User) (domain.User, bool, error) {
	w.parent.mu.Lock()
	defer w.parent.mu.Unlock()
	w.parent.inserted = true
	w.parent.gotInvitedBy = u.InvitedBy
	return u, true, nil
}

func (w *invPrincUserWtr) Upsert(_ context.Context, u domain.User) (domain.User, bool, error) {
	return u, false, nil
}
func (w *invPrincUserWtr) ActivateInvite(_ context.Context, id domain.UserID, _ domain.ExternalSubject, _ domain.DisplayName) (domain.User, error) {
	return domain.User{ID: id}, nil
}
func (w *invPrincUserWtr) InsertActive(_ context.Context, u domain.User) (domain.User, error) {
	return u, nil
}
func (w *invPrincUserWtr) Delete(context.Context, domain.UserID) error { return nil }
func (w *invPrincUserWtr) UpdateLabels(_ context.Context, id domain.UserID, _ domain.Labels) (domain.User, error) {
	return domain.User{ID: id}, nil
}
func (w *invPrincUserWtr) SetInviteStatus(_ context.Context, id domain.UserID, _ domain.InviteStatus) (domain.User, error) {
	return domain.User{ID: id}, nil
}

// Visibility — дублёр структурных фактов о вызывающем не несёт: они читаются
// живой БД, и пробы, которые их проверяют, гоняют настоящий Postgres
// (services/iam/internal/apps/kaname/api/listvisibility). nil здесь означает
// «сузить нечем», и списочный use-case обязан на нём ОТКАЗАТЬ, а не листать
// ненаречённое.
func (r *invPrincReader) Visibility() visibility.ReaderIface { return nil }

// Visibility — дублёр структурных фактов о вызывающем не несёт: они читаются
// живой БД, и пробы, которые их проверяют, гоняют настоящий Postgres
// (services/iam/internal/apps/kaname/api/listvisibility). nil здесь означает
// «сузить нечем», и списочный use-case обязан на нём ОТКАЗАТЬ, а не листать
// ненаречённое.
func (r *invPrincWriter) Visibility() visibility.ReaderIface { return nil }

// MembershipExists — дублёр не отвечает на вопрос о членстве: предмет этой
// пробы другой, и подставной ответ был бы утверждением, которого никто не
// делал. Единственный прод-вызывающий — разрешение осиротевшей операции
// исключения из аккаунта (#1127).
func (invPrincUserRdr) MembershipExists(context.Context, domain.UserID, domain.AccountID) (bool, error) {
	return false, nil
}

// RemoveMembership — дублёр исключения из аккаунта не делает: предмет этой
// пробы другой. Снятие членства проверяется своими пробами (#1127).
func (*invPrincUserWtr) RemoveMembership(context.Context, domain.UserID, domain.AccountID) (bool, error) {
	return false, nil
}

// EmitInviteMail — порт со-коммита намерения отправить письмо приглашения.
// Дублёр не глотает того, что настоящий отвергает: пустой адресат и пустой ключ
// партиции отвергаются здесь так же, как ограничением миграции, — иначе фикстура
// была бы снисходительнее продукта и скрыла бы ровно тот дефект, ради которого её
// подставляют.
func (w *invPrincWriter) EmitInviteMail(_ context.Context, userID, accountID, to, _ string) error {
	if to == "" {
		return fmt.Errorf("invite mail: recipient required")
	}
	if userID == "" {
		return fmt.Errorf("invite mail: user id required")
	}
	w.parent.mu.Lock()
	defer w.parent.mu.Unlock()
	w.parent.mailIntents = append(w.parent.mailIntents,
		mailIntent{UserID: userID, AccountID: accountID, To: to})
	return nil
}

// mailIntent — со-коммиченное намерение отправить письмо, запомненное дублёром.
type mailIntent struct {
	UserID    string
	AccountID string
	To        string
}
