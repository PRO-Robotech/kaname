// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// register_expired_invite_integration_test.go — истёкшее приглашение держит
// адрес, пока не решит пригласивший (приёмка
// `docs/engineering/acceptance/expired-invitation-keeps-the-address-until-the-inviter-acts.md`,
// A198; задача PRO-Robotech/kaname#198).
//
// Сценарии A198-01, A198-03, A198-04: регистрация адресом истёкшего приглашения —
// единый отказ, и ничего не меняется; снятие строки распорядителем освобождает
// регистрацию; распорядитель узнаёт об истечении от `ResendInvite`. Сценарий
// A198-02 (повторное приглашение в тот же аккаунт освобождает регистрацию) на
// дереве не выполняется: быстрый путь приглашения находит строку по членству и
// срока не продлевает, — его производитель есть правка прод-кода, которую
// приёмка не называет (её DoD п. 3), и он ведётся новой редакцией приёмки. Каждая проба утверждает и положительного близнеца, меняющего
// ровно один факт. Глаголы распорядителя — настоящие use-case'ы над настоящей
// базой и настоящим хранилищем операций; права на них решает модель на крае,
// поэтому дверь здесь — пропускающая.
package registration_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// a198AllowAll — дверь решения глаголов распорядителя: пропускает (вопрос прав
// — предмет края, а не этих сценариев).
type a198AllowAll struct{}

func (a198AllowAll) Check(context.Context, string, string, string) (bool, error) { return true, nil }

// a198MailLimit — окно писем приглашения, не мешающее сценариям.
var a198MailLimit = outboxtypes.InviteMailRateLimit{MaxPerWindow: 100, Window: time.Hour}

// a198Scene — стенд A198: распорядитель с аккаунтом и хранилище операций.
type a198Scene struct {
	*harness
	inviter domain.User
	ops     operations.Repo
	pctx    context.Context
}

func newA198Scene(t *testing.T) *a198Scene {
	t.Helper()
	h := newHarness(t)
	inviter := seedActiveUserWithAccount(t, h, freshEmail("a198-inviter"))
	return &a198Scene{
		harness: h, inviter: inviter, ops: operations.NewRepo(h.pool, "kaname"),
		pctx: operations.WithPrincipal(h.ctx, operations.Principal{Type: "user", ID: string(inviter.ID)}),
	}
}

// pending — строка приглашения существующим глаголом хранилища со сроком ttl
// от сейчас (отрицательный — истёкшая).
func (s *a198Scene) pending(t *testing.T, email string, ttl time.Duration) domain.User {
	t.Helper()
	w, err := s.repo.Writer(s.ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(s.ctx) }()
	row, _, err := w.UsersW().InsertPending(s.ctx, domain.User{
		ID: domain.UserID(ids.NewID(domain.PrefixUser)), AccountID: s.inviter.AccountID,
		Email: domain.Email(email), DisplayName: "Invited", InviteStatus: domain.InviteStatusPending,
		InvitedBy: s.inviter.ID,
	}, time.Now().UTC().Add(ttl))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): строка приглашения")
	require.NoError(t, w.Commit(s.ctx))
	return row
}

// await — исход операции распорядителя.
func (s *a198Scene) await(t *testing.T, op *operations.Operation) *operations.Operation {
	t.Helper()
	require.NotNil(t, op)
	var done *operations.Operation
	require.Eventually(t, func() bool {
		got, err := s.ops.Get(s.ctx, op.ID)
		if err != nil || !got.Done {
			return false
		}
		done = got
		return true
	}, 10*time.Second, 20*time.Millisecond, "операция %s обязана завершиться", op.ID)
	return done
}

// inviteRow — состояние строки приглашения.
type inviteRow struct {
	status   string
	deadline time.Time
	methods  int
	sessions int
	accounts int
	member   string
}

func (s *a198Scene) inviteRow(t *testing.T, id domain.UserID) inviteRow {
	t.Helper()
	var r inviteRow
	require.NoError(t, s.pool.QueryRow(s.ctx, `SELECT invite_status, invite_expires_at FROM kaname.users WHERE id = $1`, string(id)).
		Scan(&r.status, &r.deadline))
	require.NoError(t, s.pool.QueryRow(s.ctx, `SELECT count(*) FROM kaname.user_login_methods WHERE user_id = $1`, string(id)).Scan(&r.methods))
	require.NoError(t, s.pool.QueryRow(s.ctx, `SELECT count(*) FROM kaname.human_sessions WHERE user_id = $1`, string(id)).Scan(&r.sessions))
	require.NoError(t, s.pool.QueryRow(s.ctx, `SELECT count(*) FROM kaname.accounts WHERE owner_user_id = $1`, string(id)).Scan(&r.accounts))
	if err := s.pool.QueryRow(s.ctx, `SELECT state FROM kaname.memberships WHERE user_id = $1 AND account_id = $2`,
		string(id), string(s.inviter.AccountID)).Scan(&r.member); err != nil {
		r.member = "<none>"
	}
	return r
}

// otherRefusals — сумма клеток отказа счётчика исходов, кроме названной.
func (s *a198Scene) otherRefusals(except registration.Outcome) int {
	n := 0
	for _, x := range registration.Outcomes() {
		if x == except || x == registration.OutcomeIssued || x == registration.OutcomeIssuedInvited {
			continue
		}
		n += s.obs.count(x)
	}
	return n
}

// TestA198_01_ExpiredInviteAddressIsTheOneRefusalAndNothingChanges — A198-01 и
// близнец (срок через сутки).
func TestA198_01_ExpiredInviteAddressIsTheOneRefusalAndNothingChanges(t *testing.T) {
	s := newA198Scene(t)
	uc := s.useCase(t, s.store)

	// Эталон текста — отказ занятого адреса (Ф4-11).
	occupied := freshEmail("a198-01-occ")
	_, err := s.register(t, uc, occupied)
	require.NoError(t, err)
	_, errOccupied := s.register(t, uc, occupied)
	require.ErrorIs(t, errOccupied, registration.ErrRefused)
	occupiedCells := s.obs.count(registration.OutcomeRefusedOccupied)

	addr := "exp-a-" + freshEmail("a198-01")[4:]
	row := s.pending(t, addr, -time.Minute)
	before := s.inviteRow(t, row.ID)

	_, err = s.register(t, uc, strings.ToUpper(addr[:5])+addr[5:])
	require.ErrorIs(t, err, registration.ErrRefused, "A198-01: регистрация адресом истёкшего приглашения — единый отказ")
	require.Equal(t, registration.TextRegistrationRefused, err.Error(), "A198-01: текст")
	require.Equal(t, errOccupied.Error(), err.Error(), "A198-01: побайтово равен отказу занятого адреса")

	after := s.inviteRow(t, row.ID)
	require.Equal(t, "PENDING", after.status, "A198-01: строка осталась приглашением")
	require.True(t, before.deadline.Equal(after.deadline), "A198-01: срок не изменился: было %s, стало %s", before.deadline, after.deadline)
	require.Equal(t, [3]int{0, 0, 0}, [3]int{after.methods, after.sessions, after.accounts},
		"A198-01: способов входа, сессий и аккаунтов на строке 0")
	require.NotEqual(t, "ACTIVE", after.member, "A198-01: членство в аккаунте пригласившего не активно")
	require.Equal(t, 1, s.obs.count(registration.OutcomeRefusedInviteExpired), "A198-01: клетка refused-invite-expired")
	require.Equal(t, occupiedCells, s.obs.count(registration.OutcomeRefusedOccupied), "A198-01: прочие клетки отказа не тронуты")
	require.Equal(t, 0, s.otherRefusals(registration.OutcomeRefusedInviteExpired)-occupiedCells, "A198-01: прочие клетки отказа — 0")

	// Близнец: срок через сутки — регистрация ложится на строку приглашения.
	liveAddr := "exp-a-live-" + freshEmail("a198-01b")[4:]
	live := s.pending(t, liveAddr, 24*time.Hour)
	out, err := s.register(t, uc, liveAddr)
	require.NoError(t, err, "A198-01 близнец: живое приглашение")
	require.True(t, out.Invited, "A198-01 близнец: Invited = true")
	require.Equal(t, live.ID, out.View.User.ID)
}

// TestA198_03_RemovingTheRowReleasesTheRegistration — A198-03 и близнец (на
// строку ссылается привязка доступа).
func TestA198_03_RemovingTheRowReleasesTheRegistration(t *testing.T) {
	s := newA198Scene(t)
	uc := s.useCase(t, s.store)
	del := user.NewDeleteUserUseCase(s.repo, s.ops)
	issuedBefore := s.obs.count(registration.OutcomeIssued)

	addr := "exp-c-" + freshEmail("a198-03")[4:]
	row := s.pending(t, addr, -time.Minute)
	op, err := del.Execute(s.pctx, row.ID)
	require.NoError(t, err, "A198-03: снятие строки принято")
	done := s.await(t, op)
	require.Nil(t, done.Error, "A198-03: Delete — Operation.done без ошибки: %v", done.Error)

	out, err := s.register(t, uc, addr)
	require.NoError(t, err, "A198-03: после снятия строки регистрация проходит")
	require.False(t, out.Invited)
	require.NotEqual(t, row.ID, out.View.User.ID, "A198-03: новый человек, id не равен снятому")
	s.assertAllThree(t, addr, out)
	require.Equal(t, issuedBefore+1, s.obs.count(registration.OutcomeIssued), "A198-03: клетка issued")

	// Близнец: на строку ссылается привязка доступа — снятие отказано, строка
	// остаётся, регистрация — единый отказ.
	twinAddr := "exp-c-bound-" + freshEmail("a198-03b")[4:]
	bound := s.pending(t, twinAddr, -time.Minute)
	var project string
	require.NoError(t, s.pool.QueryRow(s.ctx, `SELECT id FROM kaname.projects WHERE account_id = $1 LIMIT 1`, string(s.inviter.AccountID)).Scan(&project))
	w, err := s.repo.Writer(s.ctx)
	require.NoError(t, err)
	ab, err := w.AccessBindingsW().Insert(s.ctx, domain.AccessBinding{
		ID: domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)), SubjectType: domain.SubjectTypeUser,
		SubjectID: domain.SubjectID(bound.ID), RoleID: domain.RoleID(domain.ClusterAdminRoleID),
		ResourceType: domain.ResourceType("project"), ResourceID: project, Target: domain.AccessTarget{AllInScope: true},
	})
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): привязка доступа")
	require.NoError(t, w.AccessBindingsW().InsertSubjects(s.ctx, ab.ID, []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(bound.ID)}}))
	require.NoError(t, w.Commit(s.ctx))

	op, err = del.Execute(s.pctx, bound.ID)
	require.NoError(t, err)
	done = s.await(t, op)
	require.NotNil(t, done.Error, "A198-03 близнец: снятие строки с привязкой обязано быть отказано")
	require.Equal(t, int32(codes.FailedPrecondition), done.Error.Code, "A198-03 близнец: FAILED_PRECONDITION")
	require.Contains(t, done.Error.Message, "has active access bindings and cannot be deleted", "A198-03 близнец: текст")
	require.Equal(t, "PENDING", s.inviteRow(t, bound.ID).status, "A198-03 близнец: строка осталась")
	_, err = s.register(t, uc, twinAddr)
	require.ErrorIs(t, err, registration.ErrRefused, "A198-03 близнец: регистрация — единый отказ")
}

// TestA198_04_TheInviterLearnsOfTheExpiry — A198-04 и близнец (срок через сутки).
func TestA198_04_TheInviterLearnsOfTheExpiry(t *testing.T) {
	s := newA198Scene(t)
	resend := user.NewResendInviteUseCase(s.repo, s.ops, a198AllowAll{}, a198MailLimit, nil)
	letters := func(id domain.UserID) int {
		var n int
		require.NoError(t, s.pool.QueryRow(s.ctx,
			`SELECT count(*) FROM kaname.invite_mail_outbox WHERE event_type = 'mail.invite.send' AND payload->>'user_id' = $1`, string(id)).Scan(&n))
		return n
	}

	expired := s.pending(t, "exp-d-"+freshEmail("a198-04")[4:], -time.Minute)
	op, err := resend.Execute(s.pctx, expired.ID, s.inviter.AccountID)
	require.Nil(t, op, "A198-04: операции нет — отказ синхронный")
	st, ok := status.FromError(err)
	require.True(t, ok, "A198-04: отказ — статус gRPC: %v", err)
	require.Equal(t, codes.FailedPrecondition, st.Code(), "A198-04: FAILED_PRECONDITION")
	require.Equal(t, "invitation of User "+string(expired.ID)+" has expired — invite again to issue a new one", st.Message(), "A198-04: текст")
	require.Zero(t, letters(expired.ID), "A198-04: письма в очередь не поставлено")

	live := s.pending(t, "exp-d-live-"+freshEmail("a198-04b")[4:], 24*time.Hour)
	queuedBefore := letters(live.ID)
	op, err = resend.Execute(s.pctx, live.ID, s.inviter.AccountID)
	require.NoError(t, err, "A198-04 близнец: живая строка — Operation")
	done := s.await(t, op)
	require.Nil(t, done.Error, "A198-04 близнец: done без ошибки: %v", done.Error)
	require.Equal(t, queuedBefore+1, letters(live.ID), "A198-04 близнец: намерение письма приглашения стоит в очереди")
}
