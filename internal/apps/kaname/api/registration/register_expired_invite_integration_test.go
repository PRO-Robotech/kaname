// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// register_expired_invite_integration_test.go — истёкшее приглашение держит
// адрес, пока не решит пригласивший (приёмка
// `docs/engineering/acceptance/expired-invitation-keeps-the-address-until-the-inviter-acts.md`,
// A198; задача PRO-Robotech/kaname#198).
//
// Сценарии A198-01…07: регистрация адресом истёкшего приглашения — единый
// отказ, и ничего не меняется; повторное приглашение (обоими глаголами потока,
// `UserService.Invite` и `MembershipService.Create`) продлевает срок одним
// правилом оператора вставки и освобождает регистрацию, но срок не укорачивает и
// выкупленной строки не трогает; снятие строки распорядителем освобождает
// регистрацию; распорядитель узнаёт об истечении от `ResendInvite`. Каждая проба
// утверждает и положительного близнеца, меняющего ровно один факт. Глаголы распорядителя — настоящие use-case'ы над настоящей
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

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/membership"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
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

// a198InviteTTL — срок посадки, под которым распорядитель приглашает в
// сценариях A198-02, -05, -06, -07 (§3 приёмки: 24 ч).
const a198InviteTTL = 24 * time.Hour

// invite — настоящий use-case обоих глаголов потока приглашения над настоящей
// базой: срок посадки 24 ч, окно писем не мешает сценарию.
func (s *a198Scene) invite() *user.InviteUserUseCase {
	return user.NewInviteUserUseCase(s.repo, s.ops, a198AllowAll{}).
		WithInviteTTL(a198InviteTTL).
		WithInviteMailRateLimit(a198MailLimit, nil)
}

// letters — намерений письма приглашения на строку в очереди.
func (s *a198Scene) letters(t *testing.T, id domain.UserID) int {
	t.Helper()
	var n int
	require.NoError(t, s.pool.QueryRow(s.ctx,
		`SELECT count(*) FROM kaname.invite_mail_outbox WHERE event_type = 'mail.invite.send' AND payload->>'user_id' = $1`,
		string(id)).Scan(&n))
	return n
}

// rowsOf — строк человека с этим адресом (вторая строка не заводится).
func (s *a198Scene) rowsOf(t *testing.T, email string) int {
	t.Helper()
	var n int
	require.NoError(t, s.pool.QueryRow(s.ctx, `SELECT count(*) FROM kaname.users WHERE lower(email) = lower($1)`, email).Scan(&n))
	return n
}

// reinvite — `UserService.Invite` распорядителя этим адресом в свой аккаунт;
// возвращает ответ операции и момент вызова (срок считается не раньше его).
func (s *a198Scene) reinvite(t *testing.T, email string) (*iamv1.User, time.Time) {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Microsecond)
	op, err := s.invite().Execute(s.pctx, user.InviteUserInput{AccountID: s.inviter.AccountID, Email: domain.Email(email)})
	require.NoError(t, err, "приглашение принято")
	done := s.await(t, op)
	require.Nil(t, done.Error, "Invite — Operation.done без ошибки: %v", done.Error)
	var u iamv1.User
	require.NoError(t, done.Response.UnmarshalTo(&u), "ответ операции — User")
	return &u, at
}

// TestA198_02_ReInvitingIntoTheSameAccountReleasesTheRegistration — A198-02;
// близнец — A198-01 (повторного приглашения нет — единый отказ, срок прежний).
func TestA198_02_ReInvitingIntoTheSameAccountReleasesTheRegistration(t *testing.T) {
	s := newA198Scene(t)
	uc := s.useCase(t, s.store)

	addr := "exp-b-" + freshEmail("a198-02")[4:]
	row := s.pending(t, addr, -time.Minute)
	require.Equal(t, "PENDING", s.inviteRow(t, row.ID).member, "ПРЕДПОСЫЛКА: человек уже состоит в аккаунте членством PENDING")
	lettersBefore := s.letters(t, row.ID)
	invitedBefore := s.obs.count(registration.OutcomeIssuedInvited)

	got, at := s.reinvite(t, addr)
	require.Equal(t, string(row.ID), got.GetId(), "A198-02: ответ операции — User прежней строки")

	after := s.inviteRow(t, row.ID)
	require.Equal(t, "PENDING", after.status, "A198-02: строка по-прежнему PENDING")
	require.False(t, after.deadline.Before(at.Add(a198InviteTTL)),
		"A198-02: срок продлён не раньше момента вызова + 24 ч: срок %s, вызов %s", after.deadline, at)
	require.Equal(t, 1, s.rowsOf(t, addr), "A198-02: вторая строка человека не заведена")
	require.Equal(t, lettersBefore+1, s.letters(t, row.ID), "A198-02: намерение письма приглашения на строку в очереди")

	out, err := s.register(t, uc, addr)
	require.NoError(t, err, "A198-02: после повторного приглашения регистрация проходит")
	require.True(t, out.Invited, "A198-02: регистрация ложится на строку приглашения")
	require.Equal(t, row.ID, out.View.User.ID, "A198-02: id прежний")
	require.Equal(t, invitedBefore+1, s.obs.count(registration.OutcomeIssuedInvited), "A198-02: клетка issued-invited")

	// Близнец (A198-01): повторного приглашения нет — единый отказ, срок прежний.
	twin := "exp-b-twin-" + freshEmail("a198-02b")[4:]
	twinRow := s.pending(t, twin, -time.Minute)
	twinBefore := s.inviteRow(t, twinRow.ID)
	_, err = s.register(t, uc, twin)
	require.ErrorIs(t, err, registration.ErrRefused, "A198-02 близнец: без повторного приглашения — единый отказ")
	require.True(t, twinBefore.deadline.Equal(s.inviteRow(t, twinRow.ID).deadline), "A198-02 близнец: срок прежний")
}

// TestA198_05_TheSecondVerbExtendsTheDeadlineTheSameWay — A198-05; близнец —
// A198-01 (без MembershipService.Create регистрация — единый отказ).
func TestA198_05_TheSecondVerbExtendsTheDeadlineTheSameWay(t *testing.T) {
	s := newA198Scene(t)
	uc := s.useCase(t, s.store)

	addr := "exp-e-" + freshEmail("a198-05")[4:]
	row := s.pending(t, addr, -time.Minute)
	var membershipID string
	require.NoError(t, s.pool.QueryRow(s.ctx, `SELECT id FROM kaname.memberships WHERE user_id = $1 AND account_id = $2 AND state = 'PENDING'`,
		string(row.ID), string(s.inviter.AccountID)).Scan(&membershipID), "ПРЕДПОСЫЛКА: членство PENDING")

	at := time.Now().UTC().Truncate(time.Microsecond)
	op, err := s.invite().CreateMembership(s.pctx, membership.CreateInput{AccountID: s.inviter.AccountID, Email: domain.Email(addr)})
	require.NoError(t, err, "A198-05: создание членства принято")
	done := s.await(t, op)
	require.Nil(t, done.Error, "A198-05: Operation.done без ошибки: %v", done.Error)
	var m iamv1.Membership
	require.NoError(t, done.Response.UnmarshalTo(&m), "A198-05: ответ — Membership")
	require.Equal(t, membershipID, m.GetId(), "A198-05: id прежнего членства")
	require.Equal(t, string(row.ID), m.GetUserId(), "A198-05: userId прежней строки")

	after := s.inviteRow(t, row.ID)
	require.False(t, after.deadline.Before(at.Add(a198InviteTTL)),
		"A198-05: срок продлён не раньше момента вызова + 24 ч: срок %s, вызов %s", after.deadline, at)

	out, err := s.register(t, uc, addr)
	require.NoError(t, err, "A198-05: регистрация проходит")
	require.True(t, out.Invited, "A198-05: регистрация ложится на строку приглашения")
	require.Equal(t, row.ID, out.View.User.ID)

	twin := "exp-e-twin-" + freshEmail("a198-05b")[4:]
	s.pending(t, twin, -time.Minute)
	_, err = s.register(t, uc, twin)
	require.ErrorIs(t, err, registration.ErrRefused, "A198-05 близнец: без MembershipService.Create — единый отказ")
}

// TestA198_06_ReInvitingNeverShortensTheDeadline — A198-06; близнец — A198-02
// (прежний срок истёк — продлён до «момент вызова + 24 ч»).
func TestA198_06_ReInvitingNeverShortensTheDeadline(t *testing.T) {
	s := newA198Scene(t)

	addr := "exp-f-" + freshEmail("a198-06")[4:]
	row := s.pending(t, addr, 30*24*time.Hour)
	before := s.inviteRow(t, row.ID)

	s.reinvite(t, addr)
	after := s.inviteRow(t, row.ID)
	require.True(t, before.deadline.Equal(after.deadline),
		"A198-06: срок побайтово прежний (через 30 суток), а не «сейчас + 24 ч»: было %s, стало %s", before.deadline, after.deadline)

	// Близнец: прежний срок истёк минуту назад — срок продлён.
	twin := "exp-f-twin-" + freshEmail("a198-06b")[4:]
	twinRow := s.pending(t, twin, -time.Minute)
	_, at := s.reinvite(t, twin)
	require.False(t, s.inviteRow(t, twinRow.ID).deadline.Before(at.Add(a198InviteTTL)), "A198-06 близнец: срок продлён")
}

// redeemed — выкупленное приглашение тем путём, которым его выкупает продукт:
// регистрация адресом живого приглашения кладёт способ входа на строку
// приглашения (строка остаётся PENDING), затем подтверждение адреса — отметка
// единственным её оператором и активация приглашения (`ActivateInvite`).
func (s *a198Scene) redeemed(t *testing.T, email string) domain.User {
	t.Helper()
	row := s.pending(t, email, a198InviteTTL)
	out, err := s.register(t, s.useCase(t, s.store), email)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): регистрация адресом живого приглашения")
	require.True(t, out.Invited, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): регистрация легла на строку приглашения")
	require.NoError(t, kanamepg.NewLoginMethodRepo(s.pool).MarkEmailVerified(s.ctx, row.ID, domain.Email(email), time.Now().UTC()),
		"НЕ-ВЫПОЛНИЛОСЬ(фикстура): отметка подтверждения адреса")
	w, err := s.repo.Writer(s.ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(s.ctx) }()
	_, err = w.UsersW().ActivateInvite(s.ctx, row.ID, domain.ExternalSubject("ext-"+string(row.ID)), "")
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): выкуп приглашения")
	require.NoError(t, w.Commit(s.ctx))
	return row
}

// TestA198_07_ReInvitingARedeemedRowChangesNothing — A198-07; близнец — A198-02
// (строка PENDING с истёкшим сроком: срок продлён, намерение письма прибавилось).
func TestA198_07_ReInvitingARedeemedRowChangesNothing(t *testing.T) {
	s := newA198Scene(t)

	addr := "exp-g-" + freshEmail("a198-07")[4:]
	row := s.redeemed(t, addr)
	before := s.inviteRow(t, row.ID)
	require.Equal(t, [2]string{"ACTIVE", "ACTIVE"}, [2]string{before.status, before.member},
		"ПРЕДПОСЫЛКА: строка и членство выкуплены")
	lettersBefore := s.letters(t, row.ID)

	got, _ := s.reinvite(t, addr)
	require.Equal(t, string(row.ID), got.GetId(), "A198-07: ответ — User прежней строки")
	require.Equal(t, iamv1.User_ACTIVE, got.GetInviteStatus(), "A198-07: inviteStatus = ACTIVE")
	after := s.inviteRow(t, row.ID)
	require.True(t, before.deadline.Equal(after.deadline), "A198-07: срок не изменился: было %s, стало %s", before.deadline, after.deadline)
	require.Equal(t, "ACTIVE", after.member, "A198-07: членство осталось ACTIVE")
	require.Equal(t, lettersBefore, s.letters(t, row.ID), "A198-07: намерения письма приглашения не прибавилось")

	// Близнец: строка PENDING с истёкшим сроком — срок продлён, письмо прибавилось.
	twin := "exp-g-twin-" + freshEmail("a198-07b")[4:]
	twinRow := s.pending(t, twin, -time.Minute)
	twinLetters := s.letters(t, twinRow.ID)
	_, at := s.reinvite(t, twin)
	require.False(t, s.inviteRow(t, twinRow.ID).deadline.Before(at.Add(a198InviteTTL)), "A198-07 близнец: срок продлён")
	require.Equal(t, twinLetters+1, s.letters(t, twinRow.ID), "A198-07 близнец: намерение письма прибавилось")
}
