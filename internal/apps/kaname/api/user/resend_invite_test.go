// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// resend_invite_test.go — глагол повторной отправки письма приглашения
// (приёмка ID-MAIL-1, §10 п. 9; MAIL-38, MAIL-25, MAIL-42; задача продукта
// #1774).
//
// Что утверждается, и каждое отрицание — в паре с положительным контролем:
//   - PENDING-приглашение в названном аккаунте → письмо ставится в очередь, и
//     операция завершается успехом с ответом-строкой;
//   - сверх нормы письмо НЕ ставится, а операция завершается ТЕМ ЖЕ исходом
//     (Р9: отказ по частоте не оракул); различие видно только счётчику;
//   - человека нет в названном аккаунте (строка есть в другом) → NOT_FOUND тем
//     же текстом, что и для несуществующего: hide-existence;
//   - приглашение выкуплено (ACTIVE) либо человек заблокирован → FAILED_PRECONDITION;
//   - срок истёк → FAILED_PRECONDITION, и текст называет следующий шаг —
//     пригласить заново;
//   - формат идентификаторов — синхронно, до операции;
//   - аноним отвергается до всего.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	repouser "github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
)

const (
	resendUserID  = "usr0000000000000rsnd"
	resendAccount = "acc0000000000000rsnd"
	resendEmail   = "resend@example.com"
)

// resendRepo — дублёр: одна строка человека и факт членства в аккаунте.
type resendRepo struct {
	invPrincRepo
	row       domain.User
	inAccount bool
}

func (f *resendRepo) Reader(context.Context) (kanamerepo.Reader, error) {
	return &resendReader{row: f.row, inAccount: f.inAccount}, nil
}

func (f *resendRepo) Writer(context.Context) (kanamerepo.Writer, error) {
	return &invPrincWriter{parent: &f.invPrincRepo}, nil
}

type resendReader struct {
	invPrincReader
	row       domain.User
	inAccount bool
}

func (r *resendReader) Users() repouser.ReaderIface {
	return resendUserRdr{row: r.row, inAccount: r.inAccount}
}

type resendUserRdr struct {
	invPrincUserRdr
	row       domain.User
	inAccount bool
}

func (r resendUserRdr) Get(_ context.Context, id domain.UserID) (domain.User, error) {
	if id != r.row.ID {
		return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", id)
	}
	return r.row, nil
}

func (r resendUserRdr) MembershipExists(_ context.Context, id domain.UserID, _ domain.AccountID) (bool, error) {
	return id == r.row.ID && r.inAccount, nil
}

func pendingRow(expires time.Time) domain.User {
	return domain.User{
		ID:              domain.UserID(resendUserID),
		AccountID:       domain.AccountID(resendAccount),
		Email:           domain.Email(resendEmail),
		DisplayName:     "Resend",
		InviteStatus:    domain.InviteStatusPending,
		InviteExpiresAt: expires,
	}
}

func resendCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr0000000000000invm"})
}

func awaitDone(t *testing.T, ops *fakeUsrOps, id string) *operations.Operation {
	t.Helper()
	require.Eventually(t, func() bool {
		got, gerr := ops.Get(context.Background(), id)
		return gerr == nil && got.Done
	}, 5*time.Second, 10*time.Millisecond, "асинхронное продолжение обязано завершиться")
	done, err := ops.Get(context.Background(), id)
	require.NoError(t, err)
	return done
}

func TestResendInvite_PendingRowQueuesTheLetter(t *testing.T) {
	repo := &resendRepo{row: pendingRow(time.Now().Add(time.Hour)), inAccount: true}
	ops := newFakeUsrOps()
	obs := &countingMailIntentObserver{}
	uc := NewResendInviteUseCase(repo, ops, invPrincAllowAll{},
		outboxtypes.InviteMailRateLimit{MaxPerWindow: 3, Window: time.Hour}, obs)

	op, err := uc.Execute(resendCtx(), domain.UserID(resendUserID), domain.AccountID(resendAccount))
	require.NoError(t, err)
	done := awaitDone(t, ops, op.ID)
	require.Nil(t, done.Error, "повторная отправка PENDING-приглашения отказала: %v", done.Error)
	require.NotNil(t, done.Response, "операция завершилась без ответа-строки")

	var md iamv1.ResendInviteMetadata
	require.NoError(t, done.Metadata.UnmarshalTo(&md))
	assert.Equal(t, resendUserID, md.GetUserId())
	assert.Equal(t, resendAccount, md.GetAccountId())

	repo.mu.Lock()
	defer repo.mu.Unlock()
	require.Len(t, repo.mailIntents, 1, "повторная отправка обязана оставить ровно одно намерение")
	assert.Equal(t, resendEmail, repo.mailIntents[0].To)
	assert.Equal(t, resendAccount, repo.mailIntents[0].AccountID)
	assert.Equal(t, resendUserID, repo.mailIntents[0].UserID)
	assert.Equal(t, 1, obs.queued)
}

// MAIL-25/MAIL-42: сверх нормы письмо не ставится, а ответ тот же. Норма
// берётся из объявления (здесь — из значения, переданного композиционным
// корнем), а не выписана в пробе.
func TestResendInvite_OverTheCapAnswersTheSameAndSendsNothing(t *testing.T) {
	repo := &resendRepo{row: pendingRow(time.Time{}), inAccount: true}
	ops := newFakeUsrOps()
	obs := &countingMailIntentObserver{}
	limit := outboxtypes.InviteMailRateLimit{MaxPerWindow: 2, Window: time.Hour}
	uc := NewResendInviteUseCase(repo, ops, invPrincAllowAll{}, limit, obs)

	var outcomes []*operations.Operation
	for i := 0; i < limit.MaxPerWindow+2; i++ {
		op, err := uc.Execute(resendCtx(), domain.UserID(resendUserID), domain.AccountID(resendAccount))
		require.NoError(t, err, "вызов %d: сверхнормативная повторная отправка отвергнута синхронно — "+
			"отказ по частоте стал оракулом", i+1)
		outcomes = append(outcomes, awaitDone(t, ops, op.ID))
	}
	for i, o := range outcomes {
		assert.Nil(t, o.Error, "вызов %d: сверхнормативная операция завершилась ошибкой — исход отличим", i+1)
		assert.NotNil(t, o.Response, "вызов %d: ответ отличается от ответа в норме", i+1)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	assert.Len(t, repo.mailIntents, limit.MaxPerWindow,
		"при норме %d писем на адрес поставлено %d", limit.MaxPerWindow, len(repo.mailIntents))
	assert.Equal(t, limit.MaxPerWindow, obs.queued)
	assert.Equal(t, 2, obs.rateLimited, "сверхнормативные обязаны быть видны оператору клеткой rate_limited")
}

// Hide-existence: строка есть, но НЕ в названном аккаунте — тот же текст, что и
// для строки, которой нет нигде.
func TestResendInvite_RowOutsideTheAccountIsNotFoundByTheSameText(t *testing.T) {
	inOther := &resendRepo{row: pendingRow(time.Time{}), inAccount: false}
	nowhere := &resendRepo{row: domain.User{ID: "usr0000000000000othr"}, inAccount: false}
	limit := outboxtypes.InviteMailRateLimit{MaxPerWindow: 3, Window: time.Hour}

	_, errOther := NewResendInviteUseCase(inOther, newFakeUsrOps(), invPrincAllowAll{}, limit, nil).
		Execute(resendCtx(), domain.UserID(resendUserID), domain.AccountID(resendAccount))
	_, errNowhere := NewResendInviteUseCase(nowhere, newFakeUsrOps(), invPrincAllowAll{}, limit, nil).
		Execute(resendCtx(), domain.UserID(resendUserID), domain.AccountID(resendAccount))

	require.Error(t, errOther)
	require.Error(t, errNowhere)
	require.Equal(t, codes.NotFound, status.Code(errOther), "строка чужого аккаунта отвечена не NOT_FOUND: %v", errOther)
	require.Equal(t, codes.NotFound, status.Code(errNowhere))
	require.Equal(t, status.Convert(errNowhere).Message(), status.Convert(errOther).Message(),
		"тексты отказов различимы — оракул существования строки в чужом аккаунте")
	require.Contains(t, status.Convert(errOther).Message(), resendUserID, "отказ не называет запрошенный идентификатор")
	for _, r := range []*resendRepo{inOther, nowhere} {
		r.mu.Lock()
		assert.Empty(t, r.mailIntents, "письмо ушло по чужой строке")
		r.mu.Unlock()
	}
}

func TestResendInvite_RedeemedOrBlockedIsAFailedPrecondition(t *testing.T) {
	limit := outboxtypes.InviteMailRateLimit{MaxPerWindow: 3, Window: time.Hour}
	for _, st := range []domain.InviteStatus{domain.InviteStatusActive, domain.InviteStatusBlocked} {
		row := pendingRow(time.Time{})
		row.InviteStatus = st
		row.ExternalID = "sub-redeemed"
		repo := &resendRepo{row: row, inAccount: true}
		_, err := NewResendInviteUseCase(repo, newFakeUsrOps(), invPrincAllowAll{}, limit, nil).
			Execute(resendCtx(), domain.UserID(resendUserID), domain.AccountID(resendAccount))
		require.Error(t, err, "%s: письмо о приглашении, которое нечего выкупать, принято", st)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err), "%s: %v", st, err)
		assert.Contains(t, status.Convert(err).Message(), resendUserID)
		repo.mu.Lock()
		assert.Empty(t, repo.mailIntents)
		repo.mu.Unlock()
	}
}

// MAIL-23 в тоне: истёкшее приглашение не пересылается — срок есть свойство
// выдачи; отказ называет следующий шаг.
func TestResendInvite_ExpiredNamesTheNextStep(t *testing.T) {
	repo := &resendRepo{row: pendingRow(time.Now().Add(-time.Minute)), inAccount: true}
	limit := outboxtypes.InviteMailRateLimit{MaxPerWindow: 3, Window: time.Hour}
	_, err := NewResendInviteUseCase(repo, newFakeUsrOps(), invPrincAllowAll{}, limit, nil).
		Execute(resendCtx(), domain.UserID(resendUserID), domain.AccountID(resendAccount))
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "%v", err)
	msg := status.Convert(err).Message()
	assert.Contains(t, msg, "expired")
	assert.Contains(t, strings.ToLower(msg), "invite again", "отказ не называет следующий шаг")
	repo.mu.Lock()
	assert.Empty(t, repo.mailIntents)
	repo.mu.Unlock()
}

func TestResendInvite_MalformedIDsAndAnonymousAreRefusedSynchronously(t *testing.T) {
	repo := &resendRepo{row: pendingRow(time.Time{}), inAccount: true}
	ops := newFakeUsrOps()
	limit := outboxtypes.InviteMailRateLimit{MaxPerWindow: 3, Window: time.Hour}
	uc := NewResendInviteUseCase(repo, ops, invPrincAllowAll{}, limit, nil)

	_, err := uc.Execute(resendCtx(), domain.UserID("garbage"), domain.AccountID(resendAccount))
	require.Equal(t, codes.InvalidArgument, status.Code(err), "мусорный user_id: %v", err)
	_, err = uc.Execute(resendCtx(), domain.UserID(resendUserID), domain.AccountID("garbage"))
	require.Equal(t, codes.InvalidArgument, status.Code(err), "мусорный account_id: %v", err)
	// Аноним — тем же отказом, что у соседа RemoveFromAccount
	// (authzguard.RequireAuthenticated): PermissionDenied, а не отдельный код.
	_, err = uc.Execute(context.Background(), domain.UserID(resendUserID), domain.AccountID(resendAccount))
	require.Equal(t, codes.PermissionDenied, status.Code(err), "аноним: %v", err)

	ops.mu.Lock()
	assert.Empty(t, ops.ops, "синхронный отказ не заводит операции")
	ops.mu.Unlock()
}

// Дублёр права приглашать, отвечающий «нет»: повторная отправка спрашивает ТО ЖЕ
// отношение, что и приглашение.
type resendDenyAll struct{}

func (resendDenyAll) Check(context.Context, string, string, string) (bool, error) { return false, nil }

func TestResendInvite_NoRightToInviteIsDenied(t *testing.T) {
	repo := &resendRepo{row: pendingRow(time.Time{}), inAccount: true}
	limit := outboxtypes.InviteMailRateLimit{MaxPerWindow: 3, Window: time.Hour}
	uc := NewResendInviteUseCase(repo, newFakeUsrOps(), resendDenyAll{}, limit, nil)
	_, err := uc.Execute(resendCtx(), domain.UserID(resendUserID), domain.AccountID(resendAccount))
	require.Equal(t, codes.PermissionDenied, status.Code(err), "%v", err)
}
