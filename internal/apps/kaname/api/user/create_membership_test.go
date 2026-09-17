// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// create_membership_test.go — `MembershipService.Create` как ВТОРОЙ ВХОД потока
// приглашения (kaname#181, IAM-ID-1 §4 S3.2).
//
// Что здесь утверждается и почему ДУБЛЁРОМ. Форма операции — какое сообщение
// лежит в `metadata`, какое в `response` — решается ДО хранилища и не зависит от
// него; а «членство читается В ТОЙ ЖЕ транзакции, что и вставка» есть порядок
// вызовов писателя, и наблюдаем он только у дублёра, который этот порядок
// записывает. Исход на живой базе утверждает соседняя проба
// (`create_membership_outcome_test.go`).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	membershipapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/membership"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

const (
	cmAccount = "acc000000000000cm181"
	cmEmail   = "membership-create@kacho.local"
	cmInviter = "usr000000000000cm181"
)

func cmCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: cmInviter})
}

// cmMailLimit — ограничение частоты письма приглашения, провязанное пробам
// этого файла. Без провязанного ограничения use-case письма не шлёт и
// приглашение НЕ проходит (`Test_Invite_WithoutAWiredLimitRefusesToSend`,
// kacho#1774) — это решение продукта, а не умолчание, и пробы членства его не
// переоткрывают: их предмет — форма операции и порядок в транзакции, письмо
// здесь лишь условие прохождения глагола.
var cmMailLimit = outboxtypes.InviteMailRateLimit{MaxPerWindow: 3, Window: time.Hour}

// awaitUsrOp ждёт терминального состояния операции у дублёра операций —
// детерминированно, по условию, а не по паузе.
func awaitUsrOp(t *testing.T, ops *fakeUsrOps, id string) *operations.Operation {
	t.Helper()
	var out *operations.Operation
	require.Eventually(t, func() bool {
		op, err := ops.Get(context.Background(), id)
		if err != nil || !op.Done {
			return false
		}
		out = op
		return true
	}, 5*time.Second, 10*time.Millisecond, "операция обязана завершиться")
	return out
}

// TestInvite_KAN181_CreateMembershipMintsCreateMembershipMetadata — форма
// операции: metadata — `CreateMembershipMetadata` с аккаунтом и кандидатом
// идентификатора человека; response — `Membership`.
func TestInvite_KAN181_CreateMembershipMintsCreateMembershipMetadata(t *testing.T) {
	repo := &invPrincRepo{}
	ops := newFakeUsrOps()
	uc := NewInviteUserUseCase(repo, ops, invPrincAllowAll{}).WithInviteMailRateLimit(cmMailLimit, nil)

	op, err := uc.CreateMembership(cmCtx(), membershipapp.CreateInput{
		AccountID: domain.AccountID(cmAccount),
		Email:     domain.Email(cmEmail),
	})
	require.NoError(t, err)
	require.NotNil(t, op)

	md := &iamv1.CreateMembershipMetadata{}
	require.NoError(t, op.Metadata.UnmarshalTo(md),
		"metadata операции создания членства — CreateMembershipMetadata, а не InviteUserMetadata")
	assert.Equal(t, cmAccount, md.GetAccountId())
	assert.Regexp(t, `^usr[0-9a-z]{17}$`, md.GetUserId(),
		"кандидат идентификатора человека чеканится до исполнения")

	done := awaitUsrOp(t, ops, op.ID)
	require.Nil(t, done.Error, "приглашение по новому глаголу обязано пройти: %v", done.Error)
	m := &iamv1.Membership{}
	require.NoError(t, done.Response.UnmarshalTo(m),
		"response операции создания членства — Membership, а не User")
	assert.Equal(t, cmAccount, m.GetAccountId())
	assert.Equal(t, md.GetUserId(), m.GetUserId(),
		"у НЕИЗВЕСТНОЙ почты строку заводит эта операция — идентификатор совпадает с кандидатом")
	assert.Equal(t, iamv1.Membership_PENDING, m.GetState(),
		"человек, которого в платформе не было, приглашён и ещё не входил")
	assert.Equal(t, cmInviter, m.GetInvitedBy(), "след приглашения называет пригласившего человека")
}

// TestInvite_KAN181_MembershipIsReadInsideTheWriterTransaction — ответ
// строится из строки, прочитанной ТОЙ ЖЕ транзакцией, что её и завела: чтение
// после коммита с реплики могло бы не увидеть только что записанного.
func TestInvite_KAN181_MembershipIsReadInsideTheWriterTransaction(t *testing.T) {
	repo := &invPrincRepo{}
	ops := newFakeUsrOps()
	uc := NewInviteUserUseCase(repo, ops, invPrincAllowAll{}).WithInviteMailRateLimit(cmMailLimit, nil)

	op, err := uc.CreateMembership(cmCtx(), membershipapp.CreateInput{
		AccountID: domain.AccountID(cmAccount),
		Email:     domain.Email(cmEmail),
	})
	require.NoError(t, err)
	awaitUsrOp(t, ops, op.ID)

	repo.mu.Lock()
	seq := append([]string(nil), repo.seq...)
	repo.mu.Unlock()
	require.Equal(t, []string{"insert-pending", "read-membership", "commit"}, seq,
		"порядок писателя: вставка → чтение членства → фиксация; чтение вне транзакции "+
			"стояло бы ПОСЛЕ commit")
}

// TestInvite_KAN181_BothVerbsReachTheSameWriter — два глагола, ОДИН поток:
// прежний `Invite` и новый `Create` доходят до одного и того же писателя
// (`InsertPending`) с одним и тем же входом. Не два места об одном предмете.
func TestInvite_KAN181_BothVerbsReachTheSameWriter(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(uc *InviteUserUseCase) (*operations.Operation, error)
	}{
		{"UserService.Invite", func(uc *InviteUserUseCase) (*operations.Operation, error) {
			return uc.Execute(cmCtx(), InviteUserInput{
				AccountID: domain.AccountID(cmAccount), Email: domain.Email(cmEmail)})
		}},
		{"MembershipService.Create", func(uc *InviteUserUseCase) (*operations.Operation, error) {
			return uc.CreateMembership(cmCtx(), membershipapp.CreateInput{
				AccountID: domain.AccountID(cmAccount), Email: domain.Email(cmEmail)})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &invPrincRepo{}
			ops := newFakeUsrOps()
			uc := NewInviteUserUseCase(repo, ops, invPrincAllowAll{}).WithInviteMailRateLimit(cmMailLimit, nil)
			op, err := tc.call(uc)
			require.NoError(t, err)
			done := awaitUsrOp(t, ops, op.ID)
			require.Nil(t, done.Error)

			repo.mu.Lock()
			defer repo.mu.Unlock()
			assert.True(t, repo.inserted, "оба глагола доходят до InsertPending")
			assert.Equal(t, cmInviter, string(repo.gotInvitedBy), "оба ставят след приглашения")
			assert.Len(t, repo.mailIntents, 1, "оба со-коммитят ровно одно письмо приглашения")
			assert.NotEmpty(t, repo.emitted, "оба со-коммитят указатель на предка строкой журнала")
		})
	}
}

// TestInvite_KAN181_CreateMembershipRefusesBadAccountSynchronously — отказ
// формы — ПЕРВЫМ стейтментом, до чеканки операции: пустой аккаунт называет
// поле, негодный — контракт-тон формы.
func TestInvite_KAN181_CreateMembershipRefusesBadAccountSynchronously(t *testing.T) {
	for _, tc := range []struct {
		name, account, wantMsg string
	}{
		{"empty", "", "Illegal argument account_id: required"},
		{"malformed", "not-an-account", "invalid account id 'not-an-account'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &invPrincRepo{}
			ops := newFakeUsrOps()
			uc := NewInviteUserUseCase(repo, ops, invPrincAllowAll{}).WithInviteMailRateLimit(cmMailLimit, nil)

			op, err := uc.CreateMembership(cmCtx(), membershipapp.CreateInput{
				AccountID: domain.AccountID(tc.account),
				Email:     domain.Email(cmEmail),
			})
			require.Nil(t, op)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Equal(t, tc.wantMsg, status.Convert(err).Message())

			ops.mu.Lock()
			defer ops.mu.Unlock()
			assert.Empty(t, ops.ops, "операция НЕ чеканится: отказ синхронный")
			repo.mu.Lock()
			defer repo.mu.Unlock()
			assert.False(t, repo.inserted, "до писателя отказ формы не доходит")
		})
	}
}
