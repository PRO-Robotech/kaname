// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// invite_term_and_rate_test.go — глагол приглашения записывает срок, продлевает
// его повтором и отвечает на отказ частоты своей полосой (приёмка ID-MAIL-1:
// Р14, Р22, Р24; MAIL-23, MAIL-25 — уровень U).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

const probeTerm = domain.InvitationTerm(48 * time.Hour)

func termProbeCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr0000000000000invm"})
}

func awaitInviteOp(t *testing.T, ops *fakeUsrOps, id string) *operations.Operation {
	t.Helper()
	var got *operations.Operation
	require.Eventually(t, func() bool {
		op, err := ops.Get(context.Background(), id)
		if err != nil || !op.Done {
			return false
		}
		got = op
		return true
	}, 5*time.Second, 10*time.Millisecond, "операция приглашения обязана завершиться")
	return got
}

// MAIL-23 (U): срок пишется величиной из объявления, а не выписанной в коде.
func Test_Invite_WritesTheDeclaredTermOnTheInvitation(t *testing.T) {
	repo := &invPrincRepo{}
	ops := newFakeUsrOps()
	uc := NewInviteUserUseCase(repo, ops, invPrincAllowAll{}, probeTerm)

	op, err := uc.Execute(termProbeCtx(), InviteUserInput{
		AccountID: domain.AccountID(invPrincAccount), Email: domain.Email(invPrincEmail),
	})
	require.NoError(t, err)
	awaitInviteOp(t, ops, op.ID)

	repo.mu.Lock()
	defer repo.mu.Unlock()
	require.True(t, repo.inserted)
	require.Equal(t, probeTerm, repo.gotTerm,
		"вставка приглашения обязана получить объявленный срок — иначе срок живёт в коде, а не в профиле")
}

// «Попросите пригласить заново» обязано работать: повторное приглашение того же
// человека в тот же аккаунт идёт идемпотентным путём и ПРОДЛЕВАЕТ срок.
func Test_Invite_ReinvitingAPendingPersonRenewsTheTerm(t *testing.T) {
	repo := &inviteIdempotentRepo{existing: domain.User{
		ID: "usr0000000000000exst", AccountID: domain.AccountID(invPrincAccount),
		Email: domain.Email(invPrincEmail), InviteStatus: domain.InviteStatusPending,
	}}
	ops := newFakeUsrOps()
	uc := NewInviteUserUseCase(repo, ops, invPrincAllowAll{}, probeTerm)

	op, err := uc.Execute(termProbeCtx(), InviteUserInput{
		AccountID: domain.AccountID(invPrincAccount), Email: domain.Email(invPrincEmail),
	})
	require.NoError(t, err)
	done := awaitInviteOp(t, ops, op.ID)
	require.Nil(t, done.Error)

	repo.mu.Lock()
	defer repo.mu.Unlock()
	require.Equal(t, []renewCall{{ID: "usr0000000000000exst", Term: probeTerm}}, repo.renewed,
		"повторное приглашение ожидающего человека обязано продлить срок объявленной величиной")
}

// Положительный контроль к продлению: вошедшему человеку продлевать нечего.
func Test_Invite_ReinvitingAnActivePersonDoesNotRenew(t *testing.T) {
	repo := &inviteIdempotentRepo{existing: domain.User{
		ID: "usr0000000000000actv", AccountID: domain.AccountID(invPrincAccount),
		Email: domain.Email(invPrincEmail), InviteStatus: domain.InviteStatusActive, ExternalID: "ext-a",
	}}
	ops := newFakeUsrOps()
	uc := NewInviteUserUseCase(repo, ops, invPrincAllowAll{}, probeTerm)
	op, err := uc.Execute(termProbeCtx(), InviteUserInput{
		AccountID: domain.AccountID(invPrincAccount), Email: domain.Email(invPrincEmail),
	})
	require.NoError(t, err)
	awaitInviteOp(t, ops, op.ID)
	repo.mu.Lock()
	defer repo.mu.Unlock()
	require.Empty(t, repo.renewed, "у вошедшего человека срока приглашения нет")
}

// Непровязанный срок — отказ, а не приглашение без срока: «не задано» не вправе
// означать «выкупается вечно».
func Test_Invite_UnconfiguredTermRefusesBeforeWriting(t *testing.T) {
	repo := &invPrincRepo{}
	uc := NewInviteUserUseCase(repo, newFakeUsrOps(), invPrincAllowAll{}, 0)
	op, err := uc.Execute(termProbeCtx(), InviteUserInput{
		AccountID: domain.AccountID(invPrincAccount), Email: domain.Email(invPrincEmail),
	})
	require.Error(t, err)
	require.Nil(t, op)
	repo.mu.Lock()
	defer repo.mu.Unlock()
	require.False(t, repo.inserted, "без срока приглашение не заводится вовсе")
}

// MAIL-25 (U): отказ частоты — своя полоса (RESOURCE_EXHAUSTED), и он СОСЧИТАН
// вместе с принятыми: без знаменателя доля отказов, по которой пересматривается
// умолчание (Р14), не вычисляется.
func Test_Invite_MailRateRefusalIsItsOwnLaneAndIsCounted(t *testing.T) {
	t.Run("отказ", func(t *testing.T) {
		repo := &invPrincRepo{mailErr: iamerr.Wrapf(iamerr.ErrMailRateExceeded, "letters to this address reached the rate")}
		ops := newFakeUsrOps()
		obs := &recordingMailRateObserver{}
		uc := NewInviteUserUseCase(repo, ops, invPrincAllowAll{}, probeTerm).WithMailRateObserver(obs)
		op, err := uc.Execute(termProbeCtx(), InviteUserInput{
			AccountID: domain.AccountID(invPrincAccount), Email: domain.Email(invPrincEmail),
		})
		require.NoError(t, err)
		done := awaitInviteOp(t, ops, op.ID)
		require.NotNil(t, done.Error, "приглашение сверх частоты обязано завершиться отказом")
		st := gstatus.FromProto(done.Error)
		require.Equal(t, codes.ResourceExhausted, st.Code(),
			"отказ частоты — «повторите позже», а не сбой и не ошибка ввода")
		require.NotContains(t, st.Message(), invPrincEmail, "текст отказа не несёт адреса")
		require.Equal(t, []string{string(domain.InviteMailRateRefused)}, obs.outcomes)
	})
	t.Run("контроль: принятое письмо тоже сосчитано", func(t *testing.T) {
		repo := &invPrincRepo{}
		ops := newFakeUsrOps()
		obs := &recordingMailRateObserver{}
		uc := NewInviteUserUseCase(repo, ops, invPrincAllowAll{}, probeTerm).WithMailRateObserver(obs)
		op, err := uc.Execute(termProbeCtx(), InviteUserInput{
			AccountID: domain.AccountID(invPrincAccount), Email: domain.Email(invPrincEmail),
		})
		require.NoError(t, err)
		done := awaitInviteOp(t, ops, op.ID)
		require.Nil(t, done.Error)
		require.Equal(t, []string{string(domain.InviteMailRateAdmitted)}, obs.outcomes)
	})
	_ = errors.New
}

type recordingMailRateObserver struct{ outcomes []string }

func (o *recordingMailRateObserver) IncInviteMailRate(outcome string) {
	o.outcomes = append(o.outcomes, outcome)
}
