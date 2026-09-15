// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// invitation_bearer_test.go — use-case половина предъявителя приглашения
// (приёмка ID-MAIL-1: Р21а, Р24; MAIL-22, MAIL-23, MAIL-24, MAIL-46 — уровень U).
//
// Решение о выкупе принимает ОПЕРАТОР базы (его судит интеграционная проба
// репозитория). Здесь утверждается то, чего база не видит:
//
//   - отказ ДОХОДИТ до вызывающего синхронно и называет причину и следующий шаг —
//     иначе его не получит ни хук поставщика, ни инструмент администратора;
//   - отказ, случившийся уже в операции (гонка пречека с выкупом), не проваливается
//     в заведение новой личности;
//   - следствия выкупа (указатель области, запись аудита) называют ТОЛЬКО те
//     аккаунты, чьи членства выкуп перевёл, а не легаси-колонку строки;
//   - почта не попадает ни в текст отказа, ни в журнал: текст отказа хук пишет в
//     журнал дословно.

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func bearerProbe(t *testing.T, standing domain.InvitationStanding) (
	*UpsertFromIdentityUseCase, *fakeUserRepo, *recordingActivationObserver,
) {
	t.Helper()
	repo := newFakeUserRepo()
	repo.existingActive = []domain.User{pendingInviteeRow()}
	repo.standing = standing
	obs := &recordingActivationObserver{}
	uc := NewUpsertFromIdentityUseCase(repo, newFakeOpsRepoUser()).WithActivationObserver(obs)
	return uc, repo, obs
}

// MAIL-23 (U): вход после срока отвергается СИНХРОННО, и отказ называет причину
// и следующий шаг — попросить пригласить заново.
func TestUpsertFromIdentity_ExpiredInvitationIsRefusedWithTheNextStep(t *testing.T) {
	uc, repo, obs := bearerProbe(t, domain.InvitationExpired)

	op, err := uc.Execute(context.Background(), activationProbeInput())
	require.Nil(t, op, "отказ обязан прийти ДО операции: хук поставщика ждёт синхронного ответа")
	require.Error(t, err)
	require.Equal(t, codes.FailedPrecondition, status.Code(err),
		"истёкшее приглашение — предусловие, а не ошибка ввода и не сбой")
	msg := status.Convert(err).Message()
	require.Contains(t, msg, "expired", "отказ обязан называть причину")
	require.Contains(t, msg, "invite you again", "отказ обязан называть следующий шаг")
	require.NotContains(t, msg, activationProbeEmail,
		"почта не попадает в текст отказа: хук поставщика пишет его в журнал дословно")
	require.Equal(t, 1, obs.count(string(domain.InviteActivationExpired)),
		"отказ по сроку обязан быть сосчитан: иначе «приглашения истекают» невидимо")
	require.Zero(t, repo.upsertCalls(), "по истёкшему приглашению личность не заводится")
}

// MAIL-24 / MAIL-46 (U): снятое приглашение отвергается так же, но говорит, что
// приглашения НЕТ, а не что оно истекло.
func TestUpsertFromIdentity_WithdrawnInvitationIsRefused(t *testing.T) {
	for _, st := range []domain.InvitationStanding{domain.InvitationWithdrawn, domain.InvitationNotIssued} {
		t.Run(string(st), func(t *testing.T) {
			uc, repo, obs := bearerProbe(t, st)
			_, err := uc.Execute(context.Background(), activationProbeInput())
			require.Error(t, err)
			require.Equal(t, codes.FailedPrecondition, status.Code(err))
			msg := status.Convert(err).Message()
			require.Contains(t, msg, "no invitation", "отказ обязан сказать, что приглашения нет")
			require.NotContains(t, msg, "expired",
				"снятое приглашение не вправе звучать как истёкшее: совет «попросите продлить» "+
					"послал бы просить то, чего аккаунт больше не предлагает")
			require.NotContains(t, msg, activationProbeEmail)
			require.Equal(t, 1, obs.count(string(st.ActivationOutcome())))
			require.Zero(t, repo.upsertCalls())
		})
	}
}

// Положительный контроль: выкупаемое приглашение проходит синхронную часть.
func TestUpsertFromIdentity_RedeemableInvitationPasses(t *testing.T) {
	uc, _, _ := bearerProbe(t, domain.InvitationRedeemable)
	op, err := uc.Execute(context.Background(), activationProbeInput())
	require.NoError(t, err)
	require.NotNil(t, op)
}

// Гонка пречека с выкупом: синхронная часть видела выкупаемое, оператор базы —
// уже нет. Отказ обязан остаться отказом, а не провалиться в заведение новой
// личности по адресу, которым строка ожидания уже владеет.
func TestUpsertFromIdentity_RefusalInsideTheOperationDoesNotBootstrap(t *testing.T) {
	for _, st := range []domain.InvitationStanding{
		domain.InvitationExpired, domain.InvitationWithdrawn, domain.InvitationNotIssued, domain.InvitationAbsent,
	} {
		t.Run(string(st), func(t *testing.T) {
			uc, repo, obs := bearerProbe(t, domain.InvitationRedeemable)
			repo.activationStanding = st

			_, err := uc.doUpsert(context.Background(), activationCandidateID, activationProbeInput(), "actor")
			require.Error(t, err, "отказ выкупа в операции обязан прерывать вход")
			require.Equal(t, codes.FailedPrecondition, status.Code(err))
			require.Zero(t, repo.upsertCalls(),
				"по отвергнутому приглашению личность НЕ заводится: иначе отказ выкупа превращается "+
					"в заведение новой строки по чужому адресу")
			require.Equal(t, 1, obs.count(string(st.ActivationOutcome())))
			require.Zero(t, obs.count(string(domain.InviteActivationActivated)))
		})
	}
}

// Следствия выкупа называют ТОЛЬКО переведённые аккаунты. Легаси-колонка строки
// называет аккаунт, из которого человека исключили; выкуп по уцелевшему
// приглашению не вправе вернуть туда ни указатель области, ни запись аудита.
func TestUpsertFromIdentity_ActivationClaimsOnlyTheAccountsItActivated(t *testing.T) {
	uc, repo, _ := bearerProbe(t, domain.InvitationRedeemable)
	const legacy = domain.AccountID("acc0000000000invite1") // pendingInviteeRow().AccountID
	const survived = domain.AccountID("acc00000000survived1")
	repo.activationAccounts = []domain.AccountID{survived}

	_, err := uc.doUpsert(context.Background(), activationCandidateID, activationProbeInput(), "actor")
	require.NoError(t, err)

	var survivedPointer, legacyPointer bool
	for _, tup := range repo.fgaTuples() {
		if tup.Relation == "account" && strings.HasPrefix(tup.Object, "iam_user:") {
			switch tup.User {
			case "account:" + string(survived):
				survivedPointer = true
			case "account:" + string(legacy):
				legacyPointer = true
			}
		}
	}
	require.True(t, survivedPointer, "указатель области обязан лечь для переведённого аккаунта")
	require.False(t, legacyPointer,
		"указатель области лёг для аккаунта, чьё членство выкуп НЕ переводил: снятое участие "+
			"вернуло аккаунту власть над строкой человека")

	var tenants []string
	for _, ev := range repo.audits() {
		if ev.EventType == auditEventUserUpdated {
			tenants = append(tenants, ev.TenantAccountID)
		}
	}
	require.Equal(t, []string{string(survived)}, tenants,
		"запись аудита активации обязана уйти аккаунту, чьё приглашение выкуплено, — и только ему")
}

// Почта не попадает в журнал ни на одном из путей отказа выкупа.
func TestUpsertFromIdentity_BearerRefusalsKeepEmailOutOfTheLog(t *testing.T) {
	for _, st := range []domain.InvitationStanding{domain.InvitationExpired, domain.InvitationWithdrawn} {
		t.Run(string(st), func(t *testing.T) {
			uc, repo, _ := bearerProbe(t, domain.InvitationRedeemable)
			repo.activationStanding = st
			var logBuf bytes.Buffer
			uc.logger = slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			_, _ = uc.doUpsert(context.Background(), activationCandidateID, activationProbeInput(), "actor")
			require.NotContains(t, logBuf.String(), activationProbeEmail)
		})
	}
	_ = fmt.Sprint
}
