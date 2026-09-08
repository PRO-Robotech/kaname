// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// invite_activation_observability_test.go — стадия S2 перехода IAM-ID-1 (задача
// kacho#472), сценарий IAM-ID-1-62: проглоченный отказ становится наблюдаемым,
// почта в лог не пишется.
//
// # Предмет
//
// Первый вход человека активирует его приглашения. Цикл активации ловил ошибку
// и делал `continue` — БЕЗУСЛОВНО, при том что комментарий рядом обещал
// «иначе propagate». То есть отказ активации проглатывался целиком: вход
// завершался успехом, приглашение оставалось неактивированным, и узнать об этом
// было неоткуда.
//
// Мягкий проход защитим ровно пока отказ действительно временный. Здесь он не
// различал «строку уже активировал конкурент» (ожидаемый исход гонки первого
// входа) и «активация не удалась» — а это разные миры: первый штатен, второй
// означает, что человек вошёл, а его членство осталось в состоянии «приглашён».
//
// # Что здесь утверждается
//
//   - отказ НЕ проглатывается: вход прерывается отказом, а не пропуском
//     (IAM-ID-1-04 — «ни одна ошибка активации не проглочена»);
//   - гонка ПРОГЛАТЫВАЕТСЯ намеренно и считается отдельно (положительный
//     контроль: без него «не проглатываем» зеленело бы на реализации, которая
//     роняет вход на штатной гонке);
//   - «ноль отказов за всю жизнь» отличимо от «никто не пробовал» — исходы
//     считаются все три, а не только отказ;
//   - почта не попадает в лог НИ на успешном, ни на отказном пути.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

const (
	activationProbeEmail = "invitee-observability@example.test"
	// Кандидат на bootstrap-строку: обычно его вычисляет resolveUserID, здесь он
	// задан явно — проба ведёт ТЕЛО операции напрямую, потому что цикл активации
	// живёт в нём, а не в синхронной части. Идти через асинхронную операцию
	// значило бы утверждать про расписание, а не про поведение.
	activationCandidateID = "usr0000000000candid1"
)

// recordingActivationObserver — счётчик исходов активации.
type recordingActivationObserver struct{ outcomes []string }

func (o *recordingActivationObserver) IncInviteActivation(outcome string) {
	o.outcomes = append(o.outcomes, outcome)
}

func (o *recordingActivationObserver) count(outcome string) int {
	n := 0
	for _, got := range o.outcomes {
		if got == outcome {
			n++
		}
	}
	return n
}

// pendingInviteeRow — строка приглашённого: внешнего идентификатора у неё нет
// (DB CHECK его запрещает), поэтому находится она по почте.
func pendingInviteeRow() domain.User {
	return domain.User{
		ID:           "usr0000000000invite1",
		AccountID:    "acc0000000000invite1",
		ExternalID:   "",
		Email:        activationProbeEmail,
		InviteStatus: domain.InviteStatusPending,
	}
}

func activationProbeInput() UpsertFromIdentityInput {
	return UpsertFromIdentityInput{
		ExternalID:  "krt-invitee-observability",
		Email:       activationProbeEmail,
		DisplayName: "Invitee",
	}
}

// newActivationProbe собирает use-case с наблюдателем и буфером лога.
func newActivationProbe(t *testing.T, activateErr error) (
	*UpsertFromIdentityUseCase, *fakeUserRepo, *recordingActivationObserver, *bytes.Buffer,
) {
	t.Helper()
	repo := newFakeUserRepo()
	repo.existingActive = []domain.User{pendingInviteeRow()}
	repo.activateErr = activateErr

	obs := &recordingActivationObserver{}
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	uc := NewUpsertFromIdentityUseCase(repo, newFakeOpsRepoUser()).
		WithActivationObserver(obs)
	uc.logger = logger
	return uc, repo, obs, &logBuf
}

// IAM-ID-1-62 / IAM-ID-1-04: настоящий отказ активации прерывает вход.
func TestUpsertFromIdentity_ActivationFailure_AbortsAndIsCounted(t *testing.T) {
	uc, _, obs, _ := newActivationProbe(t, errors.New("activation storage unavailable"))

	_, err := uc.doUpsert(context.Background(), activationCandidateID, activationProbeInput(), "actor")

	require.Error(t, err,
		"отказ активации обязан прерывать вход отказом, а не пропуском: иначе человек "+
			"входит успешно, а его приглашение остаётся неактивированным, и узнать об этом неоткуда")

	require.Equal(t, 1, obs.count(activationOutcomeFailed),
		"отказ обязан быть СОСЧИТАН, а не только возвращён: строка лога — не наблюдаемость "+
			"(security.md §Hardening п.8)")
	require.Zero(t, obs.count(activationOutcomeActivated),
		"несостоявшаяся активация не вправе считаться состоявшейся")
}

// Положительный контроль к предыдущему: ожидаемая гонка первого входа
// проглатывается НАМЕРЕННО и считается своим исходом.
//
// Без этой пробы «отказ не проглатывается» зеленело бы на реализации, которая
// роняет вход на штатной гонке, — то есть чинила бы тихий дефект громким.
func TestUpsertFromIdentity_ActivationRace_IsSkippedAndCountedApart(t *testing.T) {
	uc, _, obs, _ := newActivationProbe(t,
		iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found in PENDING state", "usr0000000000invite1"))

	_, err := uc.doUpsert(context.Background(), activationCandidateID, activationProbeInput(), "actor")

	require.NoError(t, err,
		"строку уже активировал конкурент — это ожидаемый исход гонки первого входа, "+
			"а не отказ: вход обязан продолжиться")

	require.Equal(t, 1, obs.count(activationOutcomeAlreadyActive),
		"гонка обязана считаться СВОИМ исходом — иначе она неотличима от настоящего отказа")
	require.Zero(t, obs.count(activationOutcomeFailed),
		"и не вправе попадать в счётчик отказов: тогда «ноль отказов» перестало бы что-либо значить")
}

// IAM-ID-1-62: «ноль отказов за всю жизнь» отличимо от «никто не пробовал».
func TestUpsertFromIdentity_ActivationCensus_ZeroFailuresIsNotSilence(t *testing.T) {
	uc, _, obs, _ := newActivationProbe(t, nil)

	_, err := uc.doUpsert(context.Background(), activationCandidateID, activationProbeInput(), "actor")
	require.NoError(t, err)

	require.Equal(t, 1, obs.count(activationOutcomeActivated),
		"успешная активация обязана считаться: без счётчика попыток ноль отказов "+
			"неотличим от «активаций не было вовсе»")
	require.Zero(t, obs.count(activationOutcomeFailed))
	require.NotEmpty(t, obs.outcomes,
		"перепись исходов обязана быть непустой — она и есть объём осмотренного")
}

// IAM-ID-1-62: почта не попадает в лог ни на одном из путей.
//
// Утверждается ОТСУТСТВИЕ подстроки в буфере лога, а не факт вызова логгера
// (testing.md §Regression-lock — PII-фикс локается на уровне наблюдаемого).
func TestUpsertFromIdentity_Activation_KeepsEmailOutOfTheLog(t *testing.T) {
	for _, tc := range []struct {
		name        string
		activateErr error
	}{
		{"отказной путь", errors.New("activation storage unavailable")},
		{"успешный путь", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uc, _, _, logBuf := newActivationProbe(t, tc.activateErr)

			_, _ = uc.doUpsert(context.Background(), activationCandidateID, activationProbeInput(), "actor")

			require.NotContains(t, logBuf.String(), activationProbeEmail,
				"почта end-user'а не пишется в лог ни на успешном, ни на отказном пути "+
					"(security.md §Hardening п.2); коррелировать следует по не-PII идентификатору")
		})
	}
}
