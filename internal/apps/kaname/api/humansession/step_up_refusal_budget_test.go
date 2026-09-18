// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// step_up_refusal_budget_test.go — СРОК запасной записи отказа отдельный, не
// общий с основной (задача PRO-Robotech/kaname#283; приёмка
// `docs/engineering/acceptance/assurance-level-is-declared-by-our-session.md`
// ред. 5, Ф11-14, Ф11-13; Р7; находка безопасности С2).
//
// Записи суждённого отказа отвязаны от отмены запроса, но у каждой ДОЛЖЕН быть
// свой срок. Общий срок на насыщённом пуле достаётся запасной записи уже
// истёкшим: основная транзакция ждёт соединения и выбирает срок целиком, а
// `pgxpool.Acquire` запасной падает сразу на истёкшем контексте — след попытки
// не ложится, и неверное предъявление, вынесенное вердиктом, остаётся
// несосчитанным.
//
// Дублёр хранилища моделирует насыщённый пул: первый `Writer` (основная запись)
// ждёт конца своего контекста и отказывает — как `Acquire`, дождавшийся срока
// вызывающего; второй `Writer` (запасная запись) на истёкшем контексте
// отказывает сразу, на живом — открывает настоящую транзакцию дублёра. При
// своём сроке у запасной записи её контекст жив, и след попытки ложится: счёт
// по адресу и по источнику +1; записи `refused` нет — базы для журнала не было.
//
// Способность падать: возврат общего срока обеим записям (инъекция) — запасная
// получает истёкший контекст, счёт остаётся 0.
package humansession_test

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
)

// poolSaturatedStore — хранилище, чей `Writer` моделирует насыщённый пул: см.
// шапку файла. Всё, кроме открытия транзакции, делегируется настоящему дублёру.
type poolSaturatedStore struct {
	*fakeStore
	mu    sync.Mutex
	calls int
}

func (s *poolSaturatedStore) Writer(ctx context.Context) (humansession.Writer, error) {
	s.mu.Lock()
	s.calls++
	first := s.calls == 1
	s.mu.Unlock()
	if first {
		// Основная запись: пул насыщен — Acquire ждёт до срока вызывающего,
		// затем отказывает.
		<-ctx.Done()
		return nil, ctx.Err()
	}
	// Запасная запись: на истёкшем контексте Acquire падает сразу; на живом —
	// открывает настоящую транзакцию дублёра.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.fakeStore.Writer(ctx)
}

func TestStepUp_F11_14_FallbackAttemptHasItsOwnBudget(t *testing.T) {
	const (
		email    = "c2@example.invalid"
		password = "correct horse battery"
		source   = "203.0.113.7"
	)
	h := newSFHarness(t)
	h.person(t, "usr-c2", email, password, true)
	login := h.mustLogin(t, email, password)
	require.Equal(t, "1", login.View.Session.AssuranceLevel, "Дано: сессия уровня «1»")

	// Церемония над насыщённым пулом; прочие зависимости — как у слушателя.
	store := &poolSaturatedStore{fakeStore: h.store}
	stepUp, err := humansession.NewStepUpUseCase(humansession.SecondFactorDeps{
		Store: store, Methods: fakeMethods{h.store}, TOTP: h.totp, Sets: h.verifier, SetHasher: h.hasher,
		Verifier: h.verifier, Limits: sfLimits(), Freshness: sfWindow, Domain: sfDomain,
		Observer: h.obs, Now: func() time.Time { return h.clock }, Logger: slog.New(slog.DiscardHandler),
	})
	require.NoError(t, err)

	byAddress := h.failures(humansession.FailureByAddress, email)
	bySource := h.failures(humansession.FailureBySource, source)

	_, err = stepUp.Execute(context.Background(), humansession.StepUpInput{
		Bearer: login.Bearer, Method: assurance.MethodPassword, Password: "not the password of this person", Source: source,
	})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "отказ наружу тот же")
	require.Equal(t, 2, store.calls, "основная запись и запасная — два открытия транзакции")

	require.Equal(t, byAddress+1, h.failures(humansession.FailureByAddress, email),
		"счёт по адресу: +1 — запасная запись легла под своим сроком")
	require.Equal(t, bySource+1, h.failures(humansession.FailureBySource, source),
		"счёт по источнику: +1")
	require.Equal(t, 0, refusedRecords(h, login.View.Session.ID),
		"записи журнала `refused` нет: основной транзакции не досталось соединения")
}
