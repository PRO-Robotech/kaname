// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyport_test

// client_secrets_queue_test.go — сверка, ждущая места вычисления проверяющего,
// кончается к сроку операции, а не после него (kaname#892).
//
// Проверяющий отдаёт ошибку только тогда, когда вызов кончился раньше, чем
// сверке досталось место вычисления. Порт обязан вернуть её отказом операции с
// концом срока в цепочке — мост церемонии читает его как конец срока, а не
// как исчерпание ёмкости (503 с `Retry-After`) и не как исход вне словаря.
// Близнец — та же сверка на живом вызове — даёт вердикт, и место доли,
// занятое кончившейся сверкой, ему досталось.

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/oauthceremony"

	"github.com/PRO-Robotech/kaname/internal/ceremonyport"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// queuedChecker — проверяющий, все места вычисления которого заняты, пока
// вызов жив: сверка ждёт места и кончается вместе с вызовом. Живой вызов
// (`free`) получает место сразу и исход «совпал».
type queuedChecker struct{ free bool }

func (c queuedChecker) VerifyPresented(ctx context.Context, _ domain.LoginVerifier, _ passwordverify.Presented) (passwordverify.Result, error) {
	if c.free {
		return passwordverify.Result{Outcome: passwordverify.OutcomeMatched}, nil
	}
	<-ctx.Done()
	return passwordverify.Result{}, ctx.Err()
}

func (queuedChecker) Aligned() bool { return true }

func (queuedChecker) Capacity() int { return 2 }

func TestClientSecrets_CheckWaitingForAComputationPlaceEndsAtTheDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &secretStore{verifiers: map[string]domain.LoginVerifier{}}
		checker := &queuedChecker{}
		port, err := ceremonyport.NewClientSecrets(store, checker, &shareCounter{})
		require.NoError(t, err)

		const deadline = time.Second
		ctx, cancel := context.WithTimeout(t.Context(), deadline)
		defer cancel()
		start := time.Now()
		verdict, err := port.VerifyClientSecret(ctx, testClientID, oauthceremony.NewPresentedSecret(rightClientSecret))
		elapsed := time.Since(start)

		require.Error(t, err, "сверка, не дождавшаяся места, стала вердиктом")
		require.ErrorIs(t, err, context.DeadlineExceeded, "конец срока не в цепочке отказа порта: %v", err)
		require.False(t, errors.Is(err, domain.ErrVerifierAtCapacity),
			"конец срока выдан за исчерпание ёмкости проверяющего: %v", err)
		require.Equal(t, oauthceremony.SecretVerdictUnspecified, verdict)
		require.Equal(t, deadline, elapsed, "порт ответил не к сроку операции")
		require.Contains(t, err.Error(), testClientID, "отказ не называет клиента")
		require.NotContains(t, err.Error(), rightClientSecret, "предъявленный секрет в тексте отказа")

		// Близнец: живой вызов, место свободно — вердикт; доля, занятая
		// кончившейся сверкой, отдана.
		checker.free = true
		verdict, err = port.VerifyClientSecret(t.Context(), testClientID, oauthceremony.NewPresentedSecret(rightClientSecret))
		require.NoError(t, err)
		require.Equal(t, oauthceremony.SecretMatched, verdict)
	})
}
