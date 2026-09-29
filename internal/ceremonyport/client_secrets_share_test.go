// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyport_test

// client_secrets_share_test.go — сверка секрета клиента церемонии занимает не
// больше СВОЕЙ ДОЛИ ёмкости проверяющего (задача PRO-Robotech/kaname#423,
// возврат ревью безопасности сборки 425).
//
// Проверяющий общий с полосой входа паролем: тот же пул вычислений, под который
// посчитан бюджет памяти. Сверка на токен-эндпоинте идёт до всякого
// доказательства клиента, и поток запросов, называющих клиента с любым секретом,
// занимал бы места проверяющего целиком — вход людей получал бы отказ по
// ёмкости. Доля церемонии — половина ёмкости; вторая половина остаётся полосе
// входа при любом потоке на токен-эндпоинте.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/oauthceremony"

	"github.com/PRO-Robotech/kaname/internal/ceremonyport"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// holdingChecker — проверяющий пробы: каждая сверка держит место, пока проба
// не отпустит, и проверяющий помнит, сколько сверок шло одновременно.
type holdingChecker struct {
	capacity int
	entered  chan struct{}
	release  chan struct{}

	mu             sync.Mutex
	inFlight, peak int
}

func newHoldingChecker(capacity int) *holdingChecker {
	return &holdingChecker{capacity: capacity, entered: make(chan struct{}, 64), release: make(chan struct{})}
}

func (c *holdingChecker) VerifyPresented(domain.LoginVerifier, passwordverify.Presented) passwordverify.Result {
	c.mu.Lock()
	c.inFlight++
	if c.inFlight > c.peak {
		c.peak = c.inFlight
	}
	c.mu.Unlock()
	c.entered <- struct{}{}
	<-c.release
	c.mu.Lock()
	c.inFlight--
	c.mu.Unlock()
	return passwordverify.Result{Outcome: passwordverify.OutcomeMismatched}
}

func (c *holdingChecker) Aligned() bool { return true }

func (c *holdingChecker) Capacity() int { return c.capacity }

func (c *holdingChecker) peakInFlight() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peak
}

func TestClientSecrets_TheCeremonyHoldsAtMostItsShareOfTheChecker(t *testing.T) {
	const capacity = 4
	checker := newHoldingChecker(capacity)
	port, err := ceremonyport.NewClientSecrets(&secretStore{verifiers: map[string]domain.LoginVerifier{}}, checker)
	require.NoError(t, err)

	// Поток запросов на всю ёмкость проверяющего.
	refused := make(chan error, capacity)
	var wg sync.WaitGroup
	for i := 0; i < capacity; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := port.VerifyClientSecret(context.Background(), unknownClientID,
				oauthceremony.NewPresentedSecret(wrongClientSecret))
			if err != nil {
				refused <- err
			}
		}()
	}
	in, out := 0, 0
	deadline := time.After(2 * time.Second)
wait:
	for in+out < capacity {
		select {
		case <-checker.entered:
			in++
		case err := <-refused:
			require.ErrorIs(t, err, domain.ErrVerifierAtCapacity, "отказ сверки сверх доли — не отказ по ёмкости")
			out++
		case <-deadline:
			break wait
		}
	}
	close(checker.release)
	wg.Wait()

	require.Equal(t, capacity/2, in,
		"поток на токен-эндпоинте занял %d из %d мест проверяющего; полосе входа оставлено %d", in, capacity, capacity-in)
	require.Equal(t, capacity-capacity/2, out, "сверки сверх доли церемонии не получили отказа по ёмкости")
	require.LessOrEqual(t, checker.peakInFlight(), capacity/2)
}

// Близнец: доля — предел одновременности, а не частоты. Сверки одна за другой
// проходят все.
func TestClientSecrets_SequentialVerificationsAreNotLimitedByTheShare(t *testing.T) {
	checker := newHoldingChecker(2)
	close(checker.release)
	port, err := ceremonyport.NewClientSecrets(&secretStore{verifiers: map[string]domain.LoginVerifier{}}, checker)
	require.NoError(t, err)
	for i := 0; i < 5; i++ {
		verdict, err := port.VerifyClientSecret(context.Background(), unknownClientID,
			oauthceremony.NewPresentedSecret(wrongClientSecret))
		require.NoError(t, err, "сверка %d", i)
		require.Equal(t, oauthceremony.SecretMismatched, verdict)
	}
}
