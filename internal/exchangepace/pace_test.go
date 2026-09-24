// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// pace_test.go — ось «обменов в секунду на идентификатор клиента» (kaname#315,
// п. 1 и 4 предиката снятия).
//
// Часы управляемые во всех пробах: темп на системных часах не различает «ведро
// пополнилось» и «проба уложилась в миллисекунду», и граница ровно на пороге
// не ставится вовсе.
package exchangepace_test

import (
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/exchangepace"
)

// clock — управляемые часы пробы.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *clock { return &clock{now: time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newPace(t *testing.T, perSec int, c *clock) *exchangepace.Pace {
	t.Helper()
	p, err := exchangepace.New(perSec, c.Now)
	require.NoError(t, err)
	return p
}

// TestReserveAdmitsExactlyTheDeclaredPaceAndNamesTheWait — объявленное число
// обменов в секунду проходит, следующий отвергается и получает срок ожидания.
func TestReserveAdmitsExactlyTheDeclaredPaceAndNamesTheWait(t *testing.T) {
	c := newClock()
	p := newPace(t, 3, c)

	for i := 0; i < 3; i++ {
		_, wait, ok := p.Reserve("client-a")
		require.Truef(t, ok, "обмен %d из объявленных трёх обязан пройти", i+1)
		require.Zero(t, wait)
	}

	refund, wait, ok := p.Reserve("client-a")
	require.False(t, ok, "четвёртый обмен в ту же секунду превышает объявленный темп")
	require.Nil(t, refund, "отказу нечего возвращать")
	// Ожидание — время до ОДНОГО целого обмена при темпе 3 в секунду,
	// округлённое ВВЕРХ: повтор, названный раньше, чем обмен пополнится, снова
	// получил бы отказ.
	require.Equal(t, time.Duration(math.Ceil(float64(time.Second)/3)), wait)
}

// TestPaceRefillsWithTimeAndNeverAboveOneSecondOfPace — ведро пополняется
// временем и не копит больше одной секунды темпа.
func TestPaceRefillsWithTimeAndNeverAboveOneSecondOfPace(t *testing.T) {
	c := newClock()
	p := newPace(t, 2, c)
	for i := 0; i < 2; i++ {
		_, _, ok := p.Reserve("client-a")
		require.True(t, ok)
	}
	_, _, ok := p.Reserve("client-a")
	require.False(t, ok)

	// Полсекунды при темпе 2 — ровно один обмен.
	c.advance(500 * time.Millisecond)
	_, _, ok = p.Reserve("client-a")
	require.True(t, ok, "через полсекунды при темпе 2 в секунду один обмен обязан пройти")
	_, _, ok = p.Reserve("client-a")
	require.False(t, ok, "и ровно один")

	// Долгий простой не копит запас сверх одной секунды темпа: иначе клиент,
	// молчавший час, получил бы право на всплеск в тысячи обменов.
	c.advance(time.Hour)
	admitted := 0
	for i := 0; i < 10; i++ {
		if _, _, ok := p.Reserve("client-a"); ok {
			admitted++
		}
	}
	require.Equal(t, 2, admitted, "запас ведра — одна секунда объявленного темпа")
}

// TestRefundReturnsTheReservationOnceAndOnlyOnce — возврат отдаёт ровно один
// обмен, повторный вызов не отдаёт ничего.
func TestRefundReturnsTheReservationOnceAndOnlyOnce(t *testing.T) {
	c := newClock()
	p := newPace(t, 1, c)

	refund, _, ok := p.Reserve("client-a")
	require.True(t, ok)
	_, _, ok = p.Reserve("client-a")
	require.False(t, ok, "темп 1 в секунду исчерпан")

	refund()
	refund() // повторный возврат обязан быть холостым

	_, _, ok = p.Reserve("client-a")
	require.True(t, ok, "возвращённый обмен обязан снова быть доступен")
	_, _, ok = p.Reserve("client-a")
	require.False(t, ok, "повторный возврат не имеет права отдать второй обмен")
}

// TestKeysArePacedSeparately — ведро одного идентификатора не делит темп с
// ведром другого.
func TestKeysArePacedSeparately(t *testing.T) {
	c := newClock()
	p := newPace(t, 1, c)

	_, _, ok := p.Reserve("client-a")
	require.True(t, ok)
	_, _, ok = p.Reserve("client-a")
	require.False(t, ok)

	// Законный близнец: другой идентификатор в ту же секунду проходит.
	_, _, ok = p.Reserve("client-b")
	require.True(t, ok, "исчерпанный темп одного клиента не имеет права задевать другого")
}

// TestConcurrentReservationsNeverExceedThePace — решение и списание одной
// операцией: параллельные запросы не проходят сверх темпа.
func TestConcurrentReservationsNeverExceedThePace(t *testing.T) {
	c := newClock()
	p := newPace(t, 5, c)

	var admitted atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, _, ok := p.Reserve("client-a"); ok {
				admitted.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	require.EqualValues(t, 5, admitted.Load(),
		"«спросить» и «списать» разнесены: параллельные запросы прошли сверх темпа")
}

// TestNewRefusesAnUndeclaredPace — темп без величины и часов не собирается.
func TestNewRefusesAnUndeclaredPace(t *testing.T) {
	c := newClock()
	for _, perSec := range []int{0, -1} {
		_, err := exchangepace.New(perSec, c.Now)
		require.Errorf(t, err, "темп %d обязан отвергать построение: ноль означал бы «без ограничения»", perSec)
	}
	_, err := exchangepace.New(1, nil)
	require.Error(t, err, "часы — вход, а не окружение")

	// Положительный контроль.
	_, err = exchangepace.New(1, c.Now)
	require.NoError(t, err)
}
