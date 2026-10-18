// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// checkcost_test.go — СТОИМОСТЬ ОДНОЙ ПРОВЕРКИ на этом железе (kaname#882):
// величина, из которой композиционный корень выводит срок операции церемонии,
// учитывающий очередь проверок на процессоре.
//
// Свойства:
//
//  1. стоимость — самый дорогой из прогонов класса ПРИМАНКИ (класс,
//     которым хешер пишет и секрет клиента), каждый под мерой вызывающего;
//  2. без приманки стоимость не меряется: мерить нечем, и угаданный класс
//     дал бы срок о чужой цене;
//  3. прогон замера занимает ЁМКОСТЬ проверяющего и ждёт её не дольше срока
//     вызывающего: замер мимо ёмкости вышел бы за бюджет памяти;
//  4. исходы замера НЕ уходят приёмнику исходов проверяющего: сосчитанные,
//     они читались бы как поток неверных паролей при каждом старте.
package passwordverify_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// alignedVerifier — проверяющий с приманкой класса argon2id (8 КиБ, 1, 1):
// класс дешёвый (ниже пола записи, но читаемый — приманку ставит не хешер
// пробы), а путь вычисления — тот же, что у класса службы.
func alignedVerifier(t *testing.T, capacity int, obs passwordverify.Observer) *passwordverify.Verifier {
	t.Helper()
	v := newVerifier(t, capacity, obs)
	decoy := verifierOf(t, argon2idValue(t, "decoy of the check cost probe", 8, 1, 1, 32))
	require.NoError(t, v.SetDecoy(decoy), "фикстура НЕ ПОСТРОЕНА: приманка не встала")
	return v
}

// sequenceMeter — мера с назначенными по порядку стоимостями: прогон
// исполняется по-настоящему, отброшено только его время.
type sequenceMeter struct {
	costs   []time.Duration
	classes []string
}

func (m *sequenceMeter) measure(class domain.PasswordCostClass, verify func()) time.Duration {
	verify()
	cost := m.costs[len(m.classes)%len(m.costs)]
	m.classes = append(m.classes, class.Key())
	return cost
}

// TestCheckCost_IsTheCostliestRunOfTheDecoyClass — свойство 1 и 4.
func TestCheckCost_IsTheCostliestRunOfTheDecoyClass(t *testing.T) {
	obs := newRecordingObserver()
	v := alignedVerifier(t, 2, obs)
	meter := &sequenceMeter{costs: []time.Duration{
		3 * time.Millisecond, 9 * time.Millisecond, 5 * time.Millisecond, 4 * time.Millisecond, 2 * time.Millisecond}}

	cost, err := v.CheckCost(context.Background(), meter.measure)
	require.NoError(t, err)
	require.Equal(t, 9*time.Millisecond, cost, "стоимость — самый дорогой прогон, а не последний и не средний")
	require.GreaterOrEqual(t, len(meter.classes), len(meter.costs), "прогонов меньше, чем назначенных стоимостей: максимум взят не из всех")
	want := argon2Class(8, 1, 1).Key()
	for i, key := range meter.classes {
		require.Equalf(t, want, key, "прогон %d мерил класс %s, а приманка — класса %s", i, key, want)
	}
	for _, o := range passwordverify.OutcomeNames() {
		require.Zerof(t, obs.count(passwordverify.Outcome(o)), "исход %s замера дошёл до приёмника проверяющего", o)
	}
}

// TestCheckCost_WithoutADecoyIsRefused — свойство 2; близнец — тот же
// проверяющий с приманкой меряется.
func TestCheckCost_WithoutADecoyIsRefused(t *testing.T) {
	bare := newVerifier(t, 2, newRecordingObserver())
	_, err := bare.CheckCost(context.Background(), passwordverify.WallClockCostMeter)
	require.Error(t, err, "проверяющий без приманки: класс замера угадывался бы")

	cost, err := alignedVerifier(t, 2, newRecordingObserver()).CheckCost(context.Background(), passwordverify.WallClockCostMeter)
	require.NoError(t, err, "близнец: с приманкой замер обязан состояться")
	require.Positive(t, cost)
}

// TestCheckCost_TakesCapacityAndWaitsNoLongerThanTheCaller — свойство 3:
// ёмкость занята целиком — замер ждёт места и отказывает по сроку вызывающего;
// место освободилось — замер идёт.
func TestCheckCost_TakesCapacityAndWaitsNoLongerThanTheCaller(t *testing.T) {
	v := alignedVerifier(t, 1, newRecordingObserver())
	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan bool)
	go func() { done <- v.WithCapacity(func() { close(held); <-release }) }()
	<-held

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := v.CheckCost(ctx, passwordverify.WallClockCostMeter)
	require.Error(t, err, "ёмкость занята, а замер прошёл мимо неё")
	require.Truef(t, errors.Is(err, context.DeadlineExceeded), "отказ замера не по сроку вызывающего: %v", err)

	close(release)
	require.True(t, <-done)
	cost, err := v.CheckCost(context.Background(), passwordverify.WallClockCostMeter)
	require.NoError(t, err, "место свободно — замер обязан состояться")
	require.Positive(t, cost)
}
