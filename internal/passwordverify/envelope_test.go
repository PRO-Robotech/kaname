// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// envelope_test.go — ОГИБАЮЩАЯ ПО ПОТОЛКУ фактической популяции (решение
// kaname#188 по Ф3-31 / ID-PW-1 Р4, PWV-03): калибратор классов стоимости и
// потолок, от которого полоса входа отсчитывает задержку всякого исхода.
//
// Предмет проб — свойства САМОЙ огибающей, не полосы входа (та — в
// `humansession`):
//
//  1. допуск класса КАЛИБРУЕТ его прогоном проверяющего и поднимает потолок,
//     если класс дороже текущего; дешевле — потолок не трогает;
//  2. известный класс второй раз не калибруется: стоимость взята у первого
//     прогона, а не измерена заново — иначе потолок плыл бы с каждым входом;
//  3. класс, который проверяющий не читает (выше потолка записи, чужой формат),
//     не калибруется: ось годности от времени освобождена (Р4), а вычислять
//     выше потолка значило бы платить ту цену, от которой потолок защищает;
//  4. калибровка занимает ЁМКОСТЬ проверяющего: страж старта сверил с пределом
//     памяти ровно `ёмкость × память проверки`, и прогон мимо ёмкости вышел бы
//     за бюджет;
//  5. префикс класса, каким его отдаёт перепись хранилища, разбирается в класс
//     обоими форматами и отвергается на чужом.
package passwordverify_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

func bcryptClass(cost uint32) domain.PasswordCostClass {
	return domain.PasswordCostClass{Format: domain.PasswordHashFormatBcrypt,
		Params: map[domain.PasswordHashCostParam]uint32{domain.CostParamBcryptCost: cost}}
}

func argon2Class(memory, iterations, parallelism uint32) domain.PasswordCostClass {
	return domain.PasswordCostClass{Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory: memory, domain.CostParamArgon2Iterations: iterations,
			domain.CostParamArgon2Parallelism: parallelism}}
}

// recordingEnvelopeObserver — приёмник событий огибающей для проб.
type recordingEnvelopeObserver struct {
	mu         sync.Mutex
	calibrated []string
	triggers   []passwordverify.EnvelopeTrigger
	floors     []time.Duration
}

func (o *recordingEnvelopeObserver) ClassCalibrated(class domain.PasswordCostClass, _ time.Duration, trigger passwordverify.EnvelopeTrigger) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calibrated = append(o.calibrated, class.Key())
	o.triggers = append(o.triggers, trigger)
}

func (o *recordingEnvelopeObserver) EnvelopeFloorObserved(floor time.Duration, _ domain.PasswordCostClass) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.floors = append(o.floors, floor)
}

func newEnvelope(t *testing.T, capacity int) (*passwordverify.Envelope, *passwordverify.Verifier, *recordingEnvelopeObserver) {
	t.Helper()
	v := newVerifier(t, capacity, newRecordingObserver())
	obs := &recordingEnvelopeObserver{}
	e, err := passwordverify.NewEnvelope(v, obs)
	require.NoError(t, err)
	return e, v, obs
}

// TestEnvelope_AdmitCalibratesTheClassAndRaisesTheFloor — пустая огибающая
// не держит ничего; допуск первого класса калибрует его и ставит потолок на
// него; потолок — не меньше самого дорогого прогона калибровки.
func TestEnvelope_AdmitCalibratesTheClassAndRaisesTheFloor(t *testing.T) {
	e, _, obs := newEnvelope(t, 2)
	require.Zero(t, e.Floor(), "до калибровки огибающей нет")
	_, ok := e.Ceiling()
	require.False(t, ok)

	adm, err := e.Admit(context.Background(), bcryptClass(4), passwordverify.EnvelopeTriggerStartup)
	require.NoError(t, err)
	require.True(t, adm.Calibrated, "первый допуск класса — калибровка")
	require.Greater(t, adm.Cost, time.Duration(0))
	require.GreaterOrEqual(t, adm.Floor, adm.Cost, "потолок не ниже стоимости самого дорогого прогона")
	require.Greater(t, adm.Floor, adm.Cost, "запас над стоимостью есть: прогон под нагрузкой длиннее калибровочного")
	require.Equal(t, adm.Floor, e.Floor())

	ceiling, ok := e.Ceiling()
	require.True(t, ok)
	require.Equal(t, bcryptClass(4).Key(), ceiling.Class.Key())
	require.Equal(t, adm.Cost, ceiling.Cost)

	require.Equal(t, []string{bcryptClass(4).Key()}, obs.calibrated)
	require.Equal(t, []passwordverify.EnvelopeTrigger{passwordverify.EnvelopeTriggerStartup}, obs.triggers)
	require.Equal(t, []time.Duration{adm.Floor}, obs.floors, "новый потолок сообщён приёмнику ровно один раз")
}

// TestEnvelope_ADearerClassRaisesTheFloorACheaperOneDoesNot — второй класс
// дороже первого поднимает потолок на себя; третий, дешевле обоих,
// калибруется, но потолка не трогает.
func TestEnvelope_ADearerClassRaisesTheFloorACheaperOneDoesNot(t *testing.T) {
	e, _, obs := newEnvelope(t, 2)
	ctx := context.Background()
	cheap, err := e.Admit(ctx, bcryptClass(4), passwordverify.EnvelopeTriggerStartup)
	require.NoError(t, err)

	dear, err := e.Admit(ctx, bcryptClass(8), passwordverify.EnvelopeTriggerStartup)
	require.NoError(t, err)
	require.True(t, dear.Calibrated)
	require.Greater(t, dear.Cost, cheap.Cost, "стоимость 8 дороже стоимости 4 (вдвое на единицу)")
	require.Greater(t, dear.Floor, cheap.Floor, "потолок поднялся")
	ceiling, ok := e.Ceiling()
	require.True(t, ok)
	require.Equal(t, bcryptClass(8).Key(), ceiling.Class.Key())

	cheaper, err := e.Admit(ctx, argon2Class(8, 1, 1), passwordverify.EnvelopeTriggerRead)
	require.NoError(t, err)
	require.True(t, cheaper.Calibrated, "класс калибруется, даже когда потолка не поднимает: его стоимость — факт огибающей")
	require.Equal(t, dear.Floor, cheaper.Floor, "потолок не опустился")
	require.Equal(t, dear.Floor, e.Floor())
	ceiling, _ = e.Ceiling()
	require.Equal(t, bcryptClass(8).Key(), ceiling.Class.Key(), "потолок — по-прежнему самый дорогой класс")

	classes := e.Classes()
	require.Len(t, classes, 3, "перепись огибающей несёт КАЖДЫЙ калиброванный класс, не только потолок")
	require.Equal(t, []passwordverify.EnvelopeTrigger{
		passwordverify.EnvelopeTriggerStartup, passwordverify.EnvelopeTriggerStartup, passwordverify.EnvelopeTriggerRead,
	}, obs.triggers)
	require.Len(t, obs.floors, 2, "потолок сообщён дважды: первый класс и подъём; третий класс потолка не менял")
}

// TestEnvelope_AKnownClassIsNotCalibratedTwice — повторный допуск известного
// класса отвечает стоимостью первого прогона, не меряя заново.
func TestEnvelope_AKnownClassIsNotCalibratedTwice(t *testing.T) {
	e, _, obs := newEnvelope(t, 2)
	ctx := context.Background()
	first, err := e.Admit(ctx, bcryptClass(5), passwordverify.EnvelopeTriggerStartup)
	require.NoError(t, err)
	require.True(t, first.Calibrated)

	start := time.Now()
	again, err := e.Admit(ctx, bcryptClass(5), passwordverify.EnvelopeTriggerRead)
	elapsed := time.Since(start)
	require.NoError(t, err)
	require.False(t, again.Calibrated, "известный класс — без калибровки")
	require.Equal(t, first.Cost, again.Cost)
	require.Equal(t, first.Floor, again.Floor)
	require.Less(t, elapsed, first.Cost, "повторный допуск — поиск по ключу, а не прогон проверяющего")
	require.Len(t, obs.calibrated, 1)
}

// TestEnvelope_AClassTheVerifierDoesNotReadIsNotCalibrated — выше потолка
// записи и чужой формат — отказ с именем исхода, потолок и перепись не тронуты.
func TestEnvelope_AClassTheVerifierDoesNotReadIsNotCalibrated(t *testing.T) {
	e, _, obs := newEnvelope(t, 2)
	ctx := context.Background()
	base, err := e.Admit(ctx, bcryptClass(4), passwordverify.EnvelopeTriggerStartup)
	require.NoError(t, err)

	_, err = e.Admit(ctx, bcryptClass(15), passwordverify.EnvelopeTriggerStartup)
	require.Error(t, err)
	var unreadable *passwordverify.ClassNotReadableError
	require.ErrorAs(t, err, &unreadable, "отказ типом: вызывающий различает «не читается» от отказа среды")
	require.Equal(t, passwordverify.OutcomeParamsAboveCeiling, unreadable.Outcome)
	require.Equal(t, bcryptClass(15).Key(), unreadable.Class.Key())

	_, err = e.Admit(ctx, domain.PasswordCostClass{Format: "pbkdf2",
		Params: map[domain.PasswordHashCostParam]uint32{"rounds": 1000}}, passwordverify.EnvelopeTriggerStartup)
	require.Error(t, err)
	require.Contains(t, err.Error(), "pbkdf2")

	require.Equal(t, base.Floor, e.Floor(), "потолок не тронут")
	require.Len(t, e.Classes(), 1)
	require.Len(t, obs.calibrated, 1)
}

// TestEnvelope_CalibrationTakesTheVerifierCapacity — калибровка занимает
// место ёмкости: при занятой ёмкости она ЖДЁТ, а не считает мимо бюджета
// памяти; срок ожидания — контекст вызывающего.
func TestEnvelope_CalibrationTakesTheVerifierCapacity(t *testing.T) {
	e, v, _ := newEnvelope(t, 1)

	hold := make(chan struct{})
	held := make(chan struct{})
	go func() {
		v.WithCapacity(func() {
			close(held)
			<-hold
		})
	}()
	<-held

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := e.Admit(ctx, bcryptClass(4), passwordverify.EnvelopeTriggerStartup)
	require.Error(t, err, "ёмкость занята целиком — калибровка не прошла мимо неё")
	require.True(t, errors.Is(err, context.DeadlineExceeded), "отказ — срок ожидания вызывающего, не свой")
	require.Zero(t, e.Floor(), "потолок не выставлен")
	require.Empty(t, e.Classes())

	close(hold)
	adm, err := e.Admit(context.Background(), bcryptClass(4), passwordverify.EnvelopeTriggerStartup)
	require.NoError(t, err, "положительный контроль: ёмкость свободна — калибровка проходит")
	require.True(t, adm.Calibrated)
}

// TestEnvelope_ConcurrentAdmitsOfOneClassCalibrateOnce — два одновременных
// допуска одного класса дают одну калибровку: второй ждёт первую и берёт её
// стоимость.
func TestEnvelope_ConcurrentAdmitsOfOneClassCalibrateOnce(t *testing.T) {
	e, _, obs := newEnvelope(t, 4)
	var wg sync.WaitGroup
	results := make([]passwordverify.Admission, 4)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			adm, err := e.Admit(context.Background(), bcryptClass(6), passwordverify.EnvelopeTriggerRead)
			require.NoError(t, err)
			results[i] = adm
		}(i)
	}
	wg.Wait()
	calibrated := 0
	for _, r := range results {
		if r.Calibrated {
			calibrated++
		}
		require.Equal(t, results[0].Cost, r.Cost, "все получили одну стоимость")
	}
	require.Equal(t, 1, calibrated, "калибровка одна на класс")
	require.Len(t, obs.calibrated, 1)
}

// TestParseCostClassPrefix_ReadsBothFormatsAndRefusesTheRest — префикс класса,
// каким его отдаёт перепись хранилища (значение без соли и тела), разбирается
// обоими форматами; чужой признак, чужая версия разметки и негодная
// стоимость — отказ.
func TestParseCostClassPrefix_ReadsBothFormatsAndRefusesTheRest(t *testing.T) {
	t.Parallel()

	got, err := passwordverify.ParseCostClassPrefix("$2a$12")
	require.NoError(t, err)
	require.Equal(t, bcryptClass(12).Key(), got.Key())

	got, err = passwordverify.ParseCostClassPrefix("$argon2id$v=19$m=65536,t=3,p=4")
	require.NoError(t, err)
	require.Equal(t, argon2Class(65536, 3, 4).Key(), got.Key())

	for _, bad := range []string{
		"", "$", "$pbkdf2$", "$2b$12", "$2a$xx", "$2a$1", "$2a$012",
		"$argon2id$v=18$m=65536,t=3,p=4", "$argon2id$v=19$m=65536,t=3", "$argon2id$v=19$m=65536,t=3,p=4,keyid=1",
		"$argon2id$v=19$m=65536,t=3,p=4$salt", "$2a$12$saltandbody",
	} {
		_, err := passwordverify.ParseCostClassPrefix(bad)
		require.Errorf(t, err, "префикс %q обязан быть отвергнут", bad)
	}
}

// TestEnvelopeTriggers_DictionaryIsClosed — поводов калибровки два: старт и
// чтение неизвестного класса; словарь закрыт и клетки счётчика заводятся из
// него.
func TestEnvelopeTriggers_DictionaryIsClosed(t *testing.T) {
	t.Parallel()
	triggers := passwordverify.EnvelopeTriggers()
	require.Equal(t, []passwordverify.EnvelopeTrigger{passwordverify.EnvelopeTriggerStartup, passwordverify.EnvelopeTriggerRead}, triggers)
	triggers[0] = "tampered"
	require.Equal(t, passwordverify.EnvelopeTriggerStartup, passwordverify.EnvelopeTriggers()[0], "словарь отдаётся копией")
}
