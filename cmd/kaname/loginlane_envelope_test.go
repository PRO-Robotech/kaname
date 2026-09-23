// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// loginlane_envelope_test.go — калибровка огибающей по потолку ПРИ СТАРТЕ
// (решение kaname#188 по Ф3-31): перепись классов хранилища ∪ класс ручки «что
// писать», каждый — прогоном проверяющего; потолок — самый дорогой из них.
//
// Что утверждают пробы:
//
//   - каждый читаемый класс переписи калибруется, и потолок — самый дорогой;
//     класс ручки калибруется ВСЕГДА, и на пустом хранилище (свежая посадка)
//     огибающая уже стоит на нём;
//   - строки, чей класс проверяющий не читает (признак вне перечня, негодная
//     стоимость, выше потолка записи), НЕ калибруются и не роняют старт: они
//     считаются и называются в самоотчёте — это находка о хранилище, а не отказ
//     полосы; ось годности от времени освобождена (ID-PW-1 Р4);
//   - класс ручки, который проверяющий не читает, — отказ старта: огибающей,
//     не покрывающей то, что продукт сам пишет, не бывает.
//
// Стоимость классов назначает мера пробы (`assignedMeter`), а не настенные
// часы: предмет проб — КАКИЕ классы калибруются и КОТОРЫЙ из них становится
// потолком, а порядок стоимостей, измеренный часами, переворачивается одной
// задержкой планировщика в замере дешёвого класса (под конкуренцией за
// процессор потолком становился bcrypt 4 вместо bcrypt 6). Прогон
// проверяющего при этом исполняется по-настоящему — отброшено только его
// время.
package main

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/loginmethod"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

type silentVerifyObserver struct{}

func (silentVerifyObserver) VerificationObserved(passwordverify.Outcome) {}

// assignedMeter — мера пробы: стоимость класса назначена пробой. Класс без
// назначенной стоимости — провал пробы, а не нулевая стоимость.
type assignedMeter struct {
	t     *testing.T
	mu    sync.Mutex
	costs map[string]time.Duration
}

func (m *assignedMeter) measure(class domain.PasswordCostClass, verify func()) time.Duration {
	verify()
	m.mu.Lock()
	defer m.mu.Unlock()
	cost, ok := m.costs[class.Key()]
	if !ok {
		m.t.Errorf("мера пробы: стоимость класса %s не назначена", class.Key())
	}
	return cost
}

// envelopeForProbe — огибающая на мере пробы; стоимости — по ключу класса
// (`PasswordCostClass.Key`).
func envelopeForProbe(t *testing.T, costs map[string]time.Duration) *passwordverify.Envelope {
	t.Helper()
	v, err := passwordverify.New(2, silentVerifyObserver{})
	require.NoError(t, err)
	meter := &assignedMeter{t: t, costs: costs}
	e, err := passwordverify.NewEnvelope(v, passwordverify.NopEnvelopeObserver{}, meter.measure)
	require.NoError(t, err)
	return e
}

// censusCosts — стоимости классов переписи и ручки, в соотношении настоящих:
// bcrypt вдвое на единицу стоимости, argon2id на 8 КиБ — десятки микросекунд.
func censusCosts() map[string]time.Duration {
	return map[string]time.Duration{
		bcryptClassOf(4).Key():       time.Millisecond,
		bcryptClassOf(6).Key():       4 * time.Millisecond,
		argon2ClassOf(8, 1, 1).Key(): 50 * time.Microsecond,
	}
}

func bcryptClassOf(cost uint32) domain.PasswordCostClass {
	return domain.PasswordCostClass{Format: domain.PasswordHashFormatBcrypt,
		Params: map[domain.PasswordHashCostParam]uint32{domain.CostParamBcryptCost: cost}}
}

func argon2ClassOf(memory, iterations, parallelism uint32) domain.PasswordCostClass {
	return domain.PasswordCostClass{Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory: memory, domain.CostParamArgon2Iterations: iterations,
			domain.CostParamArgon2Parallelism: parallelism}}
}

// TestLoginLane_188_EnvelopeIsCalibratedOnThePopulationAndTheKnob — перепись с
// тремя читаемыми классами и тремя нечитаемыми префиксами: калибруются три,
// потолок — самый дорогой; нечитаемое сосчитано, а не уронило старт.
func TestLoginLane_188_EnvelopeIsCalibratedOnThePopulationAndTheKnob(t *testing.T) {
	e := envelopeForProbe(t, censusCosts())
	census := []loginmethod.CostClassCount{
		{Prefix: "$2a$04", Rows: 2},
		{Prefix: "$2a$06", Rows: 1},
		{Prefix: "$argon2id$v=19$m=8,t=1,p=1", Rows: 3},
		{Prefix: "", Rows: 2},       // признак вне перечня
		{Prefix: "$2a$15", Rows: 1}, // выше потолка записи — вычисление не начинается (Р4)
		{Prefix: "$2a$xx", Rows: 1}, // стоимость не разбирается
	}
	report, err := calibrateLoginEnvelope(context.Background(), e, census, argon2ClassOf(8, 1, 1), slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	require.EqualValues(t, 10, report.RowsCounted)
	require.Equal(t, 3, report.ClassesCalibrated, "три читаемых класса переписи; класс ручки среди них — калибруется один раз")
	require.EqualValues(t, 4, report.UnreadableRows)
	require.Equal(t, 3, report.UnreadablePrefixes)

	require.Len(t, e.Classes(), 3)
	ceiling, ok := e.Ceiling()
	require.True(t, ok)
	require.Equal(t, bcryptClassOf(6).Key(), ceiling.Class.Key(), "потолок — самый дорогой класс популяции, а не класс ручки")
	require.Equal(t, 4*time.Millisecond, ceiling.Cost)
	require.Equal(t, 5*time.Millisecond, e.Floor(), "потолок — стоимость самого дорогого класса с запасом в четверть")
	require.Equal(t, e.Floor(), report.Floor)
	require.Equal(t, ceiling.Class.Key(), report.CeilingClass)
}

// TestLoginLane_188_TheKnobIsTheCeilingWhenItIsTheDearest — законный близнец
// пробы выше: та же перепись, но класс ручки дороже всей популяции — потолок
// на нём. Вместе они различают выбор ПО СТОИМОСТИ от выбора по месту класса в
// порядке калибровки (ручка калибруется последней).
func TestLoginLane_188_TheKnobIsTheCeilingWhenItIsTheDearest(t *testing.T) {
	costs := censusCosts()
	costs[argon2ClassOf(8, 1, 1).Key()] = 9 * time.Millisecond
	e := envelopeForProbe(t, costs)
	census := []loginmethod.CostClassCount{
		{Prefix: "$2a$04", Rows: 2},
		{Prefix: "$2a$06", Rows: 1},
	}
	report, err := calibrateLoginEnvelope(context.Background(), e, census, argon2ClassOf(8, 1, 1), slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	require.Equal(t, 3, report.ClassesCalibrated)
	ceiling, ok := e.Ceiling()
	require.True(t, ok)
	require.Equal(t, argon2ClassOf(8, 1, 1).Key(), ceiling.Class.Key(), "класс ручки дороже популяции — потолок на нём")
	require.Equal(t, 9*time.Millisecond+9*time.Millisecond/4, report.Floor)
	require.Equal(t, ceiling.Class.Key(), report.CeilingClass)
}

// TestLoginLane_188_FreshInstallationIsCalibratedOnTheKnobAlone — пустое
// хранилище: огибающая стоит на классе ручки.
func TestLoginLane_188_FreshInstallationIsCalibratedOnTheKnobAlone(t *testing.T) {
	e := envelopeForProbe(t, censusCosts())
	report, err := calibrateLoginEnvelope(context.Background(), e, nil, bcryptClassOf(4), slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	require.Zero(t, report.RowsCounted)
	require.Equal(t, 1, report.ClassesCalibrated)
	require.Greater(t, e.Floor(), time.Duration(0))
	ceiling, ok := e.Ceiling()
	require.True(t, ok)
	require.Equal(t, bcryptClassOf(4).Key(), ceiling.Class.Key())
}

// TestLoginLane_188_AnUnreadableKnobClassRefusesTheStart — класс ручки, который
// проверяющий не читает, — отказ, называющий класс.
func TestLoginLane_188_AnUnreadableKnobClassRefusesTheStart(t *testing.T) {
	e := envelopeForProbe(t, censusCosts())
	_, err := calibrateLoginEnvelope(context.Background(), e, nil, bcryptClassOf(15), slog.New(slog.DiscardHandler))
	require.Error(t, err)
	require.Contains(t, err.Error(), bcryptClassOf(15).Key())
	require.Zero(t, e.Floor())
}
