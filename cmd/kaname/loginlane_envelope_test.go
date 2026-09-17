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
package main

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/loginmethod"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

type silentVerifyObserver struct{}

func (silentVerifyObserver) VerificationObserved(passwordverify.Outcome) {}

func envelopeForProbe(t *testing.T) *passwordverify.Envelope {
	t.Helper()
	v, err := passwordverify.New(2, silentVerifyObserver{})
	require.NoError(t, err)
	e, err := passwordverify.NewEnvelope(v, passwordverify.NopEnvelopeObserver{})
	require.NoError(t, err)
	return e
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
	e := envelopeForProbe(t)
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
	require.Greater(t, e.Floor(), ceiling.Cost)
	require.Equal(t, e.Floor(), report.Floor)
	require.Equal(t, ceiling.Class.Key(), report.CeilingClass)
}

// TestLoginLane_188_FreshInstallationIsCalibratedOnTheKnobAlone — пустое
// хранилище: огибающая стоит на классе ручки.
func TestLoginLane_188_FreshInstallationIsCalibratedOnTheKnobAlone(t *testing.T) {
	e := envelopeForProbe(t)
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
	e := envelopeForProbe(t)
	_, err := calibrateLoginEnvelope(context.Background(), e, nil, bcryptClassOf(15), slog.New(slog.DiscardHandler))
	require.Error(t, err)
	require.Contains(t, err.Error(), bcryptClassOf(15).Key())
	require.Zero(t, e.Floor())
}
