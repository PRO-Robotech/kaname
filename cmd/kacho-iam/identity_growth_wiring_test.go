// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeIdentityLedger — источник, чей исход задаёт проба.
type fakeIdentityLedger struct {
	total int64
	err   error
}

func (f *fakeIdentityLedger) IdentitiesEverSeen(context.Context) (int64, error) {
	return f.total, f.err
}

// TestIdentityGrowthSampler_FailedSampleDoesNotDropTheValue — отказ замера НЕ
// откатывает величину к нулю.
//
// # Почему это несущее свойство, а не аккуратность
//
// Ряд объявлен СЧЁТЧИКОМ, и витрина считает его монотонным. Падение величины
// читается ею как ПЕРЕЗАПУСК счётчика: `increase()` за окно, в которое попал
// откат, прибавляет всё накопленное заново. Одна недоступность базы на
// пятнадцать секунд превращалась бы во всплеск роста, которого не было, — то
// есть в ложную тревогу ровно на том пороге, ради которого ряд заведён.
//
// Отказ обязан быть виден ОТДЕЛЬНОЙ клеткой, а не искажением величины: «замер не
// прошёл» и «личностей стало меньше» — разные утверждения, и второе к тому же
// невозможно.
func TestIdentityGrowthSampler_FailedSampleDoesNotDropTheValue(t *testing.T) {
	ledger := &fakeIdentityLedger{total: 7}
	sampler := newIdentityGrowthSampler(ledger)

	require.NoError(t, sampler.sampleOnce(context.Background()))
	require.Equal(t, int64(7), sampler.Counts().IdentitiesEverSeen,
		"успешный замер не донёс величину: проба ниже прошла бы на любом источнике")

	ledger.err = errors.New("база недоступна")
	ledger.total = 0
	require.Error(t, sampler.sampleOnce(context.Background()))

	counts := sampler.Counts()
	require.Equal(t, int64(7), counts.IdentitiesEverSeen,
		"отказ замера обнулил величину: витрина прочтёт это перезапуском счётчика "+
			"и покажет всплеск роста, которого не было")
	require.Equal(t, uint64(1), counts.SamplesOK,
		"успешные замеры перестали считаться: ноль в величине снова неотличим от "+
			"неработающего замера")
	require.Equal(t, uint64(1), counts.SamplesFailed,
		"отказ замера не сосчитан: мёртвый замерщик молчит так же, как исправный")
}

// TestIdentityGrowthSampler_ZeroIsAValueAndSaysSo — ноль личностей отличим от
// неснятого замера.
//
// Положительная половина пары к предыдущей пробе: величина ноль ЗАКОННА, и
// объявлять её отказом нельзя. Различает эти два состояния только счётчик
// успешных замеров — до первого успеха он ноль, после первого растёт.
func TestIdentityGrowthSampler_ZeroIsAValueAndSaysSo(t *testing.T) {
	sampler := newIdentityGrowthSampler(&fakeIdentityLedger{total: 0})

	before := sampler.Counts()
	require.Zero(t, before.SamplesOK,
		"до первого замера успешные замеры не ноль: различить «ноль личностей» и "+
			"«замер не снят» станет нечем")

	require.NoError(t, sampler.sampleOnce(context.Background()))

	after := sampler.Counts()
	require.Equal(t, int64(0), after.IdentitiesEverSeen,
		"ноль личностей объявлен отказом: законное состояние платформы стало ошибкой")
	require.Equal(t, uint64(1), after.SamplesOK,
		"успешный замер нуля не сосчитан: ноль остался неотличим от неснятого замера")
}
