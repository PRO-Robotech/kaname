// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_deadline_test.go — срок операции церемонии учитывает очередь
// проверок секрета на процессоре (kaname#882).
//
// Проверка секрета клиента — вычисление argon2id, отмены не знающее. Все места
// ёмкости проверяющего (вход людей и сверка церемонии) ждут места вычисления по
// очереди; занятые разом, они кончаются не позже, чем ёмкость × стоимость одной
// проверки, измеренной в одиночку на тех же процессорах. Срок операции,
// считавший каждый вызов «оператором базы порядка миллисекунды», отказывал по
// сроку всем одновременным обменам разом.
package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// TestCeremonyOperationDeadline_CoversAFullQueueOfChecks — срок — два предела
// вызова базы плюс ёмкость × стоимость одной проверки (запас уже в стоимости:
// потолок огибающей); растёт с ёмкостью и со стоимостью.
func TestCeremonyOperationDeadline_CoversAFullQueueOfChecks(t *testing.T) {
	const cost = 200 * time.Millisecond
	for _, capacity := range []int{1, 2, 8, 32} {
		got, err := ceremonyOperationDeadline(capacity, cost)
		require.NoErrorf(t, err, "ёмкость %d", capacity)
		queue := time.Duration(capacity) * cost
		require.GreaterOrEqualf(t, got, 2*credentialLanePeerTimeout+queue,
			"ёмкость %d: срок %v не покрывает очередь проверок %v сверх двух пределов вызова базы", capacity, got, queue)
		require.Equalf(t, 2*credentialLanePeerTimeout+queue, got,
			"ёмкость %d: срок — два предела вызова базы плюс очередь проверок", capacity)
	}
	small, err := ceremonyOperationDeadline(2, cost)
	require.NoError(t, err)
	costly, err := ceremonyOperationDeadline(2, 4*cost)
	require.NoError(t, err)
	require.Greater(t, costly, small, "дороже проверка — длиннее срок")
}

// TestCeremonyOperationDeadline_RefusesWhatItCannotCount — неположительная
// стоимость или ёмкость — отказ сборки, а не срок без очереди.
func TestCeremonyOperationDeadline_RefusesWhatItCannotCount(t *testing.T) {
	for _, c := range []struct {
		capacity int
		cost     time.Duration
	}{{0, time.Millisecond}, {-1, time.Millisecond}, {2, 0}, {2, -time.Millisecond}} {
		_, err := ceremonyOperationDeadline(c.capacity, c.cost)
		require.Errorf(t, err, "ёмкость %d, стоимость %v: срок без очереди собран", c.capacity, c.cost)
	}
}

// TestLoginLaneSecretCheckCost_IsTheCalibratedEnvelopeFloor — стоимость
// проверки, из которой корень выводит срок операции церемонии, — потолок
// огибающей полосы входа, откалиброванный при старте, а не иная величина. Мера
// пробы назначает классу стоимость 40 мс: потолок с запасом в четверть — 50 мс,
// и ровно его полоса отдаёт церемонии. Полоса без огибающей либо с пустой
// огибающей отдаёт ноль, и срок из него не собирается
// (TestCeremonyOperationDeadline_RefusesWhatItCannotCount).
func TestLoginLaneSecretCheckCost_IsTheCalibratedEnvelopeFloor(t *testing.T) {
	class := argon2ClassOf(8, 1, 1)
	costs := map[string]time.Duration{class.Key(): 40 * time.Millisecond}
	e := envelopeForProbe(t, costs)
	_, err := e.Admit(context.Background(), class, passwordverify.EnvelopeTriggerStartup)
	require.NoError(t, err)

	lane := &loginLane{envelope: e}
	require.Equal(t, 50*time.Millisecond, lane.secretCheckCost(),
		"стоимость проверки для срока церемонии — потолок огибающей (40 мс с запасом в четверть)")
	deadline, err := ceremonyOperationDeadline(16, lane.secretCheckCost())
	require.NoError(t, err)
	require.Equal(t, 2*credentialLanePeerTimeout+16*50*time.Millisecond, deadline,
		"срок операции корня — из стоимости, которую отдаёт полоса входа")

	require.Zero(t, (&loginLane{envelope: envelopeForProbe(t, costs)}).secretCheckCost(),
		"пустая огибающая: стоимость не откалибрована")
	require.Zero(t, (&loginLane{}).secretCheckCost(), "огибающей нет — стоимости нет")
	var none *loginLane
	require.Zero(t, none.secretCheckCost(), "полосы нет — стоимости нет")
}
