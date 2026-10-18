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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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
