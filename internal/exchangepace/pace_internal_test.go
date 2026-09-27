// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package exchangepace

// pace_internal_test.go — память ведомых идентификаторов ограничена.
//
// Ключ ведра — ЗАЯВЛЕННЫЙ идентификатор, и заявить можно любой. Таблица,
// которая помнит каждый заявленный, росла бы от входа предъявителя, а не от
// числа клиентов. Проба внутренняя: объём таблицы — свойство реализации,
// наружу он не отдаётся.

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func (p *Pace) tracked() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.buckets)
}

// TestRefundedReservationsLeaveNoTrace — возвращённая бронь не оставляет строки.
func TestRefundedReservationsLeaveNoTrace(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	p, err := New(5, func() time.Time { return now })
	require.NoError(t, err)

	for i := 0; i < 1000; i++ {
		refund, _, ok := p.Reserve("claimed-" + strconv.Itoa(i))
		require.True(t, ok)
		refund()
	}
	require.Zero(t, p.tracked(),
		"возвращённые брони обязаны уходить из таблицы: иначе её объём задаёт предъявитель")

	// Законный близнец: удержанная бронь строку ОСТАВЛЯЕТ — иначе темп не
	// помнил бы ничего.
	_, _, ok := p.Reserve("kept")
	require.True(t, ok)
	require.Equal(t, 1, p.tracked())
}

// TestRefilledBucketsAreSwept — пополнившиеся вёдра уходят из таблицы, и её
// объём ограничен теми, кто обменивался за последнюю секунду.
func TestRefilledBucketsAreSwept(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	// Темп 1 в секунду: удержанная бронь пополняется ровно за секунду, и
	// середина горизонта различима с его концом.
	p, err := New(1, func() time.Time { return now })
	require.NoError(t, err)

	for i := 0; i < 1000; i++ {
		_, _, ok := p.Reserve("client-" + strconv.Itoa(i))
		require.True(t, ok)
	}
	require.Equal(t, 1000, p.tracked())

	// Законный близнец: до конца горизонта пополнения вёдра не полны и
	// обязаны оставаться — иначе темп забывал бы обмены, которые считает.
	now = now.Add(500 * time.Millisecond)
	refund, _, ok := p.Reserve("probe")
	require.True(t, ok)
	refund()
	require.Equal(t, 1000, p.tracked(), "неполное ведро убирать нельзя: оно помнит обмен")

	// Горизонт пополнения прошёл: все вёдра полны, и полное ведро неотличимо от
	// отсутствующего.
	now = now.Add(500 * time.Millisecond)
	refund, _, ok = p.Reserve("next")
	require.True(t, ok)
	refund()
	require.Zero(t, p.tracked(),
		"пополнившиеся вёдра обязаны уходить из таблицы за горизонт пополнения")
}
