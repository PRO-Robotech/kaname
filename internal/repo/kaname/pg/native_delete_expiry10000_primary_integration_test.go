// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// Вызывается прежний измеритель и точка исходного отчёта без изменения посева,
// materialization, SQL30s или pass120s. Это отдельный gate, а не полный отчёт.
func TestNativeDeleteExpiry10000_OriginalPrimaryConverges(t *testing.T) {
	skipShort(t)
	var point wdPoint
	matches := 0
	for _, p := range wdBandPoints {
		if p.Objects == 10000 && p.Rules == 1 && p.Fanout == 0 && !p.Seeded {
			point = p
			matches++
		}
	}
	require.Equal(t, 1, matches, "исходная точка expiry10000 должна быть единственной")
	r := runBandPoint(t, context.WithValue(context.Background(), expiryActivityKey{}, true), "удаление истечением срока", point, bandExpire)
	require.Equal(t, passConverged, r.outcome, "первичная ошибка/тайм-аут сохраняет RED: %s", r.detail)
	require.Zero(t, r.census.MembersActive)
	require.Zero(t, r.census.MembersRejected)
	require.Zero(t, r.census.MembersOther)
	require.Zero(t, r.census.LedgerRows)
	require.Equal(t, int64(point.Objects), r.census.MirrorObjects)
	require.Zero(t, r.census.LockFPCollisions)
	// Прежняя фикстура даёт пять bootstrap events, по одному write и delete на
	// каждый объект. R381 до отката удаления оставлял ровно 10005 outbox rows.
	require.Equal(t, int64(2*point.Objects+5), r.census.FGAOutbox)
	t.Logf("ORIGINAL_EXPIRY10000_GREEN elapsed=%s statements=%d census=%+v; full18reportNOTPROVEN", r.elapsed, r.stmts, r.census)
}
