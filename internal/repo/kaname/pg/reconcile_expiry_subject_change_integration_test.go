// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// reconcile_expiry_subject_change_integration_test.go — истечение срока выдачи
// пишет журнал смены субъекта той же формы, что отзыв и удаление (kaname#920).
//
// ПРЕДМЕТ. Журнал смены субъекта читает край: по строке он сбрасывает кэш
// решений субъекта и закрывает его открытые потоки подписки. Отзыв и удаление
// пишут строку в той же транзакции, что снимает выдачу; истечение срока
// снимает выдачу тем же переходом ACTIVE→REVOKED, и без строки журнала край
// о снятии не узнаёт — открытый поток субъекта живёт до своего бюджета.
//
// ФОРМА СТРОКИ — та, что пишет отзыв (`revoke.go`): event_type
// `binding_revoke`, op `binding_delete`, по строке на каждого субъекта выдачи.
//
// ЗАКОННЫЙ БЛИЗНЕЦ — повторное истечение уже снятой выдачи: переход не
// случился, и строки журнала быть не должно (иначе край получал бы сигнал о
// снятии, которого не было, на каждом проходе сведения).

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

type subjectChangeRow struct {
	op, eventType, payloadSubject, payloadType string
}

func subjectChangeRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subjectID string) []subjectChangeRow {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT op, event_type, payload->>'subject_id', coalesce(payload->>'subject_type', '')
		  FROM kaname.subject_change_outbox
		 WHERE subject_id = $1
		 ORDER BY id`, subjectID)
	require.NoError(t, err)
	defer rows.Close()
	var out []subjectChangeRow
	for rows.Next() {
		var r subjectChangeRow
		require.NoError(t, rows.Scan(&r.op, &r.eventType, &r.payloadSubject, &r.payloadType))
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

func TestExpireBinding_WritesSubjectChangeLikeRevoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "sc920")
	rec, _ := newReconciler(pool)

	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "sc920role", domain.Rules{forwardAnchorRule()})
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	before := len(subjectChangeRows(t, ctx, pool, string(fx.member)))

	require.NoError(t, rec.ExpireBinding(ctx, bid))
	require.Equal(t, string(domain.AccessBindingStatusRevoked), bindingStatus(t, ctx, pool, bid),
		"ПРЕДПОСЫЛКА: истечение перевело выдачу в REVOKED")

	got := subjectChangeRows(t, ctx, pool, string(fx.member))[before:]
	require.Len(t, got, 1, "истечение срока обязано записать строку журнала смены субъекта — как отзыв")
	assert.Equal(t, subjectChangeRow{
		op: "binding_delete", eventType: "binding_revoke",
		payloadSubject: string(fx.member), payloadType: string(domain.SubjectTypeUser),
	}, got[0], "строка той же формы, что пишет отзыв")

	// Близнец: повторное истечение снятой выдачи перехода не делает и журнал не пишет.
	require.NoError(t, rec.ExpireBinding(ctx, bid))
	assert.Len(t, subjectChangeRows(t, ctx, pool, string(fx.member))[before:], 1,
		"повторное истечение уже снятой выдачи не пишет второй строки")
}
