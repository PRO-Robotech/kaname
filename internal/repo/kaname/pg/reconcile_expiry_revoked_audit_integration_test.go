// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// reconcile_expiry_revoked_audit_integration_test.go — истечение срока выдачи
// пишет аудит снятия той же формы, что отзыв и удаление (kaname#920).
//
// ПРЕДМЕТ. Отзыв и удаление пишут в журнал аудита строку
// `iam.access_binding.revoked` на КАЖДОГО субъекта выдачи, в той же транзакции,
// что снимает выдачу (revokedAuditFor). Истечение срока снимает выдачу тем же
// переходом ACTIVE→REVOKED; без строки аудита след соответствия показывает
// выдачу выданной и никогда не снятой.
//
// ФОРМА — сверяется с НАСТОЯЩИМ отзывом в той же базе, а не с выписанным
// перечнем: вторая выдача того же субъекта на той же области отзывается
// use-case отзыва, и строки обоих сравниваются по виду события, области
// арендатора и составу полей. Различаются лишь те величины, что принадлежат
// выдаче и снимающему: роль, идентификатор выдачи, действующее лицо.
//
// ЗАКОННЫЙ БЛИЗНЕЦ — повторное истечение уже снятой выдачи: перехода нет, и
// второй строки аудита быть не должно.

import (
	"context"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

type revokedAuditRow struct {
	eventType string
	tenant    *string
	payload   map[string]any
}

func revokedAuditRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bid domain.AccessBindingID) []revokedAuditRow {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT event_type, tenant_account_id, event_payload
		  FROM kaname.audit_outbox
		 WHERE event_type = 'iam.access_binding.revoked'
		   AND event_payload->>'binding_id' = $1
		 ORDER BY created_at, id`, string(bid))
	require.NoError(t, err)
	defer rows.Close()
	var out []revokedAuditRow
	for rows.Next() {
		var (
			r   revokedAuditRow
			raw []byte
		)
		require.NoError(t, rows.Scan(&r.eventType, &r.tenant, &raw))
		require.NoError(t, json.Unmarshal(raw, &r.payload))
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

func payloadKeys(p map[string]any) []string {
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestExpireBinding_WritesRevokedAuditLikeRevoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	fx := setupGamma(t, ctx, pool, "au920")
	rec, _ := newReconciler(pool)

	expRole := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "au920exp", domain.Rules{forwardAnchorRule()})
	revRole := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "au920rev", domain.Rules{forwardAnchorRule()})
	expired := insertThinBinding(t, ctx, fx.repo, fx.member, expRole, fx.prj)
	revoked := insertThinBinding(t, ctx, fx.repo, fx.member, revRole, fx.prj)

	// Образец формы — настоящий отзыв второй выдачи того же субъекта.
	revDone := startUseCaseDeactivation(t, ctx, pool, fx, revoked, revokeDeactivation)
	select {
	case err := <-revDone:
		require.NoError(t, err, "ПРЕДПОСЫЛКА: отзыв-образец завершился")
	case <-time.After(2 * expiryRaceBudget):
		t.Fatalf("ПРЕДПОСЫЛКА: отзыв-образец не завершился за %s", 2*expiryRaceBudget)
	}
	want := revokedAuditRows(t, ctx, pool, revoked)
	require.Len(t, want, 1, "ПРЕДПОСЫЛКА: отзыв пишет одну строку аудита снятия на субъекта")

	require.NoError(t, rec.ExpireBinding(ctx, expired))
	require.Equal(t, string(domain.AccessBindingStatusRevoked), bindingStatus(t, ctx, pool, expired),
		"ПРЕДПОСЫЛКА: истечение перевело выдачу в REVOKED")

	got := revokedAuditRows(t, ctx, pool, expired)
	require.Len(t, got, 1, "истечение срока обязано записать строку аудита снятия на субъекта — как отзыв")
	assert.Equal(t, want[0].eventType, got[0].eventType, "вид события — тот же, что у отзыва")
	assert.Equal(t, want[0].tenant, got[0].tenant, "область арендатора — та же, что у отзыва")
	assert.Equal(t, payloadKeys(want[0].payload), payloadKeys(got[0].payload), "состав полей — тот же, что у отзыва")
	for _, k := range []string{"subject_type", "subject_id", "resource_type", "resource_id"} {
		assert.Equal(t, want[0].payload[k], got[0].payload[k], "поле %s — то же, что у отзыва той же области и субъекта", k)
	}
	assert.Equal(t, string(expRole), got[0].payload["role_id"], "роль — снятой выдачи")
	assert.Equal(t, string(expired), got[0].payload["binding_id"], "выдача — снятая")
	assert.NotEmpty(t, got[0].payload["actor"], "действующее лицо названо — след не пуст")

	// Близнец: повторное истечение снятой выдачи перехода не делает и аудита не пишет.
	require.NoError(t, rec.ExpireBinding(ctx, expired))
	assert.Len(t, revokedAuditRows(t, ctx, pool, expired), 1,
		"повторное истечение уже снятой выдачи не пишет второй строки аудита")
}
