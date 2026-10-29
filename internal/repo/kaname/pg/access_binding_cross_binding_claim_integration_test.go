// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// access_binding_cross_binding_claim_integration_test.go — кто ДЕРЖИТ прямой
// факт, когда строка снятия его касается (kaname#919).
//
// WHY IT EXISTS. The emitted-tuple ledger is keyed PER BINDING (binding_id,
// fga_user, relation, object), а сам ФАКТ отношения не счётный: его ключ —
// (объект, отношение, субъект), без выдачи. Две выдачи ОДНОМУ субъекту на ОДНУ
// область держат ДВЕ строки ведомости на ОДИН живой факт. Снос, снимающий факт по
// своей ведомости, поэтому снимал бы доступ, который другая ДЕЙСТВУЮЩАЯ выдача
// продолжает давать.
//
// Прежде вопрос задавало приложение — чтением ведомостей соседей до вставки строки
// снятия (SelectTuplesClaimedByOtherActiveBindings), и ответ устаревал раньше, чем
// применялся. Теперь его задаёт свёртка строки снятия под замком строки факта
// (миграция 20261019180000). Три свойства, которые держала проба запроса, держит
// свёртка, и проверяются они здесь на ней:
//   - факт, который записан в ведомости ДЕЙСТВУЮЩЕЙ выдачи, строка снятия не снимает;
//   - ведомость ОТОЗВАННОЙ выдачи факт не держит — снятие последнего держателя
//     действует;
//   - факт, которого не держит никто, снимается (иначе ноль выше ни о чём).

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/domain"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// journalRows кладёт строки журнала через порт писателя выдачи — тем же путём,
// что use-case выдачи и снятия.
func journalRows(t *testing.T, ctx context.Context, repo *kanamepg.Repository, del bool, tuples ...repoab.RelationTuple) {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	if del {
		require.NoError(t, w.AccessBindingsW().EmitRelationDelete(ctx, tuples))
	} else {
		require.NoError(t, w.AccessBindingsW().EmitRelationWrite(ctx, tuples))
	}
	require.NoError(t, w.Commit(ctx))
}

func directFact(t *testing.T, ctx context.Context, pool *pgxpool.Pool, k repoab.RelationTuple) bool {
	t.Helper()
	typ, id, ok := strings.Cut(k.Object, ":")
	require.True(t, ok)
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kaname.relation_fact
		 WHERE object_type = $1 AND object_id = $2 AND relation = $3 AND subject = $4`,
		typ, id, k.Relation, k.User).Scan(&n))
	return n > 0
}

func TestABEmittedTuples_CrossBindingClaim_OnlyActiveBindingsKeepAFactAlive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "xclaim")
	acc := seedAccount(t, ctx, repo, "acc-xclaim", uid)

	// TWO bindings of the SAME subject on the SAME scope. Different roles, because
	// the partial UNIQUE access_bindings_active_grant_uniq forbids a duplicate ACTIVE
	// 5-tuple — which is exactly why the shared-tuple class exists at all: distinct
	// bindings whose emitted sets OVERLAP.
	abA := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: domain.SystemViewerRoleID, ResourceType: "account", ResourceID: string(acc.ID),
	})
	abB := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: domain.SystemAdminRoleID, ResourceType: "account", ResourceID: string(acc.ID),
	})

	shared := repoab.RelationTuple{User: "user:" + string(uid), Relation: "editor", Object: "account:" + string(acc.ID)}
	// Факт, которого не записала ни одна ведомость.
	unheld := repoab.RelationTuple{User: "user:" + string(uid), Relation: "viewer", Object: "account:" + string(acc.ID)}

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().InsertEmittedTuples(ctx, abA.ID, []repoab.RelationTuple{shared}))
	require.NoError(t, w.AccessBindingsW().InsertEmittedTuples(ctx, abB.ID, []repoab.RelationTuple{shared}))
	require.NoError(t, w.Commit(ctx))
	journalRows(t, ctx, repo, false, shared, unheld)
	require.True(t, directFact(t, ctx, pool, shared), "ПРЕДПОСЫЛКА: запись общего кортежа легла фактом")
	require.True(t, directFact(t, ctx, pool, unheld), "ПРЕДПОСЫЛКА: запись кортежа без держателя легла фактом")

	// Обе выдачи действуют: строка снятия факт не снимает.
	journalRows(t, ctx, repo, true, shared)
	require.True(t, directFact(t, ctx, pool, shared), "факт, который держат две действующие выдачи, снят строкой снятия")

	// B отозвана: факт держит одна A.
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w2.AccessBindingsW().RevokeGuarded(ctx, abB.ID, uid)
	require.NoError(t, err)
	require.NoError(t, w2.Commit(ctx))
	journalRows(t, ctx, repo, true, shared)
	require.True(t, directFact(t, ctx, pool, shared), "факт, который держит действующая A, снят строкой снятия")

	// A отозвана: держателей нет — снятие последнего действует.
	w3, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w3.AccessBindingsW().RevokeGuarded(ctx, abA.ID, uid)
	require.NoError(t, err)
	require.NoError(t, w3.Commit(ctx))
	journalRows(t, ctx, repo, true, shared)
	require.False(t, directFact(t, ctx, pool, shared),
		"ведомость ОТОЗВАННОЙ выдачи держит факт — снятие последнего держателя не действует")

	// Близнец: факт без держателя та же строка снимает с первого раза.
	journalRows(t, ctx, repo, true, unheld)
	require.False(t, directFact(t, ctx, pool, unheld), "факт без держателя строка снятия не сняла — свёртка не снимает вовсе")
}
