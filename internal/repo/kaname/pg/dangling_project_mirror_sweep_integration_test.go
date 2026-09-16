// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// dangling_project_mirror_sweep_integration_test.go — проход по строкам
// зеркала, чей проект НАЗВАН и не резолвится (стадия S2 приёмки
// `non-empty-project-is-not-deleted.md`: IAM-PNE-2-01, 2-02, 2-03 полоса В).
//
// # Предмет НЕ пересекается с действующим проходом зеркала
//
// Сосед (`orphan_mirror_sweep`) берёт строки, у которых родитель не назван
// ВОВСЕ — обе колонки пусты. Здесь — строки, у которых `parent_project_id`
// назван, а строки `kaname.projects` с таким id нет: остаток, который отказ по
// непустоте по построению не закрывает (окно доставки регистрации, §7.1).
//
// # Что проход делает и чего НЕ делает
//
// Называет строку видом и идентификатором и печатает перепись. НИЧЕГО не
// удаляет и родителя не выдумывает: родителя чужого ресурса знает владелец, а
// спросить его служба не может — она лист. Второе доказывается пробой с цепью
// предков к ЖИВОМУ проекту: без неё «починке» нечего записать, и проход,
// выводящий родителя из цепи, был бы неотличим от честного (§0.2в, Н11).
//
// # Потолок — обе стороны оси
//
// У соседа признак «потолок достигнут» стоит уже НА потолке при нулевом
// остатке, а «сирот» у него — длина выборки (§0.2в, Н19). Здесь три мира на
// одной оси — N−1, N, N+1 — и точные значения обеих величин в каждом.

import (
	"context"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func newDanglingSweeper(pool *pgxpool.Pool, maxRows int) *seed.DanglingProjectMirrorSweeper {
	return seed.NewDanglingProjectMirrorSweeper(
		kanamepg.NewDanglingProjectMirrorAdapter(pool),
		seed.DanglingProjectMirrorConfig{MaxRowsPerRun: maxRows},
	)
}

// insertDanglingMirrorRow кладёт строку зеркала с НАЗВАННЫМ родителем, которому
// не отвечает ни одна строка проектов, и возвращает её идентификатор.
func insertDanglingMirrorRow(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objectType string) (objectID, ghost string) {
	t.Helper()
	ghost = ids.NewID("prj")
	objectID = "obj-" + ids.NewID("pne")
	_, err := pool.Exec(ctx,
		`INSERT INTO kaname.resource_mirror (object_type, object_id, parent_project_id, parent_account_id, labels)
		 VALUES ($1, $2, $3, '', '{}'::jsonb)`, objectType, objectID, ghost)
	require.NoError(t, err)
	return objectID, ghost
}

func mirrorRowParents(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objectID string) (project, account string, present bool) {
	t.Helper()
	err := pool.QueryRow(ctx,
		`SELECT parent_project_id, parent_account_id FROM kaname.resource_mirror WHERE object_id = $1`,
		objectID).Scan(&project, &account)
	if err != nil {
		return "", "", false
	}
	return project, account, true
}

// ── IAM-PNE-2-01 — сирота обнаруживается и НАЗЫВАЕТСЯ ────────────────────────

func TestDanglingProjectMirrorSweep_PNE_2_01(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	// Дерево без осиротевших строк: проход ПРОХОДИТ и печатает M = 0.
	clean, err := newDanglingSweeper(pool, 100).RunOnce(ctx)
	require.NoError(t, err)
	require.True(t, clean.Executed)
	require.Equal(t, 0, clean.Orphans, "чистое дерево: %s", clean.Census())
	require.Empty(t, clean.Named)
	require.Contains(t, clean.Census(), "осиротевших 0")

	// Сирота и положительный контроль — строка с ЖИВЫМ проектом.
	orphanID, ghost := insertDanglingMirrorRow(t, ctx, pool, "vpc.network")
	_, livePrj := seedAccountProjectForMirror(t, ctx, pool, "pne201")
	liveID := "obj-" + ids.NewID("pne")
	_, err = pool.Exec(ctx,
		`INSERT INTO kaname.resource_mirror (object_type, object_id, parent_project_id, parent_account_id, labels)
		 VALUES ('vpc.network', $1, $2, '', '{}'::jsonb)`, liveID, livePrj)
	require.NoError(t, err)

	res, err := newDanglingSweeper(pool, 100).RunOnce(ctx)
	require.NoError(t, err)
	require.True(t, res.Executed)
	require.Equal(t, 2, res.MirrorRows, "строк осмотрено")
	require.Equal(t, 1, res.Orphans, "осиротевших: %s", res.Census())
	require.Len(t, res.Named, 1)
	require.Equal(t, "vpc.network", res.Named[0].ObjectType, "сирота названа видом")
	require.Equal(t, orphanID, res.Named[0].ObjectID, "и идентификатором")
	require.Equal(t, ghost, res.Named[0].ParentProjectID, "и родителем, которого нет")
	for _, row := range res.Named {
		require.NotEqual(t, liveID, row.ObjectID, "строка с живым проектом НЕ названа")
	}
	require.Contains(t, res.Census(), "строк осмотрено 2")
	require.Contains(t, res.Census(), "осиротевших 1")
	require.False(t, res.Truncated, "потолок не достигнут при 1 сироте и потолке 100")
}

// ── IAM-PNE-2-02 — проход НИЧЕГО не удаляет и родителя не выдумывает ─────────

func TestDanglingProjectMirrorSweep_PNE_2_02(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	orphanID, ghost := insertDanglingMirrorRow(t, ctx, pool, "vpc.network")
	// Цепь предков ведёт к ЖИВОМУ проекту — источник, из которого догадка
	// родителя могла бы вывести.
	_, livePrj := seedAccountProjectForMirror(t, ctx, pool, "pne202")
	insertParentEdge(t, ctx, pool, "vpc_network", orphanID, "project", livePrj, 1)

	res, err := newDanglingSweeper(pool, 100).RunOnce(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, res.Orphans, "%s", res.Census())

	project, account, present := mirrorRowParents(t, ctx, pool, orphanID)
	require.True(t, present, "строка на месте — проход ничего не удаляет")
	require.Equal(t, ghost, project, "колонка родителя-проекта не тронута: родитель не выдуман из цепи")
	require.Equal(t, "", account, "колонка родителя-аккаунта не тронута")
	var edges int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.resource_parent_edge WHERE object_id = $1`, orphanID).Scan(&edges))
	require.Equal(t, 1, edges, "цепь предков не тронута")
}

// ── IAM-PNE-2-03 полоса В — потолок и перепись, обе стороны оси ──────────────

func TestDanglingProjectMirrorSweep_PNE_2_03V(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	const limit = 3

	worlds := []struct {
		name      string
		orphans   int
		named     int
		truncated bool
	}{
		{"N − 1", limit - 1, limit - 1, false},
		{"ровно N", limit, limit, false},
		{"N + 1", limit + 1, limit, true},
	}
	for _, w := range worlds {
		t.Run(w.name, func(t *testing.T) {
			pool, err := coredb.NewPool(ctx, setupTestDB(t))
			require.NoError(t, err)
			defer pool.Close()
			for i := 0; i < w.orphans; i++ {
				insertDanglingMirrorRow(t, ctx, pool, "vpc.network")
			}
			res, err := newDanglingSweeper(pool, limit).RunOnce(ctx)
			require.NoError(t, err)
			require.True(t, res.Executed)
			require.Equal(t, w.orphans, res.Orphans, "сколько сирот — отдельный счёт, не длина выборки: %s", res.Census())
			require.Len(t, res.Named, w.named, "названо столько, сколько сирот, но не больше потолка")
			require.Equal(t, w.truncated, res.Truncated, "признак «потолок достигнут» — только когда сирот больше, чем названо: %s", res.Census())
			require.Contains(t, res.Census(), "осиротевших "+strconv.Itoa(w.orphans))
			require.Contains(t, res.Census(), "названо "+strconv.Itoa(w.named))
			if w.truncated {
				require.Contains(t, res.Census(), "потолок достигнут")
			} else {
				require.NotContains(t, res.Census(), "потолок достигнут")
			}
		})
	}
}
