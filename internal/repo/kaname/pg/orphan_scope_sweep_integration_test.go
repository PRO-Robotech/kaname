// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// orphan_scope_sweep_integration_test.go — интеграционные пробы разовой уборки
// выдач, чья область УЖЕ УДАЛЕНА (задача #810, продолжение #792).
//
// #792 закрыл ИСТОЧНИК: `Project.Delete` дренирует выдачи своей области в той же
// транзакции. Правка действует вперёд и накопленного не убирает — на стенде в день
// заведения висело 145 выдач на удалённых проектах из 193, все ACTIVE, с 1854
// кортежами в ведомости. Контроль на соседнем пути — 0 из 239 у аккаунта, потому
// что `Account.Delete` свои выдачи дренирует давно.
//
// ЧТО ИМЕННО ВОСПРОИЗВОДИТ ФИКСТУРА. Строка проекта снимается ПРЯМЫМ `DELETE`, без
// дренажа, — ровно то, что делал `Project.Delete` до #792. Синтетической эта
// фикстура не является: у `access_bindings` нет внешнего ключа на `projects`
// (ссылка мягкая, межресурсная), поэтому база за нас ничего не доделывает и выдача
// переживает свою область в состоянии ACTIVE. Именно так накопились те 145 строк.
//
// ПОЧЕМУ ПРОВЕРЯЕТСЯ ОЧЕРЕДЬ, А НЕ ТОЛЬКО СТРОКИ. У ведомости
// `access_binding_emitted_tuples` внешний ключ на выдачу стоит `ON DELETE CASCADE`,
// поэтому её строки уходят САМИ и «ведомость пуста» ничего не доказывает: снять
// строку и оставить доступ живым — форма без содержания ровно того класса, который
// мы ловим в коде. Содержание здесь — намерение снятия в `fga_outbox`, и
// утверждается оно отдельно от строк.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/domain"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// orphanFixture — общая посадка обеих проб: живая область и мёртвая, у каждой своя
// выдача со своей ведомостью выпущенных кортежей.
type orphanFixture struct {
	repo      *kanamepg.Repository
	live      domain.ProjectID
	dead      domain.ProjectID
	bLive     domain.AccessBindingID
	bDead     domain.AccessBindingID
	objLive   string
	objDead   string
	deadRels  []string
	subjectID string
}

func setupOrphanScope(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) orphanFixture {
	t.Helper()
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "orph-own-"+suffix)
	member := mustSeedUser(t, ctx, pool, "orph-mem-"+suffix)
	acc := seedAccount(t, ctx, repo, "orph-acc-"+suffix, owner)
	live := seedProject(t, ctx, repo, acc.ID, "orph-live-"+suffix)
	dead := seedProject(t, ctx, repo, acc.ID, "orph-dead-"+suffix)

	// Системная роль — её присваиваемость триггер `access_bindings_role_assignable_trg`
	// пропускает без разбора области, поэтому фикстура не зависит от правил
	// scoping'а ролей: они не предмет этой пробы.
	const sysViewer = domain.RoleID("rol000000000sysviewer")

	objLive := "iam_project:" + string(live.ID)
	objDead := "iam_project:" + string(dead.ID)
	subject := "user:" + string(member)

	bLive := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: sysViewer, ResourceType: "project", ResourceID: string(live.ID),
	})
	bDead := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: sysViewer, ResourceType: "project", ResourceID: string(dead.ID),
	})

	// Ведомость пишется ТЕМ ЖЕ путём, что и в проде (`InsertEmittedTuples`), а не
	// прямым INSERT: фикстура не вправе быть снисходительнее продукта.
	deadRels := []string{"v_get", "v_update"}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().InsertEmittedTuples(ctx, bLive.ID, []repoab.RelationTuple{
		{User: subject, Relation: "v_get", Object: objLive},
	}))
	require.NoError(t, w.AccessBindingsW().InsertEmittedTuples(ctx, bDead.ID, []repoab.RelationTuple{
		{User: subject, Relation: deadRels[0], Object: objDead},
		{User: subject, Relation: deadRels[1], Object: objDead},
	}))
	require.NoError(t, w.Commit(ctx))

	// Историческое состояние: строка проекта снята БЕЗ дренажа выдач.
	_, err = pool.Exec(ctx, `DELETE FROM kaname.projects WHERE id = $1`, string(dead.ID))
	require.NoError(t, err, "прямое снятие строки проекта — то, что делал Delete до #792")

	// Предпосылка пробы: до уборки висячая выдача ЖИВА. Без этого утверждения
	// зелёный прогон был бы неотличим от прогона, где фикстура не сложилась.
	require.Equal(t, 1, bindingRowCount(t, ctx, pool, bDead.ID),
		"предпосылка: выдача пережила свою область — иначе проверять нечего")
	require.Equal(t, 2, ledgerTupleCount(t, ctx, pool, bDead.ID),
		"предпосылка: ведомость висячей выдачи непуста")

	return orphanFixture{
		repo: repo, live: live.ID, dead: dead.ID,
		bLive: bLive.ID, bDead: bDead.ID,
		objLive: objLive, objDead: objDead, deadRels: deadRels, subjectID: subject,
	}
}

// TestOrphanScope_01_RevokesDeadScope_LeavesLiveScopeIntact — отрицание в паре с
// положительным контролем: уборка снимает выдачу мёртвой области и НЕ трогает
// выдачу живой. Без второй половины «снял всё подряд» читалось бы как успех.
func TestOrphanScope_01_RevokesDeadScope_LeavesLiveScopeIntact(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	f := setupOrphanScope(t, ctx, pool, "01")
	sweeper := newOrphanScopeSweeper(pool, f.repo)

	res, err := sweeper.RunOnce(ctx)
	require.NoError(t, err)

	require.True(t, res.Executed, "единственный прогон обязан быть исполнителем")
	assert.Equal(t, 1, res.ScopesRevoked, "убрана ровно одна область")
	assert.Equal(t, 1, res.BindingsRevoked, "снята ровно одна выдача")
	assert.Equal(t, 2, res.TuplesRetracted, "сняты оба кортежа висячей выдачи")

	// ── мёртвая область: строки нет, ведомости нет, снятие ЭМИТИРОВАНО ──
	assert.Equal(t, 0, bindingRowCount(t, ctx, pool, f.bDead),
		"выдача на удалённом проекте обязана исчезнуть")
	assert.Equal(t, 0, ledgerTupleCount(t, ctx, pool, f.bDead),
		"ведомость висячей выдачи обязана опустеть")
	assert.Equal(t, 1, countFGAOutbox(t, ctx, pool, "fga.tuple.delete", f.objDead),
		"снятие кортежей обязано быть эмитировано в очередь — иначе доступ жив, "+
			"а уборка лишь выглядит исполненной")
	assert.ElementsMatch(t, f.deadRels, fgaOutboxRelations(t, ctx, pool, "fga.tuple.delete", f.objDead),
		"строка снятия обязана нести ВЕСЬ набор отношений субъекта на объекте")

	// ── положительный контроль: живая область не тронута ──
	assert.Equal(t, 1, bindingRowCount(t, ctx, pool, f.bLive),
		"выдача живого проекта обязана уцелеть")
	assert.Equal(t, 1, ledgerTupleCount(t, ctx, pool, f.bLive),
		"ведомость живой выдачи обязана уцелеть")
	assert.Equal(t, 0, countFGAOutbox(t, ctx, pool, "fga.tuple.delete", f.objLive),
		"по живой области снятие не эмитируется")
}

// TestOrphanScope_02_Idempotent — повторный прогон на вычищенном дереве не находит
// ничего и не пишет ничего (пункт 3 предиката снятия #810).
func TestOrphanScope_02_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	f := setupOrphanScope(t, ctx, pool, "02")
	sweeper := newOrphanScopeSweeper(pool, f.repo)

	first, err := sweeper.RunOnce(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, first.ScopesRevoked)
	emittedAfterFirst := countFGAOutbox(t, ctx, pool, "fga.tuple.delete", f.objDead)
	require.Equal(t, 1, emittedAfterFirst)

	second, err := sweeper.RunOnce(ctx)
	require.NoError(t, err)
	assert.True(t, second.Executed, "повтор обязан ИСПОЛНИТЬСЯ, а не пропуститься")
	assert.Equal(t, 0, second.ScopesRevoked, "повтор не находит областей")
	assert.Equal(t, 0, second.BindingsRevoked, "повтор не снимает выдач")
	assert.Equal(t, emittedAfterFirst, countFGAOutbox(t, ctx, pool, "fga.tuple.delete", f.objDead),
		"повтор не пишет в очередь второй раз")
}

// ── вспомогательное: перепись строк, отношений и сборка уборщика ───────────────

// bindingRowCount — есть ли строка выдачи (0 или 1).
func bindingRowCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id domain.AccessBindingID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_bindings WHERE id = $1`, string(id)).Scan(&n))
	return n
}

// fgaOutboxRelations — набор отношений, который несёт строка очереди по объекту.
// Payload держит ЛИБО `relation` (одно), ЛИБО `relations` (набор) — читаются оба,
// иначе проба молча зеленела бы на форме, которой не ждала.
func fgaOutboxRelations(t *testing.T, ctx context.Context, pool *pgxpool.Pool, eventType, object string) []string {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT coalesce(payload->>'relations', '["'||(payload->>'relation')||'"]')
		   FROM kaname.fga_outbox
		  WHERE event_type = $1 AND payload->>'object' = $2`,
		eventType, object)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var raw string
		require.NoError(t, rows.Scan(&raw))
		var rels []string
		require.NoError(t, json.Unmarshal([]byte(raw), &rels))
		out = append(out, rels...)
	}
	require.NoError(t, rows.Err())
	return out
}

// newOrphanScopeSweeper — сборка уборщика над pg-адаптером.
func newOrphanScopeSweeper(pool *pgxpool.Pool, repo *kanamepg.Repository) *seed.OrphanScopeSweeper {
	return seed.NewOrphanScopeSweeper(repo, kanamepg.NewOrphanScopeAdapter(pool), seed.OrphanScopeConfig{})
}

// TestOrphanScope_03_CensusNamesTheDeadScopeAndNotTheLiveOne — перепись судится
// ОТДЕЛЬНО от уборки, и вот почему.
//
// Инъекция при заведении этих проб (снят предикат висячести в SQL переписи, обе
// пробы остались ЗЕЛЁНЫМИ) показала: перепроверка внутри транзакции гасит
// сломанную перепись целиком. Это верное поведение защиты в глубину и негодное
// свойство пробы: сломайся перепись — уборка молча начала бы таскать в
// транзакцию каждую живую область кластера, и ни одно утверждение выше этого не
// заметило бы. Поэтому у переписи своё утверждение, а не общее с исходом.
func TestOrphanScope_03_CensusNamesTheDeadScopeAndNotTheLiveOne(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	f := setupOrphanScope(t, ctx, pool, "03")

	scopes, err := kanamepg.NewOrphanScopeAdapter(pool).ListOrphanBindingScopes(ctx, 100)
	require.NoError(t, err)

	var named []string
	for _, sc := range scopes {
		named = append(named, string(sc.ResourceType)+":"+sc.ResourceID)
	}
	assert.Contains(t, named, "project:"+string(f.dead),
		"перепись обязана назвать область, чьей строки-владельца нет")
	assert.NotContains(t, named, "project:"+string(f.live),
		"перепись НЕ вправе называть живую область — иначе уборка тащит в транзакцию весь кластер")

	// Объём осмотренного печатается всегда: «ноль названных» обязано быть отличимо
	// от «ноль прочитанных».
	t.Logf("перепись висячих областей: названо %d", len(scopes))
}
