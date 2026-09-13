// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// orphan_mirror_sweep_integration_test.go — интеграционные пробы прохода по
// строкам зеркала, оставшимся БЕЗ РОДИТЕЛЯ (задача `PRO-Robotech/kacho#2051`).
//
// # Что именно воспроизводит фикстура
//
// Строка зеркала вставляется с ПУСТЫМИ колонками родителя — ровно то, что
// производит приём регистрации, получивший пустой `parent_project_id`. Ни
// ключа, ни проверки, запрещающих это, у таблицы нет: колонки объявлены
// `DEFAULT ''::text NOT NULL`, то есть «пусто» — законное состояние строки.
// Синтетической фикстура поэтому не является: производитель, приславший пустого
// родителя, заводит такую строку и сегодня.
//
// # Отрицание — ТОЛЬКО в паре с положительным контролем
//
// Проб четыре, и три из них существуют затем, чтобы первая не зеленела на
// сломанном предикате:
//
//	01  сирота найдена, названа и починена цепью   ← предмет
//	02  строка без цепи оставлена ВЛАДЕЛЬЦУ        ← граница названа, не обойдена
//	03  строка с ПРОЕКТОМ не сирота                ← полоса первого условия
//	04  строка с АККАУНТОМ не сирота               ← полоса второго условия
//	05  починка идемпотентна                       ← повтор не двигает перепись
//
// # Почему полос ДВЕ, а не одна — это разбор ошибки, а не педантизм
//
// Сперва проб было четыре: «не сирота» проверялось ОДНОЙ — строкой с проектом.
// Она проходила по ПЕРВОМУ условию предиката (`parent_project_id = ''` ложно) и
// до второго не доходила НИКОГДА, то есть о полосе аккаунта не утверждала
// ничего. Инъекция это и показала: подмена выражения аккаунта наивной формой не
// покраснила ни одной пробы.
//
// Отсюда правило, стоящее дороже самих проб: у каждого условия предиката своя
// проба, и она обязана падать на снятии СВОЕГО условия. Одна проба на два
// условия молчит о втором, оставаясь на вид покрывающей оба.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// newOrphanMirrorSweeper собирает проход над пулом.
func newOrphanMirrorSweeper(pool *pgxpool.Pool) *seed.OrphanMirrorSweeper {
	return seed.NewOrphanMirrorSweeper(
		kanamepg.NewOrphanMirrorAdapter(pool),
		seed.OrphanMirrorConfig{MaxRowsPerRun: 100},
	)
}

// insertMirrorRow кладёт строку зеркала с ЯВНО названными родителями.
func insertMirrorRow(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	objectType, objectID, parentProject, parentAccount string,
) {
	t.Helper()
	_, err := pool.Exec(ctx,
		`INSERT INTO kaname.resource_mirror
		     (object_type, object_id, parent_project_id, parent_account_id, labels)
		 VALUES ($1, $2, $3, $4, '{}'::jsonb)`,
		objectType, objectID, parentProject, parentAccount)
	require.NoError(t, err)
}

// insertParentEdge кладёт одно ребро цепи предков.
func insertParentEdge(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	objectType, objectID, parentType, parentID string, depth int,
) {
	t.Helper()
	_, err := pool.Exec(ctx,
		`INSERT INTO kaname.resource_parent_edge
		     (object_type, object_id, parent_type, parent_id, depth)
		 VALUES ($1, $2, $3, $4, $5)`,
		objectType, objectID, parentType, parentID, depth)
	require.NoError(t, err)
}

// seedAccountProjectForMirror заводит НАСТОЯЩИЕ строки аккаунта и проекта.
//
// Строки настоящие, а не выдуманные идентификаторы: фикстура обязана быть не
// снисходительнее продукта, а внешние ключи зеркала и выдач ссылаются на
// настоящие проект и аккаунт.
func seedAccountProjectForMirror(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) (accID, prjID string) {
	t.Helper()
	userID := "usr-" + suffix
	accID = "acc-" + suffix
	prjID = "prj-" + suffix

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	exec := func(sql string, args ...any) {
		t.Helper()
		_, eerr := tx.Exec(ctx, sql, args...)
		require.NoError(t, eerr, "посев обвязки: %s", sql)
	}
	exec(`INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
	      VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		userID, accID, "ext-"+suffix, "u-"+suffix+"@example.com", "Mirror "+suffix)
	exec(`INSERT INTO accounts (id, name, owner_user_id, labels)
	      VALUES ($1, $2, $3, '{}'::jsonb)`, accID, "acc-"+suffix, userID)
	exec(`INSERT INTO projects (id, account_id, name, labels)
	      VALUES ($1, $2, $3, '{}'::jsonb)`, prjID, accID, "prj-"+suffix)
	require.NoError(t, tx.Commit(ctx))
	return accID, prjID
}

// mirrorParents читает колонки родителя обратно из базы.
func mirrorParents(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	objectType, objectID string,
) (project, account string) {
	t.Helper()
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT parent_project_id, parent_account_id
		   FROM kaname.resource_mirror
		  WHERE object_type = $1 AND object_id = $2`,
		objectType, objectID).Scan(&project, &account))
	return project, account
}

// TestOrphanMirrorSweep_01_NamesTheOrphanAndRepairsItFromTheChain — предмет:
// строка без родителя НАЙДЕНА, НАЗВАНА и починена выводом из цепи предков.
//
// Рядом стоит положительный контроль: строка С родителем прохода не тревожит.
// Без него «нашёл всё подряд» было бы неотличимо от верного предиката.
func TestOrphanMirrorSweep_01_NamesTheOrphanAndRepairsItFromTheChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	// сирота: колонки пусты, но владелец прислал цепь предков ⇒ ПОЧИНИМА
	insertMirrorRow(t, ctx, pool, "vpc_network", "net-orphan-01", "", "")
	insertParentEdge(t, ctx, pool, "vpc_network", "net-orphan-01", "project", "prj-from-chain", 1)
	insertParentEdge(t, ctx, pool, "vpc_network", "net-orphan-01", "account", "acc-from-chain", 2)

	// положительный контроль: строка С родителем — проход её не трогает
	insertMirrorRow(t, ctx, pool, "vpc_network", "net-healthy-01", "prj-healthy", "acc-healthy")

	res, err := newOrphanMirrorSweeper(pool).RunOnce(ctx)
	require.NoError(t, err)
	t.Log(res.Census())

	require.True(t, res.Executed, "единственный прогон обязан быть исполнителем")
	// Знаменатель НЕ ноль: «сирот одна» при пустом зеркале означало бы другое.
	assert.GreaterOrEqual(t, res.MirrorRows, 2, "перепись обязана видеть обе строки")
	assert.Equal(t, 1, res.Orphans, "сирота ровно одна — здоровая строка не находка")
	assert.Equal(t, 1, res.Repaired, "цепь предков была ⇒ строка починена")
	assert.Empty(t, res.LeftToOwner, "чинить владельцу нечего: цепь была")

	// починка привела строку К ФАКТУ, а не к выдуманному родителю
	project, account := mirrorParents(t, ctx, pool, "vpc_network", "net-orphan-01")
	assert.Equal(t, "prj-from-chain", project, "проект выведен из ЦЕПИ, а не придуман")
	assert.Equal(t, "acc-from-chain", account, "аккаунт выведен из ЦЕПИ, а не придуман")

	// положительный контроль не тронут ни одним оператором
	hp, ha := mirrorParents(t, ctx, pool, "vpc_network", "net-healthy-01")
	assert.Equal(t, "prj-healthy", hp, "здоровая строка не тронута")
	assert.Equal(t, "acc-healthy", ha, "здоровая строка не тронута")
}

// TestOrphanMirrorSweep_02_RowWithoutAChainIsLeftToTheOwner — граница названа, а
// не обойдена: строка без колонок И без цепи внутри службы НЕ ЧИНИТСЯ.
//
// Служба — лист графа: спросить владельца о родителе она не может, обратный
// вызов замкнул бы граф. Проход обязан такую строку НАЗВАТЬ, а не выдумать ей
// родителя: выдуманная вложенность раздала бы доступ.
func TestOrphanMirrorSweep_02_RowWithoutAChainIsLeftToTheOwner(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	insertMirrorRow(t, ctx, pool, "vpc_network", "net-orphan-02", "", "")

	res, err := newOrphanMirrorSweeper(pool).RunOnce(ctx)
	require.NoError(t, err)
	t.Log(res.Census())

	assert.Equal(t, 1, res.Orphans, "сирота найдена")
	assert.Equal(t, 0, res.Repaired, "чинить не из чего — цепи нет")
	require.Len(t, res.LeftToOwner, 1, "строка НАЗВАНА, а не проглочена")
	assert.Equal(t, "vpc_network:net-orphan-02", res.LeftToOwner[0].String(),
		"названа КООРДИНАТОЙ: без неё оператор не знает, что перерегистрировать")

	// Родитель НЕ выдуман: колонки остались пусты.
	project, account := mirrorParents(t, ctx, pool, "vpc_network", "net-orphan-02")
	assert.Empty(t, project, "родитель не выдуман")
	assert.Empty(t, account, "родитель не выдуман")
}

// TestOrphanMirrorSweep_03_RowWithProjectOnlyIsNotAnOrphan — полоса ПЕРВОГО
// условия: строка с непустым проектом сиротой не является.
//
// Падает на снятии условия `parent_project_id = ”` и только на нём.
func TestOrphanMirrorSweep_03_RowWithProjectOnlyIsNotAnOrphan(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	_, prjID := seedAccountProjectForMirror(t, ctx, pool, "om03")
	insertMirrorRow(t, ctx, pool, "vpc_network", "net-project-only-03", prjID, "")

	res, err := newOrphanMirrorSweeper(pool).RunOnce(ctx)
	require.NoError(t, err)
	t.Log(res.Census())

	assert.GreaterOrEqual(t, res.MirrorRows, 1, "строка в зеркале есть — молчание не от пустоты")
	assert.Equal(t, 0, res.Orphans, "строка с ПРОЕКТОМ сиротой не является")
	assert.Empty(t, res.LeftToOwner)
}

// TestOrphanMirrorSweep_04_RowWithAccountOnlyIsNotAnOrphan — полоса ВТОРОГО
// условия: строка с непустым аккаунтом и пустым проектом сиротой не является.
//
// Ресурс, лежащий прямо в аккаунте, проектного родителя не имеет — это законное
// состояние, а не дефект, и аккаунтная выдача такую строку матчит.
//
// Проба существует ОТДЕЛЬНО от 03 потому, что 03 до второго условия не доходит:
// её строка отсеивается первым. Ровно эту слепоту показала инъекция — подмена
// выражения аккаунта наивной формой не покраснила ни одной пробы, пока этой не
// было.
func TestOrphanMirrorSweep_04_RowWithAccountOnlyIsNotAnOrphan(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	accID, _ := seedAccountProjectForMirror(t, ctx, pool, "om04")
	insertMirrorRow(t, ctx, pool, "vpc_network", "net-account-only-04", "", accID)

	res, err := newOrphanMirrorSweeper(pool).RunOnce(ctx)
	require.NoError(t, err)
	t.Log(res.Census())

	assert.GreaterOrEqual(t, res.MirrorRows, 1, "строка в зеркале есть — молчание не от пустоты")
	assert.Equal(t, 0, res.Orphans,
		"строка с АККАУНТОМ (%s) и пустым проектом сиротой не является", accID)
	assert.Empty(t, res.LeftToOwner)
}

// TestOrphanMirrorSweep_05_RepairIsIdempotent — повтор прохода безопасен.
//
// Починенная строка в следующую перепись не попадает (у неё появился родитель),
// и второй прогон НЕ засчитывает её починенной второй раз. Без этой пробы
// «идемпотентно» осталось бы словом в шапке.
func TestOrphanMirrorSweep_05_RepairIsIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	insertMirrorRow(t, ctx, pool, "vpc_network", "net-orphan-05", "", "")
	insertParentEdge(t, ctx, pool, "vpc_network", "net-orphan-05", "project", "prj-idem", 1)

	sweeper := newOrphanMirrorSweeper(pool)

	first, err := sweeper.RunOnce(ctx)
	require.NoError(t, err)
	t.Log("прогон 1: " + first.Census())
	require.Equal(t, 1, first.Orphans)
	require.Equal(t, 1, first.Repaired)

	second, err := sweeper.RunOnce(ctx)
	require.NoError(t, err)
	t.Log("прогон 2: " + second.Census())
	assert.Equal(t, 0, second.Orphans, "починенная строка сиротой больше не числится")
	assert.Equal(t, 0, second.Repaired, "повтор НЕ засчитывает вторую починку")
	assert.Empty(t, second.LeftToOwner)

	project, _ := mirrorParents(t, ctx, pool, "vpc_network", "net-orphan-05")
	assert.Equal(t, "prj-idem", project, "значение не сдвинулось от повтора")
}
