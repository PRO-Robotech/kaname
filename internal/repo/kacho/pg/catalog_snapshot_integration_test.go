// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// catalog_snapshot_integration_test.go — сценарии IAM-CT-2-01 · -06 · -07
// (kacho#1816, приёмка
// `services/iam/docs/engineering/acceptance/catalog-readers-move-to-the-table.md`)
// на НАСТОЯЩЕЙ базе с применёнными миграциями.
//
// # `-01`: утверждается РАВЕНСТВО, а не константа
//
// Снимок обязан наполняться ТЕМ ЖЕ чтением, каким страж паритета читает строки:
// второй запрос об одном предмете дал бы два места, расходящиеся молча. Проверить
// это можно только счётом операторов, УШЕДШИХ НА СЕРВЕР, — считает их наблюдатель
// запросов `pgx.QueryTracer`, поставленный на соединение.
//
// Меряются ДВЕ величины на одном прогоне: `K` — операторов у порта, вызванного
// отдельно (столько шлёт сам страж), и `N` — операторов за весь путь старта
// «страж + наполнение снимка». Утверждается `N == K` при `K > 0`. Константа `3`
// сюда не вписана намеренно: свернут когда-нибудь три оператора в один —
// утверждение останется верным без правки, а `K = 0` (за каталогом не сходили
// вовсе) делает равенство тождественно истинным и потому отвергается отдельно.
//
// # Чего `-01` НЕ доказывает
//
// Равенство операторов не отличает «снимок взял прочитанное строками» от «снимок
// наполнен литералом, а страж отработал рядом»: по ЖИВОМУ множеству литерал и
// строки равны, поэтому у обоих `N == K`. Это утверждает `-06` — снятая ПОСЛЕ
// старта строка не доезжает до проекции. Пара обязательна; поодиночке ни один из
// двух свойства не держит.

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/catalog"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// catalogStatementCounter — наблюдатель операторов, считающий ОТДЕЛЬНО те, что
// адресованы таблицам каталога.
//
// Отсечка по таблице обязательна: счёт всего трафика зависел бы от миграций и
// прочих посевов и не был бы величиной о предмете.
type catalogStatementCounter struct {
	mu      sync.Mutex
	total   int
	catalog int
}

func (c *catalogStatementCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn,
	data pgx.TraceQueryStartData) context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total++
	if strings.Contains(data.SQL, "kacho_iam.catalog_") {
		c.catalog++
	}
	return ctx
}

func (c *catalogStatementCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (c *catalogStatementCounter) catalogCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.catalog
}

func (c *catalogStatementCounter) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total, c.catalog = 0, 0
}

func countedCatalogPool(t *testing.T) (*pgxpool.Pool, *catalogStatementCounter, context.Context) {
	t.Helper()
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(pgtest.NewDB(t))
	if err != nil {
		t.Fatalf("разбор строки подключения: %v", err)
	}
	counter := &catalogStatementCounter{}
	cfg.ConnConfig.Tracer = counter
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("пул: %v", err)
	}
	pgtest.ClosePoolAtEnd(t, pool)
	counter.reset()
	return pool, counter, ctx
}

// TestIAMCT2_01_SnapshotAddsNoSecondReadOfTheCatalog — `-01`.
func TestIAMCT2_01_SnapshotAddsNoSecondReadOfTheCatalog(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	pool, counter, ctx := countedCatalogPool(t)
	repo := kachopg.NewCatalogRepo(pool)

	// K — операторов у стража, вызванного ОТДЕЛЬНО.
	counter.reset()
	censusK, err := seed.AssertCatalogParity(ctx, repo)
	if err != nil {
		t.Fatalf("страж паритета: %v", err)
	}
	k := counter.catalogCount()
	if k == 0 {
		t.Fatalf("за каталогом не сходили ВОВСЕ (K=0) — равенство ниже стало бы "+
			"тождественно истинным, а вердикт беспредметным; перепись стража %d/%d/%d",
			censusK.RowModules, censusK.RowResources, censusK.RowVerbs)
	}

	// N — операторов за весь путь СТАРТА: страж плюс наполнение снимка.
	counter.reset()
	censusN, err := seed.AssertCatalogParity(ctx, repo)
	if err != nil {
		t.Fatalf("страж паритета на пути старта: %v", err)
	}
	snap, err := catalog.NewSnapshot(censusN.Live, repo, nil, nil)
	if err != nil {
		t.Fatalf("снимок: %v", err)
	}
	n := counter.catalogCount()

	t.Logf("операторов к таблицам каталога: у стража отдельно K=%d, за путь старта со снимком N=%d", k, n)
	if n != k {
		t.Errorf("N=%d при K=%d — снимок завёл СВОЁ чтение каталога: два места об одном "+
			"предмете, и разойдутся они молча", n, k)
	}
	// Положительный контроль: снимок не просто «не читал» — он ЗАПОЛНЕН.
	if got := snap.Facts().AllVerbVocabulary(); len(got) == 0 {
		t.Errorf("снимок пуст при N==K — равенство выполнено тем, что снимок ничего не взял")
	}
}

// TestIAMCT2_06_07_RetiredAfterStartDoesNotReachTheProjection — `-06` и `-07`.
//
// Приёмка называет здесь `compute.disk`, и на нём проба была бы ВАКУУМНОЙ: этой
// пары в литерале нет вовсе, поэтому переходник не резолвит её ни до снятия, ни
// после, и «пар не произведено» верно при любом порте. Поэтому снимается ЖИВАЯ
// пара — та, что до снятия пары ДАЁТ.
//
// Фикстура пишет снятие ПРЯМО В БАЗУ и не снисходительнее продукта: она ставит
// ровно то, что поставит будущий административный путь — `retired_at`, причину И
// `live = false`.
//
// ТРЕТЬЕ СЛАГАЕМОЕ ОБЯЗАТЕЛЬНО, и здесь стояло обратное. Прежняя редакция этого
// абзаца утверждала, что `live` — колонка ВЫЧИСЛЯЕМАЯ и подделать её фикстура не
// может by construction. Схема говорит другое: `live boolean NOT NULL DEFAULT
// true` плюс `CONSTRAINT catalog_*_live_matches_retired CHECK (live = (retired_at
// IS NULL))` — согласие держит ПРОВЕРКА, а не генерация, поэтому писатель обязан
// проставить обе колонки сам. Утверждение о схеме, взятое из намерения, стоило
// пробе способности исполниться вовсе: без `live = false` обновление отвергалось
// `SQLSTATE 23514`, и проба падала ДО первого своего утверждения.
func TestIAMCT2_06_07_RetiredAfterStartDoesNotReachTheProjection(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	const dotted = "vpc.cidrGroup"
	fgaType, ok := authzmap.FGAObjectType(dotted)
	if !ok {
		t.Fatalf("переходник не знает %q — проба потеряла свой предмет", dotted)
	}
	sel := []domain.RuleSelector{{ObjectTypes: []string{dotted}, Verbs: []string{"*"}}}

	pool, _, ctx := countedCatalogPool(t)
	repo := kachopg.NewCatalogRepo(pool)

	census, err := seed.AssertCatalogParity(ctx, repo)
	if err != nil {
		t.Fatalf("страж паритета: %v", err)
	}
	snap, err := catalog.NewSnapshot(census.Live, repo, nil, nil)
	if err != nil {
		t.Fatalf("снимок: %v", err)
	}

	// ДО снятия — пары есть. Без этого контроля «пар ноль» зеленело бы и на
	// порте, который их не производит никогда.
	if got := snap.Facts().RoleVerbsFromSelectors(sel); len(got) == 0 {
		t.Fatalf("до снятия у %q ноль пар — контроль не выполнен", dotted)
	}

	// Снятие строки В РАБОТАЮЩЕМ процессе.
	if _, err := pool.Exec(ctx,
		`UPDATE kacho_iam.catalog_verb SET retired_at = now(), live = false, retired_reason = $2
		   WHERE module || '.' || resource = $1 AND retired_at IS NULL`,
		dotted, "kacho#1816 IAM-CT-2-06"); err != nil {
		t.Fatalf("снять строки глаголов: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE kacho_iam.catalog_resource SET retired_at = now(), live = false, retired_reason = $2
		   WHERE dotted = $1 AND retired_at IS NULL`,
		dotted, "kacho#1816 IAM-CT-2-06"); err != nil {
		t.Fatalf("снять строку ресурса: %v", err)
	}

	if err := snap.Refresh(ctx); err != nil {
		t.Fatalf("обновление снимка: %v", err)
	}

	if got := snap.Facts().VerbsOfType(fgaType); len(got) != 0 {
		t.Errorf("после снятия набор глаголов %q = %v — снятый тип доехал до проекции", fgaType, got)
	}
	if got := snap.Facts().RoleVerbsFromSelectors(sel); len(got) != 0 {
		t.Errorf("после снятия пары по %q = %v — пересчёт произвёл бы их, и отказ пришёл бы "+
			"ЧУЖОЙ полосой: внешним ключом role_verb_type_fk", dotted, got)
	}

	// `-07`: ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ. Читатель, оставленный на литерале,
	// по-прежнему считает тип живым. Это ОЖИДАЕМОЕ различие — оно и есть предмет
	// задачи, а не дефект.
	if got := authzmap.VerbsOfType(fgaType); len(got) == 0 {
		t.Errorf("литерал перестал знать %q — тогда различие снимка и литерала неотличимо "+
			"от общего отсутствия типа, и `-06` больше ничего не утверждает", fgaType)
	}
	// И страж СЛЕДУЮЩЕГО старта это расхождение поймает: строки ушли, литерал
	// остался. Без этого утверждения переезд читателей выглядел бы способом
	// обойти паритет.
	if _, perr := seed.AssertCatalogParity(ctx, repo); perr == nil {
		t.Errorf("страж паритета молчит при снятой строке живого типа — расхождение литерала " +
			"со строками перестало отказывать в старте")
	}
}
