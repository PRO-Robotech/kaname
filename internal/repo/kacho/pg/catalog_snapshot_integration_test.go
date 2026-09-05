// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
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
	censusK, err := seed.AssertCatalogParity(ctx, repo, seed.ImageAnchor())
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
	censusN, err := seed.AssertCatalogParity(ctx, repo, seed.ImageAnchor())
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

	census, err := seed.AssertCatalogParity(ctx, repo, seed.ImageAnchor())
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
	// И СЛЕДУЮЩИЙ СТАРТ этим снятием не ломается — задача #1861.
	//
	// Здесь стояло обратное утверждение, и оно было верным для своего дня:
	// страж требовал точного равенства, поэтому снятая строка роняла старт, и
	// снять модуль было нельзя иначе как пересборкой образа. Это и есть предмет
	// #1861 — «опора стража это литерал»: перечень, порождённый сборкой, судил
	// не как ВЕРХНЯЯ ГРАНИЦА, а как равенство.
	//
	// Что утверждается теперь: снятая строка — свидетельство РЕШЕНИЯ, и страж
	// его принимает, называя строку снятой, а не пропавшей. Проверяется исход
	// СТАРТА, а не форма вызова: `serve.go` возвращает ошибку ровно тогда, когда
	// её вернул страж, поэтому «страж молчит» здесь и означает «служба
	// поднялась».
	parity, perr := seed.AssertCatalogParity(ctx, repo, seed.ImageAnchor())
	if perr != nil {
		t.Fatalf("страж отказал в старте после СНЯТИЯ строки — снять модуль по-прежнему "+
			"нельзя иначе как пересборкой образа: %v", perr)
	}
	if len(parity.WithdrawnRows) == 0 {
		t.Errorf("страж промолчал, но снятого не назвал (нет строкой %d, нет в литерале %d) — "+
			"«промолчал» и «промолчал и назвал, ЧТО снято» разные вещи, и первое зеленеет на "+
			"страже, переставшем смотреть вовсе",
			len(parity.MissingRows), len(parity.ExtraRows))
	}
	t.Logf("после снятия: снято решением %d · нет строкой %d · нет в литерале %d · снятых строк %d/%d/%d",
		len(parity.WithdrawnRows), len(parity.MissingRows), len(parity.ExtraRows),
		parity.RetiredModules, parity.RetiredResources, parity.RetiredVerbs)

	// ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ, без которого утверждение выше зеленело бы на
	// страже, принимающем ЛЮБУЮ пропавшую строку. Та же строка, удалённая ВОВСЕ
	// (ни живой, ни снятой), — это уже не решение оператора, а непроехавший
	// посев, и он обязан ронять старт по-прежнему.
	if _, err := pool.Exec(ctx,
		`DELETE FROM kacho_iam.catalog_verb WHERE module || '.' || resource = $1`, dotted); err != nil {
		t.Fatalf("удалить строки действий вовсе: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`DELETE FROM kacho_iam.catalog_resource WHERE dotted = $1`, dotted); err != nil {
		t.Fatalf("удалить строку ресурса вовсе: %v", err)
	}
	gone, gerr := seed.AssertCatalogParity(ctx, repo, seed.ImageAnchor())
	if gerr == nil {
		t.Errorf("страж молчит при строке, которой нет НИ ЖИВОЙ, НИ СНЯТОЙ — непроехавший "+
			"посев принят за решение оператора; снято решением %d, нет строкой %d",
			len(gone.WithdrawnRows), len(gone.MissingRows))
	}
	if len(gone.MissingRows) == 0 {
		t.Errorf("отказ не назвал ни одной пропавшей строки — оператору нечем чинить")
	}
}

// TestIAMCT2_14_AppliedAfterStartReachesTheProjection — `-14`, ЗЕРКАЛО `-06`.
//
// `-06` утверждает, что СНЯТЫЙ в работающем процессе тип пар не даёт. Это одна
// половина, и порознь она выполнима портом, который не производит пар НИКОГДА.
// Вторая половина — ЗАВЕДЁННЫЙ тип пары ДАЁТ, — не утверждалась ни одним из
// тринадцати сценариев приёмки переезда, и не по недосмотру: до колонки
// `catalog_resource.object_type` она была НЕВЫПОЛНИМА. Имя типа модели прав
// строка не несла, его отдавал словарь, ПОРОЖДЁННЫЙ СБОРКОЙ, и тип, которого
// сборка не знала, пропускался молча — при живом членстве модуля и роли,
// созданной без отказа.
//
// Проба идёт ЧЕРЕЗ НАСТОЯЩИЙ ПРИМЕНИТЕЛЬ, а не пишет строки сама: предмет
// сценария — что заведение доезжает от манифеста до проекции ЦЕЛИКОМ, а
// фикстура, пишущая строки напрямую, обошла бы ровно то звено, где значение
// терялось (деривация `modulecatalog.RowsOf`).
//
// Это пункт 1 DoD эпика #1027: «применить манифест с новым типом → синтетический
// вопрос вердикту даёт ненулевой ответ». Вердикт (`relverdict`) читает
// `kacho_iam.role_verb`, а его пишет ровно эта проекция.
func TestIAMCT2_14_AppliedAfterStartReachesTheProjection(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	const (
		appliedModule = "probemod"
		appliedRes    = "alpha"
		appliedDotted = appliedModule + "." + appliedRes
		appliedType   = "probemod_alpha"
	)
	sel := []domain.RuleSelector{{ObjectTypes: []string{appliedDotted}, Verbs: []string{"*"}}}

	pool, _, ctx := countedCatalogPool(t)
	repo := kachopg.NewCatalogRepo(pool)

	// КОНТРОЛЬ ПРЕДПОСЫЛКИ: сборка этого типа не знает. Впиши кто-нибудь его в
	// манифест — и проба зеленела бы вхолостую, а отличить это от исправного
	// порта было бы нечем.
	if _, known := authzmap.FGAObjectType(appliedDotted); known {
		t.Fatalf("сборка знает %q — предпосылка -14 отпала, проба стала бы вакуумной", appliedDotted)
	}

	census, err := seed.AssertCatalogParity(ctx, repo, seed.ImageAnchor())
	if err != nil {
		t.Fatalf("страж паритета: %v", err)
	}
	snap, err := catalog.NewSnapshot(census.Live, repo, nil, nil)
	if err != nil {
		t.Fatalf("снимок: %v", err)
	}

	// ДО применения — пар нет. Отрицательный контроль: без него «пары есть»
	// зеленело бы на снимке, который знал тип с самого начала.
	if got := snap.Facts().RoleVerbsFromSelectors(sel); len(got) != 0 {
		t.Fatalf("до применения у %q уже %d пар — контроль не выполнен", appliedDotted, len(got))
	}

	// ЗАВЕДЕНИЕ в РАБОТАЮЩЕМ процессе — настоящим применителем.
	rep, err := applierOver(t, pool).Apply(ctx, probeManifest(
		probeResource(appliedRes, "get", "list", "update", "delete"),
	))
	if err != nil {
		t.Fatalf("применение манифеста с новым типом: %v", err)
	}
	if !rep.Changed() {
		t.Fatalf("применение каталог не изменило (%s) — заводить было нечего, вердикт беспредметен", rep)
	}
	t.Logf("применение: %s", rep)

	if err := snap.Refresh(ctx); err != nil {
		t.Fatalf("обновление снимка: %v", err)
	}

	// Набор глаголов ЖИВОГО типа читается по имени МОДЕЛИ, приехавшему строкой.
	if got := snap.Facts().VerbsOfType(appliedType); len(got) == 0 {
		t.Errorf("набор глаголов заведённого типа %q пуст — имя типа не доехало строкой", appliedType)
	}

	pairs := snap.Facts().RoleVerbsFromSelectors(sel)
	if len(pairs) == 0 {
		t.Fatalf("после применения пар по %q ноль: строки каталога записаны, членство модуля "+
			"живо, роль создалась бы без отказа — и арендатор не получил бы НИЧЕГО", appliedDotted)
	}
	got := map[string]bool{}
	for _, p := range pairs {
		if p.ObjectType != appliedDotted {
			t.Errorf("пара названа чужим типом %q, ожидался %q", p.ObjectType, appliedDotted)
			continue
		}
		got[p.Verb] = true
	}
	for _, verb := range []string{"get", "list", "update", "delete"} {
		if !got[verb] {
			t.Errorf("глагол %q объявлен манифестом и в проекцию не попал (получено %v)", verb, got)
		}
	}
	t.Logf("заведённый тип %q → пар проекции %d, глаголы %v", appliedDotted, len(pairs), got)

	// ЗЕРКАЛО `-07`: читатель, оставленный на литерале, заведённого типа
	// по-прежнему НЕ знает. Это ожидаемое различие, и оно же — мера сделанного:
	// снимок отвечает там, где литерал молчит.
	if got := authzmap.VerbsOfType(appliedType); len(got) != 0 {
		t.Errorf("литерал знает %q (%v) — тогда различие снимка и литерала неотличимо от "+
			"общего знания типа, и проба больше ничего не утверждает", appliedType, got)
	}
}

// TestWithdrawnRowDoesNotBlockTheNextBoot — НАБЛЮДАЕМОЕ утверждение задачи
// продукта #1861: после снятия строки каталога СЛУЖБА ПОДНИМАЕТСЯ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТОГО НЕ ДОКАЗЫВАЕТ ОДИН СТРАЖ
//
// «Страж промолчал» — утверждение о ФУНКЦИИ, а не о старте. Дальше по цепи
// композиционного корня идут ещё два звена, и любое из них могло бы отказать по
// той же причине, вернув отказ ЧУЖОЙ полосой:
//
//	снимок каталога   наполняется прочитанным стражем; снятая строка обязана из
//	                  него уйти, а не остаться «известной, но мёртвой»
//	пересев проекции  пишет пары «роль → тип × глагол», и каждая пара упирается
//	                  во внешний ключ `role_verb_type_fk` → `catalog_resource
//	                  (dotted, live)`. Возьми он перечень у ЛИТЕРАЛА — снятый тип
//	                  доехал бы до ключа и был бы отвергнут им, то есть служба
//	                  всё равно не поднялась бы, только отказ пришёл бы из места,
//	                  где предмета нет
//
// Поэтому проба идёт по всем трём звеньям подряд, в том же порядке, в каком их
// зовёт `serve.go`, и утверждает исход КАЖДОГО.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СНИМАЕТСЯ РЕСУРС, А НЕ МОДУЛЬ ЦЕЛИКОМ
//
// Это не упрощение, а измеренная граница: снять строку, которую называет живое
// правило системной роли, база НЕ ДАЁТ — `role_rule_ref_res_fk` отвергает
// обновление (SQLSTATE 23503, замер по этому дереву). То есть снятие модуля
// обязано начинаться с уборки выдач, и это отдельная полоса со своим предметом.
// Взятый здесь `vpc.cidrGroup` живых правил не имеет — та же строка, которую
// снимает `-06` выше, — поэтому снятие проходит, и предмет пробы остаётся
// предметом СТАРТА, а не предметом уборки выдач.
func TestWithdrawnRowDoesNotBlockTheNextBoot(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	const dotted = "vpc.cidrGroup"

	pool, _, ctx := countedCatalogPool(t)
	repo := kachopg.NewCatalogRepo(pool)

	// КОНТРОЛЬ: до снятия цепь старта проходит. Без него «поднялась» ниже
	// зеленело бы и на дереве, где она не поднималась никогда.
	if _, err := seed.AssertCatalogParity(ctx, repo, seed.ImageAnchor()); err != nil {
		t.Fatalf("контроль: страж отказал ДО снятия — вердикт беспредметен: %v", err)
	}

	// СНЯТИЕ — та же форма, какой его пишет применитель по доставленному
	// манифесту: `retired_at`, причина И `live = false` (согласие держит
	// проверка `catalog_*_live_matches_retired`, а не генерация колонки).
	if _, err := pool.Exec(ctx,
		`UPDATE kacho_iam.catalog_verb SET retired_at = now(), live = false, retired_reason = $2
		   WHERE module || '.' || resource = $1 AND retired_at IS NULL`,
		dotted, "kacho#1861"); err != nil {
		t.Fatalf("снять строки действий: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE kacho_iam.catalog_resource SET retired_at = now(), live = false, retired_reason = $2
		   WHERE dotted = $1 AND retired_at IS NULL`,
		dotted, "kacho#1861"); err != nil {
		t.Fatalf("снять строку ресурса: %v", err)
	}

	// ── звено 1: страж паритета ─────────────────────────────────────────────
	parity, perr := seed.AssertCatalogParity(ctx, repo, seed.ImageAnchor())
	if perr != nil {
		t.Fatalf("СТАРТ ОТКАЗАН после снятия строки — снять её нельзя иначе как "+
			"пересборкой образа, и это ровно предмет #1861: %v", perr)
	}
	if len(parity.WithdrawnRows) == 0 {
		t.Errorf("страж промолчал, но снятого не назвал — «промолчал» и «промолчал и "+
			"назвал, ЧТО снято» разные вещи; нет строкой %d, нет в литерале %d",
			len(parity.MissingRows), len(parity.ExtraRows))
	}
	t.Logf("звено 1 — страж: снято решением %d · нет строкой %d · нет в литерале %d",
		len(parity.WithdrawnRows), len(parity.MissingRows), len(parity.ExtraRows))

	// ── звено 2: снимок каталога ────────────────────────────────────────────
	snap, serr := catalog.NewSnapshot(parity.Live, repo, nil, nil)
	if serr != nil {
		t.Fatalf("снимок каталога не построился после снятия: %v", serr)
	}
	if got := snap.Facts().RoleVerbsFromSelectors(
		[]domain.RuleSelector{{ObjectTypes: []string{dotted}, Verbs: []string{"*"}}}); len(got) != 0 {
		t.Errorf("снимок по-прежнему производит %d пар на снятом %q — тогда звено 3 "+
			"упёрлось бы в ключ role_verb_type_fk", len(got), dotted)
	}

	// ── звено 3: пересев проекции системных ролей ───────────────────────────
	census, rerr := seed.ReseedSystemRoleVerbs(ctx, kachopg.New(pool, nil), pool, snap.Facts(), nil)
	if rerr != nil {
		t.Fatalf("пересев проекции отказал после снятия — отказ пришёл бы ЧУЖОЙ полосой "+
			"(ключ role_verb_type_fk), и служба не поднялась бы: %v", rerr)
	}
	if census.Examined == 0 {
		t.Fatalf("пересев осмотрел НОЛЬ ролей — звено 3 беспредметно, и его молчание "+
			"неотличимо от исправной работы: осмотрено %d, пересеяно %d", census.Examined, census.Reseeded)
	}
	if census.Failed != 0 {
		t.Errorf("пересев отказал на %d ролях из %d", census.Failed, census.Examined)
	}
	t.Logf("звено 3 — пересев: осмотрено %d · пересеяно %d · пар %d · отказало %d",
		census.Examined, census.Reseeded, census.Pairs, census.Failed)

	// И проекция снятого типа ПУСТА: ключ её не пропустил бы, но утверждать надо
	// исход, а не то, что мы на него понадеялись.
	var pairs int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_verb WHERE object_type = $1`, dotted).Scan(&pairs); err != nil {
		t.Fatalf("перепись проекции снятого типа: %v", err)
	}
	if pairs != 0 {
		t.Errorf("у снятого %q осталось %d пар проекции", dotted, pairs)
	}
}
