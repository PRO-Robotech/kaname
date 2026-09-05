// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// batch_roundtrip_integration_test.go — СТОИМОСТЬ ПАРТИИ ПРИНАДЛЕЖИТ ЗАПРОСУ, А
// НЕ ЧИСЛУ ЕЁ ПУНКТОВ.
//
// # Предмет
//
// Вопрос о доступе пообъектен, и это свойство предиката. Число ОБРАЩЕНИЙ К БАЗЕ
// — величина другая, и оно пообъектным быть не обязано: страница списка соседа
// однородна by construction (один субъект, один тип, одно отношение, различаются
// только идентификаторы), а такой набор отвечается ОДНИМ запросом.
//
// До этой правки партия из ста разбиралась ста запросами внутри одной читающей
// транзакции: «партия» существовала по форме и отсутствовала по существу.
//
// # Единица — ОБРАЩЕНИЕ, и оно считается ЯВНО
//
// Считает не наша оценка и не время, а сама библиотека доступа: наблюдатель
// запросов (`pgx.QueryTracer`) стоит на соединении и отмечает КАЖДЫЙ оператор,
// уходящий на сервер, включая служебные `begin`/`rollback`. Величина поэтому не
// зависит ни от машины, ни от кэша, ни от нагрузки соседа — и её нельзя получить
// косвенно, из времени ответа.
//
// # Отрицание в паре с положительным контролем
//
// «Не растёт» выполняется тождественно для формы, которая не отвечает ничем.
// Поэтому рядом с числом обращений утверждается и СОСТАВ ответа — здесь в
// вырожденном виде (все сто вердиктов обязаны быть разрешающими), а полностью,
// на смешанной странице и с проверкой порядка, — соседней пробой
// `batch_matches_per_object_integration_test.go`. Второй раз она тут не
// пересказывается: два места об одном предмете расходятся молча.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// statementCounter — наблюдатель операторов на соединении.
//
// Считает ВСЁ, что уходит на сервер, и отдельно — те операторы, что несут текст
// вердикта. Две величины, а не одна, потому что они отвечают на разные вопросы:
// общая говорит, сколько раз запрос сходил к базе (включая `begin`/`rollback`,
// которых на партию ровно по одному), а вторая — сколько из них были ВОПРОСОМ О
// ДОСТУПЕ. Одна общая величина не отличила бы «партия отвечена одним вопросом»
// от «партия не спросила вовсе».
type statementCounter struct {
	mu       sync.Mutex
	total    int
	verdicts int
	seen     []string
}

// verdictMark — признак текста вердикта. Выбран по выражению, которое несут ВСЕ
// формы вопроса о доступе и не несёт ни один служебный оператор.
const verdictMark = "scope_distinct"

func (c *statementCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn,
	data pgx.TraceQueryStartData) context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total++
	if strings.Contains(data.SQL, verdictMark) {
		c.verdicts++
	}
	c.seen = append(c.seen, statementHead(data.SQL))
	return ctx
}

func (c *statementCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (c *statementCounter) snapshot() (total, verdicts int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total, c.verdicts
}

func (c *statementCounter) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total, c.verdicts, c.seen = 0, 0, nil
}

func statementHead(sql string) string {
	for _, line := range strings.Split(sql, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			if len(s) > 60 {
				return s[:60]
			}
			return s
		}
	}
	return ""
}

// withCountedPool сеет закоммиченные данные и отдаёт пул, на соединениях
// которого стоит счётчик операторов.
//
// Счётчик обнуляется ПОСЛЕ посева: посев — не предмет замера, и его операторы,
// попав в число, сделали бы величину непонятной.
func withCountedPool(t *testing.T, seed func(ctx context.Context, tx pgx.Tx)) (
	*pgxpool.Pool, *statementCounter, context.Context) {
	t.Helper()
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(pgtest.NewDB(t))
	if err != nil {
		t.Fatalf("разбор строки подключения: %v", err)
	}
	counter := &statementCounter{}
	cfg.ConnConfig.Tracer = counter
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("пул: %v", err)
	}
	// Закрытие С ПРЕДЕЛОМ, а не `t.Cleanup(pool.Close)`: отложенное закрытие ждёт
	// соединение, которое проба, упавшая внутри открытой транзакции, не вернёт
	// никогда, — и уносит с собой вердикт всего пакета. Держится гейтом дерева
	// `TestPoolCloseInTestsIsBounded`; он и поймал здесь первую редакцию.
	pgtest.ClosePoolAtEnd(t, pool)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("транзакция посева: %v", err)
	}
	seed(ctx, tx)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("коммит посева: %v", err)
	}
	counter.reset()
	return pool, counter, ctx
}

// batchPageSize — контрактная партия соседа. Сужать её ради бюджета запрещено
// нормой, поэтому меряется она как есть.
const batchPageSize = 100

// batchStatementCeiling — предел числа обращений на партию ЛЮБОЙ длины.
//
// ЧЕТЫРЕ: транзакция чтения — это `begin`, чтение имени типа в словаре каталога
// (`catalogTypeName`, kacho#1986), сам вопрос и `rollback`. Величина объявлена ДО
// прогона и НЕ ЗАВИСИТ от числа идентификаторов — в этом и состоит утверждение.
//
// Здесь стояло ТРИ, и четвёртое обращение — цена правки #1986, названная прямо, а
// не подкрученная под зелёное: имя типа в словаре каталога читается у ЖИВОЙ строки,
// потому что таблица, порождённая сборкой, о типе, заведённом применением
// манифеста, не знает. Форма, читавшая имя ВНУТРИ запроса (обращений остаётся
// три), измерена прибором объёма и отвергнута: она меняла ПОРЯДОК РОСТА полосы
// отказа — несущие строки 28·40·52·1080 против 28·40·52·64. Нелинейность по
// населению — отказ, а не медленность.
const batchStatementCeiling = 4

// TestAllowedMany_OnePageIsOneQuestionToTheStore — партия из ста обращается к
// базе столько же раз, сколько партия из одного.
func TestAllowedMany_OnePageIsOneQuestionToTheStore(t *testing.T) {
	var ids []string
	pool, counter, ctx := withCountedPool(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-get", "vpc_network", "get", "anchor", "{}")
		bindRole(t, ctx, tx, "acb-get", "rol-get")
		ids = seedNetworks(t, ctx, tx, batchPageSize)
	})
	asker := relverdict.NewAsker(pool)

	// Положительный контроль: партия из ОДНОГО. Без него «не растёт» зеленело бы
	// на форме, которая не спрашивает вовсе.
	one, err := asker.AllowedMany(ctx, "user:usr-1", "vpc_network", ids[:1], "v_get", nil)
	if err != nil {
		t.Fatalf("партия из одного: %v", err)
	}
	oneTotal, oneVerdicts := counter.snapshot()
	if len(one) != 1 || !one[0] {
		t.Fatalf("партия из одного дала %v — предмет замера отсутствует, и число обращений "+
			"ниже описывало бы форму, которая не отвечает", one)
	}
	if oneVerdicts == 0 {
		t.Fatalf("вопросов о доступе не задано вовсе (обращений всего %d): «не растёт» "+
			"выполнялось бы тождественно, и проба ничего бы не утверждала", oneTotal)
	}

	counter.reset()
	many, err := asker.AllowedMany(ctx, "user:usr-1", "vpc_network", ids, "v_get", nil)
	if err != nil {
		t.Fatalf("партия из ста: %v", err)
	}
	manyTotal, manyVerdicts := counter.snapshot()

	t.Logf("обращений к базе: партия из 1 — всего %d, из них вопросов о доступе %d; "+
		"партия из %d — всего %d, вопросов %d",
		oneTotal, oneVerdicts, batchPageSize, manyTotal, manyVerdicts)

	// Состав ответа — рядом с числом, иначе отрицание зеленеет на сломанном.
	if len(many) != batchPageSize {
		t.Fatalf("ответ на партию из %d имеет длину %d", batchPageSize, len(many))
	}
	for i, allowed := range many {
		if !allowed {
			t.Fatalf("объект %s объявлен недоступным, хотя выдача роли покрывает весь тип "+
				"в области проекта: сузился ОТВЕТ, а не число вопросов", ids[i])
		}
	}

	// РАВЕНСТВО, а не только предел. Предел ловит абсолютную величину, а заголовок
	// обещает ДРУГОЕ — что партия из ста стоит столько же, сколько партия из одного.
	// Без этой проверки обе величины могли бы вырасти вместе, и утверждение
	// заголовка не покраснело бы, пока рост не упрётся в предел.
	if manyTotal != oneTotal {
		t.Fatalf("партия из %d обращается к базе %d раз, партия из одного — %d.\n"+
			"  Число обращений ЗАВИСИТ от длины партии, а обязано не зависеть: набор\n"+
			"  однороден by construction — один субъект, тип, отношение.",
			batchPageSize, manyTotal, oneTotal)
	}
	if manyTotal > batchStatementCeiling {
		t.Fatalf("партия из %d обращается к базе %d раз при пределе %d (партия из одного — %d).\n"+
			"  Партия существует по форме и отсутствует по существу: каждый идентификатор "+
			"уезжает отдельным вопросом.\n"+
			"  Набор однороден by construction — один субъект, тип, отношение, — и отвечается "+
			"одним запросом.",
			batchPageSize, manyTotal, batchStatementCeiling, oneTotal)
	}
}

// TestDirectRelationsMany_OnePageIsOneQuestionAndSaysWhatOneByOneSays —
// диагностика хвоста текста отказа тоже принадлежит ЗАПРОСУ, а не набору.
//
// # Почему она здесь, рядом с вердиктом
//
// Хвост текста отказа платится на КАЖДОМ отказанном объекте, а страница списка
// отказами и состоит — она ими сужается. Пока вердикт стоил вопрос на объект,
// это было незаметно; сведя вердикт к одному вопросу, диагностику оставить
// пообъектной значило бы перенести стоимость набора на соседнюю полосу и
// объявить предмет закрытым.
//
// # Три утверждения, и ни одно не выводится из других
//
//	(1) ОБРАЩЕНИЙ столько же, сколько на одном объекте;
//	(2) СОСТАВ тот же, что у пообъектного пути, — поимённо;
//	(3) ПРЕДЕЛ считается НА ОБЪЕКТ, а не на ответ: общий предел молча обрезал бы
//	    хвост у объектов, до которых очередь дошла позже, и хвост зависел бы от
//	    положения объекта на странице.
func TestDirectRelationsMany_OnePageIsOneQuestionAndSaysWhatOneByOneSays(t *testing.T) {
	const (
		objects  = 40
		perObj   = 4 // отношений на объекте — больше предела ниже
		tailLim  = 2
		subject  = "user:usr-1"
		objType  = "vpc_network"
		relation = "viewer"
	)
	var ids []string
	pool, counter, ctx := withCountedPool(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		ids = seedNetworks(t, ctx, tx, objects)
		for _, id := range ids {
			// Имена отношений намеренно НЕ по алфавиту порядка вставки: предел
			// отбирает первые по имени, и совпадение с порядком вставки скрыло бы
			// ошибку отбора.
			for _, rel := range []string{"zeta", relation, "editor", "admin"}[:perObj] {
				exec(t, ctx, tx,
					`INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject)
					 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`, objType, id, rel, subject)
			}
		}
	})
	asker := relverdict.NewAsker(pool)

	// Положительный контроль: страница из ОДНОГО объекта.
	if _, err := asker.DirectRelationsMany(ctx, subject, objType, ids[:1], tailLim); err != nil {
		t.Fatalf("страница из одного: %v", err)
	}
	oneTotal, _ := counter.snapshot()
	if oneTotal == 0 {
		t.Fatalf("страница из одного не обратилась к базе ни разу: предмета замера нет")
	}

	counter.reset()
	many, err := asker.DirectRelationsMany(ctx, subject, objType, ids, tailLim)
	if err != nil {
		t.Fatalf("страница из %d: %v", objects, err)
	}
	manyTotal, _ := counter.snapshot()
	t.Logf("обращений к базе: страница из 1 — %d; страница из %d — %d", oneTotal, objects, manyTotal)

	if manyTotal > oneTotal {
		t.Fatalf("страница из %d обращается к базе %d раз, страница из одного — %d: "+
			"диагностика хвоста отказа возвращает стоимость набора туда, откуда её убрал вердикт",
			objects, manyTotal, oneTotal)
	}

	// (2) и (3): состав и предел — поимённо против пообъектного пути.
	var mismatched []string
	for _, id := range ids {
		one, oerr := asker.DirectRelations(ctx, subject, objType, id, tailLim)
		if oerr != nil {
			t.Fatalf("пообъектная диагностика %s: %v", id, oerr)
		}
		if len(one) != tailLim {
			t.Fatalf("пообъектный путь отдал %d отношений на объекте %s при пределе %d — "+
				"предпосылка сверки нарушена, предел не проверяется", len(one), id, tailLim)
		}
		got := many[id]
		if strings.Join(got, ",") != strings.Join(one, ",") {
			mismatched = append(mismatched, id+": страница="+strings.Join(got, ",")+
				", по одному="+strings.Join(one, ","))
		}
	}
	if len(mismatched) > 0 {
		t.Fatalf("страничная диагностика отвечает не то же, что пообъектная: %s",
			strings.Join(mismatched, "; "))
	}
}

// TestAllowedMany_EveryArmOfTheRuleReachesThePage — страничный вопрос читает ВСЕ
// ТРИ ветви правила и ПРЯМОЙ ФАКТ, и каждая ветвь различает свои объекты.
//
// # Зачем это отдельно от сверки с пообъектным путём
//
// Сверка состава ловит расхождение только там, где оно есть НА ПОСЕЯННЫХ данных.
// Ветвь, которую посев не задел, у обоих путей молчит одинаково — и «ответы
// совпали» читается шире, чем есть. Ветви имён и меток в страничном запросе
// адресуют объект ИНАЧЕ, чем в прямом (колонкой строки, а не параметром), поэтому
// именно они и могли бы разойтись молча: страница отвечала бы отказом там, где
// право есть, а отказ этот неотличим от честного.
//
// # Обе стороны на каждой ветви
//
// У каждой ветви на странице есть объект, до которого она достаёт, и объект,
// до которого не достаёт. Проба, сеющая только достижимые, зеленела бы на
// реализации, разрешающей всё подряд; проба, сеющая только недостижимые, — на
// реализации, не разрешающей ничего.
//
// # НЕОТДЕЛИМА ОТ `TestAllowedMany_AgreesWithAllowedObjectByObject`
//
// Та проба сверяет страничный ответ с пообъектным и держит сужение по ветви
// ВЫДАЧ — но только его: её посев строит доступ якорной выдачей, поэтому ветви
// фактов и меток у неё молчат на обоих путях одинаково. Эта проба держит две
// оставшиеся, но НЕ утверждает согласия двух путей.
//
// Вместе они покрывают все три сужения; порознь каждая оставляет полосу без
// сторожа, и оставшаяся об этом не покраснеет. Снимать — только обе сразу.
func TestAllowedMany_EveryArmOfTheRuleReachesThePage(t *testing.T) {
	const subject = "user:usr-1"

	// Объекты: два на ветвь. Первый в паре — достижимый, второй — нет.
	var (
		namesHit, namesMiss   = "net-00", "net-01"
		labelsHit, labelsMiss = "net-02", "net-03"
		factHit, factMiss     = "net-04", "net-05"
	)
	page := []string{namesHit, namesMiss, labelsHit, labelsMiss, factHit, factMiss}
	want := []bool{true, false, true, false, true, false}

	pool, _, ctx := withCountedPool(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedNetworks(t, ctx, tx, len(page))

		// Ветвь ИМЁН: правило адресует один объект перечнем.
		// Тип здесь — в словаре КАТАЛОГА: этот посевщик, в отличие от соседнего
		// `seedRole`, перевода не делает, а колонки выдачи названы каталогом.
		seedRoleNames(t, ctx, tx, "rol-names", catalogFormOf(t, "vpc_network"), "get", []string{namesHit})
		bindRole(t, ctx, tx, "acb-names", "rol-names")

		// Ветвь МЕТОК: правило адресует объекты совпадением меток; метка стоит
		// только на одном из двух.
		seedRole(t, ctx, tx, "rol-labels", "vpc_network", "get", "labels", `{"env":"prod"}`)
		bindRole(t, ctx, tx, "acb-labels", "rol-labels")
		exec(t, ctx, tx,
			`UPDATE kacho_iam.resource_mirror SET labels = '{"env":"prod"}'::jsonb
			  WHERE object_type = $1 AND object_id = $2`, catalogFormOf(t, "vpc_network"), labelsHit)

		// ПРЯМОЙ ФАКТ на самом объекте — ветвь, не связанная с выдачами вовсе.
		// Отношение факта — то, которое называет ПЛАН вопроса (`v_get`), а не
		// произвольное имя: факт под чужим именем не совпал бы ни с одним
		// источником и исчез бы молча — то есть проба зеленела бы на отказе.
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject)
			 VALUES ('vpc_network', $1, 'v_get', $2)`, factHit, subject)
	})
	asker := relverdict.NewAsker(pool)

	got, err := asker.AllowedMany(ctx, subject, "vpc_network", page, "v_get", nil)
	if err != nil {
		t.Fatalf("страничный вопрос: %v", err)
	}
	if len(got) != len(page) {
		t.Fatalf("длина ответа %d при %d объектах", len(got), len(page))
	}

	var wrong []string
	for i, id := range page {
		// Сверка ВНУТРИ пары, а не с пообъектным путём: предмет здесь — что ветвь
		// на странице вообще работает и что она РАЗЛИЧАЕТ, а не что два пути
		// согласны (это утверждает соседняя проба).
		if got[i] != want[i] {
			wrong = append(wrong, fmt.Sprintf("%s: страница=%v, ожидалось %v", id, got[i], want[i]))
		}
	}
	t.Logf("объектов на странице %d: ветви имён, меток и прямого факта — по достижимому и "+
		"недостижимому объекту в каждой", len(page))
	if len(wrong) > 0 {
		t.Fatalf("ветвь правила на странице отвечает не то, что должна: %s", strings.Join(wrong, "; "))
	}
}
