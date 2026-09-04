// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package relverdict_test

// planrows_live_integration_test.go — ПРИБОР ПОРЯДКОВ НА НАСТОЯЩЕМ ПЛАНЕ.
//
// # Предмет — не величина, а прибор
//
// Соседние самопроверки (`pg/planrows`) стоят на синтетике: она даёт вход,
// которого живой план сегодня не даёт вовсе — параллельный узел, незнакомый тип,
// `Bitmap Index Scan` без предка. Здесь предмет ДРУГОЙ и синтетикой не
// проверяемый:
//
//  1. текст запроса взят У ПРОДУКТА, а не переписан. Гейт, планирующий
//     собственную копию, остаётся зелёным ровно тогда, когда продукт исполняет
//     другой предикат, — то есть в единственном интересном случае. Поэтому
//     оператор ЗАХВАТЫВАЕТСЯ трассировщиком у настоящего вызова `Ask`, а его
//     тождество с `verdictQuerySQL` проверяется отдельным утверждением: захват
//     без этой сверки доказывал бы лишь то, что пакет что-то отправил;
//  2. извлекатель разбирает то, что печатает НАСТОЯЩИЙ Postgres, а не то, что
//     мы думаем, будто он печатает;
//  3. несущая величина снята РЯДОМ со сверочной, на ОДНОЙ фикстуре, и их
//     расхождение названо числом. Расхождение законно и ожидаемо — счётчик
//     считает строки, тронутые сканом, а план — отданные узлом после фильтра, —
//     но МОЛЧАНИЕ о нём неотличимо от прибора, меряющего не ту величину.
//
// # Чего эта проба НЕ делает
//
// Она не сравнивает точки, не знает про сетку и не выносит вердикта о
// стоимости. Одна точка, один вопрос: прибор исправен и мерит названное.

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/planrows"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/relverdict"
)

// livePlanObjects — сколько объектов кладётся в зеркало под живую точку.
//
// Величина невелика намеренно: предмет пробы — исправность прибора, а не форма
// кривой. Но и не единица: на пустом зеркале планировщик выбирает план по
// вырожденным оценкам, и разбирался бы план, которого на развёрнутой базе не
// бывает.
const livePlanObjects = 200

// liveWantRelations — ПРЕДПОСЫЛКА замера: отношения, которые запрос вердикта
// обязан читать.
//
// Это не перечень для разложения — разложение прибор берёт из плана. Набор нужен
// затем, чтобы «ноль строк» отличалось от «смотрели не туда»: план, не
// содержащий ни одного из них, означает, что смотреть было негде.
var liveWantRelations = []string{
	"relation_fact", "access_bindings", "access_binding_subjects",
	"role_verb", "role_rule_selectors", "group_members",
	"resource_parent_edge", "resource_mirror",
}

// verdictCapture — трассировщик pgx: производитель входа для прибора.
type verdictCapture struct {
	mu    sync.Mutex
	stmts []capturedVerdictStmt
}

type capturedVerdictStmt struct {
	sql  string
	args []any
}

func (c *verdictCapture) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stmts = append(c.stmts, capturedVerdictStmt{sql: d.SQL, args: d.Args})
	return ctx
}

func (c *verdictCapture) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// matching — захваченные операторы, ТОЖДЕСТВЕННЫЕ тексту запроса вердикта.
//
// Сверка дословная, а не «содержит»: подстрока совпала бы и с оператором,
// который лишь похож, и тогда планировался бы не тот запрос.
func (c *verdictCapture) matching(want string) []capturedVerdictStmt {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []capturedVerdictStmt
	for _, s := range c.stmts {
		if s.sql == want {
			out = append(out, s)
		}
	}
	return out
}

// TestPlanRows_InstrumentReadsTheProductsOwnStatement — прибор на живом плане.
func TestPlanRows_InstrumentReadsTheProductsOwnStatement(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()

	cfg, err := pgxpool.ParseConfig(pgtest.NewDB(t))
	if err != nil {
		t.Fatalf("разбор строки подключения: %v", err)
	}
	capture := &verdictCapture{}
	cfg.ConnConfig.Tracer = capture
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("пул: %v", err)
	}
	pgtest.ClosePoolAtEnd(t, pool)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("транзакция: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Фикстура — готовым посевом пакета, идущим ЧЕРЕЗ ПРОИЗВОДИТЕЛЯ цепи: свой
	// посев прямой записью в таблицу рёбер утверждал бы свойство себя.
	seedLabelledSet(t, ctx, tx, livePlanObjects)

	// Сверочная величина снимается ВОКРУГ того же вопроса и на той же фикстуре.
	before := tuplesRead(t, ctx, tx)
	verdict, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
		Subject:    "user:usr-1",
		ObjectType: "vpc_network",
		ObjectID:   "net-0000000",
		Relation:   "v_get",
	})
	after := tuplesRead(t, ctx, tx)
	if err != nil {
		t.Fatalf("вопрос вердикта: %v", err)
	}
	// Положительный контроль: прибор обязан мерить ВЕРНО отвеченный вопрос.
	// Иначе замерялась бы стоимость запроса, который ничего не находит, и
	// «дёшево» означало бы «не сработало».
	if verdict != relverdict.Allow {
		t.Fatalf("вердикт %s там, где право выдано ролью на проекте: прибор мерил бы "+
			"стоимость неверного ответа", verdict)
	}
	sverochnaya := after - before

	// ── 1. Текст запроса взят у продукта ─────────────────────────────────────
	axis, err := relverdict.LabelAxisForTest("vpc.network", "vpc_network")
	if err != nil {
		t.Fatalf("ось меток: %v", err)
	}
	want := relverdict.VerdictQuerySQLForTest(axis)
	got := capture.matching(want)
	if len(got) != 1 {
		t.Fatalf("захвачено %d операторов, тождественных запросу вердикта, ожидался ровно один.\n"+
			"Ноль означает, что продукт исполняет ДРУГОЙ текст, чем собирает verdictQuerySQL, — "+
			"и прибор планировал бы не тот запрос; больше одного означает, что вопрос задан дважды "+
			"и точка мерит два вопроса вместо одного.", len(got))
	}
	stmt := got[0]
	const wantArgs = 9
	if len(stmt.args) != wantArgs {
		t.Fatalf("у захваченного оператора %d параметров, ожидалось %d "+
			"(субъект, тип, id, типы предков, отношения, глаголы, глубина, предел условий=%d, тип каталога)",
			len(stmt.args), wantArgs, relverdict.MaxConditionRowsForTest)
	}

	// ── 2. План снимается с ЗАХВАЧЕННОГО оператора и его же параметров ───────
	var raw []byte
	if err := tx.QueryRow(ctx,
		"EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT JSON) "+stmt.sql, stmt.args...).Scan(&raw); err != nil {
		t.Fatalf("снятие плана: %v", err)
	}
	m, err := planrows.Extract(raw, liveWantRelations)
	if err != nil {
		t.Fatalf("прибор отказал на живом плане: %v", err)
	}

	// ── 3. Перепись печатается ВСЕГДА, вместе с обеими величинами ────────────
	t.Logf("\n%s\nСВЕРКА ДВУХ ПРИБОРОВ (одна фикстура, ОДИН план)\n"+
		"  несущая (план, отдано узлами)      %d\n"+
		"  сверочная (pg_stat_xact_all_tables) %d\n"+
		"  расхождение сверочная/несущая       %.2f\n"+
		"  ВНИМАНИЕ: отношение читается только ВНУТРИ одного плана; между точками с\n"+
		"  разными планами оно описывает смену плана, а не погрешность.\n",
		m.Census, m.Rows, sverochnaya, float64(sverochnaya)/float64(max64(m.Rows, 1)))

	// ── 4. Утверждения о самом приборе ──────────────────────────────────────
	if m.Rows <= 0 {
		t.Fatalf("несущая величина %d на плане, где предпосылка выполнена: прибор ничего не сосчитал", m.Rows)
	}
	if m.Nodes != m.Attributed+m.Unattributed {
		t.Fatalf("перепись не сходится: узлов %d, отнесено %d, не отнесено %d — "+
			"разница означает узел, выпавший молча", m.Nodes, m.Attributed, m.Unattributed)
	}
	if sverochnaya <= 0 {
		t.Fatalf("сверочная величина %d — счётчик Postgres ничего не насчитал, "+
			"и сверять несущую не с чем", sverochnaya)
	}

	// ── МНОЖИТЕЛЬ ЦИКЛОВ: плечо переехало на СВОЙ план, и это записано ───────
	//
	// Прежняя редакция требовала узла с числом циклов больше одного ОТ ПЛАНА
	// ВЕРДИКТА и обосновывала это рекурсивным обходом цепи областей. Обхода
	// больше нет (R7-1-18: замыкание читается одним обращением), поэтому
	// требование стало ложным: оно краснело бы на верной правке. Плечо не
	// снято — оно перенесено на план, который циклы даёт ПО ПОСТРОЕНИЮ, и
	// утверждает ровно то, ради чего стояло: прибор умножает на число циклов, а
	// не берёт `Actual Rows` как есть.
	//
	// Оставить прежнюю форму значило бы держать проверку, у которой предмет
	// исчез; заменить её синтетикой — потерять «на живом Postgres», ради чего
	// файл и существует.
	var loopRaw []byte
	if err := tx.QueryRow(ctx, `EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT JSON)
		SELECT count(*) FROM kacho_iam.resource_mirror m
		 WHERE EXISTS (SELECT 1 FROM kacho_iam.accounts a WHERE a.id = m.parent_account_id)`).Scan(&loopRaw); err != nil {
		t.Fatalf("снятие плана с циклами: %v", err)
	}
	lm, err := planrows.Extract(loopRaw, []string{"accounts", "resource_mirror"})
	if err != nil {
		t.Fatalf("прибор отказал на плане с циклами: %v", err)
	}
	var multiCycle []planrows.Access
	for _, a := range lm.Accesses {
		if a.Loops > 1 {
			multiCycle = append(multiCycle, a)
		}
	}
	if len(multiCycle) == 0 {
		t.Fatalf("на плане, построенном РАДИ циклов, ни один отнесённый узел не идёт больше чем в\n"+
			"один цикл: плечо множителя оказалось бы зелёным при любом поведении прибора.\nПерепись:\n%s",
			lm.Census)
	}
	a0 := multiCycle[0]
	if a0.Rows < int64(a0.Loops) {
		t.Errorf("узел %s на %s: циклов %d, строк %d — множитель не применён "+
			"(величина совпала бы с `Actual Rows` без множителя)", a0.NodeType, a0.Relation, a0.Loops, a0.Rows)
	}
	t.Logf("множитель на живом плане: узлов с числом циклов больше одного %d "+
		"(первый — %s на %s, циклов %d, строк %d)",
		len(multiCycle), a0.NodeType, a0.Relation, a0.Loops, a0.Rows)

	// План вердикта после R7-1-18 циклов больше не обязан давать вовсе — это
	// СЛЕДСТВИЕ починки, и оно печатается, чтобы «циклов нет» не читалось как
	// «прибор их потерял».
	var verdictMulti int
	for _, a := range m.Accesses {
		if a.Loops > 1 {
			verdictMulti++
		}
	}
	t.Logf("на плане вердикта узлов с числом циклов больше одного: %d "+
		"(обход цепи областей снят, замыкание читается одним обращением)", verdictMulti)

	// Ключ отнесения назван у каждого доступа — без него «отнесено» нельзя
	// оспорить, а разбор отнесения есть единственный способ отличить объявленное
	// правило от подобранного под числа.
	for _, a := range m.Accesses {
		if a.Key == "" {
			t.Fatalf("доступ к %s (%s) отнесён без названного ключа: %+v", a.Relation, a.NodeType, a)
		}
	}
	if !strings.Contains(m.Census, strings.TrimSpace(planrows.AttributionRule)) {
		t.Fatal("перепись живого плана не печатает правило отнесения дословно из кода")
	}
}

// TestPlanRows_RefusesOnAPlanThatCannotCarryTheMeasurement — отказ на живом
// Postgres, а не только на синтетике.
//
// Отрицательное плечо к пробе выше: прибор, отдающий число по любому плану,
// прошёл бы её и молча превратил бы «смотрели не туда» в «работы не было».
func TestPlanRows_RefusesOnAPlanThatCannotCarryTheMeasurement(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)

		var raw []byte
		if err := tx.QueryRow(ctx,
			`EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT JSON)
			 SELECT id FROM kacho_iam.accounts WHERE id = $1`, "acc-1").Scan(&raw); err != nil {
			t.Fatalf("снятие плана: %v", err)
		}

		// Положительный контроль ПЕРВЫМ: тот же план с верной предпосылкой обязан
		// дать число. Иначе «отказал» было бы неотличимо от «прибор сломан».
		okm, err := planrows.Extract(raw, []string{"accounts"})
		if err != nil {
			t.Fatalf("прибор отказал там, где ожидаемое отношение в плане ЕСТЬ: %v", err)
		}
		if okm.Rows <= 0 {
			t.Fatalf("на плане чтения аккаунта величина %d", okm.Rows)
		}

		// И отказ — на том же плане с предпосылкой, которой этот план не несёт.
		_, err = planrows.Extract(raw, liveWantRelations)
		if err == nil {
			t.Fatal("прибор отдал число по плану, не содержащему ни одного отношения пути вердикта: " +
				"ноль в этом случае означает «не нашли, где смотреть», а не «работы не было»")
		}
		if !strings.Contains(err.Error(), "relation_fact") {
			t.Fatalf("отказ не называет, чего искали: %v", err)
		}
		t.Logf("отказ на живом плане получен и назван: %s", firstLine(err.Error()))
	})
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
