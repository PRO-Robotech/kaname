// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package relverdict_test

// matrix_volume_integration_test.go — СТОИМОСТЬ ОДНОЙ ОПЕРАЦИИ ПРОТИВ ОБЪЁМА БАЗЫ.
//
// # Чем этот прибор отличается от соседних — предмет РАЗНЫЙ, а не «шире»
//
// Соседний прибор порядков (scalegrid_probe_integration_test.go) варьирует ОДНУ
// ось за раз: его точка N = 10⁶ держит выдач тысячу, а точка B = 10⁶ держит
// объектов тысячу. То есть база в нём НИКОГДА не бывала полной — произведение
// осей не наливалось ни разу. Соседний прибор предела прочности варьирует
// РАЗМЕР ОДНОЙ ВЫДАЧИ (членов, правил, веер) и тоже не про объём базы.
//
// Здесь наоборот: матрица прав наливается ЦЕЛИКОМ (объекты и выдачи растут
// вместе), а операций делается ПО ОДНОЙ. Вопрос не «сколько в секунду», а
// «меняется ли стоимость ОДНОЙ операции от того, сколько всего лежит в базе».
//
// # Четыре операции, и порядок между ними ПРИЧИННЫЙ, а не декоративный
//
//	1. ЗАПИСЬ           — создать одну выдачу (продуктовый путь);
//	2. ЧТЕНИЕ           — вердикт по объекту и глаголу; обязан быть allow;
//	3. УДАЛЕНИЕ         — отозвать ту же выдачу (продуктовый путь);
//	4. ПРОВЕРКА ОТЗЫВА  — вердикт по ТОМУ ЖЕ объекту; обязан быть deny.
//
// Перечень называет четыре операции, а не их порядок: без записи нечего
// отзывать, а без отзыва нечего проверять. Поэтому запись идёт первой, и
// «чтение» меряется на ПОЛОЖИТЕЛЬНОМ пути, а «проверка отзыва» — на
// ОТРИЦАТЕЛЬНОМ. Это и есть несущая пара: положительный вердикт вправе
// ответить первой же подошедшей строкой, отрицательный обязан дочитать набор
// источников до конца, — и мерить надо оба, иначе «чтение дешёвое» сказано про
// половину случаев.
//
// Шаги 2 и 4 — УТВЕРЖДЕНИЯ, а не печать. Allow, оказавшийся deny, означал бы,
// что запись не доехала; deny, оказавшийся allow, — что отзыв не подействовал.
// Прибор, печатающий вердикт без проверки, зеленел бы на обоих.
//
// # Чего этот прибор НЕ меряет — названо ДО чисел, а не после
//
//   - Меряется РЕЛЯЦИОННАЯ форма вердикта — тот код, который отвечает на вопрос
//     о доступе по таблицам iam, и сегодня он же принимает решение: внешнего
//     движка отношений в продукте нет, он снят стадией S6 эпика #747. Прежде
//     здесь стояла оговорка «движок не участвует: он требует поднятого стенда»
//     — то есть оговорка о существовании снятого;
//   - МАТЕРИАЛИЗАЦИЯ прав (reconcile.Reconciler) не запускается вовсе, и это не
//     пропуск: отзыв даёт отказ НЕМЕДЛЕННО и в тех же таблицах, потому что
//     ветвь выдач запроса вердикта несёт `b.status = 'ACTIVE'` и
//     `b.revoked_at IS NULL`. Наполнение журнала — предмет соседнего прибора
//     (запись и отзыв), а не этого;
//   - СЕТЬ, край, кэши вердиктов — здесь нет ни одного.
//
// # Сверочная величина снимается ТОЛЬКО на чтениях, и вот почему
//
// `pg_stat_xact_all_tables` — счётчик ТЕКУЩЕЙ транзакции. Чтения прибор ведёт
// на своей транзакции и вправе спросить её изнутри. Запись и отзыв идут в
// СОБСТВЕННОЙ транзакции продукта (`repo.Writer` открывает свою), изнутри
// которой прибор не спрашивает ничего. Подставить туда накопительный счётчик
// базы значило бы сменить единицу молча, поэтому на записи и отзыве этой
// колонки НЕТ — и это отличимо от нуля отдельным признаком.

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/planrows"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/relverdict"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/scalegrid"
)

// matrixEnv — ручка «запускать замер матрицы», и только это. Что мерить, она не
// решает: сетка стоит константой ниже и ниоткуда не переопределяется.
const matrixEnv = "KACHO_MATRIX_VOLUME"

// matrixRunCommand — команда повторения, дословно. Константой рядом с ручкой,
// потому что попадает в отчёт: отчёт без дословной команды через месяц нечем
// проверить.
const matrixRunCommand = "KACHO_MATRIX_VOLUME=1 go test " +
	"./services/iam/internal/repo/kacho/pg/relverdict/ -run TestMatrixVolume_Report " +
	"-count=1 -v -timeout 120m"

// matrixReportPath — куда ложится отчёт, рядом с отчётами соседних приборов.
const matrixReportPath = "services/iam/internal/repo/kacho/pg/scalegrid/REPORT-R7-3-matrix-volume.txt"

// ── ПРЕДМЕТ ВОПРОСА ──────────────────────────────────────────────────────────

const (
	// matrixUserID — субъект пробы. СВЕЖИЙ и БЕЗ ЕДИНОЙ иной выдачи: будь у него
	// вторая, отзыв первой не дал бы отказа, и шаг 4 стал бы невыполним — то
	// есть прибор мерил бы не то, что называет.
	matrixUserID  = "usr-mx"
	matrixSubject = "user:" + matrixUserID
	// matrixRoleID — своя роль, не разделяемая ни с одним посевом осей.
	matrixRoleID   = "rol-mx"
	matrixRoleName = "probe.mx"
	// matrixObjectID — объект вопроса; существует на КАЖДОЙ точке (нижняя сеет
	// тысячу объектов).
	matrixObjectID = "repo-0000000"
	// matrixGrantedBy — кто выдал и кто отзывает. Отзыв без отзывающего схема не
	// принимает (`access_bindings_revoked_consistency_ck`).
	matrixGrantedBy = "usr-1"
)

// matrixRepeats — сколько полных циклов из четырёх операций идёт на точке.
//
// Нулевой цикл ПРОГРЕВОЧНЫЙ: исполняется, но в выборку не входит. Первый вопрос
// на свежей точке платит за разбор и за первое касание страниц, и его включение
// сдвинуло бы медиану на величину, к объёму базы отношения не имеющую.
//
// Одиннадцать, а не двадцать один, как у соседнего прибора чтения: там повтор
// стоит одного вопроса, здесь — ещё и записи с отзывом, то есть настоящих строк
// в базе. Десять замеров после прогрева дают медиану, а цена остаётся
// пренебрежимой против миллиона посеянных строк.
const matrixRepeats = 11

// ── СЕТКА ────────────────────────────────────────────────────────────────────

// matrixPoint — точка ОБЪЁМА, а не оси. Величины растут ВМЕСТЕ; в этом весь
// предмет прибора. Точка, двигающая одну величину при неподвижных остальных,
// уже измерена соседом, и повторять её здесь значило бы отвечать на чужой
// вопрос.
type matrixPoint struct {
	Name       string
	N, B, R, F int
}

// grid — та же точка в форме, которую понимают посевщик и перепись.
//
// Ось объявлена N потому, что `Census.Verify` читает у точки ПОРОГИ (N/B/R/F),
// а не имя оси. Имя оси в этой форме ни на что не влияет и в отчёт не попадает:
// отчёт печатает `matrixPoint.String`.
func (p matrixPoint) grid() scalegrid.Point {
	return scalegrid.Point{
		Axis: scalegrid.AxisN, N: p.N, B: p.B, R: p.R, F: p.F,
		Recruit: scalegrid.RecruitDirect,
	}
}

func (p matrixPoint) String() string {
	return fmt.Sprintf("%s (объектов %d × выдач %d, R=%d F=%d)", p.Name, p.N, p.B, p.R, p.F)
}

// matrixPoints — четыре точки объёма по возрастанию.
//
// Произведение, а не одна ось: на верхней точке в таблицах лежит около 6·10⁶
// строк (10⁶ объектов + 3·10⁶ рёбер их цепи + 2·10⁶ строк выдач), тогда как ни
// один соседний прибор этих величин одновременно не наливал.
//
// R и F неподвижны намеренно: они не про объём базы, а про то, сколько строк
// адресует ЛИЧНО спрашиваемого, и их влияние измерено соседом по своим осям.
// Держать их подвижными здесь значило бы смешать два вопроса в одной кривой.
var matrixPoints = []matrixPoint{
	{Name: "малая", N: 1000, B: 1000, R: 9, F: 1},
	{Name: "средняя", N: 10000, B: 10000, R: 9, F: 1},
	{Name: "большая", N: 100000, B: 100000, R: 9, F: 1},
	{Name: "предельная", N: 1000000, B: 1000000, R: 9, F: 1},
}

// matrixGridText — сетка словами, для шапки отчёта.
//
// Своя, а не `scalegrid.Describe`: та печатает «ось X: значения — неподвижны
// …», что для матрицы было бы ложью — здесь неподвижных нет.
func matrixGridText() string {
	var b strings.Builder
	fmt.Fprintf(&b, "  матрица (объекты и выдачи растут ВМЕСТЕ, неподвижных осей нет):\n")
	for _, p := range matrixPoints {
		fmt.Fprintf(&b, "    %-12s объектов %8d · выдач %8d · выдач на спрашиваемого %d · фактов %d\n",
			p.Name, p.N, p.B, p.R, p.F)
	}
	fmt.Fprintf(&b, "  циклов из четырёх операций на точку: %d (нулевой прогревочный, в выборку не входит)\n",
		matrixRepeats)
	return b.String()
}

// matrixGridDigest — отпечаток сетки по СОДЕРЖИМОМУ точек.
func matrixGridDigest() string {
	parts := make([]string, 0, len(matrixPoints))
	for _, p := range matrixPoints {
		parts = append(parts, p.String())
	}
	return scalegrid.Digest([][]scalegrid.Point{gridOf(matrixPoints)}) + "/" +
		fmt.Sprintf("%02d", len(parts))
}

func gridOf(ps []matrixPoint) []scalegrid.Point {
	out := make([]scalegrid.Point, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.grid())
	}
	return out
}

// ── ОПЕРАЦИИ ─────────────────────────────────────────────────────────────────

// opKind — одна из четырёх операций. Строкой, потому что она же печатается.
type opKind string

const (
	opWrite  opKind = "запись (создать выдачу)"
	opRead   opKind = "чтение (вердикт, allow)"
	opRevoke opKind = "удаление (отозвать выдачу)"
	opCheck  opKind = "проверка отзыва (вердикт, deny)"
)

// matrixOps — порядок печати; совпадает с порядком исполнения.
func matrixOps() []opKind { return []opKind{opWrite, opRead, opRevoke, opCheck} }

// opResult — стоимость ОДНОЙ операции на одной точке.
type opResult struct {
	kind opKind

	// rows / removed / touched — несущая величина: строки плана
	// (Actual Rows × Actual Loops листовых узлов), отброшенное и их сумма.
	rows, removed, touched int64
	// planTaken — снят ли план. Без признака «ноль строк» неотличимо от «плана
	// не снимали», а это разные вещи.
	planTaken bool
	plan      string

	// tuples — сверочная величина (`pg_stat_xact_all_tables`); заполняется
	// ТОЛЬКО на чтениях, см. шапку файла. tuplesTaken отличает «не спрашивали»
	// от «Postgres ничего не прочитал».
	tuples      int64
	tuplesTaken bool

	// calls — обращений к БД на ОДНУ операцию, трассировщиком pgx. Собственные
	// запросы прибора в счёт НЕ входят.
	calls int64

	// p50 / p95 — часы. Наблюдение, не вердикт.
	p50, p95 time.Duration

	// verdict — исход вердикта для чтений; пусто для записи и отзыва.
	verdict string
}

func (r opResult) ratio() float64 {
	if r.rows == 0 || !r.tuplesTaken {
		return 0
	}
	return float64(r.tuples) / float64(r.rows)
}

// tableCount — строка переписи объёма: таблица, строк, байт.
type tableCount struct {
	table string
	rows  int64
	bytes int64
}

// matrixResult — одна точка целиком.
type matrixResult struct {
	point  matrixPoint
	census scalegrid.Census
	// tables — перепись ПО КАЖДОЙ таблице порознь: строки и занятое место. Без
	// неё «объём базы» — слово, а не величина.
	tables  []tableCount
	dbRows  int64
	dbBytes int64
	seedIn  time.Duration
	ops     map[opKind]opResult
	cycles  int
}

// ── ПРЕДПОСЫЛКИ ПЛАНА ────────────────────────────────────────────────────────

// matrixWantRead — отношения, которые ОБЯЗАН читать запрос вердикта. Тот же
// перечень, что у соседнего прибора чтения: предмет один, и второй перечень
// разошёлся бы с первым молча.
var matrixWantRead = probeWantRelations

// matrixWantWrite — отношение, которое обязаны назвать вставка и отзыв выдачи.
var matrixWantWrite = []string{"access_bindings"}

// ── ПОСЕВ И ПОДКЛЮЧЕНИЕ ──────────────────────────────────────────────────────

// matrixDSN — строка подключения с областью имён продукта.
//
// Нужна потому, что продуктовый писатель выдач адресует таблицы БЕЗ схемы
// (`INSERT INTO access_bindings …`), тогда как запрос вердикта — со схемой.
// Прибор, поднявший пул без `search_path`, получил бы отказ на первой же записи
// и был бы вправе счесть его дефектом продукта; дефекта нет, есть разная форма
// адресации, и удовлетворена она обязана быть здесь.
func matrixDSN(t *testing.T) string {
	t.Helper()
	return pgtest.NewDB(t)
}

// openMatrixPool — пул с трассировщиком.
//
// Соединений НЕСКОЛЬКО, в отличие от соседнего прибора чтения: тот держал одно,
// потому что весь его посев жил в НЕЗАКОММИЧЕННОЙ транзакции и второе
// соединение видело бы пустую базу. Здесь посев КОММИТИТСЯ — иначе продуктовый
// путь записи (он открывает свою транзакцию из пула) не увидел бы ни объекта,
// ни роли, — и ограничение снимается вместе со своей причиной.
func openMatrixPool(t *testing.T, ctx context.Context) (*pgxpool.Pool, *verdictCapture) {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(matrixDSN(t))
	if err != nil {
		t.Fatalf("разбор строки подключения: %v", err)
	}
	capture := &verdictCapture{}
	cfg.ConnConfig.Tracer = capture
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("пул: %v", err)
	}
	pgtest.ClosePoolAtEnd(t, pool)
	return pool, capture
}

// seedMatrixSubject — субъект вопроса и его роль. Один раз на всю базу.
func seedMatrixSubject(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
		 VALUES ($1, 'ext-mx', 'usr-mx@kacho.local', 'acc-1')`, matrixUserID)
	seedProbeRole(t, ctx, tx, matrixRoleID, matrixRoleName)
}

// matrixBinding — выдача, которую создаёт и отзывает каждый цикл.
func matrixBinding(id string) domain.AccessBinding {
	return domain.AccessBinding{
		ID:              domain.AccessBindingID(id),
		SubjectType:     domain.SubjectTypeUser,
		SubjectID:       domain.SubjectID(matrixUserID),
		RoleID:          domain.RoleID(matrixRoleID),
		ResourceType:    "project",
		ResourceID:      "prj-1",
		Scope:           domain.ScopeProject,
		Status:          domain.AccessBindingStatusActive,
		GrantedByUserID: matrixGrantedBy,
	}
}

// matrixQuery — вопрос вердикта. Один и тот же на обоих чтениях: «тот же
// объект» из перечня операций — требование, а не оборот речи.
func matrixQuery() relverdict.Query {
	return relverdict.Query{
		Subject:    matrixSubject,
		ObjectType: probeModelType,
		ObjectID:   matrixObjectID,
		Relation:   probeRelation,
	}
}

// ── ПЕРЕПИСЬ ОБЪЁМА ──────────────────────────────────────────────────────────

// matrixTables — таблицы, по которым идёт перепись объёма.
//
// Перечень ВЫПИСАН, и это признаётся вслух. Вывести его из кода вердикта, как
// делает отпечаток предмета, здесь нельзя: половина этих таблиц вердиктом не
// читается вовсе (`users`, `roles`), а лежать в базе обязана — объём базы это
// всё, что в ней лежит, а не только читаемое одним запросом. Цена выписанного
// перечня названа: таблица, заведённая позже, в перепись молча не попадёт.
var matrixTables = []string{
	"resource_mirror",
	"resource_parent_edge",
	"access_bindings",
	"access_binding_subjects",
	"group_members",
	"roles",
	"role_verb",
	"role_rule_selectors",
	"relation_fact",
	"users",
}

// takeMatrixTables — строки и байты ПО КАЖДОЙ таблице порознь.
//
// Порознь, а не одним квантифицирующим стейтментом: счёт по таблице квантора не
// несёт, и смешивать его с утверждением «у каждой строки зеркала есть цепь»
// нельзя. Байты берутся `pg_total_relation_size` — вместе с индексами, потому
// что индекс тоже лежит в базе и тоже читается.
func takeMatrixTables(t *testing.T, ctx context.Context, tx pgx.Tx) ([]tableCount, int64, int64) {
	t.Helper()
	out := make([]tableCount, 0, len(matrixTables))
	var totalRows, totalBytes int64
	for _, tbl := range matrixTables {
		var n, b int64
		if err := tx.QueryRow(ctx,
			fmt.Sprintf(`SELECT count(*)::bigint FROM kacho_iam.%s`, tbl)).Scan(&n); err != nil {
			t.Fatalf("перепись строк %s: %v", tbl, err)
		}
		if err := tx.QueryRow(ctx,
			`SELECT pg_total_relation_size($1)::bigint`, "kacho_iam."+tbl).Scan(&b); err != nil {
			t.Fatalf("перепись места %s: %v", tbl, err)
		}
		out = append(out, tableCount{table: tbl, rows: n, bytes: b})
		totalRows += n
		totalBytes += b
	}
	return out, totalRows, totalBytes
}

// ── ОПЕРАЦИИ, КАЖДАЯ СО СВОИМ ЗАМЕРОМ ────────────────────────────────────────

// askOnMatrix — один вердикт на СВОЕЙ транзакции чтения.
//
// Своя транзакция на вопрос, а не одна на все повторы: сверочная величина
// транзакционная, и на общей транзакции она копила бы работу всех предыдущих
// вопросов — то есть росла бы от числа повторов, а не от объёма базы.
//
// Число обращений снимается ДО того, как прибор задаст собственный запрос о
// прочитанных строках: иначе в «обращения операции» попал бы вопрос прибора.
func askOnMatrix(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	capture *verdictCapture) (relverdict.Verdict, int64, int64, time.Duration) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("транзакция чтения: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	before := tuplesRead(t, ctx, tx)
	capture.reset()
	t0 := time.Now()
	v, _, err := relverdict.Ask(ctx, tx, matrixQuery())
	took := time.Since(t0)
	calls := int64(capture.count())
	if err != nil {
		t.Fatalf("вопрос вердикта: %v", err)
	}
	after := tuplesRead(t, ctx, tx)
	return v, after - before, calls, took
}

// writeOnMatrix — продуктовая запись выдачи: строка выдачи и строки её субъектов.
//
// Обе вставки идут ОДНОЙ транзакцией писателя, как их делает продуктовый
// use-case создания. Строка выдачи без строки субъекта вердиктом не читается
// вовсе, и «запись», ограниченная первой вставкой, создала бы выдачу, которой
// вердикт не видит, — то есть шаг 2 упал бы на исправном продукте.
//
// Возвращает захваченный оператор вставки: план снимается с ТОГО ЖЕ текста,
// который исполнил продукт, а не с редакции прибора.
func writeOnMatrix(t *testing.T, ctx context.Context, repo *kachopg.Repository,
	capture *verdictCapture, id string) (int64, time.Duration, capturedVerdictStmt) {
	t.Helper()
	w, err := repo.Writer(ctx)
	if err != nil {
		t.Fatalf("писатель: %v", err)
	}
	// Освобождение соединения на ЛЮБОМ пути: упавшее утверждение завершает
	// горутину теста с невозвращённым соединением, и закрытие пула ждёт его до
	// конца прогона — пакет умирает по сроку, не напечатав причины.
	defer func() { _ = w.Rollback(ctx) }()

	capture.reset()
	t0 := time.Now()
	if _, err := w.AccessBindingsW().Insert(ctx, matrixBinding(id)); err != nil {
		t.Fatalf("вставка выдачи %s: %v", id, err)
	}
	if err := w.AccessBindingsW().InsertSubjects(ctx, domain.AccessBindingID(id),
		[]domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(matrixUserID)}}); err != nil {
		t.Fatalf("вставка субъектов выдачи %s: %v", id, err)
	}
	if err := w.Commit(ctx); err != nil {
		t.Fatalf("фиксация записи %s: %v", id, err)
	}
	took := time.Since(t0)
	calls := int64(capture.count())
	return calls, took, findCaptured(t, capture, "вставки выдачи", "INSERT INTO access_bindings")
}

// revokeOnMatrix — продуктовый отзыв выдачи.
func revokeOnMatrix(t *testing.T, ctx context.Context, repo *kachopg.Repository,
	capture *verdictCapture, id string) (int64, time.Duration, capturedVerdictStmt) {
	t.Helper()
	w, err := repo.Writer(ctx)
	if err != nil {
		t.Fatalf("писатель: %v", err)
	}
	defer func() { _ = w.Rollback(ctx) }()

	capture.reset()
	t0 := time.Now()
	out, err := w.AccessBindingsW().RevokeGuarded(ctx, domain.AccessBindingID(id), matrixGrantedBy)
	if err != nil {
		t.Fatalf("отзыв выдачи %s: %v", id, err)
	}
	if out.Status != domain.AccessBindingStatusRevoked {
		t.Fatalf("отзыв выдачи %s вернул состояние %s, ожидалось REVOKED", id, out.Status)
	}
	if err := w.Commit(ctx); err != nil {
		t.Fatalf("фиксация отзыва %s: %v", id, err)
	}
	took := time.Since(t0)
	calls := int64(capture.count())
	return calls, took, findCaptured(t, capture, "отзыва выдачи", "UPDATE access_bindings")
}

// findCaptured — захваченный оператор, начинающийся с образца.
//
// Сверка по НАЧАЛУ текста, а не по вхождению: вхождение совпало бы и с
// оператором, который таблицу лишь упоминает, и планировался бы не тот запрос.
// Ровно один — обязательное требование: ноль означает, что продукт исполняет
// другой текст, больше одного — что прибор мерит две операции.
func findCaptured(t *testing.T, capture *verdictCapture, what, prefix string) capturedVerdictStmt {
	t.Helper()
	capture.mu.Lock()
	defer capture.mu.Unlock()
	var out []capturedVerdictStmt
	for _, s := range capture.stmts {
		if strings.HasPrefix(strings.TrimSpace(s.sql), prefix) {
			out = append(out, s)
		}
	}
	if len(out) != 1 {
		t.Fatalf("захвачено %d операторов %s (образец %q), ожидался один: ноль означает, "+
			"что продукт исполняет другой текст, больше одного — что прибор мерит две операции",
			len(out), what, prefix)
	}
	return out[0]
}

// ── ПЛАНЫ ────────────────────────────────────────────────────────────────────

// matrixPlanShape — отпечаток плана по СВОЕЙ предпосылке.
//
// Своя, а не общая с чтением: у вставки и отзыва предпосылка другая, и разбор их
// плана перечнем отношений вердикта вернул бы «план не разобран» на исправном
// плане.
func matrixPlanShape(raw []byte, want []string) string {
	m, err := planrows.Extract(raw, want)
	if err != nil {
		return "план не разобран"
	}
	types := make([]string, 0, len(m.Accesses))
	seen := map[string]bool{}
	for _, a := range m.Accesses {
		key := a.NodeType + "→" + a.Relation
		if !seen[key] {
			seen[key] = true
			types = append(types, key)
		}
	}
	sort.Strings(types)
	return strings.Join(types, " ")
}

// explainCaptured — план ЗАХВАЧЕННОГО оператора.
func explainCaptured(t *testing.T, ctx context.Context, tx pgx.Tx,
	stmt capturedVerdictStmt, want []string) (planrows.Measurement, string) {
	t.Helper()
	var raw []byte
	if err := tx.QueryRow(ctx,
		"EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT JSON) "+stmt.sql, stmt.args...).Scan(&raw); err != nil {
		t.Fatalf("снятие плана: %v", err)
	}
	m, err := planrows.Extract(raw, want)
	if err != nil {
		t.Fatalf("прибор строк плана отказал: %v", err)
	}
	return m, matrixPlanShape(raw, want)
}

// withArg0 — тот же оператор с ДРУГИМ первым параметром.
//
// Нужен потому, что `EXPLAIN ANALYZE` ИСПОЛНЯЕТ то, что планирует. Повторить
// настоящую вставку значило бы нарушить уникальность действующей выдачи;
// поэтому план вставки снимается на ДВОЙНИКЕ — том же операторе с новым
// идентификатором — в транзакции, которая затем откатывается. Настоящая
// операция остаётся закоммиченной, а её часы и обращения сняты отдельно.
func withArg0(stmt capturedVerdictStmt, v any) capturedVerdictStmt {
	args := make([]any, len(stmt.args))
	copy(args, stmt.args)
	if len(args) > 0 {
		args[0] = v
	}
	return capturedVerdictStmt{sql: stmt.sql, args: args}
}

func withPlan(r opResult, m planrows.Measurement, shape string) opResult {
	r.rows, r.removed, r.touched = m.Rows, m.Removed, m.Touched
	r.plan, r.planTaken = shape, true
	return r
}

// askAndExplain — вердикт и план ОДНОГО и того же вопроса.
func matrixAskAndExplain(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	capture *verdictCapture, want relverdict.Verdict) (planrows.Measurement, string) {
	t.Helper()
	axis, err := relverdict.LabelAxisForTest(probeCatalogType, probeModelType)
	if err != nil {
		t.Fatalf("ось меток: %v", err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("транзакция снятия плана: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	capture.reset()
	v, _, err := relverdict.Ask(ctx, tx, matrixQuery())
	if err != nil {
		t.Fatalf("вопрос вердикта при снятии плана: %v", err)
	}
	if v != want {
		t.Fatalf("при снятии плана вердикт %s, ожидался %s", v, want)
	}
	stmts := capture.matching(relverdict.VerdictQuerySQLForTest(axis))
	if len(stmts) != 1 {
		t.Fatalf("захвачено %d операторов, тождественных запросу вердикта, ожидался один: "+
			"ноль означает, что продукт исполняет другой текст, больше одного — что прибор "+
			"мерит два вопроса", len(stmts))
	}
	return explainCaptured(t, ctx, tx, stmts[0], matrixWantRead)
}

// ── ЗАМЕР ТОЧКИ ──────────────────────────────────────────────────────────────

// measureMatrixPoint — четыре операции на одной точке объёма.
func measureMatrixPoint(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	repo *kachopg.Repository, capture *verdictCapture, p matrixPoint, seq *int) matrixResult {
	t.Helper()
	res := matrixResult{point: p, ops: map[opKind]opResult{}, cycles: matrixRepeats}

	durs := map[opKind][]time.Duration{}
	calls := map[opKind]int64{}
	tuples := map[opKind]int64{}
	var insertStmt, revokeStmt capturedVerdictStmt

	for i := 0; i < matrixRepeats; i++ {
		*seq++
		id := fmt.Sprintf("acb-mx%014d", *seq)

		wCalls, wTook, wStmt := writeOnMatrix(t, ctx, repo, capture, id)

		v, rTuples, rCalls, rTook := askOnMatrix(t, ctx, pool, capture)
		if v != relverdict.Allow {
			t.Fatalf("точка %s, цикл %d: после записи вердикт %s, ожидался allow — "+
				"выдача создана, но доступа не даёт", p, i, v)
		}

		dCalls, dTook, dStmt := revokeOnMatrix(t, ctx, repo, capture, id)

		cv, cTuples, cCalls, cTook := askOnMatrix(t, ctx, pool, capture)
		if cv != relverdict.Deny {
			t.Fatalf("точка %s, цикл %d: после отзыва вердикт %s, ожидался deny — "+
				"отзыв не подействовал", p, i, cv)
		}

		insertStmt, revokeStmt = wStmt, dStmt

		// Нулевой цикл прогревочный: исполняется, но в выборку не входит.
		if i == 0 {
			continue
		}
		durs[opWrite] = append(durs[opWrite], wTook)
		durs[opRead] = append(durs[opRead], rTook)
		durs[opRevoke] = append(durs[opRevoke], dTook)
		durs[opCheck] = append(durs[opCheck], cTook)
		calls[opWrite], calls[opRead] = wCalls, rCalls
		calls[opRevoke], calls[opCheck] = dCalls, cCalls
		tuples[opRead], tuples[opCheck] = rTuples, cTuples
	}

	for _, k := range matrixOps() {
		d := durs[k]
		sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
		r := opResult{kind: k, calls: calls[k], p50: quantile(d, 0.50), p95: quantile(d, 0.95)}
		switch k {
		case opRead:
			r.verdict, r.tuples, r.tuplesTaken = relverdict.Allow.String(), tuples[k], true
		case opCheck:
			r.verdict, r.tuples, r.tuplesTaken = relverdict.Deny.String(), tuples[k], true
		}
		res.ops[k] = r
	}

	// ── ПЛАНЫ.
	//
	// Порядок здесь ВЫНУЖДЕННЫЙ, и вынуждает его схема: действующая выдача одна
	// на пятёрку (субъект, роль, область, отбор). Пока выдача действует, ВТОРУЮ
	// такую же — в том числе двойника под `EXPLAIN` — вставить нельзя, отвергнет
	// частичная уникальность. Поэтому план вставки снимается ПОКА действующей
	// выдачи нет, а план отзыва — КОГДА она есть. Первая редакция сняла их
	// подряд и упала на 23505; ошибка сохранена здесь абзацем, потому что
	// порядок выглядит произвольным ровно до тех пор, пока не наступишь.
	//
	// Состояние на входе: все выдачи цикла отозваны, значит вердикт deny.

	// 1) отрицательное чтение — на нынешнем состоянии, без подготовки.
	m, shape := matrixAskAndExplain(t, ctx, pool, capture, relverdict.Deny)
	res.ops[opCheck] = withPlan(res.ops[opCheck], m, shape)

	// 2) вставка — двойником, ПОКА действующей выдачи нет.
	*seq++
	func() {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("транзакция снятия плана вставки: %v", err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		m, shape := explainCaptured(t, ctx, tx,
			withArg0(insertStmt, fmt.Sprintf("acb-mx%014d", *seq)), matrixWantWrite)
		res.ops[opWrite] = withPlan(res.ops[opWrite], m, shape)
	}()

	// 3) положительное чтение — воспроизводится настоящей выдачей: allow без
	// действующей выдачи не существует, и снимать его план было бы не с чего.
	*seq++
	planID := fmt.Sprintf("acb-mx%014d", *seq)
	if _, _, _, err := repoWrite(t, ctx, repo, planID); err != nil {
		t.Fatalf("подготовка плана положительного пути: %v", err)
	}
	m, shape = matrixAskAndExplain(t, ctx, pool, capture, relverdict.Allow)
	res.ops[opRead] = withPlan(res.ops[opRead], m, shape)

	// 4) отзыв — двойником на ДЕЙСТВУЮЩЕЙ выдаче: отозванная дала бы ноль
	// изменённых строк и план, описывающий несделанную работу.
	func() {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("транзакция снятия плана отзыва: %v", err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		m, shape := explainCaptured(t, ctx, tx, withArg0(revokeStmt, planID), matrixWantWrite)
		res.ops[opRevoke] = withPlan(res.ops[opRevoke], m, shape)
	}()

	// Выдача, созданная ради плана, снимается по-настоящему: оставленная
	// действующей, она дала бы allow там, где следующая точка ждёт deny.
	if _, _, _, err := repoRevoke(t, ctx, repo, planID); err != nil {
		t.Fatalf("снятие выдачи, созданной ради плана: %v", err)
	}
	return res
}

// repoWrite / repoRevoke — те же продуктовые вызовы без утверждений о часах:
// подготовка плана меряться не должна, она лишь создаёт состояние.
func repoWrite(t *testing.T, ctx context.Context, repo *kachopg.Repository,
	id string) (domain.AccessBinding, int64, time.Duration, error) {
	t.Helper()
	w, err := repo.Writer(ctx)
	if err != nil {
		return domain.AccessBinding{}, 0, 0, err
	}
	defer func() { _ = w.Rollback(ctx) }()
	out, err := w.AccessBindingsW().Insert(ctx, matrixBinding(id))
	if err != nil {
		return out, 0, 0, err
	}
	if err := w.AccessBindingsW().InsertSubjects(ctx, domain.AccessBindingID(id),
		[]domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(matrixUserID)}}); err != nil {
		return out, 0, 0, err
	}
	return out, 0, 0, w.Commit(ctx)
}

func repoRevoke(t *testing.T, ctx context.Context, repo *kachopg.Repository,
	id string) (domain.AccessBinding, int64, time.Duration, error) {
	t.Helper()
	w, err := repo.Writer(ctx)
	if err != nil {
		return domain.AccessBinding{}, 0, 0, err
	}
	defer func() { _ = w.Rollback(ctx) }()
	out, err := w.AccessBindingsW().RevokeGuarded(ctx, domain.AccessBindingID(id), matrixGrantedBy)
	if err != nil {
		return out, 0, 0, err
	}
	return out, 0, 0, w.Commit(ctx)
}

// ── ПРОГОН ───────────────────────────────────────────────────────────────────

// runMatrix — прогнать перечень точек на ОДНОЙ базе, растущей приращением.
//
// Общая для полного прогона и для малой сетки: две реализации одного прохода
// разошлись бы молча, и малая сетка перестала бы охранять то, что мерит полная.
func runMatrix(t *testing.T, ctx context.Context, points []matrixPoint) []matrixResult {
	t.Helper()
	pool, capture := openMatrixPool(t, ctx)
	repo := kachopg.New(pool, nil)

	results := make([]matrixResult, 0, len(points))
	var f *gridFixture
	seq := 0

	for i, p := range points {
		// Посев КОММИТИТСЯ: продуктовый писатель открывает свою транзакцию и
		// незакоммиченного не увидит. Точки растут ПРИРАЩЕНИЕМ — иначе четыре
		// точки посадили бы 1.11·10⁶ объектов вместо миллиона.
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("транзакция посева: %v", err)
		}
		if i == 0 {
			f = newGridFixture(t, ctx, tx)
			seedMatrixSubject(t, ctx, tx)
		} else {
			f.tx = tx
		}
		t0 := time.Now()
		f.seedPoint(t, ctx, p.grid())
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("фиксация посева точки %s: %v", p, err)
		}
		seedIn := time.Since(t0)

		// Перепись — ДО операций: она описывает объём, ПРОТИВ которого они
		// исполнялись. Снятая после, она включала бы строки самого замера.
		ctx1, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("транзакция переписи: %v", err)
		}
		census, err := scalegrid.TakeCensus(ctx, ctx1, probeSpeakers)
		if err != nil {
			_ = ctx1.Rollback(ctx)
			t.Fatalf("перепись в точке %s: %v", p, err)
		}
		census.VerdictsAsked = int64(matrixRepeats * 2)
		if err := census.Verify(p.grid()); err != nil {
			_ = ctx1.Rollback(ctx)
			t.Fatalf("%v", err)
		}
		tables, dbRows, dbBytes := takeMatrixTables(t, ctx, ctx1)
		_ = ctx1.Rollback(ctx)

		res := measureMatrixPoint(t, ctx, pool, repo, capture, p, &seq)
		res.census, res.tables = census, tables
		res.dbRows, res.dbBytes, res.seedIn = dbRows, dbBytes, seedIn
		results = append(results, res)

		t.Logf("точка %s: посев %s · строк в базе %d · места %s\n%s",
			p, seedIn.Round(time.Millisecond), dbRows, humanBytes(dbBytes), opsLog(res))
	}
	return results
}

// TestMatrixVolume_Report — полный замер и отчёт артефактом дерева.
func TestMatrixVolume_Report(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	if os.Getenv(matrixEnv) == "" {
		t.Skipf("замер матрицы идёт РУЧНЫМ прогоном: %s", matrixRunCommand)
	}
	ctx := context.Background()
	started := time.Now()

	results := runMatrix(t, ctx, matrixPoints)

	body := renderMatrixReport(results, time.Since(started), postgresVersion(t, ctx))
	path, err := matrixReportAbsPath()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("запись отчёта: %v", err)
	}
	t.Logf("отчёт записан: %s\n\n%s", path, body)
}

// matrixSmallPoints — малая сетка: та же машинерия, объём на три порядка меньше.
//
// Её предмет — НЕ форма кривой (для этого мало точек), а два свойства, каждое
// из которых ломается молча: прибор что-то мерит, и стоимость операции не
// растёт вместе с базой.
var matrixSmallPoints = []matrixPoint{
	{Name: "малая", N: 100, B: 100, R: 9, F: 1},
	{Name: "средняя", N: 1000, B: 1000, R: 9, F: 1},
}

// TestMatrixVolume_SmallGridMeasuresSomethingAndStaysFlat — утверждение
// ДВУХОСЕВОЕ, и это обязательно.
//
// Односторонняя проба «ничего не растёт» зеленеет на СЛОМАННОМ приборе,
// докладывающем ноль: ноль не растёт лучше всего. Поэтому рядом с плоскостью
// стоит положительный контроль — база обязана ВЫРАСТИ, а прибор обязан
// ОТЧИТАТЬСЯ ненулевой работой по каждой из четырёх операций.
//
// Четыре утверждения о вердиктах (allow после записи, deny после отзыва на
// каждой точке) проверяются внутри `measureMatrixPoint` и роняют прогон там же:
// они не наблюдение, а условие осмысленности замера.
func TestMatrixVolume_SmallGridMeasuresSomethingAndStaysFlat(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()
	results := runMatrix(t, ctx, matrixSmallPoints)
	if len(results) != len(matrixSmallPoints) {
		t.Fatalf("исполнено точек %d из %d", len(results), len(matrixSmallPoints))
	}
	lo, hi := results[0], results[len(results)-1]

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: база выросла.
	if hi.dbRows <= lo.dbRows {
		t.Fatalf("объём базы не вырос: %d → %d строк. Плоская стоимость на неросшей "+
			"базе не свойство запроса, а отсутствие замера", lo.dbRows, hi.dbRows)
	}

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: прибор отчитался работой по каждой операции.
	for _, r := range results {
		for _, k := range matrixOps() {
			o := r.ops[k]
			if !o.planTaken {
				t.Errorf("точка %s, %s: план не снят", r.point.Name, k)
			}
			if o.touched <= 0 {
				t.Errorf("точка %s, %s: тронуто %d — прибор не увидел работы там, где "+
					"операция исполнилась; ноль здесь неотличим от сломанного прибора",
					r.point.Name, k, o.touched)
			}
			if o.calls <= 0 {
				t.Errorf("точка %s, %s: обращений %d — операция не сходила в БД ни разу",
					r.point.Name, k, o.calls)
			}
		}
	}

	// ── ПРЕДМЕТ: стоимость одной операции не растёт вместе с базой.
	for _, k := range matrixOps() {
		got := ratioOf(hi.ops[k].touched, lo.ops[k].touched)
		if got > matrixFlatCeiling {
			t.Errorf("%s: тронуто выросло в %.2f раза (%d → %d) при потолке %.1f — "+
				"стоимость одной операции следует за объёмом базы",
				k, got, lo.ops[k].touched, hi.ops[k].touched, matrixFlatCeiling)
		}
	}

	t.Logf("объём базы %d → %d строк (%s → %s); отношения по операциям:",
		lo.dbRows, hi.dbRows, humanBytes(lo.dbBytes), humanBytes(hi.dbBytes))
	for _, k := range matrixOps() {
		t.Logf("  %-34s тронуто %d → %d (×%.2f), p50 %s → %s", k,
			lo.ops[k].touched, hi.ops[k].touched,
			ratioOf(hi.ops[k].touched, lo.ops[k].touched),
			lo.ops[k].p50.Round(time.Microsecond), hi.ops[k].p50.Round(time.Microsecond))
	}
}

func opsLog(res matrixResult) string {
	var b strings.Builder
	for _, k := range matrixOps() {
		r := res.ops[k]
		fmt.Fprintf(&b, "    %-34s строк %6d · тронуто %6d · обращений %d · p50 %s\n",
			k, r.rows, r.touched, r.calls, r.p50.Round(time.Microsecond))
	}
	return b.String()
}
