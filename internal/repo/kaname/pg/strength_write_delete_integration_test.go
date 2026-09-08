// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// strength_write_delete_integration_test.go — ПРЕДЕЛ ПРОЧНОСТИ: ЗАПИСЬ и УДАЛЕНИЕ.
//
// # Что здесь меряется, и почему это НЕ вся стоимость выдачи
//
// Замер заводился при двух действующих рамках: рамка A (pg/relverdict +
// pg/scalegrid) мерила ЧТЕНИЕ реляционной формы, рамка B — материализатор прав
// плюс ВНЕШНИЙ движок отношений. Со снятием движка (S6) рамка B перестала
// существовать как отдельный путь: решение принимает та самая реляционная форма,
// а материализатор остался её наполнителем. Файл переживает эту перемену без
// правки предмета — он с самого начала мерил ПРОДУКТОВЫЙ МАТЕРИАЛИЗАТОР и
// никогда не мерил движок.
//
// Что участвует — материализатор целиком и своим кодом: `reconcile.Reconciler`
// поверх настоящего `pg.ReconcileAdapter` и настоящего Postgres (testcontainers).
// Соседний прибор `services/iam/tools/authzformbench` — ДРУГОЙ прибор с другими единицами: он
// сравнивает формы одной выдачи между собой, а не меряет продуктовый материализатор.
// Складывать его числа с этими нельзя. Что именно он берёт за образец сравнения,
// здесь не воспроизводится намеренно: это его предмет, он меняется вместе с ним, и
// пересказ разошёлся бы молча.
//
// Что здесь НЕ измеряется и потому НЕ утверждается:
//
//	· кэши вердиктов края и сервиса-владельца (слагаемые 1–2);
//	· «время до первого ОТКАЗА» — несущая величина удаления. Её предмет —
//	  наблюдаемый отказ на публичном RPC, а публичного RPC здесь нет.
//
// Двух прежних слагаемых окна небезопасности — времени применения кортежа к
// движку и ожидания в очереди до дренажа — БОЛЬШЕ НЕТ у самого предмета, а не
// только у этого замера: строка журнала порождает прямой факт триггером в момент
// коммита, поэтому ждать между «выдал» и «видно» нечего.
//
// Измеряется СХОДИМОСТЬ ПРОХОДА и его стоимость в стейтментах — то есть ровно
// то, что ломается первым по §1.2 спецификации, и слагаемое 4 окна по §1.3.
//
// # Первой строкой — бинарная величина, а не миллисекунды
//
// Проход имеет ТРИ исхода: сошёлся · оборван по сроку отсоединённого прохода
// (2 минуты) · откатился по сроку одного стейтмента (30 секунд). «Ноль
// записанных строк за быстро» — запрещённое прочтение, и различает эти исходы
// только флаг, печатаемый раньше всякого времени.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/scalegrid"
)

// strengthWDEnv — ручка «запускать замер записи и удаления», и только это.
const strengthWDEnv = "KACHO_STRENGTH_WRITE"

// wdReportPath — отчёт рамки B, файлом дерева.
//
// Путь берётся ИЗ КОНСТАНТЫ прибора, а не выписывается вторым литералом: гейт
// свежести читает отчёт по ней, и второе написание позволило бы положить отчёт
// мимо гейта — то есть иметь замер, о котором гейт ничего не знает и потому
// молчит.
const wdReportPath = scalegrid.WriteDeleteReportPath

// ── ТОЧКИ ────────────────────────────────────────────────────────────────────

// wdPoint — точка замера записи/удаления.
//
// Членов на выдачу = K правил × N объектов: ключ члена включает отпечаток
// правила (`PRIMARY KEY (binding_id, role_id, rule_fp, object_type, object_id)`),
// значит один объект, накрытый K правилами, даёт K членов.
type wdPoint struct {
	// Objects — объектов зеркала в области выдачи.
	Objects int
	// Rules — правил роли (K); каждое накрывает все объекты.
	Rules int
	// Fanout — выдач на роль (веер полной полосы). Ноль — точка не про веер.
	Fanout int
	// Seeded — состояние сверх объявленного продуктом.
	Seeded bool
}

// Members — членов НА ОДНУ ВЫДАЧУ, которых точка обязана материализовать.
func (p wdPoint) Members() int { return p.Objects * p.Rules }

// TotalMembers — членов, которых точка обязана материализовать ВСЕГО.
//
// Отличается от Members ровно на веер, и различать их обязательно: делить
// стейтменты веера на членов ОДНОЙ выдачи значит печатать число, верное для
// другого предиката, — «1571 стейтмент на члена» там, где их три. Первая
// редакция отчёта так и делала.
func (p wdPoint) TotalMembers() int {
	if p.Fanout > 0 {
		return p.Fanout * p.Members()
	}
	return p.Members()
}

func (p wdPoint) String() string {
	s := fmt.Sprintf("объектов %d × правил %d = членов %d", p.Objects, p.Rules, p.Members())
	if p.Fanout > 0 {
		s += fmt.Sprintf(", веер выдач %d", p.Fanout)
	}
	if p.Seeded {
		s += ", ПОСЕВНОЕ"
	}
	return s
}

// wdBandPoints — точки обеих полос по числу членов на выдачу.
//
// Верхняя точка — 6.55·10⁵ (64 правила × 10240 объектов), объявленная
// спецификацией. Веер 10 000 выдач НЕИСПОЛНИМ по времени посева и здесь не
// стоит: 10 000 действующих выдач одной роли требуют 10 000 РАЗЛИЧНЫХ субъектов
// (частичная уникальность), а при 10 140 членах это 1.014·10⁸ членов —
// то есть посев, а не замер.
var wdBandPoints = []wdPoint{
	{Objects: 100, Rules: 1},
	{Objects: 1000, Rules: 1},
	{Objects: 10000, Rules: 1},
	{Objects: 1024, Rules: 64},
	{Objects: 10240, Rules: 64, Seeded: true},
}

// wdFanoutPoints — веер выдач полной полосы (правка правил роли).
//
// Верхняя точка — 512, объявленное умолчание `iam.accessBinding`. Умолчание НЕ
// ЭНФОРСИТСЯ (таблицы учёта для видов iam в дереве нет), поэтому 512 достижимо
// и помечено как то, что продукт объявил потолком, но не проверяет.
var wdFanoutPoints = []wdPoint{
	{Objects: 100, Rules: 1, Fanout: 1},
	{Objects: 100, Rules: 1, Fanout: 9},
	{Objects: 100, Rules: 1, Fanout: 227},
	{Objects: 100, Rules: 1, Fanout: 512, Seeded: true},
}

// ── ИСХОД ПРОХОДА ────────────────────────────────────────────────────────────

// passOutcome — ТРИ исхода прохода, и четвёртого нет.
type passOutcome string

const (
	// passConverged — проход сошёлся.
	passConverged passOutcome = "СОШЁЛСЯ"
	// passDeadline — оборван по сроку отсоединённого прохода (2 минуты).
	passDeadline passOutcome = "ОБОРВАН ПО СРОКУ ПРОХОДА (2 мин)"
	// passStatement — откатился по сроку одного стейтмента (30 секунд, 57014).
	passStatement passOutcome = "ОТКАТИЛСЯ ПО СРОКУ СТЕЙТМЕНТА (57014)"
	// passOther — иной отказ; называется дословно, а не сводится к предыдущим.
	passOther passOutcome = "ОТКАЗ"
)

// classifyPass — исход прохода по ОШИБКЕ, а не по времени.
//
// По времени классифицировать нельзя: проход, уложившийся в срок и упавший по
// иной причине, выглядел бы сошедшимся. Срок стейтмента опознаётся по коду
// SQLSTATE 57014 — «query canceled»; срок прохода — по исчерпанию контекста.
func classifyPass(err error, ctxErr error) (passOutcome, string) {
	if err == nil {
		return passConverged, ""
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "57014" {
		return passStatement, err.Error()
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctxErr, context.DeadlineExceeded) {
		return passDeadline, err.Error()
	}
	return passOther, err.Error()
}

// ── СЧЁТЧИК СТЕЙТМЕНТОВ ──────────────────────────────────────────────────────

// stmtCounter — трассировщик pgx: стейтментов СОБСТВЕННОГО Postgres iam.
//
// Обязателен, и вот почему: только он отличает «много строк» от «много
// обращений», то есть ПАКЕТНУЮ полосу от ПОШТУЧНОЙ. Быстрый путь пишет тремя
// пакетными стейтментами на весь веер; полный — по стейтменту на члена. По
// времени эти две формы на малой точке неотличимы, а ломаются они по-разному:
// пакетная — вся разом, поштучная — постепенно.
type stmtCounter struct {
	mu    sync.Mutex
	n     int64
	byTag map[string]int64
}

func newStmtCounter() *stmtCounter { return &stmtCounter{byTag: map[string]int64{}} }

func (c *stmtCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn,
	d pgx.TraceQueryStartData) context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	c.byTag[firstWords(d.SQL)]++
	return ctx
}

func (c *stmtCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (c *stmtCounter) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n = 0
	c.byTag = map[string]int64{}
}

func (c *stmtCounter) count() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// top — три самых частых стейтмента. Печатаются затем, чтобы «стейтментов
// много» было отличимо от «стейтментов много ОДНОГО ВИДА»: первое означает
// разнообразную работу, второе — поштучную полосу.
func (c *stmtCounter) top(n int) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	type kv struct {
		k string
		v int64
	}
	var all []kv
	for k, v := range c.byTag {
		all = append(all, kv{k, v})
	}
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			if all[j].v > all[i].v {
				all[i], all[j] = all[j], all[i]
			}
		}
	}
	var b strings.Builder
	for i := 0; i < n && i < len(all); i++ {
		if i > 0 {
			b.WriteString(" · ")
		}
		fmt.Fprintf(&b, "%s×%d", all[i].k, all[i].v)
	}
	return b.String()
}

func firstWords(sql string) string {
	f := strings.Fields(strings.TrimSpace(sql))
	if len(f) == 0 {
		return "(пусто)"
	}
	if len(f) > 3 {
		f = f[:3]
	}
	return strings.Join(f, " ")
}

// ── ПЕРЕПИСЬ ─────────────────────────────────────────────────────────────────

// wdCensus — что осталось в таблицах после прохода.
type wdCensus struct {
	MembersActive   int64
	MembersRejected int64
	MembersOther    int64
	LedgerRows      int64
	FGAOutbox       int64
	ReconcileOutbox int64
	MirrorObjects   int64
	// LockFPCollisions — сколько выдач делят отпечаток замка с другой.
	LockFPCollisions int64
}

func takeWDCensus(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	bid domain.AccessBindingID) wdCensus {
	t.Helper()
	var c wdCensus
	rows, err := pool.Query(ctx,
		`SELECT verification_status, count(*)::bigint
		   FROM kaname.access_binding_target_members WHERE binding_id = $1
		  GROUP BY verification_status`, string(bid))
	require.NoError(t, err)
	for rows.Next() {
		var st string
		var n int64
		require.NoError(t, rows.Scan(&st, &n))
		switch st {
		case string(domain.VerificationActive):
			c.MembersActive = n
		case "REJECTED":
			c.MembersRejected = n
		default:
			c.MembersOther += n
		}
	}
	rows.Close()
	require.NoError(t, rows.Err())

	one := func(dst *int64, sql string, args ...any) {
		require.NoError(t, pool.QueryRow(ctx, sql, args...).Scan(dst))
	}
	one(&c.LedgerRows,
		`SELECT count(*)::bigint FROM kaname.access_binding_emitted_tuples WHERE binding_id = $1`,
		string(bid))
	one(&c.FGAOutbox, `SELECT count(*)::bigint FROM kaname.fga_outbox`)
	one(&c.ReconcileOutbox, `SELECT count(*)::bigint FROM kaname.resource_reconcile_outbox`)
	one(&c.MirrorObjects, `SELECT count(*)::bigint FROM kaname.resource_mirror`)
	// Столкновение отпечатков замка: полный проход берёт исключительную
	// консультативную блокировку по `hashtext(id)`, а он 32-битный. Две РАЗНЫЕ
	// выдачи вправе сесть на один замок и получить ЛОЖНУЮ сериализацию — то
	// есть ждать друг друга без всякой причины. Величина снимается всегда:
	// ноль здесь — свидетельство, а не молчание.
	one(&c.LockFPCollisions,
		`SELECT coalesce(sum(n - 1), 0)::bigint FROM (
		   SELECT count(*) AS n FROM kaname.access_bindings
		    GROUP BY hashtext(id) HAVING count(*) > 1) t`)
	return c
}

// ── ЗАМЕР ────────────────────────────────────────────────────────────────────

// wdResult — строка отчёта.
type wdResult struct {
	band    string
	point   wdPoint
	outcome passOutcome
	detail  string
	elapsed time.Duration
	stmts   int64
	topStmt string
	census  wdCensus
	// seedIn — время посева; печатается отдельно и НИКОГДА не складывается со
	// временем прохода: посев — не предмет замера.
	seedIn time.Duration
	// saturated — доля наблюдений штатного прибора, ушедших в верхнюю корзину.
	// Корзины кончаются на 5000, поэтому на худшем входе доля равна единице, и
	// это предъявляется как РЕЗУЛЬТАТ: штатной наблюдаемости на этом режиме нет.
	saturated bool
}

// wdLabels — метки, которыми объект накрывается меточным правилом.
func wdLabels(k int) map[string]string {
	m := make(map[string]string, 16)
	for j := 0; j < 16; j++ {
		m[fmt.Sprintf("w%02d", (k*7+j*3)%64)] = "v"
	}
	return m
}

// wdAllLabels — 64 метки: предел, объявленный продуктом. Объект несёт их все,
// поэтому его накрывают ВСЕ 64 правила.
func wdAllLabels() map[string]string {
	m := make(map[string]string, 64)
	for i := 0; i < 64; i++ {
		m[fmt.Sprintf("w%02d", i)] = "v"
	}
	return m
}

// wdRules — K правил, накрывающих один и тот же объект.
//
// K = 1 даёт ЯКОРНОЕ правило (форма, которой пользуется продукт по умолчанию);
// K > 1 — меточные, каждое со своими 16 ключами из 64, которые несёт объект.
// Смешивать нельзя: якорное правило накрывает объект независимо от меток, и
// набор «якорное + меточные» мерил бы K+1 правил, называя это K.
func wdRules(k int) domain.Rules {
	if k <= 1 {
		return domain.Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "update"}}}
	}
	out := make(domain.Rules, 0, k)
	for i := 0; i < k; i++ {
		out = append(out, domain.Rule{
			Module: "compute", Resources: []string{"instance"},
			Verbs: []string{"get", "update"}, MatchLabels: wdLabels(i),
		})
	}
	return out
}

// seedWDObjects — объекты зеркала в области выдачи.
func seedWDObjects(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	prj, acc string, n int, labels map[string]string) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	s := scalegrid.NewSeeder(tx)
	for i := 0; i < n; i++ {
		require.NoError(t, s.Queue(ctx, scalegrid.MirrorRow{
			ObjectType: "compute.instance", ObjectID: fmt.Sprintf("wdi-%07d", i),
			ParentProjectID: prj, ParentAccountID: acc,
			Labels:      labels,
			ParentChain: []string{"project:" + prj, "account:" + acc},
		}))
	}
	require.NoError(t, s.Flush(ctx))
	require.NoError(t, tx.Commit(ctx))
	_, err = pool.Exec(ctx, `ANALYZE kaname.resource_mirror, kaname.access_binding_target_members,
		kaname.access_binding_emitted_tuples`)
	require.NoError(t, err)
}

// runWDPass — проход под ТЕМ ЖЕ сроком, что действует у продукта.
//
// Срок берётся из `shared.PostCommitTimeout`, а не выписывается числом: копия
// разошлась бы с оригиналом молча, и замер утверждал бы про потолок, которого
// в дереве нет.
func runWDPass(t *testing.T, counter *stmtCounter, fn func(ctx context.Context) error) wdResult {
	t.Helper()
	var r wdResult
	ctx, cancel := context.WithTimeout(context.Background(), shared.PostCommitTimeout)
	defer cancel()
	counter.reset()
	t0 := time.Now()
	err := fn(ctx)
	r.elapsed = time.Since(t0)
	r.stmts = counter.count()
	r.topStmt = counter.top(3)
	r.outcome, r.detail = classifyPass(err, ctx.Err())
	return r
}

// ── ПРОГОН ───────────────────────────────────────────────────────────────────

// TestStrengthWriteDelete_Report — запись и удаление, РУЧНОЙ прогон.
func TestStrengthWriteDelete_Report(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	if os.Getenv(strengthWDEnv) == "" {
		t.Skipf("замер записи и удаления идёт РУЧНЫМ прогоном: %s=1 go test "+
			"./services/iam/internal/repo/kaname/pg/ -run TestStrengthWriteDelete_Report "+
			"-count=1 -v -timeout 120m", strengthWDEnv)
	}
	ctx := context.Background()

	runCommand := fmt.Sprintf("%s=1 go test -C services/iam ./internal/repo/kaname/pg/ "+
		"-run TestStrengthWriteDelete_Report -count=1 -v -timeout 120m", strengthWDEnv)
	prov := scalegrid.TakeProvenance(runCommand, nil)
	prov.GridText = wdGridText()
	// Отпечаток берётся СВОЙ: предмет этого замера — материализатор, а не запрос
	// вердикта. Отпечаток читающего прибора краснел бы здесь на чужой правке и
	// молчал бы на своей.
	if root, rerr := scalegrid.AbsPathOf(""); rerr == nil {
		if fp, ferr := scalegrid.ComputeWriteDeleteFingerprint(strings.TrimSuffix(root, "/")); ferr == nil {
			prov.Fingerprint = fp
		}
	}

	started := time.Now()
	var results []wdResult

	// ── ПОЛОСА 1: АДДИТИВНАЯ (создание выдачи) ──────────────────────────────
	for _, p := range wdBandPoints {
		results = append(results, runBandPoint(t, ctx, "аддитивная (создание)", p, bandAdditive))
		writeWDReport(t, prov, results, time.Since(started), false)
	}
	// ── ПОЛОСА 2: ПОЛНАЯ (правка правил роли, истечение, обход) ─────────────
	for _, p := range wdBandPoints {
		results = append(results, runBandPoint(t, ctx, "полная (правка роли)", p, bandFull))
		writeWDReport(t, prov, results, time.Since(started), false)
	}
	// ── ПОЛОСА 3: УДАЛЕНИЕ ИСТЕЧЕНИЕМ СРОКА ─────────────────────────────────
	for _, p := range wdBandPoints[:4] {
		results = append(results, runBandPoint(t, ctx, "удаление истечением срока", p, bandExpire))
		writeWDReport(t, prov, results, time.Since(started), false)
	}
	// ── ПОЛОСА 4: ВЕЕР ВЫДАЧ ────────────────────────────────────────────────
	for _, p := range wdFanoutPoints {
		results = append(results, runFanoutPoint(t, ctx, p))
		writeWDReport(t, prov, results, time.Since(started), false)
	}

	prov.Postgres = wdPostgresVersion(t, ctx)
	writeWDReport(t, prov, results, time.Since(started), true)
}

type bandKind int

const (
	bandAdditive bandKind = iota
	bandFull
	bandExpire
)

// runBandPoint — одна точка одной полосы на СВОЕЙ базе.
func runBandPoint(t *testing.T, ctx context.Context, band string, p wdPoint, kind bandKind) wdResult {
	t.Helper()
	counter := newStmtCounter()
	pool := wdPool(t, ctx, counter)
	suffix := fmt.Sprintf("wd%d%d%d", int(kind), p.Objects, p.Rules)
	fx := setupGamma(t, ctx, pool, suffix)
	rec, _ := newReconciler(pool)

	labels := wdAllLabels()
	t0 := time.Now()
	seedWDObjects(t, ctx, pool, string(fx.prj), string(fx.accID), p.Objects, labels)
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "role"+suffix, wdRules(p.Rules))
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	seedFor := time.Since(t0)

	var r wdResult
	switch kind {
	case bandAdditive:
		r = runWDPass(t, counter, func(c context.Context) error {
			return rec.ReconcileBindingForward(c, bid)
		})
	case bandFull:
		r = runWDPass(t, counter, func(c context.Context) error {
			return rec.ReconcileBinding(c, bid)
		})
	case bandExpire:
		// Истечение срока меряется на УЖЕ материализованном состоянии: его
		// предмет — снятие членов, а не их создание. Материализация идёт
		// отдельным проходом и в замер НЕ входит.
		if err := rec.ReconcileBindingForward(ctx, bid); err != nil {
			t.Fatalf("подготовка точки %s: материализация не сошлась: %v", p, err)
		}
		// Срок ставится ОТ `created_at`, а не от `now()`: схема требует
		// `expires_at > created_at` (`access_bindings_expires_future_ck`), и
		// прошедшая метка её нарушает. Значение остаётся в прошлом относительно
		// `now()` — то есть выдача истёкшая, — но ограничение соблюдено. Первая
		// редакция ставила `now() - 1 минута` и была отвергнута схемой: это и
		// есть тот случай, когда фикстура пытается посадить состояние, которого
		// продукт не допускает.
		_, err := pool.Exec(ctx,
			`UPDATE kaname.access_bindings
			    SET expires_at = created_at + interval '1 millisecond'
			  WHERE id = $1`, string(bid))
		require.NoError(t, err)
		r = runWDPass(t, counter, func(c context.Context) error {
			return rec.ExpireBinding(c, bid)
		})
	}
	r.band, r.point, r.seedIn = band, p, seedFor
	r.census = takeWDCensus(t, ctx, pool, bid)
	// Корзины штатного прибора кончаются на 5000: всё, что выше, попадает в
	// верхнюю и там неразличимо.
	r.saturated = int64(p.Members()) > 5000

	t.Logf("[%s] %s\n    ИСХОД %s%s\n    время %s · стейтментов %d (%s)\n"+
		"    членов ACTIVE %d / REJECTED %d / прочих %d · строк реестра %d\n"+
		"    очередь движка %d · очередь пересведения %d · посев %s",
		band, p, r.outcome, wdDetail(r.detail), r.elapsed.Round(time.Millisecond),
		r.stmts, r.topStmt,
		r.census.MembersActive, r.census.MembersRejected, r.census.MembersOther,
		r.census.LedgerRows, r.census.FGAOutbox, r.census.ReconcileOutbox,
		seedFor.Round(time.Millisecond))
	pool.Close()
	return r
}

// runFanoutPoint — веер выдач: правка правил роли задевает ВСЕ её выдачи.
//
// Меряется СУММАРНЫЙ проход по вееру под ОДНИМ сроком отсоединённого прохода:
// именно так его исполняет продукт, и именно поэтому исход «оборван» здесь
// возможен, а на одной выдаче — нет.
func runFanoutPoint(t *testing.T, ctx context.Context, p wdPoint) wdResult {
	t.Helper()
	counter := newStmtCounter()
	pool := wdPool(t, ctx, counter)
	suffix := fmt.Sprintf("wdf%d", p.Fanout)
	fx := setupGamma(t, ctx, pool, suffix)
	rec, _ := newReconciler(pool)

	t0 := time.Now()
	seedWDObjects(t, ctx, pool, string(fx.prj), string(fx.accID), p.Objects, wdAllLabels())
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "rolef"+suffix, wdRules(p.Rules))
	// Веер: N выдач одной роли. Каждая — своему субъекту: частичная уникальность
	// действующей выдачи ключуется субъектом строки, и второй выдачи тому же
	// субъекту на той же области с той же ролью не бывает.
	bids := make([]domain.AccessBindingID, 0, p.Fanout)
	for i := 0; i < p.Fanout; i++ {
		u := mustSeedUser(t, ctx, pool, fmt.Sprintf("%sm%04d", suffix, i))
		bids = append(bids, insertThinBinding(t, ctx, fx.repo, u, roleID, fx.prj))
	}
	seedFor := time.Since(t0)

	r := runWDPass(t, counter, func(c context.Context) error {
		for _, bid := range bids {
			if err := rec.ReconcileBinding(c, bid); err != nil {
				return fmt.Errorf("выдача %s из веера %d: %w", bid, p.Fanout, err)
			}
		}
		return nil
	})
	r.band, r.point, r.seedIn = "полная, ВЕЕР выдач", p, seedFor
	r.census = takeWDCensus(t, ctx, pool, bids[len(bids)-1])
	// Члены считаются по ПОСЛЕДНЕЙ выдаче веера; общее число членов — веер ×
	// членов на выдачу, и оно печатается отдельной колонкой.
	r.saturated = int64(p.TotalMembers()) > 5000

	t.Logf("[веер %d] %s\n    ИСХОД %s%s\n    время %s · стейтментов %d (%s)\n"+
		"    членов у ПОСЛЕДНЕЙ выдачи ACTIVE %d · строк реестра %d · посев %s",
		p.Fanout, p, r.outcome, wdDetail(r.detail), r.elapsed.Round(time.Millisecond),
		r.stmts, r.topStmt, r.census.MembersActive, r.census.LedgerRows,
		seedFor.Round(time.Millisecond))
	pool.Close()
	return r
}

func wdDetail(d string) string {
	if d == "" {
		return ""
	}
	return "\n    причина: " + d
}

// wdPool — пул со счётчиком стейтментов И С ТЕМИ ЖЕ СРОКАМИ, ЧТО У ПРОДУКТА.
//
// Сроки ставятся ЯВНО и теми же значениями, что `pkg/db.NewPool`: без них исход
// «ОТКАТИЛСЯ ПО СРОКУ СТЕЙТМЕНТА» не наступил бы НИКОГДА — прибор объявил бы
// сходимость там, где продукт откатывается, и был бы проверкой, не способной
// упасть. Своим пулом здесь пришлось обойтись потому, что трассировщик
// стейтментов ставится только на конфигурацию, а `NewPool` её не отдаёт; цена
// этого — обязанность повторить сроки, и она названа здесь, а не подразумевается.
//
// Значения ВЫПИСАНЫ, и это признаётся вслух: `pkg/db` их не экспортирует.
// Расхождение с ним сделало бы замер утверждением о посадке, которой нет, —
// поэтому оно сторожится пробой рядом (TestWDPoolCarriesTheProductsTimeouts).
const (
	wdStatementTimeoutMS = "30000"
	wdIdleInTxTimeoutMS  = "60000"
)

func wdPool(t *testing.T, ctx context.Context, counter *stmtCounter) *pgxpool.Pool {
	t.Helper()
	dsn := setupTestDB(t)
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.Tracer = counter
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = wdStatementTimeoutMS
	cfg.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = wdIdleInTxTimeoutMS
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	return pool
}

// TestWDPoolCarriesTheProductsTimeouts — ПРЕДПОСЫЛКА замера, проверяемая отдельно.
//
// Прибор, чей пул не несёт продуктовых сроков, не может наблюдать исход
// «откатился по сроку стейтмента» BY CONSTRUCTION — и объявит сходимость там,
// где продукт откатывается. Проба спрашивает у САМОГО СЕРВЕРА, что он видит на
// соединении прибора, а не сверяет две константы между собой: сверка констант
// зеленела бы и на пуле, который эти параметры не отправил.
func TestWDPoolCarriesTheProductsTimeouts(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()
	pool := wdPool(t, ctx, newStmtCounter())
	// Закрытие С ПРЕДЕЛОМ: отложенное `pool.Close()` ждёт соединение, которого
	// проба, упавшая внутри открытой транзакции, не вернёт никогда, — и уносит
	// с собой вердикт всего пакета. Гейт дерева `TestPoolCloseInTestsIsBounded`
	// это и поймал на первой редакции файла.
	pgtest.ClosePoolAtEnd(t, pool)

	var stmt, idle string
	require.NoError(t, pool.QueryRow(ctx, "SHOW statement_timeout").Scan(&stmt))
	require.NoError(t, pool.QueryRow(ctx, "SHOW idle_in_transaction_session_timeout").Scan(&idle))
	if stmt != "30s" {
		t.Errorf("на соединении прибора statement_timeout = %q, у продукта 30s: исход "+
			"«откатился по сроку стейтмента» этим прибором ненаблюдаем, и его молчание "+
			"означало бы сходимость, которой никто не проверял", stmt)
	}
	if idle != "1min" {
		t.Errorf("на соединении прибора idle_in_transaction_session_timeout = %q, у продукта 60s", idle)
	}
	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: сама проба способна увидеть ДРУГОЕ значение.
	// Без него «совпало» получено бы прибором, который всегда отвечает одно.
	other, err := pgxpool.ParseConfig(setupTestDB(t))
	require.NoError(t, err)
	other.ConnConfig.RuntimeParams = map[string]string{"statement_timeout": "7000"}
	op, err := pgxpool.NewWithConfig(ctx, other)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, op)
	var control string
	require.NoError(t, op.QueryRow(ctx, "SHOW statement_timeout").Scan(&control))
	if control != "7s" {
		t.Errorf("контроль не воспроизвёл ДРУГОЕ значение (получено %q): значит проба выше "+
			"утверждает не о соединении, а о чём-то своём", control)
	}
}

func wdPostgresVersion(t *testing.T, ctx context.Context) string {
	t.Helper()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	if err != nil {
		return "не установлена"
	}
	pgtest.ClosePoolAtEnd(t, pool)
	var v string
	if err := pool.QueryRow(ctx, "SHOW server_version").Scan(&v); err != nil {
		return "не установлена"
	}
	return v
}

// ── ОТЧЁТ ────────────────────────────────────────────────────────────────────

func wdGridText() string {
	var b strings.Builder
	fmt.Fprintf(&b, "  полосы: аддитивная (создание выдачи) · полная (правка роли) · "+
		"удаление истечением срока · веер выдач\n")
	fmt.Fprintf(&b, "  точки по членам на выдачу (объектов × правил):")
	for _, p := range wdBandPoints {
		fmt.Fprintf(&b, " %d", p.Members())
		if p.Seeded {
			b.WriteString("*")
		}
	}
	fmt.Fprintf(&b, "\n  веер выдач:")
	for _, p := range wdFanoutPoints {
		fmt.Fprintf(&b, " %d", p.Fanout)
		if p.Seeded {
			b.WriteString("*")
		}
	}
	fmt.Fprintf(&b, "\n  «*» — состояние, объявленное продуктом невозможным либо им не производимое\n")
	fmt.Fprintf(&b, "  срок отсоединённого прохода: %s (shared.PostCommitTimeout, читается из кода)\n",
		shared.PostCommitTimeout)
	return b.String()
}

func writeWDReport(t *testing.T, prov scalegrid.Provenance, results []wdResult,
	wall time.Duration, final bool) {
	t.Helper()
	title := "R7-2 — ПРЕДЕЛ ПРОЧНОСТИ: ЗАПИСЬ и УДАЛЕНИЕ (продуктовый материализатор)"
	if !final {
		title += " — ПРОМЕЖУТОЧНЫЙ СРЕЗ"
	}
	header, err := prov.Header(title)
	if err != nil {
		t.Fatalf("шапка отчёта: %v", err)
	}
	path, err := scalegrid.AbsPathOf(wdReportPath)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if err := os.WriteFile(path, []byte(header+renderWDReport(results, wall, final)), 0o644); err != nil {
		t.Fatalf("запись отчёта: %v", err)
	}
	if final {
		t.Logf("отчёт записан: %s", path)
	}
}

func renderWDReport(results []wdResult, wall time.Duration, final bool) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }

	w("\nЧТО ЭТОТ ОТЧЁТ ИЗМЕРЯЕТ И ЧЕГО НЕ ИЗМЕРЯЕТ (дословно)\n")
	w("  ИЗМЕРЯЕТ  продуктовый материализатор прав (reconcile.Reconciler поверх\n")
	w("            настоящего pg.ReconcileAdapter и настоящего Postgres): сходимость\n")
	w("            прохода, стейтменты собственной БД, члены по статусам, строки\n")
	w("            реестра, глубину обеих очередей.\n")
	w("  НЕ ИЗМЕРЯЕТ кэши вердиктов края и сервиса-владельца и «время до первого\n")
	w("            ОТКАЗА» — несущую величину удаления, чей предмет есть наблюдаемый\n")
	w("            отказ на публичном RPC. Это ТРЕТИЙ исход по ним, а не «уложились».\n")
	w("            Прежних слагаемых «применение кортежа к движку» и «ожидание в\n")
	w("            очереди до дренажа» нет у самого предмета: прямой факт складывает\n")
	w("            триггер в момент коммита журнала.\n")
	w("  Числа этого отчёта НЕЛЬЗЯ складывать с числами прибора services/iam/tools/authzformbench:\n")
	w("  это другой прибор с другими единицами и другим предметом.\n")

	w("\nИСХОД ПРОХОДА — ПЕРВОЙ КОЛОНКОЙ, ДО ВСЯКИХ МИЛЛИСЕКУНД\n")
	w("  Исходов ТРИ: СОШЁЛСЯ · ОБОРВАН ПО СРОКУ ПРОХОДА · ОТКАТИЛСЯ ПО СРОКУ\n")
	w("  СТЕЙТМЕНТА. «Ноль записанных строк за быстро» — запрещённое прочтение:\n")
	w("  отличить его от сошедшегося прохода можно только этой колонкой.\n")

	w("\n%-26s %-11s %-38s %10s %9s %10s %10s %9s\n",
		"полоса", "членов", "исход", "время", "стейтм.", "ACTIVE", "реестр", "очер.движ.")
	w("%s\n", strings.Repeat("-", 132))
	for _, r := range results {
		members := fmt.Sprintf("%d", r.point.Members())
		if r.point.Fanout > 0 {
			members = fmt.Sprintf("%d×%d", r.point.Fanout, r.point.Members())
		}
		if r.point.Seeded {
			members += "*"
		}
		w("%-26s %-11s %-38s %10s %9d %10d %10d %9d\n",
			r.band, members, r.outcome, r.elapsed.Round(time.Millisecond), r.stmts,
			r.census.MembersActive, r.census.LedgerRows, r.census.FGAOutbox)
	}

	w("\nСТЕЙТМЕНТОВ НА ЧЛЕНА — ЭТО И ЕСТЬ РАЗЛИЧИЕ ПАКЕТНОЙ И ПОШТУЧНОЙ ПОЛОС\n")
	w("  Знаменатель — члены ВСЕГО (веер × членов на выдачу), а не члены одной выдачи:\n")
	w("  делить стейтменты веера на вторую величину значит печатать число, верное для\n")
	w("  другого предиката.\n")
	w("%-26s %-13s %14s %16s %s\n", "полоса", "членов всего", "стейтментов", "на члена", "три самых частых")
	w("%s\n", strings.Repeat("-", 132))
	for _, r := range results {
		per := "—"
		if r.point.TotalMembers() > 0 {
			per = fmt.Sprintf("%.4f", float64(r.stmts)/float64(r.point.TotalMembers()))
		}
		w("%-26s %-13d %14d %16s %s\n", r.band, r.point.TotalMembers(), r.stmts, per, r.topStmt)
	}

	w("\nНАСЫЩЕНИЕ ШТАТНОГО ПРИБОРА\n")
	w("  Корзины `kaname_binding_materialization_tuples` кончаются на 5000. Точка,\n")
	w("  чьё число членов выше, попадает в верхнюю корзину целиком и там неразличима:\n")
	w("  штатной наблюдаемости на этом режиме НЕТ, и это результат, а не оговорка.\n")
	sat := 0
	for _, r := range results {
		if r.saturated {
			sat++
		}
	}
	w("  точек сверх верхней корзины: %d из %d\n", sat, len(results))

	w("\nСТОЛКНОВЕНИЕ ОТПЕЧАТКОВ ЗАМКА (полный проход берёт исключительный по hashtext(id))\n")
	w("  `hashtext` 32-битный: две РАЗНЫЕ выдачи вправе сесть на один замок и дать\n")
	w("  ЛОЖНУЮ сериализацию — ждать друг друга без причины. Ноль здесь — свидетельство.\n")
	for _, r := range results {
		if r.point.Fanout > 0 {
			w("  веер %d выдач: выдач, делящих отпечаток замка с другой — %d\n",
				r.point.Fanout, r.census.LockFPCollisions)
		}
	}

	w("\nОТЛОЖЕННАЯ РАБОТА, ОСТАВШАЯСЯ ПОСЛЕ ПРОХОДА (очереди)\n")
	w("%-26s %-13s %14s %20s\n", "полоса", "членов всего", "очередь движка", "очередь пересведения")
	w("%s\n", strings.Repeat("-", 132))
	for _, r := range results {
		w("%-26s %-13d %14d %20d\n", r.band, r.point.TotalMembers(),
			r.census.FGAOutbox, r.census.ReconcileOutbox)
	}

	w("\n\nОБЪЁМ ОСМОТРЕННОГО\n")
	w("  точек исполнено %d, настенное время %s\n", len(results), wall.Round(time.Second))
	if !final {
		w("  ПРОГОН НЕ ОКОНЧЕН: полосы ниже исполненных не сняты. Это ТРЕТИЙ исход по ним.\n")
	}
	if len(results) == 0 {
		w("  ТОЧЕК ИСПОЛНЕНО НОЛЬ — отчёт беспредметен, и его молчание не является замером.\n")
	}
	return b.String()
}
