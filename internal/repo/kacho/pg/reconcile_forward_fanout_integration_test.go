// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// reconcile_forward_fanout_integration_test.go — стоимость ОДНОГО прохода материализации
// как функция ЧИСЛА ВЫДАЧ, попавших в веер.
//
// ПРЕДМЕТ. Форвард получает список выдач, чей селектор совпал с одним объектом, и дальше
// читает КАЖДУЮ по отдельности: строка выдачи и строка роли — два обращения к базе на
// выдачу. Значит стоимость прохода растёт с числом выдач области, а не с числом объектов,
// хотя меняется ровно один объект. Замер по дереву выдач боевого стенда (8267 объектов
// зеркала): p50 = 9 кандидатов, p95 = 19, p99 = 226, максимум 227 — то есть хвост в
// двадцать пять раз тяжелее середины, и на нём один пост-коммитный проход выливается в
// 454 последовательных обращения.
//
// ЧТО УТВЕРЖДАЕТ ПРОБА — ИСХОД, А НЕ ВЫЗОВ. Она не проверяет, «позвали ли пакетную
// загрузку»: такое утверждение зеленеет на реализации, которая внутри всё равно ходит по
// одной. Она считает РЕАЛЬНЫЕ обращения к базе за проход (через pgx-трассировщик) и
// требует, чтобы их число НЕ зависело от размера веера: сколько поштучных чтений выдачи и
// роли ушло на веер из 4 — столько же и на веер из 64.
//
// ПАРНЫЙ ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ обязателен: «мало обращений» — свойство, которым обладает
// и проход, не сделавший ничего. Поэтому оба прохода дополнительно обязаны материализовать
// ВСЕ свои выдачи (по строке члена на каждую) — иначе отрицание зеленело бы на сломанном.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// perIDReadTracer считает обращения к базе за проход, разделяя их на два вида:
//   - поштучное чтение ОДНОЙ выдачи / ОДНОЙ роли по первичному ключу (`WHERE id = $1`) —
//     именно то, что растёт с размером веера;
//   - всё остальное.
//
// Трассировщик pgx вызывается на КАЖДОМ round-trip, поэтому счётчик отражает реальный
// разговор с сервером, а не намерение кода.
type perIDReadTracer struct {
	mu      sync.Mutex
	perID   int
	total   int
	samples []string
}

func (t *perIDReadTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	sql := strings.Join(strings.Fields(data.SQL), " ")
	t.mu.Lock()
	defer t.mu.Unlock()
	t.total++
	// Поштучное чтение по первичному ключу — «FROM <t> WHERE id = $1». Пакетное чтение
	// того же предмета пишется через `= ANY($1)` и под предикат не попадает, поэтому
	// счётчик различает две формы, а не два имени функции.
	if (strings.Contains(sql, "FROM access_bindings WHERE id = $1") ||
		strings.Contains(sql, "FROM roles WHERE id = $1")) &&
		!strings.Contains(sql, "ANY(") {
		t.perID++
		if len(t.samples) < 3 {
			t.samples = append(t.samples, sql)
		}
	}
	return ctx
}

func (t *perIDReadTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (t *perIDReadTracer) snapshot() (perID, total int, samples []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.perID, t.total, append([]string(nil), t.samples...)
}

// newTracedPool строит пул по тому же DSN, что и остальные интеграционные пробы, но с
// подключённым трассировщиком — чтобы считать round-trip'ы прохода.
func newTracedPool(t *testing.T, ctx context.Context, dsn string) (*pgxpool.Pool, *perIDReadTracer) {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	tr := &perIDReadTracer{}
	cfg.ConnConfig.Tracer = tr
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	require.NoError(t, pool.Ping(ctx))
	return pool, tr
}

// seedFanOut заводит n выдач, чей ARM_ANCHOR-селектор совпадает с любым compute.instance
// проекта: n разных субъектов, роли поделены на roleShare штук (в дереве роли у выдач
// одной области повторяются — на стенде при 227 кандидатах различных ролей 194, при
// медианных 9 — четыре). Возвращает идентификаторы выдач и отпечаток правила.
func seedFanOut(t *testing.T, ctx context.Context, pool *pgxpool.Pool, fx gammaFixture, prefix string, n, roleShare int) ([]domain.AccessBindingID, string) {
	t.Helper()
	rule := forwardAnchorRule()
	roles := make([]domain.RoleID, roleShare)
	for i := range roles {
		roles[i] = seedRulesRole(t, ctx, pool, fx.repo, fx.prj, fmt.Sprintf("%s_role_%02d", prefix, i), domain.Rules{rule})
	}
	out := make([]domain.AccessBindingID, 0, n)
	for i := 0; i < n; i++ {
		subj := mustSeedUser(t, ctx, pool, fmt.Sprintf("%ss%03d", prefix, i))
		out = append(out, insertThinBinding(t, ctx, fx.repo, subj, roles[i%roleShare], fx.prj))
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out, rule.Fingerprint()
}

// forwardOnFreshObject прогоняет ОДИН пост-коммитный форвард по свежему объекту (путь
// создания: у объекта ещё нет ни одного члена, поэтому проход остаётся аддитивным) и
// возвращает его длительность.
func forwardOnFreshObject(t *testing.T, ctx context.Context, pool *pgxpool.Pool, rec forwardRunner, fx gammaFixture, objID string) time.Duration {
	t.Helper()
	seedMirrorRow(t, ctx, pool, "compute.instance", objID, string(fx.prj), string(fx.accID), nil, time.Now())
	start := time.Now()
	require.NoError(t, rec.ReconcileObjectForward(ctx, "compute.instance", objID))
	return time.Since(start)
}

// forwardRunner — ровно та часть реконсайлера, которую эта проба трогает.
type forwardRunner interface {
	ReconcileObjectForward(ctx context.Context, objectType, objectID string) error
}

// countMembersOnObject — сколько выдач материализовали свою строку члена на этом объекте.
// Это и есть положительный контроль: проход, не сделавший ничего, даст ноль.
func countMembersOnObject(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(DISTINCT binding_id) FROM kacho_iam.access_binding_target_members
		  WHERE object_type='compute.instance' AND object_id=$1`, objID).Scan(&n))
	return n
}

// Проба 08 — стоимость прохода НЕ зависит от размера веера.
//
// Веер из 4 и веер из 64 обязаны стоить одинаковое число ПОШТУЧНЫХ чтений выдачи/роли.
// До правки: 8 против 128 (по два на выдачу) — проба краснеет и называет форму запроса.
// После правки: 0 против 0 (обе стороны читаются пакетом) — при том, что обе стороны
// по-прежнему материализуют ВСЕ свои выдачи (парный положительный контроль).
func TestReconcileForward_08_FanOutCostIndependentOfBindingCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)

	small, medium := 4, 64

	pool, tracer := newTracedPool(t, ctx, dsn)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "fwdfan")
	rec, _ := newReconciler(pool)

	// Веер A (малый) — свой проект, чтобы веера не смешивались.
	bindsSmall, _ := seedFanOut(t, ctx, pool, fx, "fana", small, 2)
	require.Len(t, bindsSmall, small)

	beforeSmall, beforeTotalSmall, _ := tracer.snapshot()
	durSmall := forwardOnFreshObject(t, ctx, pool, rec, fx, "iFanSmall")
	afterSmall, afterTotalSmall, _ := tracer.snapshot()
	perIDSmall, totalSmall := afterSmall-beforeSmall, afterTotalSmall-beforeTotalSmall

	assert.Equal(t, small, countMembersOnObject(t, ctx, pool, "iFanSmall"),
		"положительный контроль: малый веер материализовал ВСЕ свои выдачи")

	// Веер B — те же выдачи плюс ещё, до medium штук в том же проекте.
	bindsRest, _ := seedFanOut(t, ctx, pool, fx, "fanb", medium-small, 4)
	require.Len(t, bindsRest, medium-small)

	beforeBig, beforeTotalBig, _ := tracer.snapshot()
	durBig := forwardOnFreshObject(t, ctx, pool, rec, fx, "iFanBig")
	afterBig, afterTotalBig, samples := tracer.snapshot()
	perIDBig, totalBig := afterBig-beforeBig, afterTotalBig-beforeTotalBig

	assert.Equal(t, medium, countMembersOnObject(t, ctx, pool, "iFanBig"),
		"положительный контроль: большой веер материализовал ВСЕ свои выдачи")

	t.Logf("веер %d: поштучных чтений %d, всего обращений %d, %s", small, perIDSmall, totalSmall, durSmall)
	t.Logf("веер %d: поштучных чтений %d, всего обращений %d, %s", medium, perIDBig, totalBig, durBig)
	if len(samples) > 0 {
		t.Logf("форма поштучного чтения: %v", samples)
	}

	assert.LessOrEqual(t, perIDBig, perIDSmall,
		"поштучные чтения выдачи/роли обязаны НЕ расти с размером веера: %d при %d выдачах против %d при %d",
		perIDBig, medium, perIDSmall, small)
	// Общее число обращений за проход тоже не вправе расти с размером веера: запись
	// (строка члена, очередь, реестр) уходит набором, а не по обращению на выдачу.
	// Строк при этом пишется больше — растёт объём набора, а не число разговоров с
	// сервером, и именно последнее делало стоимость линейной.
	assert.LessOrEqual(t, totalBig, totalSmall,
		"обращений за проход обязано НЕ расти с размером веера: %d при %d выдачах против %d при %d",
		totalBig, medium, totalSmall, small)
}

// Проба 10 — профиль на РЕАЛЬНЫХ размерах веера из дерева выдач и его цена во времени.
//
// Размеры взяты не с потолка: перепись веера по стенду (8267 объектов зеркала, предикат —
// та же SQL-форма, что и у SelectorBindingsMatchingObject) дала p50 = 9 кандидатов и
// хвост 226/227. Проба гоняет K свежих объектов на каждом размере, печатает p50/p95
// длительности прохода (замер ДО и ПОСЛЕ правки делается ОДНИМ И ТЕМ ЖЕ способом) и
// утверждает то же свойство, что и проба 08, но на этих двух размерах: поштучные чтения
// выдачи/роли не растут. Положительный контроль — каждый проход материализовал ВСЕ выдачи
// своего веера.
func TestReconcileForward_10_FanOutLatencyProfileAtTreeSizes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, tracer := newTracedPool(t, ctx, setupTestDB(t))
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "fwdprof")
	rec, _ := newReconciler(pool)

	const passes = 15
	// p50 дерева = 9, хвост = 227. Второй размер набирается ДОБАВЛЕНИЕМ к первому, поэтому
	// оба веера живут в одном проекте и второй строго включает первый.
	stages := []struct {
		name string
		add  int
	}{{"p50=9", 9}, {"tail=227", 227 - 9}}

	seeded := 0
	for si, st := range stages {
		binds, _ := seedFanOut(t, ctx, pool, fx, fmt.Sprintf("prof%d", si), st.add, 4)
		require.Len(t, binds, st.add)
		seeded += st.add

		durs := make([]time.Duration, 0, passes)
		before, _, _ := tracer.snapshot()
		for k := 0; k < passes; k++ {
			objID := fmt.Sprintf("iProf%d_%02d", si, k)
			durs = append(durs, forwardOnFreshObject(t, ctx, pool, rec, fx, objID))
			require.Equal(t, seeded, countMembersOnObject(t, ctx, pool, objID),
				"положительный контроль: проход материализовал ВСЕ %d выдач веера", seeded)
		}
		after, _, _ := tracer.snapshot()
		perID := after - before

		sort.Slice(durs, func(a, b int) bool { return durs[a] < durs[b] })
		p50 := durs[len(durs)*50/100]
		p95 := durs[min(len(durs)*95/100, len(durs)-1)]
		t.Logf("веер %s (%d выдач, %d проходов): p50 %s, p95 %s; поштучных чтений выдачи/роли за все проходы %d (%.1f на проход)",
			st.name, seeded, passes, p50, p95, perID, float64(perID)/float64(passes))

		assert.LessOrEqual(t, perID, 2*passes,
			"на %d выдачах проход обязан читать выдачи и роли ПАКЕТОМ: поштучных чтений %d за %d проходов",
			seeded, perID, passes)
	}
}

// Проба 09 — законный близнец той же формы: ОДИНОЧНАЯ выдача по-прежнему читается.
//
// Без этого утверждение «поштучных чтений не растёт» зеленело бы и на проходе, который
// вообще перестал читать выдачи, — то есть на сломанном. Здесь проход по одиночному
// биндингу (create-путь самой выдачи) обязан прочитать её и материализовать свою область.
func TestReconcileForward_09_SingleBindingStillLoadsItsFacts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, tracer := newTracedPool(t, ctx, setupTestDB(t))
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "fwdone")
	rec, _ := newReconciler(pool)

	rule := forwardAnchorRule()
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "fwdonerole", domain.Rules{rule})
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	seedMirrorRow(t, ctx, pool, "compute.instance", "iOne", string(fx.prj), string(fx.accID), nil, time.Now())

	before, _, _ := tracer.snapshot()
	require.NoError(t, rec.ReconcileObjectForward(ctx, "compute.instance", "iOne"))
	after, _, _ := tracer.snapshot()

	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "iOne")
	require.True(t, ok, "одиночная выдача материализована")
	assert.Equal(t, domain.VerificationActive, st)
	assert.True(t, ledgerHasTuple(t, ctx, pool, bid, "user:"+string(fx.member), "v_update", "compute_instance:iOne"),
		"реестр несёт выданный кортеж")
	t.Logf("одиночная выдача: поштучных чтений %d", after-before)
}
