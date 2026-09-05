// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// reconcile_forward_burst_cost_integration_test.go — ЗАМЕР всплеска созданий в
// одном аккаунте, где владельческая привязка ОДНА на всех (задача продукта
// #2059).
//
// # Посылка задачи и что с ней стало
//
// Задача утверждала: путь создания открывает вторую пишущую транзакцию и БЕРЁТ в
// ней пообъектную advisory-блокировку, поэтому N созданий в одной области встают
// в очередь на ключе единственной привязки. Первая половина верна и осталась —
// проход идёт своей писательской транзакцией после коммита. Вторая половина
// сегодня НЕ верна: форвард пути создания advisory-блокировки не берёт вовсе.
//
// Утверждение это ЭКСПЕРИМЕНТАЛЬНОЕ, а не вычитанное: наблюдатель запросов
// считает операторы `pg_advisory*`, ушедшие НА СЕРВЕР, отдельно на форварде и
// отдельно на полном проходе. Полный проход — ЗАКОННЫЙ БЛИЗНЕЦ: он блокировку
// берёт, поэтому ноль у форварда отличим от «счётчик ничего не считает».
//
// ГРАНИЦА СЧЁТЧИКА НАЗВАНА, а не подразумевается: он видит операторы, ПОСЛАННЫЕ
// КЛИЕНТОМ, и не видит блокировки, взятой внутри триггера или серверной функции
// (такая в дереве есть — ревизия величин пределов). Поэтому ноль счётчика сам по
// себе вопроса задачи не закрывает, и вторым, независимым от счётчика ответом
// служит СРАВНЕНИЕ ВОЛНЫ С ТЕМ ЖЕ ЧИСЛОМ ПОСЛЕДОВАТЕЛЬНЫХ проходов: очередь на
// общем ключе отнимает у волны выигрыш от параллели целиком, и никакая невидимая
// блокировка этого не скрывает.
//
// # Хвост на объект против одиночного прохода этого НЕ различает
//
// Здесь стояло обратное — «форма роста хвоста по оси», — и на этом месте проба
// краснела на ранере конвейера ВСЕГДА. Медиана на объект при C одновременных
// растёт как C и при очереди на ключе, и при насыщении машины; отличается только
// делитель, и делитель этот — фактическая параллельность машины, а не предмет
// замера. Порог «вчетверо от одиночного прохода» поэтому утверждал не форму
// роста, а то, что параллельность машины не меньше четырёх на волне шириной 2N.
//
// Замерено, а не выведено: на ОДНОЙ И ТОЙ ЖЕ ревизии отношение медианы 2N к
// одиночному проходу равно 5.74x и 5.86x на ранере конвейера (два прогона из
// двух с момента заведения пробы — иного она там и не давала) против 1.5x на
// 32-ядерной машине. Продукт в обоих замерах один; менялась только машина.
// Величина эта по-прежнему ПЕЧАТАЕТСЯ — она полезна при разборе, — но не
// утверждается, ровно как обещает абзац про печать ниже.
//
// # Ось замера — число ОДНОВРЕМЕННЫХ созданий, и больше ничего
//
// Одна посадка, прогретое состояние, три точки: 1 · N · 2N. Печатается хвост
// (медиана и максимум) на объект и общее время волны; рядом, НА КАЖДОЙ ИЗ ДВУХ
// параллельных точек, — то же число объектов ПОСЛЕДОВАТЕЛЬНО, потому что
// «сериализуется» проверяется сравнением параллельной волны с последовательной,
// а не абсолютной величиной.
//
// # Что утверждается, а что печатается
//
// Утверждается СТРУКТУРНОЕ: операторов блокировки у форварда ноль, у полного
// прохода больше нуля, и волна из N — а затем из 2N — параллельных проходит
// быстрее тех же N (2N) последовательных. Абсолютные величины печатаются, но не
// утверждаются: они свойство машины, и порог возле измеренного краснел бы на
// занятом ранере.
//
// ЧУВСТВИТЕЛЬНОСТЬ НАЗВАНА, а не подразумевается. Полную сериализацию на ключе
// сравнение с последовательностью ловит на любой машине, где параллель вообще
// даёт выигрыш. ЧАСТИЧНУЮ — тем хуже, чем меньше параллельность машины: доля
// работы, которую позволено сериализовать незамеченно, растёт вместе с
// делителем. Утверждать долю точнее нечем: это потребовало бы знать
// параллельность машины, то есть вернуть в порог ровно ту величину, из-за
// которой здесь и краснело.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// advisoryStatementCounter — наблюдатель операторов, считающий ОТДЕЛЬНО те, что
// берут advisory-блокировку.
//
// Отсечка по имени функции обязательна: счёт всего трафика прохода зависел бы от
// числа объектов и не был бы величиной о предмете.
type advisoryStatementCounter struct {
	mu       sync.Mutex
	total    int
	advisory int
}

func (c *advisoryStatementCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn,
	data pgx.TraceQueryStartData) context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total++
	if strings.Contains(data.SQL, "pg_advisory") {
		c.advisory++
	}
	return ctx
}

func (c *advisoryStatementCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (c *advisoryStatementCounter) take() (advisory, total int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	advisory, total = c.advisory, c.total
	c.advisory, c.total = 0, 0
	return advisory, total
}

// TestReconcileForward_BurstOnOneOwnerBindingDoesNotSerialize — замер #2059.
func TestReconcileForward_BurstOnOneOwnerBindingDoesNotSerialize(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()

	cfg, err := pgxpool.ParseConfig(setupTestDB(t))
	require.NoError(t, err)
	counter := &advisoryStatementCounter{}
	cfg.ConnConfig.Tracer = counter
	// Пул шире волны: узкий пул сериализовал бы волну САМ, и замер говорил бы о
	// пуле, а не о блокировке (`architecture.md` §«Пул размеряется по длинному
	// меньшинству»).
	cfg.MaxConns = 32
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	fx := setupGamma(t, ctx, pool, "burst")
	rule := forwardAnchorRule()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "burstrole", domain.Rules{rule})
	// ОДНА привязка на всех — ровно та посадка, о которой задача: владельческая
	// привязка в аккаунте одна, и все создания области идут через неё.
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)

	const (
		n    = 8  // N одновременных
		twoN = 16 // 2N одновременных
		warm = 4
		// Прогрев ПУЛА отдельной волной 2N — обязателен, а не аккуратность.
		// Соединения пул заводит лениво, поэтому первая же параллельная волна
		// платит за 2N установлений разом, и замер говорил бы о холодном пуле.
		// Наблюдалось: без него волна из 8 занимала 22.9 мс при 2.9 мс на одиночном
		// проходе, а волна из 16 — те же 24.3 мс, то есть «сериализация», исчезающая
		// при удвоении оси.
		warmWave = twoN
		// Последовательный контроль берётся на ОБЕИХ параллельных точках, поэтому
		// twoN входит в бюджет дважды: волной и последовательностью.
		total = warm + warmWave + 1 + n + twoN + n + twoN
	)
	now := time.Now()
	objects := make([]string, 0, total)
	for i := 0; i < total; i++ {
		id := fmt.Sprintf("burst-%03d", i)
		seedMirrorRow(t, ctx, pool, "compute.instance", id, string(fx.prj), string(fx.accID), nil, now)
		objects = append(objects, id)
	}

	rec, adapter := newReconciler(pool)
	next := 0
	take := func(k int) []string {
		out := objects[next : next+k]
		next += k
		return out
	}

	// ── ПРОГРЕВ: планы, кеши страниц — и ОТДЕЛЬНО соединения пула волной ──────
	for _, id := range take(warm) {
		require.NoError(t, rec.ReconcileObjectForward(ctx, "compute.instance", id))
	}
	forwardWave(t, ctx, rec, take(warmWave))
	counter.take()

	// ── ОПЫТ 1: сколько операторов блокировки берёт ФОРВАРД ───────────────────
	single := take(1)[0]
	start := time.Now()
	require.NoError(t, rec.ReconcileObjectForward(ctx, "compute.instance", single))
	oneObject := time.Since(start)
	fwdAdvisory, fwdTotal := counter.take()

	// ── ЗАКОННЫЙ БЛИЗНЕЦ: полный проход блокировку БЕРЁТ ──────────────────────
	// Без него ноль у форварда неотличим от «счётчик ничего не считает».
	require.NoError(t, adapter.WithTx(ctx, func(ctx context.Context, s reconcile.ReconcileStore) error {
		return s.AcquireBindingLock(ctx, bid)
	}))
	fullAdvisory, fullTotal := counter.take()

	t.Logf("операторы блокировки: форвард %d из %d операторов прохода; "+
		"полный проход (близнец) %d из %d",
		fwdAdvisory, fwdTotal, fullAdvisory, fullTotal)

	require.Positive(t, fullAdvisory,
		"близнец не взял блокировки — счётчик не считает, и ноль у форварда был бы о пустоте")
	require.Zero(t, fwdAdvisory,
		"форвард пути создания взял advisory-блокировку: посылка #2059 подтверждается, "+
			"и предметом становится очередь на ключе привязки")

	// ── ЗАМЕР: волна из N и 2N против ТЕХ ЖЕ N последовательно ────────────────
	waveN := forwardWave(t, ctx, rec, take(n))
	wave2N := forwardWave(t, ctx, rec, take(twoN))
	seqN := forwardSequence(t, ctx, rec, take(n))
	seq2N := forwardSequence(t, ctx, rec, take(twoN))

	t.Logf("ЗАМЕР #2059 (одна посадка, прогрето: %d прогревов; ось — число одновременных)", warm)
	t.Logf("точка 1  · один проход: %v", oneObject)
	t.Logf("точка N  · одновременных %d: волна целиком %v, на объект медиана %v, максимум %v",
		n, waveN.wall, waveN.median, waveN.max)
	t.Logf("точка 2N · одновременных %d: волна целиком %v, на объект медиана %v, максимум %v",
		twoN, wave2N.wall, wave2N.median, wave2N.max)
	t.Logf("контроль · те же %d ПОСЛЕДОВАТЕЛЬНО: %v (на объект медиана %v)",
		n, seqN.wall, seqN.median)
	t.Logf("контроль · те же %d ПОСЛЕДОВАТЕЛЬНО: %v (на объект медиана %v)",
		twoN, seq2N.wall, seq2N.median)
	// Вывод произносят УТВЕРЖДЕНИЯ ниже, а не эта печать. Прежде здесь стояла
	// готовая фраза «рост СУБЛИНЕЙНЫЙ, очереди на общем ключе нет», выводившаяся
	// БЕЗУСЛОВНО, — и на красном прогоне она печаталась рядом с утверждением,
	// говорившим ровно обратное. Два места об одном предмете в одном выводе.
	t.Logf("выигрыш волны против той же последовательности: N %.2fx, 2N %.2fx "+
		"(очередь на общем ключе дала бы около 1.00x на обеих точках)",
		float64(seqN.wall)/float64(waveN.wall), float64(seq2N.wall)/float64(wave2N.wall))
	t.Logf("хвост на объект против одиночного прохода: %.1fx (1→N) и %.1fx (1→2N) "+
		"при росте оси в %dx и %dx — ПЕЧАТАЕТСЯ, НЕ УТВЕРЖДАЕТСЯ: делителем здесь "+
		"служит фактическая параллельность машины (см. шапку файла)",
		float64(waveN.median)/float64(oneObject), float64(wave2N.median)/float64(oneObject),
		n, twoN)

	// Оба утверждения о времени — СРАВНЕНИЕ волны с ТЕМ ЖЕ ЧИСЛОМ последовательных
	// проходов, а не абсолютная величина. Сериализуйся волна на одном ключе — она
	// заняла бы не меньше последовательной; здесь требуется хотя бы четверть
	// выигрыша, что на порядок мягче наблюдаемого и потому не краснеет на занятой
	// машине.
	require.Less(t, waveN.wall, (seqN.wall*3)/4,
		"волна из %d одновременных заняла %v против %v последовательных — проходы "+
			"сериализуются, и предметом становится ключ, на котором это происходит",
		n, waveN.wall, seqN.wall)

	// ВТОРОЕ утверждение — та же форма на УДВОЕННОЙ оси, и это не повтор первого:
	// блокировка, невидимая счётчику, чья конкуренция начинается выше N, показала
	// бы себя только здесь. Сравнение остаётся с той же последовательностью,
	// потому что она — единственная величина, которая делит выигрыш от параллели
	// на «его нет» и «он есть», не спрашивая, сколько у машины ядер.
	require.Less(t, wave2N.wall, (seq2N.wall*3)/4,
		"волна из %d одновременных заняла %v против %v тех же %d последовательных — "+
			"выигрыша от параллели нет, то есть проходы стоят в очереди на общем ключе",
		twoN, wave2N.wall, seq2N.wall, twoN)
}

// waveCost — величины одной точки замера.
type waveCost struct {
	wall   time.Duration
	median time.Duration
	max    time.Duration
}

// forwardWave — k форвардов ОДНОВРЕМЕННО.
func forwardWave(t *testing.T, ctx context.Context, rec *reconcile.Reconciler, ids []string) waveCost {
	t.Helper()
	require.NotEmpty(t, ids, "волна пуста — величина была бы о пустоте")
	each := make([]time.Duration, len(ids))
	errs := make([]error, len(ids))
	var wg sync.WaitGroup
	wall := time.Now()
	for i, id := range ids {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			start := time.Now()
			errs[i] = rec.ReconcileObjectForward(ctx, "compute.instance", id)
			each[i] = time.Since(start)
		}(i, id)
	}
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "проход объекта %s", ids[i])
	}
	return summarize(time.Since(wall), each)
}

// forwardSequence — те же k форвардов ПОСЛЕДОВАТЕЛЬНО. Это контроль: без него
// «волна быстрая» не отличалось бы от «машина быстрая».
func forwardSequence(t *testing.T, ctx context.Context, rec *reconcile.Reconciler, ids []string) waveCost {
	t.Helper()
	require.NotEmpty(t, ids, "последовательность пуста — контроль был бы о пустоте")
	each := make([]time.Duration, 0, len(ids))
	wall := time.Now()
	for _, id := range ids {
		start := time.Now()
		require.NoError(t, rec.ReconcileObjectForward(ctx, "compute.instance", id))
		each = append(each, time.Since(start))
	}
	return summarize(time.Since(wall), each)
}

// summarize — медиана и максимум по проходам плюс время волны целиком.
func summarize(wall time.Duration, each []time.Duration) waveCost {
	sorted := append([]time.Duration(nil), each...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	return waveCost{wall: wall, median: sorted[len(sorted)/2], max: sorted[len(sorted)-1]}
}
