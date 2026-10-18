// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// reconcile_forward_burst_cost_integration_test.go — проба всплеска созданий в
// одном аккаунте, где владельческая привязка ОДНА на всех (задача продукта
// kacho#2059; признак часов снят задачей kaname#771).
//
// # Посылка задачи и что с ней стало
//
// Задача утверждала: путь создания открывает вторую пишущую транзакцию и БЕРЁТ в
// ней пообъектную advisory-блокировку, поэтому N созданий в одной области встают
// в очередь на ключе единственной привязки. Первая половина верна и осталась —
// проход идёт своей писательской транзакцией после коммита. Вторая половина
// сегодня НЕ верна: форвард пути создания advisory-блокировки не берёт вовсе.
//
// # Два ответа, и оба — без часов
//
// ПЕРВЫЙ — счётчик операторов `pg_advisory*`, ушедших НА СЕРВЕР, отдельно на
// форварде и на полном проходе. Полный проход — ЗАКОННЫЙ БЛИЗНЕЦ: он блокировку
// берёт, поэтому ноль у форварда отличим от «счётчик ничего не считает».
// Граница счётчика названа: он видит операторы, ПОСЛАННЫЕ КЛИЕНТОМ, и не видит
// блокировки, взятой внутри триггера или серверной функции.
//
// ВТОРОЙ — ВСТРЕЧА У КОММИТА, и он этой границы не имеет. Каждый из 2N
// одновременных проходов, дойдя до коммита своей транзакции, ждёт у общей точки,
// пока до неё не дойдут все. Всё, что транзакция прохода держит — блокировки
// строк, advisory-блокировки клиента, триггера или серверной функции, — она
// держит до коммита. Поэтому встреча собирается целиком тогда и только тогда,
// когда 2N транзакций прохода одновременно открыты ПОСЛЕ всей своей записи:
// очередь на общем ключе собрать её не даёт — держатель ключа ждёт у точки, а
// остальные ждут ключа. Утверждается ЧИСЛО — сколько проходов стояли у точки
// одновременно (пик), — а не время.
//
// Предел ожидания у точки есть, но он ограничивает только КРАСНЫЙ исход: при
// сериализации встреча не собирается ни за какое время, при её отсутствии
// собирается, как только дойдёт последний проход. Зелёный от скорости машины не
// зависит, красный — тоже: на сериализующей реализации пик равен единице на
// любом узле.
//
// # Почему здесь больше нет времени
//
// Прежде вторым ответом было сравнение времени волны с тем же числом
// последовательных проходов, со строгим «быстрее». Оно утверждало о планировщике
// общего узла, а не о коде: под `-race` на 6 CPU отношение разбрасывалось от
// 0.60x до 5.98x, и проба падала один раз из трёх (kaname#769, kaname#771).
// Красный такой пробы неотличим от регрессии, зелёный — от удачи.
//
// # Способность упасть — постоянным близнецом, а не откатанной инъекцией
//
// TestReconcileForward_BurstRendezvousRedsOnASerializingTrigger ставит на
// таблицу членов триггер, который берёт ОДНУ advisory-блокировку на всех — ровно
// тот класс блокировки, которого счётчик не видит, — и требует, чтобы встреча не
// собралась (пик 1). Близнец гоняется каждым прогоном, поэтому способность пробы
// упасть на сериализующей реализации проверяется вместе с ней, а не однажды.

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

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
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

// Он же — точка встречи у коммита: проход, чей контекст несёт участника встречи,
// останавливается на операторе `commit` своей транзакции. Встреча зовётся ДО
// захвата мьютекса счётчика — иначе ждущий у точки держал бы счётчик, и
// остальные проходы встали бы на нём, а не на предмете замера.
func (c *advisoryStatementCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn,
	data pgx.TraceQueryStartData) context.Context {
	if p, ok := ctx.Value(rendezvousKey{}).(*rendezvousParticipant); ok &&
		strings.EqualFold(strings.TrimSpace(data.SQL), "commit") {
		p.arriveOnce()
	}
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

// rendezvousKey — ключ участника встречи в контексте прохода.
type rendezvousKey struct{}

// commitRendezvous — точка встречи у коммита на want проходов.
//
// Величина встречи — ПИК: сколько проходов стояли у точки одновременно. Пик
// равен want ровно тогда, когда want транзакций прохода были открыты разом после
// всей своей записи; очередь на общем ключе даёт пик 1. Предел ожидания
// ограничивает только несобравшуюся встречу: после него точка «сломана», и
// следующие проходы её минуют, а не ждут предела каждый.
type commitRendezvous struct {
	want  int
	limit time.Duration

	mu      sync.Mutex
	present int
	peak    int
	arrived int
	full    chan struct{} // закрыт, когда у точки стоят все want
	broken  bool
}

func newCommitRendezvous(want int, limit time.Duration) *commitRendezvous {
	return &commitRendezvous{want: want, limit: limit, full: make(chan struct{})}
}

// rendezvousParticipant — один проход; у точки он стоит не больше одного раза.
type rendezvousParticipant struct {
	r    *commitRendezvous
	once sync.Once
}

func (p *rendezvousParticipant) arriveOnce() { p.once.Do(p.r.arrive) }

func (r *commitRendezvous) arrive() {
	r.mu.Lock()
	r.arrived++
	if r.broken {
		r.mu.Unlock()
		return
	}
	r.present++
	if r.present > r.peak {
		r.peak = r.present
	}
	if r.present == r.want {
		close(r.full)
	}
	r.mu.Unlock()

	timer := time.NewTimer(r.limit)
	defer timer.Stop()
	select {
	case <-r.full:
	case <-timer.C:
		r.mu.Lock()
		r.broken = true
		r.mu.Unlock()
	}

	r.mu.Lock()
	r.present--
	r.mu.Unlock()
}

// outcome — пик встречи, сколько проходов дошли до коммита вообще и собралась ли
// встреча до предела.
func (r *commitRendezvous) outcome() (peak, arrived int, met bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.peak, r.arrived, r.peak == r.want
}

// rendezvousWave — форварды ids ОДНОВРЕМЕННО, каждый со своим участником одной
// встречи у коммита.
func rendezvousWave(t *testing.T, ctx context.Context, rec *reconcile.Reconciler, ids []string,
	limit time.Duration) *commitRendezvous {
	t.Helper()
	require.NotEmpty(t, ids, "волна пуста — встреча была бы о пустоте")
	r := newCommitRendezvous(len(ids), limit)
	errs := make([]error, len(ids))
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			pctx := context.WithValue(ctx, rendezvousKey{}, &rendezvousParticipant{r: r})
			errs[i] = rec.ReconcileObjectForward(pctx, "compute.instance", id)
		}(i, id)
	}
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "проход объекта %s", ids[i])
	}
	return r
}

// requireMaterialized — у каждого объекта волны есть строка члена под привязкой
// bid. Предпосылка обоих утверждений встречи: без записи у коммита стояла бы
// транзакция, которая ничего не держит, и пик говорил бы о пустоте, а триггер
// близнеца не сработал бы вовсе.
func requireMaterialized(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bid domain.AccessBindingID, ids []string) {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(DISTINCT object_id) FROM kaname.access_binding_target_members
		  WHERE binding_id=$1 AND object_type='compute.instance' AND object_id = ANY($2)`,
		string(bid), ids).Scan(&n))
	require.Equal(t, len(ids), n, "строки членов есть не у всех объектов волны")
}

// burstWorld — посадка всплеска: пул шире волны, одна привязка на все объекты,
// count зеркальных объектов.
type burstWorld struct {
	pool    *pgxpool.Pool
	counter *advisoryStatementCounter
	rec     *reconcile.Reconciler
	adapter *kanamepg.ReconcileAdapter
	bid     domain.AccessBindingID
	objects []string
}

func newBurstWorld(t *testing.T, ctx context.Context, suffix string, count int) burstWorld {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(setupTestDB(t))
	require.NoError(t, err)
	counter := &advisoryStatementCounter{}
	cfg.ConnConfig.Tracer = counter
	// Пул шире волны: узкий пул не дал бы собраться встрече САМ, и пик говорил бы
	// о пуле, а не о блокировке (`architecture.md` §«Пул размеряется по длинному
	// меньшинству»).
	cfg.MaxConns = 32
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	fx := setupGamma(t, ctx, pool, suffix)
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, suffix+"role", domain.Rules{forwardAnchorRule()})
	// ОДНА привязка на всех — ровно та посадка, о которой задача: владельческая
	// привязка в аккаунте одна, и все создания области идут через неё.
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)

	now := time.Now()
	objects := make([]string, 0, count)
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("%s-%03d", suffix, i)
		seedMirrorRow(t, ctx, pool, "compute.instance", id, string(fx.prj), string(fx.accID), nil, now)
		objects = append(objects, id)
	}
	rec, adapter := newReconciler(pool)
	return burstWorld{pool: pool, counter: counter, rec: rec, adapter: adapter, bid: bid, objects: objects}
}

const (
	// burstWidth — 2N одновременных созданий: встреча на 2N покрывает и N.
	burstWidth = 16
	// meetLimit — предел ожидания у точки там, где встреча обязана собраться. Он
	// ограничивает только красный исход и потому взят с запасом на медленный
	// узел под `-race`: собравшаяся встреча его не ждёт.
	meetLimit = 2 * time.Minute
	// noMeetLimit — предел у близнеца, где встреча собраться не может ни за
	// какое время: величина здесь — цена близнеца, а не порог.
	noMeetLimit = 3 * time.Second
)

// TestReconcileForward_BurstOnOneOwnerBindingDoesNotSerialize — kacho#2059,
// признак без часов — kaname#771.
func TestReconcileForward_BurstOnOneOwnerBindingDoesNotSerialize(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	w := newBurstWorld(t, ctx, "burst", 1+burstWidth)
	single, wave := w.objects[0], w.objects[1:]

	// ── ОПЫТ 1: сколько операторов блокировки берёт ФОРВАРД ───────────────────
	w.counter.take()
	require.NoError(t, w.rec.ReconcileObjectForward(ctx, "compute.instance", single))
	fwdAdvisory, fwdTotal := w.counter.take()

	// ── ЗАКОННЫЙ БЛИЗНЕЦ: полный проход блокировку БЕРЁТ ──────────────────────
	// Без него ноль у форварда неотличим от «счётчик ничего не считает».
	require.NoError(t, w.adapter.WithTx(ctx, func(ctx context.Context, s reconcile.ReconcileStore) error {
		return s.AcquireBindingLock(ctx, w.bid)
	}))
	fullAdvisory, fullTotal := w.counter.take()

	t.Logf("операторы блокировки: форвард %d из %d операторов прохода; "+
		"полный проход (близнец) %d из %d",
		fwdAdvisory, fwdTotal, fullAdvisory, fullTotal)

	require.Positive(t, fullAdvisory,
		"близнец не взял блокировки — счётчик не считает, и ноль у форварда был бы о пустоте")
	require.Zero(t, fwdAdvisory,
		"форвард пути создания взял advisory-блокировку: посылка kacho#2059 подтверждается, "+
			"и предметом становится очередь на ключе привязки")

	// ── ОПЫТ 2: встреча 2N проходов у коммита ─────────────────────────────────
	r := rendezvousWave(t, ctx, w.rec, wave, meetLimit)
	peak, arrived, met := r.outcome()
	t.Logf("встреча у коммита: одновременно у точки %d из %d проходов (дошли до коммита %d)",
		peak, len(wave), arrived)
	requireMaterialized(t, ctx, w.pool, w.bid, wave)
	require.Equal(t, len(wave), arrived, "до коммита дошли не все проходы — встреча была бы не о них")
	require.True(t, met,
		"у коммита одновременно стояли %d из %d проходов: транзакции прохода не открыты разом "+
			"после своей записи, то есть проходы стоят в очереди на общем ключе",
		peak, len(wave))
}

// TestReconcileForward_BurstRendezvousRedsOnASerializingTrigger — близнец
// способности упасть (kaname#771): та же встреча на реализации, которая
// сериализует проходы блокировкой, НЕВИДИМОЙ счётчику операторов, — триггером на
// таблице членов, берущим одну advisory-блокировку на всех. Встреча обязана не
// собраться: пик 1.
func TestReconcileForward_BurstRendezvousRedsOnASerializingTrigger(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	w := newBurstWorld(t, ctx, "serial", burstWidth)

	// База пробы своя у каждого теста (pgtest.NewDB), поэтому триггер живёт ровно
	// в этом тесте; снимается он всё равно явно — уборка заводится до создания.
	t.Cleanup(func() {
		_, _ = w.pool.Exec(context.Background(),
			`DROP TRIGGER IF EXISTS burst_serialize ON kaname.access_binding_target_members;
			 DROP FUNCTION IF EXISTS public.burst_serialize()`)
	})
	_, err := w.pool.Exec(ctx, `
		CREATE FUNCTION public.burst_serialize() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM pg_advisory_xact_lock(771);
			RETURN NULL;
		END $$;
		CREATE TRIGGER burst_serialize BEFORE INSERT ON kaname.access_binding_target_members
			FOR EACH STATEMENT EXECUTE FUNCTION public.burst_serialize();`)
	require.NoError(t, err, "триггер сериализации не поставлен")

	w.counter.take()
	r := rendezvousWave(t, ctx, w.rec, w.objects, noMeetLimit)
	peak, arrived, met := r.outcome()
	fwdAdvisory, _ := w.counter.take()
	t.Logf("встреча у коммита на сериализующем триггере: одновременно у точки %d из %d (дошли %d); "+
		"операторов блокировки, посланных клиентом, %d", peak, len(w.objects), arrived, fwdAdvisory)

	requireMaterialized(t, ctx, w.pool, w.bid, w.objects)
	require.Equal(t, len(w.objects), arrived, "до коммита дошли не все проходы — близнец был бы не о них")
	require.Zero(t, fwdAdvisory,
		"счётчик увидел блокировку триггера — близнец перестал быть о блокировке, невидимой счётчику")
	require.False(t, met, "встреча собралась на сериализующем триггере — проба не способна упасть")
	require.Equal(t, 1, peak, "на сериализующем триггере у коммита одновременно стоял не один проход")
}
