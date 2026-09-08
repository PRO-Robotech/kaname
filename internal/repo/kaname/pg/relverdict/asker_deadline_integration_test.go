// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// asker_deadline_integration_test.go — что остаётся в базе, когда теневой вопрос
// не уложился в свой срок.
//
// Предмет пробы — НЕ «вернулась ли ошибка». Предмет — соединение: транзакция
// чтения снимается тем же контекстом, которым вопрос и был ограничен, и на
// исчерпании срока этот контекст уже мёртв. Снятие, отданное мёртвому контексту,
// до базы не доезжает — транзакция остаётся открытой, соединение из пула не
// возвращается пригодным, и под нагрузкой это видно как рост числа соединений
// «в открытой транзакции» при единицах активных.
//
// Проба УТВЕРЖДАЕТ ЧИСЛО, а не наличие конструкции: сколько соединений этого
// приложения осталось в открытой транзакции после отказа по сроку.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// poolTagged собирает пул, помеченный именем приложения: считать соединения надо
// ИМЕННО теневые, иначе в число попадут посев и сама наблюдающая связь, и проба
// станет неотличима от шума.
func poolTagged(t *testing.T, dsn, appName string) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("разбор DSN: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = appName
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("пул %s: %v", appName, err)
	}
	pgtest.ClosePoolAtEnd(t, pool)
	return pool
}

// heldInTransaction — сколько соединений приложения висят в открытой транзакции
// (в том числе в прерванной: она тоже держит слот до снятия).
func heldInTransaction(t *testing.T, observer *pgxpool.Pool, appName string) int {
	t.Helper()
	var n int
	err := observer.QueryRow(context.Background(), `
		SELECT count(*) FROM pg_stat_activity
		 WHERE application_name = $1
		   AND state IN ('idle in transaction', 'idle in transaction (aborted)')`, appName).Scan(&n)
	if err != nil {
		t.Fatalf("срез базы: %v", err)
	}
	return n
}

// TestShadowDeadlineLeavesNoOpenTransaction — предикат 2 задачи #751.
//
// Блокировка таблицы даёт ДЕТЕРМИНИРОВАННЫЙ срыв срока: читающий запрос встаёт
// на замке, а не «иногда не успевает», поэтому проба не зависит ни от загрузки
// машины, ни от объёма данных.
func TestShadowDeadlineLeavesNoOpenTransaction(t *testing.T) {
	dsn := pgtest.NewDB(t)
	const appName = "kaname-shadow-probe"

	shadowPool := poolTagged(t, dsn, appName)
	observer := poolTagged(t, dsn, "kaname-shadow-observer")
	asker := relverdict.NewAsker(shadowPool)

	ctx := context.Background()

	// Замок держится ОТДЕЛЬНОЙ связью и снимается сразу после срыва срока: цель —
	// сорвать срок, а не изучать поведение под замком.
	blocker, err := observer.Acquire(ctx)
	if err != nil {
		t.Fatalf("связь для замка: %v", err)
	}
	blockTx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatalf("транзакция замка: %v", err)
	}
	if _, err := blockTx.Exec(ctx,
		`LOCK TABLE kaname.relation_fact IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatalf("замок: %v", err)
	}

	// Теневой вопрос со СВОИМ коротким сроком — как на живом пути.
	sctx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	_, askErr := asker.Allowed(sctx, "user:usr-1", "vpc_network", "net-1", "v_get", nil)
	cancel()

	if askErr == nil {
		t.Fatal("вопрос под замком ответил успехом — срок не сорвался, и проба меряет не тот путь")
	}

	// Замок снят: с этого мгновения ничто, кроме брошенной транзакции, слот не держит.
	_ = blockTx.Rollback(ctx)
	blocker.Release()

	// Ждём УСЛОВИЯ, а не времени: снятие транзакции — не мгновенная операция, и
	// проба, читающая срез сразу, мерила бы скорость планировщика.
	deadline := time.Now().Add(5 * time.Second)
	var held int
	for time.Now().Before(deadline) {
		held = heldInTransaction(t, observer, appName)
		if held == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("после отказа теневой сверки по сроку осталось %d соединений в открытой "+
		"транзакции (ожидалось 0): транзакция чтения снимается тем же контекстом, которым "+
		"вопрос был ограничен, а на исчерпании срока он уже мёртв — снятие до базы не "+
		"доезжает. Под нагрузкой это и есть рост числа соединений «в транзакции» при "+
		"единицах активных: %s", held, poolNote(shadowPool))
}

// poolNote — состояние пула рядом с числом: «сколько занято» и «сколько всего»
// отличают брошенную транзакцию от честно занятого слота.
func poolNote(p *pgxpool.Pool) string {
	s := p.Stat()
	return fmt.Sprintf("пул: всего %d, занято %d, свободно %d",
		s.TotalConns(), s.AcquiredConns(), s.IdleConns())
}

// TestRollbackOfAnExpiredQuestionKeepsTheConnection — что снятие транзакции
// делает со СВЯЗЬЮ, когда срок вопроса уже истёк.
//
// Транзакция чтения снималась тем же контекстом, что ограничивал вопрос. Когда
// срок истёк, этот контекст мёртв, и `Rollback` возвращает его ошибку, НЕ
// ОТПРАВИВ ничего: связь уходит в пул с незакрытой транзакцией, пул признаёт её
// непригодной и уничтожает. Каждый такой случай стоит одного подключения к базе —
// на стороне, которая и так узкая.
//
// Проба утверждает НАБЛЮДАЕМОЕ — тот же ли backend обслуживает следующий запрос.
// Пул на ОДНО соединение делает утверждение однозначным: при большем пуле «другой
// pid» означал бы и уничтожение, и просто другой свободный слот.
//
// Рядом — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ той же формы: снятие мёртвым контекстом связь
// теряет. Без него «связь сохранилась» было бы неотличимо от «пул её и так не
// переиспользует», и проба зеленела бы, ничего не измеряя.
func TestRollbackOfAnExpiredQuestionKeepsTheConnection(t *testing.T) {
	dsn := pgtest.NewDB(t)

	// openTxThenAbandon открывает транзакцию чтения, отменяет контекст вызывающего
	// (запроса в полёте НЕТ — как между последней строкой ответа и снятием) и
	// снимает её переданным способом. Отдаёт backend до и после.
	openTxThenAbandon := func(t *testing.T, appName string, roll func(context.Context, pgx.Tx) error) (int32, int32) {
		t.Helper()
		cfg, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatalf("разбор DSN: %v", err)
		}
		cfg.ConnConfig.RuntimeParams["application_name"] = appName
		cfg.MaxConns = 1
		pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
		if err != nil {
			t.Fatalf("пул: %v", err)
		}
		pgtest.ClosePoolAtEnd(t, pool)

		pid := func() int32 {
			var p int32
			if err := pool.QueryRow(context.Background(), `SELECT pg_backend_pid()`).Scan(&p); err != nil {
				t.Fatalf("pg_backend_pid: %v", err)
			}
			return p
		}

		before := pid()
		ctx, cancel := context.WithCancel(context.Background())
		tx, err := pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
		if err != nil {
			cancel()
			t.Fatalf("транзакция чтения: %v", err)
		}
		if _, err := tx.Exec(ctx, `SELECT 1`); err != nil {
			cancel()
			t.Fatalf("оператор в транзакции: %v", err)
		}
		cancel() // вызывающий ушёл: срок вопроса истёк
		_ = roll(ctx, tx)
		return before, pid()
	}

	t.Run("снятие живым контекстом связь сохраняет", func(t *testing.T) {
		before, after := openTxThenAbandon(t, "kaname-rollback-live", relverdict.RollbackForTest)
		if before != after {
			t.Fatalf("связь потеряна: backend %d сменился на %d. Снятие транзакции обязано "+
				"идти контекстом, который жив: иначе каждый сорванный по сроку вопрос стоит "+
				"одного подключения, и под нагрузкой пул не «дорастает до потолка», а "+
				"непрерывно перебирает связи", before, after)
		}
	})

	t.Run("положительный контроль: снятие мёртвым контекстом связь теряет", func(t *testing.T) {
		before, after := openTxThenAbandon(t, "kaname-rollback-dead",
			func(ctx context.Context, tx pgx.Tx) error { return tx.Rollback(ctx) })
		if before == after {
			t.Fatalf("мёртвый контекст связь НЕ потерял (backend %d) — проба не различает "+
				"два способа снятия и потому ничего не утверждает о живом", before)
		}
	})
}

// TestShadowDeadlineDoesNotCostTheConnection — что срыв срока стоит ПУЛУ, когда
// запрос уже в полёте.
//
// Соседняя проба выше берёт узкий случай: транзакция открыта, запроса нет.
// Здесь — тот, что и наблюдался на нагрузке: запрос ИСПОЛНЯЕТСЯ, и срок истекает
// посреди него. Тогда за пригодность связи отвечает не только контекст снятия,
// но и то, как драйвер доводит отмену: срок, поставленный сокету, оставляет
// запрос на сервере живым и рвёт связь клиентски, тогда как настоящий
// CancelRequest снимает запрос ТАМ и связь сохраняет.
//
// Пул на ОДНО соединение делает утверждение однозначным, и собирается он
// `coredb.NewPool` — то есть тем же способом, что и в службе: проба, собравшая
// пул своей рукой, утверждала бы о своей копии настроек, а не о боевой.
func TestShadowDeadlineDoesNotCostTheConnection(t *testing.T) {
	dsn := pgtest.NewDB(t)
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	ctx := context.Background()
	shadowPool, err := coredb.NewPool(ctx,
		dsn+sep+"pool_max_conns=1&application_name=kaname-shadow-churn")
	if err != nil {
		t.Fatalf("пул: %v", err)
	}
	pgtest.ClosePoolAtEnd(t, shadowPool)

	observer := poolTagged(t, dsn, "kaname-shadow-observer")
	asker := relverdict.NewAsker(shadowPool)

	backendPID := func() int32 {
		var pid int32
		if err := shadowPool.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			t.Fatalf("pg_backend_pid: %v", err)
		}
		return pid
	}
	before := backendPID()

	// Детерминированный срыв срока: читающий запрос встаёт на замке таблицы.
	blocker, err := observer.Acquire(ctx)
	if err != nil {
		t.Fatalf("связь для замка: %v", err)
	}
	blockTx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatalf("транзакция замка: %v", err)
	}
	if _, err := blockTx.Exec(ctx,
		`LOCK TABLE kaname.relation_fact IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatalf("замок: %v", err)
	}

	sctx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	if _, askErr := asker.Allowed(sctx, "user:usr-1", "vpc_network", "net-1", "v_get", nil); askErr == nil {
		cancel()
		t.Fatal("вопрос под замком ответил успехом — срок не сорвался, и проба меряет не тот путь")
	}
	cancel()

	_ = blockTx.Rollback(ctx)
	blocker.Release()

	if after := backendPID(); after != before {
		t.Fatalf("сорванный по сроку теневой вопрос стоил соединения: backend %d сменился на %d. "+
			"Отмена, доведённая только до сокета, оставляет запрос на сервере и рвёт связь "+
			"клиентски; пул возвращённую связь уничтожает и заводит новую. Под нагрузкой это "+
			"не рост пула до потолка, а непрерывный перебор связей — по одному подключению за "+
			"каждый сорванный вопрос, на стороне, которая и так узкая", before, after)
	}
}
