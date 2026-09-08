// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_compensation_integration_test.go — компенсация переживает смерть
// процесса.
//
// Утверждается ИСХОД, а не факт вызова: намерение, записанное одним процессом,
// исполняется ДРУГИМ (дренаж поднимается отдельно, после того как «первый
// процесс» ничего больше не сделал). Это и есть проверка на то, ради чего
// компенсация вообще durable — прямой вызов в момент провала такой пробы не
// прошёл бы.
package clients_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/observability"
	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/clients"
)

// recordingReleaser — провайдер, у которого снятие проходит. Повторное снятие
// уже снятого клиента — успех (так ведёт себя настоящий: 404 → nil), поэтому
// повтор доставки безопасен и это проверяется отдельно.
type recordingReleaser struct {
	mu    sync.Mutex
	calls []string
	fail  error
}

func (r *recordingReleaser) DeleteOAuthClient(_ context.Context, clientID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	r.calls = append(r.calls, clientID)
	return nil
}

// DeleteJWTBearerTrustGrant — вторая операция снятия у провайдера. Снятое
// доверие пишется в тот же список: предмет каждой записи называет её же
// идентификатор, а пробам важно, что снятие ДОЕХАЛО.
func (r *recordingReleaser) DeleteJWTBearerTrustGrant(_ context.Context, grantID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	r.calls = append(r.calls, grantID)
	return nil
}

func (r *recordingReleaser) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

// countingObserver — счётчик исполненных компенсаций по атрибуции саги.
type countingObserver struct {
	mu sync.Mutex
	n  map[string]int
}

func newCountingObserver() *countingObserver {
	return &countingObserver{n: map[string]int{}}
}

func (o *countingObserver) IncCompensationApplied(origin string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.n[origin]++
}

func (o *countingObserver) total() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	s := 0
	for _, v := range o.n {
		s += v
	}
	return s
}

func setupCompensationDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in -short mode (postgres)")
	}
	// Своя база на общем Postgres пакета; путь поиска — тот же, что у прод-бинаря,
	// и объявлен `pgtest.Config.SearchPath` этого пакета.
	dsn := pgtest.NewDB(t)
	pool, err := coredb.NewPool(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

// startCompensationDrainer поднимает дренаж очереди компенсаций — отдельно от
// того, кто записал намерение.
func startCompensationDrainer(
	t *testing.T, pool *pgxpool.Pool, rel clients.ProviderClientReleaser, obs clients.CompensationObserver,
) {
	t.Helper()
	d, err := drainer.New[clients.ProviderCompensationEvent](
		pool,
		drainer.Config{
			Table:        clients.ProviderCompensationTable,
			Channel:      clients.ProviderCompensationChannel,
			BatchSize:    32,
			PollFallback: 500 * time.Millisecond,
			MaxAttempts:  5,
			BackoffMin:   50 * time.Millisecond,
			BackoffMax:   200 * time.Millisecond,
			ApplyTimeout: 2 * time.Second,
		},
		clients.DecodeProviderCompensation,
		clients.NewProviderCompensationApplier(rel, obs),
		observability.NewSlogger(testLoggerWriter{t}),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Log("compensation drainer did not stop within 5s")
		}
	})
}

// waitPending ждёт, пока в очереди не останется недоставленных строк.
func waitPending(t *testing.T, pool *pgxpool.Pool, want int64) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var got int64
	for time.Now().Before(deadline) {
		require.NoError(t, pool.QueryRow(context.Background(),
			`SELECT count(*) FROM `+clients.ProviderCompensationTable+` WHERE sent_at IS NULL`,
		).Scan(&got))
		if got == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("недоставленных строк осталось %d, ожидалось %d", got, want)
}

// TestIntegration_ProviderCompensation_SurvivesProcessDeath — главное
// утверждение класса. Намерение записано; исполнителя в этом процессе нет
// вовсе; поднимается ДРУГОЙ процесс — и занятое у провайдера освобождается.
func TestIntegration_ProviderCompensation_SurvivesProcessDeath(t *testing.T) {
	pool := setupCompensationDB(t)
	emitter := clients.NewProviderCompensationOutbox(pool)

	// «Первый процесс»: коммит своей строки не прошёл, намерение записано — и
	// на этом он умер. Ни одного прямого вызова снятия не было.
	require.NoError(t, emitter.EmitHydraClientDelete(
		context.Background(), "hydra-cli-orphan-1", "sa_key", "mapping row was not committed"))

	var pending int64
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM `+clients.ProviderCompensationTable+` WHERE sent_at IS NULL`).Scan(&pending))
	require.Equal(t, int64(1), pending, "намерение обязано пережить процесс, который его записал")

	// «Второй процесс»: поднимается дренаж.
	rel := &recordingReleaser{}
	obs := newCountingObserver()
	startCompensationDrainer(t, pool, rel, obs)

	waitPending(t, pool, 0)
	require.Equal(t, []string{"hydra-cli-orphan-1"}, rel.snapshot(),
		"клиент обязан быть снят у провайдера ровно по записанной координате")
	require.Equal(t, 1, obs.total(), "исполненная компенсация обязана быть посчитана")
}

// TestIntegration_ProviderCompensation_RepeatedDeliveryIsSafe — идемпотентность.
// Два намерения на ОДИН client_id (повтор доставки / повторная неудачная
// попытка выпуска) применяются оба; второе снятие приходит на уже снятого
// клиента и это успех, а не ошибка.
func TestIntegration_ProviderCompensation_RepeatedDeliveryIsSafe(t *testing.T) {
	pool := setupCompensationDB(t)
	emitter := clients.NewProviderCompensationOutbox(pool)

	for i := 0; i < 2; i++ {
		require.NoError(t, emitter.EmitHydraClientDelete(
			context.Background(), "hydra-cli-dup", "user_token", "mapping row was not committed"))
	}

	rel := &recordingReleaser{}
	obs := newCountingObserver()
	startCompensationDrainer(t, pool, rel, obs)

	waitPending(t, pool, 0)
	require.Equal(t, []string{"hydra-cli-dup", "hydra-cli-dup"}, rel.snapshot(),
		"повтор компенсации обязан быть безопасен: оба намерения применяются, второе — no-op у провайдера")
	require.Equal(t, 2, obs.total())

	var poisoned, failed int64
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM `+clients.ProviderCompensationTable+` WHERE last_error IS NOT NULL`).Scan(&failed))
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM `+clients.ProviderCompensationTable+` WHERE attempt_count >= 5`).Scan(&poisoned))
	require.Equal(t, int64(0), failed, "повторное снятие не должно записываться как ошибка")
	require.Equal(t, int64(0), poisoned)
}

// TestIntegration_ProviderCompensation_EmptyClientIDRefusedAtWrite — компенсация
// без предмета не попадает в очередь. Иначе дренаж вечно ретраил бы вызов
// снятия «ничего»: форма компенсации при отсутствии того, что компенсируют.
func TestIntegration_ProviderCompensation_EmptyClientIDRefusedAtWrite(t *testing.T) {
	pool := setupCompensationDB(t)

	// Писателя обходим намеренно: проверяется ИНВАРИАНТ БАЗЫ, а не ранний
	// отказ в Go — иначе проба зеленела бы и при снятом CHECK'е.
	_, err := pool.Exec(context.Background(),
		`INSERT INTO `+clients.ProviderCompensationTable+` (event_type, payload) VALUES ($1, $2)`,
		clients.EventProviderOAuthClientDelete, []byte(`{"client_id": "", "origin": "sa_key"}`))
	require.Error(t, err, "пустой client_id обязан отвергаться на уровне БД")

	// Парный положительный контроль: законная строка той же формы проходит.
	_, err = pool.Exec(context.Background(),
		`INSERT INTO `+clients.ProviderCompensationTable+` (event_type, payload) VALUES ($1, $2)`,
		clients.EventProviderOAuthClientDelete, []byte(`{"client_id": "hydra-cli-ok", "origin": "sa_key"}`))
	require.NoError(t, err, "законная компенсация обязана проходить — иначе запрет ловит форму, а не существо")
}
