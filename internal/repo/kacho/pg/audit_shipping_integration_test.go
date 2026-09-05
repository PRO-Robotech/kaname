// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// audit_shipping_integration_test.go — журнал аудита службы прав ДОЕЗЖАЕТ до
// приёмника, и доезжает ЦЕЛИКОМ.
//
// # Что здесь проверяется сверх проб самого механизма
//
// Пробы `pkg/audit` гоняют вывоз по таблице, объявленной в них же, поэтому они
// утверждают о МЕХАНИЗМЕ и молчат о том, совпадает ли с ним ЖИВАЯ таблица.
// Здесь применены настоящие миграции службы и работает настоящий путь записи —
// то есть проверяется ровно то, чего механизм проверить не может: что форма
// журнала службы вывозу адресуема, а колонки, которых нет у соседа
// (`tenant_account_id`, `event_payload`), доезжают до приёмника.

import (
	"context"
	"io"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/audit"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/observability"
	"github.com/PRO-Robotech/kacho/pkg/outbox/metrics"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// capturingSink — приёмник, запоминающий доставленное.
type capturingSink struct {
	mu  sync.Mutex
	got []audit.Record
}

func (s *capturingSink) Ship(_ context.Context, r audit.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, r)
	return nil
}

func (s *capturingSink) Name() string { return "capturing" }

func (s *capturingSink) records() []audit.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]audit.Record, len(s.got))
	copy(out, s.got)
	return out
}

// TestAuditJournalReachesTheSink — строка, записанная НАСТОЯЩИМ путём эмиссии,
// вывозится и помечается доставленной.
func TestAuditJournalReachesTheSink(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "shipping")
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccountsW().Insert(ctx, domain.Account{
		ID: accID, Name: domain.AccountName("shipping-acc"), OwnerUserID: uid, Labels: domain.Labels{},
	})
	require.NoError(t, err)
	require.NoError(t, w.EmitAuditEvent(ctx, service.AuditEvent{
		EventType:       "iam.account.created",
		TenantAccountID: string(accID),
		Payload: map[string]any{
			"actor": string(uid), "resource_type": "account", "resource_id": string(accID),
		},
	}))
	require.NoError(t, w.Commit(ctx))

	sink := &capturingSink{}
	sh, err := audit.NewShipper(pool, sink, metrics.NewMemRecorder(),
		observability.NewSlogger(io.Discard),
		audit.ShipperConfig{Table: "kacho_iam.audit_outbox"})
	require.NoError(t, err)

	res, err := sh.Pass(ctx)
	require.NoError(t, err)
	require.NotZero(t, res.Shipped, "живая таблица журнала обязана быть адресуема вывозу")
	require.Zero(t, res.Deferred)

	var mine *audit.Record
	for i := range sink.records() {
		r := sink.records()[i]
		if payload, ok := r.Fields["event_payload"].(map[string]any); ok &&
			payload["resource_id"] == string(accID) {
			mine = &r
			break
		}
	}
	require.NotNil(t, mine, "записанное событие обязано быть среди доставленных")
	require.Equal(t, "iam.account.created", mine.EventType)
	require.Equal(t, string(accID), mine.Fields["tenant_account_id"],
		"колонка, которой нет у журнала соседней службы, обязана доехать: вывоз доставляет строку целиком")
	require.NotContains(t, mine.Fields, "status", "учётные колонки доставки — не часть записи журнала")

	// Обе половины пометки: состояние И состоявшаяся попытка. Одно состояние
	// оставило бы «доставлено ноль раз» и «доставлено без единой попытки»
	// неотличимыми — ровно ту пару, из-за которой очередь и разбирали.
	var (
		status   string
		attempts int
		sentAt   *string
	)
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT status, attempts, sent_at::text FROM kacho_iam.audit_outbox WHERE id = $1`,
		mine.ID).Scan(&status, &attempts, &sentAt))
	require.Equal(t, "sent", status)
	require.Equal(t, 1, attempts)
	require.NotNil(t, sentAt)
}

// TestAuditJournalStatusVocabularyIsTwo — ОТРИЦАНИЕ к пробе выше: словарь
// состояний закрыт ровно тем, что продукт производит.
//
// Без него сужение словаря миграцией держалось бы только текстом миграции, и
// возврат состояния, которого никто не пишет, прошёл бы молча.
func TestAuditJournalStatusVocabularyIsTwo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	// Положительный контроль: законное состояние ограничением принимается.
	_, err = pool.Exec(ctx,
		`INSERT INTO kacho_iam.audit_outbox (id, event_type, event_payload, status)
		 VALUES ($1, 'iam.account.created', '{}'::jsonb, 'pending')`,
		"evt_"+ids.NewID("aud")[3:]+"aaaaa")
	require.NoError(t, err)

	// Отрицание: КАЖДОЕ снятое состояние отвергается базой, а не кодом.
	//
	// Перебор обязателен: проба, щупающая одно значение из двух, остаётся
	// зелёной при возврате второго — то есть половину словаря не проверяет
	// вовсе, и это ровно та половина, о которой никто не вспомнит.
	for _, gone := range []string{"in_flight", "failed"} {
		_, err = pool.Exec(ctx,
			`UPDATE kacho_iam.audit_outbox SET status = $1 WHERE status = 'pending'`, gone)
		require.Error(t, err,
			"состояние %q продукт не производит — оно обязано быть невыразимо в таблице", gone)
	}
}
