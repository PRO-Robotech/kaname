// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// active_has_a_way_in_integration_test.go — глаголы, которые производят строку
// `ACTIVE`, на строке без способа входа завершают операцию ОТКАЗОМ, и исход
// операции — наш фиксированный внутренний текст (задача PRO-Robotech/kaname#608,
// приёмка `active-identity-has-a-way-in.md` AWI-01, AWI-06).
//
// Предмет — исход ГЛАГОЛА, а не оператора репозитория: тот же отказ базы
// (отложенный ключ `users_active_has_a_way_in_fk`) проходит сквозь транзакцию
// use-case'а и становится ошибкой операции. Тело операции — то, что вернула
// функция работы; `operations.Run` кладёт её статус в `Operation.error` как
// есть, поэтому проба судит статус, возвращённый функцией работы.
//
// Производитель — снятие блокировки (`Unblock`) на BLOCKED без пароля и без
// отметки: отказ, строка BLOCKED, события аудита нет; близнец, отличающийся
// одним фактом, — строка с отметкой открытого пути, исход ACTIVE.
//
// Второй глагол этого вида — внутреннее заведение личности по удостоверению
// внешнего поставщика — снят с контракта (kaname#929, AWI-09): производить
// строку им больше нечем, и его пробы ушли вместе с ним.
//
// Текст отказа — `internal error`, код INTERNAL: строку без способа входа
// производит наш код, а не ввод вызывающего (hard-no-err-echo). Ни имя
// ограничения, ни текст драйвера в исход не выходят; журнал не несёт адреса
// (hard-no-pii-in-logs) — корреляция по идентификатору.
//
// ЧЕМ КРАСНЕЕТ. Ключ уже стоит в базе ветки (миграция 20261005030000), красного
// «до кода» нет; способность упасть доказана инъекцией — миграция без ключа:
// каждая отрицательная ветвь красная («операция завершилась успехом»).

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

type wayInVerbHarness struct {
	ctx    context.Context
	pool   *pgxpool.Pool
	repo   *kanamepg.Repository
	log    *bytes.Buffer
	logger *slog.Logger
}

func newWayInVerbHarness(t *testing.T) *wayInVerbHarness {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsnWithSchema(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	prev := slog.Default()
	slog.SetDefault(logger)
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &wayInVerbHarness{ctx: ctx, pool: pool, repo: kanamepg.New(pool, nil), log: &buf, logger: logger}
}

func (h *wayInVerbHarness) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, h.pool.QueryRow(h.ctx, q, args...).Scan(&n))
	return n
}

func (h *wayInVerbHarness) status(t *testing.T, id domain.UserID) string {
	t.Helper()
	var st string
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT invite_status FROM kaname.users WHERE id = $1`, string(id)).Scan(&st))
	return st
}

// requireRefusedOperation — исход операции глагола при отказе базы.
func (h *wayInVerbHarness) requireRefusedOperation(t *testing.T, err error, email, scenario string) {
	t.Helper()
	require.Error(t, err, "%s: операция завершилась успехом — производитель тупика не получил отказа", scenario)
	st, ok := status.FromError(err)
	require.True(t, ok, "%s: исход операции — статус: %v", scenario, err)
	require.Equal(t, codes.Internal, st.Code(), "%s: отказ — наш дефект, а не ввод вызывающего", scenario)
	require.Equal(t, "internal error", st.Message(), "%s: текст исхода фиксированный", scenario)
	require.NotContains(t, h.log.String(), email, "%s: журнал не несёт адреса", scenario)
	require.Contains(t, h.log.String(), "users_active_has_a_way_in_fk", "%s: журнал называет ограничение", scenario)
}

// seedPersonWithAccount — личность в данном состоянии с аккаунтом, одной
// транзакцией. password — строка пароля той же транзакцией; mark — отметка
// открытого пути (форма «после переноса»). email — подтверждён ли адрес.
func (h *wayInVerbHarness) seedPersonWithAccount(t *testing.T, state, email, ext string, password, mark, verified bool) (domain.UserID, domain.AccountID) {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	acc := domain.AccountID(ids.NewID(domain.PrefixAccount))
	tx, err := h.pool.Begin(h.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(h.ctx) }()
	_, err = tx.Exec(h.ctx, `INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`,
		string(acc), "awi-"+string(acc[len(acc)-6:]), string(uid))
	require.NoError(t, err)
	_, err = tx.Exec(h.ctx, `INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status, email_verified_at, recovery_path_opened_at)
		VALUES ($1, $2, $3, $4, 'AWI', $5, CASE WHEN $6 THEN now() END, CASE WHEN $7 THEN now() END)`,
		string(uid), string(acc), ext, email, state, verified, mark)
	require.NoError(t, err)
	if password {
		_, err = tx.Exec(h.ctx, `INSERT INTO kaname.user_login_methods (user_id, kind, verifier)
			VALUES ($1, 'password', 'fixture-password-row-without-a-known-password')`, string(uid))
		require.NoError(t, err)
	}
	require.NoError(t, tx.Commit(h.ctx))
	return uid, acc
}

func freshWayInEmail(tag string) string {
	return "awi-" + tag + "-" + ids.NewID("tst")[3:11] + "@example.invalid"
}

// TestAWI06_UnblockVerbWithoutAWayInFailsItsOperation — снятие блокировки
// глаголом на BLOCKED без пароля и без отметки.
func TestAWI06_UnblockVerbWithoutAWayInFailsItsOperation(t *testing.T) {
	h := newWayInVerbHarness(t)
	uc := NewUnblockUserUseCase(h.repo, nil)

	email := freshWayInEmail("unblock")
	refused, _ := h.seedPersonWithAccount(t, "BLOCKED", email, "ext-awi-unblock-"+ids.NewID("tst")[3:11], false, false, false)
	_, err := uc.doSetInviteStatus(h.ctx, refused, "system", auditEventUserUnblocked)
	h.requireRefusedOperation(t, err, email, "AWI-06/Unblock")
	require.Equal(t, "BLOCKED", h.status(t, refused), "после отказа строка остаётся BLOCKED")
	require.Zero(t, h.count(t, `SELECT count(*) FROM kaname.audit_outbox WHERE event_payload->>'resource_id' = $1`, string(refused)),
		"событие аудита откатилось вместе с записью")

	twinEmail := freshWayInEmail("unblock-twin")
	twin, _ := h.seedPersonWithAccount(t, "BLOCKED", twinEmail, "ext-awi-unblock-twin-"+ids.NewID("tst")[3:11], false, true, false)
	_, err = uc.doSetInviteStatus(h.ctx, twin, "system", auditEventUserUnblocked)
	require.NoError(t, err, "близнец: строка с отметкой открытого пути возвращается из блокировки")
	require.Equal(t, "ACTIVE", h.status(t, twin))
	require.Equal(t, 1, h.count(t, `SELECT count(*) FROM kaname.audit_outbox WHERE event_payload->>'resource_id' = $1`, string(twin)))
}
