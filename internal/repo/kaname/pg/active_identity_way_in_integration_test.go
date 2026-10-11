// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// active_identity_way_in_integration_test.go — ещё два производителя строки
// `ACTIVE` получают отказ, если способа входа нет (задача
// PRO-Robotech/kaname#608, приёмка `active-identity-has-a-way-in.md` AWI-01,
// AWI-06, AWI-08; §3 «сценарий → производитель»).
//
// Соседняя проба `active_identity_producers_integration_test.go` судит третьего
// производителя — вставку `InsertActive`. Здесь — два оставшихся операторами
// репозитория, каждый своим путём, транзакцией писателя:
//
//   - `ActivateInvite` — PENDING → ACTIVE. Без строки пароля той же
//     транзакцией (так приглашение активировал продукт до kaname#456) фиксация
//     отвергнута, строка остаётся PENDING. Близнец — та же активация со строкой
//     пароля той же транзакцией (так её делает исход подтверждения адреса после
//     регистрации).
//   - `SetInviteStatus(ACTIVE)` — снятие блокировки. BLOCKED без пароля и без
//     отметки открытого пути (AWI-06) — отказ, строка остаётся BLOCKED.
//     Близнец — та же строка с отметкой (форма «после переноса»): возврат из
//     блокировки у перенесённой строки не ломается.
//
// Отличающий факт у каждой пары — один: строка пароля либо отметка.
//
// Отказ — наш дефект, а не ввод вызывающего: внутренняя ошибка без текста
// драйвера; журнал называет ограничение и идентификатор, адреса не несёт.
//
// ЧЕМ КРАСНЕЕТ. Ключ `users_active_has_a_way_in_fk` уже стоит в базе ветки
// (миграция 20261005030000), поэтому красного «до кода» у этих проб нет —
// их роль — закрепить отказ КАЖДОГО производителя. Способность упасть
// доказана инъекцией: миграция без ключа — обе отрицательные ветви красные
// («зафиксирован — производитель тупика не получил отказа»).

import (
	"bytes"
	"context"
	stderrors "errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// awiProducerHarness — база и захват журнала одной пробы.
type awiProducerHarness struct {
	ctx  context.Context
	pool *pgxpool.Pool
	log  *bytes.Buffer
}

func newAWIProducerHarness(t *testing.T) *awiProducerHarness {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	var logBuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &awiProducerHarness{ctx: ctx, pool: pool, log: &logBuf}
}

// writer — транзакция писателя репозитория, тот же тип, что у продукта.
func (h *awiProducerHarness) writer(t *testing.T) *writeTx {
	t.Helper()
	tx, err := h.pool.Begin(h.ctx)
	require.NoError(t, err)
	w := &writeTx{readTx: readTx{tx: tx}}
	t.Cleanup(func() { _ = w.Rollback(h.ctx) })
	return w
}

func (h *awiProducerHarness) status(t *testing.T, id domain.UserID) string {
	t.Helper()
	var st string
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT invite_status FROM users WHERE id = $1`, string(id)).Scan(&st))
	return st
}

func (h *awiProducerHarness) passwordRows(t *testing.T, id domain.UserID) int {
	t.Helper()
	var n int
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT count(*) FROM user_login_methods WHERE user_id = $1 AND kind = 'password'`, string(id)).Scan(&n))
	return n
}

// seedInviter — распорядитель с аккаунтом и строкой пароля одной транзакцией.
func (h *awiProducerHarness) seedInviter(t *testing.T) (domain.UserID, domain.AccountID) {
	t.Helper()
	inviter := domain.UserID(ids.NewID(domain.PrefixUser))
	acc := domain.AccountID(ids.NewID(domain.PrefixAccount))
	tx, err := h.pool.Begin(h.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(h.ctx) }()
	_, err = tx.Exec(h.ctx, `INSERT INTO accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`,
		string(acc), "awi-"+string(acc[len(acc)-6:]), string(inviter))
	require.NoError(t, err)
	_, err = tx.Exec(h.ctx, `INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, 'Inviter', 'ACTIVE')`,
		string(inviter), string(acc), "ext-awi-inviter-"+string(inviter), "awi-inviter-"+string(inviter)+"@example.invalid")
	require.NoError(t, err)
	seedWayIn(t, h.ctx, tx)
	require.NoError(t, tx.Commit(h.ctx))
	return inviter, acc
}

// seedVerifiedInvite — приглашение PENDING с подтверждённым адресом (так его
// оставляет подтверждение адреса перед активацией) и без строки пароля.
func (h *awiProducerHarness) seedVerifiedInvite(t *testing.T, email string) domain.UserID {
	t.Helper()
	inviter, acc := h.seedInviter(t)
	w := h.writer(t)
	row, _, err := w.UsersW().InsertPending(h.ctx, domain.User{
		ID: domain.UserID(ids.NewID(domain.PrefixUser)), AccountID: acc, Email: domain.Email(email),
		DisplayName: "invitee", InviteStatus: domain.InviteStatusPending, InvitedBy: inviter,
	}, time.Time{})
	require.NoError(t, err)
	_, err = w.tx.Exec(h.ctx, `UPDATE users SET email_verified_at = now() WHERE id = $1`, string(row.ID))
	require.NoError(t, err)
	require.NoError(t, w.Commit(h.ctx), "PENDING без пароля инвариантом не судится (AWI-03)")
	require.Zero(t, h.passwordRows(t, row.ID))
	return row.ID
}

// seedBlocked — личность BLOCKED без строки пароля; withMark — с отметкой
// открытого пути (форма «после переноса»). BLOCKED инвариантом не судится,
// поэтому посев её ставит (AWI-06 «Дано»).
func (h *awiProducerHarness) seedBlocked(t *testing.T, email string, withMark bool) domain.UserID {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	acc := domain.AccountID(ids.NewID(domain.PrefixAccount))
	tx, err := h.pool.Begin(h.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(h.ctx) }()
	_, err = tx.Exec(h.ctx, `INSERT INTO accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`,
		string(acc), "awi-"+string(acc[len(acc)-6:]), string(uid))
	require.NoError(t, err)
	_, err = tx.Exec(h.ctx, `INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, 'Blocked', 'BLOCKED')`,
		string(uid), string(acc), "ext-awi-blocked-"+string(uid), email)
	require.NoError(t, err)
	if withMark {
		_, err = tx.Exec(h.ctx, `UPDATE users SET recovery_path_opened_at = now() WHERE id = $1`, string(uid))
		require.NoError(t, err)
	}
	require.NoError(t, tx.Commit(h.ctx))
	require.Zero(t, h.passwordRows(t, uid))
	return uid
}

// requireProducerRefused — общий исход отказа производителя.
func (h *awiProducerHarness) requireProducerRefused(t *testing.T, err error, email, scenario string) {
	t.Helper()
	require.Error(t, err, "%s: зафиксирован — производитель тупика не получил отказа", scenario)
	require.True(t, stderrors.Is(err, iamerr.ErrInternal), "%s: отказ — наш дефект, а не ввод вызывающего: %v", scenario, err)
	require.NotContains(t, err.Error(), "violates", "%s: текст драйвера наружу не выходит", scenario)
	require.NotContains(t, err.Error(), "users_active_has_a_way_in_fk", "%s: имя ограничения наружу не выходит", scenario)
	require.Contains(t, h.log.String(), "users_active_has_a_way_in_fk", "%s: журнал называет ограничение", scenario)
	require.NotContains(t, h.log.String(), email, "%s: журнал не несёт адреса (корреляция по идентификатору)", scenario)
}

// TestIntegration_AWI_ActivateInviteWithoutAWayInIsRefused — производитель
// `ActivateInvite` (PENDING → ACTIVE) без строки пароля той же транзакцией
// получает отказ на фиксации; близнец со строкой пароля фиксируется.
func TestIntegration_AWI_ActivateInviteWithoutAWayInIsRefused(t *testing.T) {
	h := newAWIProducerHarness(t)

	refusedEmail := "awi-invite-refused-" + ids.NewID("tst")[3:11] + "@example.invalid"
	refused := h.seedVerifiedInvite(t, refusedEmail)
	w := h.writer(t)
	_, err := w.UsersW().ActivateInvite(h.ctx, refused, domain.ExternalSubject("ext-awi-act-"+string(refused)), "")
	require.NoError(t, err, "оператор сам по себе проходит: проверка отложена до фиксации")
	err = w.Commit(h.ctx)
	h.requireProducerRefused(t, err, refusedEmail, "AWI-08/ActivateInvite")
	require.Equal(t, "PENDING", h.status(t, refused), "после отказа приглашение остаётся PENDING")

	twinEmail := "awi-invite-twin-" + ids.NewID("tst")[3:11] + "@example.invalid"
	twin := h.seedVerifiedInvite(t, twinEmail)
	w = h.writer(t)
	_, err = w.UsersW().ActivateInvite(h.ctx, twin, domain.ExternalSubject("ext-awi-act-"+string(twin)), "")
	require.NoError(t, err)
	v, verr := domain.NewLoginVerifier("$2a$12$awi.activate.invite.twin")
	require.NoError(t, verr)
	_, err = insertLoginMethod(h.ctx, w.tx, domain.LoginMethod{
		UserID: twin, Kind: domain.LoginMethodPassword, Verifier: v, State: domain.LoginMethodStateActive,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(h.ctx), "близнец: та же активация со строкой пароля той же транзакцией фиксируется")
	require.Equal(t, "ACTIVE", h.status(t, twin))
	require.Equal(t, 1, h.passwordRows(t, twin))
}

// TestIntegration_AWI_06_UnblockWithoutAWayInIsRefused — производитель
// `SetInviteStatus(ACTIVE)` (снятие блокировки) на BLOCKED без пароля и без
// отметки получает отказ на фиксации; близнец с отметкой фиксируется.
func TestIntegration_AWI_06_UnblockWithoutAWayInIsRefused(t *testing.T) {
	h := newAWIProducerHarness(t)

	refusedEmail := "awi-unblock-refused-" + ids.NewID("tst")[3:11] + "@example.invalid"
	refused := h.seedBlocked(t, refusedEmail, false)
	w := h.writer(t)
	_, err := w.UsersW().SetInviteStatus(h.ctx, refused, domain.InviteStatusActive)
	require.NoError(t, err, "оператор сам по себе проходит: проверка отложена до фиксации")
	err = w.Commit(h.ctx)
	h.requireProducerRefused(t, err, refusedEmail, "AWI-06/SetInviteStatus")
	require.Equal(t, "BLOCKED", h.status(t, refused), "после отказа строка остаётся BLOCKED")

	twinEmail := "awi-unblock-twin-" + ids.NewID("tst")[3:11] + "@example.invalid"
	twin := h.seedBlocked(t, twinEmail, true)
	w = h.writer(t)
	_, err = w.UsersW().SetInviteStatus(h.ctx, twin, domain.InviteStatusActive)
	require.NoError(t, err)
	require.NoError(t, w.Commit(h.ctx), "близнец: строка с отметкой открытого пути возвращается из блокировки")
	require.Equal(t, "ACTIVE", h.status(t, twin))
}
