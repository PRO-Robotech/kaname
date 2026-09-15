// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// invite_mail_address_rate_integration_test.go — ограничение частоты писем на
// адрес (приёмка ID-MAIL-1: Р14, Р22; §10 пп. 13, 17; MAIL-25, MAIL-42, MAIL-43 —
// уровень I).
//
// # Где стоит ограничитель, и почему перечня глаголов здесь нет
//
// Ограничитель стоит в ЕДИНСТВЕННОМ писателе очереди писем — там, где намерение
// отправить письмо ложится в базу. Любой глагол, отправляющий письмо, проходит
// через этого писателя, поэтому новый глагол попадает под ограничение по
// построению, а не по перечню, который пришлось бы вести руками. Что писателей
// очереди ровно один, держит гейт дерева `internal/check`
// (`TestInviteMailQueueHasOneWriterAndItIsRated`).
//
// # Решение и его следствие — ОДИН оператор
//
// «Есть ли место в окне» и «списать» не разнесены: одна вставка с условием на
// правке окна. Проверка-перед-списанием разошлась бы со списанием ровно под
// конкуренцией (ban #10), и потолок стал бы «величина × параллелизм».

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

var mailRateProbe = domain.InviteMailAddressRate{Letters: 3, Window: time.Hour}

func newRatedRepo(t *testing.T, rate domain.InviteMailAddressRate) (context.Context, *pgxpool.Pool, *kanamepg.Repository) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return ctx, pool, kanamepg.New(pool, nil).WithInviteMailAddressRate(rate)
}

// emitLetter кладёт намерение в СВОЕЙ транзакции и возвращает исход коммита.
func emitLetter(ctx context.Context, repo *kanamepg.Repository, to string) error {
	w, err := repo.Writer(ctx)
	if err != nil {
		return err
	}
	if err := w.EmitInviteMail(ctx, ids.NewID(domain.PrefixUser), "acc0000000000000rate", to, ""); err != nil {
		_ = w.Rollback(ctx)
		return err
	}
	return w.Commit(ctx)
}

func intentsTo(t *testing.T, ctx context.Context, pool *pgxpool.Pool, to string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.invite_mail_outbox WHERE lower(payload->>'to') = lower($1)`, to).Scan(&n))
	return n
}

// MAIL-25 / MAIL-42 (I): сверх величины — отказ; в пределах — письмо ложится.
// Положительный контроль — другой адрес в том же окне не задет.
func TestIntegration_InviteMailRate_RefusesBeyondTheDeclaredLetters(t *testing.T) {
	ctx, pool, repo := newRatedRepo(t, mailRateProbe)
	const to = "rated-addr@example.com"
	for i := 0; i < mailRateProbe.Letters; i++ {
		require.NoError(t, emitLetter(ctx, repo, to), "письмо %d в пределах величины обязано лечь", i+1)
	}
	err := emitLetter(ctx, repo, to)
	require.Error(t, err, "письмо сверх величины обязано отвергаться")
	require.True(t, errors.Is(err, iamerr.ErrMailRateExceeded),
		"отказ обязан нести признак ПОЛОСЫ частоты, а не общий отказ: %v", err)
	require.NotContains(t, err.Error(), to, "текст отказа не несёт адреса: он уезжает в журналы")
	require.Equal(t, mailRateProbe.Letters, intentsTo(t, ctx, pool, to),
		"отвергнутое письмо не вправе оставить намерение в очереди")

	// Регистр адреса — не другой адрес.
	require.ErrorIs(t, emitLetter(ctx, repo, strings.ToUpper(to)), iamerr.ErrMailRateExceeded,
		"адрес, отличающийся регистром, — тот же ящик; иначе ограничение обходится сменой регистра")

	require.NoError(t, emitLetter(ctx, repo, "other-addr@example.com"),
		"КОНТРОЛЬ: другой адрес в том же окне ограничением не задет")
}

// Окно сдвигается внутри строки: по истечении окна письмо снова ложится, и счёт
// начинается с единицы.
func TestIntegration_InviteMailRate_WindowElapsesAndCountsAgain(t *testing.T) {
	ctx, pool, repo := newRatedRepo(t, domain.InviteMailAddressRate{Letters: 1, Window: time.Hour})
	const to = "window-addr@example.com"
	require.NoError(t, emitLetter(ctx, repo, to))
	require.ErrorIs(t, emitLetter(ctx, repo, to), iamerr.ErrMailRateExceeded)

	tag, err := pool.Exec(ctx,
		`UPDATE kaname.invite_mail_address_windows SET window_started_at = now() - interval '61 minutes'`)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(), "ПРЕДПОСЫЛКА: окно этого адреса одно")

	require.NoError(t, emitLetter(ctx, repo, to), "по истечении окна письмо обязано лечь снова")
	var letters int
	require.NoError(t, pool.QueryRow(ctx, `SELECT letters FROM kaname.invite_mail_address_windows`).Scan(&letters))
	require.Equal(t, 1, letters, "новое окно начинается с единицы, а не продолжает прежнее")
}

// Ровно «величина» писем под конкуренцией — не «величина × параллелизм».
func TestIntegration_InviteMailRate_HoldsUnderConcurrency(t *testing.T) {
	ctx, pool, repo := newRatedRepo(t, mailRateProbe)
	const to = "concurrent-addr@example.com"
	const n = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = emitLetter(ctx, repo, to)
		}(i)
	}
	close(start)
	wg.Wait()

	var ok, refused int
	for _, e := range errs {
		switch {
		case e == nil:
			ok++
		case errors.Is(e, iamerr.ErrMailRateExceeded):
			refused++
		default:
			t.Fatalf("исход, которого не бывает: %v", e)
		}
	}
	require.Equal(t, mailRateProbe.Letters, ok, "легло писем: %d при величине %d", ok, mailRateProbe.Letters)
	require.Equal(t, n-mailRateProbe.Letters, refused)
	require.Equal(t, mailRateProbe.Letters, intentsTo(t, ctx, pool, to))
}

// Ограничитель, чья величина не провязана, отказывает, а не пропускает: «не
// задано» на пути ограничения читается закрыто (Р14 — значения «без
// ограничения» не существует).
func TestIntegration_InviteMailRate_UnboundRateRefusesTheLetter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	const to = "unbound-addr@example.com"
	err = emitLetter(ctx, repo, to)
	require.Error(t, err, "письмо при непровязанной величине обязано отвергаться")
	require.Zero(t, intentsTo(t, ctx, pool, to))
}

// Строка окна не несёт адреса: окно ключуется отпечатком, и копии личных
// данных в таблице частоты нет.
func TestIntegration_InviteMailRate_WindowStoresNoAddress(t *testing.T) {
	ctx, pool, repo := newRatedRepo(t, mailRateProbe)
	const to = "pii-addr@example.com"
	require.NoError(t, emitLetter(ctx, repo, to))
	var row string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT row_to_json(w)::text FROM kaname.invite_mail_address_windows w`).Scan(&row))
	require.NotContains(t, strings.ToLower(row), "pii-addr", "строка окна несёт адрес: %s", row)
	require.NotEmpty(t, row, "ПРЕДПОСЫЛКА: строка окна прочитана")
}

// Уборка снимает только истёкшие окна и печатает перепись.
func TestIntegration_InviteMailRate_SweepRemovesOnlyElapsedWindows(t *testing.T) {
	ctx, pool, repo := newRatedRepo(t, mailRateProbe)
	require.NoError(t, emitLetter(ctx, repo, "elapsed-addr@example.com"))
	require.NoError(t, emitLetter(ctx, repo, "current-addr@example.com"))
	_, err := pool.Exec(ctx, `
		UPDATE kaname.invite_mail_address_windows
		   SET window_started_at = now() - interval '2 hours'
		 WHERE address_digest = sha256(convert_to('elapsed-addr@example.com', 'UTF8'))`)
	require.NoError(t, err)

	sweeper := kanamepg.NewInviteMailAddressWindowRepo(pool, mailRateProbe)
	removed, full, err := sweeper.SweepElapsedInviteMailWindows(ctx, 0, 100)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed, "снята обязана быть ровно истёкшая строка")
	require.False(t, full)

	var left int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.invite_mail_address_windows`).Scan(&left))
	require.Equal(t, 1, left, "действующее окно уборка не трогает")
	t.Logf("перепись уборки: снято %d · осталось %d", removed, left)
	_ = fmt.Sprint
}
