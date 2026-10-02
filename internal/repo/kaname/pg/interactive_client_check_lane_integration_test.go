// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// interactive_client_check_lane_integration_test.go — полоса отказов проверок
// таблицы интерактивных клиентов на ЖИВОЙ схеме и НАСТОЯЩИХ отказах сервера
// (kaname#317).
//
// Соседняя проба `pgmaperr_interactive_client_test.go` подаёт переводчику
// синтетический отказ. Здесь утверждается то, чего синтетика знать не может:
//
//   - ПЕРЕПИСЬ ПОЛНА. Каждое ограничение-проверка таблицы, стоящее в базе
//     после наката всей цепочки, решено: либо значение присылает вызывающий
//     (перечень ниже, полоса ввода), либо отказ — фиксированный INTERNAL.
//     Ограничение, заведённое позже без решения, уезжает в полосу ввода по
//     умолчанию — и эта проба краснеет, называя его;
//   - СЕРВЕР НАЗЫВАЕТ ТАБЛИЦУ, по которой переводчик отличает свою строку:
//     отказ захвачен, а не предположен;
//   - МАТЕРИАЛ НЕ ВЫХОДИТ. Сервер кладёт строку целиком в `Detail`, с
//     материалом секрета, — ни текст отказа, ни журнал его не несут.

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// icCallerValueChecks — ограничения, судящие значение, которое ПРИСЫЛАЕТ
// вызывающий: перечни адресов возврата. Полоса ввода.
var icCallerValueChecks = map[string]bool{
	"interactive_clients_redirect_uris_count_ck":    true,
	"interactive_clients_post_logout_uris_count_ck": true,
}

func icPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	pool, err := pgxpool.New(context.Background(), pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return pool
}

// TestIntegration_InteractiveClientChecksAreAllAdjudicated — перепись
// ограничений-проверок таблицы клиентов: каждое решено.
func TestIntegration_InteractiveClientChecksAreAllAdjudicated(t *testing.T) {
	pool := icPool(t)
	ctx := context.Background()

	rows, err := pool.Query(ctx, `
		SELECT conname FROM pg_constraint
		 WHERE conrelid = 'kaname.interactive_clients'::regclass AND contype = 'c'
		 ORDER BY conname`)
	require.NoError(t, err)
	var live []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		live = append(live, name)
	}
	require.NoError(t, rows.Err())
	require.NotEmpty(t, live, "проверка НЕ ИСПОЛНЯЛАСЬ: у таблицы клиентов не найдено ни одной проверки")

	logBuf := icCaptureLog(t)
	liveSet := make(map[string]bool, len(live))
	var internal, input int
	for _, name := range live {
		liveSet[name] = true
		err := wrapPgErr(icCheckPgErr(name, "interactive_clients"), "InteractiveClient", "ic-census")
		switch {
		case icCallerValueChecks[name]:
			input++
			require.True(t, stderrors.Is(err, iamerr.ErrInvalidArg),
				"%s: значение присылает вызывающий — полоса ввода, получено %v", name, err)
		default:
			internal++
			require.True(t, stderrors.Is(err, iamerr.ErrInternal),
				"%s: ограничение не решено — значение не присылает вызывающий, а отказ обвиняет "+
					"его (%v). Решение: полоса дефекта службы либо запись в icCallerValueChecks", name, err)
		}
	}
	t.Logf("перепись: проверок таблицы клиентов %d — дефект службы %d, ввод вызывающего %d; журнал %d байт",
		len(live), internal, input, logBuf.Len())

	// Обратное направление: решение о несуществующем ограничении — ложь о схеме.
	for _, name := range icProducedValueChecks {
		require.True(t, liveSet[name], "спецификация называет ограничение %s, которого в схеме нет", name)
	}
	for name := range icCallerValueChecks {
		require.True(t, liveSet[name], "перечень ввода называет ограничение %s, которого в схеме нет", name)
	}
	for name := range interactiveClientProducedValueChecks {
		require.True(t, liveSet[name], "перечень полосы дефекта в коде называет ограничение %s, которого в схеме нет", name)
	}
}

// TestIntegration_InteractiveClientBackstopOnRealServerRefusals — настоящие
// отказы сервера по каждому ограничению полосы дефекта и близнец полосы ввода.
func TestIntegration_InteractiveClientBackstopOnRealServerRefusals(t *testing.T) {
	pool := icPool(t)
	ctx := context.Background()
	material := icProducedVerifier(t)

	const insert = `
		INSERT INTO kaname.interactive_clients
		       (id, name, redirect_uris, client_id, token_endpoint_auth_method, status,
		        secret_verifier, secret_verifier_set_at)
		VALUES ($1, $2, $3::text[], $4, $5, $6, $7, $8::timestamptz)`
	type row struct {
		id, redirect, method, status, verifier string
		stamped                                bool
	}
	base := func(n int) row {
		return row{id: "ic-" + icPad(n), redirect: "{https://app.example.test/cb}", method: "none", status: "ACTIVE"}
	}
	capture := func(n int, r row) *pgconn.PgError {
		t.Helper()
		var setAt any
		if r.stamped {
			setAt = time.Now()
		}
		_, err := pool.Exec(ctx, insert, r.id, "ic-lane-"+icPad(n), r.redirect, "client-lane-"+icPad(n),
			r.method, r.status, r.verifier, setAt)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr, "строка %d: отказ обязан прийти от сервера", n)
		return pgErr
	}

	// Положительный контроль сцены: строка без нарушений принимается — иначе
	// каждый отказ ниже мог бы прийти от чего угодно.
	ok := base(1)
	_, err := pool.Exec(ctx, insert, ok.id, "ic-lane-"+icPad(1), ok.redirect, "client-lane-"+icPad(1),
		ok.method, ok.status, "", nil)
	require.NoError(t, err, "положительный контроль: строка производителя принимается")

	secretRow := func(n int) row { r := base(n); r.method = "client_secret_basic"; return r }
	cases := []struct {
		constraint string
		row        row
	}{
		{"interactive_clients_id_form_ck", func() row { r := base(2); r.id = "ic-NOT-A-FORM"; return r }()},
		{"interactive_clients_status_ck", func() row { r := base(3); r.status = "GONE"; return r }()},
		{"interactive_clients_auth_method_ck", func() row { r := base(4); r.method = ""; return r }()},
		{"interactive_clients_secret_verifier_method_ck",
			func() row { r := base(5); r.verifier, r.stamped = material, true; return r }()},
		{"interactive_clients_secret_verifier_form_ck",
			func() row { r := secretRow(6); r.verifier, r.stamped = "raw-secret-of-the-client", true; return r }()},
		{"interactive_clients_secret_verifier_stamp_ck",
			func() row { r := secretRow(7); r.verifier = material; return r }()},
	}

	logBuf := icCaptureLog(t)
	for i, c := range cases {
		logBuf.Reset()
		pgErr := capture(10+i, c.row)
		require.Equal(t, "23514", pgErr.Code, c.constraint)
		require.Equal(t, c.constraint, pgErr.ConstraintName, "сработать обязано ИМЕННО это ограничение")
		require.Equal(t, "interactive_clients", pgErr.TableName, "сервер называет таблицу — переводчик сверяет её")

		mapped := wrapPgErr(pgErr, "InteractiveClient", "ic-real")
		require.True(t, stderrors.Is(mapped, iamerr.ErrInternal), "%s: наш дефект, получено %v", c.constraint, mapped)
		require.Equal(t, iamerr.ErrInternal.Error(), mapped.Error(), "%s: текст фиксированный", c.constraint)
		logged := logBuf.String()
		require.Contains(t, logged, "constraint="+c.constraint, "положительный контроль: запись в журнале ЕСТЬ")
		require.NotContains(t, logged, material, "материал не доезжает до журнала")
		require.NotContains(t, mapped.Error(), material, "материал не доезжает до текста отказа")
	}

	// БЛИЗНЕЦ полосы ввода: пустой перечень адресов возврата присылает вызывающий.
	twin := base(30)
	twin.redirect = "{}"
	pgErr := capture(30, twin)
	require.Equal(t, "interactive_clients_redirect_uris_count_ck", pgErr.ConstraintName)
	require.True(t, stderrors.Is(wrapPgErr(pgErr, "InteractiveClient", "ic-real"), iamerr.ErrInvalidArg),
		"значение вызывающего остаётся полосой ввода")
}

// icProducedVerifier — проверочное значение, вычеканенное ТЕМ ЖЕ
// производителем, каким пишутся пароли: материал, который форма колонки
// принимает, иначе отказ пришёл бы от формы, а не от предмета случая.
func icProducedVerifier(t *testing.T) string {
	t.Helper()
	record, ok := domain.PasswordHashFormatByMarker(string(domain.PasswordHashFormatArgon2id))
	require.True(t, ok, "формат argon2id обязан стоять в перечне")
	hasher, err := passwordverify.NewHasher(passwordverify.Declared{
		Format: domain.PasswordHashFormatArgon2id,
		Params: record.Floor,
	})
	require.NoError(t, err, "хешер объявленного формата")
	v, err := hasher.Hash("s3cret-of-the-interactive-client")
	require.NoError(t, err)
	return v.Reveal()
}

// icPad — 17 знаков crockford-base32 из номера: форма `ic-…` закрыта
// ограничением схемы.
func icPad(n int) string {
	const digits = "0123456789abcdefghjkmnpqrstvwxyz"
	out := []byte("00000000000000000")
	for i := len(out) - 1; i >= 0 && n > 0; i-- {
		out[i] = digits[n%32]
		n /= 32
	}
	return string(out)
}
