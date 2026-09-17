// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// pgmaperr_login_method_integration_test.go — перевод отказов таблицы секрета
// на НАСТОЯЩИХ сообщениях сервера (фаза Ф2, `kacho#1268`).
//
// Соседняя проба `pgmaperr_login_method_test.go` подаёт переводчику
// синтетический `pgconn.PgError` — то есть утверждает о полях, которые заполнила
// она сама. Что именно кладёт сервер в `Detail`, `TableName` и `ConstraintName`,
// решает сервер, и здесь это ЗАХВАЧЕНО, а не предположено:
//
//   - посылка «сервер кладёт строку целиком в `Detail`» доказана: материал там
//     лежит (без этого утверждение о защите от него было бы защитой от
//     несуществующего);
//   - переводчик на этом же отказе материала не отдаёт ни в текст, ни в журнал —
//     журнал перехвачен, и запись в нём ЕСТЬ (иначе «материала в журнале нет»
//     было бы верно и о журнале, в который ничего не писали).

import (
	"bytes"
	"context"
	stderrors "errors"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

const lmRealMaterial = "$2a$12$REALDETAIL.login.material.f2p1.never.surfaces"

func TestWrapPgErr_LoginMethodOnRealServerRefusals(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL DEFERRED`)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, external_id, email, account_id, invite_status)
		VALUES ('usr00000000000lmreal', 'ext-lmreal', 'lmreal@example.invalid', 'acc00000000000lmreal', 'ACTIVE')`)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO accounts (id, name, owner_user_id) VALUES ('acc00000000000lmreal', 'lm-real', 'usr00000000000lmreal')`)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	const user = domain.UserID("usr00000000000lmreal")

	capture := func(q string, args ...any) *pgconn.PgError {
		t.Helper()
		_, err := pool.Exec(ctx, q, args...)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr, "отказ обязан прийти от сервера")
		return pgErr
	}

	// Журнал перехвачен на время пробы: переводчик пишет о сработавшем рубеже.
	var logBuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	// ── вид вне словаря при непустом материале ───────────────────────────────
	// Здесь стоял `totp` — с Ф12 (kacho#1281) это ЗАКОННЫЙ вид, и проба зеленела бы
	// на вставке, которую сервер принимает; вне словаря — вид, которого нет ни в
	// одной фазе.
	kindErr := capture(`INSERT INTO user_login_methods (user_id, kind, verifier) VALUES ($1, 'sms', $2)`,
		string(user), lmRealMaterial)
	require.Equal(t, "23514", kindErr.Code)
	require.Equal(t, "user_login_methods_kind_check", kindErr.ConstraintName)
	require.Equal(t, loginMethodsTable, kindErr.TableName, "сервер называет таблицу — переводчик сверяет её")
	require.Contains(t, kindErr.Detail, lmRealMaterial,
		"ПОСЫЛКА: сервер кладёт строку целиком в Detail — с материалом")

	mapped := wrapPgErr(kindErr, "LoginMethod.Create", loginMethodHint(user, "sms"))
	require.True(t, stderrors.Is(mapped, iamerr.ErrInternal), "последний рубеж — наш дефект: %v", mapped)
	require.NotContains(t, mapped.Error(), lmRealMaterial, "материал не доезжает до текста отказа")
	require.NotContains(t, mapped.Error(), "Failing row", "строка целиком не доезжает до текста отказа")

	logged := logBuf.String()
	require.Contains(t, logged, "login method backstop fired",
		"положительный контроль: запись о рубеже в журнале ЕСТЬ")
	require.NotContains(t, logged, lmRealMaterial, "материал не доезжает до журнала")

	// ── пустой материал ───────────────────────────────────────────────────────
	emptyErr := capture(`INSERT INTO user_login_methods (user_id, kind, verifier) VALUES ($1, 'password', '')`, string(user))
	require.Equal(t, "user_login_methods_verifier_check", emptyErr.ConstraintName)
	require.True(t, stderrors.Is(wrapPgErr(emptyErr, "LoginMethod.Create", loginMethodHint(user, "password")), iamerr.ErrInternal))

	// ── второй способ того же вида ───────────────────────────────────────────
	_, err = pool.Exec(ctx, `INSERT INTO user_login_methods (user_id, kind, verifier) VALUES ($1, 'password', $2)`,
		string(user), lmRealMaterial)
	require.NoError(t, err)
	dupErr := capture(`INSERT INTO user_login_methods (user_id, kind, verifier) VALUES ($1, 'password', $2)`,
		string(user), lmRealMaterial+"-second")
	require.Equal(t, "user_login_methods_pkey", dupErr.ConstraintName)
	require.NotContains(t, dupErr.Detail, "REALDETAIL",
		"ключ уникальности материала не несёт — поэтому и Detail его не несёт")
	mapped = wrapPgErr(dupErr, "LoginMethod.Create", loginMethodHint(user, domain.LoginMethodPassword))
	require.True(t, stderrors.Is(mapped, iamerr.ErrAlreadyExists))
	require.Equal(t, "Login method password of user usr00000000000lmreal already exists", iamerr.StripSentinel(mapped))

	// ── человека нет ─────────────────────────────────────────────────────────
	fkErr := capture(`INSERT INTO user_login_methods (user_id, kind, verifier) VALUES ('usr0000000000lmghost', 'password', $1)`,
		lmRealMaterial)
	require.Equal(t, "user_login_methods_user_fk", fkErr.ConstraintName)
	mapped = wrapPgErr(fkErr, "LoginMethod.Create", loginMethodHint("usr0000000000lmghost", domain.LoginMethodPassword))
	require.True(t, stderrors.Is(mapped, iamerr.ErrReferenceMissing))
	require.Equal(t, "User usr0000000000lmghost not found", iamerr.StripSentinel(mapped))
	require.NotContains(t, mapped.Error(), lmRealMaterial)
}
