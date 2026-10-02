// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// check_value_lane_integration_test.go — полоса отказа проверки по вопросу
// «чьё это значение» на ЖИВОЙ схеме (kaname#395).
//
// Две пробы:
//
//   - перепись: каждая живая проверка схемы (`pg_constraint`, contype 'c')
//     подаётся переводчику, и его ответ сверяется со спецификацией
//     (`cvCallerValueSpec`). Проверка, заведённая миграцией без решения,
//     краснит пробу и называет себя;
//   - настоящие отказы сервера по обе стороны: служебная колонка
//     (`human_sessions.ended_reason`) и ввод вызывающего
//     (`accounts.description`). Что сервер кладёт в `TableName`,
//     `ConstraintName` и `Detail`, здесь ЗАХВАЧЕНО, а не предположено.

import (
	"context"
	stderrors "errors"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

func cvPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	pool, err := pgxpool.New(context.Background(), pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return pool
}

// cvLiveChecks — перепись живых проверок схемы службы.
func cvLiveChecks(t *testing.T, pool *pgxpool.Pool) []cvLiveCheck {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		SELECT c.relname, con.conname
		  FROM pg_constraint con
		  JOIN pg_class c ON c.oid = con.conrelid
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE con.contype = 'c' AND n.nspname = 'kaname'
		 ORDER BY c.relname, con.conname`)
	require.NoError(t, err)
	defer rows.Close()
	var live []cvLiveCheck
	for rows.Next() {
		var c cvLiveCheck
		require.NoError(t, rows.Scan(&c.table, &c.constraint))
		live = append(live, c)
	}
	require.NoError(t, rows.Err())
	return live
}

// TestIntegration_EveryLiveCheckAnswersInItsLane — перепись: ответ переводчика
// на каждую живую проверку схемы совпадает со спецификацией полосы.
func TestIntegration_EveryLiveCheckAnswersInItsLane(t *testing.T) {
	pool := cvPool(t)
	live := cvLiveChecks(t, pool)
	require.NotEmpty(t, live, "проверка НЕ ИСПОЛНЯЛАСЬ: в схеме не найдено ни одной проверки")

	tables := map[string]struct{}{}
	liveNames := map[string]struct{}{}
	for _, c := range live {
		tables[c.table] = struct{}{}
		liveNames[c.constraint] = struct{}{}
	}

	logBuf := cvCaptureLog(t)
	findings, input, defect := cvJudge(live, cvCallerValueSpec)
	t.Logf("перепись: таблиц %d, проверок %d — полоса ввода %d, полоса дефекта службы %d; находок %d; журнал %d байт",
		len(tables), len(live), input, defect, len(findings), logBuf.Len())
	require.Empty(t, findings, "проверки отвечают не своей полосой:\n%s", strings.Join(findings, "\n"))

	// Обратное направление: спецификация, называющая ограничение, которого в
	// схеме нет, — ложь о схеме, и о её предмете ничего не утверждает.
	var ghosts []string
	for name := range cvCallerValueSpec {
		if _, ok := liveNames[name]; !ok {
			ghosts = append(ghosts, name)
		}
	}
	sort.Strings(ghosts)
	require.Empty(t, ghosts, "спецификация полосы ввода называет ограничения, которых в схеме нет: %v", ghosts)
}

// TestIntegration_CheckValueLaneOnRealServerRefusals — настоящие отказы сервера
// по обе стороны полосы.
func TestIntegration_CheckValueLaneOnRealServerRefusals(t *testing.T) {
	pool := cvPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL DEFERRED`)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, external_id, email, account_id, invite_status)
		VALUES ('usr00000000000cvreal', 'ext-cvreal', 'cvreal@example.invalid', 'acc00000000000cvreal', 'ACTIVE')`)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO accounts (id, name, owner_user_id) VALUES ('acc00000000000cvreal', 'cv-real', 'usr00000000000cvreal')`)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	capture := func(q string, args ...any) *pgconn.PgError {
		t.Helper()
		_, err := pool.Exec(ctx, q, args...)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr, "отказ обязан прийти от сервера: %v", err)
		return pgErr
	}
	logBuf := cvCaptureLog(t)

	// ── сторона 1: служебная колонка ─────────────────────────────────────────
	// Причину завершения пишут только константы домена; значение вне словаря
	// значит «служба записала то, чего её словарь не знает».
	sessErr := capture(`
		INSERT INTO human_sessions
		    (id, user_id, bearer_digest, authenticated_at, last_presented_at, expires_at,
		     assurance_level, presented_methods, ended_at, ended_reason)
		VALUES ('hss-cvreal', 'usr00000000000cvreal', $1, now(), now(), now() + interval '1 hour',
		        '1', ARRAY['password'], now(), 'not-a-reason-of-the-domain')`, cvBearerInDetail)
	require.Equal(t, "23514", sessErr.Code)
	require.Equal(t, "human_sessions_ended_reason_check", sessErr.ConstraintName)
	require.Equal(t, "human_sessions", sessErr.TableName, "сервер называет таблицу — переводчик судит её")
	require.Contains(t, sessErr.Detail, cvBearerInDetail,
		"ПОСЫЛКА: сервер кладёт строку целиком в Detail — с дайджестом предъявителя")

	logBuf.Reset()
	mapped := wrapPgErr(sessErr, "HumanSession", "hss-cvreal")
	require.True(t, stderrors.Is(mapped, iamerr.ErrInternal), "служебное значение — наш дефект: %v", mapped)
	require.Equal(t, iamerr.ErrInternal.Error(), mapped.Error(), "текст отказа фиксированный")
	logged := logBuf.String()
	require.Contains(t, logged, "check backstop fired", "положительный контроль: запись о рубеже ЕСТЬ")
	require.Contains(t, logged, "constraint=human_sessions_ended_reason_check")
	require.Contains(t, logged, "table=human_sessions")
	require.NotContains(t, logged, cvBearerInDetail, "материал строки не доезжает до журнала")
	require.NotContains(t, logged, sessErr.Detail, "Detail не доезжает до журнала")
	require.NotContains(t, logged, sessErr.Message, "текст драйвера не доезжает до журнала")

	// ── сторона 2: ввод вызывающего ──────────────────────────────────────────
	descErr := capture(`UPDATE accounts SET description = repeat('d', 300) WHERE id = 'acc00000000000cvreal'`)
	require.Equal(t, "accounts_description_check", descErr.ConstraintName)
	require.Equal(t, "accounts", descErr.TableName)

	logBuf.Reset()
	mapped = wrapPgErr(descErr, "Account", "acc00000000000cvreal")
	require.True(t, stderrors.Is(mapped, iamerr.ErrInvalidArg), "значение вызывающего — полоса ввода: %v", mapped)
	require.Equal(t, "Illegal argument description: length must be <=256", iamerr.StripSentinel(mapped))
	require.NotContains(t, logBuf.String(), "check backstop fired", "близнец записи о рубеже не пишет")
}

// cvRaisedByName — имена ограничений, которые живые функции схемы поднимают
// клаузой `CONSTRAINT = '…'`. Такой отказ в `pg_constraint` не значится, а
// перепись вправе его решать.
func cvRaisedByName(t *testing.T, pool *pgxpool.Pool) map[string]struct{} {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		SELECT m[1]
		  FROM pg_proc p
		  JOIN pg_namespace n ON n.oid = p.pronamespace,
		       regexp_matches(p.prosrc, 'CONSTRAINT\s*=\s*''([a-z0-9_]+)''', 'g') AS m
		 WHERE n.nspname = 'kaname'`)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]struct{}{}
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		out[name] = struct{}{}
	}
	require.NoError(t, rows.Err())
	return out
}

// TestIntegration_CheckLedgerCoversTheLiveSchema — перепись против живой схемы
// в обе стороны: каждая живая проверка решена, и каждое решение называет то,
// что в схеме есть.
func TestIntegration_CheckLedgerCoversTheLiveSchema(t *testing.T) {
	pool := cvPool(t)
	live := cvLiveChecks(t, pool)
	require.NotEmpty(t, live, "проверка НЕ ИСПОЛНЯЛАСЬ: в схеме не найдено ни одной проверки")
	raised := cvRaisedByName(t, pool)
	require.NotEmpty(t, raised, "ПОСЫЛКА: у схемы есть отказ триггера, поднятый по имени, — без него "+
		"обратное направление не проверяет свою ветвь")

	// Прямое направление.
	findings := cvUndecided(live)

	// Обратное направление: решение о таблице и ограничении, которых нет, —
	// ложь о схеме.
	byTable := map[string]map[string]struct{}{}
	for _, c := range live {
		if byTable[c.table] == nil {
			byTable[c.table] = map[string]struct{}{}
		}
		byTable[c.table][c.constraint] = struct{}{}
	}
	var whole, mixed, triggerNamed int
	for table, lanes := range checkValueLanes {
		checks, ok := byTable[table]
		if !ok {
			findings = append(findings, table+": перепись называет таблицу, у которой в схеме нет проверок")
			continue
		}
		if lanes == nil {
			whole++
			continue
		}
		mixed++
		seen := map[string]string{}
		for lane, names := range map[string][]string{"ввода": lanes.caller, "службы": lanes.service} {
			for _, name := range names {
				if other, dup := seen[name]; dup {
					findings = append(findings, table+"."+name+": названа в двух полосах — "+other+" и "+lane)
				}
				seen[name] = lane
				if _, ok := checks[name]; ok {
					continue
				}
				if _, ok := raised[name]; ok && lane == "ввода" {
					triggerNamed++
					continue
				}
				findings = append(findings, table+"."+name+": перечень полосы "+lane+
					" называет ограничение, которого у таблицы в схеме нет")
			}
		}
	}
	sort.Strings(findings)
	t.Logf("перепись схемы: живых проверок %d в %d таблицах; объявлено таблиц %d — пишет служба целиком %d, "+
		"смешанных %d; решений по отказу триггера %d (поднятых по имени в схеме %d); находок %d",
		len(live), len(byTable), whole+mixed, whole, mixed, triggerNamed, len(raised), len(findings))
	require.Empty(t, findings, "перепись расходится со схемой:\n%s", strings.Join(findings, "\n"))
}
