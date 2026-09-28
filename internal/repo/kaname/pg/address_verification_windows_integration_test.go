// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// address_verification_windows_integration_test.go — окна и уборка кодов
// подтверждения адреса держатся ОПЕРАТОРАМИ базы (kaname#456, миграция
// `20260927190000_address_verification_is_our_verb.sql`; ban #10).
//
// # Что утверждается
//
//   - окно обращений источника (`source_request_windows`) под КОНКУРЕНЦИЕЙ
//     пропускает ровно предел: N одновременных обращений одного источника
//     одной полосы — допущено ровно Limit, остальные отвергнуты, строка окна
//     считает ровно Limit. Решение принимает условие `WHERE` правки
//     `ON CONFLICT`, а не чтение перед записью; близнец — другой источник и
//     другая полоса того же источника допускаются, пока окно первого полно;
//   - уборка кодов подтверждения снимает только то, что предел писем уже не
//     прочтёт: окончившаяся строка моложе окна писем остаётся (она считает
//     письма окна), окончившаяся старше окна снята, живая неистёкшая строка
//     старше окна остаётся (её ещё предъявят);
//   - строка окна писем на адрес (`invite_mail_windows`) называет вид письма
//     сама: умолчания у колонки вида нет, писатель без вида отвергнут схемой,
//     а не списан молча в окно приглашений.
package pg_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// widePool — пул службы шириной width: одновременные обращения обязаны
// дойти до базы одновременно, а не очередью пула.
func widePool(t *testing.T, width int) (context.Context, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	dsn := setupTestDB(t)
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	pool, err := coredb.NewPool(ctx, dsn+sep+"pool_max_conns="+strconv.Itoa(width))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	require.EqualValues(t, width, pool.Config().MaxConns, "ширина пула пробы не применилась")
	return ctx, pool
}

// chargeConcurrently — callers одновременных списаний одного окна в один
// момент; ответ — число допущенных и ошибки хранилища.
func chargeConcurrently(ctx context.Context, repo *kanamepg.HumanSessionRepo, lane humansession.SourceLane,
	source string, at time.Time, pace humansession.SourcePace, callers int) (int, []error) {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		admitted int
		errs     []error
		startGun = make(chan struct{})
	)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startGun
			ok, err := repo.ChargeSource(ctx, lane, source, at, pace)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			if ok {
				admitted++
			}
		}()
	}
	close(startGun)
	wg.Wait()
	return admitted, errs
}

func sourceWindowRequests(t *testing.T, ctx context.Context, pool *pgxpool.Pool, lane humansession.SourceLane, source string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT requests FROM kaname.source_request_windows WHERE lane = $1 AND source = $2`,
		string(lane), source).Scan(&n))
	return n
}

func TestSourceWindowAdmitsExactlyTheLimitUnderConcurrentCallers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	const (
		callers = 32
		rounds  = 3
	)
	ctx, pool := widePool(t, 16)
	repo := kanamepg.NewHumanSessionRepo(pool)
	pace := humansession.SourcePace{Limit: 3, Window: time.Hour}
	lane := humansession.SourceLaneRegistration
	at := time.Now().UTC().Truncate(time.Microsecond)

	for r := 0; r < rounds; r++ {
		source := fmt.Sprintf("198.51.100.%d", 10+r)
		admitted, errs := chargeConcurrently(ctx, repo, lane, source, at, pace, callers)
		require.Empty(t, errs, "раунд %d: одновременные обращения получили ошибки вместо исхода", r)
		require.Equal(t, pace.Limit, admitted,
			"раунд %d: из %d одновременных обращений одного источника допущено %d при пределе %d — окно списано гонкой, а не условием оператора",
			r, callers, admitted, pace.Limit)
		require.Equal(t, pace.Limit, sourceWindowRequests(t, ctx, pool, lane, source),
			"раунд %d: строка окна считает не предел", r)
	}

	// Близнецы — ровно один факт против полного окна: другой источник той же
	// полосы и тот же источник другой полосы допускаются.
	full := "198.51.100.10"
	ok, err := repo.ChargeSource(ctx, lane, full, at, pace)
	require.NoError(t, err)
	require.False(t, ok, "полное окно источника обязано отвергать и последовательное обращение")

	ok, err = repo.ChargeSource(ctx, lane, "198.51.100.99", at, pace)
	require.NoError(t, err)
	require.True(t, ok, "другой источник той же полосы допускается: окно принадлежит источнику")

	ok, err = repo.ChargeSource(ctx, humansession.SourceLaneRecoveryRequest, full, at, pace)
	require.NoError(t, err)
	require.True(t, ok, "тот же источник другой полосы допускается: окно принадлежит полосе и источнику")
}

// codeDigest — свёртка, годная ограничению схемы и уникальная по метке.
func codeDigest(tag string) string {
	sum := sha256.Sum256([]byte(tag))
	return hex.EncodeToString(sum[:])
}

func TestUnservableVerificationCodesSweepKeepsWhatThePaceStillCounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.NewHumanSessionRepo(pool)

	const letterWindow = time.Hour
	holder := mustSeedUser(t, ctx, pool, "sweep-codes-a")
	second := mustSeedUser(t, ctx, pool, "sweep-codes-b")

	// Моменты строк — от часов базы: уборка судит `now()` базы.
	put := func(id string, user string, row string) {
		t.Helper()
		_, err := pool.Exec(ctx, `
			INSERT INTO kaname.email_verification_codes
			       (id, user_id, email, code_digest, issued_at, expires_at, consumed_at, superseded_at)
			SELECT $1, $2, 'sweep@example.invalid', $3, v.issued_at, v.expires_at, v.consumed_at, v.superseded_at
			  FROM (`+row+`) AS v(issued_at, expires_at, consumed_at, superseded_at)`,
			id, user, codeDigest(id))
		require.NoError(t, err, "строка кода %s", id)
	}
	// Окончилась (вытеснена) старше окна — снимается.
	put("evc-old-superseded", string(holder), `SELECT now() - interval '2 hours', now() - interval '90 minutes',
		NULL::timestamptz, now() - interval '119 minutes'`)
	// Окончилась (применена) моложе окна — остаётся: считает письма окна.
	put("evc-fresh-consumed", string(holder), `SELECT now() - interval '10 minutes', now() + interval '20 minutes',
		now() - interval '5 minutes', NULL::timestamptz`)
	// Живая, неистёкшая, старше окна — остаётся: её ещё предъявят.
	put("evc-old-live", string(holder), `SELECT now() - interval '2 hours', now() + interval '1 hour',
		NULL::timestamptz, NULL::timestamptz`)
	// Истекла старше окна без применения и вытеснения — снимается.
	put("evc-old-expired", string(second), `SELECT now() - interval '3 hours', now() - interval '150 minutes',
		NULL::timestamptz, NULL::timestamptz`)

	removed, more, err := repo.SweepUnservableVerificationCodes(ctx, letterWindow, 100)
	require.NoError(t, err)
	require.False(t, more, "пачка не исчерпана — уборке нечего добирать")

	var left []string
	rows, err := pool.Query(ctx, `SELECT id FROM kaname.email_verification_codes ORDER BY id`)
	require.NoError(t, err)
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		left = append(left, id)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.Equal(t, []string{"evc-fresh-consumed", "evc-old-live"}, left,
		"уборка сняла не то: окончившаяся строка моложе окна писем и живая неистёкшая строка обязаны остаться")
	require.EqualValues(t, 2, removed, "сняты ровно окончившиеся строки старше окна писем")
}

func TestMailWindowRowNamesItsKindWithoutADefault(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	// Писатель без вида — отказ схемы по колонке вида, а не строка окна
	// приглашений.
	_, err = pool.Exec(ctx, `
		INSERT INTO kaname.invite_mail_windows (recipient, window_started_at, sent, updated_at)
		VALUES ('kind-omitted@example.invalid', now(), 1, now())`)
	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr),
		"строка окна писем без вида легла молча — умолчание колонки списывает письмо в окно приглашений (err=%v)", err)
	require.Equal(t, "23502", pgErr.Code, "отказ не тот: %s", pgErr.Message)
	require.Equal(t, "kind", pgErr.ColumnName, "отказ не по колонке вида: %s", pgErr.Message)

	// Близнец — один факт: вид назван, строка ложится.
	_, err = pool.Exec(ctx, `
		INSERT INTO kaname.invite_mail_windows (kind, recipient, window_started_at, sent, updated_at)
		VALUES ('invite', 'kind-named@example.invalid', now(), 1, now())`)
	require.NoError(t, err, "строка окна с названным видом обязана лечь")
}
