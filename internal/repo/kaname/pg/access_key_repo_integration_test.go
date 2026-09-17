// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_key_repo_integration_test.go — адаптер хранилища ключей доступа и
// испытаний (iam Ф7, `kacho#1273`), против настоящего Postgres.
//
// # Что утверждают пробы этого файла
//
//   - Ф7-15: под конкуренцией один и тот же идентификатор удостоверения
//     заводится ровно один раз — исход производит ключ уникальности, а не
//     сравнение прочитанного; разные идентификаторы проходят все;
//   - Ф7-20: атомарный сдвиг счётчика — из двух одновременных утверждений с
//     `c₁ < c₂` сохранённое равно `c₂` при любом порядке, проигравший получает
//     ноль строк без сигнала; ветвь а — проходят оба, ветвь б — одно;
//   - Ф7-37: слот потолка списывает оператор базы в той же транзакции; на
//     последний слот из двух одновременных заведений проходит ровно одно;
//     снятие возвращает слот; потолок другого человека не расходуется;
//   - Ф7-38: величина нулём — всякое заведение отвергается отказом, называющим
//     величину; уже принятые не удаляются;
//   - §4.1 п. 11: событие аудита лежит в ТОЙ ЖЕ транзакции, что строка —
//     откат вставки уносит событие;
//   - Ф7-03/Ф7-53: испытание потребляется одним условным оператором — из двух
//     одновременных предъявлений проходит одно;
//   - Ф7-31: столбца аттестации в таблице нет (попытка положить — 42703), а
//     открытый ключ есть (живой близнец);
//   - словарь алгоритмов схемы совпадает со словарём проверяющего;
//   - Ф7-27: снятие суженное владельцем — чужой и отсутствующий дают одно
//     «нет строки».
package pg_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
)

// Адаптер обязан исполнять порты use-case.
var (
	_ access_keys.Store        = (*pg.AccessKeyRepo)(nil)
	_ access_keys.Freshness    = (*pg.HumanSessionFreshness)(nil)
	_ access_keys.LoginMethods = (*pg.LoginMethodRepo)(nil)
)

func akPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	pool, err := pgxpool.New(context.Background(), pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return pool
}

func akCeiling(t *testing.T, pool *pgxpool.Pool, limit int64) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO own_ceilings (kind, limit_value) VALUES ('iam.user.accessKey', $1)
		ON CONFLICT (kind) DO UPDATE SET limit_value = EXCLUDED.limit_value`, limit)
	require.NoError(t, err)
}

func akKey(user domain.UserID, cred string) domain.AccessKey {
	return domain.AccessKey{
		ID: domain.AccessKeyID(ids.NewHyphenID(ids.PrefixAccessKeyHyphen)), UserID: user,
		CredentialID: []byte(fmt.Sprintf("%-32s", cred)), PublicKey: []byte{0xa5, 0x01, 0x02},
		Algorithm: -7, UserHandle: []byte(user), Name: "", Description: "проба",
		CreatedAt: time.Now().UTC(),
	}
}

func akInsert(t *testing.T, repo *pg.AccessKeyRepo, k domain.AccessKey) domain.AccessKey {
	t.Helper()
	ctx := context.Background()
	if k.Name == "" {
		k.Name = domain.AccessKeyName(k.ID)
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	got, err := w.InsertKey(ctx, k)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return got
}

func akCount(t *testing.T, pool *pgxpool.Pool, user domain.UserID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM user_access_keys WHERE user_id = $1`, string(user)).Scan(&n))
	return n
}

func TestAccessKeyRepo_F7_15_CredentialIDUniquenessUnderConcurrency(t *testing.T) {
	pool := akPool(t)
	akCeiling(t, pool, 10)
	repo := pg.NewAccessKeyRepo(pool)
	people := lmPeople(t, pool, "ak15", 1)
	ctx := context.Background()

	const writers = 6
	var wg sync.WaitGroup
	outcomes := make(chan error, writers)
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			w, err := repo.Writer(ctx)
			if err != nil {
				outcomes <- err
				return
			}
			defer func() { _ = w.Rollback(ctx) }()
			k := akKey(people[0], "same-credential-id")
			k.Name = domain.AccessKeyName(k.ID)
			if _, err := w.InsertKey(ctx, k); err != nil {
				outcomes <- err
				return
			}
			outcomes <- w.Commit(ctx)
		}()
	}
	close(start)
	wg.Wait()
	close(outcomes)
	ok, dup := 0, 0
	for err := range outcomes {
		switch {
		case err == nil:
			ok++
		case iamerrIs(err, iamerr.ErrAlreadyExists):
			dup++
		default:
			t.Fatalf("неожиданный исход: %v", err)
		}
	}
	require.Equal(t, 1, ok, "ровно одна вставка одного идентификатора")
	require.Equal(t, writers-1, dup)
	require.Equal(t, 1, akCount(t, pool, people[0]))

	// Положительный контроль: разные идентификаторы одновременно — проходят все.
	var wg2 sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg2.Add(1)
		go func(i int) {
			defer wg2.Done()
			w, err := repo.Writer(ctx)
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = w.Rollback(ctx) }()
			k := akKey(people[0], fmt.Sprintf("distinct-%d", i))
			k.Name = domain.AccessKeyName(k.ID)
			if _, err := w.InsertKey(ctx, k); err != nil {
				errs <- err
				return
			}
			errs <- w.Commit(ctx)
		}(i)
	}
	wg2.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.Equal(t, 5, akCount(t, pool, people[0]))
}

func iamerrIs(err, target error) bool {
	for e := err; e != nil; {
		if e == target {
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

func TestAccessKeyRepo_F7_20_SignCountAdvancesAtomically(t *testing.T) {
	pool := akPool(t)
	akCeiling(t, pool, 10)
	repo := pg.NewAccessKeyRepo(pool)
	people := lmPeople(t, pool, "ak20", 1)
	ctx := context.Background()
	k := akKey(people[0], "counter")
	k.SignCount = 10
	k = akInsert(t, repo, k)
	now := time.Now().UTC()

	advance := func(reported uint32) (bool, error) {
		w, err := repo.Writer(ctx)
		if err != nil {
			return false, err
		}
		defer func() { _ = w.Rollback(ctx) }()
		ok, err := w.AdvanceSignCount(ctx, k.ID, 10, reported, now)
		if err != nil || !ok {
			return ok, err
		}
		return true, w.Commit(ctx)
	}
	// Ветвь б: `c₂` фиксируется первым — `c₁` проигрывает нулём строк.
	ok, err := advance(12)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = advance(11)
	require.NoError(t, err)
	require.False(t, ok, "проигравший конкуренции — ноль строк, не исключение")
	var stored int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT sign_count FROM user_access_keys WHERE id = $1`, string(k.ID)).Scan(&stored))
	require.Equal(t, int64(12), stored, "сохранённое не убывает и равно наибольшему из прошедших")

	// Ветвь а: `c₁` первым, затем `c₂` — проходят оба.
	k2 := akKey(people[0], "counter-2")
	k2.SignCount = 10
	k2 = akInsert(t, repo, k2)
	step := func(expected, reported uint32) bool {
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		defer func() { _ = w.Rollback(ctx) }()
		ok, err := w.AdvanceSignCount(ctx, k2.ID, expected, reported, now)
		require.NoError(t, err)
		if ok {
			require.NoError(t, w.Commit(ctx))
		}
		return ok
	}
	require.True(t, step(10, 11))
	require.True(t, step(11, 12))
	require.NoError(t, pool.QueryRow(ctx, `SELECT sign_count FROM user_access_keys WHERE id = $1`, string(k2.ID)).Scan(&stored))
	require.Equal(t, int64(12), stored)

	// Одновременно: два утверждения с одним ожидаемым значением — проходит ровно одно.
	k3 := akInsert(t, repo, func() domain.AccessKey { x := akKey(people[0], "counter-3"); x.SignCount = 5; return x }())
	var wg sync.WaitGroup
	wins := make(chan bool, 2)
	for _, reported := range []uint32{6, 7} {
		wg.Add(1)
		go func(r uint32) {
			defer wg.Done()
			w, err := repo.Writer(ctx)
			require.NoError(t, err)
			defer func() { _ = w.Rollback(ctx) }()
			ok, err := w.AdvanceSignCount(ctx, k3.ID, 5, r, now)
			require.NoError(t, err)
			if ok {
				require.NoError(t, w.Commit(ctx))
			}
			wins <- ok
		}(reported)
	}
	wg.Wait()
	close(wins)
	won := 0
	for ok := range wins {
		if ok {
			won++
		}
	}
	require.Equal(t, 1, won, "из двух одновременных сдвигов с одним ожидаемым проходит ровно один")

	// Ноль при нуле — сдвигается только момент.
	z := akInsert(t, repo, akKey(people[0], "zero"))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	ok, err = w.AdvanceSignCount(ctx, z.ID, 0, 0, now)
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, w.Commit(ctx))
	var used *time.Time
	require.NoError(t, pool.QueryRow(ctx, `SELECT sign_count, last_used_at FROM user_access_keys WHERE id = $1`, string(z.ID)).Scan(&stored, &used))
	require.Equal(t, int64(0), stored)
	require.NotNil(t, used)
}

func TestAccessKeyRepo_F7_37_F7_38_CeilingIsChargedByTheDatabase(t *testing.T) {
	pool := akPool(t)
	akCeiling(t, pool, 2)
	repo := pg.NewAccessKeyRepo(pool)
	people := lmPeople(t, pool, "ak37", 2)
	ctx := context.Background()
	akInsert(t, repo, akKey(people[0], "first"))

	// Два одновременных заведения на последний слот — проходит ровно одно.
	var wg sync.WaitGroup
	outcomes := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w, err := repo.Writer(ctx)
			if err != nil {
				outcomes <- err
				return
			}
			defer func() { _ = w.Rollback(ctx) }()
			k := akKey(people[0], fmt.Sprintf("last-slot-%d", i))
			k.Name = domain.AccessKeyName(k.ID)
			if _, err := w.InsertKey(ctx, k); err != nil {
				outcomes <- err
				return
			}
			outcomes <- w.Commit(ctx)
		}(i)
	}
	wg.Wait()
	close(outcomes)
	ok, full := 0, 0
	for err := range outcomes {
		switch {
		case err == nil:
			ok++
		case iamerrIs(err, iamerr.ErrQuotaExceeded):
			full++
			require.Contains(t, err.Error(), "limit of 2", "отказ называет действующую величину")
		default:
			t.Fatalf("неожиданный исход: %v", err)
		}
	}
	require.Equal(t, 1, ok)
	require.Equal(t, 1, full)
	require.Equal(t, 2, akCount(t, pool, people[0]))

	// Потолок другого человека не расходуется.
	akInsert(t, repo, akKey(people[1], "other-person"))

	// Снятие возвращает слот.
	keys, _, err := repo.KeysOf(ctx, people[0], "", 10)
	require.NoError(t, err)
	require.Len(t, keys, 2)
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	removed, found, err := w.DeleteOwnedByID(ctx, people[0], keys[0].ID)
	require.NoError(t, err)
	require.True(t, found, "свой ключ %s из перечня %v снимается", keys[0].ID, keys)
	require.Equal(t, keys[0].ID, removed.ID)
	require.NoError(t, w.Commit(ctx))
	akInsert(t, repo, akKey(people[0], "after-revoke"))
	require.Equal(t, 2, akCount(t, pool, people[0]))

	// Ноль — ключей не заводить, принятые остаются.
	akCeiling(t, pool, 0)
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w2.Rollback(ctx) }()
	k0 := akKey(people[1], "under-zero")
	k0.Name = domain.AccessKeyName(k0.ID)
	_, err = w2.InsertKey(ctx, k0)
	require.Error(t, err)
	require.True(t, iamerrIs(err, iamerr.ErrQuotaExceeded), "%v", err)
	require.Contains(t, err.Error(), "limit of 0")
	_ = w2.Rollback(ctx)
	require.Equal(t, 1, akCount(t, pool, people[1]))
}

func TestAccessKeyRepo_AuditEventLivesInTheSameTransaction(t *testing.T) {
	pool := akPool(t)
	akCeiling(t, pool, 10)
	repo := pg.NewAccessKeyRepo(pool)
	people := lmPeople(t, pool, "akau", 1)
	ctx := context.Background()
	countEvents := func() int {
		var n int
		require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM audit_outbox WHERE event_type = $1`, access_keys.AuditAccessKeyRegistered).Scan(&n))
		return n
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	k := akKey(people[0], "rolled-back")
	k.Name = domain.AccessKeyName(k.ID)
	_, err = w.InsertKey(ctx, k)
	require.NoError(t, err)
	require.NoError(t, w.EmitAudit(ctx, outboxtypes.AuditEvent{EventType: access_keys.AuditAccessKeyRegistered, Payload: map[string]any{"access_key_id": string(k.ID)}}))
	require.NoError(t, w.Rollback(ctx))
	require.Equal(t, 0, countEvents(), "откат вставки унёс событие")
	require.Equal(t, 0, akCount(t, pool, people[0]))

	w, err = repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.InsertKey(ctx, k)
	require.NoError(t, err)
	require.NoError(t, w.EmitAudit(ctx, outboxtypes.AuditEvent{EventType: access_keys.AuditAccessKeyRegistered, Payload: map[string]any{"access_key_id": string(k.ID)}}))
	require.NoError(t, w.Commit(ctx))
	require.Equal(t, 1, countEvents())
}

func TestAccessKeyRepo_F7_03_ChallengeIsConsumedOnce(t *testing.T) {
	pool := akPool(t)
	repo := pg.NewAccessKeyRepo(pool)
	people := lmPeople(t, pool, "ak03", 2)
	ctx := context.Background()
	now := time.Now().UTC()
	ch := domain.AccessKeyChallenge{Challenge: []byte(fmt.Sprintf("%-32s", "one-shot")), UserID: people[0],
		Purpose: domain.ChallengeForRegistration, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.InsertChallenge(ctx, ch))
	require.NoError(t, w.Commit(ctx))

	got, found, err := repo.Challenge(ctx, ch.Challenge, people[0], domain.ChallengeForRegistration)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, domain.ChallengeIssued, got.StateAt(now))
	_, found, err = repo.Challenge(ctx, ch.Challenge, people[1], domain.ChallengeForRegistration)
	require.NoError(t, err)
	require.False(t, found, "чужое испытание не находится (Ф7-55)")
	_, found, err = repo.Challenge(ctx, ch.Challenge, people[0], domain.ChallengeForAssertion)
	require.NoError(t, err)
	require.False(t, found, "испытание регистрации утверждением не предъявить")

	var wg sync.WaitGroup
	wins := make(chan bool, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, err := repo.Writer(ctx)
			require.NoError(t, err)
			defer func() { _ = w.Rollback(ctx) }()
			ok, err := w.ConsumeChallenge(ctx, ch.Challenge, people[0], domain.ChallengeForRegistration, now)
			require.NoError(t, err)
			if ok {
				require.NoError(t, w.Commit(ctx))
			}
			wins <- ok
		}()
	}
	wg.Wait()
	close(wins)
	won := 0
	for ok := range wins {
		if ok {
			won++
		}
	}
	require.Equal(t, 1, won, "из трёх одновременных предъявлений проходит одно")
	got, _, _ = repo.Challenge(ctx, ch.Challenge, people[0], domain.ChallengeForRegistration)
	require.Equal(t, domain.ChallengeConsumed, got.StateAt(now))

	// Просроченное не потребляется.
	old := domain.AccessKeyChallenge{Challenge: []byte(fmt.Sprintf("%-32s", "expired")), UserID: people[0],
		Purpose: domain.ChallengeForAssertion, IssuedAt: now.Add(-10 * time.Minute), ExpiresAt: now.Add(-5 * time.Minute)}
	w, err = repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.InsertChallenge(ctx, old))
	ok, err := w.ConsumeChallenge(ctx, old.Challenge, people[0], domain.ChallengeForAssertion, now)
	require.NoError(t, err)
	require.False(t, ok)
	require.NoError(t, w.Commit(ctx))

	// Уборка: истёкшие и предъявленные старше порога снимаются, живые — нет.
	n, _, err := repo.SweepUnservableChallenges(ctx, time.Minute, 100)
	require.NoError(t, err)
	require.Equal(t, int64(1), n, "снято просроченное старше порога; только что предъявленное ещё хранится")
}

func TestAccessKeyRepo_F7_31_AttestationHasNoColumn(t *testing.T) {
	pool := akPool(t)
	ctx := context.Background()
	_, err := pool.Exec(ctx, `UPDATE user_access_keys SET attestation = $1`, []byte{1})
	require.Error(t, err, "столбца аттестации нет — 42703")
	require.Contains(t, err.Error(), "42703")
	var live int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema='kaname' AND table_name='user_access_keys' AND column_name='public_key'`).Scan(&live))
	require.Equal(t, 1, live, "живой близнец: столбец открытого ключа есть")
}

func TestAccessKeyRepo_AlgorithmDictionaryAgreesWithTheVerifier(t *testing.T) {
	pool := akPool(t)
	ctx := context.Background()
	var def string
	require.NoError(t, pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'user_access_keys_algorithm_check'`).Scan(&def))
	for _, a := range webauthnverify.KnownAlgorithms() {
		require.Contains(t, def, fmt.Sprintf("'%d'", int64(a)), "словарь схемы не знает %d", a)
	}
	require.Equal(t, 3, len(webauthnverify.KnownAlgorithms()))
	require.Equal(t, 3, countOccurrences(def, "::bigint"), "в словаре схемы ровно три алгоритма")
}

func countOccurrences(s, sub string) int {
	n := 0
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			n++
		}
	}
	return n
}

func TestAccessKeyRepo_F7_27_DeleteIsNarrowedByOwner(t *testing.T) {
	pool := akPool(t)
	akCeiling(t, pool, 10)
	repo := pg.NewAccessKeyRepo(pool)
	people := lmPeople(t, pool, "ak27", 2)
	ctx := context.Background()
	bobs := akInsert(t, repo, akKey(people[1], "bobs"))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, found, err := w.DeleteOwnedByID(ctx, people[0], bobs.ID)
	require.NoError(t, err)
	require.False(t, found, "чужой — «нет строки»")
	_, found, err = w.DeleteOwnedByID(ctx, people[0], domain.AccessKeyID("ak-0000000000000000z"))
	require.NoError(t, err)
	require.False(t, found, "несуществующий — то же «нет строки»")
	require.NoError(t, w.Rollback(ctx))
	require.Equal(t, 1, akCount(t, pool, people[1]))
	locked, err := func() ([]domain.AccessKey, error) {
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		defer func() { _ = w.Rollback(ctx) }()
		return w.LockKeysOf(ctx, people[1])
	}()
	require.NoError(t, err)
	require.Len(t, locked, 1)
}

func TestAccessKeyRepo_FreshnessReadsTheLatestLiveSession(t *testing.T) {
	pool := akPool(t)
	people := lmPeople(t, pool, "akfr", 1)
	ctx := context.Background()
	fresh := pg.NewHumanSessionFreshness(pool)
	_, found, err := fresh.LastPresentedAt(ctx, people[0])
	require.NoError(t, err)
	require.False(t, found, "сессий нет — предъявления не было")
	now := time.Now().UTC().Truncate(time.Microsecond)
	insert := func(id, digest string, presented time.Time, ended *time.Time, expires time.Time) {
		var reason *string
		if ended != nil {
			r := "logout"
			reason = &r
		}
		_, err := pool.Exec(ctx, `
			INSERT INTO human_sessions (id, user_id, bearer_digest, authenticated_at, last_presented_at, expires_at, assurance_level, presented_methods, ended_at, ended_reason)
			VALUES ($1, $2, $3, $4, $5, $6, '1', ARRAY['password'], $7, $8)`,
			id, string(people[0]), digest, presented.Add(-time.Hour), presented, expires, ended, reason)
		require.NoError(t, err)
	}
	old := now.Add(-2 * time.Hour)
	insert("hss-00000000000000001", fmt.Sprintf("%064d", 1), now.Add(-time.Minute), &old, now.Add(time.Hour))
	insert("hss-00000000000000002", fmt.Sprintf("%064d", 2), now.Add(-30*time.Minute), nil, now.Add(time.Hour))
	insert("hss-00000000000000003", fmt.Sprintf("%064d", 3), now.Add(-5*time.Minute), nil, now.Add(-time.Minute))
	at, found, err := fresh.LastPresentedAt(ctx, people[0])
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, now.Add(-30*time.Minute), at, "снятая и истёкшая сессии не считаются; берётся самая свежая живая")
}

func TestAccessKeyRepo_KeysOfPagesInCreationOrder(t *testing.T) {
	pool := akPool(t)
	akCeiling(t, pool, 10)
	repo := pg.NewAccessKeyRepo(pool)
	people := lmPeople(t, pool, "akpg", 1)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		k := akKey(people[0], fmt.Sprintf("page-%d", i))
		k.CreatedAt = time.Now().UTC().Add(time.Duration(i) * time.Second)
		akInsert(t, repo, k)
	}
	first, next, err := repo.KeysOf(ctx, people[0], "", 2)
	require.NoError(t, err)
	require.Len(t, first, 2)
	require.NotEmpty(t, next)
	rest, next2, err := repo.KeysOf(ctx, people[0], next, 2)
	require.NoError(t, err)
	require.Len(t, rest, 1)
	require.Empty(t, next2)
	require.True(t, first[0].CreatedAt.Before(first[1].CreatedAt))
	_, _, err = repo.KeysOf(ctx, people[0], "garbage", 2)
	require.Error(t, err, "мусорный курсор — отказ формы")
	creds, err := repo.CredentialIDsOf(ctx, people[0])
	require.NoError(t, err)
	require.Len(t, creds, 3)
	got, found, err := repo.KeyByCredentialID(ctx, creds[0])
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, people[0], got.UserID)
	require.Equal(t, "проба", string(got.Description))
}

// TestAccessKeyRepo_KeyOwnedByIDIsNarrowedByOwner — чтение по паре (человек,
// ключ) для резолвера осиротевших операций: свой ключ читается той же
// проекцией, что перечень; чужой и несуществующий — «нет строки», одинаково
// (побайтовая неразличимость, Ф7-27).
func TestAccessKeyRepo_KeyOwnedByIDIsNarrowedByOwner(t *testing.T) {
	pool := akPool(t)
	akCeiling(t, pool, 10)
	repo := pg.NewAccessKeyRepo(pool)
	people := lmPeople(t, pool, "akid", 2)
	ctx := context.Background()
	mine := akInsert(t, repo, akKey(people[0], "mine"))

	got, found, err := repo.KeyOwnedByID(ctx, people[0], mine.ID)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, mine.ID, got.ID)
	require.Equal(t, people[0], got.UserID)
	require.Equal(t, mine.Name, got.Name)
	require.Equal(t, mine.CredentialID, got.CredentialID)

	_, found, err = repo.KeyOwnedByID(ctx, people[1], mine.ID)
	require.NoError(t, err)
	require.False(t, found, "чужой — «нет строки»")
	_, found, err = repo.KeyOwnedByID(ctx, people[0], domain.AccessKeyID("ak-0000000000000000z"))
	require.NoError(t, err)
	require.False(t, found, "несуществующий — то же «нет строки»")
}
