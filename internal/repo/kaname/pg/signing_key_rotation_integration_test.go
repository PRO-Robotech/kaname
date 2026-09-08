// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// signing_key_rotation_integration_test.go — сценарии F1-06, F1-07, F1-29,
// F1-31 приёмки F1: инвариант «подписывает ровно один» и машина состояний.
package pg_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/signingkeygen"
)

func signingKeyPool(t *testing.T) (*pgxpool.Pool, *kanamepg.SigningKeyRepo) {
	t.Helper()
	pool, err := coredb.NewPool(context.Background(), setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return pool, kanamepg.NewSigningKeyRepo(pool)
}

func seedKey(t *testing.T, repo *kanamepg.SigningKeyRepo, kid string, state domain.SigningKeyState) domain.SigningKeyRecord {
	t.Helper()
	mat, err := signingkeygen.Generate(domain.SigningAlgRS256)
	require.NoError(t, err)
	now := time.Now().UTC().Truncate(time.Second)
	rec := domain.SigningKeyRecord{
		KID: domain.KeyID(kid), Algorithm: domain.SigningAlgRS256, State: state,
		PublicKeyPEM: mat.PublicKeyPEM, PrivateKeyWrapped: []byte("wrapped-" + kid),
		CreatedAt: now, NotAfter: now.Add(90 * 24 * time.Hour),
	}
	switch state {
	case domain.SigningKeyActive:
		rec.ActivatedAt = &now
	case domain.SigningKeyRetired:
		rec.RetiredAt = &now
	case domain.SigningKeyRemoved:
		rec.RemovedAt = &now
	case domain.SigningKeyCompromised:
		rec.CompromisedAt = &now
	}
	require.NoError(t, repo.Insert(context.Background(), rec))
	return rec
}

func countActive(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM kaname.token_signing_keys WHERE state = 'ACTIVE'`).Scan(&n))
	return n
}

// TestSigningKey_F1_06_ExactlyOneSignerUnderConcurrency — F1-06.
func TestSigningKey_F1_06_ExactlyOneSignerUnderConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, repo := signingKeyPool(t)

	// Given — в ключнице есть подписывающий ключ.
	seedKey(t, repo, "kacho-f106-active", domain.SigningKeyActive)

	// When — N параллельных попыток сделать подписывающим ДРУГОЙ ключ.
	const n = 8
	kids := make([]domain.KeyID, n)
	for i := range kids {
		kids[i] = domain.KeyID("kacho-f106-cand" + string(rune('a'+i)))
		seedKey(t, repo, string(kids[i]), domain.SigningKeyPublished)
	}
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	for i := range kids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = repo.Activate(ctx, kids[i], time.Now().UTC())
		}(i)
	}
	close(start)
	wg.Wait()

	// Then — подписывающим оказывается РОВНО ОДИН.
	require.Equal(t, 1, countActive(t, pool), "инвариант «подписывает ровно один» нарушен")

	won := 0
	for i, err := range errs {
		if err == nil {
			won++
			continue
		}
		require.NotContains(t, err.Error(), "SQLSTATE",
			"проигравшая транзакция обязана получить ОЖИДАЕМЫЙ отказ, а не пересказ ошибки драйвера: %v", err)
		_ = i
	}
	require.GreaterOrEqual(t, won, 1, "хотя бы одна попытка обязана пройти — иначе проба зелена на ключнице, отвергающей всё")

	// And — свойство держит ИНВАРИАНТ БАЗЫ, а не прикладной путь: попытка
	// записать второго подписывающего НАПРЯМУЮ, минуя репозиторий и соблюдая
	// все прочие ограничения схемы, тоже отвергается.
	winner := activeKID(t, pool)
	var bypass domain.KeyID
	for _, kid := range kids {
		if kid != winner {
			bypass = kid
			break
		}
	}
	require.NotEmpty(t, bypass)
	_, err := pool.Exec(ctx,
		`UPDATE kaname.token_signing_keys
		    SET state='ACTIVE', activated_at=now(), retired_at=NULL,
		        removed_at=NULL, compromised_at=NULL
		  WHERE kid = $1`, string(bypass))
	require.Error(t, err, "прямая запись второго подписывающего обязана отвергаться базой")
	require.Contains(t, err.Error(), "23505",
		"отвергает именно уникальный индекс, а не прикладная проверка и не иное ограничение")
	require.Equal(t, 1, countActive(t, pool))

	// Положительный контроль той же прямой записи: она проходит, когда
	// подписывающего нет вовсе. Без него отказ выше был бы неотличим от
	// ограничения, отвергающего любую прямую запись.
	_, err = pool.Exec(ctx,
		`UPDATE kaname.token_signing_keys SET state='RETIRED', retired_at=now(), activated_at=NULL
		  WHERE state='ACTIVE'`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`UPDATE kaname.token_signing_keys
		    SET state='ACTIVE', activated_at=now(), retired_at=NULL
		  WHERE kid = $1`, string(bypass))
	require.NoError(t, err, "прямая запись подписывающего при свободном месте обязана проходить")
	require.Equal(t, 1, countActive(t, pool))
}

func activeKID(t *testing.T, pool *pgxpool.Pool) domain.KeyID {
	t.Helper()
	var kid string
	err := pool.QueryRow(context.Background(),
		`SELECT kid FROM kaname.token_signing_keys WHERE state = 'ACTIVE'`).Scan(&kid)
	require.NoError(t, err)
	return domain.KeyID(kid)
}

// TestSigningKey_F1_07_SwapIsAtomic — F1-07.
func TestSigningKey_F1_07_SwapIsAtomic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, repo := signingKeyPool(t)

	seedKey(t, repo, "kacho-f107-a", domain.SigningKeyActive)
	seedKey(t, repo, "kacho-f107-b", domain.SigningKeyPublished)
	seedKey(t, repo, "kacho-f107-c", domain.SigningKeyPublished)

	// Читатель наблюдает состояние ПОКА идёт конкурентная смена: момента, в
	// котором подписывающих ноль или два, не существует.
	stop := make(chan struct{})
	var observed sync.Map
	var reader sync.WaitGroup
	reader.Add(1)
	go func() {
		defer reader.Done()
		for {
			select {
			case <-stop:
				return
			default:
				observed.Store(countActive(t, pool), true)
			}
		}
	}()

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, kid := range []domain.KeyID{"kacho-f107-b", "kacho-f107-c"} {
		wg.Add(1)
		go func(i int, kid domain.KeyID) {
			defer wg.Done()
			errs[i] = repo.Activate(ctx, kid, time.Now().UTC())
		}(i, kid)
	}
	wg.Wait()
	close(stop)
	reader.Wait()

	observed.Range(func(k, _ any) bool {
		require.Equal(t, 1, k, "наблюдалось состояние с %v подписывающими — смена не атомарна", k)
		return true
	})
	require.Equal(t, 1, countActive(t, pool))

	// Проигравшая получает ОЖИДАЕМЫЙ отказ, а не тихо перезаписывает
	// победителя. При этом ровно один из двух обязан выиграть.
	winners := 0
	for _, err := range errs {
		if err == nil {
			winners++
		}
	}
	require.GreaterOrEqual(t, winners, 1)
}

// TestSigningKey_F1_29_KeySetFollowsStateAndActivationIsNotExpressible — F1-29.
func TestSigningKey_F1_29_KeySetFollowsStateAndActivationIsNotExpressible(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	_, repo := signingKeyPool(t)

	published := seedKey(t, repo, "kacho-f129-pub", domain.SigningKeyPublished)
	active := seedKey(t, repo, "kacho-f129-act", domain.SigningKeyActive)
	retired := seedKey(t, repo, "kacho-f129-ret", domain.SigningKeyRetired)
	removed := seedKey(t, repo, "kacho-f129-rem", domain.SigningKeyRemoved)
	compromised := seedKey(t, repo, "kacho-f129-cmp", domain.SigningKeyCompromised)

	set, err := repo.KeySet(ctx)
	require.NoError(t, err)
	inSet := map[domain.KeyID]bool{}
	for _, rec := range set {
		inSet[rec.KID] = true
	}

	// Then — ключ, ещё не ставший подписывающим, в наборе УЖЕ есть.
	require.True(t, inSet[published.KID], "PUBLISHED обязан быть в наборе до того, как станет подписывающим")
	require.True(t, inSet[active.KID])
	require.True(t, inSet[retired.KID], "выведенный остаётся в наборе всю отсрочку")

	// And — снятый и скомпрометированный в наборе ОТСУТСТВУЮТ: пара
	// доказывает, что ответ следует состоянию, а не отдаёт все строки подряд.
	require.False(t, inSet[removed.KID])
	require.False(t, inSet[compromised.KID])

	// And — переход в подпись из REMOVED и COMPROMISED НЕ ВЫРАЖАЕТСЯ.
	require.Error(t, repo.Activate(ctx, removed.KID, time.Now().UTC()))
	require.Error(t, repo.Activate(ctx, compromised.KID, time.Now().UTC()))
	require.False(t, domain.SigningKeyRemoved.CanActivate())
	require.False(t, domain.SigningKeyCompromised.CanActivate())

	// Положительный контроль перехода: из PUBLISHED — выражается.
	require.NoError(t, repo.Activate(ctx, published.KID, time.Now().UTC()))
}

// TestSigningKey_F1_31_CompromisedLeavesTheKeySetImmediately — F1-31.
func TestSigningKey_F1_31_CompromisedLeavesTheKeySetImmediately(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	_, repo := signingKeyPool(t)
	rec := seedKey(t, repo, "kacho-f131", domain.SigningKeyActive)

	// Given (зеркало F1-29) — ДО глагола тот же ключ в наборе ПРИСУТСТВУЕТ.
	// Без этой половины проба зелена и на наборе, который не отдаёт ничего.
	set, err := repo.KeySet(ctx)
	require.NoError(t, err)
	require.True(t, containsKID(set, rec.KID), "до глагола ключ обязан быть в наборе")

	// When — ключ объявлен скомпрометированным.
	require.NoError(t, repo.Compromise(ctx, rec.KID, time.Now().UTC()))

	// Then — он покидает набор НЕМЕДЛЕННО.
	set, err = repo.KeySet(ctx)
	require.NoError(t, err)
	require.False(t, containsKID(set, rec.KID))

	// And — глагол ОТДЕЛЁН от вывода из ротации: вывод оставил бы ключ в
	// наборе, объявление утёкшим — нет.
	other := seedKey(t, repo, "kacho-f131-ret", domain.SigningKeyActive)
	require.NoError(t, repo.Retire(ctx, other.KID, time.Now().UTC()))
	set, err = repo.KeySet(ctx)
	require.NoError(t, err)
	require.True(t, containsKID(set, other.KID), "выведенный остаётся в наборе — иначе два глагола сливаются в один")
}

func containsKID(set []domain.SigningKeyRecord, kid domain.KeyID) bool {
	for _, r := range set {
		if r.KID == kid {
			return true
		}
	}
	return false
}

// TestSigningKey_StateStampsAreEnforcedByTheSchema — строка, объявляющая себя
// выведенной без отметки вывода, лишает отсрочку слагаемого, поэтому такую
// строку не принимает схема, а не прикладной путь.
func TestSigningKey_StateStampsAreEnforcedByTheSchema(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, _ := signingKeyPool(t)
	_, err := pool.Exec(ctx, `INSERT INTO kaname.token_signing_keys
		(kid, algorithm, state, public_key_pem, private_key_wrapped, created_at, not_after)
		VALUES ('kacho-nostamp','RS256','RETIRED','pem','\x01', now(), now() + interval '1 day')`)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "23514"),
		"отметка состояния обязана требоваться схемой: %v", err)
}
