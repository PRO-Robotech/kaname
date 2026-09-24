// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// signing_key_lifecycle_integration_test.go — передача подписи УСЛОВНА на
// ожидаемого подписывающего, и ротация по сроку под конкуренцией реплик даёт
// ровно одного нового подписывающего без брошенных ключей (#314).
//
// Судится на настоящей базе, а не на дублёре: условность держит сама СУБД —
// условный оператор понижения и частичный уникальный индекс, — и дублёр мог бы
// её лишь изображать.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/signingkeys"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/keywrap"
)

// TestSigningKey_ReplaceActiveHandsOverOnlyFromTheExpectedSigner — передача
// подписи, ожидающая НЕ того подписывающего, отвергается и ничего не меняет;
// ожидающая того — меняет обоих одним переходом.
func TestSigningKey_ReplaceActiveHandsOverOnlyFromTheExpectedSigner(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, repo := signingKeyPool(t)
	cur := seedKey(t, repo, "kaname-rpl-cur", domain.SigningKeyActive)
	next := seedKey(t, repo, "kaname-rpl-next", domain.SigningKeyPublished)
	stale := seedKey(t, repo, "kaname-rpl-stale", domain.SigningKeyPublished)

	// Отрицание: ожидается не тот, кто подписывает.
	err := repo.ReplaceActive(ctx, next.KID, stale.KID, time.Now().UTC())
	require.ErrorIs(t, err, iamerr.ErrFailedPrecondition)
	active, err := repo.Active(ctx)
	require.NoError(t, err)
	require.Equal(t, cur.KID, active.KID, "отвергнутая передача не трогает подписывающего")
	got, err := repo.Get(ctx, next.KID)
	require.NoError(t, err)
	require.Equal(t, domain.SigningKeyPublished, got.State)

	// Законный близнец: ожидается тот — подпись переходит, прежний выведен.
	require.NoError(t, repo.ReplaceActive(ctx, next.KID, cur.KID, time.Now().UTC()))
	active, err = repo.Active(ctx)
	require.NoError(t, err)
	require.Equal(t, next.KID, active.KID)
	got, err = repo.Get(ctx, cur.KID)
	require.NoError(t, err)
	require.Equal(t, domain.SigningKeyRetired, got.State)
	require.NotNil(t, got.RetiredAt)
	require.Equal(t, 1, countActive(t, pool))
}

// TestSigningKey_RetireWithoutASuccessorIsNotExpressibleForTheSigner — вывод
// подписывающего без преемника не выражается переходом хранилища: подписывающий
// покидает подпись только передачей (ReplaceActive) или объявлением утечки.
// Иначе чтение «ключ опубликован» и запись «вывести» разделяло бы окно, в
// которое ключ успевает вступить в подпись, — и вывод оставлял бы службу без
// подписи.
func TestSigningKey_RetireWithoutASuccessorIsNotExpressibleForTheSigner(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, repo := signingKeyPool(t)
	signer := seedKey(t, repo, "kaname-ret-signer", domain.SigningKeyActive)
	spare := seedKey(t, repo, "kaname-ret-spare", domain.SigningKeyPublished)

	err := repo.Retire(ctx, signer.KID, time.Now().UTC())
	require.ErrorIs(t, err, iamerr.ErrFailedPrecondition)
	require.Equal(t, 1, countActive(t, pool), "вывод подписывающего без преемника не выражается")

	// Законный близнец: опубликованный, не подписывающий ключ выводится.
	require.NoError(t, repo.Retire(ctx, spare.KID, time.Now().UTC()))
	got, err := repo.Get(ctx, spare.KID)
	require.NoError(t, err)
	require.Equal(t, domain.SigningKeyRetired, got.State)
}

// TestSigningKey_ConcurrentDueRotationsYieldOneSignerAndNoStrandedKey —
// реплики, одновременно увидевшие наступивший срок, дают ОДНОГО нового
// подписывающего, а ключи проигравших не остаются опубликованными навсегда.
func TestSigningKey_ConcurrentDueRotationsYieldOneSignerAndNoStrandedKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, repo := signingKeyPool(t)
	wrapper, err := keywrap.New(make([]byte, keywrap.KeySize))
	require.NoError(t, err)

	const lifetime, lead = 48 * time.Hour, time.Hour
	start := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	newKS := func(at time.Time) *signingkeys.Keystore {
		ks, err := signingkeys.New(signingkeys.Config{
			Algorithm: domain.SigningAlgES256, KeyLifetime: lifetime,
			RemovalGrace: tokenpolicy.KeyRemovalGrace, RotationLead: lead,
			HandoverLimit: time.Minute, StrandedAfter: 2 * time.Minute,
			Clock: func() time.Time { return at },
		}, repo, repo, wrapper)
		require.NoError(t, err)
		return ks
	}
	require.NoError(t, newKS(start).EnsureSigningKey(ctx))
	first, err := repo.Active(ctx)
	require.NoError(t, err)
	due := first.NotAfter.Add(-lead)

	const replicas = 4
	var (
		wg      sync.WaitGroup
		gate    = make(chan struct{})
		rotated = make([]bool, replicas)
		errs    = make([]error, replicas)
	)
	for i := 0; i < replicas; i++ {
		ks := newKS(due)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-gate
			rotated[i], errs[i] = ks.RotateIfDue(ctx)
		}(i)
	}
	close(gate)
	wg.Wait()

	winners := 0
	for i := range errs {
		require.NoError(t, errs[i], "проигранная гонка — не отказ реплики")
		if rotated[i] {
			winners++
		}
	}
	require.Equal(t, 1, winners, "срок наступил один раз — подпись переходит один раз")
	require.Equal(t, 1, countActive(t, pool))
	active, err := repo.Active(ctx)
	require.NoError(t, err)
	require.NotEqual(t, first.KID, active.KID)

	var stranded int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.token_signing_keys WHERE state = 'PUBLISHED'`).Scan(&stranded))
	require.Zero(t, stranded, "порождённый проигравшим ключ не остаётся опубликованным без будущего")
}

// TestSigningKey_RetireOfAnUnknownKeyIsNotFound — вывод неизвестного ключа
// называет отсутствие, а не «переход не допускается»: оператор, ошибившийся в
// идентификаторе, обязан это узнать.
func TestSigningKey_RetireOfAnUnknownKeyIsNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	_, repo := signingKeyPool(t)
	wrapper, err := keywrap.New(make([]byte, keywrap.KeySize))
	require.NoError(t, err)
	ks, err := signingkeys.New(signingkeys.Config{
		Algorithm: domain.SigningAlgES256, KeyLifetime: 48 * time.Hour,
		RemovalGrace: tokenpolicy.KeyRemovalGrace, RotationLead: time.Hour,
		HandoverLimit: time.Minute, StrandedAfter: 2 * time.Minute,
		Clock: time.Now,
	}, repo, repo, wrapper)
	require.NoError(t, err)
	require.NoError(t, ks.EnsureSigningKey(ctx))

	_, err = ks.Retire(ctx, "kaname-no-such-key", "oncall")
	require.True(t, errors.Is(err, iamerr.ErrNotFound), "ожидался NotFound, получено: %v", err)
	_, err = ks.Compromise(ctx, "kaname-no-such-key", "oncall")
	require.True(t, errors.Is(err, iamerr.ErrNotFound), "ожидался NotFound, получено: %v", err)
}
