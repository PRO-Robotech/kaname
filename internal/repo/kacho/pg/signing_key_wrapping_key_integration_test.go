// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// signing_key_wrapping_key_integration_test.go — стенд, поднятый ПОВЕРХ
// существующей базы (задача #1062), против настоящего Postgres.
//
// Пробы уровня ключницы утверждают о её решении. Эта утверждает о том, ради
// чего решение принято: что второй подъём над ТОЙ ЖЕ базой разворачивает
// ПРЕЖНИЕ подписные ключи — и доказывается это ПОДПИСЬЮ ТОКЕНА, а не тем, что
// вызов вернул nil. «Ключница построилась» и «подписать по-прежнему есть чем» —
// разные утверждения, и до этой пробы верным считалось первое.
package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/signingkeys"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/keywrap"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho-iam/internal/tokensigner"
)

const wrapProbeIssuer = "https://iam.kacho.local"

// bootIAM собирает ключницу и подписанта заново — как это делает композиционный
// корень на КАЖДОМ подъёме службы. Общего состояния между подъёмами нет: всё,
// что переживает подъём, лежит в базе и в ключе обёртки.
func bootIAM(t *testing.T, ctx context.Context, dsn string, wrapKey byte, clock func() time.Time,
) (*signingkeys.Keystore, *tokensigner.Signer, error) {
	t.Helper()
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	wrapper, err := keywrap.New(bytesRepeat(wrapKey, keywrap.KeySize))
	require.NoError(t, err)
	repo := kachopg.NewSigningKeyRepo(pool)
	ks, err := signingkeys.New(signingkeys.Config{
		Algorithm:    domain.SigningAlgES256,
		KeyLifetime:  90 * 24 * time.Hour,
		RemovalGrace: tokenpolicy.KeyRemovalGrace,
		Clock:        clock,
	}, repo, repo, wrapper)
	require.NoError(t, err)

	if err := ks.EnsureSigningKey(ctx); err != nil {
		return nil, nil, err
	}
	signer, err := tokensigner.New(tokensigner.Config{
		Issuer: wrapProbeIssuer, Clock: clock, MaxTokenTTL: tokenpolicy.MaxTokenTTL,
	}, ks)
	require.NoError(t, err)
	return ks, signer, nil
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// TestSigningKeyContour_StandRaisedOverAnExistingDatabase — три подъёма над
// ОДНОЙ базой: тот же ключ обёртки переиспользует записанное, другой — даёт
// названный отказ старта и не заводит ничего.
func TestSigningKeyContour_StandRaisedOverAnExistingDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	at := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return at }

	// Счётчик строк смотрит в базу МИМО ключницы — иначе он утверждал бы о том
	// же, о чём и она. Пул у него СВОЙ и один на пробу: закрытие идёт через
	// pgtest.ClosePoolAtEnd, потому что `defer pool.Close()` ждёт возврата всех
	// выданных соединений и на упавшей пробе вешает весь пакет, а не её одну.
	countPool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, countPool)
	countKeys := func() int {
		var n int
		require.NoError(t, countPool.QueryRow(ctx, `SELECT count(*) FROM kacho_iam.token_signing_keys`).Scan(&n))
		return n
	}

	// ── Подъём 1: пустая база. Ключ порождается, токен подписывается.
	_, signer1, err := bootIAM(t, ctx, dsn, 7, clock)
	require.NoError(t, err)
	first, err := signer1.Sign(ctx, tokensigner.Request{
		Subject: "sva-wrapprobe", Audience: []string{"registry.kacho.local"},
		TokenType: "at+jwt", TTL: 5 * time.Minute,
	})
	require.NoError(t, err)
	require.Equal(t, 1, countKeys())

	// ── Подъём 2: ТА ЖЕ база, ТОТ ЖЕ ключ обёртки (штатное пересоздание стенда
	//    после починки посева).
	ks2, signer2, err := bootIAM(t, ctx, dsn, 7, clock)
	require.NoError(t, err, "подъём над существующей базой обязан пройти")

	// Then — ПОДПИСЬЮ, а не построением: токен выпущен ТЕМ ЖЕ ключом.
	second, err := signer2.Sign(ctx, tokensigner.Request{
		Subject: "sva-wrapprobe", Audience: []string{"registry.kacho.local"},
		TokenType: "at+jwt", TTL: 5 * time.Minute,
	})
	require.NoError(t, err, "прежняя приватная половина обязана развернуться")
	require.Equal(t, first.KID, second.KID, "второй подъём завёл НОВЫЙ ключ вместо прежнего")
	require.Equal(t, 1, countKeys(), "второй подъём добавил строку в ключницу")

	// And — токен ПЕРВОГО подъёма по-прежнему проверяется ключом из набора:
	// «подписать есть чем» и «ранее выданное всё ещё действительно» — разные
	// утверждения, и предмет задачи — второе.
	set, err := ks2.PublishedSet(ctx)
	require.NoError(t, err)
	require.Len(t, set, 1)
	require.Equal(t, first.KID, set[0].KID)

	verify := func(token string) error {
		mat, merr := ks2.ActiveSigningKey(ctx)
		require.NoError(t, merr)
		pub, perr := jwt.ParseECPublicKeyFromPEM([]byte(mat.PublicKeyPEM))
		require.NoError(t, perr)
		_, verr := jwt.NewParser(
			jwt.WithValidMethods(tokenpolicy.Algorithms()),
			jwt.WithExpirationRequired(),
			jwt.WithIssuer(wrapProbeIssuer),
			jwt.WithAudience("registry.kacho.local"),
			jwt.WithTimeFunc(clock),
		).Parse(token, func(*jwt.Token) (any, error) { return pub, nil })
		return verr
	}
	require.NoError(t, verify(first.Token), "токен первого подъёма перестал проверяться")
	require.NoError(t, verify(second.Token))

	// ── Подъём 3: ТА ЖЕ база, ДРУГОЙ ключ обёртки — то, что делал посев на
	//    каждом прогоне. Служба обязана ОТКАЗАТЬСЯ стартовать.
	_, _, err = bootIAM(t, ctx, dsn, 9, clock)
	require.Error(t, err, "смена ключа обёртки над непустой ключницей обязана быть отказом старта")
	require.ErrorIs(t, err, signingkeys.ErrWrappingKeyMismatch)
	require.Contains(t, err.Error(), string(first.KID), "отказ обязан назвать ключ")

	// And — ни одной новой строки: отказ ПОСЛЕ порождения был бы той же
	// потерей, только с сообщением.
	require.Equal(t, 1, countKeys(), "поверх нечитаемого ключа заведён новый")

	// And — прежний ключ по-прежнему цел: отказ ничего не испортил, и вернув
	// прежний ключ обёртки, стенд поднимается снова.
	_, signer4, err := bootIAM(t, ctx, dsn, 7, clock)
	require.NoError(t, err, "возврат прежнего ключа обёртки обязан снимать отказ")
	fourth, err := signer4.Sign(ctx, tokensigner.Request{
		Subject: "sva-wrapprobe", Audience: []string{"registry.kacho.local"},
		TokenType: "at+jwt", TTL: 5 * time.Minute,
	})
	require.NoError(t, err)
	require.Equal(t, first.KID, fourth.KID)
	require.Equal(t, 1, countKeys())
}
