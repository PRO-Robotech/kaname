// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// wrapping_key_rotation_test.go — смена ключа ОБЁРТКИ не теряет ни одного
// подписного ключа (задача #1065).
//
// # Что именно утверждается
//
// Не «ключница приняла список», а наблюдение, которым закрывается задача:
// токен, ВЫДАННЫЙ ДО смены ключа обёртки, после неё по-прежнему проверяется —
// подписью против публикуемого набора, а не подъёмом пода. И записанная
// приватная половина по-прежнему ПОДПИСЫВАЕТ: ключница не заводит новый ключ
// поверх нечитаемых.
//
// # Почему проба не вакуумна
//
// Рядом стоит отрицание: ключница, собранная на списке БЕЗ прежнего ключа, тот
// же материал не читает вовсе. Без него «открылось» означало бы «открывается
// что угодно», и проба зеленела бы на обёртке, не проверяющей подлинность.
package signingkeys_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/signingkeys"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/keywrap"
	"github.com/PRO-Robotech/kacho-iam/internal/tokensigner"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
)

// wrappingKey — ключ обёртки объявленного размера, различимый по байту.
func wrappingKey(b byte) []byte {
	k := make([]byte, keywrap.KeySize)
	for i := range k {
		k[i] = b
	}
	return k
}

// keystoreOver собирает ключницу над УЖЕ СУЩЕСТВУЮЩИМ хранилищем на заданном
// списке ключей обёртки — то есть ровно так, как её собирает композиционный
// корень после смены значения ручки.
func keystoreOver(t *testing.T, store *memStore, at time.Time, wrapKeys ...[]byte) *signingkeys.Keystore {
	t.Helper()
	wrapper, err := keywrap.New(wrapKeys...)
	require.NoError(t, err)
	ks, err := signingkeys.New(signingkeys.Config{
		Algorithm:    domain.SigningAlgRS256,
		KeyLifetime:  90 * 24 * time.Hour,
		RemovalGrace: tokenpolicy.KeyRemovalGrace,
		Clock:        fixedClock(at),
	}, store, store, wrapper)
	require.NoError(t, err)
	return ks
}

// signerOver собирает подписанта над ключницей.
func signerOver(t *testing.T, ks *signingkeys.Keystore, at time.Time) *tokensigner.Signer {
	t.Helper()
	s, err := tokensigner.New(tokensigner.Config{
		Issuer:      "https://iam.kacho.test",
		Clock:       func() time.Time { return at },
		MaxTokenTTL: tokenpolicy.MaxTokenTTL,
	}, ks)
	require.NoError(t, err)
	return s
}

// verifyAgainstPublishedSet проверяет ПОДПИСЬ токена против публикуемого
// набора: находит ключ по `kid` заголовка и сверяет им подпись.
//
// Проверка идёт публичной половиной из набора, а не тем, чем подписывали:
// иначе она утверждала бы о самой себе.
func verifyAgainstPublishedSet(t *testing.T, ks *signingkeys.Keystore, raw string) jwt.MapClaims {
	t.Helper()
	set, err := ks.PublishedSet(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, set, "публикуемый набор пуст — проверять нечем")

	claims := jwt.MapClaims{}
	_, err = jwt.NewParser(jwt.WithoutClaimsValidation()).ParseWithClaims(raw, claims, func(tok *jwt.Token) (any, error) {
		kid, _ := tok.Header["kid"].(string)
		for _, pub := range set {
			if string(pub.KID) == kid {
				return jwt.ParseRSAPublicKeyFromPEM([]byte(pub.PublicKeyPEM))
			}
		}
		return nil, jwt.ErrTokenUnverifiable
	})
	require.NoError(t, err, "подпись токена не проверилась против публикуемого набора")
	return claims
}

func mintRequest() tokensigner.Request {
	return tokensigner.Request{
		Subject:   "usr-01hp0000000000000000000000",
		Audience:  []string{"api.kacho.test"},
		TokenType: "at+jwt",
		TTL:       15 * time.Minute,
	}
}

// TestTokenIssuedBeforeTheWrappingKeyChangeStillVerifiesAfterIt — предикат
// снятия #1065: смена ключа обёртки без потери записанного.
func TestTokenIssuedBeforeTheWrappingKeyChangeStillVerifiesAfterIt(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	previous, current := wrappingKey(1), wrappingKey(2)
	store := newMemStore()

	// ── ДО СМЕНЫ: ключница на прежнем ключе выпускает токен ────────────────
	before := keystoreOver(t, store, at, previous)
	require.NoError(t, before.EnsureSigningKey(ctx))
	wasKID, err := store.Active(ctx)
	require.NoError(t, err)

	issued, err := signerOver(t, before, at).Sign(ctx, mintRequest())
	require.NoError(t, err)
	claimsBefore := verifyAgainstPublishedSet(t, before, issued.Token)
	require.Equal(t, "https://iam.kacho.test", claimsBefore["iss"])

	// ── СМЕНА: новый ключ встаёт ПЕРВЫМ, прежний остаётся для чтения ───────
	after := keystoreOver(t, store, at, current, previous)

	// Служба поднимается: ключница НЕ заводит нового ключа поверх записанного.
	require.NoError(t, after.EnsureSigningKey(ctx))
	stillKID, err := store.Active(ctx)
	require.NoError(t, err)
	require.Equal(t, wasKID.KID, stillKID.KID,
		"после смены ключа обёртки подписывающим стал ДРУГОЙ ключ — прежние токены обесценены")
	require.Len(t, store.rows, 1, "после смены ключа обёртки в ключнице завёлся лишний ключ")

	// ── ПРЕЖДЕ ВЫДАННЫЙ ТОКЕН ПО-ПРЕЖНЕМУ ПРОВЕРЯЕТСЯ ─────────────────────
	claimsAfter := verifyAgainstPublishedSet(t, after, issued.Token)
	require.Equal(t, claimsBefore["jti"], claimsAfter["jti"])

	// …и записанная приватная половина по-прежнему ПОДПИСЫВАЕТ: читаемость
	// доказывается подписью, а не тем, что чтение не вернуло ошибку.
	fresh, err := signerOver(t, after, at).Sign(ctx, mintRequest())
	require.NoError(t, err, "после смены ключа обёртки записанная приватная половина не подписывает")
	require.Equal(t, wasKID.KID, fresh.KID)
	verifyAgainstPublishedSet(t, after, fresh.Token)

	// ── ОТРИЦАНИЕ: без прежнего ключа в списке материал НЕ читается ────────
	// Без него всё выше зелено на обёртке, открывающей что угодно.
	withoutPrevious := keystoreOver(t, store, at, current)
	_, err = withoutPrevious.ActiveSigningKey(ctx)
	require.Error(t, err,
		"список без прежнего ключа прочитал материал, обёрнутый прежним — обёртка не проверяет подлинность")
}

// TestWrappingKeyChangeMovesNewMaterialOntoTheCurrentKey — материал,
// записанный ПОСЛЕ смены, открывается ОДНИМ текущим ключом.
//
// Это и есть предикат, по которому прежний ключ когда-нибудь можно вывести из
// списка: пока хоть одна строка набора открывается только им, вывод отнимет
// подписи. Без этого свойства список рос бы вечно и не убывал никогда.
func TestWrappingKeyChangeMovesNewMaterialOntoTheCurrentKey(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	previous, current := wrappingKey(1), wrappingKey(2)
	store := newMemStore()

	// Ключ, записанный ДО смены, одним текущим ключом не открывается…
	before := keystoreOver(t, store, at, previous)
	require.NoError(t, before.EnsureSigningKey(ctx))
	onlyCurrent := keystoreOver(t, store, at, current)
	_, err := onlyCurrent.ActiveSigningKey(ctx)
	require.Error(t, err)

	// …а порождённый ПОСЛЕ смены — открывается: новая обёртка делается первым
	// ключом списка.
	after := keystoreOver(t, store, at, current, previous)
	pub, err := after.Generate(ctx)
	require.NoError(t, err)
	rec, err := store.Get(ctx, pub.KID)
	require.NoError(t, err)

	wrapper, err := keywrap.New(current)
	require.NoError(t, err)
	plain, err := wrapper.Unwrap(rec.PrivateKeyWrapped)
	require.NoError(t, err,
		"ключ, порождённый после смены, не открывается ТЕКУЩИМ ключом — оборачивает не первый из списка")
	require.NotEmpty(t, plain)
}
