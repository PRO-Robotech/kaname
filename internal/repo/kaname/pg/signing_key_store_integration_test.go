// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// signing_key_store_integration_test.go — F1-08, первая красная проба фазы.
//
// Приёмка §10 ставит читателя первым не из вкуса. Предшествующее хранилище
// подписных ключей было снято ровно потому, что приватную половину не
// расшифровывал никто: запись удавалась, строки появлялись, и хранилище
// выглядело исправным. Хранилище без читателя неотличимо от рабочего.
//
// Поэтому утверждение здесь — о ПРИГОДНОСТИ прочитанного к подписи, а не о том,
// что чтение вернуло ненулевые байты: прочитанная приватная половина
// разворачивается, подписывает, и подпись проверяется публичной половиной той
// же строки.
package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/keywrap"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/signingkeygen"
)

// TestSigningKeyStore_F1_08_ReadBackPrivateHalfIsFitToSign — F1-08.
func TestSigningKeyStore_F1_08_ReadBackPrivateHalfIsFitToSign(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	wrapper, err := keywrap.New(make([]byte, 32))
	require.NoError(t, err)
	repo := kanamepg.NewSigningKeyRepo(pool)

	// Given — ключ порождён и записан с ОБЁРНУТОЙ приватной половиной.
	material, err := signingkeygen.Generate(domain.SigningAlgRS256)
	require.NoError(t, err)
	wrapped, err := wrapper.Wrap(material.PrivateKeyPEM)
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Second)
	rec := domain.SigningKeyRecord{
		KID:               "kacho-f108",
		Algorithm:         domain.SigningAlgRS256,
		State:             domain.SigningKeyPublished,
		PublicKeyPEM:      material.PublicKeyPEM,
		PrivateKeyWrapped: wrapped,
		CreatedAt:         now,
		NotAfter:          now.Add(90 * 24 * time.Hour),
	}
	require.NoError(t, repo.Insert(ctx, rec))

	// When — тот же процесс читает ключ обратно.
	got, err := repo.Get(ctx, rec.KID)
	require.NoError(t, err)

	// Then — приватная половина восстанавливается И ПРИГОДНА К ПОДПИСИ.
	privPEM, err := wrapper.Unwrap(got.PrivateKeyWrapped)
	require.NoError(t, err, "обёртка обязана сниматься тем же ключом")

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(privPEM)
	require.NoError(t, err, "прочитанная приватная половина обязана разбираться как ключ")

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "https://kaname.kacho.local",
		"exp": now.Add(time.Minute).Unix(),
	})
	tok.Header["kid"] = string(got.KID)
	signed, err := tok.SignedString(signKey)
	require.NoError(t, err, "прочитанный ключ обязан ПОДПИСЫВАТЬ, а не просто разбираться")

	// And — подпись проверяется публичной половиной ТОЙ ЖЕ строки: без этого
	// «пригоден к подписи» зелено и на ключе, не имеющем отношения к записи.
	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(got.PublicKeyPEM))
	require.NoError(t, err)
	parsed, err := jwt.Parse(signed, func(*jwt.Token) (any, error) { return verifyKey, nil },
		jwt.WithValidMethods([]string{"RS256"}))
	require.NoError(t, err, "публичная половина записи обязана проверять подпись её приватной половины")
	require.True(t, parsed.Valid)
	require.Equal(t, string(got.KID), parsed.Header["kid"])
}
