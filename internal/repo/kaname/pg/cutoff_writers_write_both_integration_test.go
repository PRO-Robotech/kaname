// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// cutoff_writers_write_both_integration_test.go — КАЖДЫЙ ПИСАТЕЛЬ ОТСЕЧКИ
// КЛАДЁТ ОБЕ ЗАПИСИ, и снятие сессии отзывает выданное в ней (kaname#313).
//
// Записей отсечки две, и судят по ним РАЗНЫЕ читатели. Путь снятия доступа,
// дошедший до одной и не дошедший до второй, снимает доступ наполовину и
// выглядит исполненным целиком.
//
// Пробы судят наблюдаемое ТОЙ ЖЕ функцией решения, которой судит поверхность.

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
	"github.com/PRO-Robotech/kaname/internal/tokenrevocation"
)

// bearerClaims — состав утверждений личного носителя в ТОЙ форме, в какой его
// получает поверхность: числовые отметки приходят `float64` после разбора JSON.
func bearerClaims(sub string, issued time.Time) jwt.MapClaims {
	return jwt.MapClaims{"sub": sub, "iat": float64(issued.Unix())}
}

// TestIntegration_LoginLaneCutoffWriterWritesBothRecords — писатель отсечки
// ПОЛОСЫ ВХОДА (выход, смена пароля, восстановление, сброс второго фактора)
// снимает доступ и на предъявлении, а не только на выдаче.
func TestIntegration_LoginLaneCutoffWriterWritesBothRecords(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	scene := ceremonyScene(t, ctx, pool, "bwrec")
	authority := kanamepg.NewMintedTokenRevocationRepo(pool)
	issued := time.Now().UTC().Add(-time.Minute)
	claims := bearerClaims(scene.UserID, issued)

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: до отсечки носитель принимается.
	revoked, err := tokenrevocation.Revoked(ctx, authority, claims)
	require.NoError(t, err)
	require.False(t, revoked, "носитель отозван ДО отсечки — отрицание ниже беспредметно")

	// Отсечку кладёт писатель ПОЛОСЫ ВХОДА, той же дверью, что и все прочие.
	sessions := kanamepg.NewHumanSessionRepo(pool)
	w, err := sessions.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.UpsertCutoff(ctx, domain.UserTokenRevocation{
		UserID:       domain.UserID(scene.UserID),
		RevokeBefore: time.Now().UTC(),
		Reason:       domain.RevokeReasonLogout,
	}, domain.UserID(scene.UserID)))
	require.NoError(t, w.Commit(ctx))

	// ПРЕДМЕТ: тот же носитель предъявлением больше не проходит.
	revoked, err = tokenrevocation.Revoked(ctx, authority, claims)
	require.NoError(t, err)
	require.True(t, revoked,
		"писатель отсечки полосы входа положил ОДНУ запись из двух: доступ снят на "+
			"выдаче и НЕ снят на предъявлении — прежний носитель продолжает "+
			"аутентифицировать вызовы")
}
