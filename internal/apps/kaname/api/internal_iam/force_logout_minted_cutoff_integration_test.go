// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// force_logout_minted_cutoff_integration_test.go — ПРИНУДИТЕЛЬНЫЙ ВЫХОД
// ДОСТИГАЕТ НОСИТЕЛЯ, КОТОРЫМ СУДИТ ЧИТАТЕЛЬ ПРЕДЪЯВЛЕНИЯ (задача kaname#313).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ — ЗАПИСЕЙ ОТСЕЧКИ ДВЕ, И СУДИТ ЧИТАТЕЛЬ ПО СВОЕЙ
//
// Записи эти не взаимозаменяемы: у каждой свой ключ, свой писатель и свой
// читатель. Снятие доступа обязано доходить до ТОЙ, по которой судит авторитет
// отзыва на пути запроса, — иначе контроль объявлен, исполнен наполовину и
// выглядит исполненным целиком.
//
// Проба утверждает наблюдаемое и судит его ТОЙ ЖЕ функцией решения, которой
// судит поверхность (`tokenrevocation.Revoked`), а не собственным пересказом
// правила: пересказ разошёлся бы с правилом молча.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ ОБЯЗАТЕЛЕН
//
// Без него «после выхода отозван» зеленело бы на правиле, которое отвергает
// что угодно: токен без отметки выпуска и токен без единого ключа отсечки
// правило отвергает by construction. Поэтому рядом судится ТОТ ЖЕ токен ДО
// выхода — он обязан быть принят.

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/tokenrevocation"
)

// personalTokenClaims — состав утверждений ЛИЧНОГО токена: субъект — наш
// `users.id`, отметка выпуска — до выхода. Ключей отсечки у него ровно один, и
// это тот самый субъект, которого называет распорядитель.
func personalTokenClaims(uid domain.UserID, issued time.Time) jwt.MapClaims {
	// Отметка выпуска кладётся В ТОЙ ФОРМЕ, в какой её получает поверхность:
	// разбор числовых отметок принимает `float64` и `json.Number` — ровно то,
	// что даёт декодирование JSON настоящего токена, — а прочие типы отвергает.
	// Токен с нечитаемой отметкой правило считает отозванным by construction,
	// поэтому негодная фикстура зеленила бы отрицание и роняла близнеца. Здесь
	// это и произошло дважды подряд: сперва с `int64`, затем с
	// `*jwt.NumericDate`, — и оба раза поймал именно близнец.
	return jwt.MapClaims{
		"sub": string(uid),
		"iat": float64(issued.Unix()),
	}
}

// TestIntegration_ForceLogoutRevokesTheMintedTokenAtPresentation — личный токен,
// выданный ДО принудительного выхода, после него предъявлением не проходит.
func TestIntegration_ForceLogoutRevokesTheMintedTokenAtPresentation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	_, pool := newForceLogoutHandler(t)
	h := ownPostureForceLogoutHandler(t, pool)
	uid := seedForceLogoutUser(t, ctx, pool)

	// Авторитет отзыва — ТОТ ЖЕ, что провязан публичному слушателю
	// (`presentedcred.Config.Revocations`).
	authority := kanamepg.NewMintedTokenRevocationRepo(pool)

	issued := time.Now().UTC().Add(-time.Minute)
	claims := personalTokenClaims(uid, issued)

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: до выхода тот же токен принимается.
	revoked, err := tokenrevocation.Revoked(ctx, authority, claims)
	require.NoError(t, err, "спросить авторитет отзыва до выхода")
	require.False(t, revoked,
		"токен отозван ДО выхода — отрицание ниже зеленело бы на правиле, "+
			"отвергающем что угодно")

	_, err = h.ForceLogout(forceLogoutAdminCtx(), &iamv1.ForceLogoutRequest{
		UserId: string(uid),
		Reason: "admin-force-logout",
	})
	require.NoError(t, err, "принудительный выход")

	// ПРЕДМЕТ: после выхода тот же токен предъявлением не проходит.
	revoked, err = tokenrevocation.Revoked(ctx, authority, claims)
	require.NoError(t, err, "спросить авторитет отзыва после выхода")
	require.True(t, revoked,
		"снятие доступа не дошло до записи отсечки, по которой судит авторитет "+
			"отзыва на пути запроса: глагол ответил успехом, а предъявление того же "+
			"носителя по-прежнему принимается")

	// Отсечка стоит на ТОМ субъекте, которого назвал распорядитель, и стоит
	// вперёд: выпущенное ПОСЛЕ неё действительно — иначе отзыв означал бы
	// вечную блокировку принципала, а не снятие выданного.
	after := personalTokenClaims(uid, time.Now().UTC().Add(time.Minute))
	revoked, err = tokenrevocation.Revoked(ctx, authority, after)
	require.NoError(t, err)
	require.False(t, revoked,
		"отсечка отвергает и выпущенное ПОСЛЕ неё — это вечная блокировка "+
			"принципала, а не снятие выданного")
}
