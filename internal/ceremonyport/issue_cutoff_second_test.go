// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// issue_cutoff_second_test.go — токен доступа церемонии, выпущенный после
// отсечки человека в ТУ ЖЕ секунду, не рождается отозванным (задача
// PRO-Robotech/kaname#684; признак — сквозной кейс Ф13-25 набора
// `kaname-access-keys`: восстановление, вход паролем и обмен кода за одну
// секунду дают токен, отвергнутый первым предъявлением).
//
// Отсечка — микросекунды общего источника, `iat` — целые секунды того же
// источника, округлённые вниз, граница правила отзыва включающая. Правило
// выдачи судит момент аутентификации сессии в микросекундах и пропускает;
// планка — вердикт НАСТОЯЩЕГО правила отзыва (`tokenrevocation.Revoked`) о
// выпущенном токене.
package ceremonyport_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/ceremonyport"
	"github.com/PRO-Robotech/kaname/internal/tokenrevocation"
)

// cutoffRule — правило выдачи и читатель правила отзыва над одной отсечкой
// субъекта пробы; адрес подтверждён, семейство живо.
type cutoffRule struct {
	admitAll
	cutoff time.Time
}

func (r cutoffRule) UserRevokedBefore(_ context.Context, userID string) (time.Time, bool, error) {
	if userID == testSubject {
		return r.cutoff, true, nil
	}
	return time.Time{}, false, nil
}

func (r cutoffRule) RevokedBefore(ctx context.Context, subject string) (time.Time, bool, error) {
	return r.UserRevokedBefore(ctx, subject)
}

func (cutoffRule) FamilyRevoked(context.Context, string) (bool, error) { return false, nil }

// issueAfterCutoff — выпуск по гранту сессии, аутентифицированной через
// offset/2 после отсечки, часами, идущими от момента offset после неё.
func issueAfterCutoff(t *testing.T, cutoff time.Time, offset time.Duration) (jwt.MapClaims, bool) {
	t.Helper()
	start := time.Now()
	clock := func() time.Time { return cutoff.Add(offset + time.Since(start)) }
	ring := newKeyRing(t, testKID)
	rule := cutoffRule{cutoff: cutoff}
	a, err := ceremonyport.NewAccessTokens(newSigner(t, ring, clock), ring, &issuanceLog{}, rule)
	require.NoError(t, err)
	grant := grantWithin(clock().Add(10 * time.Minute))
	grant.Session.AuthTime = cutoff.Add(offset / 2)

	issued, err := a.IssueAccessToken(context.Background(), grant)
	require.NoError(t, err, "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: сессия после отсечки проходит правило выдачи")
	_, claims := unverifiedClaims(t, issued.Token)
	revoked, err := tokenrevocation.Revoked(context.Background(), rule, claims)
	require.NoError(t, err)
	return claims, revoked
}

// TestIssue_TokenIssuedAfterTheCutoffInTheSameSecondIsNotRevoked — красная до
// фикса: отсечка на 100 мс секунды, вход через 150 мс после неё, выпуск через
// 300 мс; выданный токен правилом отзыва не снят.
func TestIssue_TokenIssuedAfterTheCutoffInTheSameSecondIsNotRevoked(t *testing.T) {
	cutoff := time.Now().UTC().Truncate(time.Second).Add(time.Hour + 100*time.Millisecond)

	claims, revoked := issueAfterCutoff(t, cutoff, 300*time.Millisecond)

	iat, err := claims.GetIssuedAt()
	require.NoError(t, err)
	require.Falsef(t, revoked,
		"kaname#684: токен, выпущенный после отсечки %s, рождается отозванным — iat %s не позже неё",
		cutoff.Format(time.RFC3339Nano), iat.UTC().Format(time.RFC3339))
	require.True(t, iat.After(cutoff), "iat строго позже отсечки, по которой судила выдача")
}

// TestIssue_TokenIssuedAfterTheCutoffInAnEarlierSecondIsNotDelayed — близнец:
// отсечка в ПРЕДЫДУЩЕЙ секунде — токен жив, момент выпуска — секунда вызова.
func TestIssue_TokenIssuedAfterTheCutoffInAnEarlierSecondIsNotDelayed(t *testing.T) {
	cutoff := time.Now().UTC().Truncate(time.Second).Add(time.Hour + 100*time.Millisecond)

	claims, revoked := issueAfterCutoff(t, cutoff, time.Second)

	iat, err := claims.GetIssuedAt()
	require.NoError(t, err)
	require.False(t, revoked, "токен, выпущенный в секунду после отсечки, жив")
	require.Equal(t, cutoff.Truncate(time.Second).Add(time.Second).Unix(), iat.Unix(),
		"момент выпуска — секунда вызова: ожидания нет")
}
