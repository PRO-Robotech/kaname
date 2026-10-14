// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// issue_cutoff_second_test.go — ключ пользователя, выданный после отсечки
// владельца в ТУ ЖЕ секунду, получает живой токен (задача kaname#684).
//
// Отсечка — микросекунды общего источника, `iat` — целые секунды того же
// источника, округлённые вниз, а граница правила отзыва включающая. Выдача
// судит якорь (момент выдачи ключа) в микросекундах и пропускает, а токен,
// выпущенный в секунду отсечки, несёт `iat`, не превосходящий её, и правило
// отзыва снимает его первым же предъявлением. Планка — наблюдаемое: вердикт
// НАСТОЯЩЕГО правила отзыва (`tokenrevocation.Revoked`) о выпущенном токене.
package client_token_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/client_token"
	"github.com/PRO-Robotech/kaname/internal/clientassertion"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/tokenrevocation"
)

// cutoffRevocations — читатель правила отзыва: отсечка владельца, семейства
// нет, адрес подтверждён.
type cutoffRevocations struct {
	owner  string
	cutoff time.Time
}

func (r cutoffRevocations) RevokedBefore(_ context.Context, subject string) (time.Time, bool, error) {
	if subject == r.owner {
		return r.cutoff, true, nil
	}
	return time.Time{}, false, nil
}

func (cutoffRevocations) FamilyRevoked(context.Context, string) (bool, error) { return false, nil }

func (cutoffRevocations) PersonMarks(context.Context, []string) (map[string]bool, error) {
	return map[string]bool{}, nil
}

// issuedAfterCutoff — выдача токена ключу, выданному после отсечки, часами,
// идущими от момента offset после отсечки; отдаёт токен и вердикт правила
// отзыва о нём.
func issuedAfterCutoff(t *testing.T, cutoff time.Time, offset time.Duration) (jwt.MapClaims, bool) {
	t.Helper()
	owner := ownerFor(domain.AssertionClientUser)
	start := time.Now()
	clock := func() time.Time { return cutoff.Add(offset + time.Since(start)) }
	cfg := client_token.Config{
		AllowedAudiences: []string{audResource},
		DefaultAudience:  audResource,
		TokenTTL:         15 * time.Minute,
		Clock:            clock,
	}
	claimsSrc := &stubClaims{keyIssuedAt: cutoff.Add(offset / 2)}
	cutoffs := &stubCutoffs{at: map[string]time.Time{owner: cutoff}}
	uc, err := client_token.New(cfg, newSignerOn(t, clock), claimsSrc, cutoffs)
	require.NoError(t, err)

	out, outcome, err := uc.Issue(context.Background(), client_token.Input{Client: client()})
	require.NoError(t, err, "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: ключ, выданный после отсечки, проходит правило выдачи")
	require.Equal(t, clientassertion.OutcomeAccepted, outcome)

	claims := jwt.MapClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(out.AccessToken, claims)
	require.NoError(t, err)
	revoked, err := tokenrevocation.Revoked(context.Background(), cutoffRevocations{owner: owner, cutoff: cutoff}, claims)
	require.NoError(t, err)
	return claims, revoked
}

// TestIssue_KeyIssuedAfterTheCutoffInTheSameSecondGetsALiveToken — красная до
// фикса: отсечка на 100 мс секунды, ключ выдан через 150 мс после неё, выдача
// — через 300 мс; токен, выданный правилом выдачи, правилом отзыва не снят.
func TestIssue_KeyIssuedAfterTheCutoffInTheSameSecondGetsALiveToken(t *testing.T) {
	cutoff := time.Now().UTC().Truncate(time.Second).Add(time.Hour + 100*time.Millisecond)

	claims, revoked := issuedAfterCutoff(t, cutoff, 300*time.Millisecond)

	iat, err := claims.GetIssuedAt()
	require.NoError(t, err)
	require.Falsef(t, revoked,
		"kaname#684: токен, выданный после отсечки %s, рождается отозванным — iat %s не позже неё",
		cutoff.Format(time.RFC3339Nano), iat.UTC().Format(time.RFC3339))
	require.True(t, iat.After(cutoff), "iat строго позже отсечки, по которой судила выдача")
}

// TestIssue_KeyIssuedAfterTheCutoffInAnEarlierSecondIsNotDelayed — близнец:
// отсечка в ПРЕДЫДУЩЕЙ секунде; токен жив, и момент выпуска — секунда выдачи,
// а не следующая (ожидания нет там, где оно не нужно).
func TestIssue_KeyIssuedAfterTheCutoffInAnEarlierSecondIsNotDelayed(t *testing.T) {
	cutoff := time.Now().UTC().Truncate(time.Second).Add(time.Hour + 100*time.Millisecond)

	claims, revoked := issuedAfterCutoff(t, cutoff, time.Second)

	iat, err := claims.GetIssuedAt()
	require.NoError(t, err)
	require.False(t, revoked, "токен, выданный в секунду после отсечки, жив")
	require.Equal(t, cutoff.Truncate(time.Second).Add(time.Second).Unix(), iat.Unix(),
		"момент выпуска — секунда выдачи: ожидания нет")
}
