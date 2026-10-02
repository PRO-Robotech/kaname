// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// not_after_test.go — граница срока, названная вызывающим (задача
// PRO-Robotech/kaname#396, порт выпуска токена доступа церемонии).
//
// Церемония называет выпуску ГРАНИЦУ, позже которой токен истечь не вправе, и
// судит выпуск по двум величинам, лежащим в самом токене: `exp` не позже
// границы, а срок в ответе обмена — `exp − iat`. Поэтому подписант обязан (а)
// не выпустить позже границы, прочитав часы сам, — граница, пересчитанная
// вызывающим в срок по СВОИМ часам, расходится с отметкой выпуска подписанта на
// время между двумя чтениями часов; и (б) отдать ровно те `iat` и `exp`, что
// легли в токен, — утверждения несут целые секунды.
package tokensigner_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

func boundedRequest(ttl time.Duration, notAfter time.Time) tokensigner.Request {
	return tokensigner.Request{
		Subject: "usr-alice", Audience: []string{"api.kacho.local"},
		TokenType: "at+jwt", TTL: ttl, NotAfter: notAfter,
	}
}

func TestSigner_NotAfterBoundsTheExpiry(t *testing.T) {
	// Часы стоят ВНУТРИ секунды: отметка выпуска — начало этой секунды.
	clock := time.Date(2026, 9, 24, 12, 0, 0, 700_000_000, time.UTC)
	second := clock.Truncate(time.Second)
	s := mustSigner(t, stubKeys{mat: newMaterial(t, "kaname-a")}, fixedClock(clock))

	t.Run("граница раньше запрошенного срока — срок режется до неё", func(t *testing.T) {
		notAfter := second.Add(10*time.Minute + 600*time.Millisecond)
		out, err := s.Sign(context.Background(), boundedRequest(time.Hour, notAfter))
		require.NoError(t, err)

		_, claims := parseHeaderAndClaims(t, out.Token)
		require.Equal(t, float64(second.Unix()), claims["iat"])
		require.Equal(t, float64(second.Add(10*time.Minute).Unix()), claims["exp"],
			"exp обязан лечь не позже границы, в целых секундах")
		require.False(t, out.ExpiresAt.After(notAfter), "отданный срок позже названной границы")
		require.Equal(t, time.Unix(int64(claims["exp"].(float64)), 0).UTC(), out.ExpiresAt.UTC(),
			"отданный срок не равен exp, лежащему в токене")
		require.Equal(t, time.Unix(int64(claims["iat"].(float64)), 0).UTC(), out.IssuedAt.UTC(),
			"отданная отметка выпуска не равна iat, лежащему в токене")
	})

	t.Run("близнец: граница позже запрошенного срока — срок запрошенный", func(t *testing.T) {
		out, err := s.Sign(context.Background(), boundedRequest(time.Minute, second.Add(time.Hour)))
		require.NoError(t, err)
		require.Equal(t, second.Add(time.Minute), out.ExpiresAt)
	})

	t.Run("граница уже прошла в пределах секунды выпуска — отказ, а не нулевой срок", func(t *testing.T) {
		_, err := s.Sign(context.Background(), boundedRequest(time.Minute, second.Add(500*time.Millisecond)))
		require.ErrorIs(t, err, tokensigner.ErrExpiryRequired)
	})

	t.Run("дробный запрошенный срок: отданный срок равен exp в токене", func(t *testing.T) {
		out, err := s.Sign(context.Background(), boundedRequest(90*time.Second+300*time.Millisecond, time.Time{}))
		require.NoError(t, err)
		_, claims := parseHeaderAndClaims(t, out.Token)
		require.Equal(t, time.Unix(int64(claims["exp"].(float64)), 0).UTC(), out.ExpiresAt.UTC(),
			"отданный срок несёт долю секунды, которой в токене нет")
	})
}
