// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package tokensigner_test

// clock_test.go — `iat` ставит поданный источник момента выпуска (общий для
// всех реплик, задача kaname#589); источник не ответил либо ответил нулём —
// отказ выпуска, а не подпись другими часами.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

func clockRequest() tokensigner.Request {
	return tokensigner.Request{Subject: "usr00000000000000001", Audience: []string{"kacho"}, TokenType: "at+jwt", TTL: 10 * time.Minute}
}

func TestSign_IssuedAtIsTheSourceMoment(t *testing.T) {
	at := time.Date(2026, 10, 7, 9, 37, 12, 900_000_000, time.UTC)
	s := mustSigner(t, stubKeys{mat: newMaterial(t, "kaname-a")}, momentclock.At(at))
	tok, err := s.Sign(context.Background(), clockRequest())
	require.NoError(t, err)
	_, claims := parseHeaderAndClaims(t, tok.Token)
	require.EqualValues(t, at.Truncate(time.Second).Unix(), claims["iat"], "iat — момент источника, в целых секундах")
	require.True(t, tok.IssuedAt.Equal(at.Truncate(time.Second)))
}

func TestSign_UnansweredOrZeroSourceRefusesTheIssue(t *testing.T) {
	for name, clock := range map[string]tokensigner.Clock{
		"источник не ответил":    momentclock.Failing{Err: errors.New("dial tcp 10.0.0.9:5432")},
		"источник ответил нулём": momentclock.At(time.Time{}),
	} {
		t.Run(name, func(t *testing.T) {
			s := mustSigner(t, stubKeys{mat: newMaterial(t, "kaname-a")}, clock)
			tok, err := s.Sign(context.Background(), clockRequest())
			require.ErrorIs(t, err, tokensigner.ErrClockUnavailable)
			require.Empty(t, tok.Token, "токена нет")
		})
	}
}
