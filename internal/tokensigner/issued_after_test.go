// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package tokensigner_test

// issued_after_test.go — `iat` строго позже отсечки, по которой судила выдача
// (Request.IssuedAfter, kaname#684): подписант, застав секунду отсечки, ждёт
// следующей не дольше секунды и читает источник заново; иначе — отказ, а не
// токен, рождённый отозванным.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

func afterRequest(after time.Time) tokensigner.Request {
	r := clockRequest()
	r.IssuedAfter = after
	return r
}

// TestSign_IssuedAfterTheCutoffWaitsForTheNextSecond — источник идёт: секунда
// отсечки пережидается, `iat` — следующая секунда.
func TestSign_IssuedAfterTheCutoffWaitsForTheNextSecond(t *testing.T) {
	cutoff := time.Date(2026, 10, 9, 10, 0, 0, 600_000_000, time.UTC)
	start := time.Now()
	clock := momentclock.Func(func() time.Time { return cutoff.Add(200*time.Millisecond + time.Since(start)) })
	s := mustSigner(t, stubKeys{mat: newMaterial(t, "kaname-a")}, clock)

	tok, err := s.Sign(context.Background(), afterRequest(cutoff))
	require.NoError(t, err)
	require.Equal(t, cutoff.Truncate(time.Second).Add(time.Second).Unix(), tok.IssuedAt.Unix(),
		"iat — первая целая секунда после отсечки")
	require.Less(t, time.Since(start), 2*time.Second, "ожидание не дольше секунды")
}

// TestSign_SourceThatDoesNotReachTheNextSecondRefuses — источник стоит: после
// ожидания секунда та же — отказ, токена нет.
func TestSign_SourceThatDoesNotReachTheNextSecondRefuses(t *testing.T) {
	cutoff := time.Date(2026, 10, 9, 10, 0, 0, 800_000_000, time.UTC)
	s := mustSigner(t, stubKeys{mat: newMaterial(t, "kaname-a")}, momentclock.At(cutoff.Add(100*time.Millisecond)))

	tok, err := s.Sign(context.Background(), afterRequest(cutoff))
	require.ErrorIs(t, err, tokensigner.ErrIssueMomentNotAfterCutoff)
	require.Empty(t, tok.Token)
}

// TestSign_CutoffAheadOfTheSourceRefusesWithoutWaiting — отсечка впереди
// источника больше чем на секунду: отказ сразу, без ожидания.
func TestSign_CutoffAheadOfTheSourceRefusesWithoutWaiting(t *testing.T) {
	at := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	s := mustSigner(t, stubKeys{mat: newMaterial(t, "kaname-a")}, momentclock.At(at))

	start := time.Now()
	_, err := s.Sign(context.Background(), afterRequest(at.Add(5*time.Second)))
	require.ErrorIs(t, err, tokensigner.ErrIssueMomentNotAfterCutoff)
	require.Less(t, time.Since(start), 500*time.Millisecond, "ждать отсечку впереди часов — не дело подписанта")
}

// TestSign_EndedCallStopsTheWait — вызов окончен во время ожидания: отказ
// причиной контекста.
func TestSign_EndedCallStopsTheWait(t *testing.T) {
	cutoff := time.Date(2026, 10, 9, 10, 0, 0, 100_000_000, time.UTC)
	s := mustSigner(t, stubKeys{mat: newMaterial(t, "kaname-a")}, momentclock.At(cutoff.Add(time.Millisecond)))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := s.Sign(ctx, afterRequest(cutoff))
	require.ErrorIs(t, err, tokensigner.ErrIssueMomentNotAfterCutoff)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 500*time.Millisecond)
}

// TestSign_CutoffInAnEarlierSecondDoesNotWait — близнец: отсечка в прошлой
// секунде — `iat` — секунда источника, без ожидания.
func TestSign_CutoffInAnEarlierSecondDoesNotWait(t *testing.T) {
	at := time.Date(2026, 10, 9, 10, 0, 1, 50_000_000, time.UTC)
	s := mustSigner(t, stubKeys{mat: newMaterial(t, "kaname-a")}, momentclock.At(at))

	start := time.Now()
	tok, err := s.Sign(context.Background(), afterRequest(at.Add(-100*time.Millisecond)))
	require.NoError(t, err)
	require.Equal(t, at.Truncate(time.Second).Unix(), tok.IssuedAt.Unix())
	require.Less(t, time.Since(start), 500*time.Millisecond)
}
