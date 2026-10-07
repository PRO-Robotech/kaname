// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// own_sessions_usecase_test.go — сценарий OS-15 приёмки
// `docs/engineering/acceptance/own-sessions-are-listed-and-ended-by-their-owner.md`
// (задача PRO-Robotech/kaname#634), уровень U: глаголы своих сессий над
// дублёром хранилища с подставным отказом по имени операции (`failOn`).

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

const osFreshness = 15 * time.Minute

// osU — «Дано U»: личность P, записи R_A и R_B, выданные в h.clock операцией
// выдачи через писатель харнесса.
type osU struct {
	h        *harness
	user     domain.User
	ra, rb   domain.HumanSession
	raBearer domain.SessionBearer
	list     *humansession.ListOwnSessionsUseCase
	end      *humansession.EndOwnSessionUseCase
	others   *humansession.EndOtherOwnSessionsUseCase
}

func givenOSU(t *testing.T) osU {
	t.Helper()
	h := newHarness(t, nil)
	u := h.person(t, "usr-os15", "os15@example.invalid", "", true)
	issue := func() (domain.HumanSession, domain.SessionBearer) {
		w, err := h.store.Writer(context.Background())
		require.NoError(t, err)
		s, b, err := humansession.IssueSession(context.Background(), w, humansession.IssueInput{
			User: u, Presented: []assurance.Presentation{assurance.PasswordPresented()}, At: h.clock, TTL: ucTTL,
		})
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): выдача записи")
		require.NoError(t, w.Commit(context.Background()))
		return s, b
	}
	ra, raBearer := issue()
	rb, _ := issue()
	deps := humansession.OwnSessionsDeps{
		Store: h.store, Freshness: osFreshness, Observer: h.obs,
		Now: func() time.Time { return h.clock }, Logger: slog.New(slog.DiscardHandler),
	}
	list, err := humansession.NewListOwnSessionsUseCase(deps)
	require.NoError(t, err)
	end, err := humansession.NewEndOwnSessionUseCase(deps)
	require.NoError(t, err)
	others, err := humansession.NewEndOtherOwnSessionsUseCase(deps)
	require.NoError(t, err)
	return osU{h: h, user: u, ra: ra, rb: rb, raBearer: raBearer, list: list, end: end, others: others}
}

func (g osU) rbEnded() bool { return g.h.store.rows[g.rb.ID].ended != nil }

func (g osU) endedEvents() int {
	n := 0
	for _, ev := range g.h.store.audit {
		if ev.EventType == humansession.AuditSessionEndedByPerson {
			n++
		}
	}
	return n
}

// TestOS15_StoreUnavailableOnResolveAndAuditFailureRollsBackTheEnd — хранилище
// недоступно на резолве; отказ записи события откатывает снятие; близнец — тот
// же посев без подставного отказа.
func TestOS15_StoreUnavailableOnResolveAndAuditFailureRollsBackTheEnd(t *testing.T) {
	ctx := context.Background()

	t.Run("(а) резолв не ответил — end", func(t *testing.T) {
		g := givenOSU(t)
		g.h.store.failOn = "resolve"
		_, err := g.end.Execute(ctx, humansession.EndOwnSessionInput{Bearer: g.raBearer, SessionID: g.rb.ID})
		require.True(t, errors.Is(err, humansession.ErrStoreUnavailable), "OS-15 (а): UNAVAILABLE, получено %v", err)
		require.False(t, g.rbEnded(), "OS-15 (а): R_B жива")
	})
	t.Run("(б) запись события отказала — end откатан", func(t *testing.T) {
		g := givenOSU(t)
		g.h.store.failOn = "audit"
		_, err := g.end.Execute(ctx, humansession.EndOwnSessionInput{Bearer: g.raBearer, SessionID: g.rb.ID})
		require.True(t, errors.Is(err, humansession.ErrStoreUnavailable), "OS-15 (б): UNAVAILABLE, получено %v", err)
		require.False(t, g.rbEnded(), "OS-15 (б): R_B жива и не помечена снятой")
		require.Zero(t, g.endedEvents(), "OS-15 (б): события нет")
	})
	t.Run("(в) запись события отказала — end-others откатан", func(t *testing.T) {
		g := givenOSU(t)
		g.h.store.failOn = "audit"
		_, err := g.others.Execute(ctx, humansession.EndOtherOwnSessionsInput{Bearer: g.raBearer})
		require.True(t, errors.Is(err, humansession.ErrStoreUnavailable), "OS-15 (в): UNAVAILABLE, получено %v", err)
		require.False(t, g.rbEnded(), "OS-15 (в): R_B жива и не помечена снятой")
		require.Zero(t, g.endedEvents(), "OS-15 (в): события нет")
	})
	t.Run("(г) резолв не ответил — перечень", func(t *testing.T) {
		g := givenOSU(t)
		g.h.store.failOn = "resolve"
		_, err := g.list.Execute(ctx, humansession.ListOwnSessionsInput{Bearer: g.raBearer})
		require.True(t, errors.Is(err, humansession.ErrStoreUnavailable), "OS-15 (г): UNAVAILABLE, получено %v", err)
	})
	t.Run("близнец — без подставного отказа снятие проходит, событие одно", func(t *testing.T) {
		g := givenOSU(t)
		_, err := g.end.Execute(ctx, humansession.EndOwnSessionInput{Bearer: g.raBearer, SessionID: g.rb.ID})
		require.NoError(t, err, "OS-15 близнец (end)")
		require.True(t, g.rbEnded(), "OS-15 близнец: R_B снята")
		require.Equal(t, domain.RevokeReasonEndedFromAnotherSession, g.h.store.rows[g.rb.ID].reason)
		require.Equal(t, 1, g.endedEvents(), "OS-15 близнец: событие одно")

		g2 := givenOSU(t)
		out, err := g2.others.Execute(ctx, humansession.EndOtherOwnSessionsInput{Bearer: g2.raBearer})
		require.NoError(t, err, "OS-15 близнец (end-others)")
		require.Equal(t, 1, out.Ended)
		require.True(t, g2.rbEnded())
		require.Equal(t, 1, g2.endedEvents())

		g3 := givenOSU(t)
		page, err := g3.list.Execute(ctx, humansession.ListOwnSessionsInput{Bearer: g3.raBearer})
		require.NoError(t, err, "OS-15 близнец (перечень)")
		require.Len(t, page.Sessions, 2)
	})
}
