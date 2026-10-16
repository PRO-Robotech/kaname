// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// own_sessions_store_failure_test.go — сбой хранилища у глаголов своих сессий
// растит клетку глагола (kaname#735). Наружу такой отказ один — UNAVAILABLE
// без причины; без клетки правило отказов нашей стороны о нём не знает.
//
// Близнец — тот же посев без подставного отказа: клетка не растёт.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
)

func TestOwnSessionsStoreFailureIsCountedByVerb(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		failOn string
		verb   humansession.StoreFailureVerb
		run    func(g osU) error
	}{
		{"перечень, резолв не ответил", "resolve", humansession.StoreFailureOwnSessionsList, func(g osU) error {
			_, err := g.list.Execute(ctx, humansession.ListOwnSessionsInput{Bearer: g.raBearer})
			return err
		}},
		{"выход из выбранной, событие не записано", "audit", humansession.StoreFailureOwnSessionEnd, func(g osU) error {
			_, err := g.end.Execute(ctx, humansession.EndOwnSessionInput{Bearer: g.raBearer, SessionID: g.rb.ID})
			return err
		}},
		{"выход из прочих, событие не записано", "audit", humansession.StoreFailureOwnSessionsEndOthers, func(g osU) error {
			_, err := g.others.Execute(ctx, humansession.EndOtherOwnSessionsInput{Bearer: g.raBearer})
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := givenOSU(t)
			g.h.store.failOn = tc.failOn
			err := tc.run(g)
			require.Truef(t, errors.Is(err, humansession.ErrStoreUnavailable), "ожидался UNAVAILABLE, получено %v", err)
			require.Equalf(t, 1, g.h.obs.storeFailures[tc.verb], "сбой хранилища глагола %q не посчитан", tc.verb)
		})
		t.Run(tc.name+" — близнец без отказа", func(t *testing.T) {
			g := givenOSU(t)
			require.NoError(t, tc.run(g))
			require.Zero(t, g.h.obs.storeFailures[tc.verb], "клетка выросла без сбоя")
		})
	}
}
