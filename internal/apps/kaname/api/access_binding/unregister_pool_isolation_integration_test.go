// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// verifies https://github.com/PRO-Robotech/kaname/issues/1019

import (
	"context"
	"sync"
	"testing"
	"time"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnregisterLateDescendant_PoolDefaultIsolation(t *testing.T) {
	for _, isolation := range []string{"read committed", "repeatable read"} {
		t.Run(isolation, func(t *testing.T) {
			w := newDescendantRingWorld(t)
			ctx, cancel := context.WithTimeout(w.ctx, 60*time.Second)
			defer cancel()
			parent := raceKey(25000, 0)
			child := parent + "/app"
			w.registerRegistry(parent)
			require.False(t, w.registered(pcrRepoType, child))
			cfg := w.pool.Config()
			cfg.ConnConfig.RuntimeParams["default_transaction_isolation"] = isolation
			upool, err := pgxpool.NewWithConfig(ctx, cfg)
			require.NoError(t, err)
			defer upool.Close()
			var poolDefault string
			require.NoError(t, upool.QueryRow(ctx, "SHOW default_transaction_isolation").Scan(&poolDefault))
			require.Equal(t, isolation, poolDefault, "фикстура: пул принял серверное умолчание")
			h := &lateCensusMirror{ResourceMirrorEmitter: kanamepg.NewResourceMirrorEmitter(), observed: make(chan lateCensus, 16)}
			uc := internaliam.NewRegisterResourceUseCase(kanamepg.NewFGAOutboxEmitter(), h, kanamepg.NewPoolTxBeginner(upool),
				kanamepg.NewCatalogTypeReader(), kanamepg.NewPublicReadPublisher(),
				accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), pcrFacts{w.pcrWorld}),
				kanamepg.NewRegistrationAudit(), kanamepg.NewRegistrationScopeReader())
			first, releaseRaw := h.first.arm()
			var once sync.Once
			release := func() { once.Do(releaseRaw) }
			defer release()
			done := make(chan error, 1)
			go func() { done <- w.withdrawWith(ctx, uc, parent) }()
			select {
			case <-first:
			case err := <-done:
				t.Fatalf("фикстура: снятие завершилось до первого обхода: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			initial := <-h.observed
			require.Empty(t, initial.descendants, "фикстура: первый обход предшествует регистрации ребёнка")
			w.registerRepository(parent, "app")
			require.True(t, w.registered(pcrRepoType, child), "фикстура: ребёнок закоммичен до продолжения снятия")
			t.Logf("pool default=%s; actual withdrawal isolation=%s; child committed after first census", poolDefault, initial.isolation)
			release()
			select {
			case err = <-done:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			require.NoError(t, err, "снятие успешно завершает весь набор")
			assert.False(t, w.registered(pcrRegType, parent), "родитель снят")
			assert.False(t, w.registered(pcrRepoType, child), "поздний ребёнок должен быть снят вместе с родителем")
			var events, descendants int
			require.NoError(t, w.pool.QueryRow(ctx, `SELECT count(*), coalesce(sum((event_payload->>'descendants')::integer),0) FROM kaname.audit_outbox WHERE event_type='iam.resource_registration.unregistered' AND event_payload #>> '{object,id}'=$1`, parent).Scan(&events, &descendants))
			assert.Equal(t, 1, events, "ровно одно событие снятия родителя")
			assert.Equal(t, 1, descendants, "аудит учитывает позднего ребёнка")
		})
	}
}
