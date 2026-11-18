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
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Production beginner берёт compatibility fence до первой переписи. Поздний
// Register ждёт снятие, затем отказывает без родителя; существующий потомок
// снимается и учитывается в аудите. Generic late-census сценарий с другим
// beginner остаётся в TestUnregisterLateDescendantVsObjectPass_NoDeadlock.
func TestUnregisterWriterSerialization_PoolDefaultIsolation(t *testing.T) {
	for _, isolation := range []string{"read committed", "repeatable read", "serializable"} {
		t.Run(isolation, func(t *testing.T) {
			w := newDescendantRingWorld(t)
			ctx, cancel := context.WithTimeout(w.ctx, 60*time.Second)
			defer cancel()
			parent := raceKey(25000, 0)
			child := parent + "/app"
			lateChild := parent + "/late"
			w.registerRegistry(parent)
			w.registerRepository(parent, "app")
			require.True(t, w.registered(pcrRepoType, child), "фикстура: существующий потомок закоммичен")
			require.NotZero(t, w.factsOn(pcrRepoType, child), "фикстура: у существующего потомка есть факты")
			require.False(t, w.registered(pcrRepoType, lateChild))
			require.Zero(t, w.factsOn(pcrRepoType, lateChild))
			cfg := w.pool.Config()
			cfg.ConnConfig.RuntimeParams["default_transaction_isolation"] = isolation
			cfg.ConnConfig.Tracer = sharedWriterTracer{}
			upool, err := pgxpool.NewWithConfig(ctx, cfg)
			require.NoError(t, err)
			defer upool.Close()
			var poolDefault string
			require.NoError(t, upool.QueryRow(ctx, "SHOW default_transaction_isolation").Scan(&poolDefault))
			require.Equal(t, isolation, poolDefault, "фикстура: пул принял серверное умолчание")
			h := &lateCensusMirror{ResourceMirrorEmitter: kanamepg.NewResourceMirrorEmitter(), observed: make(chan lateCensus, 16)}
			uc := internaliam.NewRegisterResourceUseCase(kanamepg.NewFGAOutboxEmitter(), h, kanamepg.NewRegistrationTxBeginner(upool),
				kanamepg.NewCatalogTypeReader(), kanamepg.NewPublicReadPublisher(),
				accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), pcrFacts{w.pcrWorld}),
				kanamepg.NewRegistrationAudit(), kanamepg.NewRegistrationScopeReader()).WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "registry"})
			first, releaseRaw := h.first.arm()
			var once sync.Once
			release := func() { once.Do(releaseRaw) }
			lateEntry := &sharedWriterEntry{entered: make(chan struct{}), release: make(chan struct{})}
			var workers sync.WaitGroup
			// LIFO: отпустить все свои паузы, отменить запросы и присоединить обе
			// реальные goroutine до upool.Close, включая Fatal и истечение ctx.
			defer func() {
				release()
				lateEntry.let()
				cancel()
				workers.Wait()
			}()
			done := make(chan error, 1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				done <- w.withdrawWith(ctx, uc, parent)
			}()
			select {
			case <-first:
			case err := <-done:
				t.Fatalf("фикстура: снятие завершилось до первого обхода: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			initial := <-h.observed
			require.Len(t, initial.descendants, 1, "фикстура: первый обход видит ровно одного существующего потомка")
			require.Equal(t, child, initial.descendants[0].ID)
			assert.Equal(t, "read committed", initial.isolation, "снятие выбирает свежие снимки независимо от умолчания пула")
			lateCtx := context.WithValue(ctx, sharedWriterEntryKey{}, lateEntry)
			lateDone := make(chan error, 1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				lateDone <- uc.Register(lateCtx, &iamv1.RegisterResourceRequest{
					SubjectId: pcrRegType + ":" + parent, Relation: "parent", Object: pcrRepoType + ":" + lateChild,
					ParentProjectId: string(w.prjA), ParentAccountId: string(w.accA),
					ParentChain: []string{pcrRegType + ":" + parent, "project:" + string(w.prjA), "account:" + string(w.accA)},
				})
			}()
			lateStart := sharedEntryStarted(t, ctx, w.pool, lateEntry, lateDone)
			lateEntry.let()
			sharedWaitWriterFence(t, ctx, w.pool, lateEntry, initial.pid, lateStart, lateDone)
			t.Logf("pool default=%s; actual withdrawal isolation=%s; late Register ждёт fence U pid=%d", poolDefault, initial.isolation, initial.pid)
			release()
			select {
			case err = <-done:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			require.NoError(t, err, "снятие успешно завершает весь набор")
			select {
			case err = <-lateDone:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			require.ErrorIs(t, err, iamerr.ErrParentScopeMismatch, "после ожидания родитель уже снят")
			assert.False(t, w.registered(pcrRegType, parent), "родитель снят")
			assert.False(t, w.registered(pcrRepoType, child), "существующий потомок снят вместе с родителем")
			assert.Zero(t, w.factsOn(pcrRepoType, child), "факты существующего потомка сняты")
			assert.False(t, w.registered(pcrRepoType, lateChild), "отказ поздней регистрации не оставил mirror или parent edges")
			assert.Zero(t, w.factsOn(pcrRepoType, lateChild), "отказ поздней регистрации не оставил facts")
			var events, descendants int
			require.NoError(t, w.pool.QueryRow(ctx, `SELECT count(*), coalesce(sum((event_payload->>'descendants')::integer),0) FROM kaname.audit_outbox WHERE event_type='iam.resource_registration.unregistered' AND event_payload #>> '{object,id}'=$1`, parent).Scan(&events, &descendants))
			assert.Equal(t, 1, events, "ровно одно событие снятия родителя")
			assert.Equal(t, 1, descendants, "аудит учитывает ровно одного существовавшего потомка")
			ordinary, err := kanamepg.NewPoolTxBeginner(upool).Begin(ctx)
			require.NoError(t, err)
			defer ordinary.Rollback(ctx)
			var ordinaryIsolation string
			require.NoError(t, ordinary.(pgx.Tx).QueryRow(ctx, "SHOW transaction_isolation").Scan(&ordinaryIsolation))
			assert.Equal(t, isolation, ordinaryIsolation, "обычные транзакции сохраняют умолчание пула")
		})
	}
}
