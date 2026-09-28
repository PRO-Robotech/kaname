// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package iamhooks_test

// audit_drops_test.go — счёт незаписанного журнала полос хука: отказ записи
// сосчитан и возвращён обработчику как есть, запись — не сосчитана, сборка без
// приёмника отказывает (kaname#389), а срезанная пределом запись сосчитана при
// любом порядке счёта и предела (kaname#436). Через сборку корня то же держит
// `TestIssuanceHookLanesCountTheAuditRecordTheStoreDidNotTake`.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
)

type dropCounter map[string]int

func (d dropCounter) AuditDropped(eventType string) { d[eventType]++ }

type auditOutcome struct{ err error }

func (a auditOutcome) Emit(context.Context, iamhooks.AuditEvent) error { return a.err }

func TestObserveAuditDrops_CountsTheRefusedWriteAndOnlyIt(t *testing.T) {
	refused := errors.New("audit sink refused")
	drops := dropCounter{}

	failing, err := iamhooks.ObserveAuditDrops(auditOutcome{err: refused}, drops)
	require.NoError(t, err)
	got := failing.Emit(context.Background(), iamhooks.AuditEvent{EventType: iamhooks.AuditTokenIssued})
	require.ErrorIs(t, got, refused, "отказ записи обязан дойти до обработчика как есть — его причину называет строка журнала")
	require.Equal(t, dropCounter{iamhooks.AuditTokenIssued: 1}, drops, "незаписанная запись не сосчитана")

	// Законный близнец: запись принята — счёт не движется.
	written, err := iamhooks.ObserveAuditDrops(auditOutcome{}, drops)
	require.NoError(t, err)
	require.NoError(t, written.Emit(context.Background(), iamhooks.AuditEvent{EventType: iamhooks.AuditRefreshIssued}))
	require.Equal(t, dropCounter{iamhooks.AuditTokenIssued: 1}, drops, "записанная запись сосчитана потерянной")
}

func TestObserveAuditDrops_RefusesAnAssemblyWithoutAnObserver(t *testing.T) {
	_, err := iamhooks.ObserveAuditDrops(auditOutcome{}, nil)
	require.ErrorIs(t, err, iamhooks.ErrAuditDropObserverMissing,
		"сборка без приёмника потерь принята — потеря журнала снова видна только строкой")
}

func TestObserveAuditDrops_LeavesAnUnwiredSinkUnwired(t *testing.T) {
	got, err := iamhooks.ObserveAuditDrops(nil, dropCounter{})
	require.NoError(t, err)
	require.Nil(t, got, "обёртка над неподанной записью журнала прошла бы мимо ветви «журнал не провязан»")
}

// hangingAudit — запись журнала, которую отпускает только конец контекста.
type hangingAudit struct{}

func (hangingAudit) Emit(ctx context.Context, _ iamhooks.AuditEvent) error {
	<-ctx.Done()
	return ctx.Err()
}

// TestObserveAuditDrops_CountsTheCutWriteOnEitherSideOfTheCallDeadline — запись,
// срезанная пределом на вызов, сосчитана и когда счёт надет поверх предела, и когда
// под ним (kaname#436, находка 3: опыт J3 опроверг довод шапки «счёт под пределом
// её бы не увидел»). Контекст вызывающего несёт ОТМЕНУ через много пределов, а не
// срок: запись обязан отпустить предел обёртки, и иначе проба назовёт отмену.
func TestObserveAuditDrops_CountsTheCutWriteOnEitherSideOfTheCallDeadline(t *testing.T) {
	const limit = 20 * time.Millisecond
	orders := map[string]func(drops dropCounter) iamhooks.AuditEmitter{
		"счёт поверх предела": func(drops dropCounter) iamhooks.AuditEmitter {
			bounded, err := iamhooks.WithCallDeadline(iamhooks.IssuancePorts{Audit: hangingAudit{}}, limit)
			require.NoError(t, err)
			counted, err := iamhooks.ObserveAuditDrops(bounded.Audit, drops)
			require.NoError(t, err)
			return counted
		},
		"счёт под пределом": func(drops dropCounter) iamhooks.AuditEmitter {
			counted, err := iamhooks.ObserveAuditDrops(hangingAudit{}, drops)
			require.NoError(t, err)
			bounded, err := iamhooks.WithCallDeadline(iamhooks.IssuancePorts{Audit: counted}, limit)
			require.NoError(t, err)
			return bounded.Audit
		},
	}
	for name, build := range orders {
		t.Run(name, func(t *testing.T) {
			drops := dropCounter{}
			sink := build(drops)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stop := time.AfterFunc(100*limit, cancel)
			defer stop.Stop()

			err := sink.Emit(ctx, iamhooks.AuditEvent{EventType: iamhooks.AuditTokenIssued})
			require.ErrorIs(t, err, context.DeadlineExceeded,
				"зависшая запись отпущена не пределом обёртки, а %v", err)
			require.Equal(t, dropCounter{iamhooks.AuditTokenIssued: 1}, drops,
				"%s: запись срезана пределом и не записана, а счёт её не увидел", name)
		})
	}
}
