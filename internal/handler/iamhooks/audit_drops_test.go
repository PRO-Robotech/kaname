// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package iamhooks_test

// audit_drops_test.go — счёт незаписанного журнала полос хука: отказ записи
// сосчитан и возвращён обработчику как есть, запись — не сосчитана, сборка без
// приёмника отказывает (kaname#389). Через сборку корня то же держит
// `TestIssuanceHookLanesCountTheAuditRecordTheStoreDidNotTake`.

import (
	"context"
	"errors"
	"testing"

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
