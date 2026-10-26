// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// unregister_descendants_audit_count_world_integration_test.go — запись аудита о
// снятии родителя называет ровно тех потомков, чью регистрацию снял этот вызов
// (PRO-Robotech/kaname#1020).
//
// # Предмет
//
// Событие `iam.resource_registration.unregistered` родителя несёт поле
// `descendants` — число снятых вместе с ним потомков. Потомок попадает в перечень
// снятия по цепи предков, а снятой его регистрация считается, только если строка
// зеркала потомка удалена этим вызовом (kaname#963, Д1). Потомок из перечня, чью
// строку к моменту снятия уже убрал другой вызов, снят не этим вызовом, и в число
// не входит.
//
// # Где такой потомок берётся
//
// Потомок, снятый ДО вызова родителя, в перечень не попадает вовсе: его снятие
// убирает и цепь предков. Поэтому состояние «в перечне, но уже снят» рождается
// только встречным снятием потомка, зафиксированным между чтением перечня и
// снятием строки потомка. Проба воспроизводит его удержанием: снятие родителя
// останавливается сразу после чтения перечня потомков (`afterDescendants`
// `mirrorHold`), в паузу X/app снимается своим вызовом, затем снятие X
// отпускается.
//
// # Что утверждается
//
// Число в событии снятия X — 1 (снят только X/web), а не 2. Близнецы:
// все потомки живы — число 2; повтор снятия X нового события не пишет (снимать
// нечего); X, заведённый заново без потомков и снятый, — число 0.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// unregisteredEvents — полезные нагрузки событий снятия объекта `id` реестра в
// порядке записи: по времени транзакции (`created_at`), а не по id — id события
// случаен и порядка не несёт.
func (w *cascadeWorld) unregisteredEvents(id string) []map[string]any {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx,
		`SELECT event_payload FROM kaname.audit_outbox
		  WHERE event_type = $1 AND event_payload #>> '{object,type}' = $2
		    AND event_payload #>> '{object,id}' = $3
		  ORDER BY created_at, id`,
		auditUnregistered, pcrRegTgt, id)
	require.NoError(w.t, err, "события снятия %s", id)
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var p map[string]any
		require.NoError(w.t, rows.Scan(&p), "событие снятия %s", id)
		out = append(out, p)
	}
	require.NoError(w.t, rows.Err(), "события снятия %s", id)
	return out
}

// descendantsIn — число потомков, названное событием снятия. Поля нет — -1:
// отсутствие отличимо от нуля.
func descendantsIn(p map[string]any) int {
	v, ok := p["descendants"].(float64)
	if !ok {
		return -1
	}
	return int(v)
}

// TestUnregisterAudit_DescendantRemovedMeanwhileIsNotCounted — X/app снят своим
// вызовом, пока снятие X стоит после чтения перечня потомков: событие снятия X
// называет одного снятого потомка (X/web), а не двух.
func TestUnregisterAudit_DescendantRemovedMeanwhileIsNotCounted(t *testing.T) {
	w := newCascadeWorld(t)
	uc, hold := w.heldRegister()
	reached, release := hold.afterDescendants.arm()
	done := make(chan error, 1)
	go func() { done <- w.withdrawWith(w.ctx, uc, pcrX) }()
	select {
	case <-reached:
	case err := <-done:
		t.Fatalf("1020: снятие X закончилось, не дойдя до чтения потомков: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("1020: снятие X не дошло до чтения потомков")
	}
	meanwhile := make(chan error, 1)
	go func() {
		meanwhile <- w.reg.Unregister(w.ctx, &iamv1.UnregisterResourceRequest{
			SubjectId: pcrRegType + ":" + pcrX, Relation: "parent",
			Object: pcrRepoType + ":" + pcrXApp, SourceVersion: w.nextVersion(),
		})
	}()
	select {
	case err := <-meanwhile:
		require.NoError(t, err, "1020: встречное снятие X/app")
	case <-time.After(20 * time.Second):
		release()
		t.Fatal("ПРЕДПОСЫЛКА 1020: встречное снятие X/app стоит за снятием X — состояние «в перечне, но уже снят» не построено")
	}
	release()
	require.NoError(t, <-done, "1020: снятие X")

	events := w.unregisteredEvents(pcrX)
	require.Len(t, events, 1, "1020: событий снятия X")
	assert.Equal(t, 1, descendantsIn(events[0]),
		"1020: событие снятия X называет потомков больше, чем снял этот вызов (X/app снят встречным вызовом)")
	w.assertDescendantGone(pcrXApp, w.grantXApp, "1020: X/app")
	w.assertDescendantGone(pcrXWeb, w.grantXWeb, "1020: X/web")
}

// TestUnregisterAudit_AllDescendantsAliveAreCounted — близнец: все потомки живы,
// событие снятия X называет обоих.
func TestUnregisterAudit_AllDescendantsAliveAreCounted(t *testing.T) {
	w := newCascadeWorld(t)

	w.withdrawX()

	events := w.unregisteredEvents(pcrX)
	require.Len(t, events, 1, "1020 близнец: событий снятия X")
	assert.Equal(t, 2, descendantsIn(events[0]), "1020 близнец: число снятых потомков X")
}

// TestUnregisterAudit_RepeatCountsNothing — повтор снятия X нового события не
// пишет; X, заведённый заново без потомков и снятый, называет ноль потомков.
func TestUnregisterAudit_RepeatCountsNothing(t *testing.T) {
	w := newCascadeWorld(t)
	w.withdrawX()

	w.withdrawX()

	events := w.unregisteredEvents(pcrX)
	require.Len(t, events, 1, "1020 повтор: повтор снятия X записал событие")
	assert.Equal(t, 2, descendantsIn(events[0]), "1020 повтор: число снятых потомков X первым снятием")

	w.registerRegistry(pcrX)
	w.withdrawX()

	events = w.unregisteredEvents(pcrX)
	require.Len(t, events, 2, "1020 повтор: событий снятия X после повторной регистрации")
	assert.Equal(t, 0, descendantsIn(events[1]), "1020 повтор: X без потомков назвал снятых потомков")
}
