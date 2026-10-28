// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// mirror_lock_test.go — строка зеркала объекта, по которому проход пишет член,
// запирается до первой записи прохода, и член по объекту, чья строка снята между
// чтением отбора и замком, не пишется (PRO-Robotech/kaname#975).
//
// Что из этого следует на живой базе против настоящего снятия регистрации,
// утверждают пробы мира `unregister_mirror_read_order_world_integration_test.go`;
// здесь — свойство кода прохода: порядок замка и судьба члена по выбывшему
// объекту на каждом из трёх путей записи (полный проход выдачи, аддитивный проход
// выдачи, проход по объекту).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// mirrorLockStore — выдача на проект с правилом-якорем над экземплярами и двумя
// экземплярами в зеркале; `gone` — экземпляр, чья строка снята между чтением
// отбора и замком.
func mirrorLockStore(gone string) *fakeStore {
	fp := domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}}.Fingerprint()
	f := &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		selectors: []domain.RuleSelector{{
			Arm: domain.ArmAnchor, RuleFP: fp,
			ObjectTypes: []string{"compute.instance"},
			Verbs:       []string{"get"},
		}},
		mirror: map[string][]domain.MirrorObject{
			"compute.instance": {
				{ObjectType: "compute.instance", ObjectID: "i-1", ParentProjectID: "prj-1"},
				{ObjectType: "compute.instance", ObjectID: "i-2", ParentProjectID: "prj-1"},
			},
		},
		selectorBindings: []domain.AccessBindingID{"acb-1"},
	}
	if gone != "" {
		f.vanished = map[MemberCoord]bool{{ObjectType: "compute.instance", ObjectID: gone}: true}
	}
	return f
}

func upsertedObjects(f *fakeStore) []string {
	var out []string
	for _, m := range f.upserts {
		out = append(out, m.ObjectID)
	}
	return out
}

// Полный проход выдачи: член по выбывшему объекту не пишется, по живому — пишется;
// замок строки зеркала взят до первой записи.
func TestReconcileBinding_NewMemberOnVanishedObjectIsNotWritten(t *testing.T) {
	f := mirrorLockStore("i-2")
	rec := New(fakeRunner{s: f}, nil, catalogfixture.Source())
	require.NoError(t, rec.ReconcileBinding(context.Background(), "acb-1"))

	assert.Equal(t, []string{"i-1"}, upsertedObjects(f), "член пишется только по объекту, чья строка зеркала есть")
	assert.False(t, hasTuple(allWrites(f), "v_get", "compute_instance:i-2"), "кортеж по выбывшему объекту записан")
	assert.ElementsMatch(t, []MemberCoord{
		{ObjectType: "compute.instance", ObjectID: "i-1"}, {ObjectType: "compute.instance", ObjectID: "i-2"},
	}, f.mirrorLocks, "строки зеркала обоих объектов новых членов запираются")
	assert.Empty(t, f.mirrorLocksAfterFirstWrite, "строка зеркала запирается до первой записи прохода")
}

// Близнец: без выбывшего объекта полный проход пишет оба члена.
func TestReconcileBinding_NewMembersOnLiveObjectsAreWritten(t *testing.T) {
	f := mirrorLockStore("")
	rec := New(fakeRunner{s: f}, nil, catalogfixture.Source())
	require.NoError(t, rec.ReconcileBinding(context.Background(), "acb-1"))

	assert.ElementsMatch(t, []string{"i-1", "i-2"}, upsertedObjects(f), "оба члена по живым объектам")
}

// Полный проход выдачи с уже записанным членом: член без записи замка не берёт
// (периодическое сведение не платит замком за каждый объект области).
func TestReconcileBinding_UnchangedMemberTakesNoMirrorLock(t *testing.T) {
	f := mirrorLockStore("")
	rec := New(fakeRunner{s: f}, nil, catalogfixture.Source())
	require.NoError(t, rec.ReconcileBinding(context.Background(), "acb-1"))
	require.Len(t, f.upserts, 2, "контроль: первый проход записал оба члена")
	f.current = append([]domain.TargetMember(nil), f.upserts...)
	f.upserts, f.mirrorLocks = nil, nil

	require.NoError(t, rec.ReconcileBinding(context.Background(), "acb-1"))
	assert.Empty(t, f.upserts, "повторный проход по неизменившейся выдаче ничего не пишет")
	assert.Empty(t, f.mirrorLocks, "повторный проход без записи не запирает строки зеркала")
}

// Аддитивный проход выдачи: член по выбывшему объекту не пишется — ни строкой
// члена, ни записью реестра, ни кортежем журнала.
func TestReconcileBindingForward_NewMemberOnVanishedObjectIsNotWritten(t *testing.T) {
	f := mirrorLockStore("i-2")
	rec := New(fakeRunner{s: f}, nil, catalogfixture.Source())
	require.NoError(t, rec.ReconcileBindingForward(context.Background(), "acb-1"))

	assert.Equal(t, []string{"i-1"}, upsertedObjects(f), "член пишется только по объекту, чья строка зеркала есть")
	w := allWrites(f)
	assert.True(t, hasTuple(w, "v_get", "compute_instance:i-1"), "контроль: кортеж по живому объекту записан")
	assert.False(t, hasTuple(w, "v_get", "compute_instance:i-2"), "кортеж по выбывшему объекту записан")
	for _, batch := range f.recorded {
		for _, row := range batch {
			assert.NotEqual(t, "i-2", row.Member.ObjectID, "запись реестра по выбывшему объекту")
		}
	}
	assert.Empty(t, f.mirrorLocksAfterFirstWrite, "строка зеркала запирается до первой записи прохода")
}

// Проход по объекту: строка объекта, снятая после чтения отбора, под замком не
// найдена — аддитивный проход не пишет ничего.
func TestReconcileObjectForward_VanishedObjectWritesNothing(t *testing.T) {
	f := mirrorLockStore("i-1")
	rec := New(fakeRunner{s: f}, nil, catalogfixture.Source())
	require.NoError(t, rec.ReconcileObjectForward(context.Background(), "compute.instance", "i-1"))

	assert.Empty(t, f.upserts, "член по выбывшему объекту записан")
	assert.Empty(t, allWrites(f), "кортеж по выбывшему объекту записан")
	assert.Contains(t, f.mirrorLocks, MemberCoord{ObjectType: "compute.instance", ObjectID: "i-1"},
		"строка объекта запирается перед записью")
}

// Полный проход по объекту: строка объекта запирается после выдач и ролей и до
// первой записи — тот же порядок родов, что у снятия регистрации.
func TestReconcileObject_ObjectRowLockedBeforeAnyWrite(t *testing.T) {
	f := mirrorLockStore("")
	f.bindingsForObject = []domain.AccessBindingID{"acb-1"}
	rec := New(fakeRunner{s: f}, nil, catalogfixture.Source())
	require.NoError(t, rec.ReconcileObject(context.Background(), "compute.instance", "i-1"))

	require.True(t, f.wrote, "контроль: проход обязан что-то записать")
	require.NotEmpty(t, f.rowLocks, "контроль: выдачи и роли заперты")
	assert.Contains(t, f.mirrorLocks, MemberCoord{ObjectType: "compute.instance", ObjectID: "i-1"},
		"строка объекта запирается")
	assert.Empty(t, f.mirrorLocksAfterFirstWrite, "строка объекта запирается до первой записи прохода")
}
