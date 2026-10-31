// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// unregister_resource_descendants_test.go — граница снятия потомков (kaname#1002):
// потомки уходят только за снятием, удалившим строку родителя, и только потомки
// того же модуля. Сквозной исход (зеркало, цепь, отношения, выдачи) судит мировая
// проба `access_binding/unregister_cascades_descendants_world_integration_test.go`;
// здесь — решение use-case, которое база не видит.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// noDescendants — у двойника зеркала потомков нет: пробы, которые его встраивают,
// судят не снятие потомков.
type noDescendants struct{}

func (noDescendants) DescendantsTx(context.Context, service.Tx, string, string) ([]service.RegisteredDescendant, error) {
	return nil, nil
}

func (noDescendants) DropRegistrationTx(context.Context, service.Tx, string, string, string) (bool, time.Time, error) {
	return false, time.Time{}, nil
}

// descendantMirror — двойник зеркала: родитель снимается (или нет — `parentGone`),
// потомки отдаются заданным списком, снятые записываются. Как и настоящее
// зеркало, снятие потомка убирает его цепь: следующее чтение перечня его не
// называет.
type descendantMirror struct {
	mirrorAdapter
	parentGone  bool
	descendants []service.RegisteredDescendant
	asked       int
	parentDels  int
	dropped     []string
	droppedIDs  map[string]bool
	// removedMeanwhile — потомки, чью строку зеркала уже убрал встречный вызов:
	// в перечне они есть, а снятие их строки ничего не удаляет (kaname#1020).
	removedMeanwhile map[string]bool
}

func (m *descendantMirror) DeleteTx(context.Context, service.Tx, string, string, time.Time) (bool, error) {
	m.parentDels++
	return m.parentGone, nil
}

func (m *descendantMirror) DescendantsTx(context.Context, service.Tx, string, string) ([]service.RegisteredDescendant, error) {
	m.asked++
	var out []service.RegisteredDescendant
	for _, d := range m.descendants {
		if !m.droppedIDs[d.ID] {
			out = append(out, d)
		}
	}
	return out, nil
}

func (m *descendantMirror) DropRegistrationTx(_ context.Context, _ service.Tx, catalogType, _ string, id string) (bool, time.Time, error) {
	m.dropped = append(m.dropped, catalogType+"/"+id)
	if m.droppedIDs == nil {
		m.droppedIDs = map[string]bool{}
	}
	m.droppedIDs[id] = true
	return !m.removedMeanwhile[id], time.Time{}, nil
}

// withdrawnKeys — ключи, чьи выдачи отозваны, строками «тип/id».
func withdrawnKeys(w *recordingWithdrawal) []string {
	out := make([]string, 0, len(w.keys))
	for _, k := range w.keys {
		out = append(out, k.Type+"/"+k.ID)
	}
	return out
}

// deletedTuples — снятые кортежи строками «субъект отношение объект».
func deletedTuples(e *recordingEmitter) []string {
	var out []string
	for _, batch := range e.deletes {
		for _, tu := range batch {
			out = append(out, tu.User+" "+tu.Relation+" "+tu.Object)
		}
	}
	return out
}

// registryDescendants — потомки реестра: репозиторий своего модуля и объект
// чужого модуля, чья цепь тоже называет реестр.
func registryDescendants() []service.RegisteredDescendant {
	return []service.RegisteredDescendant{
		{ModelType: "registry_repository", ID: "reg1/app", Standing: []service.RelationTuple{
			{User: "registry_registry:reg1", Relation: "parent", Object: "registry_repository:reg1/app"},
			{User: "user:usr_owner", Relation: "owner", Object: "registry_repository:reg1/app"},
		}},
		{ModelType: "vpc_network", ID: "vpcn_foreign"},
	}
}

func unregisterRegistry(t *testing.T, m *descendantMirror, w *recordingWithdrawal, e *recordingEmitter) {
	t.Helper()
	uc := NewRegisterResourceUseCase(e, m, &smTxBeginner{}, seededCatalogTypes{}, &recordingPublisher{}, w, noAudit{}, unitScopes())
	require.NoError(t, uc.Unregister(context.Background(), &unregReq{
		subject: "project:prj_a", relation: "project", object: "registry_registry:reg1",
		version: time.Now(),
	}))
}

// TestUnregister_DescendantsOfOwnModuleGoWithTheParent — снятие реестра снимает
// репозиторий (регистрацию, отношения, выдачи) и не трогает объект чужого модуля.
func TestUnregister_DescendantsOfOwnModuleGoWithTheParent(t *testing.T) {
	m := &descendantMirror{parentGone: true, descendants: registryDescendants()}
	w := &recordingWithdrawal{}
	e := &recordingEmitter{}

	unregisterRegistry(t, m, w, e)

	assert.Equal(t, []string{"registry.repositories/reg1/app"}, m.dropped,
		"kaname#1002: снят не ровно потомок своего модуля")
	assert.Contains(t, withdrawnKeys(w), "registry.repositories/reg1/app", "kaname#1002: выдачи потомка не отозваны")
	assert.NotContains(t, withdrawnKeys(w), "vpc.network/vpcn_foreign", "kaname#1002: отозваны выдачи объекта чужого модуля")
	assert.Contains(t, deletedTuples(e), "user:usr_owner owner registry_repository:reg1/app",
		"kaname#1002: отношение владельца потомка не снято")
	assert.Contains(t, deletedTuples(e), "registry_registry:reg1 parent registry_repository:reg1/app",
		"kaname#1002: указатель потомка на родителя не снят")
}

// TestUnregister_StaleTombstoneLeavesDescendants — близнец: снятие, не удалившее
// строку родителя (устаревшее надгробие, незарегистрированный ключ), потомков не
// снимает и их выдач не отзывает. Перечень оно читает — до первой записи, когда
// исход удаления строки родителя ещё не известен (kaname#1019), — и ключи
// потомков запирает вместе с ключом родителя.
func TestUnregister_StaleTombstoneLeavesDescendants(t *testing.T) {
	m := &descendantMirror{parentGone: false, descendants: registryDescendants()}
	w := &recordingWithdrawal{}
	e := &recordingEmitter{}

	unregisterRegistry(t, m, w, e)

	assert.Equal(t, 1, m.asked, "kaname#1019: перечень потомков прочитан не один раз до первой записи")
	assert.Empty(t, m.dropped, "kaname#1002: потомки сняты при снятии, не удалившем родителя")
	assert.Empty(t, w.keys, "kaname#1002: выдачи отозваны при снятии, не удалившем родителя")
}

// TestUnregister_LocksParentAndDescendantsBeforeTheFirstWrite — порядок родов
// замков kaname#975 на пути снятия потомков (kaname#1019): ключи родителя и
// потомков своего модуля запираются ОДНИМ вызовом замка, до удаления строки
// родителя, до снятия первого потомка и до первой строки снятия фактов.
func TestUnregister_LocksParentAndDescendantsBeforeTheFirstWrite(t *testing.T) {
	m := &descendantMirror{parentGone: true, descendants: registryDescendants()}
	e := &recordingEmitter{}
	type snapshot struct{ asked, parentDels, dropped, deletes int }
	var at []snapshot
	w := &recordingWithdrawal{}
	w.onLock = func([]domain.ResourceRef) {
		at = append(at, snapshot{m.asked, m.parentDels, len(m.dropped), len(e.deletes)})
	}

	unregisterRegistry(t, m, w, e)

	require.Len(t, w.locked, 1, "kaname#1019: замков выдач и ролей не один")
	assert.Equal(t, []domain.ResourceRef{
		{Type: "registry.registries", ID: "reg1"},
		{Type: "registry.repositories", ID: "reg1/app"},
	}, w.locked[0], "kaname#1019: замок не на родителя и потомка своего модуля")
	assert.Equal(t, snapshot{asked: 1}, at[0],
		"kaname#1019: к замку перечень не прочитан либо запись уже была (строка родителя, потомок, факты)")
	assert.Equal(t, []string{"registry.repositories/reg1/app"}, m.dropped, "kaname#1002: снят не ровно потомок своего модуля")
}

// TestUnregister_LateDescendantIsTakenToo — потомок, зарегистрированный после
// чтения перечня и до снятия строки родителя, снимается тем же вызовом: перечень
// дочитывается после снятия известных потомков, и ключ позднего запирается
// отдельным замком.
func TestUnregister_LateDescendantIsTakenToo(t *testing.T) {
	late := service.RegisteredDescendant{ModelType: "registry_repository", ID: "reg1/late"}
	m := &descendantMirror{parentGone: true, descendants: registryDescendants()}
	w := &recordingWithdrawal{}
	w.onLock = func([]domain.ResourceRef) {
		if len(m.descendants) == 2 {
			m.descendants = append(m.descendants, late)
		}
	}
	e := &recordingEmitter{}

	unregisterRegistry(t, m, w, e)

	assert.Equal(t, []string{"registry.repositories/reg1/app", "registry.repositories/reg1/late"}, m.dropped,
		"kaname#1019: поздний потомок не снят")
	require.Len(t, w.locked, 2, "kaname#1019: ключ позднего потомка не заперт отдельным замком")
	assert.Equal(t, []domain.ResourceRef{{Type: "registry.registries", ID: "reg1"}, {Type: "registry.repositories", ID: "reg1/app"}, {Type: "registry.repositories", ID: "reg1/late"}}, w.locked[1],
		"kaname#1019: повтор не удерживает весь увеличенный план")
	assert.Contains(t, withdrawnKeys(w), "registry.repositories/reg1/late", "kaname#1019: выдачи позднего потомка не отозваны")
}

// recordingAudit — двойник аудита регистрации, запоминающий события.
type recordingAudit struct {
	noAudit
	events []service.AuditEvent
}

func (a *recordingAudit) EmitTx(_ context.Context, _ service.Tx, ev service.AuditEvent) error {
	a.events = append(a.events, ev)
	return nil
}

// unregisteredDescendantsCount — число потомков в единственном событии снятия.
func unregisteredDescendantsCount(t *testing.T, a *recordingAudit) any {
	t.Helper()
	require.Len(t, a.events, 1, "kaname#1020: событий снятия не одно")
	require.Equal(t, AuditEventResourceUnregistered, a.events[0].EventType, "kaname#1020: тип события")
	return a.events[0].Payload["descendants"]
}

// TestUnregister_AuditCountsOnlyDescendantsThisCallRemoved — в перечне два
// потомка своего модуля, строку одного уже убрал встречный вызов: событие снятия
// родителя называет одного снятого потомка (kaname#1020). Близнец — оба живы:
// число два.
func TestUnregister_AuditCountsOnlyDescendantsThisCallRemoved(t *testing.T) {
	two := func() []service.RegisteredDescendant {
		return append(registryDescendants(), service.RegisteredDescendant{ModelType: "registry_repository", ID: "reg1/web"})
	}
	for _, tc := range []struct {
		name    string
		removed map[string]bool
		want    int
	}{
		{"один снят встречным вызовом", map[string]bool{"reg1/app": true}, 1},
		{"близнец: оба живы", nil, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &descendantMirror{parentGone: true, descendants: two(), removedMeanwhile: tc.removed}
			a := &recordingAudit{}
			uc := NewRegisterResourceUseCase(&recordingEmitter{}, m, &smTxBeginner{}, seededCatalogTypes{},
				&recordingPublisher{}, &recordingWithdrawal{}, a, unitScopes())
			require.NoError(t, uc.Unregister(context.Background(), &unregReq{
				subject: "project:prj_a", relation: "project", object: "registry_registry:reg1", version: time.Now(),
			}))
			assert.Equal(t, tc.want, unregisteredDescendantsCount(t, a), "kaname#1020: число снятых потомков в событии")
		})
	}
}
