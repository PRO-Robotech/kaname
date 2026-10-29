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
// потомки отдаются заданным списком, снятые записываются.
type descendantMirror struct {
	mirrorAdapter
	parentGone  bool
	descendants []service.RegisteredDescendant
	asked       int
	dropped     []string
}

func (m *descendantMirror) DeleteTx(context.Context, service.Tx, string, string, time.Time) (bool, error) {
	return m.parentGone, nil
}

func (m *descendantMirror) DescendantsTx(context.Context, service.Tx, string, string) ([]service.RegisteredDescendant, error) {
	m.asked++
	return m.descendants, nil
}

func (m *descendantMirror) DropRegistrationTx(_ context.Context, _ service.Tx, catalogType, _ string, id string) (bool, time.Time, error) {
	m.dropped = append(m.dropped, catalogType+"/"+id)
	return true, time.Time{}, nil
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
	uc := NewRegisterResourceUseCase(e, m, &smTxBeginner{}, seededCatalogTypes{}, &recordingPublisher{}, w, noAudit{})
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
// читает и не снимает.
func TestUnregister_StaleTombstoneLeavesDescendants(t *testing.T) {
	m := &descendantMirror{parentGone: false, descendants: registryDescendants()}
	w := &recordingWithdrawal{}
	e := &recordingEmitter{}

	unregisterRegistry(t, m, w, e)

	assert.Zero(t, m.asked, "kaname#1002: потомки прочитаны при снятии, не удалившем родителя")
	assert.Empty(t, m.dropped, "kaname#1002: потомки сняты при снятии, не удалившем родителя")
	assert.Empty(t, w.keys, "kaname#1002: выдачи отозваны при снятии, не удалившем родителя")
}
