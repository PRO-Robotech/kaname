// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// role_tuple_reconciler_journal_test.go — веер правки роли кладёт журнал ОДНИМ набором.
//
// Каждый вызов журнала — отдельный проход триггера по строкам прямого факта, в своём
// порядке. Транзакция, положившая журнал двумя вызовами (снятое, потом выданное, —
// и так по каждой выдаче роли), берёт строки факта в порядке вызовов, который не делит
// ни один другой писатель; встречная транзакция берёт их в каноническом порядке, и база
// снимает одну из сторон отказом 40P01 (разбор и пробы на базе —
// delete_sibling_full_pass_deadlock_integration_test.go). Поэтому проба утверждает число
// вызовов: оно и есть предмет, а не подробность реализации.
//
// Состав утверждается рядом: один вызов, потерявший половину набора, был бы хуже двух.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	ab_repo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

func TestRoleTupleReconciler_FoldsTheJournalOnce(t *testing.T) {
	const ownerID, accountID, projectID = "usr_owner_rtrj------", "acc_rtrj------------", "prj_rtrj------------"
	repo := newABFakeRepo(ownerID, accountID, projectID, roleID178b, "viewer",
		domain.Permissions{"compute.instance.*.get"})
	bid := seedAccountBinding(repo, accountID, roleID178b, false)

	// Хранимый набор выдачи несёт кортеж, которого новая роль не выводит: правка роли
	// обязана его СНЯТЬ — и одновременно ВЫДАТЬ то, что выводит новая роль.
	stale := ab_repo.RelationTuple{User: "user:usr_some_subject01--", Relation: "viewer", Object: "account:" + accountID}
	w, err := repo.Writer(context.Background())
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().InsertEmittedTuples(context.Background(), bid, []ab_repo.RelationTuple{stale}))

	newRole := domain.Role{
		ID: roleID178b, AccountID: domain.AccountID(accountID), Name: "viewer",
		Rules: domain.Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}}},
	}
	b := *repo.ab
	want := buildBindingTuples(b, newRole)
	require.NotEmpty(t, want, "контроль: новая роль выводит набор — правке есть что выдать")
	require.NotContains(t, want, stale, "контроль: хранимый кортеж новой ролью не выводится — правке есть что снять")

	require.NoError(t, NewRoleTupleReconciler().ReconcileRoleTuples(context.Background(), w, roleID178b, newRole))

	repo.mu.Lock()
	defer repo.mu.Unlock()
	assert.Equal(t, 1, repo.journalFolds,
		"снятое и выданное — один набор транзакции: два вызова берут строки факта в порядке вызовов, "+
			"которого не делит встречный писатель")
	assert.ElementsMatch(t, want, repo.fgaWritten, "выдано ровно то, что выводит новая роль")
	assert.ElementsMatch(t, []ab_repo.RelationTuple{stale}, repo.fgaDeleted, "снято ровно то, что новая роль не выводит")
}
