// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// role_tuple_reconciler_multi_subject_test.go — сверка кортежей уровня выдачи
// при смене роли судит КАЖДОГО субъекта выдачи (kaname#880, Н2 ревью).
//
// Создание выпускает кортежи уровня выдачи на каждого субъекта (create.go);
// сверка при смене роли строила новую сторону сравнения из одиночной пары
// строки выдачи — проекции первого субъекта. Тогда кортежи субъектов со
// второго по N-й попадали в «снятые», даже если ярус роли не менялся.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
	ab_repo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// rtrMultiSubjectGrant заводит выдачу роли «только разрешения» `perms` на
// аккаунт перечню `subjects` и возвращает репозиторий-двойник.
func rtrMultiSubjectGrant(t *testing.T, roleID string, perms domain.Permissions, subjects ...domain.Subject) *abFakeRepo {
	t.Helper()
	const (
		ownerID   = "usr_rtr_owner-------"
		accountID = "acc_rtr_account-----"
	)
	repo := newABFakeRepo(ownerID, accountID, accountID, roleID, "viewer", perms)
	opsRepo := newFakeOpsRepo()
	uc := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(newRecordingFGA(), nil)
	op, err := uc.Execute(newOwnerContext(ownerID), domain.AccessBinding{
		RoleID: domain.RoleID(roleID), ResourceType: "account", ResourceID: accountID, Subjects: subjects,
	})
	require.NoError(t, err)
	require.NotNil(t, op)
	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))
	return repo
}

// rtrReconcile — сверка кортежей выдач роли под ролью `perms`.
func rtrReconcile(t *testing.T, repo *abFakeRepo, roleID string, perms domain.Permissions) {
	t.Helper()
	w, err := repo.Writer(context.Background())
	require.NoError(t, err)
	require.NoError(t, NewRoleTupleReconciler().ReconcileRoleTuples(context.Background(), w, domain.RoleID(roleID),
		domain.Role{ID: domain.RoleID(roleID), Permissions: perms}))
}

func rtrEmitted(t *testing.T, repo *abFakeRepo) []ab_repo.RelationTuple {
	t.Helper()
	rd, err := repo.Reader(context.Background())
	require.NoError(t, err)
	got, err := rd.AccessBindings().SelectEmittedTuples(context.Background(), repo.lastInsertedID())
	require.NoError(t, err)
	return got
}

// TestRoleTupleReconcile_MultiSubject_UnchangedTierKeepsEverySubject — ярус роли
// не меняется: сверка не снимает ни одного кортежа и реестр выпущенного
// сохраняет кортежи каждого субъекта. Близнец — выдача одному субъекту.
func TestRoleTupleReconcile_MultiSubject_UnchangedTierKeepsEverySubject(t *testing.T) {
	const roleID = "rol00000000000rtr01a"
	perms := domain.Permissions{"iam.access_bindings.get", "iam.access_bindings.list"}
	userA := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_rtr_a-----------"}
	userB := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_rtr_b-----------"}
	for _, tc := range []struct {
		name     string
		subjects []domain.Subject
	}{
		{"[A,B]", []domain.Subject{userA, userB}},
		{"[B,A]", []domain.Subject{userB, userA}},
		{"близнец [A]", []domain.Subject{userA}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := rtrMultiSubjectGrant(t, roleID, perms, tc.subjects...)
			before := rtrEmitted(t, repo)
			for _, s := range tc.subjects {
				require.Contains(t, before, ab_repo.RelationTuple{
					User: "user:" + string(s.ID), Relation: "viewer", Object: "account:acc_rtr_account-----",
				}, "контроль: создание выпустило кортеж яруса субъекту %s", s.ID)
			}
			repo.drainFGAWritten()

			rtrReconcile(t, repo, roleID, perms)

			assert.Empty(t, repo.drainFGADeleted(), "ярус не менялся — сверка не снимает ни одного кортежа")
			assert.ElementsMatch(t, before, rtrEmitted(t, repo), "реестр выпущенного не изменился")
		})
	}
}

// TestRoleTupleReconcile_MultiSubject_TierChangeReachesEverySubject — ярус роли
// меняется (чтение → правка): прежний кортеж снят и новый выпущен КАЖДОМУ
// субъекту выдачи, при любом их порядке.
func TestRoleTupleReconcile_MultiSubject_TierChangeReachesEverySubject(t *testing.T) {
	const roleID = "rol00000000000rtr01b"
	readPerms := domain.Permissions{"iam.role.read"}
	writePerms := domain.Permissions{"iam.role.read", "iam.role.write"}
	userA := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_rtr_a-----------"}
	userB := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_rtr_b-----------"}
	for _, order := range [][]domain.Subject{{userA, userB}, {userB, userA}} {
		t.Run(string(order[0].ID), func(t *testing.T) {
			repo := rtrMultiSubjectGrant(t, roleID, readPerms, order...)
			repo.drainFGAWritten()

			rtrReconcile(t, repo, roleID, writePerms)

			written, deleted := repo.drainFGAWritten(), repo.drainFGADeleted()
			emitted := rtrEmitted(t, repo)
			for _, s := range order {
				viewer := ab_repo.RelationTuple{User: "user:" + string(s.ID), Relation: "viewer", Object: "account:acc_rtr_account-----"}
				editor := ab_repo.RelationTuple{User: "user:" + string(s.ID), Relation: "editor", Object: "account:acc_rtr_account-----"}
				assert.Contains(t, deleted, viewer, "прежний ярус снят субъекту %s", s.ID)
				assert.Contains(t, written, editor, "новый ярус выпущен субъекту %s", s.ID)
				assert.Contains(t, emitted, editor, "реестр несёт новый ярус субъекта %s", s.ID)
				assert.NotContains(t, emitted, viewer, "реестр не несёт прежний ярус субъекта %s", s.ID)
			}
		})
	}
}
