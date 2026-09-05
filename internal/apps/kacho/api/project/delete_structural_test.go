// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package project

// delete_structural_test.go — снятие проекта снимает и его структурные кортежи.
//
// # Предмет
//
// Создание проекта СО-КОММИТИТ два структурных кортежа в той же транзакции, что и
// строку (`create_test.go`, `TestCreateProject_SECL_EmitsHierarchyAndClusterTupleInTx`):
//
//	account:<A>              --account--> project:<P>
//	cluster:cluster_kacho_root --cluster--> project:<P>
//
// Снятие убирало строку и писало запись аудита — и ничего больше. Кортежи
// оставались: и в движке отношений, и в проекции журнала (`relation_fact`), из
// которой цепь областей берёт предка проекта (миграция 781001). То есть проект,
// которого в собственной таблице нет, продолжает существовать в графе прав —
// права переживают свой предмет.
//
// # Почему проба смотрит на НАМЕРЕНИЕ СНЯТИЯ, а не на «метод вызван»
//
// Запись в движок идёт ТОЛЬКО строкой журнала (#789), поэтому эмитированное в
// той же транзакции намерение — и есть наблюдаемое снятие: доедет оно
// поголовным дренажом. Утверждение «doDelete отработал» на этом дефекте зеленело
// бы полностью: строка удалялась, аудит писался, ошибок ноль.
//
// # Отрицание стоит В ПАРЕ с положительным контролем
//
// Вторая проба требует, чтобы путь снятия НЕ писал кортежей (`EmitFGARelationWrite`
// пуст). Без неё первая зеленела бы и на реализации, которая на снятии эмитирует
// всё подряд, — то есть на пути, воскрешающем удалённый проект в графе.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// deleteProjectFixture — репозиторий с уже существующим проектом под acc-A000000000000000.
func deleteProjectFixture(t *testing.T) (*fakeProjRepo, *DeleteProjectUseCase) {
	t.Helper()
	repo := newFakeProjRepo()
	repo.currentAccID = domain.AccountID("acc0000000000000abcd")
	return repo, NewDeleteProjectUseCase(repo, newFakeOpsRepoProj())
}

func runDelete(t *testing.T, uc *DeleteProjectUseCase, id string) {
	t.Helper()
	op, err := uc.Execute(operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "test-principal"}), domain.ProjectID(id))
	require.NoError(t, err)
	require.NotNil(t, op)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(ctx))
}

func hasTuple(tuples []service.RelationTuple, user, relation, object string) bool {
	for _, tp := range tuples {
		if tp.User == user && tp.Relation == relation && tp.Object == object {
			return true
		}
	}
	return false
}

// TestDeleteProject_EmitsStructuralTupleDeletesInTx — снятие проекта снимает оба
// структурных кортежа, и снимает их В ТОЙ ЖЕ транзакции, что и строку.
func TestDeleteProject_EmitsStructuralTupleDeletesInTx(t *testing.T) {
	repo, uc := deleteProjectFixture(t)
	const id = "prj0000000000000abcd"

	runDelete(t, uc, id)

	deletes := repo.fgaDeletes()
	assert.True(t,
		hasTuple(deletes, "account:acc0000000000000abcd", "account", "project:"+id),
		"указатель проекта на аккаунт пережил снятие: цепь областей (781001) берёт "+
			"предка проекта из проекции журнала, и выдача на аккаунт продолжит доходить "+
			"до объектов под проектом, которого нет")
	assert.True(t,
		hasTuple(deletes, "cluster:cluster_kacho_root", "cluster", "project:"+id),
		"указатель проекта на кластер пережил снятие: удалённый проект остаётся под "+
			"администратором облака")
}

// TestDeleteProject_DoesNotWriteTuples — положительный контроль к пробе выше:
// путь снятия кортежей НЕ пишет.
func TestDeleteProject_DoesNotWriteTuples(t *testing.T) {
	repo, uc := deleteProjectFixture(t)

	runDelete(t, uc, "prj0000000000000abce")

	assert.Empty(t, repo.fgaTuples(),
		"путь снятия эмитировал намерение ЗАПИСИ — удалённый проект воскресает в графе прав")
}
