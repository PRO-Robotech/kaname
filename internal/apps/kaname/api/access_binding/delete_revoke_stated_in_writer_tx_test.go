// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// delete_revoke_stated_in_writer_tx_test.go — WHEN the revoke set is stated, and why
// that instant is the whole contract.
//
// # Норма
//
// Отзыв обязан быть заявлен ВНУТРИ той же транзакции, что снимает привязку: строка
// журнала `kaname.fga_outbox` попадает в проекцию `kaname.relation_fact`
// триггером `relation_fact_follows_journal` (миграции 0098/0100) — В ТОЙ ЖЕ
// транзакции. Значит отказ действует НА КОММИТЕ, то есть заведомо раньше, чем
// Operation становится done, и откат вызывающей транзакции снимает оба следа сразу.
//
// # Что здесь стояло раньше, и почему предмет пробы уцелел, а её механизм — нет
//
// Файл назывался delete_sync_removal_test.go и утверждал другое: что после коммита
// тот же набор СИНХРОННО удаляется из внешнего движка через
// clients.RelationStore.DeleteTuples, — потому что очередь к движку отставала, и без
// этого второго прохода отказ ждал дренаж. У этого утверждения больше нет предмета:
// движок снят (стадия S6), порт `DeleteTuples` не несёт, и удалять некуда.
//
// Счётчик, считавший вызовы снятого метода, остался бы БЕЗ ПРОИЗВОДИТЕЛЯ:
// «набор удалён синхронно» было бы ложно всегда, а «набор не удалён» — истинно по
// построению типа дублёра. Такая проба хуже отсутствующей.
//
// Живое свойство — то же самое: ОТКАЗ ДЕЙСТВУЕТ К МОМЕНТУ Operation done. Изменился
// механизм, которым оно достигается, и вместе с ним — то, что надо утверждать: не
// «после коммита позвали снятие», а «до коммита заявлен отзыв». Второе строже:
// пост-коммитный проход мог упасть и оставить привязку снятой при живых правах, а
// заявление внутри транзакции либо доезжает вместе с ней, либо откатывается вместе
// с ней.
//
// # Что снято вместе со своим предметом
//
// Рядом жила проба delete_sync_removal_retry_test.go: она требовала, чтобы воркёр
// ПОВТОРЯЛ пост-коммитное снятие через транзиентный отказ движка. Повторять нечего и
// не нужно: заявление идёт одним оператором внутри транзакции, и его отказ роняет
// транзакцию целиком, а не оставляет расхождение, которое надо догонять повторами.
// Мотив той пробы сохранён здесь, чтобы его не пришлось выводить заново: отзыв
// обязан быть НАДЁЖЕН как выдача, иначе отказ откладывается на отстающий путь.
// Сегодня надёжность даёт атомарность, а не повтор.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// indexOfTxOp returns the position of an exact writer-tx trace mark, or -1.
func indexOfTxOp(trace []string, want string) int {
	for i, got := range trace {
		if got == want {
			return i
		}
	}
	return -1
}

// TestDeleteAccessBinding_RevokeSetIsStatedBeforeTheWriterTxCommits — the revoke set
// is stated INSIDE the transaction, it is byte-symmetric to the granted set, and both
// facts hold by the time the Operation reports done.
func TestDeleteAccessBinding_RevokeSetIsStatedBeforeTheWriterTxCommits(t *testing.T) {
	const (
		roleID     = "rol_viewer_sync_001"
		roleName   = "kacho.view"
		subjectID  = "usr_sync_subject"
		resourceID = "prj_sync_project"
		ownerID    = "usr_sync_owner"
		accountID  = "acc_sync_account"
	)

	perms := domain.Permissions{"iam.access_bindings.get", "iam.access_bindings.list"}
	repo := newABFakeRepo(ownerID, accountID, resourceID, roleID, roleName, perms)
	opsRepo := newFakeOpsRepo()
	fga := newRecordingFGA()
	ctx := newOwnerContext(ownerID)

	// ── Grant ───────────────────────────────────────────────────────────────
	createUC := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(fga, nil)
	binding := domain.AccessBinding{
		SubjectType:  "user",
		SubjectID:    domain.SubjectID(subjectID),
		RoleID:       domain.RoleID(roleID),
		ResourceType: "project",
		ResourceID:   resourceID,
	}
	_, err := createUC.Execute(ctx, binding)
	require.NoError(t, err, "Create.Execute must succeed")

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx), "async Create worker must complete")

	written := repo.drainFGAWritten()
	require.GreaterOrEqual(t, len(written), 2,
		"Create must state ≥2 journal tuples (role-relation + hierarchy)")

	abID := repo.lastInsertedID()
	require.NotEmpty(t, abID)

	// Only the revoke's transaction is the subject: drop the grant's marks.
	repo.resetTxOpTrace()

	// ── Revoke ──────────────────────────────────────────────────────────────
	deleteUC := NewDeleteAccessBindingUseCase(repo, opsRepo).WithRelationStore(fga, nil)
	_, err = deleteUC.Execute(newOwnerContext(subjectID), abID)
	require.NoError(t, err, "Delete.Execute must succeed")

	waitCtx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	require.NoError(t, operations.Wait(waitCtx2), "async Delete worker must complete")

	// CORE 1 — ORDER. The revoke is stated before the transaction closes, so the
	// projection into the fact table happens inside it and the deny is effective at
	// the commit.
	trace := repo.txOpTrace()
	emitted := indexOfTxOp(trace, "emit_relation_delete")
	committed := indexOfTxOp(trace, "commit")
	require.GreaterOrEqual(t, emitted, 0,
		"the revoke set was never stated in the writer-tx (trace: %v) — with no journal row "+
			"there is nothing for the trigger to fold into the fact table, so the grant survives "+
			"its own binding", trace)
	require.GreaterOrEqual(t, committed, 0,
		"the writer-tx never committed (trace: %v)", trace)
	assert.Less(t, emitted, committed,
		"the revoke set must be stated BEFORE the writer-tx commits (trace: %v). Stated after, it "+
			"is a second write that can be lost on its own — which is exactly the gap the removed "+
			"post-commit removal had to be retried past", trace)

	// CORE 2 — SET. What is stated is byte-symmetric to what the grant stated: a
	// revoke removing a different set would leave access behind or strip access it
	// never gave.
	revoked := repo.drainFGADeleted()
	require.Equal(t, len(written), len(revoked),
		"the revoke set must have exactly as many tuples as the grant stated")
	for _, w := range written {
		assert.Contains(t, revoked, w,
			"the revoke must state tuple {User:%q Relation:%q Object:%q} granted at Create",
			w.User, w.Relation, w.Object)
	}
}
