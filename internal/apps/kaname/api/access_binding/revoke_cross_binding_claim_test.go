// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// revoke_cross_binding_claim_test.go — СНЯТИЕ ОДНОЙ ВЫДАЧИ НЕ СНИМАЕТ ДОСТУП,
// КОТОРЫЙ ДАЁТ ДРУГАЯ ДЕЙСТВУЮЩАЯ ВЫДАЧА (access-loss regression) — и где это
// правило теперь живёт.
//
// ДЕФЕКТ (наблюдался вживую). Реестр выпущенных кортежей
// (kaname.access_binding_emitted_tuples) ключуется ВЫДАЧЕЙ (binding_id, fga_user,
// relation, object), а факт, по которому решается доступ, счётчика не несёт — одна
// строка на (объект, отношение, субъект). Две выдачи ОДНОМУ субъекту на ОДНУ
// область держат ДВЕ строки реестра на ОДИН факт, и снятие, снимавшее факт по своему
// реестру дословно, снимало доступ, который другая, ДЕЙСТВУЮЩАЯ, выдача даёт.
//
// ГДЕ ПРАВИЛО. Прежде use-case вычитал из своего набора кортежи, которые ещё держит
// другая действующая выдача, — чтением ведомостей соседей на снимке своей
// транзакции до вставки строки снятия. Ответ устаревал раньше, чем применялся:
// вторая выдача, зафиксированная между чтением и вставкой, теряла факт, а два
// снятия, читавшие друг друга живыми, оба оставляли факт без держателя
// (kaname#919). Вопрос о держателях задаёт теперь свёртка строки снятия — под
// замком строки факта, свежим снимком (миграция 20261019180000).
//
// Отсюда контракт use-case, который судит этот файл: снятие ЖУРНАЛИРУЕТ ВЕСЬ свой
// реестр, общий кортеж — тоже; удержание общего факта — свойство базы, и держат
// его пробы на настоящей базе:
//   - shared_tuple_teardown_race_integration_test.go — SD-919-N1 (последовательно,
//     отзыв и удаление), DB-919-A (вторая выдача между решением и строкой снятия),
//     DB-919-B (оба держателя сняты до коммита соседа), SD-919-W, SD-919-C;
//   - repo/kaname/pg/access_binding_cross_binding_claim_integration_test.go —
//     держит лишь ведомость ДЕЙСТВУЮЩЕЙ выдачи.
// Фейк здесь базы не моделирует, поэтому утверждать «общий кортеж не назван» он
// мог бы лишь о снятом механизме.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
	ab_repo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// crossClaimFixture grants one binding and returns the tuple-set it emitted,
// split into the scope-anchor role-relation tuples (the cross-binding SHARED
// class — another binding of the same subject on the same scope emits exactly
// these) and the binding-private hierarchy parent-pointer (object
// iam_access_binding:<id>, unique to this binding — never shared).
type crossClaimFixture struct {
	repo      *abFakeRepo
	opsRepo   *fakeOpsRepo
	fga       *recordingFGA
	bindingID domain.AccessBindingID
	shared    []ab_repo.RelationTuple
	private   []ab_repo.RelationTuple
	subjectID string
}

func newCrossClaimFixture(t *testing.T) crossClaimFixture {
	t.Helper()
	const (
		roleID     = "rol_edit_cross_claim"
		roleName   = "kaname.edit"
		subjectID  = "usr_cross_claim_subj"
		resourceID = "prj_cross_claim_proj"
		ownerID    = "usr_cross_claim_owne"
		accountID  = "acc_cross_claim_acco"
	)
	perms := domain.Permissions{
		"iam.access_bindings.get",
		"iam.access_bindings.list",
		"iam.access_bindings.update",
	}
	f := crossClaimFixture{
		repo:      newABFakeRepo(ownerID, accountID, resourceID, roleID, roleName, perms),
		opsRepo:   newFakeOpsRepo(),
		fga:       newRecordingFGA(),
		subjectID: subjectID,
	}
	createUC := NewCreateAccessBindingUseCase(f.repo, f.opsRepo, catalogfixture.Source()).WithRelationStore(f.fga, nil)
	_, err := createUC.Execute(newOwnerContext(ownerID), domain.AccessBinding{
		SubjectType:  "user",
		SubjectID:    domain.SubjectID(subjectID),
		RoleID:       domain.RoleID(roleID),
		ResourceType: "project",
		ResourceID:   resourceID,
	})
	require.NoError(t, err, "Create.Execute must succeed")

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx), "async Create worker must complete")

	for _, tup := range f.repo.drainFGAWritten() {
		if strings.HasPrefix(tup.Object, "iam_access_binding:") {
			f.private = append(f.private, tup)
			continue
		}
		f.shared = append(f.shared, tup)
	}
	require.NotEmpty(t, f.shared, "grant must emit scope-anchor role-relation tuples")
	require.NotEmpty(t, f.private, "grant must emit the binding-private hierarchy parent-pointer")

	f.bindingID = f.repo.lastInsertedID()
	require.NotEmpty(t, f.bindingID)
	// The fake Insert stores the row verbatim; the real table DEFAULTs status to
	// ACTIVE. Stamp it so the soft-revoke CAS (`… WHERE status='ACTIVE'`) behaves as
	// it does against Postgres.
	f.repo.mu.Lock()
	f.repo.ab.Status = domain.AccessBindingStatusActive
	f.repo.mu.Unlock()
	return f
}

// assertWholeLedgerJournaled — набор строк снятия, который use-case КЛАДЁТ в
// журнал своей writer-tx, — это весь реестр выдачи: и кортежи якоря области (те,
// что другая выдача того же субъекта выпускает дословно), и личный указатель
// иерархии. Пустой набор — отказ, а не тихий успех: «ничего не названо» иначе
// проходило бы любую проверку на непустое пересечение.
func assertWholeLedgerJournaled(t *testing.T, f crossClaimFixture, verb string) {
	t.Helper()

	revoked := f.repo.drainFGADeleted()
	want := append(append([]ab_repo.RelationTuple{}, f.shared...), f.private...)
	require.Len(t, revoked, len(want),
		"%s must journal its WHOLE emitted set — retaining a shared fact is the fold's decision, not the use-case's", verb)
	for _, w := range want {
		assert.Contains(t, revoked, w,
			"%s must journal {User:%q Relation:%q Object:%q} — the fold under the fact-row lock decides whether another ACTIVE binding still holds it",
			verb, w.User, w.Relation, w.Object)
	}
}

// TestDeleteAccessBinding_JournalsTheWholeEmittedSet — удаление: строка выдачи
// уходит, строки снятия — на весь её реестр.
func TestDeleteAccessBinding_JournalsTheWholeEmittedSet(t *testing.T) {
	f := newCrossClaimFixture(t)

	deleteUC := NewDeleteAccessBindingUseCase(f.repo, f.opsRepo).WithRelationStore(f.fga, nil)
	_, err := deleteUC.Execute(newOwnerContext(f.subjectID), f.bindingID)
	require.NoError(t, err, "Delete.Execute must succeed")

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx), "async Delete worker must complete")

	assertWholeLedgerJournaled(t, f, "Delete")
}

// TestRevokeAccessBinding_JournalsTheWholeEmittedSet — отзыв (строка остаётся,
// статус ACTIVE→REVOKED) называет тот же набор: пути различаются лишь тем, остаётся
// ли строка, но не тем, какие кортежи названы.
func TestRevokeAccessBinding_JournalsTheWholeEmittedSet(t *testing.T) {
	f := newCrossClaimFixture(t)

	revokeUC := NewRevokeAccessBindingUseCase(f.repo, f.opsRepo).WithRelationStore(f.fga, nil)
	_, err := revokeUC.Execute(newOwnerContext(f.subjectID), f.bindingID)
	require.NoError(t, err, "Revoke.Execute must succeed")

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx), "async Revoke worker must complete")

	assertWholeLedgerJournaled(t, f, "Revoke")
}
