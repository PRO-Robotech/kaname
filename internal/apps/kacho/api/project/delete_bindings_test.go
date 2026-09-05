// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package project

// delete_bindings_test.go — снятие проекта снимает и ВЫДАЧИ, сделанные на него.
//
// # Предмет
//
// `Project.Delete` снимал строку проекта, его структурные кортежи (#791) и писал
// аудит. Сами выдачи — строки `access_bindings` со `resource_type='project'` — не
// трогал никто. Внешнего ключа с `access_bindings` на `projects` нет (комментарий
// в `account/delete.go` это прямо оговаривает), поэтому база за него не доделывает:
// строка остаётся **активной**, её кортежи остаются в движке, а периодический
// реконсайлер продолжает их материализовать.
//
// Наблюдаемое следствие — не гигиена ведомости, а действующая выдача: доступ живёт
// на объект, которого нет, а снять его штатным путём нельзя, потому что область,
// через которую привязку нашли бы, удалена.
//
// # Почему проба смотрит на НАМЕРЕНИЕ СНЯТИЯ, а не на «строка удалена»
//
// Запись в движок идёт ТОЛЬКО строкой журнала (#789), поэтому эмитированное в той
// же транзакции намерение — и есть наблюдаемое снятие. Утверждение «doDelete
// отработал» на этом дефекте зеленело бы полностью: строка проекта удалялась,
// аудит писался, ошибок ноль.
//
// # Симметрия снятия — из ВЕДОМОСТИ, а не из текущей роли
//
// Снимается ровно тот набор, который постановка записала в
// `access_binding_emitted_tuples` (`SelectEmittedTuples`), а не выведенный заново
// из роли: роль могла с тех пор измениться, и повторный вывод снял бы не то, что
// клал. Это дословно тот же приём, что у `AccessBinding.Delete` и у
// `revokeAccountOwnerTuples`.
//
// # Отрицание стоит В ПАРЕ с положительным контролем
//
// Проба «своя привязка снята» без пробы «чужая уцелела» зеленела бы на реализации,
// которая сносит выдачи без разбора области.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	abrepo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/access_binding"
)

const (
	victimProject   = "prj0000000000000v1ct"
	bystanderProjec = "prj0000000000000byst"
)

// seedProjectBinding кладёт в фикстуру выдачу на область (тип, id) вместе с её
// ведомостью выпущенных кортежей.
func seedProjectBinding(f *fakeProjRepo, bindingID, resType, resID string, tuples ...abrepo.RelationTuple) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bindingsByScope == nil {
		f.bindingsByScope = map[string][]domain.AccessBinding{}
		f.bindingLedger = map[domain.AccessBindingID][]abrepo.RelationTuple{}
	}
	key := resType + ":" + resID
	f.bindingsByScope[key] = append(f.bindingsByScope[key], domain.AccessBinding{
		ID:           domain.AccessBindingID(bindingID),
		SubjectType:  domain.SubjectType("user"),
		SubjectID:    domain.SubjectID("usr0000000000000abcd"),
		ResourceType: domain.ResourceType(resType),
		ResourceID:   resID,
		Status:       domain.AccessBindingStatus("ACTIVE"),
	})
	f.bindingLedger[domain.AccessBindingID(bindingID)] = tuples
}

// TestDeleteProject_RevokesItsAccessBindingsInTx — снятие проекта снимает выдачу,
// сделанную НА ЭТОТ проект: и строку, и ровно тот набор кортежей, который значится
// в её ведомости.
func TestDeleteProject_RevokesItsAccessBindingsInTx(t *testing.T) {
	repo, uc := deleteProjectFixture(t)
	seedProjectBinding(repo, "acb0000000000000v1ct", "project", victimProject,
		abrepo.RelationTuple{User: "user:usr0000000000000abcd", Relation: "v_get", Object: "project:" + victimProject},
		abrepo.RelationTuple{User: "user:usr0000000000000abcd", Relation: "v_list", Object: "project:" + victimProject},
	)

	runDelete(t, uc, victimProject)

	deletes := repo.fgaDeletes()
	assert.True(t,
		hasTuple(deletes, "user:usr0000000000000abcd", "v_get", "project:"+victimProject),
		"выдача пережила свой предмет: кортеж v_get на удалённый проект не снят — "+
			"реконсайлер продолжит его материализовать, а снять штатным путём нечем")
	assert.True(t,
		hasTuple(deletes, "user:usr0000000000000abcd", "v_list", "project:"+victimProject),
		"снят не весь набор ведомости: симметрия снятия обязана быть дословной")
	assert.Contains(t, repo.deletedBindings(), domain.AccessBindingID("acb0000000000000v1ct"),
		"строка выдачи осталась ACTIVE на удалённом проекте — периодический реконсайлер "+
			"воскресит её кортежи после любого снятия")
	assert.Equal(t, 1, repo.commits(),
		"снятие проекта обязано быть ОДНОЙ транзакцией: дренаж выдач, удаление строки и "+
			"снятие кортежей, разложенные по разным транзакциям, оставляют проект наполовину снятым")
}

// TestDeleteProject_LeavesOtherScopesBindingsAlone — ПАРНЫЙ ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
// Выдача чужого проекта переживает снятие нетронутой; без этой пробы предыдущая
// зеленела бы и на реализации, сносящей выдачи без разбора области.
func TestDeleteProject_LeavesOtherScopesBindingsAlone(t *testing.T) {
	repo, uc := deleteProjectFixture(t)
	seedProjectBinding(repo, "acb0000000000000v1ct", "project", victimProject,
		abrepo.RelationTuple{User: "user:usr0000000000000abcd", Relation: "v_get", Object: "project:" + victimProject})
	seedProjectBinding(repo, "acb0000000000000byst", "project", bystanderProjec,
		abrepo.RelationTuple{User: "user:usr0000000000000abcd", Relation: "v_get", Object: "project:" + bystanderProjec})

	runDelete(t, uc, victimProject)

	assert.NotContains(t, repo.deletedBindings(), domain.AccessBindingID("acb0000000000000byst"),
		"снята выдача ЧУЖОГО проекта: дренаж не разбирает область")
	assert.False(t,
		hasTuple(repo.fgaDeletes(), "user:usr0000000000000abcd", "v_get", "project:"+bystanderProjec),
		"снят кортеж выдачи чужого проекта — снятие одного проекта отбирает доступ к другому")
}

// TestDeleteProject_RefusesInsteadOfPartialDrain — отказ, а не тихая частичная
// работа. Проект с числом выдач сверх предела дренажа отвергается сообщением,
// называющим ситуацию (паритет с `Account.Delete`), и НИЧЕГО не коммитит.
//
// Проба ставится именно на исход, а не на «дренаж вызван»: весь чинимый дефект —
// усечение, которого никто не мог увидеть.
func TestDeleteProject_RefusesInsteadOfPartialDrain(t *testing.T) {
	repo := newFakeProjRepo()
	repo.currentAccID = domain.AccountID("acc0000000000000abcd")
	repo.bindingsInexhaustible = true
	ops := newFakeOpsRepoProj()
	uc := NewDeleteProjectUseCase(repo, ops)

	op, err := uc.Execute(operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "test-principal"}), domain.ProjectID(victimProject))
	require.NoError(t, err)
	require.NotNil(t, op)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(ctx))

	got, gerr := ops.Get(context.Background(), op.ID)
	require.NoError(t, gerr)
	require.True(t, got.Done, "операция не завершилась")
	require.NotNil(t, got.Error,
		"проект с неисчерпаемым дренажом снялся УСПЕХОМ — это и есть тихая частичная работа: "+
			"часть выдач осталась активной, и ни ошибки, ни счётчика, ни строки об этом нет")
	assert.Equal(t, int32(codes.FailedPrecondition), got.Error.GetCode(),
		"отказ дренажа обязан быть FAILED_PRECONDITION (паритет с Account.Delete)")
	assert.Contains(t, got.Error.GetMessage(), "access bindings",
		"отказ обязан называть ситуацию, иначе оператор не поймёт, что делать")
	assert.Zero(t, repo.commits(),
		"транзакция закоммичена при отказе дренажа — часть работы применена вопреки отказу")
}

// ── дублёр выдач ───────────────────────────────────────────────────────────
//
// Встроенный nil-интерфейс: методы, которых дренаж звать не должен, паникуют, а
// не возвращают правдоподобный ноль. Дублёр, отвечающий на БОЛЬШЕЕ, чем настоящий
// репозиторий, прячет ровно то, что проверяется.

type fakeProjABRdr struct {
	abrepo.ReaderIface
	parent *fakeProjRepo
}

func (r *fakeProjABRdr) ListByScope(_ context.Context, rt domain.ResourceType, rid string,
	_ abrepo.PageFilter) ([]domain.AccessBinding, string, error) {
	r.parent.mu.Lock()
	defer r.parent.mu.Unlock()
	if r.parent.bindingsInexhaustible {
		// Область, которая никогда не пустеет: воспроизводит проект с числом
		// выдач сверх любого предела дренажа.
		return []domain.AccessBinding{{
			ID:           domain.AccessBindingID("acb0000000000000endl"),
			ResourceType: rt,
			ResourceID:   rid,
			Status:       domain.AccessBindingStatus("ACTIVE"),
		}}, "", nil
	}
	return append([]domain.AccessBinding(nil), r.parent.bindingsByScope[string(rt)+":"+rid]...), "", nil
}

func (r *fakeProjABRdr) SelectEmittedTuples(_ context.Context,
	id domain.AccessBindingID) ([]abrepo.RelationTuple, error) {
	r.parent.mu.Lock()
	defer r.parent.mu.Unlock()
	return append([]abrepo.RelationTuple(nil), r.parent.bindingLedger[id]...), nil
}

type fakeProjABWtr struct {
	abrepo.WriterIface
	parent *fakeProjRepo
}

func (w *fakeProjABWtr) Delete(_ context.Context, id domain.AccessBindingID) error {
	w.parent.mu.Lock()
	defer w.parent.mu.Unlock()
	w.parent.deletedBindingIDs = append(w.parent.deletedBindingIDs, id)
	if !w.parent.bindingsInexhaustible {
		for key, list := range w.parent.bindingsByScope {
			kept := list[:0]
			for _, b := range list {
				if b.ID != id {
					kept = append(kept, b)
				}
			}
			w.parent.bindingsByScope[key] = kept
		}
	}
	return nil
}

// ── наблюдатели фикстуры ───────────────────────────────────────────────────

func (f *fakeProjRepo) deletedBindings() []domain.AccessBindingID {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]domain.AccessBindingID(nil), f.deletedBindingIDs...)
}

func (f *fakeProjRepo) commits() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.commitCount
}
