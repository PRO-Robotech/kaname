// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// list_by_role_page_cost_test.go — СТОИМОСТЬ СТРАНИЦЫ ПРИНАДЛЕЖИТ ЗАПРОСУ,
// А НЕ СТРОКЕ (задача #2054).
//
// Полоса «кто держит роль R» спрашивает право построчно: на каждую строку
// страницы уходил вопрос супер-гейта и вопрос про область. `page_size` — часть
// контракта и доходит до 1000 (`api-conventions.md` §Pagination), поэтому
// последовательные вопросы по строкам не укладываются в срок под нагрузкой и
// дают `UNAVAILABLE` на ПОЛОЖИТЕЛЬНОМ пути; сужать `page_size` ради бюджета
// запрещено (`security.md` §«Фильтрация — страница → проверка страницы»).
//
// Утверждается НАБЛЮДАЕМОЕ — число вопросов к хранилищу прав, — а не устройство
// памятки: пробы остаются верными при любой реализации, которая перестала
// платить построчно.
//
// Пробы идут ТРОЙКОЙ, и третья несущая:
//   - стоимость НЕ растёт с числом строк при неизменном наборе областей;
//   - стоимость РАСТЁТ с числом различных областей — иначе первая проба была бы
//     вакуумной: она зеленела бы и на реализации, которая не спрашивает вовсе;
//   - отбор строк НЕ изменился — ни одна не пропущена, ни одна не выдана дважды.

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// countingFGA — считает КАЖДЫЙ вопрос к хранилищу прав и отвечает `admin`
// только по названным объектам. Счётчик и есть предмет замера.
type countingFGA struct {
	mu      sync.Mutex
	asked   []string
	adminOn map[string]bool
}

func newCountingFGA(adminObjects ...string) *countingFGA {
	f := &countingFGA{adminOn: map[string]bool{}}
	for _, o := range adminObjects {
		f.adminOn[o] = true
	}
	return f
}

func (f *countingFGA) Check(_ context.Context, _, relation, object string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, relation+" "+object)
	return f.adminOn[object], nil
}

// questions — сколько вопросов задано за прогон.
func (f *countingFGA) questions() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.asked)
}

var _ clients.RelationStore = (*countingFGA)(nil)

const pageCostRoleID = "rol000000000sysadmin"

// bindingsOnScopes — строки страницы, разложенные по названным областям
// по кругу. Тип области — ЛИСТОВОЙ (не account/project): у такого нет
// владельца в базе, поэтому полоса упирается ровно в вопрос о правах, и замер
// не смешивает его с чтениями базы.
func bindingsOnScopes(rows int, scopeIDs []string) []domain.AccessBinding {
	out := make([]domain.AccessBinding, 0, rows)
	for i := 0; i < rows; i++ {
		out = append(out, domain.AccessBinding{
			ID:           domain.AccessBindingID("acb_cost_" + string(rune('a'+i))),
			SubjectType:  domain.SubjectTypeUser,
			SubjectID:    "usr_member0000000000",
			RoleID:       domain.RoleID(pageCostRoleID),
			ResourceType: "compute.instance",
			ResourceID:   scopeIDs[i%len(scopeIDs)],
			Status:       domain.AccessBindingStatusActive,
		})
	}
	return out
}

// runPageCost — один прогон полосы: сеет страницу, исполняет чтение чужим
// вызывающим и возвращает выданные строки вместе с числом заданных вопросов.
func runPageCost(t *testing.T, rows int, scopeIDs []string, adminObjects ...string) ([]domain.AccessBinding, int) {
	t.Helper()
	repo := newABFakeRepo("usr_owner", "acc_cost", "prj_cost", pageCostRoleID, "viewer",
		domain.Permissions{"iam.access_bindings.get"})
	repo.lbrRows = bindingsOnScopes(rows, scopeIDs)

	fga := newCountingFGA(adminObjects...)
	uc := NewListByRoleUseCase(repo).WithRelationStore(fga, nil)

	got, _, err := uc.Execute(foreignCtx(), pageCostRoleID, repoab.ListByRoleFilter{PageSize: 1000})
	require.NoError(t, err)
	return got, fga.questions()
}

// TestListByRole_PageCostDoesNotGrowWithPageSize — при НЕИЗМЕННОМ наборе
// областей страница из двенадцати строк стоит столько же, сколько из четырёх.
func TestListByRole_PageCostDoesNotGrowWithPageSize(t *testing.T) {
	scopes := []string{"ins_cost_one", "ins_cost_two"}

	_, cost4 := runPageCost(t, 4, scopes)
	_, cost12 := runPageCost(t, 12, scopes)

	t.Logf("перепись: областей %d · строк 4 → вопросов %d · строк 12 → вопросов %d",
		len(scopes), cost4, cost12)
	require.Equal(t, cost4, cost12,
		"стоимость страницы принадлежит запросу: при тех же двух областях "+
			"двенадцать строк обязаны стоить столько же, сколько четыре "+
			"(вопросов: 4 строки → %d, 12 строк → %d)", cost4, cost12)
}

// TestListByRole_PageCostGrowsWithDistinctScopes — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к
// пробе выше. Без него «не растёт» зеленело бы и на реализации, которая не
// спрашивает вовсе, — то есть утверждение было бы вакуумным.
func TestListByRole_PageCostGrowsWithDistinctScopes(t *testing.T) {
	_, costOneScope := runPageCost(t, 4, []string{"ins_ctl_one"})
	_, costFourScopes := runPageCost(t, 4,
		[]string{"ins_ctl_one", "ins_ctl_two", "ins_ctl_three", "ins_ctl_four"})

	t.Logf("перепись: строк 4 · областей 1 → вопросов %d · областей 4 → вопросов %d",
		costOneScope, costFourScopes)
	require.Greater(t, costFourScopes, costOneScope,
		"проба обязана ВИДЕТЬ различие: четыре различных области спрашиваются "+
			"дороже одной (вопросов: одна область → %d, четыре → %d)",
		costOneScope, costFourScopes)
}

// TestListByRole_FilteringKeepsExactlyTheAuthorisedRows — ЗАКОННЫЙ БЛИЗНЕЦ:
// отбор не изменился. Шесть строк на трёх областях, право — на одной; выданы
// ровно её строки, в исходном порядке, без повторов и без пропусков.
func TestListByRole_FilteringKeepsExactlyTheAuthorisedRows(t *testing.T) {
	scopes := []string{"ins_keep_one", "ins_keep_two", "ins_keep_three"}

	got, cost := runPageCost(t, 6, scopes, "compute.instance:ins_keep_two")

	t.Logf("перепись: строк 6 · областей %d · выдано %d · вопросов %d",
		len(scopes), len(got), cost)
	require.Len(t, got, 2, "видны ровно строки той области, на которую есть право")
	seen := map[domain.AccessBindingID]int{}
	for _, b := range got {
		require.Equal(t, "ins_keep_two", b.ResourceID,
			"строка чужой области не имеет права попасть в ответ")
		seen[b.ID]++
	}
	for id, n := range seen {
		require.Equal(t, 1, n, "строка %s выдана дважды", id)
	}
}

// TestListByRole_NoRowsAsksNothing — пустая страница не оплачивается вовсе:
// вопрос супер-гейта не задаётся, пока нет ни одной строки, о которой он решает.
func TestListByRole_NoRowsAsksNothing(t *testing.T) {
	_, cost := runPageCost(t, 0, []string{"ins_none"})

	require.Zero(t, cost,
		"страница без строк не задаёт ни одного вопроса о правах")
}
