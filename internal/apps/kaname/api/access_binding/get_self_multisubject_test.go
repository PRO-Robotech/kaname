// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// get_self_multisubject_test.go — самопол `Get` судит ВЕСЬ набор субъектов
// выдачи, а не только легаси-первого (`SubjectID` = `Subjects[0]`).
//
// Задача #2049. Полный набор `Subjects` загружается той же читающей
// транзакцией двадцатью строками выше самопола (`get.go`,
// `rd.AccessBindings().ListSubjects`) — и в самополе не итерировался. Субъект,
// стоящий в мультисубъектной выдаче НЕ первым, самопола не проходил и уезжал в
// ветвь права выдавать; своей собственной выдачи он не видел, тогда как первый
// субъект видел. Направление отказа безопасное (меньше доступа, не больше),
// поэтому дефект тихий: жалуется только тот, кому не показали.
//
// Обе стороны утверждения обязаны стоять рядом. Без положительного контроля
// (первый субъект по-прежнему проходит) утверждение зеленело бы на самополе,
// пропускающем кого угодно; без отрицательного (посторонний по-прежнему
// получает отказ) — на самополе, отвечающем «да» всякому.
//
// Оснастка сужена намеренно: право выдавать отвечает отказом (`denyingFGA`), а
// порт перечисления не провязан вовсе (`WithRelationQueries` не зовётся, nil ⇒
// deny). Значит единственная полоса, которая может отдать выдачу, — самопол, и
// зелёное этой пробы утверждает именно про него.

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// multiSubjectBindingSubjects — набор из трёх субъектов; легаси-первый (тот, что
// продублирован в `SubjectID`) стоит первым, предмет пробы — второй и третий.
var multiSubjectBindingSubjects = []domain.Subject{
	{Type: domain.SubjectTypeUser, ID: domain.SubjectID("usr0000000000000frst")},
	{Type: domain.SubjectTypeUser, ID: domain.SubjectID("usr0000000000000scnd")},
	{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID("sva0000000000000thrd")},
}

// seedMultiSubjectBinding кладёт в дублёр выдачу с набором субъектов: строку
// `access_bindings` (легаси-первый в `SubjectID`) и её детей
// `access_binding_subjects` — тем же путём, которым их наполняет запись.
func seedMultiSubjectBinding(repo *abFakeRepo) domain.AccessBindingID {
	id := domain.AccessBindingID("acb0000000000multi01")
	repo.mu.Lock()
	repo.ab = &domain.AccessBinding{
		ID:           id,
		SubjectType:  multiSubjectBindingSubjects[0].Type,
		SubjectID:    multiSubjectBindingSubjects[0].ID,
		RoleID:       domain.RoleID("rol21232f297a57a5a74"),
		ResourceType: domain.ResourceType("account"),
		ResourceID:   "acc00000000000ba01ab",
	}
	repo.mu.Unlock()
	seedABSubjects(repo, id, multiSubjectBindingSubjects)
	return id
}

// getAsPrincipal — один прогон `Get` от имени названного принципала при
// отказывающем праве выдавать и непровязанном перечислении.
func getAsPrincipal(t *testing.T, principalID string) (domain.AccessBinding, error) {
	t.Helper()
	repo := newABFakeRepo("usr_owner", "acc00000000000ba01ab", "prj_test", "rol_v", "kacho.view", nil)
	id := seedMultiSubjectBinding(repo)
	uc := NewGetAccessBindingUseCase(repo).WithRelationStore(&denyingFGA{}, nil)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: principalID})
	return uc.Execute(ctx, id)
}

// TestGetAccessBinding_SelfCheckSpansEverySubjectOfTheSet — предмет #2049.
//
// Перепись печатает объём осмотренного: сколько позиций набора пройдено и
// сколько из них самопол принял. Одно число («принял N») скрывало бы ровно тот
// случай, ради которого проба заведена, — набор, у которого проходит лишь
// первая позиция.
func TestGetAccessBinding_SelfCheckSpansEverySubjectOfTheSet(t *testing.T) {
	admitted := 0
	for i, sub := range multiSubjectBindingSubjects {
		name := "позиция-" + string(rune('1'+i))
		t.Run(name, func(t *testing.T) {
			got, err := getAsPrincipal(t, string(sub.ID))
			if err != nil {
				t.Fatalf("субъект %s (позиция %d) не прошёл самопол своей же выдачи: %v",
					sub.ID, i+1, err)
			}
			if got.ID != domain.AccessBindingID("acb0000000000multi01") {
				t.Fatalf("вернулась не та выдача: %s", got.ID)
			}
			admitted++
		})
	}
	t.Logf("перепись: позиций набора осмотрено %d · самопол принял %d",
		len(multiSubjectBindingSubjects), admitted)
	if admitted != len(multiSubjectBindingSubjects) {
		t.Fatalf("самопол принял %d позиций из %d — набор судится не целиком",
			admitted, len(multiSubjectBindingSubjects))
	}
}

// TestGetAccessBinding_SelfCheckRejectsASubjectOutsideTheSet — отрицание в паре
// с положительным выше. Без него «набор судится целиком» зеленело бы на
// самополе, отвечающем «да» всякому принципалу.
func TestGetAccessBinding_SelfCheckRejectsASubjectOutsideTheSet(t *testing.T) {
	_, err := getAsPrincipal(t, "usr0000000000000outs")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("посторонний, не входящий в набор, обязан получить отказ, получено %v", err)
	}
	t.Logf("перепись: позиций набора %d · принципалов вне набора проверено 1",
		len(multiSubjectBindingSubjects))
}

// TestGetAccessBinding_SelfCheckIgnoresTheSubjectsOfAnotherBinding — вторая
// половина отрицания: набор берётся у ЭТОЙ выдачи, а не у какой-нибудь. Без неё
// «судится весь набор» зеленело бы на реализации, принимающей любого, кто стоит
// в субъектах хоть одной выдачи дерева.
func TestGetAccessBinding_SelfCheckIgnoresTheSubjectsOfAnotherBinding(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc00000000000ba01ab", "prj_test", "rol_v", "kacho.view", nil)
	id := seedMultiSubjectBinding(repo)
	// Чужая выдача со своим набором — её субъект к предмету запроса отношения
	// не имеет.
	seedABSubjects(repo, domain.AccessBindingID("acb0000000000other01"), []domain.Subject{
		{Type: domain.SubjectTypeUser, ID: domain.SubjectID("usr000000000000alien")},
	})
	uc := NewGetAccessBindingUseCase(repo).WithRelationStore(&denyingFGA{}, nil)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr000000000000alien"})

	if _, err := uc.Execute(ctx, id); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("субъект ЧУЖОЙ выдачи обязан получить отказ на этой, получено %v", err)
	}
}

// ── вторая полоса того же класса: перечисление держателей роли ───────────────
//
// Самопол выдачи в дереве стоит в ДВУХ местах, и оба читали легаси-первого:
// `get.go` (предмет #2049) и `list_by_role.go`. Набор субъектов там наполнен
// тем же путём чтения (`readBindingsWithSubjects` → `projectSubjectsBatch`),
// поэтому дефект и его починка у полос общие. Чинится класс, а не экземпляр
// (`testing.md` §«Гейт на класс», п. 1); перепись прод-дерева, из которой взят
// радиус:
//
//	git grep -n 'IsSelf(' -- 'services/iam/**/*.go' ':!*_test.go'
//	→ 13 вхождений, из них по субъекту ВЫДАЧИ — 2 (get.go, list_by_role.go);
//	  остальные судят владельца аккаунта либо идентификатор человека.

// TestListByRole_SelfCheckSpansEverySubjectOfTheSet — вторая полоса, тот же
// предмет: держатель роли, стоящий в выдаче не первым, обязан видеть строку,
// которая называет его самого.
func TestListByRole_SelfCheckSpansEverySubjectOfTheSet(t *testing.T) {
	const (
		roleID    = "rol000000000sysadmin"
		accountID = "acc00000000000ba01ab"
	)
	seen := 0
	for i, sub := range multiSubjectBindingSubjects {
		repo := newABFakeRepo("usr_owner", accountID, accountID, roleID, "viewer", nil)
		id := domain.AccessBindingID("acb0000000000multi01")
		repo.ab = &domain.AccessBinding{
			ID:           id,
			SubjectType:  multiSubjectBindingSubjects[0].Type,
			SubjectID:    multiSubjectBindingSubjects[0].ID,
			RoleID:       domain.RoleID(roleID),
			ResourceType: "account",
			ResourceID:   accountID,
			Status:       domain.AccessBindingStatusActive,
		}
		seedABSubjects(repo, id, multiSubjectBindingSubjects)
		uc := NewListByRoleUseCase(repo).WithRelationStore(&denyingFGA{}, nil)

		got, _, err := uc.Execute(newOwnerContext(string(sub.ID)), roleID,
			repoab.ListByRoleFilter{PageSize: 50})
		if err != nil {
			t.Fatalf("позиция %d: %v", i+1, err)
		}
		if len(got) != 1 {
			t.Errorf("субъект %s (позиция %d) не увидел выдачи, которая его называет: строк %d",
				sub.ID, i+1, len(got))
			continue
		}
		seen++
	}
	t.Logf("перепись: позиций набора осмотрено %d · строку увидели %d",
		len(multiSubjectBindingSubjects), seen)
	if seen != len(multiSubjectBindingSubjects) {
		t.Fatalf("строку увидели %d позиций из %d — набор судится не целиком",
			seen, len(multiSubjectBindingSubjects))
	}
}

// TestListByRole_SelfCheckRejectsASubjectOutsideTheSet — отрицание в паре:
// посторонний по-прежнему получает пустую страницу, а не чужую выдачу.
func TestListByRole_SelfCheckRejectsASubjectOutsideTheSet(t *testing.T) {
	const (
		roleID    = "rol000000000sysadmin"
		accountID = "acc00000000000ba01ab"
	)
	repo := newABFakeRepo("usr_owner", accountID, accountID, roleID, "viewer", nil)
	id := domain.AccessBindingID("acb0000000000multi01")
	repo.ab = &domain.AccessBinding{
		ID:           id,
		SubjectType:  multiSubjectBindingSubjects[0].Type,
		SubjectID:    multiSubjectBindingSubjects[0].ID,
		RoleID:       domain.RoleID(roleID),
		ResourceType: "account",
		ResourceID:   accountID,
		Status:       domain.AccessBindingStatusActive,
	}
	seedABSubjects(repo, id, multiSubjectBindingSubjects)
	uc := NewListByRoleUseCase(repo).WithRelationStore(&denyingFGA{}, nil)

	got, _, err := uc.Execute(newOwnerContext("usr0000000000000outs"), roleID,
		repoab.ListByRoleFilter{PageSize: 50})
	if err != nil {
		t.Fatalf("посторонний получает пустую страницу, не ошибку: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("посторонний, не входящий в набор, увидел %d строк", len(got))
	}
}
