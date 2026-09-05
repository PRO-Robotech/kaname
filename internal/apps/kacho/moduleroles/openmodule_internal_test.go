// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package moduleroles

// openmodule_internal_test.go — применитель ролей принимает МОДУЛЬ ОПЕРАТОРА.
//
// Полоса размыкания набора: загрузчик манифеста перестал судить имя модуля
// перечнем, порождённым сборкой, — и применитель обязан перестать тоже, иначе
// доставка оператора грузится и не применяется, а отказ приходит на старте
// службы, называя «unknown module» о модуле, чей манифест только что прошёл
// доставку.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
)

// outsideTheShippedTable — модуль, которого в порождённой сборкой таблице нет.
//
// Проверяется, а не предполагается: окажись он членом — обе пробы ниже
// утверждали бы о члене набора и были бы зелёными при закрытом наборе.
func outsideTheShippedTable(t *testing.T) string {
	t.Helper()
	const name = "acme"
	canon := authzmap.CatalogSeedModules()
	if len(canon) == 0 {
		t.Fatal("порождённая таблица пуста — сверка беспредметна")
	}
	if domain.ModuleSetOf(canon...).IsKnownModule(name) {
		t.Fatalf("%q состоит в порождённой таблице (%s) — вход не «вне таблицы»",
			name, strings.Join(canon, ", "))
	}
	t.Logf("перепись: модулей в порождённой таблице %d (%s); вход %q вне её",
		len(canon), strings.Join(canon, ", "), name)
	return name
}

// TestRoleOfAdmitsAModuleTheShippedTableDoesNotKnow — роль модуля оператора
// проходит проверку домена у применителя.
func TestRoleOfAdmitsAModuleTheShippedTableDoesNotKnow(t *testing.T) {
	module := outsideTheShippedTable(t)

	mr := &manifest.Role{
		ID:          module + ".widget.admin",
		Description: "Полный доступ к виджетам acme в проекте оператора",
		Tier: &manifest.Tier{
			TierType: domain.ScopeTypeClusterDotted,
			TierID:   domain.ClusterSingletonID,
		},
	}
	produced := []domain.Rule{{Module: module, Resources: []string{"widget"}, Verbs: []string{"get"}}}

	if _, err := roleOf(module, mr, produced); err != nil {
		t.Fatalf("роль модуля оператора отвергнута применителем: %v", err)
	}

	// Парный положительный — та же роль модуля ИЗ таблицы: без него отрицание
	// зеленело бы на применителе, принимающем всё.
	own := authzmap.CatalogSeedModules()[0]
	mrOwn := *mr
	mrOwn.ID = own + ".widget.admin"
	if _, err := roleOf(own, &mrOwn,
		[]domain.Rule{{Module: own, Resources: []string{"widget"}, Verbs: []string{"get"}}}); err != nil {
		t.Fatalf("парный положительный (модуль из таблицы) отвергнут: %v", err)
	}

	// Отрицательная сторона на месте: правило, называющее ЧУЖОЙ модуль,
	// применитель по-прежнему отвергает.
	if _, err := roleOf(module, mr,
		[]domain.Rule{{Module: "someoneelse", Resources: []string{"widget"}, Verbs: []string{"get"}}}); err == nil {
		t.Error("правило над чужим модулем принято применителем")
	}
}

// TestReconcileSeesTheLiveRolesOfAModuleOutsideTheShippedTable — сверка видит
// живые роли модуля оператора, а не считает их «без владельца».
//
// Дыра, ради которой проба: классификация владельца шла по перечню,
// порождённому сборкой, поэтому живая роль `acme.*` попадала в «без владельца» и
// ПРОПУСКАЛАСЬ — расхождение «живая, но не объявлена» не находилось никогда, и
// снять устаревшую роль оператора было нечем.
func TestReconcileSeesTheLiveRolesOfAModuleOutsideTheShippedTable(t *testing.T) {
	module := outsideTheShippedTable(t)

	live := []domain.Role{{
		ID:        domain.SystemRoleID(domain.RoleName(module + ".widget.admin")),
		ClusterID: domain.ClusterSingletonID,
		Name:      domain.RoleName(module + ".widget.admin"),
		IsSystem:  true,
	}}

	found, census := Reconcile(module, nil, live)
	if census.OfThisModule != 1 {
		t.Fatalf("живых ролей своего модуля %d, ожидалась 1 (без владельца %d, чужих %d) — "+
			"роль модуля оператора невидима сверке, и снять устаревшую нечем",
			census.OfThisModule, census.WithoutOwner, census.OtherModule)
	}
	if len(found) != 1 || found[0].Kind != LiveNotDeclared {
		t.Fatalf("расхождение «живая, но не объявлена» не найдено: %v", found)
	}

	// Парный положительный: роль ЧУЖОГО модуля из той же таблицы остаётся
	// «другим модулем», а не переезжает в «свой».
	other := authzmap.CatalogSeedModules()[0]
	_, c2 := Reconcile(module, nil, []domain.Role{{
		ID:        domain.SystemRoleID(domain.RoleName(other + ".network.admin")),
		ClusterID: domain.ClusterSingletonID,
		Name:      domain.RoleName(other + ".network.admin"),
		IsSystem:  true,
	}})
	if c2.OtherModule != 1 {
		t.Errorf("роль модуля %q при сверке %q отнесена не к «другому модулю» "+
			"(свой %d, без владельца %d, чужой %d)",
			other, module, c2.OfThisModule, c2.WithoutOwner, c2.OtherModule)
	}
}
