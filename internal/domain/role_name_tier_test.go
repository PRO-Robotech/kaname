// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// role_name_tier_test.go — форма имени роли судится ПО ЯРУСУ и зеркалит
// ограничения таблицы (`0056_role_definition_tier.sql`).
//
// # Находка, из-за которой проба написана
//
// Приёмка `roles-come-as-data-not-migrations.md` §3.1 называла ОДНО
// препятствие тому, чтобы системную роль записал Go: путь пользовательской роли
// не пишет `cluster_id` (её П6). Препятствий ДВА. Второе — здесь: форма
// системного имени в домене была `^roles/[a-z]+\.[a-z]+$`, и ей не
// удовлетворяет НИ ОДНА живая строка (предикат: `grep -c "'roles/"` по
// миграциям → ноль во всех файлах). То есть `Role.Validate()` отвергал КАЖДУЮ
// системную роль продукта, включая `vpc.network.admin`.
//
// Правило пережило свой предмет и не могло покраснеть: системную роль в Go до
// этой работы никто не строил.
package domain_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// systemRoleFixture — системная роль с живым именем продукта.
func systemRoleFixture(name string) domain.Role {
	return domain.Role{
		ID:          domain.SystemRoleID(domain.RoleName(name)),
		ClusterID:   domain.ClusterSingletonID,
		Name:        domain.RoleName(name),
		Description: domain.Description("Роль модуля, объявленная манифестом."),
		Rules: domain.Rules{{
			Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"},
		}},
		IsSystem: true,
	}
}

// TestSystemRoleNameFormMirrorsTheAppliedConstraint — живые имена продукта
// принимаются, а форма ограничения таблицы соблюдена в обе стороны.
func TestSystemRoleNameFormMirrorsTheAppliedConstraint(t *testing.T) {
	live := []string{
		"vpc.network.admin", "iam.access_binding.view", "compute.instance.edit",
		"module.storage_sa", "kacho-system.admin", "loadbalancer.operator",
		"admin", "edit", "view", "owner",
	}
	for _, name := range live {
		if err := systemRoleFixture(name).Validate(); err != nil {
			t.Errorf("живая системная роль %q отвергнута доменом: %v\n"+
				"Пока она отвергается, ни один писатель на Go не может её записать — "+
				"и это второе препятствие рядом с тем, что путь пользовательской роли "+
				"не пишет cluster_id", name, err)
		}
	}

	// Обратная сторона: то, что отвергает ограничение таблицы, обязан отвергать
	// и домен, — иначе отказ приезжает SQLSTATE 23514 без имени поля.
	for _, name := range []string{
		"vpc.networkOperator", "vpc.network.rules.admin", "roles/iam.viewer",
		"Vpc.network.admin", "vpc.network.", "",
	} {
		err := systemRoleFixture(name).Validate()
		if err == nil {
			t.Errorf("имя %q принято доменом, а ограничение таблицы "+
				"roles_system_name_check его отвергнет: отказ придёт SQLSTATE 23514 "+
				"без имени поля и без координаты", name)
			continue
		}
		if !strings.Contains(err.Error(), "name") {
			t.Errorf("отказ по имени %q не называет поля: %v", name, err)
		}
	}
}

// TestCustomRoleNameFormIsNotWidenedByTheSystemForm — положительный контроль:
// расширение системной формы не расширило пользовательскую. Иначе роль с точкой
// проходила бы домен и отвергалась ограничением `roles_custom_name_check`.
func TestCustomRoleNameFormIsNotWidenedByTheSystemForm(t *testing.T) {
	custom := domain.Role{
		ID:          "rol00000000000000cus0",
		AccountID:   "acc000000000000000",
		Name:        "network_viewer",
		Description: domain.Description("Пользовательская роль аккаунта."),
		Rules: domain.Rules{{
			Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"},
		}},
	}
	if err := custom.Validate(); err != nil {
		t.Fatalf("законная пользовательская роль отвергнута: %v", err)
	}
	widened := custom
	widened.Name = "vpc.network.admin"
	if err := widened.Validate(); err == nil {
		t.Errorf("пользовательская роль с точечным именем принята — форма яруса не " +
			"различает ярусов, и отказ приедет от ограничения таблицы, а не от домена")
	}
}
