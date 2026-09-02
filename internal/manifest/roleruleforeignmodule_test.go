// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// roleruleforeignmodule_test.go — правило роли называет модуль МАНИФЕСТА
// (задача PRO-Robotech/kacho#1902; замечание В1 приёмки
// `roles-come-as-data-not-migrations.md`).
//
// # Что здесь утверждается и почему это не повтор соседа
//
// `TestMODMR11RoleIDOfAForeignModuleIsRefused` (roles_test.go) судит
// ИДЕНТИФИКАТОР роли: `roles[].id` обязан начинаться модулем манифеста. Здесь
// судится ВЫДАЧА той же роли: `roles[].rules[].module` — модуль, В КОТОРОМ роль
// раздаёт права. Это разные предметы, и до #1902 второй не судился ничем: модуль
// правила проверялся только на членство в закрытом наборе модулей платформы
// (`domain.Rule.Validate`), поэтому манифест модуля `vpc` объявлял роль
// `vpc.superuser` с правилом над `iam` — и она принималась.
//
// # Три оси, и третья — контроль на чужой отказ
//
//  1. чужой модуль в правиле — отказ, называющий ОБА значения;
//  2. свой модуль — законный близнец, проходит (без него отрицание зеленело бы
//     на загрузчике, отвергающем всякое правило);
//  3. подстановка `*` — по-прежнему отказ ДОМЕНА дословным текстом
//     («wildcard '*' is system-only»), а не новый отказ владения. Ось нужна
//     именно как контроль: проверка, поставленная ПЕРЕД доменом, украла бы у
//     него отказ и сменила бы текст, который есть часть контракта.
package manifest_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

// roleRuleModuleFixture — манифест модуля `vpc` с одной ролью своего модуля;
// модуль ПРАВИЛА подставляется.
const roleRuleModuleFixture = "apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
	"  - id: vpc.superuser\n" +
	"    description: Распоряжается ресурсами проекта.\n" +
	"    tier: {tierType: iam.project, tierId: prj000000000000000}\n" +
	"    rules:\n      - {module: %s, resources: [network], classes: [get]}\n"

func roleRuleWithModule(module string) []byte {
	return []byte(strings.Replace(roleRuleModuleFixture, "%s", module, 1))
}

// TestRoleRuleOfAForeignModuleIsRefused — правило роли, раздающее права в чужом
// модуле, отвергается с названием ОБОИХ значений.
func TestRoleRuleOfAForeignModuleIsRefused(t *testing.T) {
	_, err := manifest.Load(roleRuleWithModule("iam"))
	if err == nil {
		t.Fatalf("правило роли над чужим модулем принято")
	}
	if !errors.Is(err, manifest.ErrRoleRuleForeignModule) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	// Оба значения названы: без модуля манифеста автор не знает, что именно
	// сравнивалось, и чинит не то поле.
	for _, want := range []string{"roles[0].rules[0].module", "iam", "vpc"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}

	// Законный близнец: правило над СВОИМ модулем проходит.
	if _, terr := manifest.Load(roleRuleWithModule("vpc")); terr != nil {
		t.Fatalf("парный положительный отвергнут: %v", terr)
	}

	// Контроль: подстановка остаётся отказом ДОМЕНА, а не отказом владения.
	// Иначе новая проверка украла бы у домена его отказ вместе с текстом.
	_, werr := manifest.Load(roleRuleWithModule(`"*"`))
	if werr == nil {
		t.Fatalf("подстановка модуля в несистемной роли принята")
	}
	if !errors.Is(werr, manifest.ErrRoleRuleInvalid) {
		t.Errorf("подстановка отвергнута не полосой домена: %v", werr)
	}
	if errors.Is(werr, manifest.ErrRoleRuleForeignModule) {
		t.Errorf("подстановка отнесена к владению — отказ домена украден: %v", werr)
	}
	if !strings.Contains(werr.Error(), "Illegal argument module (wildcard '*' is system-only)") {
		t.Errorf("отказ не несёт дословного текста домена: %v", werr)
	}

	t.Logf("перепись: осей три — чужой модуль · свой модуль · подстановка; " +
		"каждая исполнена своим входом")
}

// TestRoleRulesOfEveryManifestNameTheirOwnModule — перепись ПО ДЕРЕВУ: правило
// каждой роли каждого манифеста называет модуль своего манифеста.
//
// Проба стоит рядом с отказом намеренно: отказ судит ОДИН документ, а свойство
// принадлежит ДЕРЕВУ. Замер на день заведения — правил 46, чужих ноль; поэтому
// запрет ничего не ломает, и это утверждается, а не предполагается.
//
// Пустой обход — НАХОДКА: манифест перестал находиться, и молчание пробы было бы
// неотличимо от чистоты.
func TestRoleRulesOfEveryManifestNameTheirOwnModule(t *testing.T) {
	// Обход — ПРОД-ПУТЬ (`CheckTree`), тот самый, которым судит
	// `make -C services/iam module-manifest-check`. Свой обходчик рядом
	// разошёлся бы с ним молча на первом же новом месте манифеста.
	rep := manifest.CheckTree(repoRootFromManifestPackage)
	if len(rep.Findings) > 0 {
		t.Fatalf("дерево не прочитано целиком, вердикта нет ни по одному манифесту: %v",
			rep.Findings)
	}
	if rep.ManifestsRead == 0 {
		t.Fatalf("манифестов не найдено ни одного — обход пуст (%s), и молчание пробы "+
			"было бы неотличимо от чистоты", rep.Summary())
	}

	roles, rules, foreign := 0, 0, 0
	for k, m := range rep.Manifests {
		for i := range m.Roles {
			roles++
			for _, rule := range m.Roles[i].Rules {
				rules++
				if rule.Module != m.Module {
					foreign++
					t.Errorf("%s: roles[%d] (%s) раздаёт права в модуле %q, а манифест — модуля %q",
						rep.Paths[k], i, m.Roles[i].ID, rule.Module, m.Module)
				}
			}
		}
	}
	t.Logf("перепись: %s · ролей %d · правил %d · чужих модулей %d",
		rep.Summary(), roles, rules, foreign)
}

// repoRootFromManifestPackage — корень дерева относительно каталога этого
// пакета. Пробы Go исполняются из каталога своего пакета, поэтому путь
// относительный и от места запуска не зависит.
const repoRootFromManifestPackage = "../../../.."
