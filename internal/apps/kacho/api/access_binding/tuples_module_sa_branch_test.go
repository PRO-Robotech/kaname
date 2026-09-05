// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// tuples_module_sa_branch_test.go — ПРОБА, устанавливающая, В КАКУЮ ВЕТВЬ
// эмиттера уходит роль служебной учётки модуля до и после мыслимой правки.
//
// Проба нужна потому, что решение «что снимать» упирается ровно в этот выбор, а
// прочитать его глазами недостаточно: ветка выбирается по `len(role.Rules) > 0`,
// и обе половины выглядят одинаково безобидно в диффе.
//
//	роль С правилами   → только иерархический указатель, НИ ОДНОГО кортежа доступа;
//	роль БЕЗ правил    → ярусные отношения на якоре области привязки.
//
// Отсюда ловушка: снять правила, ОСТАВИВ строки прав, значит перевести роль в
// легаси-ветку и ВЫДАТЬ ей отношение на кластерном якоре, которого до правки не
// было. И оно КРУПНЕЕ, чем читается по слову «ярус»: на кластере — и только на
// нём — `tuplesForBinding` прогоняет отношения через `mapClusterRelations`,
// который сводит и `admin`, и `editor` в ОДНО прямое `system_admin`. У
// `module.compute_sa` строки прав несут create/update/delete, поэтому легаси-
// ветка выдала бы ей `system_admin@cluster:cluster_kacho_root` — верхний из трёх
// уровней супер-доступа, администратора облака, каскадом на всё. Пяти остальным
// (только `.get`) досталось бы `system_viewer@cluster`, которого у nlb, реестра
// и хранилища сегодня нет вовсе (у vpc/compute/шлюза он есть из посева 0014).
//
// Это не «уборка мёртвого объявления», а новая выдача кластерного размера под её
// видом. Величина измерена пробой, не выведена из чтения: первая редакция этого
// файла утверждала `editor`, и проба её опровергла.
//
// Обе половины стоят рядом и меряются ОДНИМ путём (`buildBindingTuples` +
// `tierTuples`), иначе «ноль кортежей» у первой было бы неотличимо от опечатки в
// пробе.
package access_binding

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// moduleSAPermissions — строки прав `module.compute_sa` из посева 0009,
// дословно. Взяты у самой сильной из шести ролей: если ловушка существует, она
// проявится на ней в максимальном ярусе.
var moduleSAPermissions = []string{
	"vpc.subnets.*.get",
	"vpc.security_groups.*.get",
	"vpc.addresses.*.get",
	"vpc.addresses.*.create",
	"vpc.addresses.*.delete",
	"vpc.addresses.*.update",
	"iam.projects.*.get",
}

// moduleSARules — правила той же роли из посева 0031 §4.7, дословно. Ни одна из
// четырёх пар закрытой таблицей типов не разрешается (см. гейт
// TestSeededRoleRulesResolveOrArePinned), но ВЕТКУ эмиттера выбирает сам факт
// наличия правил, а не их разрешимость — именно это здесь и меряется.
func moduleSARules() domain.Rules {
	return domain.Rules{
		{Module: "vpc", Resources: []string{"subnets"}, Verbs: []string{"get"}},
		{Module: "vpc", Resources: []string{"security_groups"}, Verbs: []string{"get"}},
		{Module: "vpc", Resources: []string{"addresses"}, Verbs: []string{"get", "create", "delete", "update"}},
		{Module: "iam", Resources: []string{"projects"}, Verbs: []string{"get"}},
	}
}

func moduleSABinding() domain.AccessBinding {
	return domain.AccessBinding{
		ID:           "acb_module_sa_probe001",
		SubjectType:  domain.SubjectTypeServiceAccount,
		SubjectID:    "sva_module_sa_probe001",
		ResourceType: "cluster",
		ResourceID:   "cluster_kacho_root",
	}
}

// TestBuildBindingTuples_ModuleSA_WithRules_EmitsNoAccessTuple — отрицание:
// роль служебной учётки модуля В ТОМ ВИДЕ, В КАКОМ ОНА ПОСЕЯНА, не эмитит ни
// одного кортежа доступа. Это и делает её объявление мёртвым.
func TestBuildBindingTuples_ModuleSA_WithRules_EmitsNoAccessTuple(t *testing.T) {
	role := domain.Role{
		Permissions: toPermissions(moduleSAPermissions),
		Rules:       moduleSARules(),
	}
	got, err := buildBindingTuples(moduleSABinding(), role)
	require.NoError(t, err)

	access := tierTuples(t, got, "cluster:cluster_kacho_root")
	assert.Empty(t, access,
		"роль С правилами обязана эмитить ТОЛЬКО иерархический указатель: "+
			"право этой роли не едет ярусным кортежем на якоре области привязки, "+
			"его не едет вовсе. Получено: %v", access)
}

// TestBuildBindingTuples_ModuleSA_RulesCleared_MintsClusterTier — ЛОВУШКА,
// предъявленная пробой: та же роль без правил выдаёт ярус на кластерном якоре.
//
// Положительная половина пары. Без неё «ноль кортежей» выше был бы получен даром
// — из сломанного пути сборки, а не из ветки эмиттера.
func TestBuildBindingTuples_ModuleSA_RulesCleared_MintsClusterTier(t *testing.T) {
	role := domain.Role{
		Permissions: toPermissions(moduleSAPermissions),
		// Rules намеренно пусты — ровно то состояние, в которое роль попала бы,
		// если снять её правила и оставить строки прав.
	}
	got, err := buildBindingTuples(moduleSABinding(), role)
	require.NoError(t, err)

	access := tierTuples(t, got, "cluster:cluster_kacho_root")
	require.NotEmpty(t, access,
		"контроль: роль без правил обязана уйти в легаси-ветку и эмитить ярус — "+
			"иначе проба не измеряет ветвление вовсе")
	for _, tp := range access {
		assert.Equal(t, "cluster:cluster_kacho_root", tp.Object,
			"ярус легаси-ветки садится на ЯКОРЬ ОБЛАСТИ привязки")
	}
	relations := make([]string, 0, len(access))
	for _, tp := range access {
		relations = append(relations, tp.Relation)
	}
	assert.Contains(t, relations, "system_admin",
		"строки прав module.compute_sa несут create/update/delete → ярус editor, а на "+
			"КЛАСТЕРНОМ якоре mapClusterRelations сводит и admin, и editor в прямое "+
			"system_admin. Легаси-ветка выдала бы служебной учётке compute "+
			"АДМИНИСТРАТОРА ОБЛАКА — верхний уровень супер-доступа, каскадом на всё. "+
			"Это НОВОЕ право, которого у роли с правилами нет: снимать правила, "+
			"оставляя права, — расширение доступа под видом уборки. Получено: %v", relations)
}

// TestBuildBindingTuples_ModuleSA_ViewerOnlyRulesCleared_MintsClusterSystemViewer —
// вторая клетка той же оси: пять остальных ролей несут только `.get`, поэтому та
// же правка выдала бы им `system_viewer@cluster`.
//
// Клетка нужна отдельно: цитата на одной роли доказала бы существование ловушки,
// но не её распределение по шести. У nlb, реестра и хранилища этого отношения
// сегодня нет (посев 0014 сеет его только шлюзу, vpc и compute) — для них это
// тоже новое право, просто уровнем ниже.
func TestBuildBindingTuples_ModuleSA_ViewerOnlyRulesCleared_MintsClusterSystemViewer(t *testing.T) {
	role := domain.Role{
		// Строки прав module.{vpc,nlb,api_gateway,registry,storage}_sa — только чтение.
		Permissions: toPermissions([]string{"iam.projects.*.get"}),
	}
	got, err := buildBindingTuples(moduleSABinding(), role)
	require.NoError(t, err)

	access := tierTuples(t, got, "cluster:cluster_kacho_root")
	relations := make([]string, 0, len(access))
	for _, tp := range access {
		relations = append(relations, tp.Relation)
	}
	assert.Contains(t, relations, "system_viewer",
		"роль только с `.get` в легаси-ветке садится на кластерный якорь отношением "+
			"system_viewer. Получено: %v", relations)
	assert.NotContains(t, relations, "system_admin",
		"и НЕ администратором облака — иначе проба не различала бы два уровня ловушки "+
			"и первая клетка была бы получена даром. Получено: %v", relations)
}

func toPermissions(in []string) []domain.Permission {
	out := make([]domain.Permission, len(in))
	for i, p := range in {
		out[i] = domain.Permission(p)
	}
	return out
}
