// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain_test

// rule_policy_test.go — политик ТРИ, и различает их ВЛАДЕЛЕЦ, а не ярус.
//
// Задача продукта #1032 (P0). Приёмка — APPROVED круга 2,
// `services/iam/docs/engineering/acceptance/role-ownership-tier-apart-from-cluster-anchor.md`,
// сценарии IAM-OM-1-01 … -05, -17, -18.
//
// # Что здесь утверждается
//
// Что послабление подстановки перестало быть следствием кластерного якоря.
// Признак `is_system` несёт второй смысл — «арендатор эту роль не правит», — и
// роль модуля обязана быть системной в этом смысле; вместе с ним она получала
// первый смысл, то есть прямой путь к `*.*.*`.
//
// # Обе стороны на каждой оси
//
//	module "*"      модульная политика     → отказ СВОИМ текстом (не арендаторским)
//	module "*"      платформенная          → проходит                (иначе отзыв уже выданного)
//	module "*"      арендаторская          → отказ ПРЕЖНИМ текстом   (побайтово)
//	ресурс "*"      свой модуль            → проходит
//	ресурс "*"      чужой модуль           → отказ, называющий ОБА значения
//	глагол "*"      любая политика         → проходит                (не сегмент пространства имён)

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// ruleOn — правило с названным модулем и ресурсами; глагол законный и
// единственный, чтобы отказ приходил от проверяемой оси, а не от соседней.
func ruleOn(module string, resources ...string) domain.Rule {
	return domain.Rule{Module: module, Resources: resources, Verbs: []string{"get"}}
}

// TestIAMOM101_ModuleWildcardInAnOwnedRoleCarriesItsOwnText — IAM-OM-1-01.
//
// Текст СВОЙ, а не заимствованный у арендаторской полосы. Прежде заказывался
// арендаторский — `wildcard '*' is system-only`, — и он ЛОЖЕН для своего
// предмета: роль модуля системная и есть, поэтому автору манифеста сообщалось
// бы, что подстановка доступна только системным ролям, про роль, которая ею
// является.
func TestIAMOM101_ModuleWildcardInAnOwnedRoleCarriesItsOwnText(t *testing.T) {
	err := ruleOn("*", "network").Validate(domain.PolicyOfRole(true, "vpc"), fixtureModules())
	if err == nil {
		t.Fatal("подстановка модуля в роли с владельцем принята — послабление осталось " +
			"следствием кластерного якоря")
	}
	const want = "Illegal argument module (wildcard '*' is not available to a role owned by " +
		"module 'vpc'; name the module this rule grants in)"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("отказ не несёт СВОЕГО текста модульной политики:\n получено %v\n ожидалось %q",
			err, want)
	}
	if strings.Contains(err.Error(), "is system-only") {
		t.Errorf("отказ заимствовал АРЕНДАТОРСКИЙ текст: он ложен для своего предмета — "+
			"роль модуля системная и есть:\n%v", err)
	}
}

// TestIAMOM102_ResourceWildcardInsideTheOwningModulePasses — IAM-OM-1-02,
// законный близнец.
//
// Без него отрицание выше зеленело бы на политике, отвергающей ВСЯКУЮ
// подстановку, — то есть на отзыве уже выданного.
func TestIAMOM102_ResourceWildcardInsideTheOwningModulePasses(t *testing.T) {
	if err := ruleOn("vpc", "*").Validate(domain.PolicyOfRole(true, "vpc"), fixtureModules()); err != nil {
		t.Fatalf("подстановка ресурса В СВОЁМ модуле отвергнута: %v", err)
	}
}

// TestIAMOM103_ResourceWildcardOutsideTheOwningModuleNamesBothValues — IAM-OM-1-03.
//
// Текст обязан назвать ОБА значения: без второго автор не знает, какое из двух
// менять — владельца роли или модуль правила.
func TestIAMOM103_ResourceWildcardOutsideTheOwningModuleNamesBothValues(t *testing.T) {
	err := ruleOn("compute", "*").Validate(domain.PolicyOfRole(true, "vpc"), fixtureModules())
	if err == nil {
		t.Fatal("подстановка ресурса при ЧУЖОМ модуле принята")
	}
	const want = "Illegal argument resources (wildcard '*' is confined to the owning module " +
		"'vpc'; this rule names module 'compute')"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("отказ не называет оба значения:\n получено %v\n ожидалось %q", err, want)
	}
}

// TestIAMOM104_VerbWildcardIsNotNarrowed — IAM-OM-1-04, положительный контроль.
//
// Глагол `*` разрешён и в арендаторской роли безусловно: он не сегмент
// пространства имён, а «все действия названного типа». Сузить его здесь значило
// бы отобрать уже выданное под видом починки.
func TestIAMOM104_VerbWildcardIsNotNarrowed(t *testing.T) {
	for _, p := range []struct {
		name   string
		policy domain.RulePolicy
	}{
		{"модульная", domain.PolicyOfRole(true, "vpc")},
		{"платформенная", domain.PolicyOfRole(true, "")},
		{"арендаторская", domain.TenantPolicy()},
	} {
		r := domain.Rule{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"*"}}
		if err := r.Validate(p.policy, fixtureModules()); err != nil {
			t.Errorf("%s политика сузила глагол `*`: %v", p.name, err)
		}
	}
}

// TestIAMOM105_PlatformRoleKeepsItsRelaxation — IAM-OM-1-05.
//
// Форма — та, которую несут строки посева системных ролей. Обратное было бы
// отзывом уже выданного и сделало бы применённую миграцию невоспроизводимой.
func TestIAMOM105_PlatformRoleKeepsItsRelaxation(t *testing.T) {
	r := domain.Rule{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}}
	if err := r.Validate(domain.PolicyOfRole(true, ""), fixtureModules()); err != nil {
		t.Fatalf("платформенная роль потеряла послабление — это отзыв уже выданного: %v", err)
	}
}

// TestIAMOM117_TenantTextsDoNotMove — IAM-OM-1-17.
//
// Арендаторские тексты утверждаются ПОБАЙТОВО: они часть контракта, и сдвинуть
// их означало бы сменить ответ на вход, о котором эта задача не решала ничего.
func TestIAMOM117_TenantTextsDoNotMove(t *testing.T) {
	for _, c := range []struct {
		rule domain.Rule
		want string
	}{
		{ruleOn("*", "network"), "Illegal argument module (wildcard '*' is system-only)"},
		{ruleOn("vpc", "*"), "Illegal argument resources (wildcard '*' is system-only)"},
	} {
		err := c.rule.Validate(domain.TenantPolicy(), fixtureModules())
		if err == nil {
			t.Fatalf("арендаторская политика приняла подстановку: %+v", c.rule)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("арендаторский текст сдвинулся:\n получено %v\n ожидалось %q", err, c.want)
		}
	}
}

// TestPolicyIsDerivedFromTheRowInOnePlace — «не системная, но с владельцем»
// получает САМУЮ СТРОГУЮ политику.
//
// Два булевых параметра дают четыре сочетания при трёх законных, и четвёртое
// пришлось бы отвергать четвёртым правилом. Здесь оно не отвергается, а
// СВОДИТСЯ к арендаторскому: послабление выдаётся по доказанному признаку, а не
// по частично совпавшему.
func TestPolicyIsDerivedFromTheRowInOnePlace(t *testing.T) {
	err := ruleOn("vpc", "*").Validate(domain.PolicyOfRole(false, "vpc"), fixtureModules())
	if err == nil {
		t.Fatal("сочетание «не системная, но с владельцем» получило послабление: " +
			"признак совпал частично, а послабление выдано целиком")
	}
	if !strings.Contains(err.Error(), "is system-only") {
		t.Errorf("вырожденное сочетание судится не арендаторской политикой: %v", err)
	}
	if got := domain.PolicyOfRole(true, "vpc").OwnerModule(); got != "vpc" {
		t.Errorf("владелец модульной политики потерян: %q", got)
	}
	if got := domain.PolicyOfRole(true, "").OwnerModule(); got != "" {
		t.Errorf("у платформенной политики появился владелец: %q", got)
	}
}

// TestZeroPolicyIsTheStrictestBranch — политика, собранная НЕ через
// [domain.PolicyOfRole], послабления не даёт.
//
// «Не знаю» не есть «можно»: нулевое значение обязано вести себя как самое
// строгое, иначе забытая инициализация открывала бы подстановку молча.
func TestZeroPolicyIsTheStrictestBranch(t *testing.T) {
	var zero domain.RulePolicy
	if err := ruleOn("*", "network").Validate(zero, fixtureModules()); err == nil {
		t.Fatal("нулевая политика приняла подстановку модуля")
	}
	if err := ruleOn("vpc", "*").Validate(zero, fixtureModules()); err == nil {
		t.Fatal("нулевая политика приняла подстановку ресурса")
	}
}
