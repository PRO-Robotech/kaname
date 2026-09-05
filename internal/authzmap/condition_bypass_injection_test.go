// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// condition_bypass_injection_test.go — доказательство того, что гейт
// `TestConditionBypassedByAnArmNeedsTheEdgeEnforcer` СПОСОБЕН упасть
// (задача продукта #2056).
//
// Гейт сегодня МОЛЧИТ по построению: читателя у обходимых отношений ноль. Поэтому
// его способность краснеть доказывается только инъекцией, и доказывать её надо
// тем строже, чем дольше он молчит: молчание проверки, которая разучилась падать,
// неотличимо от молчания исправной.
//
// Осей пять, и по каждой утверждаются ОБЕ стороны:
//
//	1. читатель без величины усиленного входа  → находка;
//	   тот же читатель С величиной             → молчание;
//	2. условие БЕЗ обходной ветви              → молчание (не наш предмет);
//	3. ветвь БЕЗ условия                       → молчание (не наш предмет);
//	4. разбор судит УЗЛЫ, а не слова: `or` и `with` в комментарии и в имени
//	   условия предметом не являются;
//	5. пустая модель                           → разбирать нечего, и предпосылка
//	   гейта обязана это отсечь, а не объявить «находок ноль».

package authzmap_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const modelFixture = `model
  schema 1.1

type user

type compute_instance
  relations
    define project: [project]
    define admin: [user, service_account, group#member]
    # ссылка на условие в комментарии: слова with и or здесь не предмет
    define ssh: [user with mfa_fresh, service_account] or admin
    define fresh_only: [user with mfa_fresh]
    define plain_or: [user] or admin
`

func declsOfFixture(t *testing.T) []conditionalDecl {
	t.Helper()
	decls, types := parseConditionalDecls(modelFixture)
	require.NotZero(t, types, "фикстура обязана разбираться в типы")
	require.NotEmpty(t, decls, "фикстура обязана разбираться в объявления")
	return decls
}

func TestConditionBypassGateRedsOnAReaderWithoutTheEdgeValue(t *testing.T) {
	findings := conditionBypassFindings(declsOfFixture(t), []catalogReader{
		{fqn: "kacho.cloud.compute.v1.InstanceService/Ssh", relation: "ssh", objectType: "compute_instance"},
	})
	require.Len(t, findings, 1, "читатель обходимого отношения без величины входа — находка")
	require.Contains(t, findings[0], "InstanceService/Ssh", "находка обязана назвать RPC")
	require.Contains(t, findings[0], "compute_instance#ssh", "находка обязана назвать отношение")
	require.Contains(t, findings[0], "required_acr_min")
}

func TestConditionBypassGateIsSilentWhenTheEdgeEnforces(t *testing.T) {
	findings := conditionBypassFindings(declsOfFixture(t), []catalogReader{
		{fqn: "kacho.cloud.compute.v1.InstanceService/Ssh", relation: "ssh",
			objectType: "compute_instance", acrMin: "2"},
	})
	require.Empty(t, findings, "читатель, несущий величину усиленного входа, находкой не является")
}

func TestConditionBypassGateDoesNotOverreach(t *testing.T) {
	// Условие БЕЗ обходной ветви — требование исполняет сама модель.
	fresh := conditionBypassFindings(declsOfFixture(t), []catalogReader{
		{fqn: "X/FreshOnly", relation: "fresh_only", objectType: "compute_instance"},
	})
	require.Empty(t, fresh, "отношение без обходной ветви предметом гейта не является")

	// Ветвь БЕЗ условия — требования не объявлено вовсе, обходить нечего.
	plain := conditionBypassFindings(declsOfFixture(t), []catalogReader{
		{fqn: "X/PlainOr", relation: "plain_or", objectType: "compute_instance"},
	})
	require.Empty(t, plain, "отношение без условия предметом гейта не является")

	// И читателя вовсе нет — сегодняшнее состояние дерева.
	require.Empty(t, conditionBypassFindings(declsOfFixture(t), nil))
}

func TestConditionBypassParserJudgesNodesNotWords(t *testing.T) {
	decls := declsOfFixture(t)
	byName := map[string]conditionalDecl{}
	for _, d := range decls {
		byName[d.relation] = d
	}

	require.True(t, byName["ssh"].conditioned, "условие обязано быть найдено в прямом присвоении")
	require.True(t, byName["ssh"].bypassed, "обходная ветвь обязана быть найдена ПОСЛЕ присвоения")
	require.True(t, byName["fresh_only"].conditioned)
	require.False(t, byName["fresh_only"].bypassed, "ветви после присвоения нет")
	require.False(t, byName["plain_or"].conditioned, "условия в присвоении нет")
	require.True(t, byName["plain_or"].bypassed)
	require.False(t, byName["admin"].conditioned)
	require.False(t, byName["admin"].bypassed)

	// Строка-комментарий объявлением не является — иначе слова `with` и `or` в
	// прозе рядом с отношением давали бы предмет из ничего.
	_, isComment := byName["ссылка"]
	require.False(t, isComment)
}

func TestConditionBypassGateRefusesAnEmptyModel(t *testing.T) {
	decls, types := parseConditionalDecls("")
	require.Zero(t, types)
	require.Empty(t, decls)
	require.Empty(t, conditionBypassFindings(decls, []catalogReader{
		{fqn: "X/Ssh", relation: "ssh", objectType: "compute_instance"},
	}), "на пустой модели судья находок не даёт — поэтому «ноль находок» обязан "+
		"отсекаться предпосылкой гейта, а не читаться как зелёное")
}
