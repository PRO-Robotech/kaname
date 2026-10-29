// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// role_preview_holding_test.go — IAM-CCR-20 приёмки
// `catalog-consequence-reaches-role-readers.md`: превью роли судит явный глагол
// правила, адресующего ресурс, признаком «сегмент держится», подстановку —
// наборами ресурсов с держащимся якорем; правило без адресуемых ресурсов даёт
// свои глаголы как прежде; глагол ЯРУСНОЙ пары судится строкой каталога пары.
//
// Каждое «И» сценария — свой кейс, и у каждого назван близнец, отличающийся
// ОДНИМ фактом. Слой — чистая функция домена, без базы.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// ccrTierOnly — перечень ярусных классов в форме, какой его подаёт владелец
// набора (`authzmap.TierOnlyVerbClasses`, сегодня один класс). Домен литерал не
// переписывает — проба подаёт его входом, как подаёт провязка.
var ccrTierOnly = []string{"create"}

// ccrFive — набор глаголов пары, отвечающий пятёркой на всякую названную пару:
// на явном глаголе неярусного класса набор не решает ничего, и кейсы, где он
// полный, утверждают именно это.
func ccrFive(module, resource string) ([]string, bool) {
	_, _ = module, resource
	return []string{"get", "list", "create", "update", "delete"}, true
}

// ccrUnheld — признак, называющий неудержанными перечисленные сегменты
// `тип/глагол` (пустой глагол — якорь).
func ccrUnheld(segs ...[2]string) PreviewHolding {
	out := make([]RoleSegment, 0, len(segs))
	for _, s := range segs {
		out = append(out, RoleSegment{ObjectType: s[0], Verb: s[1]})
	}
	return PreviewHoldingOf(out, ccrTierOnly)
}

// ccrRole — роль арендатора с признаком.
func ccrRole(h PreviewHolding, rules ...Rule) Role {
	return Role{Rules: Rules(rules), Holding: h}
}

func TestPreview_IAMCCR20_UnheldSegmentGivesNoVerb(t *testing.T) {
	thing := Rule{Module: "probe", Resources: []string{"thing"}, Verbs: []string{"get", "delete"}}
	instance := Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"list"}}

	// Дано: неудержаны оба сегмента первого правила.
	r := ccrRole(ccrUnheld([2]string{"probe.thing", "get"}, [2]string{"probe.thing", "delete"}), thing, instance)
	require.Equal(t, []string{"list"}, r.AuthoredVerbs(ccrFive),
		"явный глагол без держащегося сегмента остался в превью — обещание отобранного права")
	require.Equal(t, []string{"list"}, r.EffectiveVerbs(ccrFive))

	// И: близнец — держится всё. Отличается одним фактом: признак пуст.
	all := ccrRole(ccrUnheld(), thing, instance)
	require.Equal(t, []string{"get", "list", "delete"}, all.AuthoredVerbs(ccrFive),
		"близнец: при держащихся сегментах превью обязано быть прежним")

	// И: гранулярность СЕГМЕНТА, а не правила — неудержан только delete.
	one := ccrRole(ccrUnheld([2]string{"probe.thing", "delete"}), thing, instance)
	require.Equal(t, []string{"get", "list"}, one.AuthoredVerbs(ccrFive),
		"правило дало ВСЕ свои глаголы при одном держащемся сегменте — гранулярность "+
			"правила вместо сегмента (§2.3, пункт 1)")
}

func TestPreview_IAMCCR20_TierPairIsJudgedByItsCatalogRow(t *testing.T) {
	rule := Rule{Module: "probe", Resources: []string{"thing"}, Verbs: []string{"get", "create"}}

	// Пара ЯРУСНАЯ: набор пары резолвится, `create` в него не входит.
	tierRow := func(module, resource string) ([]string, bool) {
		if module == "probe" && resource == "thing" {
			return []string{"get", "list", "update", "delete"}, true
		}
		return nil, false
	}
	tier := ccrRole(ccrUnheld([2]string{"probe.thing", "create"}), rule)
	require.Equal(t, []string{"get", "create"}, tier.AuthoredVerbs(tierRow),
		"глагол ЯРУСНОЙ пары ушёл из превью: проекция выдач его не держит никогда, а право "+
			"выдаётся ярусным кортежем — превью стало у́же выдачи")

	// Близнец: неудержан `get`, а не `create`.
	getGone := ccrRole(ccrUnheld([2]string{"probe.thing", "get"}), rule)
	require.Equal(t, []string{"create"}, getGone.AuthoredVerbs(tierRow))

	// Пара ПООБЪЕКТНАЯ того же класса: `create` в наборе пары есть.
	perObject := func(module, resource string) ([]string, bool) {
		if module == "probe" && resource == "thing" {
			return []string{"get", "list", "create", "update", "delete"}, true
		}
		return nil, false
	}
	po := ccrRole(ccrUnheld([2]string{"probe.thing", "create"}), rule)
	require.Equal(t, []string{"get"}, po.AuthoredVerbs(perObject),
		"пообъектная пара ярусного класса получила ярусную ветвь — вывод по КЛАССУ, а не по "+
			"ПАРЕ: обещание права, строки которого проекция не держит")

	// Пара, чей набор не резолвится (ресурс снят либо неизвестен).
	gone := func(string, string) ([]string, bool) { return nil, false }
	g := ccrRole(ccrUnheld([2]string{"probe.thing", "create"}), rule)
	require.Equal(t, []string{"get"}, g.AuthoredVerbs(gone),
		"ярусная ветвь дана паре снятого ресурса — пункт 3 сам стал экземпляром класса #76")
}

func TestPreview_IAMCCR20_RuleWithoutAddressableResourcesIsAsBefore(t *testing.T) {
	unheld := ccrUnheld(
		[2]string{"compute.instance", "get"},
		[2]string{"compute.instance", "list"},
		[2]string{"compute.instance", "update"},
	)
	lookup := WithCommonFallback(ccrFive, []string{"get", "list", "create", "update", "delete"})

	// Форма посеянной системной роли `edit`: адресуемых сегментов ноль.
	edit := ccrRole(unheld, Rule{Module: wildcard, Resources: []string{wildcard}, Verbs: []string{"get", "list", "update"}})
	require.Equal(t, []string{"get", "list", "update"}, edit.AuthoredVerbs(lookup),
		"правило без адресуемых ресурсов опустело — буквальное прочтение биконъюнкции "+
			"пункта 1 (§2.3, «Цена буквального прочтения»)")
	require.Equal(t, []string{"get", "list", "update", EditorDeleteVerb}, edit.EffectiveVerbs(lookup))

	// Близнец: то же правило с адресуемым ресурсом при ДОСЛОВНО том же признаке.
	named := ccrRole(unheld, Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "list", "update"}})
	require.Empty(t, named.AuthoredVerbs(lookup),
		"близнец: адресуемые сегменты не держатся — превью обязано быть пустым")
	require.Empty(t, named.EffectiveVerbs(lookup))
}

func TestPreview_IAMCCR20_WildcardExpandsOnlyResourcesWithAHeldAnchor(t *testing.T) {
	sets := func(module, resource string) ([]string, bool) {
		switch module + "." + resource {
		case "probe.widgets":
			return []string{"get", "list", "update", "delete"}, true
		case "probe.spare":
			return []string{"get", "list"}, true
		}
		return nil, false
	}
	v := ccrRole(ccrUnheld([2]string{"probe.widgets", ""}),
		Rule{Module: "probe", Resources: []string{"widgets", "spare"}, Verbs: []string{"*"}})
	require.Equal(t, []string{"get", "list"}, v.AuthoredVerbs(sets),
		"подстановка развернулась набором ресурса с НЕудержанным якорем — обещание update и "+
			"delete, которых роль не держит нигде (§2.3, пункт 2)")

	// Близнец: якорь widgets держится.
	held := ccrRole(ccrUnheld(),
		Rule{Module: "probe", Resources: []string{"widgets", "spare"}, Verbs: []string{"*"}})
	require.Equal(t, []string{"get", "list", "update", "delete"}, held.AuthoredVerbs(sets))
}

func TestPreview_IAMCCR20_EditorQualifierFollowsTheNarrowedSet(t *testing.T) {
	// Роль D мира М: правка по снятому ресурсу, чтение по живому.
	d := ccrRole(ccrUnheld([2]string{"probe.widgets", "update"}),
		Rule{Module: "probe", Resources: []string{"widgets"}, Verbs: []string{"update"}},
		Rule{Module: "probe", Resources: []string{"gadgets"}, Verbs: []string{"get"}})
	require.Equal(t, []string{"get"}, d.EffectiveVerbs(ccrFive),
		"квалификатор редактора пережил своё основание")
	require.Empty(t, d.VerbNotes(ccrFive))
}

func TestPreviewHolding_ZeroValueIsUnread(t *testing.T) {
	require.False(t, PreviewHolding{}.Read(), "нулевое значение обязано значить «не прочитано»")
	require.True(t, PreviewHoldingOf(nil, nil).Read(),
		"пустой ответ проекции — прочитанный признак «держится всё», а не «не прочитано»")
}
