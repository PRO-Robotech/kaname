// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// role_rule_state_test.go — постатейное состояние правила роли.
//
// Приёмка `services/iam/docs/engineering/acceptance/rule-state-names-withdrawn-apart-from-unresolved.md`,
// сценарии MOD-RS-01…05, 09…11. Чистые величины, без базы.
//
// Здесь утверждается ФУНКЦИЯ. Что состояние, которое она называет, представимо
// в ЭТОМ дереве, — отдельное утверждение и отдельная проба (интеграционная).

import "testing"

// ruleOf — правило в форме, которой их пишет арендатор.
func ruleOf(module string, resources, verbs []string) Rule {
	return Rule{Module: module, Resources: resources, Verbs: verbs}
}

// MOD-RS-01 — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ. Без него всякое отрицание ниже зеленело бы
// на реализации, всегда возвращающей UNRESOLVED.
func TestRuleState_MODRS01_NothingLost_IsActive(t *testing.T) {
	rules := Rules{
		ruleOf("vpc", []string{"network"}, []string{"get", "delete"}),
		ruleOf("compute", []string{"instance"}, []string{"get"}),
	}
	got := RuleStatesOf(rules, nil, nil)
	if len(got) != len(rules) {
		t.Fatalf("записей %d, правил %d — обязаны совпасть", len(got), len(rules))
	}
	for i, st := range got {
		if st.State != RuleLifecycleActive {
			t.Fatalf("правило %d: состояние %v, ожидалось ACTIVE", i, st.State)
		}
		if st.Lost != 0 || st.Explained != 0 {
			t.Fatalf("правило %d: потери %d, объяснено %d — ожидалось 0/0", i, st.Lost, st.Explained)
		}
	}
	if got[0].Segments != 2 {
		t.Fatalf("правило 0 объявляет %d сегментов, ожидалось 2", got[0].Segments)
	}
}

// MOD-RS-02 — потеря ОБЪЯСНЕНА ведомостью: отозвано. Соседнее правило остаётся
// действующим — без этой половины утверждение было бы односторонним и зеленело
// бы на реализации, объявляющей отозванными все правила разом.
func TestRuleState_MODRS02_LossExplainedByLedger_IsWithdrawn(t *testing.T) {
	rules := Rules{
		ruleOf("vpc", []string{"network"}, []string{"get"}),
		ruleOf("vpc", []string{"gateway"}, []string{"delete"}),
	}
	unresolved := []RoleSegment{{ObjectType: "vpc.gateway", Verb: "delete"}}
	withdrawn := []WithdrawnGrant{{ObjectType: "vpc.gateway", Verb: "delete", Reason: "снят из манифеста"}}

	got := RuleStatesOf(rules, unresolved, withdrawn)
	if got[1].State != RuleLifecycleWithdrawn {
		t.Fatalf("правило 1: состояние %v, ожидалось WITHDRAWN", got[1].State)
	}
	if got[1].Lost != 1 || got[1].Explained != 1 {
		t.Fatalf("правило 1: потерь %d, объяснено %d — ожидалось 1/1", got[1].Lost, got[1].Explained)
	}
	if got[0].State != RuleLifecycleActive {
		t.Fatalf("правило 0: состояние %v, ожидалось ACTIVE — соседнее не задето", got[0].State)
	}
}

// MOD-RS-03 — форма инцидента 513001: потеря есть, ведомости НЕТ. Это и есть
// различие, ради которого заведён предмет: без слова оно неотличимо от MOD-RS-02.
func TestRuleState_MODRS03_LossWithoutLedger_IsUnresolvedNotWithdrawn(t *testing.T) {
	rules := Rules{ruleOf("vpc", []string{"gateway"}, []string{"delete"})}
	unresolved := []RoleSegment{{ObjectType: "vpc.gateway", Verb: "delete"}}

	got := RuleStatesOf(rules, unresolved, nil)
	if got[0].State == RuleLifecycleWithdrawn {
		t.Fatal("необъяснённая потеря названа WITHDRAWN — отозванное неотличимо от неразрешённого")
	}
	if got[0].State != RuleLifecycleUnresolved {
		t.Fatalf("состояние %v, ожидалось UNRESOLVED", got[0].State)
	}
	if got[0].Lost != 1 || got[0].Explained != 0 {
		t.Fatalf("потерь %d, объяснено %d — ожидалось 1/0", got[0].Lost, got[0].Explained)
	}
}

// MOD-RS-04 — смешанный случай НЕ схлопывается: слово называет состояние,
// требующее разбора, а обе величины видны одновременно.
func TestRuleState_MODRS04_MixedLoss_KeepsBothCounters(t *testing.T) {
	rules := Rules{ruleOf("vpc", []string{"gateway", "address"}, []string{"delete"})}
	unresolved := []RoleSegment{
		{ObjectType: "vpc.gateway", Verb: "delete"},
		{ObjectType: "vpc.address", Verb: "delete"},
	}
	withdrawn := []WithdrawnGrant{{ObjectType: "vpc.gateway", Verb: "delete", Reason: "снят"}}

	got := RuleStatesOf(rules, unresolved, withdrawn)
	if got[0].State != RuleLifecycleUnresolved {
		t.Fatalf("состояние %v, ожидалось UNRESOLVED — необъяснённая потеря сильнее", got[0].State)
	}
	if got[0].Explained != 1 {
		t.Fatalf("объяснённых %d, ожидалась 1 — величина потеряна вместе со словом", got[0].Explained)
	}
	if got[0].Lost-got[0].Explained != 1 {
		t.Fatalf("необъяснённых %d, ожидалась 1", got[0].Lost-got[0].Explained)
	}
}

// MOD-RS-05 — правило без АДРЕСУЕМЫХ сегментов действует, а не пусто: терять ему
// нечего. Прибор, чьи находки ложны, перестают читать.
func TestRuleState_MODRS05_NothingAddressable_IsActive(t *testing.T) {
	rules := Rules{
		ruleOf("*", []string{"*"}, []string{"*"}),
		ruleOf("vpc", []string{"*"}, []string{"get"}),
	}
	got := RuleStatesOf(rules, nil, nil)
	for i, st := range got {
		if st.Segments != 0 {
			t.Fatalf("правило %d объявляет %d адресуемых сегментов, ожидалось 0", i, st.Segments)
		}
		if st.State != RuleLifecycleActive {
			t.Fatalf("правило %d: состояние %v, ожидалось ACTIVE", i, st.State)
		}
	}
}

// MOD-RS-09 — сегмент, объявленный ДВУМЯ правилами, потерян у ОБОИХ. Проверяет,
// что разложение по правилам не дедуплицирует между ними: схлопнув, мы объявили
// бы одно из правил действующим.
func TestRuleState_MODRS09_SegmentSharedByTwoRules_BothWithdrawn(t *testing.T) {
	rules := Rules{
		ruleOf("vpc", []string{"gateway"}, []string{"delete"}),
		ruleOf("vpc", []string{"gateway"}, []string{"delete"}),
	}
	unresolved := []RoleSegment{{ObjectType: "vpc.gateway", Verb: "delete"}}
	withdrawn := []WithdrawnGrant{{ObjectType: "vpc.gateway", Verb: "delete", Reason: "снят"}}

	got := RuleStatesOf(rules, unresolved, withdrawn)
	for i, st := range got {
		if st.State != RuleLifecycleWithdrawn {
			t.Fatalf("правило %d: состояние %v, ожидалось WITHDRAWN у обоих", i, st.State)
		}
	}
}

// MOD-RS-10 — записей ровно по числу правил, и ключ указывает на своё правило.
// Без этого `RuleIndex` был бы ложной координатой.
func TestRuleState_MODRS10_OneEntryPerRuleKeyedByIndex(t *testing.T) {
	rules := Rules{
		ruleOf("*", []string{"*"}, []string{"*"}),
		ruleOf("vpc", []string{"network"}, []string{"get"}),
		ruleOf("compute", []string{"instance"}, []string{"get", "delete"}),
	}
	got := RuleStatesOf(rules, nil, nil)
	if len(got) != 3 {
		t.Fatalf("записей %d, правил 3", len(got))
	}
	want := []int{0, 1, 2}
	for i, st := range got {
		if st.RuleIndex != want[i] {
			t.Fatalf("запись %d несёт ключ %d", i, st.RuleIndex)
		}
	}
	if got[0].Segments != 0 || got[1].Segments != 1 || got[2].Segments != 2 {
		t.Fatalf("объявлено %d/%d/%d, ожидалось 0/1/2",
			got[0].Segments, got[1].Segments, got[2].Segments)
	}
}

// MOD-RS-11 — ЯКОРЬ сверяется якорем. Правило с глаголом `*` даёт сегмент с
// пустым глаголом, и объясняет его якорная строка ведомости — а НЕ строка,
// назвавшая какой-то один глагол.
func TestRuleState_MODRS11_AnchorMatchesAnchorOnly(t *testing.T) {
	rules := Rules{ruleOf("vpc", []string{"gateway"}, []string{"*"})}
	unresolved := []RoleSegment{{ObjectType: "vpc.gateway", Verb: ""}}

	anchored := RuleStatesOf(rules, unresolved,
		[]WithdrawnGrant{{ObjectType: "vpc.gateway", Verb: "", Reason: "снят"}})
	if anchored[0].State != RuleLifecycleWithdrawn {
		t.Fatalf("якорь при якорной строке ведомости: %v, ожидалось WITHDRAWN", anchored[0].State)
	}

	// Обратная сторона: строка ведомости на ИМЕНОВАННЫЙ глагол якорь не
	// объясняет. Без этой половины сверка «по типу» прошла бы за сверку «по паре».
	named := RuleStatesOf(rules, unresolved,
		[]WithdrawnGrant{{ObjectType: "vpc.gateway", Verb: "delete", Reason: "снят"}})
	if named[0].State != RuleLifecycleUnresolved {
		t.Fatalf("якорь при именованной строке ведомости: %v, ожидалось UNRESOLVED", named[0].State)
	}
}

// Ноль отличим от «не считали»: вычисленное состояние непусто ВСЕГДА.
func TestRuleState_ZeroIsDistinguishableFromNotComputed(t *testing.T) {
	rules := Rules{ruleOf("*", []string{"*"}, []string{"*"})}
	got := RuleStatesOf(rules, nil, nil)
	if got[0].State == RuleLifecycleUnknown {
		t.Fatal("вычисленное состояние равно нулевому варианту — «посчитано» неотличимо от «не считали»")
	}
	if RuleStatesOf(nil, nil, nil) != nil {
		t.Fatal("у роли без правил записей быть не может")
	}
}

// RuleRefsByRule сохраняет ДЛИНУ входа: правило без адресуемых сегментов даёт
// пустой срез, а не пропускается. Иначе индекс перестал бы указывать на своё
// правило.
func TestRuleRefsByRule_LengthMatchesInputAlways(t *testing.T) {
	rules := Rules{
		ruleOf("*", []string{"*"}, []string{"*"}),
		ruleOf("vpc", []string{"network", "subnet"}, []string{"get"}),
	}
	got := RuleRefsByRule(rules)
	if len(got) != len(rules) {
		t.Fatalf("срезов %d, правил %d", len(got), len(rules))
	}
	if len(got[0]) != 0 {
		t.Fatalf("подстановка дала %d сегментов, ожидалось 0", len(got[0]))
	}
	if len(got[1]) != 2 {
		t.Fatalf("правило на два ресурса дало %d сегментов, ожидалось 2", len(got[1]))
	}
	// Дедупликация ВНУТРИ правила остаётся: повтор ресурса сегментов не удваивает.
	dup := RuleRefsByRule(Rules{ruleOf("vpc", []string{"network", "network"}, []string{"get"})})
	if len(dup[0]) != 1 {
		t.Fatalf("повтор ресурса дал %d сегментов, ожидался 1", len(dup[0]))
	}
}

// Единица постатейной величины ДРУГАЯ, чем у счётчика роли, и это утверждается
// числами, а не комментарием: сегмент, объявленный двумя правилами, у роли один,
// а у правил — по одному каждому. Сложи мы их в одно имя, арендатор увидел бы
// два разных числа под одной подписью.
func TestRuleState_UnitDiffersFromTheRoleCounterOnPurpose(t *testing.T) {
	rules := Rules{
		ruleOf("vpc", []string{"gateway"}, []string{"delete"}),
		ruleOf("vpc", []string{"gateway"}, []string{"delete"}),
	}
	roleDeclared := len(RuleRefsOf(rules))
	if roleDeclared != 1 {
		t.Fatalf("счётчик роли %d, ожидался 1 — дедупликация по всей роли", roleDeclared)
	}
	sum := 0
	for _, st := range RuleStatesOf(rules, nil, nil) {
		sum += st.Segments
	}
	if sum != 2 {
		t.Fatalf("сумма по правилам %d, ожидалась 2 — дедупликации между правилами быть не должно", sum)
	}
	if sum == roleDeclared {
		t.Fatal("суммы совпали: единицы схлопнулись, и различие потеряно")
	}
}
