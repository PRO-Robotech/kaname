// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// verbcondition_admission_test.go — доставленный ГЛАГОЛ с условием отвергается
// допуском, то есть отказом ПУСКА, а не молчаливой выдачей права (#1979).
//
// # Почему проба здесь, а не только у разбора
//
// Невыразимость такого плана держит `authzplan` (verbcondition_test.go). Здесь
// утверждается ШОВ: что невыразимость доезжает до допуска правилом Д5′ и что
// поэтому доставка с таким глаголом НЕ УСТАНАВЛИВАЕТСЯ. Без этого утверждения
// «разбор объявил невыразимым» и «служба отказалась стартовать» — два разных
// факта, и второй никем не проверен.
//
// # Почему предмет достижим именно доставкой
//
// Условие `mfa_fresh` объявлено КАНОНОМ, поэтому правило Д4(б) («всякое условие
// нового типа — имя из условий канона») его пропускает: имя законное. Строку
// `condition` доставка добавить не может вовсе — Д7(б) допускает за границей
// префикса только пять форм, и `condition` среди них нет. То есть единственный
// способ внести условие доставкой — сослаться на каноническое имя, и ровно этот
// способ здесь и проверяется.
//
// Гейт, на который сослался потребитель
// (`relverdict.TestNoConditionedRelationIsAVerb`), читает КАНОН
// (`ResolveCanonicalModel`) и доставленного типа не видит by construction —
// поэтому он этот шов не закрывает и закрыть не может.
package authzmodel

import (
	"strings"
	"testing"
)

// TestDeliveredVerbWithConditionIsRefused — несущее утверждение.
func TestDeliveredVerbWithConditionIsRefused(t *testing.T) {
	block := swapDecl(twin(t),
		"define v_get: [user, service_account, group#member] or super_admin",
		"define v_get: [user with mfa_fresh, service_account, group#member] or super_admin")
	composed := compose(block)

	rep, err := Admit(composed)
	if err != nil {
		t.Fatalf("допуск обязан вернуть отчёт, а не ошибку: %v", err)
	}
	if rep.Admitted() {
		t.Fatalf("доставленный ГЛАГОЛ с условием ДОПУЩЕН (находок %d).\n"+
			"Привязка роли условия не несёт: право было бы выдано при невыполненном условии, "+
			"и снаружи это неотличимо от штатной выдачи", len(rep.Findings))
	}
	got := findingsOf(rep, RuleD5)
	if len(got) == 0 {
		t.Fatalf("ждали находку %s (план объявления нового типа невыразим), получено %v", RuleD5, rules(rep))
	}
	joined := ""
	for _, f := range got {
		joined += f.String() + "\n"
	}
	for _, want := range []string{"acme_widget", "v_get", "mfa_fresh"} {
		if !strings.Contains(joined, want) {
			t.Errorf("находка обязана называть координату и условие; нет %q в:\n%s", want, joined)
		}
	}
	t.Logf("осмотрено: находок %v; отказ пуска назван: %s", rules(rep), strings.TrimSpace(joined))
}

// TestDeliveredConditionOnNonVerbIsAdmitted — положительный близнец 1.
//
// Без него отказ выше зеленел бы и у допуска, отвергающего ВСЯКОЕ условие
// доставленного типа, — то есть у того, который запретил бы доставке ровно ту
// форму, что канон употребляет сам и считает законной.
func TestDeliveredConditionOnNonVerbIsAdmitted(t *testing.T) {
	block := swapDecl(twin(t),
		"define viewer: [user, service_account, group#member] or editor",
		"define viewer: [user with mfa_fresh, service_account, group#member] or editor")
	composed := compose(block)

	rep, err := Admit(composed)
	if err != nil {
		t.Fatalf("допуск обязан вернуть отчёт: %v", err)
	}
	if !rep.Admitted() {
		t.Fatalf("условие на НЕ-глаголе обязано допускаться: строка факта несёт условие на себе "+
			"и вычисляется на пути запроса. Находки: %v", rep.Findings)
	}
	t.Logf("осмотрено: условие на не-глаголе допущено, находок 0")
}

// TestDeliveredLawfulTwinIsAdmitted — положительный близнец 2: тот же блок БЕЗ
// условия. Он доказывает, что отказ выше даёт условие, а не сам близнец.
func TestDeliveredLawfulTwinIsAdmitted(t *testing.T) {
	rep, err := Admit(compose(twin(t)))
	if err != nil {
		t.Fatalf("допуск обязан вернуть отчёт: %v", err)
	}
	if !rep.Admitted() {
		t.Fatalf("законный близнец обязан допускаться, находки: %v", rep.Findings)
	}
}

// TestPlansRefuseDeliveredVerbWithCondition — второй потребитель того же шва.
//
// Допуск отказывает ПУСКУ, но `Plans` строится и напрямую (`New`), и на нём
// решение о доступе принимается. Утверждение «допуск отказал» о нём ничего не
// говорит: у плана несколько потребителей, и молчание одного из них здесь
// читалось бы как выданное право.
func TestPlansRefuseDeliveredVerbWithCondition(t *testing.T) {
	block := swapDecl(twin(t),
		"define v_get: [user, service_account, group#member] or super_admin",
		"define v_get: [user with mfa_fresh, service_account, group#member] or super_admin")

	plans, err := New(compose(block))
	if err != nil {
		t.Fatalf("разбор обязан состояться — иначе проба утверждает о входе, которого не построила: %v", err)
	}
	if _, err := plans.Plan("acme_widget", "v_get"); err == nil {
		t.Fatal("потребитель ОТДАЛ план с условием на глаголе: вердикт по нему выдал бы право " +
			"при невыполненном условии")
	}
	// Положительный контроль в той же пробе: соседний глагол того же типа
	// условия не несёт и обязан компилироваться. Без него отказ выше зеленел бы
	// и у потребителя, сломавшегося на всём типе целиком.
	if _, err := plans.Plan("acme_widget", "v_list"); err != nil {
		t.Fatalf("глагол без условия обязан компилироваться: %v", err)
	}
	t.Log("осмотрено: v_get с условием отвергнут, v_list без условия компилируется")
}
