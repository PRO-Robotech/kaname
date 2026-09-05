// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzplan

import (
	"strings"
	"testing"
)

// verbcondition_test.go — условие на прямом списке ГЛАГОЛА формой E не
// выражается, и план обязан объявить это, а не отдать безусловный атом (#1979).
//
// # Почему это невыразимость, а не справка
//
// Прямой список глагола на самом объекте разворачивается из ПРИВЯЗКИ роли, и
// форма E ставит ему в соответствие привязку. Привязка условия не несёт: роль
// раздаёт глаголы, и места под `condition_name` у неё нет. Значит условие,
// написанное на таком списке, при вердикте ИСЧЕЗАЕТ — право выдаётся при
// невыполненном условии.
//
// Это отличается от условия на отношении-НЕ-глаголе: тому соответствует атом
// факта, а строка факта условие несёт на себе (`condition_name`/
// `condition_params`) и вычисляется на пути запроса. Там условие не теряется, и
// объявлять такой план невыразимым значило бы отобрать доступ у трёх живых
// отношений канона вместе с их БЕЗУСЛОВНЫМИ источниками.
//
// Различает эти два случая ровно то, какой АТОМ порождает терм, — поэтому и
// проверка стоит рядом с порождением атома, а не в потребителе: потребителей у
// плана несколько, и каждый решал бы этот вопрос заново.
//
// # Почему предмет достижим, а не искусствен
//
// В КАНОНЕ такого нет: все три условных отношения — не глаголы. Предмет
// появляется вместе со сборкой модели из доставленных манифестов: имя условия
// канона доставленному типу доступно, и `[user with mfa_fresh]` на глаголе
// проходит и разбор, и допуск. Гейт, на который сослался потребитель
// (`relverdict.TestNoConditionedRelationIsAVerb`), читает КАНОН и доставленный
// тип не видит by construction.

const verbConditionDSL = `type user
type acme_widget
  relations
    define v_get: [user with mfa_fresh]
`

// TestConditionOnVerbDirectListIsInexpressible — несущее утверждение.
func TestConditionOnVerbDirectListIsInexpressible(t *testing.T) {
	m, err := ParseModel(verbConditionDSL)
	if err != nil {
		t.Fatalf("предпосылка: этот вход разбор обязан ПРИНИМАТЬ, иначе у дефекта нет "+
			"производителя и проба беспредметна: %v", err)
	}
	if !IsVerb("v_get") {
		t.Fatal("предпосылка отпала: v_get перестал быть глаголом — вход не кормит дефект")
	}
	p, err := m.Compile("acme_widget", "v_get")
	if err != nil {
		t.Fatalf("компиляция: %v", err)
	}
	if p.Expressible() {
		t.Fatalf("план объявлен ВЫРАЗИМЫМ при условии на прямом списке глагола.\n"+
			"Атомы: %v\nConditioned: %v\n"+
			"Привязка условия не несёт — значит вердикт выдаст право при НЕВЫПОЛНЕННОМ "+
			"условии, и потребитель, читающий только Expressible(), об этом не узнает",
			p.Atoms, p.Conditioned)
	}
	joined := strings.Join(p.Unclassified, "\n")
	for _, want := range []string{"acme_widget", "v_get", "mfa_fresh"} {
		if !strings.Contains(joined, want) {
			t.Errorf("невыразимость обязана называть координату и условие; нет %q в:\n%s", want, joined)
		}
	}
	t.Logf("осмотрено: план acme_widget.v_get невыразим, названо: %v", p.Unclassified)
}

// TestConditionOnNonVerbStaysExpressible — положительный близнец 1.
//
// Без него отказ выше зеленел бы и у компилятора, объявляющего невыразимым
// ВСЯКОЕ условие, — то есть у того, который отобрал бы доступ у канона.
func TestConditionOnNonVerbStaysExpressible(t *testing.T) {
	const dsl = `type user
type acme_widget
  relations
    define console: [user with mfa_fresh]
`
	m, err := ParseModel(dsl)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	p, err := m.Compile("acme_widget", "console")
	if err != nil {
		t.Fatalf("компиляция: %v", err)
	}
	if !p.Expressible() {
		t.Fatalf("условие на НЕ-глаголе обязано оставаться выразимым: атому факта соответствует "+
			"строка, и она несёт условие на себе. Невыразимость здесь отобрала бы доступ у трёх "+
			"живых отношений канона. Получено: %v", p.Unclassified)
	}
	if len(p.Conditioned) == 0 {
		t.Fatal("справка Conditioned обязана остаться: на ней ключуются перечисляющие ответы")
	}
	t.Logf("осмотрено: план acme_widget.console выразим, справка: %v", p.Conditioned)
}

// TestVerbWithoutConditionStaysExpressible — положительный близнец 2.
func TestVerbWithoutConditionStaysExpressible(t *testing.T) {
	const dsl = `type user
type acme_widget
  relations
    define v_get: [user]
`
	m, err := ParseModel(dsl)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	p, err := m.Compile("acme_widget", "v_get")
	if err != nil {
		t.Fatalf("компиляция: %v", err)
	}
	if !p.Expressible() {
		t.Fatalf("глагол БЕЗ условия обязан оставаться выразимым, получено: %v", p.Unclassified)
	}
}

// TestCanonHasNoInexpressiblePlan — положительный близнец 3, по всему канону.
//
// Он и есть доказательство, что правило не отобрало ничего живого: канон обязан
// компилироваться целиком, включая три отношения с условием.
func TestCanonHasNoInexpressiblePlan(t *testing.T) {
	_, dsl, err := ResolveCanonicalModel()
	if err != nil {
		t.Fatalf("канон: %v", err)
	}
	m, err := ParseModel(string(dsl))
	if err != nil {
		t.Fatalf("разбор канона: %v", err)
	}
	pairs, conditioned := 0, 0
	for _, tn := range m.TypeNames() {
		for _, r := range m.Type(tn).Relations {
			pairs++
			p, err := m.Compile(tn, r.Name)
			if err != nil {
				t.Fatalf("компиляция %s.%s: %v", tn, r.Name, err)
			}
			if len(p.Conditioned) > 0 {
				conditioned++
			}
			if !p.Expressible() {
				t.Errorf("канон перестал компилироваться: %s.%s невыразим: %v", tn, r.Name, p.Unclassified)
			}
		}
	}
	if pairs == 0 {
		t.Fatal("прочитано ноль пар — «невыразимых нет» означало бы «ничего не прочитано»")
	}
	if conditioned == 0 {
		t.Fatal("в каноне ноль планов с условием — тогда правило про условие на глаголе " +
			"проверять не на чем, и близнец выше беспредметен")
	}
	t.Logf("осмотрено: пар %d, из них с условием %d, невыразимых 0", pairs, conditioned)
}
