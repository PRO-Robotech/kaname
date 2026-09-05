// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzplan

import (
	"strings"
	"testing"
)

// pointeruniqueness_test.go — вход, на котором `AssertOnePointerPerParentType`
// разыменовывал nil (#1987).
//
// Метод объявлен утверждением О МОДЕЛИ («его обязан уметь задать и тот, кто
// модель проверяет, не компилируя»), то есть предназначен для НЕДОВЕРЕННОГО
// входа: текст ему приносит доставленный манифест. Паника на таком входе
// означала бы не отказ, а падение службы на чужом вводе.
//
// Механика дефекта: карта указателей ключуется ИМЕНЕМ типа
// (`m.Pointers[t.Name]`), а отношение спрашивалось у КОНКРЕТНОГО блока
// (`t.Rel(rel)`). На двух блоках одного имени с разными именами указателей карта
// несёт указатели ОБОИХ, а каждый блок знает только свои — `t.Rel` отдавал nil, и
// `PointerTargets` его разыменовывал.

// splitPointerNamesAcrossDuplicateBlocks — два блока одного имени, у каждого свой
// указатель в `account` под своим именем. Разбор такой вход ПРИНИМАЕТ (#1978:
// занятость имени он не проверяет), поэтому вход достижим, а не искусствен.
const splitPointerNamesAcrossDuplicateBlocks = `type user
type account
  relations
    define admin: [user]
type doc
  relations
    define acct: [account]
    define admin: admin from acct
type doc
  relations
    define owner_acct: [account]
    define admin: admin from owner_acct
`

func TestAssertOnePointerPerParentTypeSurvivesDuplicateTypeBlocks(t *testing.T) {
	m, err := ParseModel(splitPointerNamesAcrossDuplicateBlocks)
	if err != nil {
		t.Fatalf("предпосылка пробы: этот вход разбор обязан ПРИНИМАТЬ, иначе у дефекта нет "+
			"производителя и проба беспредметна: %v", err)
	}
	// Предпосылка названа числом: карта несёт указатели ОБОИХ блоков, а блок —
	// только свои. Без неё проба зеленела бы на входе, который дефект не кормит.
	if got := len(m.Pointers["doc"]); got != 2 {
		t.Fatalf("предпосылка пробы отпала: карта указателей `doc` обязана нести оба имени "+
			"(указателей %d, ждали 2) — вход перестал кормить дефект", got)
	}

	var err2 error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ПАНИКА на входе, который принял ParseModel: %v. Метод объявлен "+
					"утверждением о модели и зовётся на доставленном тексте — паника здесь "+
					"означает падение службы на чужом вводе, а не отказ", r)
			}
		}()
		err2 = m.AssertOnePointerPerParentType()
	}()

	if err2 == nil {
		t.Fatal("на типе, объявленном дважды, утверждение о единственности указателя не определено: " +
			"ждали ОТКАЗ, получено nil — молчание здесь читается как «предпосылка держится»")
	}
	if !strings.Contains(err2.Error(), "doc") {
		t.Fatalf("отказ обязан называть тип, получено: %v", err2)
	}
	t.Logf("осмотрено: типов %d, блоков с именем doc 2, указателей в карте doc %d; отказ: %v",
		len(m.Types), len(m.Pointers["doc"]), err2)
}

// TestAssertOnePointerPerParentTypeStillRefusesRealAmbiguity — положительный
// близнец к отказу выше: настоящая неоднозначность (ОДИН блок, два указателя в
// один тип) обязана по-прежнему отвергаться. Без него отказ на дубле блоков
// зеленел бы и у метода, отвергающего вообще всё.
func TestAssertOnePointerPerParentTypeStillRefusesRealAmbiguity(t *testing.T) {
	const dsl = `type user
type account
  relations
    define admin: [user]
type doc
  relations
    define acct: [account]
    define owner_acct: [account]
    define admin: admin from acct or admin from owner_acct
`
	m, err := ParseModel(dsl)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if err := m.AssertOnePointerPerParentType(); err == nil {
		t.Fatal("два указателя ОДНОГО блока в один тип-предок обязаны отвергаться")
	}
}

// TestAssertOnePointerPerParentTypeAdmitsTheCanon — второй положительный
// близнец: канон обязан проходить. Отказ, срабатывающий на каноне, снял бы сам
// себя первым же прогоном.
func TestAssertOnePointerPerParentTypeAdmitsTheCanon(t *testing.T) {
	_, dsl, err := ResolveCanonicalModel()
	if err != nil {
		t.Fatalf("канон: %v", err)
	}
	m, err := ParseModel(string(dsl))
	if err != nil {
		t.Fatalf("разбор канона: %v", err)
	}
	if err := m.AssertOnePointerPerParentType(); err != nil {
		t.Fatalf("канон обязан проходить: %v", err)
	}
	t.Logf("осмотрено: типов канона %d", len(m.Types))
}
