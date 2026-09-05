// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmodel

import (
	"errors"
	"sort"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/authzplan"
)

// declares_test.go — ОДНО суждение на приём и на компиляцию (#1290).
//
// `Declares` существует затем, чтобы входной контроль отвергал ровно ту пару,
// которую компиляция плана не разберёт. Раньше приём судил ОБЪЕДИНЕНИЕ наборов
// всех типов, а компиляция — набор КОНКРЕТНОГО типа, и пара из зазора между ними
// доезжала до компиляции и падала внутренней ошибкой на корректном запросе.
//
// Равенство двух суждений здесь не объявлено, а ПРОВЕРЕНО: обход идёт по всем
// типам × всем именам отношений, какие модель вообще знает, и требует совпадения
// в ОБЕ стороны. Обе стороны непусты по настоящим данным — синтетика не нужна,
// но пустота каждой из них проверяется отдельно, иначе равенство зеленело бы
// вакуумно.
func TestDeclaresJudgesTheSameSetAsCompile(t *testing.T) {
	p, err := Shared()
	if err != nil {
		t.Fatalf("разбор вшитой модели: %v", err)
	}
	m := p.Model()

	names := m.TypeNames()
	sort.Strings(names)
	relNames := map[string]bool{}
	for _, tn := range names {
		for _, r := range m.Type(tn).Relations {
			relNames[r.Name] = true
		}
	}
	rels := make([]string, 0, len(relNames))
	for r := range relNames {
		rels = append(rels, r)
	}
	sort.Strings(rels)

	pairs, declared, undeclared, mismatch := 0, 0, 0, 0
	for _, tn := range names {
		for _, r := range rels {
			pairs++
			says := p.Declares(tn, r)
			_, cerr := m.Compile(tn, r)
			switch {
			case says && cerr == nil:
				declared++
			case !says && cerr != nil:
				undeclared++
			default:
				mismatch++
				if mismatch <= 10 {
					t.Errorf("%s.%s: Declares=%v, а компиляция %v — приём и компиляция "+
						"судят РАЗНЫЕ наборы, и пара из зазора падает внутрь", tn, r, says, cerr)
				}
			}
		}
	}

	t.Logf("перепись: типов %d · имён отношений %d · пар осмотрено %d · объявлено %d · не объявлено %d · расхождений %d",
		len(names), len(rels), pairs, declared, undeclared, mismatch)

	// Обе стороны обязаны быть непусты: равенство, у которого одна из ветвей
	// не встретилась ни разу, не проверено — оно просто не спрошено.
	if declared == 0 {
		t.Errorf("ни одна пара не объявлена — обход прошёл вхолостую, и равенство ничего не значит")
	}
	if undeclared == 0 {
		t.Errorf("ни одна пара не отвергнута — отрицательная сторона равенства не проверена")
	}
}

// TestDeclaresTypeMatchesCompilePrecondition — вторая координата отказа.
//
// У необъявленного типа не объявлено НИ ОДНО отношение, поэтому сообщение про
// отношение увело бы вызывающего править не то поле. `DeclaresType` отвечает на
// тот же вопрос, на котором компиляция останавливается первым — и это проверено
// её собственным сигнальным значением, а не текстом.
func TestDeclaresTypeMatchesCompilePrecondition(t *testing.T) {
	p, err := Shared()
	if err != nil {
		t.Fatalf("разбор вшитой модели: %v", err)
	}
	m := p.Model()

	seen := 0
	for _, tn := range m.TypeNames() {
		seen++
		if !p.DeclaresType(tn) {
			t.Errorf("тип %q объявлен моделью, а DeclaresType отвечает «нет»", tn)
		}
	}
	if seen == 0 {
		t.Fatalf("в модели ноль типов — обход прошёл вхолостую")
	}
	t.Logf("перепись: типов осмотрено %d", seen)

	// ЗАКОННЫЙ БЛИЗНЕЦ наоборот: имени, которого в модели нет, обязаны сказать
	// «нет» оба — и предикат, и компиляция (своим сигнальным значением).
	const absent = "no_such_object_type_1290"
	if p.DeclaresType(absent) {
		t.Errorf("DeclaresType(%q) = true при отсутствии типа в модели", absent)
	}
	if _, cerr := m.Compile(absent, "viewer"); !errors.Is(cerr, authzplan.ErrTypeNotDeclared) {
		t.Errorf("компиляция по отсутствующему типу вернула %v, а ожидалось %v",
			cerr, authzplan.ErrTypeNotDeclared)
	}
}
