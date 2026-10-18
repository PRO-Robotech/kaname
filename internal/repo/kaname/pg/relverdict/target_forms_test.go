// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// target_forms_test.go — ОДНА ТАБЛИЦА ФОРМ ЦЕЛИ на обе стороны прочтения (kaname#863).
//
// Каждая строка таблицы — форма колонки `access_bindings.target` и то, что о
// ней обязаны сказать все судьи разом: база (принимает ли), материализатор
// (`DecodeTarget`: принимает ровно то же, что база) и, на законной форме, решение о
// доступе (`wholeScopeTarget`, `namedInTarget`: тот же класс, что `DecodeTarget`). Таблица одна,
// поэтому расхождение двух прочтений не может спрятаться за двумя разными
// перечнями форм. Unit-часть судит `DecodeTarget`; integration-часть — базу и SQL
// на той же таблице (`target_forms_integration_test.go`).

import (
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// Пары, о которых спрашивают оба прочтения: названная и не названная.
var (
	tfPairX = domain.ResourceRef{Type: "vpc.network", ID: "enp863x"}
	tfPairY = domain.ResourceRef{Type: "vpc.network", ID: "enp863y"}
	// tfPairXOther — тот же идентификатор у другого типа: совпадение одного id не годится.
	tfPairXOther = domain.ResourceRef{Type: "vpc.subnet", ID: "enp863x"}
)

// tfForm — строка таблицы.
type tfForm struct {
	name  string
	json  string
	legal bool                 // база принимает
	whole bool                 // «вся область»
	named []domain.ResourceRef // названные пары (для законной формы с перечнем)
}

// tfForms — таблица форм. Законные формы — ровно те, что пишет `Encode`, их
// ближайшие соседи и значение колонки по умолчанию; формы вне контракта — те,
// на которых прочтения расходились до kaname#863, и элементы перечня вне формы.
var tfForms = []tfForm{
	{name: "allInScope", json: `{"allInScope": true}`, legal: true, whole: true},
	{name: "allInScope false", json: `{"allInScope": false}`, legal: true, whole: true},
	{name: "пустой объект", json: `{}`, legal: true, whole: true},
	{name: "пустой перечень", json: `{"resources": []}`, legal: true, whole: true},
	{name: "перечень из одной пары", json: `{"resources": [{"type": "vpc.network", "id": "enp863x"}]}`,
		legal: true, named: []domain.ResourceRef{tfPairX}},
	{name: "перечень из двух пар", json: `{"resources": [{"type": "vpc.network", "id": "enp863x"}, {"type": "vpc.network", "id": "enp863y"}]}`,
		legal: true, named: []domain.ResourceRef{tfPairX, tfPairY}},
	{name: "элемент с лишним ключом", json: `{"resources": [{"type": "vpc.network", "id": "enp863x", "name": "n"}]}`,
		legal: true, named: []domain.ResourceRef{tfPairX}},
	{name: "незнакомый ключ корня", json: `{"note": 1}`, legal: true, whole: true},

	{name: "resources null", json: `{"resources": null}`},
	{name: "resources строка", json: `{"resources": "x"}`},
	{name: "resources объект", json: `{"resources": {}}`},
	{name: "resources объект-пара", json: `{"resources": {"type": "vpc.network", "id": "enp863x"}}`},
	{name: "корень — массив", json: `[]`},
	{name: "корень — массив с целью", json: `[{"resources": [{"type": "vpc.network", "id": "enp863x"}]}]`},
	{name: "корень — строка", json: `"x"`},
	{name: "корень — число", json: `1`},
	{name: "корень — null", json: `null`},
	{name: "allInScope строка", json: `{"allInScope": "true"}`},
	{name: "элемент — строка", json: `{"resources": ["enp863x"]}`},
	{name: "элемент без id", json: `{"resources": [{"type": "vpc.network"}]}`},
	{name: "id — число", json: `{"resources": [{"type": "vpc.network", "id": 863}]}`},
	{name: "type — null", json: `{"resources": [{"type": null, "id": "enp863x"}]}`},
	{name: "законная пара и элемент вне формы", json: `{"resources": [{"type": "vpc.network", "id": "enp863x"}, 5]}`},
}

// tfProbes — пары, о которых спрашивают оба прочтения на каждой форме.
var tfProbes = []domain.ResourceRef{tfPairX, tfPairY, tfPairXOther}

// wantNamed — ответ «цель называет пару» по строке таблицы.
func (f tfForm) wantNamed(p domain.ResourceRef) bool {
	for _, r := range f.named {
		if r == p {
			return true
		}
	}
	return false
}

func TestDecodeTargetReadsEveryFormOfTheTable(t *testing.T) {
	var legal, outside int
	for _, f := range tfForms {
		t.Run(f.name, func(t *testing.T) {
			got, err := relverdict.DecodeTarget([]byte(f.json))
			if !f.legal {
				if !errors.Is(err, relverdict.ErrTargetForm) {
					t.Fatalf("DecodeTarget(%s): форма вне контракта обязана дать ErrForm, получено %+v, %v", f.json, got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeTarget(%s): %v", f.json, err)
			}
			if got.AllInScope != f.whole {
				t.Errorf("DecodeTarget(%s): вся область = %v, ждали %v", f.json, got.AllInScope, f.whole)
			}
			for _, p := range tfProbes {
				if got.Contains(p.Type, p.ID) != f.wantNamed(p) {
					t.Errorf("DecodeTarget(%s): Contains(%s, %s) = %v, ждали %v",
						f.json, p.Type, p.ID, !f.wantNamed(p), f.wantNamed(p))
				}
			}
		})
		if f.legal {
			legal++
		} else {
			outside++
		}
	}
	t.Logf("перепись таблицы: форм %d, законных %d, вне контракта %d", len(tfForms), legal, outside)
	if legal == 0 || outside == 0 {
		t.Fatalf("предпосылка: таблица без законных (%d) либо без внеконтрактных (%d) форм — судить не с чем", legal, outside)
	}
}

// Запись и прочтение — одна форма: каждое значение домена, записанное Encode,
// читается Decode в тот же класс.
func TestEncodeTargetIsReadBackByDecodeTarget(t *testing.T) {
	for _, in := range []domain.AccessTarget{
		{},
		{AllInScope: true},
		{Resources: []domain.ResourceRef{tfPairX}},
		{Resources: []domain.ResourceRef{tfPairX, tfPairY}},
	} {
		b, err := relverdict.EncodeTarget(in)
		if err != nil {
			t.Fatalf("EncodeTarget(%+v): %v", in, err)
		}
		got, err := relverdict.DecodeTarget(b)
		if err != nil {
			t.Fatalf("Decode(EncodeTarget(%+v)) = %s: %v", in, b, err)
		}
		if len(in.Resources) == 0 {
			if !got.AllInScope || len(got.Resources) != 0 {
				t.Errorf("%+v → %s → %+v: ждали всю область", in, b, got)
			}
			continue
		}
		if got.AllInScope || len(got.Resources) != len(in.Resources) {
			t.Errorf("%+v → %s → %+v: ждали тот же перечень", in, b, got)
		}
	}
}
