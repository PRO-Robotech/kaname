// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// verb_relations_of_type_test.go — набор отношений принадлежит ТИПУ.
//
// Предмет. Таблица держала признак «полный набор либо ничего», из-за чего набор не
// мог отличаться у одного типа от другого: представление «у этого типа четыре из
// пяти» или «у этого типа шестое» было НЕВЫРАЗИМО по устройству таблицы. Теперь
// тип объявляет свой набор, а полноту и совпадение с моделью требует гейт.
//
// На этой стадии все типы объявляют прежнюю пятёрку, поэтому наблюдаемое поведение
// не меняется — и это утверждается отдельно (эквивалентность булеву предикату).
package authzmap_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
)

// TestVerbRelationsOfType_IsPerTypeAndTotal — набор читается У ТИПА и покрывает
// весь каталог; булев предикат стал производным и с набором не расходится.
func TestVerbRelationsOfType_IsPerTypeAndTotal(t *testing.T) {
	types := catalogObjectTypes(t)
	require.NotEmpty(t, types, "каталог пуст — предпосылка сломана, молчание ничего не доказывает")

	full, empty := 0, 0
	for _, ot := range types {
		set := authzmap.VerbRelationsOfType(ot)
		// эквивалентность старому предикату — стадия не меняет поведения
		require.Equalf(t, len(set) > 0, authzmap.TypeHasVerbRelations(ot),
			"тип %q: набор и булев предикат разошлись (набор=%v, предикат=%v)",
			ot, set, authzmap.TypeHasVerbRelations(ot))
		if len(set) > 0 {
			full++
			require.Truef(t, sort.StringsAreSorted(set),
				"тип %q: набор обязан приходить отсортированным (детерминизм эмиссии): %v", ot, set)
		} else {
			empty++
		}
	}
	t.Logf("перепись: типов с набором: %d; без набора: %d", full, empty)
	// Число снимается ПЕРЕМЕРОМ каталога типов и меняется только вместе с ним,
	// поэтому расхождение здесь — находка о каталоге, а не повод поправить цифру.
	// В слиянии сошлись две правки каталога: `vpc_cidr_group` (эта ветка) и типы
	// производственной формы compute (ствол); значение взято замером слитого
	// дерева, а не сложением двух прежних.
	require.Equalf(t, 27, full,
		"глагольных типов ожидалось 27, получено %d — число снято перемером против ревизии посадки", full)
}

// TestVerbRelationsOfType_UnknownTypeCarriesNoSet — неизвестный тип набора не
// несёт. Парный отрицательный к утверждению выше: без него «набор непуст у всех»
// было бы неотличимо от «функция возвращает пятёрку кому угодно».
func TestVerbRelationsOfType_UnknownTypeCarriesNoSet(t *testing.T) {
	require.Empty(t, authzmap.VerbRelationsOfType("no_such_type"))
	require.Empty(t, authzmap.VerbRelationsOfType(""))
	require.False(t, authzmap.TypeHasVerbRelations("no_such_type"))
}

// TestVerbRelationsOfType_ResultIsNotAliasedToTheTable — возвращённый набор не
// алиасит таблицу: вызывающий не вправе испортить источник истины эмиссии.
func TestVerbRelationsOfType_ResultIsNotAliasedToTheTable(t *testing.T) {
	types := catalogObjectTypes(t)
	require.NotEmpty(t, types)
	ot := types[0]
	first := authzmap.VerbRelationsOfType(ot)
	require.NotEmpty(t, first)
	before := append([]string(nil), first...)
	first[0] = "v_tampered"
	require.Equal(t, before, authzmap.VerbRelationsOfType(ot),
		"набор типа %q изменился после правки полученной копии — таблица отдаётся по ссылке", ot)
}

// TestCommonVerbVocabulary_IsTheIntersection — «набор, ОБЩИЙ для всех ресурсов».
//
// На этой стадии все типы несут одну пятёрку ⇒ пересечение равно ей. После первого
// типа с расширенным набором пересечение сузится — и это верно: поле публичного
// каталога объявлено именно как общий для всех ресурсов набор, а не как «все
// глаголы, какие бывают».
func TestCommonVerbVocabulary_IsTheIntersection(t *testing.T) {
	types := catalogObjectTypes(t)
	require.NotEmpty(t, types)

	// пересечение, посчитанное независимо от реализации
	var want []string
	for i, ot := range types {
		set := authzmap.VerbRelationsOfType(ot)
		if len(set) == 0 {
			continue
		}
		if want == nil && i >= 0 {
			want = append([]string(nil), set...)
			continue
		}
		in := map[string]bool{}
		for _, s := range set {
			in[s] = true
		}
		kept := want[:0]
		for _, s := range want {
			if in[s] {
				kept = append(kept, s)
			}
		}
		want = kept
	}
	// поле каталога несёт ГЛАГОЛЫ, а не имена отношений
	verbs := make([]string, 0, len(want))
	for _, r := range want {
		verbs = append(verbs, r[len("v_"):])
	}
	sort.Strings(verbs)

	got := append([]string(nil), authzmap.CommonVerbVocabulary()...)
	sort.Strings(got)
	require.Equal(t, verbs, got,
		"общий словарь обязан быть ПЕРЕСЕЧЕНИЕМ наборов всех типов, а не отдельным литералом")
	t.Logf("перепись: типов в пересечении: %d; общий словарь: %v", len(types), got)
}
