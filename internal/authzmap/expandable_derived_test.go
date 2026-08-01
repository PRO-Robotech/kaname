// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// expandable_derived_test.go — поверхность развёртки доступа ВЫВОДИТСЯ из наборов
// типов, а не перечисляется отдельно.
//
// Предмет. Список допустимых отношений перечислялся сам по себе, поэтому новое
// отношение у типа пришлось бы дописывать в него руками — место, о котором надо не
// забыть. Теперь список выводится: объявил тип отношение — оно появилось в
// принимаемых; снял — исчезло.
//
// Набор при этом остаётся РАСШИРЯЕМЫМ, а не ОТКРЫТЫМ: внутренняя машинерия модели
// (переносчики охвата, подтягивающие резолверы, платформенные роли) по-прежнему
// отвергается. Без парного отрицательного переформулировка превратила бы замок в
// решето.
package authzmap_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
)

// TestExpandableRelations_IsDerivedFromTypeSets — принимаемое множество есть
// ОБЪЕДИНЕНИЕ наборов всех типов ∪ ярусные ∪ членство.
func TestExpandableRelations_IsDerivedFromTypeSets(t *testing.T) {
	types := catalogObjectTypes(t)
	require.NotEmpty(t, types, "каталог пуст — предпосылка сломана")

	union := map[string]bool{}
	for _, ot := range types {
		for _, r := range authzmap.VerbRelationsOfType(ot) {
			union[r] = true
		}
	}
	require.NotEmpty(t, union, "объединение наборов пусто — выводить нечего")
	for _, r := range []string{"viewer", "editor", "admin", "member"} {
		union[r] = true
	}

	var want []string
	for r := range union {
		want = append(want, r)
	}
	sort.Strings(want)

	for _, r := range want {
		require.Truef(t, authzmap.IsExpandableRelation(r),
			"отношение %q входит в объединение наборов типов (либо ярусное/членство), "+
				"но принимаемым не считается — тенант не может спросить «кто может это делать»", r)
	}
	t.Logf("перепись: типов в объединении: %d; принимаемых отношений выведено: %d", len(types), len(want))

	// Число не записано, а ВЫВЕДЕНО: 5 глагольных + 3 ярусных + членство.
	require.Equalf(t, 9, len(want),
		"принимаемых отношений ожидалось 9 (5 глагольных + 3 ярусных + членство), получено %d", len(want))
}

// TestExpandableRelations_RejectsModelInternals — ПАРНЫЙ ОТРИЦАТЕЛЬНЫЙ.
//
// Набор расширяем, но не открыт: внутренняя машинерия модели остаётся отвергнутой.
// Пересылка произвольной строки во внешнее хранилище прав дала бы вызывающему
// возможность прощупывать внутренний граф отношений.
func TestExpandableRelations_RejectsModelInternals(t *testing.T) {
	f := parseModel(t)
	rels := f.allRelationNames()
	require.NotEmpty(t, rels, "модель разобрана в ноль отношений — отрицание было бы бессодержательным")

	allowed := map[string]bool{"viewer": true, "editor": true, "admin": true, "member": true}
	for _, ot := range catalogObjectTypes(t) {
		for _, r := range authzmap.VerbRelationsOfType(ot) {
			allowed[r] = true
		}
	}

	rejected := 0
	for r := range rels {
		if allowed[r] {
			continue
		}
		require.Falsef(t, authzmap.IsExpandableRelation(r),
			"отношение %q — внутренняя машинерия модели, но объявлено принимаемым: "+
				"поверхность аудита расширилась мимо разбора", r)
		rejected++
	}
	require.NotZerof(t, rejected,
		"ни одно отношение модели не было отвергнуто — отрицание проверило пустое множество "+
			"и зеленело бы при полностью открытом наборе")
	t.Logf("перепись: отношений модели осмотрено: %d; отвергнуто как машинерия: %d", len(rels), rejected)
}
