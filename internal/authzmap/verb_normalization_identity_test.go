// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// verb_normalization_identity_test.go — приведение имени глагола ТОЖДЕСТВЕННО на
// каждом глаголе, который реально объявлен в дереве.
//
// Это утверждение о БЕЗОПАСНОСТИ правки, и оно обязано мериться по дереву, а не по
// платформенному литералу: литерал — одна из сторон, которую правка и трогает.
// Перечисление берётся из наборов ВСЕХ типов каталога, поэтому «приведение ничего
// не изменило» относится ко всему, что эмитится, а не к образцу.
package authzmap_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

func TestNormalizeVerb_IsIdentityOnEveryDeclaredVerb(t *testing.T) {
	types := catalogObjectTypes(t)
	require.NotEmpty(t, types, "каталог пуст — перечислять нечего, молчание ничего не доказывает")

	seen := map[string]bool{}
	checked := 0
	for _, ot := range types {
		verbs := authzmap.VerbsOfType(ot)
		require.NotEmptyf(t, verbs, "тип %q не объявляет ни одного глагола", ot)
		for _, v := range verbs {
			require.Equalf(t, v, domain.NormalizeVerb(v),
				"приведение изменило объявленный глагол %q типа %q — правка перестала быть безопасной: "+
					"имя отношения собирается из приведённой формы, значит изменилось бы и оно", v, ot)
			seen[v] = true
			checked++
		}
		// и обратная сторона: имя отношения, собранное из приведённого глагола,
		// совпадает с тем, что объявляет тип
		rels := authzmap.VerbRelationsOfType(ot)
		require.Lenf(t, rels, len(verbs), "тип %q: число отношений и глаголов разошлось", ot)
		relSet := map[string]bool{}
		for _, r := range rels {
			relSet[r] = true
		}
		for _, v := range verbs {
			name := authzmap.VerbRelationPrefix + domain.NormalizeVerb(v)
			require.Truef(t, relSet[name],
				"тип %q: собранное имя %q не входит в объявленный набор %v — эмиссия адресовала бы "+
					"отношение, которого у типа нет", ot, name, rels)
		}
	}
	t.Logf("перепись: типов осмотрено: %d; проверок тождественности: %d; различных глаголов: %d",
		len(types), checked, len(seen))
}
