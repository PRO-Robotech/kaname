// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// scope_vocabulary_derived_test.go — выведенные указатели словаря областей
// ПОЛНЫ и ОДНОЗНАЧНЫ (задача продукта #2057).
//
// # Почему это отдельная проба, а не строка комментария
//
// Обратные указатели («ярус → вид», «проволочная форма → вид») строятся обходом
// карты, а обход карты в Go неупорядочен. Пока в карте по одному якорю на ярус,
// указатель однозначен; появись второй якорь того же яруса — карта молча стала
// бы зависеть от порядка обхода, то есть от прогона. Заметить это чтением
// нельзя: код не меняется вовсе.
//
// Поэтому кардинальность утверждается, а не подразумевается: якорей ровно
// столько, сколько ярусов, и каждый ярус ходит туда-обратно в СВОЙ вид.
package domain_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestScopeVocabularyDerivedPointersAreTotalAndUnambiguous(t *testing.T) {
	vocab := domain.ScopeTierByKind()
	require.NotEmpty(t, vocab,
		"словарь пуст: сверять нечего, и всякое утверждение ниже выполнилось бы тождественно")

	var anchors, aliases []string
	for kind := range vocab {
		if domain.IsScopeAnchorKind(kind) {
			anchors = append(anchors, kind)
			continue
		}
		aliases = append(aliases, kind)
	}
	t.Logf("перепись словаря: видов %d · якорей %d · унаследованных написаний %d",
		len(vocab), len(anchors), len(aliases))

	// ── якорь ходит туда-обратно, и ярусы якорей ПОПАРНО различны ──
	seenTier := map[domain.Scope]string{}
	for _, kind := range anchors {
		dotted := domain.ScopeTypeToDotted(kind)
		require.NotEqual(t, kind, dotted,
			"якорь %q не получил проволочной формы: перевод потерял запись", kind)

		back, ok := domain.ScopeTypeFromDotted(dotted)
		require.True(t, ok, "проволочная форма %q не переводится обратно", dotted)
		require.Equal(t, kind, back,
			"якорь %q ушёл в %q и вернулся как %q: обратный указатель неоднозначен",
			kind, dotted, back)

		tier := vocab[kind]
		if prev, dup := seenTier[tier]; dup {
			require.Failf(t, "ярус якоря не уникален",
				"ярус %v принадлежит и %q, и %q: указатель «ярус → вид» строится обходом "+
					"карты и молча зависел бы от порядка обхода", tier, prev, kind)
		}
		seenTier[tier] = kind
	}
	require.Len(t, seenTier, len(anchors),
		"ярусов у якорей меньше, чем самих якорей — обратный указатель неполон")

	// ── унаследованное написание ярус выводит, но якорем НЕ становится ──
	for _, kind := range aliases {
		require.Equal(t, kind, domain.ScopeTypeToDotted(kind),
			"унаследованное написание %q получило проволочную форму: оно стало якорем, "+
				"хотя публичный Create приводит область закрытым переводом из трёх значений", kind)
		require.Equal(t, vocab[kind], domain.DeriveFromResourceType(kind),
			"вывод яруса для %q разошёлся со словарём: читатель обзавёлся своим перечнем", kind)
	}

	// ── положительный контроль: словарь и вывод яруса — ОДИН источник ──
	// Без него утверждения выше зеленели бы и на словаре, которого не читает никто.
	for kind, tier := range vocab {
		require.Equal(t, tier, domain.DeriveFromResourceType(kind),
			"вид %q: словарь говорит %v, вывод яруса — %v", kind, tier, domain.DeriveFromResourceType(kind))
	}
	require.Equal(t, domain.ScopeProject, domain.DeriveFromResourceType("вид-вне-словаря"),
		"вид вне словаря обязан давать самый узкий ярус: ошибка умолчания не расширяет доступ")
}
