// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package tokenintrospecthttp

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
)

// TestIntrospectionAgreesWithThePolicy — состав проверок интроспекции сходится с
// единым перечнем, а всякое расхождение НАЗВАНО с причиной (#902).
//
// Три проверяющих токена расходились по составу, и сверить их можно было только
// чтением. Проба закрывает это с обеих сторон: чего не хватает — находка; что
// не исполняется намеренно — обязано нести причину, иначе отступление
// неотличимо от пропуска.
func TestIntrospectionAgreesWithThePolicy(t *testing.T) {
	h := &Handler{}

	missing := tokenpolicy.MissingChecksExcept(h.DeclaredChecks(), h.DeclaredDeviations())
	require.Emptyf(t, missing,
		"обязательные проверки не исполняются и не объявлены отступлением: %v", missing)

	require.NotEmpty(t, h.DeclaredDeviations(),
		"отступления есть по существу (адресат и тип — свойства поверхности "+
			"предъявления, не издателя); пустой перечень означал бы, что их забыли "+
			"объявить, а не что их нет")

	for _, d := range h.DeclaredDeviations() {
		require.NotEmptyf(t, d.Reason,
			"отступление по %q без причины неотличимо от пропуска", d.Check)
	}

	// Обратная сторона: отступление НЕ вправе прощать то, что проверяющий и так
	// исполняет — иначе перечень станет местом, где требование снимают на всякий
	// случай.
	declared := map[tokenpolicy.Check]bool{}
	for _, c := range h.DeclaredChecks() {
		declared[c] = true
	}
	for _, d := range h.DeclaredDeviations() {
		require.Falsef(t, declared[d.Check],
			"проверка %q объявлена и исполняемой, и отступлением сразу", d.Check)
	}
}
