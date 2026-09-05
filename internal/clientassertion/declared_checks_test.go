// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clientassertion

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
)

// TestClientAssertionAgreesWithThePolicy — состав проверок четвёртого
// проверяющего сходится с единым перечнем, а расхождение НАЗВАНО с причиной.
func TestClientAssertionAgreesWithThePolicy(t *testing.T) {
	v := &Verifier{}

	missing := tokenpolicy.MissingChecksExcept(v.DeclaredChecks(), v.DeclaredDeviations())
	require.Emptyf(t, missing,
		"обязательные проверки не исполняются и не объявлены отступлением: %v", missing)

	for _, d := range v.DeclaredDeviations() {
		require.NotEmptyf(t, d.Reason,
			"отступление по %q без причины неотличимо от пропуска", d.Check)
	}

	declared := map[tokenpolicy.Check]bool{}
	for _, c := range v.DeclaredChecks() {
		declared[c] = true
	}
	for _, d := range v.DeclaredDeviations() {
		require.Falsef(t, declared[d.Check],
			"проверка %q объявлена и исполняемой, и отступлением сразу", d.Check)
	}
}
