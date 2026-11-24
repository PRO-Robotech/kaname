// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestCatalogPublicationSelectorGrowthKeepsOnlyNewTypesAndVerbs(t *testing.T) {
	before := domain.RuleSelector{
		ObjectTypes: []string{"erp.invoice", "erp.order"},
		Grants: map[string][]string{
			"erp.invoice": {"get"},
			"erp.order":   {"get", "list"},
		},
	}
	after := domain.RuleSelector{
		ObjectTypes: []string{"erp.invoice", "erp.order", "erp.payment"},
		Grants: map[string][]string{
			"erp.invoice": {"get", "approve"},
			"erp.order":   {"get", "list"},
			"erp.payment": {"get"},
		},
	}

	growth := selectorGrowth(before, after)
	require.Equal(t, []string{"erp.payment"}, growth.types)
	require.Equal(t, map[string][]string{
		"erp.invoice": {"approve"},
		"erp.payment": {"get"},
	}, growth.grants)

	repeat := selectorGrowth(after, after)
	require.Empty(t, repeat.types)
	require.Empty(t, repeat.grants)
}
