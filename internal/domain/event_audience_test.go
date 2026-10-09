// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TestAuthzRevisionForm_AcceptsTheSnapshotFormOnly — токен версии прав —
// текстовая форма снимка, которую отдаёт `CurrentAuthzRevision`
// (`pg_current_snapshot()::text`). Каждая отвергнутая строка — близнец
// принятой ровно одним фактом.
func TestAuthzRevisionForm_AcceptsTheSnapshotFormOnly(t *testing.T) {
	for _, s := range []string{"781:781:", "780:790:781,785", "1:2:1", "0:0:"} {
		require.True(t, domain.ValidAuthzRevisionForm(s), "принятая форма %q", s)
	}
	for _, s := range []string{
		"", "781", "781:781", "781:781:x", "a:781:", "781:780:", // число частей, нецифра, xmin > xmax
		"780:790:791", "780:790:779", "780:790:785,781", "780:790:781,781", // xip вне [xmin,xmax), не по возрастанию, повтор
		"0781:790:", "-1:790:", "780:790:781,", " 780:790:",
	} {
		require.False(t, domain.ValidAuthzRevisionForm(s), "отвергнутая форма %q", s)
	}
}

// TestEventFactsScope_UnitesBothGenerations — области версии — проект,
// аккаунт и цепи обоих поколений без повторов, в порядке появления.
func TestEventFactsScope_UnitesBothGenerations(t *testing.T) {
	f := domain.EventFacts{
		ProjectID: "prj-1", AccountID: "acc-1",
		ParentChain:         []string{"project:prj-1", "account:acc-1"},
		PreviousParentChain: []string{"project:prj-0", "account:acc-1"},
	}
	require.Equal(t, []string{"project:prj-1", "account:acc-1", "project:prj-0"}, f.Scope())
	require.Empty(t, domain.EventFacts{}.Scope(), "фактов нет — областей кроме объекта нет")
}

// TestEventFactsMalformedChainEntry_NamesTheField — элемент цепи без типа
// либо без id назван с полем; близнец — форма соблюдена.
func TestEventFactsMalformedChainEntry_NamesTheField(t *testing.T) {
	_, _, bad := domain.EventFacts{ParentChain: []string{"project:prj-1"}}.MalformedChainEntry()
	require.False(t, bad)
	for _, c := range []struct {
		f     domain.EventFacts
		field string
	}{
		{domain.EventFacts{ParentChain: []string{"prj-1"}}, "parent_chain"},
		{domain.EventFacts{ParentChain: []string{":prj-1"}}, "parent_chain"},
		{domain.EventFacts{PreviousParentChain: []string{"project:"}}, "previous_parent_chain"},
	} {
		field, _, bad := c.f.MalformedChainEntry()
		require.True(t, bad)
		require.Equal(t, c.field, field)
	}
}
