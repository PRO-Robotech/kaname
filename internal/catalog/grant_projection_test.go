// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog_test

import (
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

func grantFacts(t *testing.T) *catalog.Facts {
	t.Helper()
	rows := catalog.Rows{Modules: []string{"iam"}, Resources: []catalog.ResourceRow{{Module: "iam", Resource: "role", ObjectType: "iam_role"}, {Module: "iam", Resource: "accessBinding", ObjectType: "iam_access_binding"}}, Verbs: []catalog.VerbRow{{Module: "iam", Resource: "role", Verb: "get", PerObject: true}, {Module: "iam", Resource: "role", Verb: "bind"}, {Module: "iam", Resource: "accessBinding", Verb: "create"}}}
	f, e := catalog.NewFacts(catalog.Halves{Live: rows})
	require.NoError(t, e)
	return f
}
func TestGrantProjectionKeepsMixedResidualAndNeverExpandsMetaWildcard(t *testing.T) {
	f := grantFacts(t)
	id := ids.NewID(domain.PrefixRole)
	rules := domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"get", "bind"}, ResourceNames: []string{id}}, {Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}}}
	p, e := f.ProjectGrantRules(rules, domain.TenantPolicy())
	require.NoError(t, e)
	require.Len(t, p.Capabilities, 2)
	require.Len(t, p.Selectors, 1)
	require.Len(t, p.Verbs, 1)
	require.Equal(t, "get", p.Verbs[0].Verb)
	ordinary, caps, e := domain.SplitGrantCapabilityRules(rules)
	require.NoError(t, e)
	require.Equal(t, caps, p.Capabilities)
	require.Equal(t, ordinary.MaterializingSelectors()[0].RuleFP, p.Selectors[0].RuleFP)
	require.NotEqual(t, caps[0].RuleFP, p.Selectors[0].RuleFP)
	for _, permission := range p.Permissions {
		require.NotContains(t, string(permission), "bind")
		require.NotContains(t, string(permission), "create")
	}
	wildcard, e := f.ProjectGrantRules(domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"*"}}}, domain.TenantPolicy())
	require.NoError(t, e)
	require.Empty(t, wildcard.Capabilities)
	require.True(t, f.GrantVerb("iam.role", "bind"))
	require.False(t, f.GrantVerb("iam.role", "*"))
	require.NotContains(t, f.VerbsOfType("iam_role"), "bind")
	// Возвращаемый canonical список не позволяет переписать следующего читателя.
	axes := authzmap.GrantAuthoringVerbs("iam", "role")
	axes[0] = "delete"
	require.Equal(t, []string{"bind"}, authzmap.GrantAuthoringVerbs("iam", "role"))
}
func TestGrantProjectionRejectsUnavailableAndInvalidMeta(t *testing.T) {
	f := grantFacts(t)
	for _, r := range []domain.Rule{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}}, {Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{"*"}}, {Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}, CreatedBySubject: true}} {
		p, e := f.ProjectGrantRules(domain.Rules{r}, domain.TenantPolicy())
		require.Error(t, e)
		require.Empty(t, p.Capabilities)
		require.Empty(t, p.Selectors)
	}
	// kaname#1034: валидный ordinary каталог, но explicit meta axis отсутствует.
	ordinaryOnly, e := catalog.NewFacts(catalog.Halves{Live: catalog.Rows{Modules: []string{"iam"}, Resources: []catalog.ResourceRow{{Module: "iam", Resource: "accessBinding", ObjectType: "iam_access_binding"}}, Verbs: []catalog.VerbRow{{Module: "iam", Resource: "accessBinding", Verb: "get", PerObject: true}}}})
	require.NoError(t, e)
	ordinary, e := ordinaryOnly.ProjectGrantRules(domain.Rules{{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"get"}}}, domain.TenantPolicy())
	require.NoError(t, e)
	require.NotEmpty(t, ordinary.Selectors)
	require.False(t, ordinaryOnly.GrantVerb("iam.accessBinding", "create"))
	unavailable, e := ordinaryOnly.ProjectGrantRules(domain.Rules{{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}}}, domain.TenantPolicy())
	require.Error(t, e)
	require.Empty(t, unavailable.Capabilities)
	require.Empty(t, unavailable.Selectors)
}
