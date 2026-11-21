// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"slices"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/stretchr/testify/require"
)

func childRegistrationRoleRows() catalog.Halves {
	h := rows()
	// Родитель поддерживает фильтр по меткам в действующем реестре источников.
	h.Live.Modules[1] = "registry"
	resourceNames := map[string]string{"boxes": "registries", "items": "repositories", "tags": "tags"}
	for i, r := range h.Live.Resources {
		if r.Module == "probemod" {
			h.Live.Resources[i].Module = "registry"
			h.Live.Resources[i].Resource = resourceNames[r.Resource]
		}
	}
	// У типа strange_item модель объявляет только v_get.
	h.Live.Verbs = slices.DeleteFunc(h.Live.Verbs, func(v catalog.VerbRow) bool {
		return v.Module == "probemod" && v.Resource == "items" && v.Verb != "get"
	})
	for i, v := range h.Live.Verbs {
		if v.Module == "probemod" {
			h.Live.Verbs[i].Module = "registry"
			h.Live.Verbs[i].Resource = resourceNames[v.Resource]
		}
	}
	return h
}

func childRegistrationRoleFixture(t *testing.T, declared bool) *Compiler {
	t.Helper()
	h := childRegistrationRoleRows()
	if declared {
		h.Live.Resources[1].ChildRegistration = &catalog.ChildRegistrationRule{
			Verb: "registerchild", ParentSegments: 1, MaxChildren: 24, MaxCreates: 4, WindowSeconds: 60,
		}
	}
	h.Live.Verbs = append(h.Live.Verbs,
		catalog.VerbRow{Module: "registry", Resource: "repositories", Verb: "registerchild", ContainerParent: "strange_box", ContainerRelation: "child_registrar"},
		catalog.VerbRow{Module: "registry", Resource: "repositories", Verb: "servicecreate", ContainerParent: "strange_box", ContainerRelation: "service_creator"},
	)
	model := strings.Replace(modelFixture, "type strange_box\n  relations\n", "type strange_box\n  relations\n"+
		"    define child_registrar: [user]\n"+
		"    define registration_alias: child_registrar\n"+
		"    define service_creator: [service_account]\n", 1)
	model = strings.Replace(model, "type strange_item\n  relations\n", "type strange_item\n  relations\n"+
		"    define registration_via_parent: child_registrar from parent\n", 1)
	c, err := New(model, h)
	require.NoError(t, err)
	return c
}

func childRegistrationRoleBinding() Binding {
	return binding(domain.Rule{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"},
		Children: []domain.Rule{{Resources: []string{"repositories"}, Verbs: []string{"registerChild"}}}})
}

func childRegistrationRoleEffects(s Set) []Effect {
	var out []Effect
	for _, e := range s.Effects() {
		if e.Provenance.Primitive == "child_registration" {
			out = append(out, e)
		}
	}
	return out
}

func TestChildRegistrationRoleProjectsSelectedParentThroughActualModel(t *testing.T) {
	c := childRegistrationRoleFixture(t, true)
	b := childRegistrationRoleBinding()
	b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "registry.registries", ID: "parent-a"}}}
	// Право должно появиться до регистрации первого потомка.
	effects := childRegistrationRoleEffects(complete(t, c.Compile(b)))
	require.NotEmpty(t, effects)
	foundParent, foundAlias, foundInherited := false, false, false
	selectors := b.Role.Rules.MaterializingSelectorsInScope(domain.DeriveFromResourceType(b.Scope.Type))
	var childFP string
	for _, selector := range selectors {
		if selector.Container != nil {
			childFP = selector.RuleFP
		}
	}
	require.NotEmpty(t, childFP)
	for _, effect := range effects {
		require.Equal(t, Use, effect.Kind)
		require.Equal(t, grantcoverage.Relation, effect.Action.Kind)
		require.Equal(t, b.SourceID, effect.Provenance.SourceID)
		require.Equal(t, b.Role.ID, effect.Provenance.RoleID)
		require.Equal(t, b.Role.Rules[0].Fingerprint(), effect.Provenance.AuthoredRuleFP)
		require.Equal(t, childFP, effect.Provenance.ProjectedRuleFP)
		require.NotEmpty(t, effect.Provenance.ModelOrigin)
		require.Len(t, effect.Constraints, 1)
		constraint := effect.Constraints[0]
		require.Equal(t, "strange_box", constraint.Type)
		require.Equal(t, &b.Scope, constraint.Within)
		require.Equal(t, grantcoverage.ObjectIDs, constraint.Region.Objects.Kind)
		require.Equal(t, []string{"parent-a"}, constraint.Region.Objects.IDs)
		switch effect.Type + "." + effect.Action.Name {
		case "strange_box.child_registrar":
			foundParent = true
			require.Empty(t, constraint.Path)
		case "strange_box.registration_alias":
			foundAlias = true
			require.Empty(t, constraint.Path)
		case "strange_item.registration_via_parent":
			foundInherited = true
			require.Len(t, constraint.Path, 1)
			require.Equal(t, "parent", constraint.Path[0].Pointer)
		}
	}
	require.True(t, foundParent)
	require.True(t, foundAlias, "must derive model aliases, not invent only the direct tuple")
	require.True(t, foundInherited, "model dependency must retain a path to the selected parent")
}

func TestChildRegistrationRoleIntersectsParentSelectionTargetAndScope(t *testing.T) {
	c := childRegistrationRoleFixture(t, true)
	for _, test := range []struct {
		name    string
		prepare func(*Binding)
		want    bool
	}{
		{"named-parent", func(b *Binding) { b.Role.Rules[0].ResourceNames = []string{"parent-a"} }, true},
		{"other-name", func(b *Binding) { b.Role.Rules[0].ResourceNames = []string{"parent-b"} }, false},
		{"child-target", func(b *Binding) {
			b.Target.Resources[0] = domain.ResourceRef{Type: "registry.repositories", ID: "parent-a/child-a"}
		}, false},
		{"other-parent-type", func(b *Binding) { b.Target.Resources[0].Type = "registry.tags" }, false},
		{"labels", func(b *Binding) { b.Role.Rules[0].MatchLabels = map[string]string{"team": "a"} }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := childRegistrationRoleBinding()
			b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "registry.registries", ID: "parent-a"}}}
			test.prepare(&b)
			effects := childRegistrationRoleEffects(complete(t, c.Compile(b)))
			require.Equal(t, test.want, len(effects) > 0)
			for _, effect := range effects {
				require.Equal(t, &b.Scope, effect.Constraints[0].Within)
				require.Equal(t, []string{"parent-a"}, effect.Constraints[0].Region.Objects.IDs)
				require.Equal(t, b.Role.Rules[0].MatchLabels, effect.Constraints[0].Region.Labels)
			}
		})
	}
	b := childRegistrationRoleBinding()
	b.Role.Rules[0].ResourceNames = []string{"parent-a"}
	effects := childRegistrationRoleEffects(complete(t, c.Compile(b)))
	require.NotEmpty(t, effects)
	for _, effect := range effects {
		require.Equal(t, []string{"parent-a"}, effect.Constraints[0].Region.Objects.IDs)
		require.Equal(t, &b.Scope, effect.Constraints[0].Within)
	}
}

func TestChildRegistrationRoleOnlyDirectHumanAndExplicitDeclaredAction(t *testing.T) {
	c := childRegistrationRoleFixture(t, true)
	for _, subject := range []domain.Subject{
		{Type: domain.SubjectTypeServiceAccount, ID: "user-a"},
		{Type: domain.SubjectTypeGroup, ID: "user-a"},
		{Type: domain.SubjectTypeSystemClass, ID: domain.ClassAuthenticated},
	} {
		t.Run(string(subject.Type), func(t *testing.T) {
			b := childRegistrationRoleBinding()
			b.Recipient = subject
			b.Subjects = []domain.Subject{subject}
			require.Empty(t, childRegistrationRoleEffects(c.Compile(b)))
		})
	}
	for _, verb := range []string{"*", "get", "serviceCreate"} {
		t.Run(verb, func(t *testing.T) {
			b := childRegistrationRoleBinding()
			b.Role.Rules[0].Children[0].Verbs = []string{verb}
			require.Empty(t, childRegistrationRoleEffects(complete(t, c.Compile(b))))
		})
	}
	require.Empty(t, childRegistrationRoleEffects(complete(t, childRegistrationRoleFixture(t, false).Compile(childRegistrationRoleBinding()))))
	// Обычное действие create по-прежнему доступно служебной учётке.
	b := binding(domain.Rule{Module: "iam", Resources: []string{"serviceAccount"}, Verbs: []string{"create"}})
	for _, effect := range complete(t, c.Compile(b)).Effects() {
		require.NotEqual(t, "service_account_creator", effect.Action.Name)
	}
	b.Recipient = domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: "sa-a"}
	found := false
	for _, effect := range complete(t, c.Compile(b)).Effects() {
		if effect.Type == "account" && effect.Action.Name == "service_account_creator" && effect.Provenance.Primitive == "container" {
			found = true
		}
	}
	require.True(t, found)
}

func TestChildRegistrationRoleDoesNotWidenChildSelectorsOrAncestorOwner(t *testing.T) {
	c := childRegistrationRoleFixture(t, true)
	for _, test := range []struct {
		name    string
		prepare func(*Binding)
	}{
		{"child-names", func(b *Binding) { b.Role.Rules[0].Children[0].ResourceNames = []string{"child-a"} }},
		{"child-labels", func(b *Binding) { b.Role.Rules[0].Children[0].MatchLabels = map[string]string{"team": "a"} }},
		{"wrong-owner", func(b *Binding) { b.Role.Rules[0].Resources = []string{"tags"} }},
		{"flat-child", func(b *Binding) {
			b.Role.Rules = domain.Rules{{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"registerChild"}}}
		}},
		{"child-wildcard", func(b *Binding) { b.Role.Rules[0].Children[0].Resources = []string{"*"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := childRegistrationRoleBinding()
			test.prepare(&b)
			// Неподходящие селекторы не дают права регистрации.
			require.Empty(t, childRegistrationRoleEffects(c.Compile(b)))
		})
	}
}

func TestChildRegistrationRoleKeepsOrdinaryChildRightsOnChildren(t *testing.T) {
	c := childRegistrationRoleFixture(t, true)
	b := childRegistrationRoleBinding()
	b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "registry.registries", ID: "parent-a"}}}
	b.Role.Rules[0].Children[0].Verbs = []string{"registerChild", "get"}
	set := complete(t, c.Compile(b))
	require.NotEmpty(t, childRegistrationRoleEffects(set))
	found := false
	for _, effect := range set.Effects() {
		if effect.Provenance.Primitive == "object_rule" && effect.Type == "strange_item" && effect.Action.Kind == grantcoverage.Verb && effect.Action.Name == "get" {
			found = true
			require.Len(t, effect.Constraints, 2)
			require.Equal(t, "strange_item", effect.Constraints[0].Type)
			require.Empty(t, effect.Constraints[0].Path)
			require.Equal(t, "strange_box", effect.Constraints[1].Type)
			require.Equal(t, []string{"parent-a"}, effect.Constraints[1].Region.Objects.IDs)
			require.Len(t, effect.Constraints[1].Path, 1)
		}
	}
	require.True(t, found)
}

func TestChildRegistrationRoleFailsClosedIfModelDoesNotAcceptHuman(t *testing.T) {
	h := childRegistrationRoleRows()
	h.Live.Resources[1].ChildRegistration = &catalog.ChildRegistrationRule{
		Verb: "registerchild", ParentSegments: 1, MaxChildren: 24, MaxCreates: 4, WindowSeconds: 60,
	}
	h.Live.Verbs = append(h.Live.Verbs, catalog.VerbRow{Module: "registry", Resource: "repositories", Verb: "registerchild", ContainerParent: "strange_box", ContainerRelation: "child_registrar"})
	for _, subject := range []string{"service_account", "user with fresh"} {
		t.Run(subject, func(t *testing.T) {
			model := strings.Replace(modelFixture, "type strange_box\n  relations\n",
				"type strange_box\n  relations\n    define child_registrar: ["+subject+"]\n", 1)
			c, err := New(model, h)
			require.ErrorContains(t, err, "модель не подтверждает право пользователя")
			require.Nil(t, c)
		})
	}
}
