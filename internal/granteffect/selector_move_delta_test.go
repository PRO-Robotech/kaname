// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"slices"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/stretchr/testify/require"
)

func TestSelectorMoveDeltaFutureChildren(t *testing.T) {
	rows := bundleRows()
	rows.Live.Resources = append(rows.Live.Resources, catalog.ResourceRow{Module: "iam", Resource: "project", ObjectType: "project", ParentTypes: []string{"account"}, ParentNames: []string{"account"}})
	rows.Live.Verbs = append(rows.Live.Verbs, catalog.VerbRow{Module: "iam", Resource: "project", Verb: "get", PerObject: true})
	bundle, err := NewBundle(t.Context(), authzmodel.DSL, rows, ProjectorVersion)
	require.NoError(t, err)

	rule := domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"team": "blue"},
		Children: []domain.Rule{{Resources: []string{"project"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"region": "west"}}}}
	old := MetadataObject{Type: "account", ID: "acc-parent", Labels: domain.Labels{"team": "blue"}}
	next := old
	next.AccessLabels = domain.Labels{"team": "blue"}
	source := binding(rule)
	source.Scope.ID = old.ID
	source.Subjects = []domain.Subject{source.Recipient}
	source.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "iam.account", ID: old.ID}}}
	moved := source
	moved.Role.Rules, err = source.Role.Rules.MoveAccessLabelSelectors([]domain.AccessLabelSelectorMove{{RuleIndex: 0, Fingerprint: rule.Fingerprint()}}, domain.TenantPolicy(), domain.ModuleSetOf("iam"))
	require.NoError(t, err)

	// Копия сохраняет отбор у переносимой роли на точном родителе.
	rewritten := completeMetadata(t, bundle.CompileSelectorMoveDelta(source, moved, old, next))
	require.NotEmpty(t, rewritten.Before.Effects())
	proves(t, rewritten.Before, rewritten.After, true)
	proves(t, rewritten.After, rewritten.Before, true)
	for _, effect := range rewritten.Before.Effects() {
		require.Equal(t, rule.Fingerprint(), effect.Provenance.AuthoredRuleFP)
	}
	for _, effect := range rewritten.After.Effects() {
		require.Equal(t, moved.Role.Rules[0].Fingerprint(), effect.Provenance.AuthoredRuleFP)
	}

	// Та же копия впервые выбирает родителя у сторонней роли. Перечня детей нет.
	foreign := moved
	foreign.Role.ID = "role-foreign"
	delta := completeMetadata(t, bundle.CompileSelectorMoveDelta(foreign, foreign, old, next))
	require.Empty(t, delta.Before.Effects())
	proves(t, delta.Before, delta.After, false)
	foundChild := false
	for _, effect := range delta.After.Effects() {
		if effect.Type != "project" || effect.Action != (grantcoverage.Action{Kind: grantcoverage.Verb, Name: "get"}) || len(effect.Constraints) != 2 {
			continue
		}
		child, parent := effect.Constraints[0], effect.Constraints[1]
		require.Equal(t, "project", child.Type)
		require.Equal(t, grantcoverage.AllObjects, child.Region.Objects.Kind)
		require.Equal(t, map[string]string{"region": "west"}, child.Region.Labels)
		require.Equal(t, "account", parent.Type)
		require.Equal(t, grantcoverage.ObjectIDs, parent.Region.Objects.Kind)
		require.Equal(t, []string{old.ID}, parent.Region.Objects.IDs)
		require.Empty(t, parent.Region.AccessLabels)
		require.Equal(t, &source.Scope, parent.Within)
		require.True(t, slices.Contains(parent.Path, authzmodel.EffectHop{From: "project", Pointer: "account", To: "account"}))
		foundChild = true
	}
	require.True(t, foundChild, "нет эффекта чтения для будущего проекта выбранного аккаунта")
}

func TestSelectorMoveDeltaRejectsChangedInputs(t *testing.T) {
	bundle := bundleCanon(t)
	source := binding(domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"env": "blue"}})
	source.Subjects = []domain.Subject{source.Recipient}
	old := MetadataObject{Type: "account", ID: "acc-a", Labels: domain.Labels{"env": "blue"}}
	for name, change := range map[string]func(*Binding, *MetadataObject){
		"role identity":      func(b *Binding, _ *MetadataObject) { b.Role.ID = "role-other" },
		"definition tier":    func(b *Binding, _ *MetadataObject) { b.Role.ProjectID = "prj-other" },
		"capability version": func(b *Binding, _ *MetadataObject) { b.CapabilityVersion = 0 },
		"missing recipients": func(b *Binding, _ *MetadataObject) { b.Subjects = nil },
		"object identity":    func(_ *Binding, o *MetadataObject) { o.ID = "acc-other" },
		"uncopied value":     func(_ *Binding, o *MetadataObject) { o.AccessLabels = domain.Labels{"env": "red"} },
	} {
		t.Run(name, func(t *testing.T) {
			proposed, next := source, old
			change(&proposed, &next)
			delta := bundle.CompileSelectorMoveDelta(source, proposed, old, next)
			require.False(t, delta.Before.Complete())
			require.False(t, delta.After.Complete())
		})
	}
}
