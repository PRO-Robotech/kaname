// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"slices"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/stretchr/testify/require"
)

func initialRegistrationFixture(t *testing.T) (*Bundle, InitialRegistrationImage) {
	t.Helper()
	h := rows()
	h.Live.Modules = append(h.Live.Modules, "registry")
	names := map[string]string{"boxes": "registries", "items": "repositories"}
	for i := range h.Live.Resources {
		row := &h.Live.Resources[i]
		if name, ok := names[row.Resource]; ok && row.Module == "probemod" {
			row.Module, row.Resource = "registry", name
		}
		if row.ObjectType == "strange_box" {
			row.ParentTypes = []string{"project"}
			row.ParentNames = []string{"project"}
		}
	}
	for i := range h.Live.Verbs {
		row := &h.Live.Verbs[i]
		if name, ok := names[row.Resource]; ok && row.Module == "probemod" {
			row.Module, row.Resource = "registry", name
		}
	}
	h.Live.Resources = append(h.Live.Resources, catalog.ResourceRow{
		Module: "iam", Resource: "project", ObjectType: "project",
		ParentTypes: []string{"account"}, ParentNames: []string{"account"},
	})
	const boxPrefix = "type strange_box\n  relations\n    define account: [account]\n" +
		"    define admin: [user, service_account, group#member] or admin from account"
	model := strings.Replace(modelFixture, boxPrefix,
		"type strange_box\n  relations\n    define project: [project]\n"+
			"    define admin: [user, service_account, group#member] or admin from project", 1)
	require.NotEqual(t, modelFixture, model)
	c, err := New(model, h)
	require.NoError(t, err)
	// Фикстура использует небольшую модель. Штатный NewBundle удостоверяет
	// полный каталог и модель.
	bundle := &Bundle{compiler: c, modelSource: model, canonicalCatalog: []byte("{}")}
	projectID, accountID := "prj-a", "acc-a"
	root := domain.ResourceRef{Type: "registry.registries", ID: "registry-a"}
	toProject := authzmodel.EffectHop{From: "strange_box", Pointer: "project", To: "project"}
	toAccount := authzmodel.EffectHop{From: "project", Pointer: "account", To: "account"}
	image := InitialRegistrationImage{
		Root: root,
		New: domain.MirrorObject{
			ObjectType: root.Type, ObjectID: root.ID, ParentProjectID: projectID, ParentAccountIDs: []string{accountID},
			Labels: map[string]string{"team": "ordinary"}, AccessLabels: map[string]string{"team": "protected"},
		},
		Ancestors: []RegistrationAncestor{
			{Path: []authzmodel.EffectHop{toProject}, Object: domain.MirrorObject{
				ObjectType: "iam.project", ObjectID: projectID, ParentProjectID: projectID, ParentAccountIDs: []string{accountID},
			}},
			{Path: []authzmodel.EffectHop{toProject, toAccount}, Object: domain.MirrorObject{
				ObjectType: "iam.account", ObjectID: accountID, ParentAccountIDs: []string{accountID},
			}},
		},
	}
	return bundle, image
}

func TestInitialRegistrationSpecializesHeldBinding(t *testing.T) {
	bundle, image := initialRegistrationFixture(t)
	all := domain.Rule{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"}}
	named := all
	named.ResourceNames = []string{image.Root.ID}
	ordinary := all
	ordinary.MatchLabels = map[string]string{"team": "ordinary"}
	protected := all
	protected.MatchAccessLabels = map[string]string{"team": "protected"}
	wrongMap := protected
	wrongMap.MatchAccessLabels = map[string]string{"team": "ordinary"}
	nested := protected
	nested.Children = []domain.Rule{{Resources: []string{"repositories"}, Verbs: []string{"get"}}}
	for _, row := range []struct {
		name string
		rule domain.Rule
		edit func(*Binding)
	}{
		{name: "all", rule: all},
		{name: "name", rule: named},
		{name: "ordinary-label", rule: ordinary},
		{name: "protected-label", rule: protected},
		{name: "explicit-target", rule: all, edit: func(b *Binding) {
			b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{image.Root}}
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			b := binding(row.rule)
			b.Subjects = []domain.Subject{b.Recipient}
			if row.edit != nil {
				row.edit(&b)
			}
			delta := completeMetadata(t, bundle.CompileInitialRegistrationBinding(b, image))
			require.Empty(t, delta.Before.Effects())
			require.NotEmpty(t, delta.After.Effects())
			for _, effect := range delta.After.Effects() {
				require.Equal(t, "strange_box", effect.Type)
				require.Len(t, effect.Constraints, 1)
				require.Equal(t, []string{image.Root.ID}, effect.Constraints[0].Region.Objects.IDs)
				require.Equal(t, &b.Scope, effect.Constraints[0].Within)
			}
			proves(t, delta.Before, delta.After, false)
			proves(t, delta.After, delta.After, true)
		})
	}

	t.Run("nested-selector-preserves-child-and-exact-container", func(t *testing.T) {
		b := binding(nested)
		b.Subjects = []domain.Subject{b.Recipient}
		b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{image.Root}}
		delta := completeMetadata(t, bundle.CompileInitialRegistrationBinding(b, image))
		require.Empty(t, delta.Before.Effects())
		require.NotEmpty(t, delta.After.Effects())
		for _, effect := range delta.After.Effects() {
			require.Equal(t, "strange_item", effect.Type)
			require.Len(t, effect.Constraints, 2)
			child, parent := effect.Constraints[0], effect.Constraints[1]
			require.Equal(t, grantcoverage.AllObjects, child.Region.Objects.Kind)
			require.Equal(t, []authzmodel.EffectHop{{From: "strange_item", Pointer: "parent", To: "strange_box"}}, parent.Path)
			require.Equal(t, []string{image.Root.ID}, parent.Region.Objects.IDs)
			require.Equal(t, protected.MatchAccessLabels, parent.Region.AccessLabels)
		}
	})

	t.Run("other-key-map-target-and-scope-do-not-match", func(t *testing.T) {
		otherTarget := binding(all)
		otherTarget.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: image.Root.Type, ID: "registry-other"}}}
		otherProject := binding(all)
		otherProject.Scope = domain.ScopeAnchor{Type: "project", ID: "prj-other"}
		for _, b := range []Binding{binding(wrongMap), otherTarget, otherProject} {
			b.Subjects = []domain.Subject{b.Recipient}
			delta := completeMetadata(t, bundle.CompileInitialRegistrationBinding(b, image))
			require.Empty(t, delta.Before.Effects())
			require.Empty(t, delta.After.Effects())
		}
	})
}

func TestInitialRegistrationSpecializesDirectAndInheritedSources(t *testing.T) {
	bundle, image := initialRegistrationFixture(t)
	recipient := domain.Subject{Type: domain.SubjectTypeUser, ID: "user-a"}
	source := Direct{SourceID: "held-account-admin", ObjectType: "account", ObjectID: "acc-a", Relation: "admin", Recipient: recipient}
	delta := completeMetadata(t, bundle.CompileInitialRegistrationDirect(source, image))
	require.Empty(t, delta.Before.Effects())
	require.NotEmpty(t, delta.After.Effects())
	rootFound := false
	for _, effect := range delta.After.Effects() {
		if effect.Type != "strange_box" {
			continue
		}
		rootFound = true
		require.Len(t, effect.Constraints, 2)
		require.Equal(t, image.Ancestors[1].Path, effect.Constraints[0].Path)
		require.Equal(t, []string{"acc-a"}, effect.Constraints[0].Region.Objects.IDs)
		require.Empty(t, effect.Constraints[1].Path)
		require.Equal(t, []string{image.Root.ID}, effect.Constraints[1].Region.Objects.IDs)
	}
	require.True(t, rootFound)

	const heldCondition = "fresh"
	condition := Condition{Name: heldCondition, Parameters: `{"at":"2026-01-01T00:00:00Z"}`}
	direct := Direct{SourceID: "accepted-initial-source", ObjectType: "strange_box", ObjectID: image.Root.ID,
		Relation: "console", Recipient: recipient, Condition: condition}
	exact := completeMetadata(t, bundle.CompileInitialRegistrationDirect(direct, image))
	require.Empty(t, exact.Before.Effects())
	require.NotEmpty(t, exact.After.Effects())
	for _, effect := range exact.After.Effects() {
		require.Equal(t, condition, effect.Condition)
		require.Equal(t, direct.SourceID, effect.Provenance.SourceID)
		require.Equal(t, []string{image.Root.ID}, effect.Constraints[0].Region.Objects.IDs)
	}
}

func TestInitialRegistrationNestedRootRequiresHeldParent(t *testing.T) {
	bundle, registry := initialRegistrationFixture(t)
	child := registry.New
	child.ObjectType, child.ObjectID = "registry.repositories", "repository-a"
	toRegistry := authzmodel.EffectHop{From: "strange_item", Pointer: "parent", To: "strange_box"}
	image := InitialRegistrationImage{
		Root:      domain.ResourceRef{Type: child.ObjectType, ID: child.ObjectID},
		New:       child,
		Ancestors: []RegistrationAncestor{{Path: []authzmodel.EffectHop{toRegistry}, Object: registry.New}},
	}
	for _, ancestor := range registry.Ancestors {
		ancestor.Path = append([]authzmodel.EffectHop{toRegistry}, ancestor.Path...)
		image.Ancestors = append(image.Ancestors, ancestor)
	}
	b := binding(domain.Rule{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"get"}})
	b.Subjects = []domain.Subject{b.Recipient}
	delta := completeMetadata(t, bundle.CompileInitialRegistrationBinding(b, image))
	require.Empty(t, delta.Before.Effects())
	require.NotEmpty(t, delta.After.Effects())
	for _, effect := range delta.After.Effects() {
		require.Equal(t, "strange_item", effect.Type)
		require.Len(t, effect.Constraints, 1)
		require.Equal(t, []string{child.ObjectID}, effect.Constraints[0].Region.Objects.IDs)
	}
	image.Ancestors = image.Ancestors[1:]
	missingParent := bundle.CompileInitialRegistrationBinding(b, image)
	require.False(t, missingParent.After.Complete())
	require.NotEmpty(t, missingParent.After.Obligations())
}

func TestInitialRegistrationRefusesUnconfirmedCoordinatesAndRecipients(t *testing.T) {
	bundle, image := initialRegistrationFixture(t)
	b := binding(domain.Rule{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"}})
	wantIncomplete := func(delta MetadataDelta) {
		t.Helper()
		require.False(t, delta.Before.Complete())
		require.False(t, delta.After.Complete())
		require.NotEmpty(t, delta.After.Obligations())
	}
	wantIncomplete(bundle.CompileInitialRegistrationBinding(b, image))
	b.Subjects = []domain.Subject{{Type: domain.SubjectTypeUser, ID: "different-user"}}
	wantIncomplete(bundle.CompileInitialRegistrationBinding(b, image))
	b.Subjects = []domain.Subject{b.Recipient}
	for _, mutate := range []func(*InitialRegistrationImage){
		func(in *InitialRegistrationImage) { in.New.ObjectID = "other" },
		func(in *InitialRegistrationImage) { in.New.ParentProjectID = "prj-other" },
		func(in *InitialRegistrationImage) { in.New.ParentAccountIDs = []string{"acc-other"} },
		func(in *InitialRegistrationImage) { in.Ancestors = in.Ancestors[1:] },
		func(in *InitialRegistrationImage) { in.Ancestors[1].Object.ObjectID = "acc-other" },
		func(in *InitialRegistrationImage) { in.Ancestors[0].Path[0].Pointer = "unproven" },
	} {
		broken := image
		broken.Ancestors = slices.Clone(image.Ancestors)
		for i := range broken.Ancestors {
			broken.Ancestors[i].Path = slices.Clone(broken.Ancestors[i].Path)
		}
		mutate(&broken)
		wantIncomplete(bundle.CompileInitialRegistrationBinding(b, broken))
	}

	// Образы проекта и аккаунта не удостоверяют путь до кластера.
	cluster := Direct{SourceID: "cluster-admin", ObjectType: "cluster", ObjectID: domain.ClusterSingletonID,
		Relation: "system_admin", Recipient: b.Recipient}
	wantIncomplete(bundle.CompileInitialRegistrationDirect(cluster, image))
	otherRoot := Direct{SourceID: "other-object", ObjectType: "strange_box", ObjectID: "registry-other",
		Relation: "viewer", Recipient: b.Recipient}
	wantIncomplete(bundle.CompileInitialRegistrationDirect(otherRoot, image))
}
