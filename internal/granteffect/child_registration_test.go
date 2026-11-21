// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"context"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	"github.com/stretchr/testify/require"
)

const childRegistrationBundleManifest = `apiVersion: iam/v1
module: example
resources:
  - name: container
    objectType: example_container
    parents: [project]
    producer: authored
    verbs: [get]
    relations:
      - {name: child_registrar, definition: "[user]"}
  - name: child
    objectType: example_child
    parents:
      - {name: parent, type: example_container}
    producer: authored
    verbs: [get]
    containerVerbs:
      - {name: registerChild, parent: parent, relation: child_registrar}
    childRegistration: {verb: registerChild, parentSegments: 1, maxChildren: 24, maxCreates: 4, windowSeconds: 60}
`

func childRegistrationBundleRows() catalog.Halves {
	return catalog.Halves{Live: catalog.Rows{
		Modules: []string{"example"},
		Resources: []catalog.ResourceRow{
			{Module: "example", Resource: "container", ObjectType: "example_container", ParentNames: []string{"project"}, ParentTypes: []string{"project"}},
			{Module: "example", Resource: "child", ObjectType: "example_child", ParentNames: []string{"parent"}, ParentTypes: []string{"example_container"},
				ChildRegistration: &catalog.ChildRegistrationRule{
					Verb: "registerchild", ParentSegments: 1, MaxChildren: 24, MaxCreates: 4, WindowSeconds: 60,
				}},
		},
		Verbs: []catalog.VerbRow{
			{Module: "example", Resource: "container", Verb: "get", PerObject: true},
			{Module: "example", Resource: "child", Verb: "get", PerObject: true},
			{Module: "example", Resource: "child", Verb: "registerchild", ContainerParent: "example_container", ContainerRelation: "child_registrar"},
		},
	}}
}

func TestChildRegistrationBundleBindsLivePathAndModel(t *testing.T) {
	m, err := manifest.LoadWithReferent([]byte(childRegistrationBundleManifest), manifest.ReferentCanon)
	require.NoError(t, err)
	source, rep, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
	require.NoError(t, err)
	ctx := context.Background()
	rows := childRegistrationBundleRows()
	bundle, err := NewBundle(ctx, source, rows, ProjectorVersion, rep.KeyTerms...)
	require.NoError(t, err)
	policy, ok := bundle.ChildRegistration("example.child")
	require.True(t, ok)
	require.Equal(t, int32(24), policy.MaxChildren)
	require.Equal(t, int32(4), policy.MaxCreates)
	require.Equal(t, int32(60), policy.WindowSeconds)
	target, err := policy.Path.Resolve("container-1/child-2")
	require.NoError(t, err)
	require.Equal(t, "example_child:container-1/child-2", target.ChildObject)
	require.Equal(t, "example_container:container-1", target.ParentObject)
	require.Equal(t, "child_registrar", target.ParentAction)
	dotted, ok := bundle.ChildRegistrationParentDotted("example_container", target.ParentAction)
	require.True(t, ok)
	require.Equal(t, "example.container", dotted)
	_, ok = bundle.ChildRegistrationParentDotted("example_container", "v_get")
	require.False(t, ok)
	_, ok = bundle.ChildRegistrationParentDotted("example_child", target.ParentAction)
	require.False(t, ok)

	rows.Live.Resources[1].ChildRegistration.MaxCreates = 12
	same, ok := bundle.ChildRegistration("example.child")
	require.True(t, ok)
	require.Equal(t, policy, same, "переданные строки не могут изменить принятую политику")
	_, ok = bundle.ChildRegistration("example_child")
	require.False(t, ok, "публичный запрос использует точечное имя каталога")

	stale := childRegistrationBundleRows()
	stale.Retired.Resources = stale.Live.Resources[1:]
	stale.Live.Resources = stale.Live.Resources[:1]
	stale.Live.Verbs = stale.Live.Verbs[:1]
	retired, err := NewBundle(ctx, source, stale, ProjectorVersion, rep.KeyTerms...)
	require.NoError(t, err)
	_, ok = retired.ChildRegistration("example.child")
	require.False(t, ok, "снятая декларация не открывает регистрацию")
	_, ok = retired.ChildRegistrationParentDotted("example_container", target.ParentAction)
	require.False(t, ok)
}

func TestChildRegistrationBundleRefusesUnconfirmedPolicy(t *testing.T) {
	m, err := manifest.LoadWithReferent([]byte(childRegistrationBundleManifest), manifest.ReferentCanon)
	require.NoError(t, err)
	source, _, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
	require.NoError(t, err)
	// Парсер принимает обе модели. Отказ должен исходить из проверки
	// соответствия родительского отношения каталожной декларации.
	saOnly := strings.Replace(source, "define child_registrar: [user]", "define child_registrar: [service_account]", 1)
	require.NotEqual(t, source, saOnly)
	_, err = authzmodel.New(saOnly)
	require.NoError(t, err)
	_, err = New(saOnly, childRegistrationBundleRows())
	require.ErrorContains(t, err, "модель не подтверждает право пользователя")

	for name, alter := range map[string]func(*catalog.Halves){
		"absent named action": func(rows *catalog.Halves) {
			rows.Live.Verbs = rows.Live.Verbs[:2]
		},
		"different parent pointer": func(rows *catalog.Halves) {
			rows.Live.Resources[1].ParentNames = []string{"project"}
		},
		"non-positive limit": func(rows *catalog.Halves) {
			rows.Live.Resources[1].ChildRegistration.MaxCreates = 0
		},
		"ordinary verb relation": func(rows *catalog.Halves) {
			rows.Live.Verbs[2].ContainerRelation = "v_get"
		},
	} {
		t.Run(name, func(t *testing.T) {
			rows := childRegistrationBundleRows()
			alter(&rows)
			_, err := New(source, rows)
			require.ErrorContains(t, err, "несогласованная политика регистрации потомков")
		})
	}
}
