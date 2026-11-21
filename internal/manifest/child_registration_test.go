// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/manifestoracle"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
)

const childRegistrationFixture = `apiVersion: iam/v1
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
`

const childRegistrationBlock = `    childRegistration:
      verb: registerChild
      parentSegments: 1
      maxChildren: 24
      maxCreates: 4
      windowSeconds: 60
`

func childRegistrationOracle(t *testing.T, subjects string) manifest.RelationOracle {
	t.Helper()
	model := `model
  schema 1.1

type user

type service_account

type example_container
  relations
    define child_registrar: [` + subjects + "]\n"
	plans, err := authzmodel.New(model)
	require.NoError(t, err)
	return manifestoracle.FromPlans(plans)
}

func TestChildRegistrationBindsNamedParentAction(t *testing.T) {
	data := []byte(childRegistrationFixture + childRegistrationBlock)
	m, err := manifest.LoadWithReferent(data, manifest.ReferentCanon)
	require.NoError(t, err)
	model, _, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
	require.NoError(t, err)
	plans, err := authzmodel.New(model)
	require.NoError(t, err)
	oracle := manifestoracle.FromPlans(plans)
	m, err = manifest.LoadWithReferent(data, manifest.ReferentCanon, manifest.WithRelationOracle(oracle))
	require.NoError(t, err)
	resource := m.Resources[1]
	policy, ok := resource.UserChildPathPolicy()
	require.True(t, ok)
	target, err := policy.Resolve("container-1/child-1")
	require.NoError(t, err)
	require.Equal(t, "example_container:container-1", target.ParentObject)
	require.Equal(t, "child_registrar", target.ParentAction)

	encoded, err := yaml.Marshal(resource.ChildRegistration)
	require.NoError(t, err)
	var decoded manifest.ChildRegistration
	require.NoError(t, yaml.Unmarshal(encoded, &decoded))
	require.Equal(t, *resource.ChildRegistration, decoded)
}

func TestChildRegistrationRequiresDirectHumanAndKeepsOtherActionsServiceOnly(t *testing.T) {
	data := []byte(childRegistrationFixture + childRegistrationBlock)
	sa := manifest.WithRelationOracle(childRegistrationOracle(t, "service_account"))
	user := manifest.WithRelationOracle(childRegistrationOracle(t, "user"))
	_, err := manifest.LoadWithReferent(data, manifest.ReferentCanon, sa)
	require.ErrorIs(t, err, manifest.ErrChildRegistrationDeclaration)

	// Без объявления это прежнее контейнерное действие для служебной учётки.
	data = []byte(childRegistrationFixture)
	_, err = manifest.LoadWithReferent(data, manifest.ReferentCanon, user)
	require.ErrorIs(t, err, manifest.ErrContainerVerbRelationSubject)
	m, err := manifest.LoadWithReferent(data, manifest.ReferentCanon, sa)
	require.NoError(t, err)
	_, ok := m.Resources[1].UserChildPathPolicy()
	require.False(t, ok)
}

func TestChildRegistrationKeepsServiceAccountForCreatorAction(t *testing.T) {
	data := []byte(strings.ReplaceAll(childRegistrationFixture+childRegistrationBlock, "registerChild", "create"))
	user := manifest.WithRelationOracle(childRegistrationOracle(t, "user"))
	sa := manifest.WithRelationOracle(childRegistrationOracle(t, "service_account"))
	both := manifest.WithRelationOracle(childRegistrationOracle(t, "user, service_account"))
	_, err := manifest.LoadWithReferent(data, manifest.ReferentCanon, user)
	require.ErrorIs(t, err, manifest.ErrContainerVerbRelationSubject)
	_, err = manifest.LoadWithReferent(data, manifest.ReferentCanon, sa)
	require.ErrorIs(t, err, manifest.ErrChildRegistrationDeclaration)
	_, err = manifest.LoadWithReferent(data, manifest.ReferentCanon, both)
	require.NoError(t, err)
}

func TestChildRegistrationRejectsIncompletePolicy(t *testing.T) {
	for _, change := range []struct {
		from string
		to   string
	}{
		{childRegistrationBlock, "    childRegistration: null\n"},
		{"verb: registerChild", "verb: missing"},
		{"parentSegments: 1", "parentSegments: 0"},
		{"parentSegments: 1", "parentSegments: 300"},
		{"maxChildren: 24", "maxChildren: 0"},
		{"maxCreates: 4", "maxCreates: 1.5"},
		{"windowSeconds: 60", "windowSeconds: null"},
	} {
		input := strings.Replace(childRegistrationBlock, change.from, change.to, 1)
		_, err := manifest.LoadWithReferent([]byte(childRegistrationFixture+input), manifest.ReferentCanon)
		require.Error(t, err, change.to)
	}
}
