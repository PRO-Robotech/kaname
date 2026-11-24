// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"fmt"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	"github.com/stretchr/testify/require"
)

// Каждая редакция проходит настоящий загрузчик, композицию и admission.
// Добавленный тип намеренно отсутствует в статическом реестре сборки.
func liveProjectionBundle(t *testing.T, addedType, addedVerb bool) *Bundle {
	t.Helper()
	names := []string{"livewidget"}
	if addedType {
		names = append(names, "livegadget")
	}
	verbs := []string{"get"}
	if addedVerb {
		verbs = append(verbs, "list")
	}
	var document strings.Builder
	document.WriteString("apiVersion: iam/v1\nmodule: vpc\nresources:\n")
	rows := bundleRows()
	rows.Live.Modules = append(rows.Live.Modules, "vpc")
	rows.Live.Resources = append(rows.Live.Resources, catalog.ResourceRow{Module: "iam", Resource: "project", ObjectType: "project"})
	for _, name := range names {
		typ := "vpc_projection_" + name
		fmt.Fprintf(&document, "  - name: %s\n    objectType: %s\n    parents: [project]\n    producer: derived\n    verbs: [%s]\n", name, typ, strings.Join(verbs, ", "))
		rows.Live.Resources = append(rows.Live.Resources, catalog.ResourceRow{
			Module: "vpc", Resource: name, ObjectType: typ, ParentTypes: []string{"project"}, ParentNames: []string{"project"},
		})
		for _, verb := range verbs {
			rows.Live.Verbs = append(rows.Live.Verbs, catalog.VerbRow{Module: "vpc", Resource: name, Verb: verb, PerObject: true})
		}
	}
	part, err := manifest.Load([]byte(document.String()))
	require.NoError(t, err)
	source, report, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{part})
	require.NoError(t, err)
	bundle, err := NewBundle(t.Context(), source, rows, ProjectorVersion, report.KeyTerms...)
	require.NoError(t, err)
	return bundle
}

func TestLiveCatalogProjectionAddsTypeAndVerbWithoutCompletingWildcardProof(t *testing.T) {
	const added = "vpc.livegadget"
	require.NotContains(t, domain.AllMaterializableTypes(), added, "контроль: тип неизвестен статическому реестру")
	before := liveProjectionBundle(t, false, false)
	withType := liveProjectionBundle(t, true, false)
	withVerb := liveProjectionBundle(t, true, true)
	for _, module := range []string{"vpc", "*"} {
		t.Run(module, func(t *testing.T) {
			role := domain.Role{ID: "role-live", IsSystem: true, Rules: domain.Rules{{Module: module, Resources: []string{"*"}, Verbs: []string{"*"}}}}
			policy := domain.PolicyOfRole(role.IsSystem, role.OwnerModule)
			original, err := before.Projection(role)
			require.NoError(t, err)
			require.NotContains(t, original.Selectors[0].ObjectTypes, added)
			previous := original
			for _, candidate := range []*Bundle{withType, withVerb} {
				projection, err := candidate.Projection(role)
				require.NoError(t, err)
				require.Equal(t, original.Checkpoint.AuthoredID, projection.Checkpoint.AuthoredID)
				require.NotEqual(t, previous.Checkpoint.RelevantCatalogID, projection.Checkpoint.RelevantCatalogID)
				require.NotEqual(t, previous.Checkpoint.ProjectionID, projection.Checkpoint.ProjectionID)
				require.Contains(t, projection.Selectors[0].ObjectTypes, added)
				require.Equal(t, role.Rules[0].Fingerprint(), projection.Selectors[0].RuleFP)
				want := []string{"get"}
				if candidate == withVerb {
					want = append(want, "list")
				}
				require.ElementsMatch(t, want, projection.Selectors[0].Grants[added])
				for _, verb := range want {
					require.Contains(t, projection.Verbs, domain.RoleVerb{ObjectType: added, Verb: verb})
				}
				if candidate == withType {
					require.NotContains(t, projection.Verbs, domain.RoleVerb{ObjectType: added, Verb: "list"})
				}
				if module == "vpc" {
					require.NotContains(t, projection.Selectors[0].ObjectTypes, "iam.account")
				}
				for _, scope := range []domain.ScopeAnchor{{Type: "account", ID: "acc-a"}, {Type: "cluster", ID: domain.ClusterSingletonID}} {
					selectors, err := candidate.GrantSelectors(role.Rules, policy, scope)
					require.NoError(t, err)
					require.Len(t, selectors, 1)
					if scope.Type == "account" {
						require.Equal(t, projection.Selectors, selectors)
					} else {
						require.Empty(t, selectors[0].ObjectTypes)
					}
					input := binding(role.Rules...)
					input.Role, input.Scope = role, scope
					effect := candidate.Compile(input)
					require.True(t, hasObligation(effect, "wildcard_type_producer"))
					require.False(t, effect.Complete())
					require.NotEqual(t, grantcoverage.Proved, Prove(effect, effect).Status)
					found := false
					for _, item := range effect.Effects() {
						if item.Type == "vpc_projection_livegadget" && item.Provenance.Primitive == "object_rule" {
							found = true
							require.Equal(t, role.Rules[0].Fingerprint(), item.Provenance.AuthoredRuleFP)
						}
					}
					require.Equal(t, scope.Type == "account", found, "actual compiler использует тот же scoped producer")
				}
				previous = projection
			}
		})
	}
	// Конкретное правило не получает новый глагол от соседнего wildcard.
	concrete := domain.Role{Rules: domain.Rules{{Module: "vpc", Resources: []string{"livegadget"}, Verbs: []string{"get"}}}}
	projection, err := withVerb.Projection(concrete)
	require.NoError(t, err)
	require.Equal(t, []domain.RoleVerb{{ObjectType: added, Verb: "get"}}, projection.Verbs)
	require.False(t, hasObligation(withVerb.Compile(binding(concrete.Rules...)), "wildcard_type_producer"))
}
