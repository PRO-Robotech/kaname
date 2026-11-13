// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	"github.com/stretchr/testify/require"
)

func bundleRows() catalog.Halves {
	return catalog.Halves{Live: catalog.Rows{
		Modules:   []string{"iam"},
		Resources: []catalog.ResourceRow{{Module: "iam", Resource: "account", ObjectType: "account"}},
		Verbs:     []catalog.VerbRow{{Module: "iam", Resource: "account", Verb: "get", PerObject: true}},
	}}
}
func bundleCanon(t *testing.T) *Bundle {
	t.Helper()
	b, err := NewBundle(context.Background(), authzmodel.DSL, bundleRows(), ProjectorVersion)
	require.NoError(t, err)
	return b
}

func TestSemanticBundleAdmitsCompositionAndRejectsParseOnly(t *testing.T) {
	// Настоящий загрузчик и compositor, как при старте. Новый тип не существует
	// в каноне и проверяет, что checker не подменяет закреплённые Plans на Shared.
	m, err := manifest.Load([]byte(`apiVersion: iam/v1
module: vpc
resources:
  - name: widget
    objectType: vpc_bundle_widget
    parents: [project]
    producer: derived
    verbs: [get, list, update, delete]
`))
	require.NoError(t, err)
	source, rep, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
	require.NoError(t, err)
	require.NotEqual(t, authzmodel.DSL, source)
	b, err := NewBundle(context.Background(), source, bundleRows(), ProjectorVersion, rep.KeyTerms...)
	require.NoError(t, err)
	plan, err := b.Plan("vpc_bundle_widget", "v_get")
	require.NoError(t, err)
	require.NotEmpty(t, plan.Atoms)
	require.Equal(t, source, b.ModelSource())
	require.Equal(t, digest([]byte(source)), b.Identity().ModelID)
	// Старая математическая фикстура разбирается, но не является композицией канона.
	_, err = authzmodel.New(modelFixture)
	require.NoError(t, err)
	bad, err := NewBundle(context.Background(), modelFixture, bundleRows(), ProjectorVersion)
	require.ErrorIs(t, err, ErrInvalidBundle)
	require.Nil(t, bad)
}

func TestSemanticBundleRejectsDefaultInvalidAndCancelledInputs(t *testing.T) {
	for _, tc := range []struct {
		name, source, version string
		rows                  catalog.Halves
	}{
		{"missing-model", "", ProjectorVersion, bundleRows()},
		{"default-version", authzmodel.DSL, "", bundleRows()},
		{"future-version", authzmodel.DSL, "granteffect/v3", bundleRows()},
		{"missing-catalog", authzmodel.DSL, ProjectorVersion, catalog.Halves{}},
		{"invalid-model", "model invalid", ProjectorVersion, bundleRows()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := NewBundle(context.Background(), tc.source, tc.rows, tc.version)
			require.Error(t, err)
			require.Nil(t, b)
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b, err := NewBundle(ctx, authzmodel.DSL, bundleRows(), ProjectorVersion)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, b)
	for _, empty := range []*Bundle{nil, {}} {
		require.ErrorIs(t, empty.Validate(), ErrInvalidBundle)
		require.False(t, empty.Compile(Binding{}).Complete())
		require.False(t, empty.CompileDirect(Direct{}).Complete())
		_, err = empty.Plan("account", "viewer")
		require.ErrorIs(t, err, ErrInvalidBundle)
		require.ErrorIs(t, empty.GrantCapabilityPlan("iam_grant_scope", "create_binding"), ErrInvalidBundle)
	}
}

func TestSemanticBundleRejectsOversizedBeforeCanonicalDeduplication(t *testing.T) {
	rows := bundleRows()
	// Канонизация схлопнула бы эти повторения в один законный модуль. Если
	// перенести бюджет после неё, отрицательный контроль станет успешным.
	rows.Live.Modules = make([]string, MaxInputBytes/6+1)
	for i := range rows.Live.Modules {
		rows.Live.Modules[i] = "iam"
	}
	b, err := NewBundle(context.Background(), authzmodel.DSL, rows, ProjectorVersion)
	require.ErrorIs(t, err, ErrInvalidBundle)
	require.Nil(t, b)
}

func TestSemanticBundleCopiesPlansCatalogAndSelectors(t *testing.T) {
	rows := bundleRows()
	b, err := NewBundle(context.Background(), authzmodel.DSL, rows, ProjectorVersion)
	require.NoError(t, err)
	id := b.Identity()
	raw := b.CanonicalCatalog()
	rows.Live.Resources[0].ObjectType = "changed"
	raw[0] = '!'
	require.Equal(t, id, b.Identity())
	require.True(t, json.Valid(b.CanonicalCatalog()))
	plan, err := b.Plan("account", "viewer")
	require.NoError(t, err)
	want, err := b.Plan("account", "viewer")
	require.NoError(t, err)
	require.NotEmpty(t, plan.Atoms)
	plan.Atoms[0].Relation = "changed"
	got, err := b.Plan("account", "viewer")
	require.NoError(t, err)
	require.Equal(t, want, got)
	conditioned, err := b.Plan("compute_instance", "ssh")
	require.NoError(t, err)
	original, err := b.Plan("compute_instance", "ssh")
	require.NoError(t, err)
	require.NotEmpty(t, conditioned.Conditioned)
	conditioned.Conditioned[0] = "changed"
	reread, err := b.Plan("compute_instance", "ssh")
	require.NoError(t, err)
	require.Equal(t, original, reread)
	rules := domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}, ResourceNames: []string{"acc-one"}}}
	scope := domain.ScopeAnchor{Type: "account", ID: "acc-root"}
	selectors, err := b.GrantSelectors(rules, domain.TenantPolicy(), scope)
	require.NoError(t, err)
	require.Len(t, selectors, 1)
	require.Equal(t, []string{"get"}, selectors[0].Grants["iam.account"])
	selectors[0].ResourceNames[0] = "changed"
	selectors[0].Grants["iam.account"][0] = "changed"
	require.Equal(t, "acc-one", rules[0].ResourceNames[0])
	again, err := b.GrantSelectors(rules, domain.TenantPolicy(), scope)
	require.NoError(t, err)
	require.Equal(t, "acc-one", again[0].ResourceNames[0])
	require.Equal(t, []string{"get"}, again[0].Grants["iam.account"])
	changed := bundleRows()
	changed.Live.Verbs[0].Verb = "update"
	other, err := NewBundle(context.Background(), authzmodel.DSL, changed, ProjectorVersion)
	require.NoError(t, err)
	require.NotEqual(t, id.CatalogID, other.Identity().CatalogID)
	otherSel, err := other.GrantSelectors(rules, domain.TenantPolicy(), scope)
	require.NoError(t, err)
	require.Empty(t, otherSel[0].Grants["iam.account"], "другие Facts не должны брать старое объявление get")
}

func TestSemanticBundleCompilerIdentityAndConcurrentIsolation(t *testing.T) {
	b := bundleCanon(t)
	direct := Direct{SourceID: "direct-one", ObjectType: "account", ObjectID: "acc-one", Relation: "admin", Recipient: domain.Subject{Type: domain.SubjectTypeUser, ID: "usr-one"}}
	set := b.CompileDirect(direct)
	require.Equal(t, b.Identity(), set.Identity())
	require.True(t, set.Complete(), "каноническая прямая выдача должна компилироваться: %v", set.Obligations())
	require.Equal(t, grantcoverage.Proved, Prove(set, set).Status)
	other := set
	other.identity.ProjectorVersion = "granteffect/v3"
	require.Equal(t, grantcoverage.ReasonIdentity, Prove(set, other).Reason)
	other.identity.ProjectorVersion = ""
	require.False(t, other.Complete())
	require.NotEqual(t, grantcoverage.Proved, Prove(other, other).Status)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				plan, err := b.Plan("account", "viewer")
				if err != nil || len(plan.Atoms) == 0 {
					t.Error("план канона потерян")
					return
				}
				plan.Atoms[0].Relation = strings.Repeat("x", j+1)
				next := b.CompileDirect(direct)
				if !reflect.DeepEqual(set.Effects(), next.Effects()) {
					t.Error("мутация копии изменила компилятор")
				}
			}
		}()
	}
	wg.Wait()
}
