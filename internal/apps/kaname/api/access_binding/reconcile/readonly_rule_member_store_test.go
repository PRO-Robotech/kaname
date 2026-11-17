// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	"github.com/stretchr/testify/require"
)

type readonlyRuleProviderProbe struct {
	ReconcileStore
	views int
	reads int
}

func (p *readonlyRuleProviderProbe) ReadOnlyRuleMemberStore() ReconcileStore {
	p.views++
	return &readonlyRuleViewProbe{ReconcileStore: p.ReconcileStore, owner: p}
}

type readonlyRuleViewProbe struct {
	ReconcileStore
	owner *readonlyRuleProviderProbe
}

func (v *readonlyRuleViewProbe) MatchSelector(ctx context.Context, types []string, labels map[string]string) ([]domain.MirrorObject, error) {
	v.owner.reads++
	return v.ReconcileStore.MatchSelector(ctx, types, labels)
}

// Общие maps здесь намеренны: расчёт не вправе менять входы или сохранять их
// в DesiredMember. Сравниваются весь порядок членов и все кортежи субъектов.
func TestReadOnlyRuleMemberViewPreservesOrderedMembersAndInputs(t *testing.T) {
	for _, scope := range []domain.ScopeAnchor{{Type: "project", ID: "p"}, {Type: "account", ID: "a"}, {Type: "cluster", ID: "c"}} {
		for _, targeted := range []bool{false, true} {
			t.Run(scope.Type+map[bool]string{false: "_all", true: "_named"}[targeted], func(t *testing.T) {
				labels := map[string]string{"env": "prod", "team": "core"}
				f := &fakeStore{scope: scope, active: true, subjects: []domain.Subject{{Type: "user", ID: "u"}, {Type: "service_account", ID: "sa"}},
					selectors: []domain.RuleSelector{
						{RuleFP: "first", Arm: domain.ArmLabels, ObjectTypes: []string{"compute.instance"}, MatchLabels: map[string]string{"env": "prod"}, Verbs: []string{"get", "update"}},
						{RuleFP: "second", Arm: domain.ArmLabels, ObjectTypes: []string{"compute.instance"}, MatchLabels: map[string]string{"team": "core"}, Verbs: []string{"get"}},
					}, mirror: map[string][]domain.MirrorObject{"compute.instance": {
						{ObjectType: "compute.instance", ObjectID: "one", ParentProjectID: "p", ParentAccountIDs: []string{"a"}, Labels: labels},
						{ObjectType: "compute.instance", ObjectID: "two", ParentProjectID: "other", ParentAccountIDs: []string{"other"}, Labels: labels},
					}}}
				if targeted {
					f.target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "compute.instance", ID: "one"}}}
				}
				ctx := context.Background()
				bs, _, err := f.LoadBinding(ctx, "binding")
				require.NoError(t, err)
				r := New(fakeRunner{s: f}, nil, catalogfixture.Source())
				expected, err := r.desiredRuleMembers(ctx, f, bs)
				require.NoError(t, err)
				require.NotEmpty(t, expected)
				provider := &readonlyRuleProviderProbe{ReconcileStore: f}
				actual, err := r.desiredRuleMembers(ctx, provider, bs)
				require.NoError(t, err)
				require.Equal(t, expected, actual)
				require.Equal(t, 1, provider.views)
				require.Equal(t, 2, provider.reads)
				require.Equal(t, map[string]string{"env": "prod", "team": "core"}, labels)
				again, err := r.desiredRuleMembers(ctx, provider, bs)
				require.NoError(t, err)
				require.Equal(t, expected, again)
				require.Equal(t, 2, provider.views)
			})
		}
	}
}

type readonlyOriginalFailureStore struct {
	ReconcileStore
	err          error
	labelReads   int
	creatorReads int
}

func (s *readonlyOriginalFailureStore) MatchSelector(context.Context, []string, map[string]string) ([]domain.MirrorObject, error) {
	s.labelReads++
	return nil, s.err
}
func (s *readonlyOriginalFailureStore) MatchCreatedByIAMDirect(context.Context, []string, domain.ScopeAnchor, []string) ([]domain.MirrorObject, error) {
	s.creatorReads++
	return nil, s.err
}

func TestReadOnlyRuleMemberViewKeepsRuleErrorsAndOriginalSpecialStores(t *testing.T) {
	ctx := context.Background()
	failure := errors.New("original selector failure")
	f := &fakeStore{scope: domain.ScopeAnchor{Type: "project", ID: "p"}, subjectType: "user", subjectID: "u", active: true}
	bs, _, err := f.LoadBinding(ctx, "binding")
	require.NoError(t, err)
	r := New(fakeRunner{s: f}, nil, catalogfixture.Source())
	ordinary := domain.RuleSelector{RuleFP: "ordinary", Arm: domain.ArmLabels, ObjectTypes: []string{"compute.instance"}, MatchLabels: map[string]string{"env": "prod"}, Verbs: []string{"get"}}
	bs.Selectors = []domain.RuleSelector{ordinary}
	original := &readonlyOriginalFailureStore{ReconcileStore: f, err: failure}
	_, want := r.desiredRuleMembers(ctx, original, bs)
	provider := &readonlyRuleProviderProbe{ReconcileStore: original}
	_, got := r.desiredRuleMembers(ctx, provider, bs)
	require.ErrorIs(t, got, failure)
	require.Equal(t, want.Error(), got.Error())
	require.Equal(t, 1, provider.reads)
	// Creator получает исходный store, а не view: его отдельная capability не теряется.
	creator := ordinary
	creator.RuleFP = "creator"
	creator.ObjectTypes = []string{"iam.serviceAccount"}
	creator.CreatedBySubject = true
	creator.Verbs = []string{"*"}
	bs.Selectors = []domain.RuleSelector{creator}
	bs.Subjects = []domain.Subject{{Type: domain.SubjectTypeServiceAccount, ID: "sa"}}
	provider.reads = 0
	_, got = r.desiredRuleMembers(ctx, provider, bs)
	require.ErrorIs(t, got, failure)
	require.Equal(t, 1, original.creatorReads)
	require.Zero(t, provider.reads)
	// Nested owner selector также должен читать исходный store.
	nested := ordinary
	nested.RuleFP = "nested"
	nested.Container = &domain.ContainerSelector{OwnerFP: "owner", Type: "compute.instance", Arm: domain.ArmLabels, MatchLabels: map[string]string{"env": "prod"}}
	bs.Selectors = []domain.RuleSelector{nested}
	before := original.labelReads
	_, got = r.desiredRuleMembers(ctx, provider, bs)
	require.ErrorIs(t, got, failure)
	require.Equal(t, before+1, original.labelReads)
	require.Zero(t, provider.reads)
}
