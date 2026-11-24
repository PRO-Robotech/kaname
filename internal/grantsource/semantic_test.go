// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantsource

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	"github.com/stretchr/testify/require"
)

func semanticSourceBundle(t *testing.T, extra bool) *granteffect.Bundle {
	t.Helper()
	rows := catalog.Halves{Live: catalog.Rows{Modules: []string{"iam"}, Resources: []catalog.ResourceRow{
		{Module: "iam", Resource: "account", ObjectType: "account"},
		{Module: "iam", Resource: "role", ObjectType: "iam_role"},
		{Module: "iam", Resource: "accessBinding", ObjectType: "iam_access_binding"},
		{Module: "iam", Resource: "serviceAccount", ObjectType: "iam_service_account"},
	}, Verbs: []catalog.VerbRow{
		{Module: "iam", Resource: "account", Verb: "get", PerObject: true},
		{Module: "iam", Resource: "role", Verb: "get", PerObject: true},
		{Module: "iam", Resource: "role", Verb: "bind"},
		{Module: "iam", Resource: "accessBinding", Verb: "create"},
		{Module: "iam", Resource: "serviceAccount", Verb: "get", PerObject: true},
	}}}
	if extra {
		rows.Live.Verbs = append(rows.Live.Verbs, catalog.VerbRow{Module: "iam", Resource: "account", Verb: "update", PerObject: true})
	}
	b, err := granteffect.NewBundle(context.Background(), authzmodel.DSL, rows, granteffect.ProjectorVersion)
	require.NoError(t, err)
	return b
}

type semanticSourceRoles struct {
	role.ReaderIface
	values map[domain.RoleID]domain.Role
}

func (r semanticSourceRoles) Get(_ context.Context, id domain.RoleID) (domain.Role, error) {
	v, ok := r.values[id]
	if !ok {
		return domain.Role{}, errors.New("fixture role absent")
	}
	return v, nil
}

type semanticSourceWriter struct {
	effectWriter
	bundle     *granteffect.Bundle
	bundleRead func() *granteffect.Bundle
	roleValues map[domain.RoleID]domain.Role
	direct     func(kaname.CanonicalSourceFilter) ([]kaname.CanonicalDirectSource, string, error)
	creators   func(kaname.CanonicalSourceFilter) ([]kaname.CanonicalCreatorSource, string, error)
}

func (w *semanticSourceWriter) SemanticBundle() *granteffect.Bundle {
	if w.bundleRead != nil {
		return w.bundleRead()
	}
	return w.bundle
}
func (w *semanticSourceWriter) SemanticRelationChecker() kaname.RelationChecker {
	panic("normalizer не должен выполнять D3 native gate")
}
func (w *semanticSourceWriter) Roles() role.ReaderIface {
	if w.roleValues != nil {
		return semanticSourceRoles{values: w.roleValues}
	}
	return w.effectWriter.Roles()
}
func (w *semanticSourceWriter) CanonicalDirectSources(_ context.Context, f kaname.CanonicalSourceFilter) ([]kaname.CanonicalDirectSource, string, error) {
	if w.direct == nil {
		return nil, "", nil
	}
	return w.direct(f)
}
func (w *semanticSourceWriter) CanonicalCreatorSources(_ context.Context, f kaname.CanonicalSourceFilter) ([]kaname.CanonicalCreatorSource, string, error) {
	if w.creators == nil {
		return nil, "", nil
	}
	return w.creators(f)
}
func semanticSourceFixture(t *testing.T, bundle *granteffect.Bundle) (*semanticSourceWriter, domain.AccessBinding) {
	t.Helper()
	base, b := effectFixture(t, sourceActor, []domain.Subject{sourceActor}, domain.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{"osetr"}})
	base.groups.list = func(group.ListFilter) ([]domain.Group, string, error) { return nil, "", nil }
	base.versions[b.ID] = 1
	return &semanticSourceWriter{effectWriter: base, bundle: bundle}, b
}
func semanticWantMeta(b *granteffect.Bundle, roleID string) granteffect.Set {
	return b.Compile(granteffect.Binding{SourceID: "proposal", Role: domain.Role{ID: "proposal-role", Rules: domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{roleID}}}}, Scope: domain.ScopeAnchor{Type: "account", ID: "acc-a"}, Recipient: sourceActor, Subjects: []domain.Subject{sourceActor}, CapabilityVersion: 1})
}
func semanticObligationCodes(s granteffect.Set) []string {
	out := []string{}
	for _, o := range s.Obligations() {
		out = append(out, o.Code)
	}
	return out
}
func requireSemanticZero(t *testing.T, out ActorEffects) {
	t.Helper()
	require.Equal(t, ActorEffects{}, out)
}

func TestSemanticActorLastPagesGroupIdentityAndActualCoverage(t *testing.T) {
	b := semanticSourceBundle(t, false)
	w, first := semanticSourceFixture(t, b)
	second := first
	second.ID = "group-binding"
	second.RoleID = "group-role"
	second.SubjectType = effectGroup.Type
	second.SubjectID = effectGroup.ID
	w.versions[second.ID] = 1
	other := domain.Subject{Type: domain.SubjectTypeUser, ID: "other"}
	w.bindings.subjects[second.ID] = []domain.Subject{effectGroup, other}
	secondRole := domain.Role{ID: second.RoleID, Rules: domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{"treska"}}}}
	w.roleValues = map[domain.RoleID]domain.Role{first.RoleID: w.role, second.RoleID: secondRole}
	pages := map[string]int{}
	w.groups.list = func(f group.ListFilter) ([]domain.Group, string, error) {
		require.Equal(t, sourceActor, *f.Member)
		pages["groups"]++
		if f.PageToken == "" {
			return nil, "last", nil
		}
		return []domain.Group{{ID: domain.GroupID(effectGroup.ID)}}, "", nil
	}
	w.bindings.list = func(s domain.Subject, f access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
		pages[string(s.Type)+":"+string(s.ID)]++
		if f.PageToken == "" {
			return nil, "last", nil
		}
		switch s {
		case sourceActor:
			return []domain.AccessBinding{first}, "", nil
		case effectGroup:
			return []domain.AccessBinding{second}, "", nil
		default:
			t.Fatal("чужой recipient")
			return nil, "", nil
		}
	}
	w.direct = func(f kaname.CanonicalSourceFilter) ([]kaname.CanonicalDirectSource, string, error) {
		require.Equal(t, sourceActor, f.Actor)
		pages["direct"]++
		if f.After == "" {
			return nil, "last", nil
		}
		return []kaname.CanonicalDirectSource{{SourceKind: kaname.CanonicalUserSelf, SourceID: string(sourceActor.ID), ObjectType: "iam_user", ObjectID: string(sourceActor.ID), Relation: "subject", Recipient: sourceActor}}, "", nil
	}
	w.creators = func(f kaname.CanonicalSourceFilter) ([]kaname.CanonicalCreatorSource, string, error) {
		require.Equal(t, sourceActor, f.Actor)
		pages["creators"]++
		if f.After == "" {
			return nil, "last", nil
		}
		return []kaname.CanonicalCreatorSource{{SourceID: "created-sa", AccountID: "acc-a", ObjectType: "iam_service_account", ObjectID: "created-sa", Creator: sourceActor}}, "", nil
	}
	got, err := CollectSemanticActor(context.Background(), w, sourceActor)
	require.NoError(t, err)
	require.Len(t, got.Bindings, 2)
	require.Len(t, got.Structural.Direct, 1)
	require.Len(t, got.Structural.Creators, 1)
	require.Equal(t, b.Identity(), got.Identity)
	require.Equal(t, b.Identity(), got.Component.Identity())
	require.Equal(t, w.at, got.DecisionAt)
	for _, n := range pages {
		require.Equal(t, 2, n)
	}
	require.Equal(t, effectGroup, got.Bindings[1].Source.Recipient)
	require.Equal(t, []domain.Subject{effectGroup, other}, got.Bindings[1].Source.Binding.Subjects)
	require.Equal(t, sourceActor, got.Structural.Creators[0].Creator)
	firstSet, secondSet := got.Bindings[0].Effects, got.Bindings[1].Effects
	require.True(t, firstSet.Complete())
	require.True(t, secondSet.Complete())
	require.Equal(t, grantcoverage.Proved, granteffect.Prove(firstSet, semanticWantMeta(b, "osetr")).Status)
	require.Equal(t, grantcoverage.NotProved, granteffect.Prove(firstSet, semanticWantMeta(b, "treska")).Status)
	require.Equal(t, grantcoverage.Proved, granteffect.Prove(granteffect.Union(firstSet, secondSet), semanticWantMeta(b, "treska")).Status)
	sourceIDs := map[string]bool{}
	for _, e := range got.Component.Effects() {
		sourceIDs[e.Provenance.SourceID] = true
	}
	require.True(t, sourceIDs[string(first.ID)])
	require.True(t, sourceIDs[string(second.ID)])
	require.True(t, sourceIDs["user_self:"+string(sourceActor.ID)])
	require.False(t, got.Component.Complete())
	require.Equal(t, grantcoverage.NotProved, granteffect.Prove(got.Component, semanticWantMeta(b, "osetr")).Status)
	for _, code := range []string{"registration_publication_source", "creator_selector_evidence", "authority_writer_protocol", "role_projection_checkpoint"} {
		require.Contains(t, semanticObligationCodes(got.Component), code)
	}
}

func TestSemanticActorRejectsInvalidInputsCancellationAndChangedBundle(t *testing.T) {
	b := semanticSourceBundle(t, false)
	other := semanticSourceBundle(t, true)
	var typedNil *semanticSourceWriter
	for _, w := range []kaname.SemanticAuthorityWriter{nil, typedNil} {
		out, err := CollectSemanticActor(context.Background(), w, sourceActor)
		require.Error(t, err)
		requireSemanticZero(t, out)
	}
	for _, invalid := range []*granteffect.Bundle{nil, {}} {
		w, _ := semanticSourceFixture(t, invalid)
		out, err := CollectSemanticActor(context.Background(), w, sourceActor)
		require.ErrorIs(t, err, granteffect.ErrInvalidBundle)
		requireSemanticZero(t, out)
	}
	for _, actor := range []domain.Subject{{}, {Type: domain.SubjectTypeUser, ID: "*"}, effectGroup, {Type: domain.SubjectTypeServiceAccount, ID: sourceActor.ID}} {
		w, carrier := semanticSourceFixture(t, b)
		w.bindings.list = func(domain.Subject, access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
			return []domain.AccessBinding{carrier}, "", nil
		}
		out, err := CollectSemanticActor(context.Background(), w, actor)
		require.Error(t, err)
		requireSemanticZero(t, out)
	}
	for _, late := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		w, _ := semanticSourceFixture(t, b)
		if late {
			w.creators = func(kaname.CanonicalSourceFilter) ([]kaname.CanonicalCreatorSource, string, error) {
				cancel()
				return nil, "", nil
			}
		} else {
			cancel()
		}
		out, err := CollectSemanticActor(ctx, w, sourceActor)
		cancel()
		require.ErrorIs(t, err, context.Canceled)
		requireSemanticZero(t, out)
	}
	w, _ := semanticSourceFixture(t, b)
	reads := 0
	w.bundleRead = func() *granteffect.Bundle {
		reads++
		if reads == 1 {
			return b
		}
		return other
	}
	out, err := CollectSemanticActor(context.Background(), w, sourceActor)
	require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable)
	requireSemanticZero(t, out)
	w, _ = semanticSourceFixture(t, b)
	one, err := CollectSemanticActor(context.Background(), w, sourceActor)
	require.NoError(t, err)
	w.bundle = other
	two, err := CollectSemanticActor(context.Background(), w, sourceActor)
	require.NoError(t, err)
	require.NotEqual(t, one.Identity, two.Identity)
	require.Equal(t, grantcoverage.ReasonIdentity, granteffect.Prove(one.Bindings[0].Effects, two.Bindings[0].Effects).Reason)
	w.at = time.Time{}
	out, err = CollectSemanticActor(context.Background(), w, sourceActor)
	require.Error(t, err)
	requireSemanticZero(t, out)
}

func TestSemanticActorExpiryIncompleteAndLateErrorRemainClosed(t *testing.T) {
	b := semanticSourceBundle(t, false)
	for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
		w, carrier := semanticSourceFixture(t, b)
		until := w.at.Add(offset)
		carrier.ExpiresAt = &until
		w.bindings.list = func(domain.Subject, access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
			return []domain.AccessBinding{carrier}, "", nil
		}
		out, err := CollectSemanticActor(context.Background(), w, sourceActor)
		require.NoError(t, err)
		if offset > 0 {
			require.Len(t, out.Bindings, 1)
		} else {
			require.Empty(t, out.Bindings)
			require.Empty(t, out.Component.Effects())
		}
		require.False(t, out.Component.Complete())
	}
	w, _ := semanticSourceFixture(t, b)
	w.role.Rules = domain.Rules{{Module: "missing", Resources: []string{"thing"}, Verbs: []string{"get"}}}
	out, err := CollectSemanticActor(context.Background(), w, sourceActor)
	require.NoError(t, err)
	require.Len(t, out.Bindings, 1)
	require.False(t, out.Bindings[0].Effects.Complete())
	require.Contains(t, semanticObligationCodes(out.Component), "input")
	for _, creators := range []bool{false, true} {
		w, _ = semanticSourceFixture(t, b)
		bad := errors.New("last source page failed")
		if creators {
			w.creators = func(kaname.CanonicalSourceFilter) ([]kaname.CanonicalCreatorSource, string, error) {
				return nil, "", bad
			}
		} else {
			w.direct = func(f kaname.CanonicalSourceFilter) ([]kaname.CanonicalDirectSource, string, error) {
				if f.After == "" {
					return nil, "last", nil
				}
				return nil, "", bad
			}
		}
		out, err = CollectSemanticActor(context.Background(), w, sourceActor)
		require.ErrorIs(t, err, bad)
		requireSemanticZero(t, out)
	}
	w, _ = semanticSourceFixture(t, b)
	w.direct = func(kaname.CanonicalSourceFilter) ([]kaname.CanonicalDirectSource, string, error) {
		return []kaname.CanonicalDirectSource{{SourceKind: kaname.CanonicalClusterAdmin, SourceID: "grant", ObjectType: "cluster", ObjectID: domain.ClusterSingletonID, Relation: "system_admin", Recipient: sourceActor, ExpiresAt: &w.at}}, "", nil
	}
	out, err = CollectSemanticActor(context.Background(), w, sourceActor)
	require.ErrorIs(t, err, kaname.ErrCanonicalSourceInvalid)
	requireSemanticZero(t, out)
	// Наличие creator evidence без грантов никогда не создаёт прямого эффекта.
	w, _ = semanticSourceFixture(t, b)
	w.bindings.list = func(domain.Subject, access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
		return nil, "", nil
	}
	w.creators = func(kaname.CanonicalSourceFilter) ([]kaname.CanonicalCreatorSource, string, error) {
		return []kaname.CanonicalCreatorSource{{SourceID: "sa-created", ObjectID: "sa-created", ObjectType: "iam_service_account", AccountID: "acc-a", Creator: sourceActor}}, "", nil
	}
	out, err = CollectSemanticActor(context.Background(), w, sourceActor)
	require.NoError(t, err)
	require.Len(t, out.Structural.Creators, 1)
	require.Empty(t, out.Component.Effects())
	require.False(t, out.Component.Complete())
}

func TestSemanticActorSharesPageRowAndEffectBudgets(t *testing.T) {
	bundle := semanticSourceBundle(t, false)
	t.Run("pages", func(t *testing.T) {
		w, _ := semanticSourceFixture(t, bundle)
		calls := 0
		direct := 0
		creators := 0
		w.groups.list = func(group.ListFilter) ([]domain.Group, string, error) {
			calls++
			if calls < maxBindingSourcePages-2 {
				return nil, strconv.Itoa(calls), nil
			}
			return nil, "", nil
		}
		w.bindings.list = func(domain.Subject, access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
			return nil, "", nil
		}
		w.direct = func(kaname.CanonicalSourceFilter) ([]kaname.CanonicalDirectSource, string, error) {
			direct++
			return nil, "", nil
		}
		w.creators = func(kaname.CanonicalSourceFilter) ([]kaname.CanonicalCreatorSource, string, error) {
			creators++
			return nil, "", nil
		}
		out, err := CollectSemanticActor(context.Background(), w, sourceActor)
		require.ErrorIs(t, err, ErrStructuralSourceLimit)
		requireSemanticZero(t, out)
		require.Equal(t, 1, direct)
		require.Zero(t, creators)
	})
	t.Run("rows", func(t *testing.T) {
		w, _ := semanticSourceFixture(t, bundle)
		groups := make([]domain.Group, maxBindingSourceRows)
		for i := range groups {
			groups[i].ID = "same-group"
		}
		w.groups.list = func(group.ListFilter) ([]domain.Group, string, error) { return groups, "", nil }
		w.bindings.list = func(domain.Subject, access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
			return nil, "", nil
		}
		w.direct = func(kaname.CanonicalSourceFilter) ([]kaname.CanonicalDirectSource, string, error) {
			return []kaname.CanonicalDirectSource{{SourceKind: kaname.CanonicalUserSelf, SourceID: string(sourceActor.ID), ObjectType: "iam_user", ObjectID: string(sourceActor.ID), Relation: "subject", Recipient: sourceActor}}, "", nil
		}
		out, err := CollectSemanticActor(context.Background(), w, sourceActor)
		require.ErrorIs(t, err, ErrStructuralSourceLimit)
		requireSemanticZero(t, out)
	})
	t.Run("metadata-and-role-rows", func(t *testing.T) {
		w, carrier := semanticSourceFixture(t, bundle)
		groups := make([]domain.Group, maxBindingSourceRows-4)
		for i := range groups {
			groups[i].ID = "same-group"
		}
		w.groups.list = func(group.ListFilter) ([]domain.Group, string, error) { return groups, "", nil }
		w.bindings.list = func(s domain.Subject, _ access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
			if s == sourceActor {
				return []domain.AccessBinding{carrier}, "", nil
			}
			return nil, "", nil
		}
		w.bindings.subjects[carrier.ID] = []domain.Subject{sourceActor, {Type: domain.SubjectTypeUser, ID: "other"}}
		// 99996 group + 1 binding + 2 subjects + 1 version исчерпывают строки;
		// чтение роли обязано отказать, а не получить отдельный бесплатный бюджет.
		out, err := CollectSemanticActor(context.Background(), w, sourceActor)
		require.ErrorIs(t, err, ErrBindingSourceLimit)
		requireSemanticZero(t, out)
	})
	t.Run("union", func(t *testing.T) {
		w, carrier := semanticSourceFixture(t, bundle)
		// Пустая legacy роль даёт пустые Sets с identity. Каждая занимает один
		// слот UnionBuilder; последний direct источник обязан разделять их лимит.
		w.role.Rules = nil
		bs := make([]domain.AccessBinding, granteffect.MaxEffects)
		for i := range bs {
			bs[i] = carrier
			bs[i].ID = domain.AccessBindingID(fmt.Sprintf("limit-%d", i))
			w.versions[bs[i].ID] = 0
			w.bindings.subjects[bs[i].ID] = []domain.Subject{sourceActor}
		}
		w.bindings.list = func(_ domain.Subject, f access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
			start := 0
			if f.PageToken != "" {
				var e error
				start, e = strconv.Atoi(f.PageToken)
				require.NoError(t, e)
			}
			end := min(start+bindingPageSize, len(bs))
			next := ""
			if end < len(bs) {
				next = strconv.Itoa(end)
			}
			return bs[start:end], next, nil
		}
		w.direct = func(kaname.CanonicalSourceFilter) ([]kaname.CanonicalDirectSource, string, error) {
			return []kaname.CanonicalDirectSource{{SourceKind: kaname.CanonicalUserSelf, SourceID: string(sourceActor.ID), ObjectType: "iam_user", ObjectID: string(sourceActor.ID), Relation: "subject", Recipient: sourceActor}}, "", nil
		}
		out, err := CollectSemanticActor(context.Background(), w, sourceActor)
		require.ErrorIs(t, err, granteffect.ErrUnionLimit)
		require.ErrorIs(t, err, ErrStructuralSourceLimit)
		requireSemanticZero(t, out)
	})
}
