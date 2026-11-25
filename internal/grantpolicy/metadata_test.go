// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantpolicy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

type metadataPolicyWriter struct {
	kaname.SemanticSourceReader
	bundle *granteffect.Bundle
	at     time.Time
	allow  map[string]bool
	admit  error
}

func (w metadataPolicyWriter) SemanticBundle() *granteffect.Bundle { return w.bundle }
func (w metadataPolicyWriter) AuthorityFence() kaname.AuthorityFence {
	return populationFence{at: w.at}
}
func (w metadataPolicyWriter) SemanticRelationChecker() kaname.RelationChecker { return w }
func (w metadataPolicyWriter) Check(_ context.Context, _, relation, object string) (bool, error) {
	return w.allow[relation+" "+object], nil
}
func (w metadataPolicyWriter) AdmitSourceActor(context.Context, domain.Subject) (kaname.SourceReadCost, error) {
	return kaname.SourceReadCost{}, w.admit
}

func metadataPolicyBundle(t *testing.T) *granteffect.Bundle {
	t.Helper()
	halves := catalog.Halves{Live: catalog.Rows{
		Modules: []string{"iam"},
		Resources: []catalog.ResourceRow{
			{Module: "iam", Resource: "account", ObjectType: "account"},
			{Module: "iam", Resource: "accessBinding", ObjectType: "iam_access_binding"},
			{Module: "iam", Resource: "role", ObjectType: "iam_role"},
		},
		Verbs: []catalog.VerbRow{
			{Module: "iam", Resource: "account", Verb: "get", PerObject: true},
			{Module: "iam", Resource: "account", Verb: "update", PerObject: true},
			{Module: "iam", Resource: "accessBinding", Verb: "create"},
			{Module: "iam", Resource: "role", Verb: "bind"},
		},
	}}
	bundle, err := granteffect.NewBundle(context.Background(), authzmodel.DSL, halves, granteffect.ProjectorVersion)
	require.NoError(t, err)
	return bundle
}

func metadataPolicyBinding(source string, s domain.Subject, labels map[string]string) granteffect.Binding {
	return granteffect.Binding{
		SourceID: source,
		Role: domain.Role{ID: "rol_read", Rules: domain.Rules{{
			Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}, MatchLabels: labels,
		}}},
		Scope:             domain.ScopeAnchor{Type: "cluster", ID: domain.ClusterSingletonID},
		Target:            domain.AccessTarget{AllInScope: true},
		Recipient:         s,
		Subjects:          []domain.Subject{s},
		CapabilityVersion: 1,
	}
}

func metadataPolicyImages() (granteffect.MetadataObject, granteffect.MetadataObject) {
	return granteffect.MetadataObject{Type: "account", ID: "acc_a", Labels: domain.Labels{"env": "old"}},
		granteffect.MetadataObject{Type: "account", ID: "acc_a", Labels: domain.Labels{"env": "new"}}
}

func TestMetadataGrantOldCoverageIsPerRecipientAndTime(t *testing.T) {
	ctx := context.Background()
	bundle := metadataPolicyBundle(t)
	decision := time.Now().UTC()
	earlier := decision.Add(time.Hour)
	later := decision.Add(2 * time.Hour)
	past := decision.Add(-time.Hour)
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_actor"}
	target := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_target"}
	other := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_other"}
	old, next := metadataPolicyImages()
	// Если OLD не покрывает новую выдачу, этот писатель останавливает путь
	// на чтении полномочий актёра. Так проверяем разницу между доказанным
	// прежним доступом и необходимостью отдельной проверки права выдавать.
	needsGrant := errors.New("требуется проверка права выдавать")
	w := metadataPolicyWriter{bundle: bundle, at: decision, admit: needsGrant}
	for _, row := range []struct {
		name              string
		priorRecipient    domain.Subject
		priorAt, wantedAt *time.Time
		priorPending      bool
		wantedPending     bool
		covered           bool
	}{
		{name: "same-recipient", priorRecipient: target, covered: true},
		{name: "different-recipient", priorRecipient: other},
		{name: "expires-first", priorRecipient: target, priorAt: &earlier, wantedAt: &later},
		{name: "coverage-outlasts-wanted", priorRecipient: target, priorAt: &later, wantedAt: &earlier, covered: true},
		{name: "already-expired", priorRecipient: target, priorAt: &past, wantedAt: &earlier},
		{name: "foreign-pending", priorRecipient: target, priorPending: true},
		{name: "both-pending", priorRecipient: target, priorPending: true, wantedPending: true},
		{name: "active-covers-pending", priorRecipient: target, wantedPending: true, covered: true},
	} {
		t.Run(row.name, func(t *testing.T) {
			prior := MetadataBinding{Binding: metadataPolicyBinding("prior", row.priorRecipient, nil), Pending: row.priorPending, ExpiresAt: row.priorAt}
			wanted := MetadataBinding{Binding: metadataPolicyBinding("wanted", target, map[string]string{"env": "new"}), Changes: true, Pending: row.wantedPending, ExpiresAt: row.wantedAt}
			err := RequireMetadataGrant(ctx, w, actor, old, next, []MetadataBinding{prior, wanted})
			if row.covered {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, needsGrant)
			}
		})
	}
	t.Run("same-pending-carrier", func(t *testing.T) {
		wanted := metadataPolicyBinding("wanted", target, map[string]string{"env": "new"})
		wanted.Role.Rules = append(wanted.Role.Rules, domain.Rule{
			Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"},
		})
		require.NoError(t, RequireMetadataGrant(ctx, w, actor, old, next, []MetadataBinding{
			{Binding: wanted, Changes: true, Pending: true},
		}))
	})
}

func TestMetadataGrantExpansionNeedsCurrentGrantCapability(t *testing.T) {
	ctx := context.Background()
	bundle := metadataPolicyBundle(t)
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_actor"}
	target := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_target"}
	old, next := metadataPolicyImages()
	wanted := metadataPolicyBinding("wanted", target, map[string]string{"env": "new"})
	delta := bundle.CompileMetadataDelta(wanted, old, next)
	require.True(t, delta.Before.Complete(), "%+v", delta.Before.Obligations())
	require.True(t, delta.After.Complete(), "%+v", delta.After.Obligations())
	ordinary := metadataPolicyBinding("actor-use", actor, nil)
	create := metadataPolicyBinding("actor-create", actor, nil)
	create.Role.Rules = domain.Rules{{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}}}
	bind := metadataPolicyBinding("actor-bind", actor, nil)
	bind.Role.Rules = domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{string(wanted.Role.ID)}}}
	useEffects, createEffects, bindEffects := bundle.Compile(ordinary), bundle.Compile(create), bundle.Compile(bind)
	for _, set := range []granteffect.Set{useEffects, createEffects, bindEffects} {
		require.True(t, set.Complete(), "%+v", set.Obligations())
	}
	createRef, err := grantcapability.Encode(grantcapability.Coordinate{Kind: domain.GrantCapabilityCreateBinding, Anchor: wanted.Scope})
	require.NoError(t, err)
	bindRef, err := grantcapability.Encode(grantcapability.Coordinate{Kind: domain.GrantCapabilityBindRole, Anchor: wanted.Scope, RoleID: wanted.Role.ID})
	require.NoError(t, err)
	createQuestion := createRef.Relation + " " + createRef.Object()
	bindQuestion := bindRef.Relation + " " + bindRef.Object()
	for _, row := range []struct {
		name    string
		effects granteffect.Set
		native  map[string]bool
		ok      bool
		stale   bool
	}{
		{name: "use-without-grant-capability", effects: useEffects, native: map[string]bool{createQuestion: true}},
		{name: "expired-or-revoked-create", effects: granteffect.Union(useEffects, createEffects), native: nil},
		{name: "create-with-ordinary-coverage", effects: granteffect.Union(useEffects, createEffects), native: map[string]bool{createQuestion: true}, ok: true},
		{name: "live-explicit-bind-of-this-role", effects: granteffect.Union(createEffects, bindEffects), native: map[string]bool{createQuestion: true, bindQuestion: true}, ok: true},
		{name: "native-bind-without-source", effects: createEffects, native: map[string]bool{createQuestion: true, bindQuestion: true}},
		{name: "bound-source-without-current-native-bind", effects: granteffect.Union(createEffects, bindEffects), native: map[string]bool{createQuestion: true}},
		{name: "same-capabilities-from-stale-decision", effects: granteffect.Union(createEffects, bindEffects), native: map[string]bool{createQuestion: true, bindQuestion: true}, stale: true},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := metadataPolicyWriter{bundle: bundle, at: time.Now().UTC(), allow: row.native}
			proof := WitnessedLowerBound{bundle: bundle, at: w.at, effects: row.effects}
			proof.census.Actor, proof.census.Identity = actor, bundle.Identity()
			if row.stale {
				proof.at = proof.at.Add(-time.Nanosecond)
			}
			err := requireMetadataExpansion(ctx, w, proof, granteffect.NewProofBudget(), metadataEffect{
				carrier: MetadataBinding{Binding: wanted, Changes: true},
				delta:   delta,
			}, delta.Before)
			if row.ok {
				require.NoError(t, err)
			} else if row.stale {
				require.ErrorIs(t, err, iamerr.ErrUnavailable)
			} else {
				require.ErrorIs(t, err, iamerr.ErrPermissionDenied)
			}
		})
	}
}
