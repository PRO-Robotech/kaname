// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantsource

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/stretchr/testify/require"
)

type provenanceWriter struct {
	*semanticSourceWriter
	admitErr       error
	page           func(kaname.CanonicalSourceFilter) (kaname.ProducerSourcePage, string, error)
	checkpoint     granteffect.ProjectionCheckpoint
	checkpointErr  error
	checkpointCost *kaname.SourceReadCost
}

func (w *provenanceWriter) AdmitSourceActor(context.Context, domain.Subject) (kaname.SourceReadCost, error) {
	return kaname.SourceReadCost{Reads: 1}, w.admitErr
}
func (w *provenanceWriter) ProducerSources(_ context.Context, f kaname.CanonicalSourceFilter) (kaname.ProducerSourcePage, string, error) {
	return w.page(f)
}
func (w *provenanceWriter) RoleProjectionCheckpoint(context.Context, domain.RoleID) (granteffect.ProjectionCheckpoint, kaname.SourceReadCost, error) {
	cost := kaname.SourceReadCost{Reads: 2, Rows: 1}
	if w.checkpointCost != nil {
		cost = *w.checkpointCost
	}
	return w.checkpoint, cost, w.checkpointErr
}
func provenanceFixture(t *testing.T) *provenanceWriter {
	b := semanticSourceBundle(t, false)
	w, _ := semanticSourceFixture(t, b)
	w.role.Rules = domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}}}
	p, err := b.Projection(w.role)
	require.NoError(t, err)
	return &provenanceWriter{semanticSourceWriter: w, checkpoint: p.Checkpoint, page: func(kaname.CanonicalSourceFilter) (kaname.ProducerSourcePage, string, error) {
		return kaname.ProducerSourcePage{Cost: kaname.SourceReadCost{Reads: 1}}, "", nil
	}}
}
func TestActorProvenanceLastPageCompilesSourceAndRetainsMissingLegacy(t *testing.T) {
	w := provenanceFixture(t)
	calls := 0
	source := kaname.ProducerSource{Identity: w.bundle.Identity(), Receipt: domain.ProducerReceipt{Kind: domain.RegistrationOwnerReceipt, Module: "iam", CatalogType: "iam.account", ObjectType: "account", ObjectID: "acc-a", Relation: "owner", Subject: sourceActor, Scopes: []domain.ContainerScope{{Registered: true, AccountID: "acc-a"}}}}
	w.page = func(f kaname.CanonicalSourceFilter) (kaname.ProducerSourcePage, string, error) {
		calls++
		if f.After == "" {
			return kaname.ProducerSourcePage{Cost: kaname.SourceReadCost{Reads: 1}}, "last", nil
		}
		return kaname.ProducerSourcePage{Sources: []kaname.ProducerSource{source}, Cost: kaname.SourceReadCost{Reads: 1, Rows: 1}}, "", nil
	}
	got, err := CollectSemanticActor(context.Background(), w, sourceActor)
	require.NoError(t, err)
	require.Equal(t, 2, calls)
	require.Len(t, got.Producers, 1)
	require.Len(t, got.RoleCheckpoints, 1)
	require.NotContains(t, semanticObligationCodes(got.Component), "role_projection_checkpoint")
	require.Contains(t, semanticObligationCodes(got.Component), "legacy_producer_receipt_census")
	require.Contains(t, semanticObligationCodes(got.Component), "authority_writer_protocol")
	require.False(t, got.Component.Complete())
	wantID := fmt.Sprintf("registration_owner:iam:account:acc-a:%s:%s", sourceActor.Type, sourceActor.ID)
	found := false
	for _, effect := range got.Component.Effects() {
		if effect.Provenance.SourceID == wantID {
			found = true
		}
	}
	require.True(t, found)
	source.Issue = "producer_version"
	got, err = CollectSemanticActor(context.Background(), w, sourceActor)
	require.NoError(t, err)
	require.Contains(t, semanticObligationCodes(got.Component), "producer_version")
	require.Len(t, got.Producers, 1)
	for _, effect := range got.Component.Effects() {
		require.NotEqual(t, wantID, effect.Provenance.SourceID)
	}
}
func TestActorProvenanceCheckpointAdmissionCancellationAndLimits(t *testing.T) {
	for _, mode := range []string{"admission", "changed-role", "unconfirmed", "foreign-source", "last-error", "budget"} {
		t.Run(mode, func(t *testing.T) {
			w := provenanceFixture(t)
			sentinel := errors.New("last page")
			switch mode {
			case "admission":
				w.admitErr = kaname.ErrSourceUnconfirmed
			case "changed-role":
				w.checkpoint.AuthoredID = "different"
			case "unconfirmed":
				w.checkpointErr = kaname.ErrSourceUnconfirmed
			case "foreign-source":
				w.page = func(kaname.CanonicalSourceFilter) (kaname.ProducerSourcePage, string, error) {
					return kaname.ProducerSourcePage{Sources: []kaname.ProducerSource{{}}, Cost: kaname.SourceReadCost{Reads: 1, Rows: 1}}, "", nil
				}
			case "last-error":
				w.page = func(f kaname.CanonicalSourceFilter) (kaname.ProducerSourcePage, string, error) {
					if f.After == "" {
						return kaname.ProducerSourcePage{Cost: kaname.SourceReadCost{Reads: 1}}, "last", nil
					}
					return kaname.ProducerSourcePage{}, "", sentinel
				}
			case "budget":
				w.page = func(kaname.CanonicalSourceFilter) (kaname.ProducerSourcePage, string, error) {
					return kaname.ProducerSourcePage{Cost: kaname.SourceReadCost{Reads: maxBindingSourcePages, Rows: 1}}, "", nil
				}
			}
			got, err := CollectSemanticActor(context.Background(), w, sourceActor)
			if mode == "changed-role" || mode == "unconfirmed" {
				require.NoError(t, err)
				require.Contains(t, semanticObligationCodes(got.Component), "role_projection_checkpoint")
				require.Empty(t, got.RoleCheckpoints)
				require.NotEmpty(t, got.Bindings)
				return
			}
			require.Error(t, err)
			requireSemanticZero(t, got)
		})
	}
	w := provenanceFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	w.page = func(kaname.CanonicalSourceFilter) (kaname.ProducerSourcePage, string, error) {
		cancel()
		return kaname.ProducerSourcePage{Cost: kaname.SourceReadCost{Reads: 1}}, "", nil
	}
	got, err := CollectSemanticActor(ctx, w, sourceActor)
	require.ErrorIs(t, err, context.Canceled)
	requireSemanticZero(t, got)
}

func TestActorProvenanceCreatorKeepsTypedRecipientAndEvidenceSeparate(t *testing.T) {
	w := provenanceFixture(t)
	actor := domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: sourceActor.ID}
	carrier := sourceBinding("creator-carrier")
	carrier.SubjectType = actor.Type
	carrier.SubjectID = actor.ID
	carrier.ResourceType = "account"
	carrier.ResourceID = "acc-a"
	w.bindings.subjects[carrier.ID] = []domain.Subject{actor}
	w.versions[carrier.ID] = 0
	w.bindings.list = func(s domain.Subject, _ access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
		if s == actor {
			return []domain.AccessBinding{carrier}, "", nil
		}
		return nil, "", nil
	}
	w.role.ID = carrier.RoleID
	w.role.Rules = domain.Rules{{Module: "iam", Resources: []string{"serviceAccount"}, Verbs: []string{"get"}, CreatedBySubject: true}}
	projection, err := w.bundle.Projection(w.role)
	require.NoError(t, err)
	w.checkpoint = projection.Checkpoint
	w.creators = func(kaname.CanonicalSourceFilter) ([]kaname.CanonicalCreatorSource, string, error) {
		return []kaname.CanonicalCreatorSource{{SourceID: "created", ObjectID: "created", ObjectType: "iam_service_account", AccountID: "acc-a", Creator: actor}}, "", nil
	}
	got, err := CollectSemanticActor(context.Background(), w, actor)
	require.NoError(t, err)
	require.Len(t, got.Bindings, 1)
	require.Len(t, got.Structural.Creators, 1)
	require.NotEmpty(t, got.Bindings[0].Effects.Effects())
	creatorFound := false
	for _, e := range got.Bindings[0].Effects.Effects() {
		for _, c := range e.Constraints {
			if c.Region.Creator.Kind == grantcoverage.ExactCreator {
				creatorFound = true
				require.Equal(t, actor, c.Region.Creator.Subject)
			}
		}
	}
	require.True(t, creatorFound)
	require.False(t, got.Component.Complete())
	// ID человека совпадает, тип не совпадает. Источник SA не переименовывается.
	w.creators = func(kaname.CanonicalSourceFilter) ([]kaname.CanonicalCreatorSource, string, error) {
		return []kaname.CanonicalCreatorSource{{SourceID: "created", ObjectID: "created", ObjectType: "iam_service_account", AccountID: "acc-a", Creator: sourceActor}}, "", nil
	}
	got, err = CollectSemanticActor(context.Background(), w, actor)
	require.ErrorIs(t, err, kaname.ErrCanonicalSourceInvalid)
	requireSemanticZero(t, got)
}

// kaname#1034: recoverable mismatch сохраняет ordinary эффекты, но не возвращает
// уже потраченные строки в общий бюджет. Граница определяется тем же collector.
func TestActorProvenanceUnconfirmedCheckpointChargesSharedBudget(t *testing.T) {
	measure := provenanceFixture(t)
	measure.checkpointErr = kaname.ErrSourceUnconfirmed
	var remaining int
	measure.page = func(kaname.CanonicalSourceFilter) (kaname.ProducerSourcePage, string, error) {
		return kaname.ProducerSourcePage{Cost: kaname.SourceReadCost{Reads: 1}}, "", nil
	}
	// Считаем прежние collectors без provenance отдельно тем же shared helper.
	budget := &sourceBudget{}
	builder := &granteffect.UnionBuilder{}
	_, err := collectAndCompileBindings(context.Background(), measure, measure.bundle, sourceActor, budget, builder)
	require.NoError(t, err)
	_, err = collectAndCompileStructuralSources(context.Background(), measure, measure.bundle, sourceActor, budget, builder)
	require.NoError(t, err)
	remaining = maxBindingSourceRows - budget.rows
	require.Positive(t, remaining)
	for _, extra := range []int{0, 1} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			w := provenanceFixture(t)
			w.checkpointErr = kaname.ErrSourceUnconfirmed
			w.checkpointCost = &kaname.SourceReadCost{Reads: 2, Rows: remaining + extra}
			got, err := CollectSemanticActor(context.Background(), w, sourceActor)
			if extra == 0 {
				require.NoError(t, err)
				require.NotEmpty(t, got.Bindings)
				require.Empty(t, got.RoleCheckpoints)
				require.Contains(t, semanticObligationCodes(got.Component), "role_projection_checkpoint")
				require.False(t, got.Component.Complete())
			} else {
				require.ErrorIs(t, err, ErrBindingSourceLimit)
				requireSemanticZero(t, got)
			}
		})
	}
}
