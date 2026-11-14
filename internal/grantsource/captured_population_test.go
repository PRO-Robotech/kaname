// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package grantsource

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/stretchr/testify/require"
)

type capturedSourceWriter struct {
	*provenanceWriter
	record *capturedSourceRecord
}
type capturedSourceRecord struct {
	owner       *capturedSourceWriter
	at          time.Time
	invalid     bool
	validations int
}

func (p *capturedSourceRecord) Validate(w kaname.SemanticAuthorityWriter, actor domain.Subject, at time.Time) error {
	p.validations++
	if p.invalid || w != p.owner || actor != sourceActor || !p.at.Equal(at) {
		return kaname.ErrSourceUnconfirmed
	}
	return nil
}
func (w *capturedSourceWriter) CapturedProducerPopulation(context.Context, domain.Subject) (kaname.CapturedProducerPopulation, error) {
	return w.record, nil
}
func capturedSourceFixture(t *testing.T) *capturedSourceWriter {
	w := &capturedSourceWriter{provenanceWriter: provenanceFixture(t)}
	w.record = &capturedSourceRecord{owner: w, at: w.AuthorityFence().DecisionAt()}
	return w
}
func TestCapturedActorRetainsPositiveSourceWithoutClaimingCompletePopulation(t *testing.T) {
	w := capturedSourceFixture(t)
	source := kaname.ProducerSource{Identity: w.bundle.Identity(), Receipt: domain.ProducerReceipt{Kind: domain.RegistrationOwnerReceipt, Module: "iam", CatalogType: "iam.account", ObjectType: "account", ObjectID: "acc-a", Relation: "owner", Subject: sourceActor, Scopes: []domain.ContainerScope{{Registered: true, AccountID: "acc-a"}}}}
	w.page = func(kaname.CanonicalSourceFilter) (kaname.ProducerSourcePage, string, error) {
		return kaname.ProducerSourcePage{Sources: []kaname.ProducerSource{source}, Cost: kaname.SourceReadCost{Rows: 1, Reads: 1}}, "", nil
	}
	got, err := CollectSemanticActor(context.Background(), w, sourceActor)
	require.NoError(t, err)
	require.Same(t, w.record, got.ProducerPopulation)
	require.Len(t, got.Producers, 1)
	require.Contains(t, semanticObligationCodes(got.Component), "captured_producer_population")
	require.False(t, got.Component.Complete())
	require.NotEmpty(t, got.Component.Effects())
	require.Equal(t, 2, w.record.validations, "record checked before and after source census")
	// Неверная стоимость страницы отклоняется до повторной проверки токена.
	w.page = func(kaname.CanonicalSourceFilter) (kaname.ProducerSourcePage, string, error) {
		return kaname.ProducerSourcePage{}, "", nil
	}
	got, err = CollectSemanticActor(context.Background(), w, sourceActor)
	require.ErrorIs(t, err, kaname.ErrCanonicalSourceInvalid)
	requireSemanticZero(t, got)
	require.Equal(t, 3, w.record.validations)
	// Пустая, но корректно учтённая страница доходит до финальной проверки:
	// инвалидированный во время чтения токен не подтверждает даже пустой census.
	w.page = func(kaname.CanonicalSourceFilter) (kaname.ProducerSourcePage, string, error) {
		w.record.invalid = true
		return kaname.ProducerSourcePage{Cost: kaname.SourceReadCost{Reads: 1}}, "", nil
	}
	got, err = CollectSemanticActor(context.Background(), w, sourceActor)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	requireSemanticZero(t, got)
	require.Equal(t, 5, w.record.validations, "invalidated token reached the final validation")
}
func TestCapturedActorStillDropsExpiredCarrierAtFinalClock(t *testing.T) {
	w := capturedSourceFixture(t)
	b := sourceBinding("effect-binding")
	b.ResourceType = "account"
	b.ResourceID = "acc-a"
	at := w.AuthorityFence().DecisionAt()
	b.ExpiresAt = &at
	w.bindings.list = func(domain.Subject, ab.PageFilter) ([]domain.AccessBinding, string, error) {
		return []domain.AccessBinding{b}, "", nil
	}
	got, err := CollectSemanticActor(context.Background(), w, sourceActor)
	require.NoError(t, err)
	require.Empty(t, got.Bindings)
	require.Same(t, w.record, got.ProducerPopulation)
	require.False(t, got.Component.Complete())
}
