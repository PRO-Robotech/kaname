// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package internal_iam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
	"github.com/stretchr/testify/require"
)

type receiptProbe struct {
	sceneScopes
	saves       []domain.ProducerReceipt
	invalidated []string
	tx          service.Tx
	fail        error
}

func (s *receiptProbe) SaveProducerReceiptTx(_ context.Context, tx service.Tx, r domain.ProducerReceipt) error {
	s.tx = tx
	s.saves = append(s.saves, r)
	return s.fail
}
func (s *receiptProbe) InvalidateRegistrationReceiptsTx(_ context.Context, tx service.Tx, object string, _ time.Time, reason string) error {
	s.tx = tx
	s.invalidated = append(s.invalidated, object+"/"+reason)
	return s.fail
}
func TestProducerReceiptOwnerAppliedReplayAndTypedPair(t *testing.T) {
	ctx := context.Background()
	scopes := &receiptProbe{sceneScopes: unitScopes()}
	scopes.pointers = map[string][]string{"registry_registry:receipt": {"project:" + unitProject}}
	txb := &smTxBeginner{}
	uc := NewRegisterResourceUseCase(smEmitter{}, newVersionedMirror(), txb, deliveredRegistryTypes{}, &recordingPublisher{}, &recordingWithdrawal{}, noAudit{}, scopes).WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "registry"})
	at := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	call := func(subject string, v time.Time) {
		_, _, _, err := uc.emit(ctx, tupleIntent{subject: subject, relation: "owner", object: "registry_registry:receipt"}, service.ResourceMirrorRow{ObjectType: "registry_registry", ObjectID: "receipt", ParentProjectID: unitProject, ParentAccountID: unitAccount, ParentChain: []string{"project:" + unitProject, "account:" + unitAccount}, SourceVersion: v}, true)
		require.NoError(t, err)
	}
	call("user:same", at)
	require.Len(t, scopes.saves, 1)
	require.Same(t, txb.tx, scopes.tx)
	require.True(t, txb.tx.committed)
	call("service_account:same", at)
	call("service_account:same", at.Add(-time.Second))
	require.Len(t, scopes.saves, 1)
	call("service_account:same", at.Add(time.Second))
	require.Len(t, scopes.saves, 2)
	require.Equal(t, domain.SubjectTypeUser, scopes.saves[0].Subject.Type)
	require.Equal(t, domain.SubjectTypeServiceAccount, scopes.saves[1].Subject.Type)
	call("service_account:same", time.Time{})
	require.Len(t, scopes.saves, 3)
	require.True(t, scopes.saves[2].SourceVersion.IsZero())
	scopes.fail = errors.New("receipt failed")
	_, _, _, err := uc.emit(ctx, tupleIntent{subject: "user:other", relation: "owner", object: "registry_registry:receipt"}, service.ResourceMirrorRow{ObjectType: "registry_registry", ObjectID: "receipt", ParentProjectID: unitProject, ParentAccountID: unitAccount, ParentChain: []string{"project:" + unitProject, "account:" + unitAccount}, SourceVersion: at.Add(2 * time.Second)}, true)
	require.ErrorIs(t, err, scopes.fail)
	require.False(t, txb.tx.committed)
}

type receiptPublisher struct{ applied bool }

func (p receiptPublisher) ApplyTx(context.Context, service.Tx, string, string, bool, time.Time) (bool, error) {
	return p.applied, nil
}
func TestProducerReceiptPublicationOnlyAppliedCanonicalClass(t *testing.T) {
	for _, applied := range []bool{false, true} {
		scopes := &receiptProbe{sceneScopes: unitScopes()}
		scopes.containers["registry_repository:receipt"] = domain.ContainerScope{Registered: true, ProjectID: unitProject, AccountID: unitAccount}
		txb := &smTxBeginner{}
		uc := NewRegisterResourceUseCase(smEmitter{}, mirrorAdapter{}, txb, seededCatalogTypes{}, receiptPublisher{applied}, &recordingWithdrawal{}, noAudit{}, scopes).WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "registry"})
		err := uc.publish(context.Background(), tupleIntent{subject: "user:*", relation: "v_get", object: "registry_repository:receipt"}, true, time.Now())
		require.NoError(t, err)
		if !applied {
			require.Empty(t, scopes.saves)
			continue
		}
		require.Len(t, scopes.saves, 1)
		require.Same(t, txb.tx, scopes.tx)
		require.Equal(t, domain.Subject{Type: domain.SubjectTypeSystemClass, ID: "anonymous"}, scopes.saves[0].Subject)
		require.Equal(t, "registry", scopes.saves[0].Module)
	}
}

type receiptDropMirror struct {
	mirrorAdapter
	dropped bool
}

func (m receiptDropMirror) DropRegistrationTx(context.Context, service.Tx, string, string, string) (bool, time.Time, error) {
	return m.dropped, time.Now(), nil
}
func TestProducerReceiptDescendantInvalidatesOnlyAppliedDeletion(t *testing.T) {
	for _, dropped := range []bool{false, true} {
		scopes := &receiptProbe{sceneScopes: unitScopes()}
		uc := &RegisterResourceUseCase{mirror: receiptDropMirror{dropped: dropped}, scopes: scopes}
		_, err := uc.dropRegistrations(context.Background(), &smTx{}, []unregisteredDescendant{{catalogType: "registry.repository", RegisteredDescendant: service.RegisteredDescendant{ModelType: "registry_repository", ID: "child"}}})
		require.NoError(t, err)
		if dropped {
			require.Equal(t, []string{"registry_repository:child/withdrawn"}, scopes.invalidated)
		} else {
			require.Empty(t, scopes.invalidated)
		}
	}
}
