// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

func TestPreparedSemanticReadIntentKeepsExplicitActorAndQuestions(t *testing.T) {
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_reader"}
	intent := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityBinding, Bundle: nativeBoundaryBundle(t), Owners: []kaname.AuthorityOwnerRef{{Kind: "account", ID: "acc_a"}}, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceAccounts, Accounts: []domain.AccountID{"acc_a"}}}
	read := kaname.SemanticReadIntent{Actor: actor, Roles: []domain.RoleID{"role_a"}, Native: []kaname.SemanticNativeQuestion{{Relation: "admin", Object: "account:acc_a"}}}
	got, err := semanticReadRequest(intent, read)
	require.NoError(t, err)
	require.False(t, got.global)
	require.Equal(t, actor, got.actor)
	require.Equal(t, []domain.AccountID{"acc_a"}, got.additionalAccounts)
	require.Equal(t, []domain.RoleID{"role_a"}, got.readRoles)
	questions, err := got.nativeQuestions.ordered(context.Background())
	require.NoError(t, err)
	require.Equal(t, []nativePolicyQuestion{{subject: "user:usr_reader", relation: "admin", objectType: "account", objectID: "acc_a"}}, questions)
	read.Roles[0] = "role_other"
	read.Native[0].Object = "account:other"
	intent.Plan.Accounts[0] = "acc_other"
	require.Equal(t, []domain.RoleID{"role_a"}, got.readRoles)
	require.Equal(t, []domain.AccountID{"acc_a"}, got.additionalAccounts)
	require.Contains(t, got.nativeQuestions.roots, nativePolicyQuestion{"user:usr_reader", "admin", "account", "acc_a"})
	read.Native = nil
	got, err = semanticReadRequest(intent, read)
	require.NoError(t, err)
	require.Nil(t, got.nativeQuestions, "пустой intent не захватывает произвольный native root")
}

func TestPreparedSemanticReadIntentRejectsWildcardAndMalformedRoots(t *testing.T) {
	intent := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityIdentity, Bundle: nativeBoundaryBundle(t), Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}}
	for _, read := range []kaname.SemanticReadIntent{
		{},
		{Actor: domain.Subject{Type: domain.SubjectTypeUser, ID: "*"}},
		{Actor: domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_a"}, Native: []kaname.SemanticNativeQuestion{{Relation: "admin", Object: "account"}}},
		{Actor: domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_a"}, Roles: []domain.RoleID{"*"}},
	} {
		_, err := semanticReadRequest(intent, read)
		require.Error(t, err)
	}
}

func TestPreparedSemanticWriterRejectsEscapedReadsBeforeSQL(t *testing.T) {
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_reader"}
	foreign := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_foreign"}
	w := &plannedSemanticWriteTx{semanticAuthorityWriteTx: &semanticAuthorityWriteTx{authorityWriteTx: &authorityWriteTx{}}, actor: actor}
	// У writer намеренно нет transaction: любой SQL здесь был бы ошибкой теста.
	_, err := w.AdmitSourceActor(context.Background(), foreign)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	_, _, err = w.ProducerSources(context.Background(), kaname.CanonicalSourceFilter{Actor: foreign})
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	_, _, err = w.CanonicalDirectSources(context.Background(), kaname.CanonicalSourceFilter{Actor: foreign})
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	_, _, err = w.CanonicalCreatorSources(context.Background(), kaname.CanonicalSourceFilter{Actor: foreign})
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	_, _, err = w.RoleProjectionCheckpoint(context.Background(), "role_not_captured")
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	allowed, err := w.SemanticRelationChecker().Check(context.Background(), "user:usr_reader", "admin", "account:acc_a")
	require.False(t, allowed)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	w.closed = true
	_, err = w.AdmitSourceActor(context.Background(), actor)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = w.SemanticRelationChecker().Check(ctx, "user:usr_reader", "admin", "account:acc_a")
	require.ErrorIs(t, err, context.Canceled)
}

func TestLegacyCoordinatedSemanticPortRequiresPlanBeforeAcquire(t *testing.T) {
	repo := New(nil, nil)
	intent := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityIdentity, Bundle: nativeBoundaryBundle(t), Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}}
	w, err := repo.CoordinatedAuthorityWriter(context.Background(), intent)
	require.Nil(t, w)
	require.ErrorIs(t, err, kaname.ErrSemanticReadPlanRequired)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w, err = repo.CoordinatedAuthorityWriter(ctx, intent)
	require.Nil(t, w)
	require.ErrorIs(t, err, context.Canceled)
}
