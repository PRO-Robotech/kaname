// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantsource"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/stretchr/testify/require"
)

func TestSemanticActorSameWriterUncommittedUnionAndRollback(t *testing.T) {
	ctx, pool, repo := authorityTestDB(t)
	uid, acc := kac127SeedUserAndAccount(t, ctx, pool, "semnorm")
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
	rid := seedAccountRulesRole(t, ctx, pool, repo, domain.AccountID(acc), "semantic_normalizer", domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}}})
	bundle := semanticBundleDB(t, ctx, pool)
	// Синтетическая active identity проверяет только compare-компонент kaname#1034.
	// Это не product activation и не подтверждение полной authority.
	semanticFixtureIdentity(t, ctx, pool, bundle)
	open := func() kaname.SemanticAuthorityWriter {
		w, err := repo.SemanticAuthorityWriter(ctx, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}, bundle)
		require.NoError(t, err)
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = w.Rollback(cleanup)
		})
		return w
	}
	w := open()
	bid := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	// Носитель и subjects создаются helper в одном writer-TX: deferred constraint
	// требует непустой набор при commit; отдельные autocommit здесь недопустимы.
	_, err := bindingset.Insert(ctx, w.AccessBindingsW(), domain.AccessBinding{ID: bid, SubjectType: actor.Type, SubjectID: actor.ID, RoleID: rid, ResourceType: "account", ResourceID: acc, Scope: domain.ScopeAccount, Status: domain.AccessBindingStatusActive})
	require.NoError(t, err)
	account := newAccount("semantic-uncommitted", domain.UserID(uid))
	_, err = w.AccountsW().Insert(ctx, account)
	require.NoError(t, err)
	saID := domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount))
	_, err = w.ServiceAccountsW().Insert(ctx, domain.ServiceAccount{ID: saID, AccountID: domain.AccountID(acc), Name: "semantic-creator", CreatedBy: actor})
	require.NoError(t, err)
	got, err := grantsource.CollectSemanticActor(ctx, w, actor)
	require.NoError(t, err)
	require.Equal(t, bundle.Identity(), got.Identity)
	require.Equal(t, bundle.Identity(), got.Component.Identity())
	require.Equal(t, w.AuthorityFence().DecisionAt(), got.DecisionAt)
	bindingFound := false
	for _, b := range got.Bindings {
		if b.Source.Binding.ID == bid {
			bindingFound = true
			require.Equal(t, actor, b.Source.Recipient)
			require.Equal(t, bundle.Identity(), b.Effects.Identity())
			require.NotEmpty(t, b.Effects.Effects())
		}
	}
	require.True(t, bindingFound, "незакоммиченный binding должен попасть в общий compile")
	ownerFound := false
	for _, s := range got.Structural.Direct {
		if s.SourceKind == kaname.CanonicalAccountOwner && s.ObjectID == string(account.ID) {
			ownerFound = true
		}
	}
	require.True(t, ownerFound, "незакоммиченный owner читается из того же writer")
	creatorFound := false
	for _, s := range got.Structural.Creators {
		if s.ObjectID == string(saID) {
			creatorFound = true
			require.Equal(t, actor, s.Creator)
		}
	}
	require.True(t, creatorFound, "creator evidence читается из того же writer")
	require.False(t, got.Component.Complete())
	codes := []string{}
	for _, o := range got.Component.Obligations() {
		codes = append(codes, o.Code)
	}
	for _, code := range []string{"registration_publication_source", "creator_selector_evidence", "authority_writer_protocol", "role_projection_checkpoint"} {
		require.Contains(t, codes, code)
	}
	// Отдельное соединение не видит ни одного из трёх новых источников.
	var count int
	require.NoError(t, pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM kaname.access_bindings WHERE id=$1)+(SELECT count(*) FROM kaname.accounts WHERE id=$2)+(SELECT count(*) FROM kaname.service_accounts WHERE id=$3)`, bid, account.ID, saID).Scan(&count))
	require.Zero(t, count)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	none, err := grantsource.CollectSemanticActor(cancelled, w, actor)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, grantsource.ActorEffects{}, none)
	require.NoError(t, w.Rollback(ctx))
	next := open()
	after, err := grantsource.CollectSemanticActor(ctx, next, actor)
	require.NoError(t, err)
	for _, b := range after.Bindings {
		require.NotEqual(t, bid, b.Source.Binding.ID)
	}
	for _, s := range after.Structural.Direct {
		require.NotEqual(t, string(account.ID), s.ObjectID)
	}
	for _, s := range after.Structural.Creators {
		require.NotEqual(t, string(saID), s.ObjectID)
	}
	require.False(t, after.Component.Complete())
	require.NoError(t, next.Rollback(ctx))
	authorityWaitReleased(t, pool)
}
