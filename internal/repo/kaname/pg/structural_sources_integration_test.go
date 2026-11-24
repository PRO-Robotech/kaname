// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantsource"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

func TestCanonicalStructuralSameTransactionAndRollback(t *testing.T) {
	ctx, pool, repo := authorityTestDB(t)
	uid, acc := kac127SeedUserAndAccount(t, ctx, pool, "strtx")
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
	w := authorityOpen(t, ctx, repo, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal})
	id := domain.AccountID(ids.NewID(domain.PrefixAccount))
	_, err := w.AccountsW().Insert(ctx, domain.Account{ID: id, Name: domain.AccountName("structural-" + string(id)), OwnerUserID: domain.UserID(uid)})
	require.NoError(t, err)
	saID := domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount))
	_, err = w.ServiceAccountsW().Insert(ctx, domain.ServiceAccount{ID: saID, AccountID: domain.AccountID(acc), Name: "structural-creator", CreatedBy: actor})
	require.NoError(t, err)
	got, err := grantsource.CollectStructuralSources(ctx, w, actor)
	require.NoError(t, err)
	found := false
	for _, s := range got.Direct {
		if s.SourceKind == kaname.CanonicalAccountOwner && s.ObjectID == string(id) {
			found = true
		}
	}
	require.True(t, found, "незакоммиченный owner виден через тот же writer")
	require.Len(t, got.Creators, 1)
	require.Equal(t, actor, got.Creators[0].Creator)
	var count int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.accounts WHERE id=$1`, id).Scan(&count))
	require.Zero(t, count)
	require.NoError(t, w.Rollback(ctx))
	next := authorityOpen(t, ctx, repo, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal})
	after, err := grantsource.CollectStructuralSources(ctx, next, actor)
	require.NoError(t, err)
	require.Empty(t, after.Creators)
	for _, s := range after.Direct {
		require.NotEqual(t, string(id), s.ObjectID)
	}
}

func TestCanonicalStructuralCurrentOwnerTypedActorAndFence(t *testing.T) {
	ctx, pool, repo := authorityTestDB(t)
	uid, acc := kac127SeedUserAndAccount(t, ctx, pool, "strown")
	w := authorityOpen(t, ctx, repo, authorityAccounts(acc))
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
	got, err := grantsource.CollectStructuralSources(ctx, w, actor)
	require.NoError(t, err)
	require.Len(t, got.Direct, 2)
	sa := domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: actor.ID}
	none, err := grantsource.CollectStructuralSources(ctx, w, sa)
	require.NoError(t, err)
	require.Empty(t, none.Direct)
	require.NoError(t, w.Rollback(ctx))
	uncovered := authorityOpen(t, ctx, repo, authorityAccounts("foreign"))
	none, err = grantsource.CollectStructuralSources(ctx, uncovered, actor)
	require.ErrorIs(t, err, kaname.ErrCanonicalSourceFence)
	require.Empty(t, none.Direct)
}

func TestCanonicalStructuralAdminExpiryLastPageAndStaleFact(t *testing.T) {
	ctx, pool, repo := authorityTestDB(t)
	uid, _ := kac127SeedUserAndAccount(t, ctx, pool, "stradm")
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
	w := authorityOpen(t, ctx, repo, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal})
	at := w.AuthorityFence().DecisionAt()
	// Запись через отдельную сессию намеренна: public protocol ещё не включён;
	// проверяется точное DecisionAt, не безопасность старого raw writer.
	_, err := pool.Exec(ctx, `INSERT INTO kaname.cluster_admin_grants(id,cluster_id,subject_type,subject_id,granted_by,granted_at,granted_until) VALUES($1,$2,'user',$3,'test',$4,$5)`, "cag_00000000000000001", domain.ClusterSingletonID, uid, at.Add(-time.Hour), at.Add(time.Hour))
	require.NoError(t, err)
	filter := kaname.CanonicalSourceFilter{Actor: actor, Limit: 1}
	found := false
	pages := 0
	for {
		ss, next, e := w.CanonicalDirectSources(ctx, filter)
		require.NoError(t, e)
		pages++
		for _, s := range ss {
			if s.SourceKind == kaname.CanonicalClusterAdmin {
				found = true
			}
		}
		if next == "" {
			break
		}
		filter.After = next
		require.Less(t, pages, 10)
	}
	require.True(t, found)
	require.GreaterOrEqual(t, pages, 3)
	_, err = pool.Exec(ctx, `UPDATE kaname.cluster_admin_grants SET granted_until=$1 WHERE subject_type='user' AND subject_id=$2`, at, uid)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject) VALUES('cluster',$1,'system_admin',$2) ON CONFLICT DO NOTHING`, domain.ClusterSingletonID, fmt.Sprintf("user:%s", uid))
	require.NoError(t, err)
	got, err := grantsource.CollectStructuralSources(ctx, w, actor)
	require.NoError(t, err)
	for _, s := range got.Direct {
		require.NotEqual(t, kaname.CanonicalClusterAdmin, s.SourceKind)
	}
	_, err = pool.Exec(ctx, `DELETE FROM kaname.cluster_admin_grants WHERE subject_type='user' AND subject_id=$1`, uid)
	require.NoError(t, err)
	got, err = grantsource.CollectStructuralSources(ctx, w, actor)
	require.NoError(t, err)
	for _, s := range got.Direct {
		require.NotEqual(t, kaname.CanonicalClusterAdmin, s.SourceKind)
	}
}
