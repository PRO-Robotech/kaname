// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
)

func TestAuthorityBindingVersionsDistinguishLegacyMissingAndVersionOne(t *testing.T) {
	ctx, pool, repo, account, user := grantProjectionFixture(t)
	legacyRole := seedAccountRole(t, ctx, pool, account, "source_version_legacy")
	newRole := seedAccountRole(t, ctx, pool, account, "source_version_new")
	require.NoError(t, insertBinding(ctx, pool, legacyRole, user, "account", string(account)))
	require.NoError(t, insertBinding(ctx, pool, newRole, user, "account", string(account)))
	var legacyID, newID domain.AccessBindingID
	require.NoError(t, pool.QueryRow(ctx, `SELECT id FROM kaname.access_bindings WHERE role_id=$1`, string(legacyRole)).Scan(&legacyID))
	require.NoError(t, pool.QueryRow(ctx, `UPDATE kaname.access_bindings SET grant_capability_version=1 WHERE role_id=$1 RETURNING id`, string(newRole)).Scan(&newID))
	w := authorityOpen(t, ctx, repo, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal})
	missing := domain.AccessBindingID("ab_missing_source_version")
	versions, err := w.BindingCapabilityVersions(ctx, []domain.AccessBindingID{legacyID, newID, missing, legacyID})
	require.NoError(t, err)
	require.Len(t, versions, 2)
	version, found := versions[legacyID]
	require.True(t, found, "версия 0 — прочитанная строка, а не отсутствие метаданных")
	require.Zero(t, version)
	require.Equal(t, 1, versions[newID])
	_, found = versions[missing]
	require.False(t, found)
	versions, err = w.BindingCapabilityVersions(ctx, nil)
	require.NoError(t, err)
	require.Empty(t, versions)
	_, err = w.BindingCapabilityVersions(ctx, []domain.AccessBindingID{""})
	require.ErrorIs(t, err, iamerr.ErrInvalidArg)
	_, err = w.BindingCapabilityVersions(ctx, make([]domain.AccessBindingID, kaname.MaxAuthorityBindingVersionBatch+1))
	require.ErrorIs(t, err, iamerr.ErrInvalidArg)
	// Отказ аргумента не портит транзакцию и не оставляет частичный ответ.
	versions, err = w.BindingCapabilityVersions(ctx, []domain.AccessBindingID{newID})
	require.NoError(t, err)
	require.Equal(t, 1, versions[newID])
}

func TestAuthorityBindingVersionsReadOwnUncommittedCarrier(t *testing.T) {
	ctx, pool, repo, account, user := grantProjectionFixture(t)
	role := seedAccountRole(t, ctx, pool, account, "source_version_writer")
	w := authorityOpen(t, ctx, repo, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal})
	b, err := bindingset.Insert(ctx, w.AccessBindingsW(), domain.AccessBinding{
		ID:          domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(user),
		RoleID: role, ResourceType: "account", ResourceID: string(account),
		GrantedByUserID: user, Status: domain.AccessBindingStatusActive,
	})
	require.NoError(t, err)
	versions, err := w.BindingCapabilityVersions(ctx, []domain.AccessBindingID{b.ID})
	require.NoError(t, err)
	version, found := versions[b.ID]
	require.True(t, found, "независимый Reader не увидел бы эту незакоммиченную строку")
	require.Zero(t, version)
	require.NoError(t, w.Rollback(ctx))
	other := authorityOpen(t, ctx, repo, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal})
	versions, err = other.BindingCapabilityVersions(ctx, []domain.AccessBindingID{b.ID})
	require.NoError(t, err)
	require.Empty(t, versions, "откат не сохраняет метаданные носителя")
}
