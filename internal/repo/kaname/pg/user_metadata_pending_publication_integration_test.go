// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"testing"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
)

func TestUserAccessLabelsPendingRequiresCurrentPublication(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	actor := bindingPublicOwner(t, r)
	ctx := callerorigin.WithAssurance(callerorigin.With(declarerCtx(r.ctx, actor), callerorigin.PresentedCredential), "1")
	target := seedMemberUser(t, ctx, r.admin, r.a, "user-pending-publication")
	seat, name, _ := roleActorFiniteLogin(t, r)
	fullContractActivate(t, r)
	first, err := owner.BootstrapCatalogPublication(ctx, r.bundle, nil)
	require.NoError(t, err)
	require.Equal(t, int64(1), first.Revision)
	_, err = r.admin.Exec(ctx, "SELECT kaname.authority_metadata_user_install_v1($1::regrole,$2::regrole,true)", r.role, name)
	require.NoError(t, err)

	bind := func(repo *kanamepg.Repository) (*kanamepg.Repository, *kanamepg.FullWriterContract) {
		t.Helper()
		contract, err := kanamepg.NewPublishedFullWriterContract(ctx, repo, first)
		require.NoError(t, err)
		full, err := repo.WithFullWriterContract(contract)
		require.NoError(t, err)
		return full, contract
	}
	shared, contract := bind(r.repo)
	enrolled, _ := bind(kanamepg.New(seat, nil))
	roles, err := kanamepg.NewRolePolicyWriters(ctx, shared, enrolled, first.Bundle)
	require.NoError(t, err)
	writer, err := roles.InstalledUserAccessLabels(ctx)
	require.NoError(t, err)
	require.NotNil(t, writer)
	newPending := func() operations.Operation {
		t.Helper()
		op, err := operations.NewFromContext(ctx, domain.PrefixOperationIAM, "Update user "+target,
			&iamv1.UpdateUserMetadata{UserId: target, AccountId: r.a, ProtectedLabels: true})
		require.NoError(t, err)
		op.ResourceID = target
		return op
	}

	accepted := newPending()
	require.NoError(t, writer.CreateUserAccessLabelsOperation(ctx, accepted))
	var exists bool
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT EXISTS (SELECT FROM ONLY kaname.operations
		WHERE id=$1 AND resource_id=$2 AND principal_id=$3 AND user_access_labels AND NOT done)`,
		accepted.ID, target, actor).Scan(&exists))
	require.True(t, exists)

	rejectWithoutRow := func() error {
		t.Helper()
		pending := newPending()
		require.NotEqual(t, accepted.ID, pending.ID)
		err := writer.CreateUserAccessLabelsOperation(ctx, pending)
		var persisted bool
		require.NoError(t, r.admin.QueryRow(ctx, "SELECT EXISTS (SELECT FROM ONLY kaname.operations WHERE id=$1)", pending.ID).Scan(&persisted))
		require.False(t, persisted)
		return err
	}
	// При явном закрытии владельцем редакция и digest журнала остаются прежними.
	require.NoError(t, owner.CloseAuthorityBundle(ctx))
	require.Equal(t, "transition", catalogIdentityPhase(t, r))
	require.Equal(t, first.Revision, publicationActivationRevision(t, r))
	require.Error(t, rejectWithoutRow())
	require.NoError(t, owner.StageFullPublicationAuthorityBundle(ctx, first))
	require.NoError(t, owner.ActivateFullPublicationAuthorityBundle(ctx, first))

	// Тот же writer после активации следующей редакции с теми же моделью и каталогом.
	second := appendActivationPublication(t, r, contract, first.Revision+1)
	require.NoError(t, owner.StageFullPublicationAuthorityBundle(ctx, second))
	require.NoError(t, owner.ActivateFullPublicationAuthorityBundle(ctx, second))
	current, err := kanamepg.NewCatalogRepo(r.runtime).LoadActivePublication(ctx)
	require.NoError(t, err)
	require.Equal(t, second.Revision, current.Revision)
	require.Equal(t, first.Digest, current.Digest)

	require.ErrorIs(t, rejectWithoutRow(), kaname.ErrSourceUnconfirmed)
}
