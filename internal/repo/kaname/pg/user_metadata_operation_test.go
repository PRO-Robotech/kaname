// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"testing"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestUserMetadataOperationBindsProtectedMarkerResourceAndPrincipal(t *testing.T) {
	caller := operations.Principal{Type: "service_account", ID: "svaoperator", DisplayName: "operator"}
	ctx := operations.WithPrincipal(t.Context(), caller)
	ctx = callerorigin.WithAssurance(callerorigin.With(ctx, callerorigin.PresentedCredential), "1")
	op, err := operations.NewFromContext(ctx, domain.PrefixOperationIAM, "Update user usrperson",
		&iamv1.UpdateUserMetadata{UserId: "usrperson", AccountId: "acclisting", ProtectedLabels: true})
	require.NoError(t, err)
	op.ResourceID = "usrperson"
	accepted, err := newUserMetadataOperation(ctx, op)
	require.NoError(t, err)
	require.Equal(t, "acclisting", accepted.account)
	require.Equal(t, domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: "svaoperator"}, accepted.actor)
	require.NotSame(t, op.Metadata, accepted.pending.Metadata)
	t.Run("legacy marker", func(t *testing.T) {
		legacy := op
		legacy.Metadata, err = anypb.New(&iamv1.UpdateUserMetadata{UserId: op.ResourceID})
		require.NoError(t, err)
		_, err = newUserMetadataOperation(ctx, legacy)
		require.ErrorIs(t, err, iamerr.ErrFailedPrecondition)
	})
	t.Run("different resource", func(t *testing.T) {
		changed := op
		changed.ResourceID = "usrother"
		_, err := newUserMetadataOperation(ctx, changed)
		require.ErrorIs(t, err, iamerr.ErrFailedPrecondition)
	})
	t.Run("different pending principal", func(t *testing.T) {
		changed := op
		changed.Principal.ID = "svaother"
		_, err := newUserMetadataOperation(ctx, changed)
		require.ErrorIs(t, err, iamerr.ErrPermissionDenied)
	})
	t.Run("terminal operation", func(t *testing.T) {
		done := op
		done.Done = true
		_, err := newUserMetadataOperation(ctx, done)
		require.ErrorIs(t, err, iamerr.ErrFailedPrecondition)
	})
}
