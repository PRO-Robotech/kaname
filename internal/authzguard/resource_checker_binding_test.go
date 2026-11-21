// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard_test

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestResourceCheckerBindingPreservesRosterAndIsolatesAttempts(t *testing.T) {
	san := "spiffe://kacho.cloud/ns/modules/sa/kacho-vpc"
	ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"), san, true)
	first := &fakeChecker{err: errors.New("first attempt backend")}
	original := authzguard.NewRelationWriteGate(first).WithModuleRoster(rosterOf(t, moduleidentity.ProfileModuleWriter, san))
	second := &fakeChecker{}
	bound := original.BindRelationChecker(second)
	module, err := bound.Authorize(ctx)
	require.NoError(t, err)
	require.Equal(t, "vpc", module)
	require.Equal(t, codes.PermissionDenied, status.Code(bound.AuthorizeAccount(ctx, "acc_resource_a")))
	require.Empty(t, first.gotObject)
	require.Equal(t, "account:acc_resource_a", second.gotObject)
	require.Equal(t, codes.Unavailable, status.Code(original.AuthorizeAccount(ctx, "acc_resource_b")))
	require.Equal(t, "account:acc_resource_b", first.gotObject)
	require.Equal(t, "account:acc_resource_a", second.gotObject)
	require.Equal(t, codes.PermissionDenied, status.Code(original.BindRelationChecker(nil).AuthorizeAccount(ctx, "acc_resource_a")))
	var absent *authzguard.RelationWriteGate
	require.Equal(t, codes.PermissionDenied, status.Code(absent.BindRelationChecker(second).AuthorizeAccount(ctx, "acc_resource_a")))
}
