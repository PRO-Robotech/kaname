// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package module

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCatalogPublicationDeniesNonHumanBeforeReadingCatalog(t *testing.T) {
	handler := NewPublicationHandler(&PublicationUseCase{})
	for _, ctx := range []context.Context{
		context.Background(),
		operations.WithPrincipal(context.Background(), operations.Principal{Type: "service_account", ID: "svc-operator"}),
	} {
		_, err := handler.PlanPublication(ctx, nil)
		require.Equal(t, codes.PermissionDenied, status.Code(err))
		_, err = handler.ApplyPublication(ctx, nil)
		require.Equal(t, codes.PermissionDenied, status.Code(err))
	}
}
