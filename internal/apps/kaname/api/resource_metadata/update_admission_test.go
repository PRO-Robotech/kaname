// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resource_metadata

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

type metadataUpdateFloors map[string]string

func (f metadataUpdateFloors) RequiredACRMin(fqn string) string { return f[fqn] }

type metadataUpdateFunc func(context.Context, UpdateInput) (*operations.Operation, error)

func (f metadataUpdateFunc) Execute(ctx context.Context, in UpdateInput) (*operations.Operation, error) {
	return f(ctx, in)
}

func TestMetadataUpdateAdmissionFailsClosedForMissingCatalogAndCapability(t *testing.T) {
	base := NewHandler(nil)
	ctx := operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: "caller"})
	_, err := base.Update(ctx, &iamv1.UpdateResourceMetadataRequest{})
	require.Equal(t, codes.Unavailable, status.Code(err))
	command := metadataUpdateFunc(func(context.Context, UpdateInput) (*operations.Operation, error) {
		t.Fatal("closed gate reached command")
		return nil, nil
	})
	const fqn = "kaname.cloud.iam.v1.ResourceMetadataService/Update"
	for _, floor := range []string{"", "0", "2", "unknown"} {
		_, err := base.WithUpdate(command, metadataUpdateFloors{fqn: floor})
		require.Error(t, err)
	}
	_, err = base.WithUpdate(nil, metadataUpdateFloors{fqn: "1"})
	require.Error(t, err)
	_, err = base.WithUpdate(command, nil)
	require.Error(t, err)
	// Реальный embedded registry без строки не должен включить writer.
	// После выпуска общей строки эта ветвь проверит фактическую конфигурацию.
	reg, err := seed.LoadPermissionRegistry(context.Background(), nil)
	require.NoError(t, err)
	_, err = base.WithUpdate(command, reg)
	if reg.RequiredACRMin(fqn) != "1" {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
	}
}

func TestMetadataUpdateAdmissionPreservesContextCoordinateAndClear(t *testing.T) {
	ctx := operations.WithPrincipal(context.Background(), operations.Principal{Type: "service_account", ID: "caller"})
	floors := metadataUpdateFloors{"kaname.cloud.iam.v1.ResourceMetadataService/Update": "1"}
	calls := 0
	base := NewHandler(nil)
	h, err := base.WithUpdate(metadataUpdateFunc(func(got context.Context, in UpdateInput) (*operations.Operation, error) {
		calls++
		require.Same(t, ctx, got)
		require.Equal(t, "registry.registries", in.ResourceType)
		require.Equal(t, "registry/shared%2Ftail", in.ResourceID)
		require.Nil(t, in.Labels)
		require.NotNil(t, in.AccessLabels)
		require.Empty(t, in.AccessLabels)
		return nil, status.Error(codes.Aborted, "recording command reached")
	}), floors)
	require.NoError(t, err)
	require.Nil(t, base.update, "включение создаёт новый handler")
	req := &iamv1.UpdateResourceMetadataRequest{ResourceType: "registry.registries", ResourceId: "registry/shared%2Ftail", Patch: &iamv1.ResourceMetadataPatch{UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"access_labels"}}}}
	_, err = h.Update(context.Background(), req)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Zero(t, calls)
	_, err = h.Update(ctx, &iamv1.UpdateResourceMetadataRequest{
		ResourceType: req.ResourceType,
		ResourceId:   req.ResourceId,
		Patch:        &iamv1.ResourceMetadataPatch{AccessLabels: map[string]string{"bad key": "value"}},
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Zero(t, calls, "невалидные метки отклоняются до команды записи")
	_, err = h.Update(ctx, req)
	require.Equal(t, codes.Aborted, status.Code(err))
	require.Equal(t, 1, calls)
	floors["kaname.cloud.iam.v1.ResourceMetadataService/Update"] = ""
	_, err = h.Update(ctx, req)
	require.Equal(t, codes.Unavailable, status.Code(err))
	require.Equal(t, 1, calls)
}
