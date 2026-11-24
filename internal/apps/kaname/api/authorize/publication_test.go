// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authorize

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/authzsnapshot"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

type publicationUnarySource struct{ snapshot authzsnapshot.Snapshot }

func (s publicationUnarySource) LoadActivePublication(context.Context) (authzsnapshot.Snapshot, error) {
	return s.snapshot, nil
}

func (s publicationUnarySource) ConfirmActivePublication(context.Context, *authzsnapshot.Snapshot) (time.Time, error) {
	return s.snapshot.ConfirmedAt, nil
}

func publicationUnaryStore(t *testing.T, refresh bool) *authzsnapshot.Store {
	t.Helper()
	// Здесь проверяется перенос снимка, а не выполнение планов.
	source := publicationUnarySource{snapshot: authzsnapshot.Snapshot{
		Revision: 12, Digest: "model-12", CatalogID: "catalog-12", ConfirmedAt: time.Now(),
		Plans: &authzmodel.Plans{}, Facts: &catalog.Facts{},
	}}
	store, err := authzsnapshot.NewStore(source, time.Hour)
	require.NoError(t, err)
	if refresh {
		require.NoError(t, store.Refresh(context.Background()))
	}
	return store
}

func TestPublicationUnaryRequiresStore(t *testing.T) {
	intercept, err := PublicationUnary(nil)
	require.Error(t, err)
	require.Nil(t, intercept)
}

func TestPublicationUnaryPinsAllDecisionMethods(t *testing.T) {
	store := publicationUnaryStore(t, true)
	intercept, err := PublicationUnary(store)
	require.NoError(t, err)
	for _, method := range []string{
		iamv1.AuthorizeService_Check_FullMethodName,
		iamv1.AuthorizeService_BatchCheck_FullMethodName,
		iamv1.AuthorizeService_ListSubjects_FullMethodName,
		iamv1.AuthorizeService_ExpandRelations_FullMethodName,
		iamv1.InternalIAMService_Check_FullMethodName,
		iamv1.RoleService_Get_FullMethodName,
		iamv1.PermissionCatalogService_ListPermissionCatalog_FullMethodName,
	} {
		t.Run(method, func(t *testing.T) {
			request, response := &struct{ value int }{1}, &struct{ value int }{2}
			result, err := intercept(context.Background(), request, &grpc.UnaryServerInfo{FullMethod: method}, func(ctx context.Context, req any) (any, error) {
				require.Same(t, request, req)
				snapshot, ok := authzsnapshot.FromContext(ctx)
				require.True(t, ok)
				require.Equal(t, int64(12), snapshot.Revision)
				require.NoError(t, store.ConfirmPin(ctx))
				return response, nil
			})
			require.NoError(t, err)
			require.Same(t, response, result)
		})
	}
}

func TestPublicationUnaryStopsCRUDWithoutConfirmation(t *testing.T) {
	intercept, err := PublicationUnary(publicationUnaryStore(t, false))
	require.NoError(t, err)
	_, err = intercept(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: iamv1.RoleService_Get_FullMethodName}, func(context.Context, any) (any, error) {
		t.Fatal("запрос прошёл без подтверждённой редакции")
		return nil, nil
	})
	require.Equal(t, codes.Unavailable, status.Code(err))
}

func TestPublicationUnaryPreservesHealthDuringPublication(t *testing.T) {
	intercept, err := PublicationUnary(publicationUnaryStore(t, false))
	require.NoError(t, err)
	reply := &healthv1.HealthCheckResponse{Status: healthv1.HealthCheckResponse_SERVING}
	result, err := intercept(context.Background(), &healthv1.HealthCheckRequest{},
		&grpc.UnaryServerInfo{FullMethod: healthv1.Health_Check_FullMethodName},
		func(context.Context, any) (any, error) { return reply, nil })
	require.NoError(t, err)
	require.Same(t, reply, result)
}

func TestPublicationUnaryKeepsSuccessfulPublishReplyAfterLocalRevisionChange(t *testing.T) {
	store := publicationUnaryStore(t, true)
	intercept, err := PublicationUnary(store)
	require.NoError(t, err)
	reply := &struct{}{}
	got, err := intercept(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: iamv1.CatalogPublicationService_ApplyPublication_FullMethodName}, func(ctx context.Context, _ any) (any, error) {
		require.NoError(t, store.ConfirmPin(ctx))
		store.ObserveCommittedRevision(13, "model-13")
		return reply, nil
	})
	require.NoError(t, err)
	require.Same(t, reply, got)
}

func TestPublicationUnaryUnconfirmedHeadStopsBeforeDownstream(t *testing.T) {
	intercept, err := PublicationUnary(publicationUnaryStore(t, false))
	require.NoError(t, err)
	result, err := intercept(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: iamv1.AuthorizeService_Check_FullMethodName}, func(context.Context, any) (any, error) {
		t.Fatal("downstream called without a confirmed model")
		return nil, nil
	})
	require.Nil(t, result)
	require.Equal(t, codes.Unavailable, status.Code(err))
	require.Equal(t, status.Convert(authzguard.AuthzBackendUnavailable()).Message(), status.Convert(err).Message())
}

func TestPublicationUnaryHeadChangeDiscardsDecisionAndKeepsOriginalPin(t *testing.T) {
	for _, method := range []string{iamv1.AuthorizeService_BatchCheck_FullMethodName, iamv1.AuthorizeService_ListSubjects_FullMethodName} {
		t.Run(method, func(t *testing.T) {
			store := publicationUnaryStore(t, true)
			intercept, err := PublicationUnary(store)
			require.NoError(t, err)
			result, err := intercept(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: method}, func(ctx context.Context, _ any) (any, error) {
				before, ok := authzsnapshot.FromContext(ctx)
				require.True(t, ok)
				store.ObserveCommittedRevision(13, "model-13")
				after, ok := authzsnapshot.FromContext(ctx)
				require.True(t, ok)
				require.Same(t, before, after)
				return &struct{}{}, nil
			})
			require.Nil(t, result)
			require.Equal(t, codes.Unavailable, status.Code(err))
		})
	}
}

func TestPublicationUnaryCancellationAndDownstreamError(t *testing.T) {
	intercept, err := PublicationUnary(publicationUnaryStore(t, true))
	require.NoError(t, err)
	info := &grpc.UnaryServerInfo{FullMethod: iamv1.InternalIAMService_Check_FullMethodName}
	t.Run("before-entry", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result, err := intercept(ctx, nil, info, func(context.Context, any) (any, error) {
			t.Fatal("downstream called after cancellation")
			return nil, nil
		})
		require.Nil(t, result)
		require.Equal(t, codes.Canceled, status.Code(err))
	})
	t.Run("before-return", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		result, err := intercept(ctx, nil, info, func(context.Context, any) (any, error) {
			cancel()
			return &iamv1.CheckResponse{Allowed: true}, nil
		})
		require.Nil(t, result)
		require.Equal(t, codes.Canceled, status.Code(err))
	})
	t.Run("preserve-error", func(t *testing.T) {
		want := status.Error(codes.PermissionDenied, "caller refused")
		_, err := intercept(context.Background(), nil, info, func(context.Context, any) (any, error) { return nil, want })
		require.Same(t, want, err)
	})
}
