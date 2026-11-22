// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package restfront

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestChildRegistrationRESTRequiresPublicProfileAndKeepsGRPCHop(t *testing.T) {
	listener := bufconn.Listen(1024 * 1024)
	t.Cleanup(func() { _ = listener.Close() })
	var calls atomic.Int32
	server := grpc.NewServer(grpc.UnaryInterceptor(func(_ context.Context, _ any, info *grpc.UnaryServerInfo, _ grpc.UnaryHandler) (any, error) {
		if info.FullMethod != iamv1.ChildRegistrationService_Register_FullMethodName {
			return nil, status.Error(codes.Internal, "unexpected endpoint")
		}
		calls.Add(1)
		return nil, status.Error(codes.PermissionDenied, "endpoint guard")
	}))
	iamv1.RegisterChildRegistrationServiceServer(server, &iamv1.UnimplementedChildRegistrationServiceServer{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) })}
	request := func(front http.Handler) int {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		req := httptest.NewRequest(http.MethodPost, "/iam/v1/childRegistrations:register", strings.NewReader(`{"resourceType":"childstage.child","resourceId":"parent/candidate"}`)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		front.ServeHTTP(response, req)
		return response.Code
	}
	staged, err := NewPublic(t.Context(), "passthrough:///child-registration", opts, Limits{}, PublicServices{})
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, request(staged))
	require.Zero(t, calls.Load())
	public, err := NewPublic(t.Context(), "passthrough:///child-registration", opts, Limits{}, PublicServices{ChildRegistration: true})
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, request(public), "запрос обязан пройти через перехватчик собственного gRPC")
	require.EqualValues(t, 1, calls.Load())
	internal, err := NewInternal(t.Context(), "passthrough:///child-registration", opts, func(*tls.ConnectionState) bool { return true })
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, request(internal))
	require.EqualValues(t, 1, calls.Load())
}
