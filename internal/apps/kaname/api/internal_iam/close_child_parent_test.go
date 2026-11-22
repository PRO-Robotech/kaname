// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type childParentCloseStub struct {
	input  kaname.ChildParentCloseInput
	closed time.Time
	err    error
	calls  int
}

func (s *childParentCloseStub) RunChildParentClose(_ context.Context, input kaname.ChildParentCloseInput) (time.Time, error) {
	s.input, s.calls = input, s.calls+1
	return s.closed, s.err
}

func TestCloseChildParentHandlerExactVersionAndCommittedReplayTime(t *testing.T) {
	version := time.Date(2026, 11, 22, 12, 0, 0, 123456000, time.UTC)
	store := &childParentCloseStub{closed: version.Add(time.Minute)}
	gate := &fakeGate{domain: "registry"}
	handler := (&Handler{regGate: gate}).WithChildParentClose(store)
	request := &iamv1.CloseChildParentRequest{ResourceType: "registry.registry", ResourceId: "registry-one", SourceVersion: timestamppb.New(version)}
	for range 2 {
		response, err := handler.CloseChildParent(t.Context(), request)
		require.NoError(t, err)
		require.Equal(t, store.closed, response.ClosedAt.AsTime())
	}
	require.Equal(t, 2, gate.callCnt)
	require.Equal(t, 2, store.calls)
	require.Equal(t, kaname.ChildParentCloseInput{ResourceType: request.ResourceType, ResourceID: request.ResourceId, SourceVersion: version}, store.input)
	method := "/kaname.cloud.iam.v1.InternalIAMService/CloseChildParent"
	require.Contains(t, authzguard.ProfileMethods(moduleidentity.ProfileModuleWriter), method)
	require.NotContains(t, authzguard.ProfileMethods(moduleidentity.ProfileEdge), method)
	require.NotContains(t, authzguard.ProfileMethods(moduleidentity.ProfileDataPlane), method)
}

func TestCloseChildParentHandlerFailsClosedBeforeRunner(t *testing.T) {
	version := timestamppb.New(time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC))
	for _, tc := range []struct {
		name       string
		stamp      *timestamppb.Timestamp
		gateErr    error
		configured bool
		code       codes.Code
	}{
		{"missing version", nil, nil, true, codes.InvalidArgument},
		{"invalid version", &timestamppb.Timestamp{Nanos: -1}, nil, true, codes.InvalidArgument},
		{"zero version", timestamppb.New(time.Time{}), nil, true, codes.InvalidArgument},
		{"module denied", version, authzguard.PermissionDenied(), true, codes.PermissionDenied},
		{"FULL port absent", version, nil, false, codes.Unavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &childParentCloseStub{}
			handler := &Handler{regGate: &fakeGate{domain: "registry", err: tc.gateErr}}
			if tc.configured {
				handler.WithChildParentClose(store)
			}
			response, err := handler.CloseChildParent(t.Context(), &iamv1.CloseChildParentRequest{
				ResourceType: "registry.registry", ResourceId: "registry-one", SourceVersion: tc.stamp,
			})
			require.Nil(t, response)
			require.Equal(t, tc.code, status.Code(err))
			require.Zero(t, store.calls)
		})
	}
}

func TestCloseChildParentHandlerFieldDetailsAndOpaqueBackendFailure(t *testing.T) {
	field := &kaname.ResourceDecisionFieldError{Field: "source_version", Description: "parent registration version does not match"}
	for _, tc := range []struct {
		name string
		err  error
		code codes.Code
	}{
		{"exact version refusal", field, codes.InvalidArgument},
		{"backend", errors.New("private driver diagnostic"), codes.Internal},
		{"cleanup overrides input", errors.Join(iamerr.ErrUnavailable, field), codes.Unavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &childParentCloseStub{err: tc.err}
			handler := (&Handler{regGate: &fakeGate{domain: "registry"}}).WithChildParentClose(store)
			response, err := handler.CloseChildParent(t.Context(), &iamv1.CloseChildParentRequest{
				ResourceType: "registry.registry", ResourceId: "registry-one", SourceVersion: timestamppb.Now(),
			})
			require.Nil(t, response)
			require.Equal(t, tc.code, status.Code(err))
			require.NotContains(t, status.Convert(err).Message(), "private driver diagnostic")
			if tc.code == codes.InvalidArgument {
				details := status.Convert(err).Details()
				require.Len(t, details, 1)
				bad, ok := details[0].(*errdetails.BadRequest)
				require.True(t, ok)
				require.Len(t, bad.FieldViolations, 1)
				require.Equal(t, "source_version", bad.FieldViolations[0].Field)
			}
		})
	}
}
