// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authorize

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authztypes"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/PRO-Robotech/kaname/internal/service"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Дублёр пропускает всё, включая внутренние имена. Так проба проверяет сам
// транспортный рубеж, независимо от второго рубежа в настоящей службе.
type grantBoundaryAuthorizer struct{ calls atomic.Int64 }

func (a *grantBoundaryAuthorizer) Check(context.Context, service.CheckRequest) (*service.CheckResult, error) {
	a.calls.Add(1)
	return &service.CheckResult{Allowed: true}, nil
}
func (a *grantBoundaryAuthorizer) BatchCheck(_ context.Context, requests []service.CheckRequest) ([]*service.CheckResult, error) {
	a.calls.Add(1)
	out := make([]*service.CheckResult, len(requests))
	for i := range out {
		out[i] = &service.CheckResult{Allowed: true}
	}
	return out, nil
}
func (a *grantBoundaryAuthorizer) ListSubjects(context.Context, service.ListSubjectsRequest) (*service.ListSubjectsResult, error) {
	a.calls.Add(1)
	return &service.ListSubjectsResult{Subjects: []string{"user:usr_alice"}}, nil
}
func (a *grantBoundaryAuthorizer) ExpandRelations(context.Context, service.ExpandRequest) (*service.ExpandResult, error) {
	a.calls.Add(1)
	return &service.ExpandResult{Tree: &authztypes.ExpandTree{Leaves: []string{"user:usr_alice"}}}, nil
}
func (a *grantBoundaryAuthorizer) NeutralDenyReasons(context.Context, service.CheckRequest) []string {
	a.calls.Add(1)
	return nil
}

func TestGrantCoordinateBoundary_HandlerRejectsDecisionAndDisclosureBeforeService(t *testing.T) {
	for _, typ := range []string{grantcapability.ScopeObjectType, grantcapability.RoleObjectType} {
		t.Run(typ, func(t *testing.T) {
			backend := &grantBoundaryAuthorizer{}
			h := NewHandler(backend, NewWhoAmIUseCase(nil, nil)).WithModuleRoster(testModuleRoster())
			resource := &iamv1.ResourceRef{Type: typ, Id: "opaque"}
			question := &iamv1.AuthorizeCheckRequest{Subject: "user:usr_alice", Resource: resource, Action: "iam.role.bind", RequiredRelation: "bind"}
			good := &iamv1.AuthorizeCheckRequest{Subject: "user:usr_alice", Resource: &iamv1.ResourceRef{Type: "vpc_network", Id: "net_one"}, Action: "vpc.network.get", RequiredRelation: "viewer"}
			for _, ctx := range []context.Context{moduleCertCtx(), userCtx("usr_alice")} {
				_, err := h.Check(ctx, question)
				require.Equal(t, codes.InvalidArgument, status.Code(err))
				for _, batch := range [][]*iamv1.AuthorizeCheckRequest{{question, good}, {good, question}} {
					_, err = h.BatchCheck(ctx, &iamv1.BatchAuthorizeCheckRequest{Checks: batch})
					require.Equal(t, codes.InvalidArgument, status.Code(err))
				}
				_, err = h.ListSubjects(ctx, &iamv1.ListSubjectsRequest{Resource: resource, Action: "iam.role.get"})
				require.Equal(t, codes.InvalidArgument, status.Code(err))
				_, err = h.ExpandRelations(ctx, &iamv1.ExpandRelationsRequest{Resource: resource, Relation: "bind"})
				require.Equal(t, codes.InvalidArgument, status.Code(err))
			}
			require.Zero(t, backend.calls.Load())

			// Все четыре законные двери доходят до того же источника.
			ctx := moduleCertCtx()
			answer, err := h.Check(ctx, good)
			require.NoError(t, err)
			require.True(t, answer.Allowed)
			_, err = h.BatchCheck(ctx, &iamv1.BatchAuthorizeCheckRequest{Checks: []*iamv1.AuthorizeCheckRequest{good}})
			require.NoError(t, err)
			_, err = h.ListSubjects(ctx, &iamv1.ListSubjectsRequest{Resource: good.Resource, Action: "vpc.network.get"})
			require.NoError(t, err)
			_, err = h.ExpandRelations(ctx, &iamv1.ExpandRelationsRequest{Resource: good.Resource, Relation: "viewer"})
			require.NoError(t, err)
			require.EqualValues(t, 4, backend.calls.Load())
		})
	}
}
