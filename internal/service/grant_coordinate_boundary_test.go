// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/stretchr/testify/require"
)

// Источник намеренно разрешает всё: отказ обязан принадлежать публичной двери,
// а не отсутствию данных или времени решения в native-источнике.
type grantBoundaryRelations struct {
	mockRelations
	calls atomic.Int64
}

func (r *grantBoundaryRelations) CheckWithContext(context.Context, string, string, string, map[string]any) (bool, error) {
	r.calls.Add(1)
	return true, nil
}
func (r *grantBoundaryRelations) ListSubjects(context.Context, string, string, string, int, string) ([]string, string, error) {
	r.calls.Add(1)
	return []string{"user:usr_root"}, "", nil
}
func (r *grantBoundaryRelations) Sources(context.Context, string, string, string) ([]string, error) {
	r.calls.Add(1)
	return []string{"user:usr_root"}, nil
}

func TestGrantCoordinateBoundary_ServiceRejectsEveryDecisionAndDisclosureDoor(t *testing.T) {
	for _, typ := range []string{grantcapability.ScopeObjectType, grantcapability.RoleObjectType} {
		t.Run(typ, func(t *testing.T) {
			store := &grantBoundaryRelations{}
			admin := &scClusterChecker{admins: map[string]bool{"user:usr_root": true}}
			svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: store, ClusterAdminChecker: admin})
			ctx := context.Background()
			_, err := svc.Check(ctx, CheckRequest{Subject: "user:usr_root", Resource: ResourceRef{Type: typ, ID: "opaque"}, Action: "iam.role.bind", RequiredRelation: "bind"})
			require.ErrorContains(t, err, "Illegal argument resource.type")
			_, err = svc.CheckRelation(ctx, CheckRelationRequest{Subject: "user:usr_root", Object: typ + ":opaque", Relation: "bind"})
			require.ErrorContains(t, err, "Illegal argument object type")
			_, err = svc.ListSubjects(ctx, ListSubjectsRequest{ResourceType: typ, ResourceID: "opaque", Action: "iam.role.get"})
			require.ErrorContains(t, err, "Illegal argument resource.type")
			_, err = svc.ExpandRelations(ctx, ExpandRequest{ResourceType: typ, ResourceID: "opaque", Relation: "bind"})
			require.ErrorContains(t, err, "Illegal argument resource.type")
			batch, err := svc.BatchCheck(ctx, []CheckRequest{{Subject: "user:usr_root", Resource: ResourceRef{Type: typ, ID: "opaque"}, Action: "iam.role.bind", RequiredRelation: "bind"}})
			require.NoError(t, err, "служба сохраняет контракт отказа отдельного пункта партии")
			require.Len(t, batch, 1)
			require.False(t, batch[0].Allowed)
			require.True(t, strings.Contains(strings.Join(batch[0].DenyReasons, " "), "Illegal argument resource.type"))
			require.Zero(t, store.calls.Load())
			require.Zero(t, admin.calls, "надзор администратора не открывает внутренний тип")

			// Законный сосед на той же разрешающей двери продолжает работать.
			good, err := svc.Check(ctx, CheckRequest{Subject: "user:usr_root", Resource: ResourceRef{Type: "vpc_network", ID: "net_one"}, Action: "vpc.network.get", RequiredRelation: "viewer"})
			require.NoError(t, err)
			require.True(t, good.Allowed)
			require.EqualValues(t, 1, store.calls.Load())
		})
	}
}
