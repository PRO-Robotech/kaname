// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// check_module_domain_test.go — внутренний Check плоскости данных ограничен
// доменом её модуля (kaname#987).
//
// Пробы DoD:
//
//  1. личность плоскости данных registry делает Check по объекту домена vpc —
//     `PermissionDenied`, решатель не спрошен;
//  2. законный близнец: та же личность делает Check по объекту домена registry
//     — обычный ответ Check (allow или deny по модели).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/servicesan"
	"github.com/PRO-Robotech/kaname/internal/testsupport/moduleroster"
)

// registryDataPlaneSAN — плоскость данных registry: учётка модуля registry в
// пространстве плоскости данных.
const registryDataPlaneSAN = "spiffe://" + moduleroster.DomainName + "/ns/registry-data/sa/kacho-registry"

// domainRoster — плоскость данных registry и модуль-владелец vpc.
func domainRoster(t *testing.T) moduleidentity.Roster {
	t.Helper()
	r, err := moduleidentity.Parse(servicesan.NewForm("kacho-{service}"), []string{
		"registry-data/kacho-registry=data-plane",
		"kacho/kacho-vpc=module-writer",
	})
	require.NoError(t, err)
	return r
}

// TestInternalCheck_DataPlaneAsksOnlyAboutItsOwnDomain — DoD пп. 1–2.
func TestInternalCheck_DataPlaneAsksOnlyAboutItsOwnDomain(t *testing.T) {
	for name, tc := range map[string]struct {
		object  string
		refused bool
	}{
		"объект чужого домена (vpc)":             {object: "vpc_network:enp_x", refused: true},
		"объект чужого домена (compute)":         {object: "compute_instance:ins_x", refused: true},
		"объект платформы (проект)":              {object: "project:prj_x", refused: true},
		"объект без типа":                        {object: "rep_x", refused: true},
		"близнец: объект своего домена":          {object: "registry_repository:rep_x"},
		"близнец: реестр — объект своего домена": {object: "registry_registry:reg_x"},
	} {
		t.Run(name, func(t *testing.T) {
			authz := &fakeAuthorizer{result: &service.CheckResult{Allowed: true, CheckedAt: time.Now().UTC()}}
			h := newCheckHandler(authz).WithModuleRoster(domainRoster(t))
			resp, err := h.Check(moduleroster.IdentityContext(registryDataPlaneSAN), &iamv1.CheckRequest{
				SubjectId: "user:usr_alice",
				Relation:  "viewer",
				Object:    tc.object,
			})
			if tc.refused {
				st, _ := status.FromError(err)
				require.Equal(t, codes.PermissionDenied, st.Code(), "ответ %v %v", resp, err)
				require.Equal(t, "permission denied", st.Message())
				require.Zero(t, authz.callCnt, "решатель спрошен о чужом домене")
				return
			}
			require.NoError(t, err)
			require.True(t, resp.GetAllowed())
			require.Equal(t, 1, authz.callCnt)
		})
	}
}

// TestInternalCheck_DomainBindingScope — граница названа: привязка к домену
// стоит у плоскости данных; модуль-владелец и вызов без признанной личности
// (стенд без взаимного TLS) спрашивают как прежде.
func TestInternalCheck_DomainBindingScope(t *testing.T) {
	for name, ctx := range map[string]context.Context{
		"модуль-владелец vpc":     moduleroster.IdentityContext(moduleroster.DeclaredVPC),
		"без признанной личности": context.Background(),
	} {
		t.Run(name, func(t *testing.T) {
			authz := &fakeAuthorizer{result: &service.CheckResult{Allowed: true, CheckedAt: time.Now().UTC()}}
			h := newCheckHandler(authz).WithModuleRoster(domainRoster(t))
			_, err := h.Check(ctx, &iamv1.CheckRequest{
				SubjectId: "user:usr_alice", Relation: "viewer", Object: "registry_repository:rep_x",
			})
			require.NoError(t, err)
			require.Equal(t, 1, authz.callCnt)
		})
	}
}
