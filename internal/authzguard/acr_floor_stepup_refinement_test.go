// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzguard

// acr_floor_stepup_refinement_test.go — SEC-ACR-14 / I8 (R3).
//
// After the step-up refinement, InternalClusterService/Get is downgraded to
// required_acr_min="1" (cluster read), while GrantAdmin stays "2" (privilege
// escalation). This locks the iam :9091 acr-floor parity: the same catalog value
// the gateway reads is enforced here — sensitive floored at "2", the downgraded
// read passes at "1".

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

const clusterGetMethod = "/kacho.cloud.iam.v1.InternalClusterService/Get"

// refinedCatalog reflects the post-refinement acr values for the gateway-fronted
// cluster RPCs: GrantAdmin/RevokeAdmin stay "2", Get/ListAdmins downgrade to "1".
func refinedCatalog() fakeACRCatalog {
	return fakeACRCatalog{
		"kacho.cloud.iam.v1.InternalClusterService/GrantAdmin":  "2",
		"kacho.cloud.iam.v1.InternalClusterService/RevokeAdmin": "2",
		"kacho.cloud.iam.v1.InternalClusterService/Get":         "1",
		"kacho.cloud.iam.v1.InternalClusterService/ListAdmins":  "1",
	}
}

// SEC-ACR-14: GrantAdmin (sensitive "2") denies acr=1; the downgraded Get ("1")
// passes acr=1 — floor parity with the gateway.
func TestACRFloor_Refinement_GrantAdminSensitive_GetRoutine(t *testing.T) {
	f := NewACRFloor(refinedCatalog(), GatewayFrontedInternalRPCs()).WithProductionMode(true)

	// GrantAdmin stays sensitive: acr=1 < 2 → denied.
	if status.Code(f.allow(gatewayACRCtx("1"), grantAdminMethod)) != codes.PermissionDenied {
		t.Fatalf("GrantAdmin(acr=2) must deny acr=1 (step-up preserved)")
	}
	// GrantAdmin passes at acr=2.
	if err := f.allow(gatewayACRCtx("2"), grantAdminMethod); err != nil {
		t.Fatalf("GrantAdmin must pass at acr=2, got %v", err)
	}

	// Get is downgraded to "1": acr=1 passes (routine unblock parity).
	if err := f.allow(gatewayACRCtx("1"), clusterGetMethod); err != nil {
		t.Fatalf("cluster Get(acr=1) must pass at acr=1 after downgrade, got %v", err)
	}
	// AAL1 floor still holds on Get: acr=0 < 1 → denied.
	if status.Code(f.allow(gatewayACRCtx("0"), clusterGetMethod)) != codes.PermissionDenied {
		t.Fatalf("cluster Get(acr=1) must still deny acr=0 (AAL1 floor holds)")
	}
}

// SEC-ACR-16 (iam side): the floor's ranking wrapper (grpcsrv.ACRSatisfies) gives
// the expected verdicts over the acr matrix — locked here so a drift on the iam
// side is caught symmetrically with the gateway verdict-parity test.
func TestACRFloor_Refinement_ACRSatisfiesMatrix(t *testing.T) {
	cases := []struct {
		presented, required string
		want                bool
	}{
		{"", "", true}, {"", "1", false}, {"", "2", false},
		{"0", "1", false}, {"1", "1", true}, {"1", "2", false},
		{"2", "1", true}, {"2", "2", true}, {"3", "2", true},
		{"1", "", true}, {"weird", "1", false}, {"weird", "", true},
	}
	for _, c := range cases {
		if got := grpcsrv.ACRSatisfies(c.presented, c.required); got != c.want {
			t.Fatalf("ACRSatisfies(%q,%q)=%v want %v", c.presented, c.required, got, c.want)
		}
	}
}
