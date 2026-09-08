// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// acr_floor_stepup_parity_test.go — SEC-ACR-16, INTERNAL arm (mirror of the
// gateway's stepup_verdict_parity_test.go).
//
// The step-up floor is enforced at two points and, since the consolidation,
// implemented once (grpcsrv.EvaluateStepUp). Neither point may re-derive it.
// `gateway/internal/...` and `services/iam/internal/...` cannot import each
// other (Go internal-package rule), so parity is held by anchoring BOTH real
// entrypoints to the shared rule: this file does it for ACRFloor, the gateway
// file does it for StepUpGate, and equality with a common reference gives
// equality with each other.
//
// The axis this guard exists for is the MACHINE PRINCIPAL. Before the
// consolidation the gateway exempted service-account principals (a machine has
// no interactive ceremony and can never present acr ≥ 1) and this floor did not
// — so a machine cleared the front door and was denied here, permanently, on the
// acr-gated RPCs. The old parity test could not see it: it built a non-machine
// token and compared only the ranking table. Every case below therefore drives
// the REAL entrypoint (ACRFloor.allow) with the principal type varied, machine
// included.

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// gatewayCallerCtx builds the ctx as the trust-aware extract leaves it for a
// VERIFIED api-gateway peer forwarding a principal of the given type and acr.
func gatewayCallerCtx(principalType, acr string) context.Context {
	ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"), gatewaySAN, true)
	ctx = grpcsrv.WithTrustedPrincipal(ctx,
		operations.Principal{Type: principalType, ID: "sub-parity"}, true)
	return grpcsrv.WithTrustedACR(ctx, acr, true)
}

// floorVerdict maps the internal entrypoint's error back onto the shared verdict
// vocabulary. The floor carries no MFA-freshness arm (the catalog port exposes
// only required_acr_min), so its deny is always the ACR arm.
func floorVerdict(t *testing.T, err error) grpcsrv.StepUpVerdict {
	t.Helper()
	if err == nil {
		return grpcsrv.StepUpAllow
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("floor must deny with PermissionDenied, got %v", err)
	}
	return grpcsrv.StepUpDenyACR
}

// TestACRFloor_VerdictParity_IAMVsSharedRule — the internal entrypoint must
// return exactly the shared rule's verdict over {principal type} × {presented
// acr} × {required acr}, machine rows included.
func TestACRFloor_VerdictParity_IAMVsSharedRule(t *testing.T) {
	principalTypes := []string{
		"",                 // absent / untrusted — never exempt (fail-closed)
		"user",             // human — never exempt
		"system",           // system fallback principal — never exempt
		"service_account",  // MACHINE — the contested branch
		"Service_Account",  // case variant — must NOT exempt (exact match only)
		"service_account ", // trailing space — must NOT exempt
		"serviceaccount",   // near-miss — must NOT exempt
	}
	acrValues := []string{"", "0", "1", "2", "3", "weird-unknown"}

	// Drive every gateway-fronted method the realistic catalog knows, so both the
	// acr_min=2 arm (GrantAdmin/RevokeAdmin/…) and the acr_min=0 arm
	// (Revoke/ForceLogout — no requirement) are covered.
	methods := []string{grantAdminMethod, revokeMethod, forceLogoutMethod}
	catalog := realisticCatalog()

	f := newACRFloor(true)
	machineRowsSeen, machineRowsAllowed := 0, 0

	for _, method := range methods {
		required := catalog[method[1:]] // catalog keys carry no leading slash
		for _, pType := range principalTypes {
			for _, presented := range acrValues {
				want := grpcsrv.EvaluateStepUp(grpcsrv.StepUpInput{
					PrincipalType: pType,
					PresentedACR:  presented,
					RequiredACR:   required,
				})
				got := floorVerdict(t, f.allow(gatewayCallerCtx(pType, presented), method))

				if want != got {
					t.Fatalf("verdict drift on %s: principal_type=%q presented=%q required=%q — shared rule says %s, iam floor says %s",
						method, pType, presented, required, verdictLabel(want), verdictLabel(got))
				}

				if pType == grpcsrv.PrincipalTypeServiceAccount {
					machineRowsSeen++
					if got == grpcsrv.StepUpAllow {
						machineRowsAllowed++
					}
				}
			}
		}
	}

	// The guard is only meaningful if it walked the contested branch.
	if machineRowsSeen == 0 {
		t.Fatal("the matrix must contain machine-principal rows")
	}
	if machineRowsAllowed != machineRowsSeen {
		t.Fatalf("every machine-principal row must be ALLOWED by the internal floor "+
			"(the exemption branch must be live): %d/%d allowed", machineRowsAllowed, machineRowsSeen)
	}
}

// TestACRFloor_VerdictParity_MachineBranch_Pinned — the contested branch pinned
// explicitly: a machine with NO acr must pass the acr_min=2 RPC that used to
// deny it forever, while a human with the same (absent) acr is still denied.
func TestACRFloor_VerdictParity_MachineBranch_Pinned(t *testing.T) {
	f := newACRFloor(true)

	if err := f.allow(gatewayCallerCtx(grpcsrv.PrincipalTypeServiceAccount, ""), grantAdminMethod); err != nil {
		t.Fatalf("machine principal must be exempt from the acr floor on %s, got %v", grantAdminMethod, err)
	}

	// MECHANISM-LOCK — the exemption must not widen beyond machines.
	for _, pType := range []string{"user", "system", ""} {
		if err := f.allow(gatewayCallerCtx(pType, ""), grantAdminMethod); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("principal_type=%q with no acr must still be denied on %s, got %v", pType, grantAdminMethod, err)
		}
	}
}

// TestACRFloor_MachineExemption_RequiresTrustedPrincipal — ANTI-SPOOF.
//
// Unlike the acr (scrubbed upstream on an unverified peer), the forwarded
// principal survives into the carrier with `trusted=false`. The floor must apply
// the trust flag itself, otherwise anyone able to reach :9091 could forge
// `x-kacho-principal-type: service_account` and skip the floor. (internalCallerPolicy
// already denies a non-gateway SAN on these RPCs — this is the second lock.)
func TestACRFloor_MachineExemption_RequiresTrustedPrincipal(t *testing.T) {
	f := newACRFloor(true)

	// A machine principal claimed by an UNTRUSTED peer: same claim, no trust.
	ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"), gatewaySAN, true)
	ctx = grpcsrv.WithTrustedPrincipal(ctx,
		operations.Principal{Type: grpcsrv.PrincipalTypeServiceAccount, ID: "sva-forged"}, false)
	ctx = grpcsrv.WithTrustedACR(ctx, "", false)

	if code := status.Code(f.allow(ctx, grantAdminMethod)); code != codes.PermissionDenied {
		t.Fatalf("an UNTRUSTED service_account claim must NOT buy the exemption; want PermissionDenied, got %v", code)
	}
}

func verdictLabel(v grpcsrv.StepUpVerdict) string {
	switch v {
	case grpcsrv.StepUpAllow:
		return "ALLOW"
	case grpcsrv.StepUpDenyACR:
		return "DENY_ACR"
	case grpcsrv.StepUpDenyAuthTimeMissing:
		return "DENY_AUTH_TIME_MISSING"
	case grpcsrv.StepUpDenyMFAStale:
		return "DENY_MFA_STALE"
	default:
		return fmt.Sprintf("verdict(%d)", v)
	}
}
