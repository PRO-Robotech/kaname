// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// caller_service.go — SAN→service-short-name helper shared by the caller policy.
//
// ServiceNameFromSAN resolves a verified SPIRE module SAN to its service
// short-name (e.g. "api-gateway"). The per-RPC CallerPolicy (caller_policy.go)
// uses it both for the floor (any kacho-<svc> SAN) and for the gateway-only set
// (svc == "api-gateway"). The former fixed-allow-list gate (CallerServiceGate)
// has been superseded by the per-RPC CallerPolicy and removed.
package authzguard

import "strings"

// ServiceNameFromSAN extracts the module service short-name from a verified SPIRE
// SAN (`spiffe://kacho.cloud/ns/<ns>/sa/kacho-<svc>` → `<svc>`). Returns
// ("", false) for any other shape (same parsing rules as SANToServiceAccountID).
func ServiceNameFromSAN(san string) (string, bool) {
	if !strings.HasPrefix(san, sanTrustPrefix) {
		return "", false
	}
	idx := strings.LastIndex(san, sanSAInfix)
	if idx < 0 {
		return "", false
	}
	saName := san[idx+len(sanSAInfix):]
	if !strings.HasPrefix(saName, svcNamePrefix) {
		return "", false
	}
	svc := strings.TrimPrefix(saName, svcNamePrefix)
	if svc == "" {
		return "", false
	}
	ns := san[len(sanTrustPrefix):idx]
	if ns == "" || strings.HasPrefix(ns, "/") {
		return "", false
	}
	return svc, true
}
