// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// caller_service.go — SAN→service-short-name helper shared by the caller policy.
//
// ServiceNameFromSAN resolves a verified SPIRE module SAN to its service
// short-name (e.g. "api-gateway"). The per-RPC CallerPolicy (caller_policy.go)
// uses it both for the floor (any kacho-<svc> SAN) and for the gateway-only set
// (svc == "api-gateway"). The former fixed-allow-list gate (CallerServiceGate)
// has been superseded by the per-RPC CallerPolicy and removed.
package authzguard

import "github.com/PRO-Robotech/kacho/pkg/grpcsrv"

// ServiceNameFromSAN extracts the module service short-name from a verified SPIRE
// SAN (`spiffe://<trust-domain>/ns/<ns>/sa/kacho-<svc>` → `<svc>`). Returns
// ("", false) for any other shape.
//
// # Одна реализация, а не две
//
// Здесь стояла ПОБАЙТОВАЯ КОПИЯ тела [SANToServiceDomain] — двадцать строк,
// повторяющих тот же разбор. Расходятся такие копии молча: правка одной не
// доезжает до другой, и вторая продолжает принимать то, что первая уже
// отвергает. Свели их вместе с переводом домена доверия в величину — иначе
// литерал пришлось бы снимать дважды, а копия осталась бы поводом завести его
// снова.
func ServiceNameFromSAN(d grpcsrv.TrustDomain, san string) (string, bool) {
	return SANToServiceDomain(d, san)
}
