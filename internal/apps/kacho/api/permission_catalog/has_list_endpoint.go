// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package permission_catalog

// has_list_endpoint.go — the curated, closed "(module,resource) → has a PUBLIC
// per-object filtered List on the api-gateway EXTERNAL listener?" table.
//
// This is the single backend source of the catalog's `hasListEndpoint` flag;
// the UI does NOT keep a second copy. The resourceNames picker renders a
// Select of caller-visible instances ONLY when hasListEndpoint=true; otherwise
// it falls back to a free-text id input.
//
// LOCKSTEP DISCIPLINE (non-blocking, but a real maintenance contract):
// this table MUST stay in lockstep with kacho-api-gateway PUBLIC-mux
// registration (internal/restmux/mux.go). A (module,resource) is `true` here
// IFF the api-gateway registers its per-object filtered List<Resource> on the
// EXTERNAL listener. Two deliberate `false` cases (both grantable + verb-bearing
// in objectTypes, so they DO appear in the catalog, but with hasListEndpoint=false):
//
//   - vpc.addressPool — AddressPool is an admin Internal-only resource.
//     Its only List is
//     InternalAddressPoolService.List on the cluster-internal :9091 mux — there
//     is NO public per-object List on the external listener. SECURITY:
//     a Select here would have the UI dial a non-existent external List (404 /
//     route-not-allowed) or, worse, surface the admin Internal surface. So the
//     picker MUST render free-text and NEVER a Select for addressPool.
//   - iam.condition — ConditionsService.List exists in proto (GET
//     /iam/v1/conditions) but is NOT registered on the api-gateway external mux
//     (the catalog filters EXISTING public Lists per-object; it does not promise
//     to REGISTER new public routes). Internal/unregistered → false.
//
// Modelled as an explicit DENY-set rather than an ALLOW-set so a future
// objectTypes addition defaults to `true` (the common case — most grantable
// leaves have a public List) and only the rare Internal-only / unregistered
// types are enumerated here. A new admin-Internal-only grantable type MUST be
// added to noPublicListEndpoint when introduced (mirrored against the gateway
// public-mux registration), the same lockstep discipline objectTypes itself has
// with fga_model.fga.

// noPublicListEndpoint — the closed set of dotted "module.resource" keys whose
// only List is NOT a public per-object filtered List on the external gateway
// listener (Internal-only, or not registered on the external mux). Everything
// else in authzmap.objectTypes has hasListEndpoint=true.
var noPublicListEndpoint = map[string]bool{
	// AddressPool — Internal-only admin resource (List on :9091, not external).
	"vpc.addressPool": true,
	// ConditionsService.List exists in proto but is NOT on the external mux.
	"iam.condition": true,
}

// hasPublicListEndpoint reports whether (module,resource) has a PUBLIC per-object
// filtered List on the api-gateway external listener. The default is true; only
// the curated Internal-only / unregistered exceptions are false.
func hasPublicListEndpoint(module, resource string) bool {
	return !noPublicListEndpoint[module+"."+resource]
}
