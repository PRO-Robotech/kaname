// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package auditlistfilter states how kacho-iam is laid out for the public-List
// gate. The analysis itself — and why it parses instead of grepping — lives in
// tools/listfiltergate.
//
// # Why iam was outside this gate, and why that was the wrong place to be outside
//
// The CI step that drives this class looped over compute, nlb, registry, storage
// and vpc. iam was absent — while carrying the largest narrowable List surface on
// the platform (ten resources declare `List`, against seven in vpc). The blind
// spot sat exactly where the subject is densest.
//
// # This service's shape
//
// Identical to vpc and nlb: one package per resource under
// internal/apps/kacho/api, each declaring the transport type `Handler`. The
// resource name is the directory.
//
// # What proves the page was narrowed
//
// iam's per-object primitive is authzfilter.VisibleSet / authzfilter.Visible
// (internal/authzfilter/visibility.go) — the `viewer ∪ v_list` union asked per
// object of the page just read. Both names are accepted, and so are the two
// package-level helpers that every resource routes through them, because the
// analyser follows package-level functions and methods on package-local types
// but stops at a field whose type is qualified.
//
// # Banned
//
// The enumeration shape — ask the authorization store for every object the
// subject may see, then narrow SQL to that prefix — is capped server-side with no
// continuation, so a tenant's own row silently falls outside it and becomes
// invisible for good.
//
// iam is a special case here and the ban still holds: iam OWNS the store client
// and IMPLEMENTS `AuthorizeService.ListObjects` as a public RPC of its own
// (api/authorize). That package declares no method named `List`, so it is not a
// resource of this gate, and nothing reachable from any `Handler.List` calls it —
// verified, not assumed. The ban therefore catches "an iam List narrows its page
// by enumerating" without touching "iam serves the enumeration RPC".
package auditlistfilter

import "github.com/PRO-Robotech/kacho/tools/listfiltergate"

// Profile describes kacho-iam to the analyser.
var Profile = listfiltergate.Profile{
	Service:    "iam",
	AnchorRoot: "internal/apps/kacho/api",
	// One package per resource, all declaring the same transport type.
	PerPackage:     true,
	ReceiverSuffix: "Handler",
	// VisibleSet/Visible are the primitive; the two names below are the helpers
	// through which the resources reach it.
	Filters: []string{"VisibleSet", "Visible", "visibleBindingIDsOnPage", "filterVisibleBindings"},
	Banned:  []string{"ListAllowedIDs", "ListObjects"},
}
