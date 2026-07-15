// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package seed

// verify_gate_fgaobject_test.go — review #5: the verify-gate's forward-smoke
// ledger-lookup object MUST be derived through the SAME canonical authzmap mapping
// the reconciler uses to WRITE the ledger row, not a divergent hand-rolled
// dotted→underscore byte substitution. For the majority of real closed-table types
// the naive `.`→`_` replacement diverges from the canonical FGA object_type
// (vpc.securityGroup → vpc_security_group, NOT vpc_securityGroup; iam.account →
// account, NOT iam_account), so a byte-loop lookup would silently miss the
// reconciler-written ledger row and the contract-phase gate would falsely report a
// forward-path regression. This test pins the gate's object derivation to
// authzmap.FGAObjectType for the divergent types.

import (
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/stretchr/testify/assert"
)

func TestVerifyGate_FGAObject_MatchesCanonicalAuthzmap(t *testing.T) {
	// Representative divergent dotted types: a naive `.`→`_` substitution would NOT
	// match the canonical reconciler-written FGA object_type for any of these.
	dotted := []string{
		"vpc.network",          // coincides ("vpc_network") — control
		"vpc.securityGroup",    // canonical "vpc_security_group" (byte-loop: "vpc_securityGroup")
		"vpc.routeTable",       // canonical "vpc_route_table"
		"vpc.networkInterface", // canonical "vpc_network_interface"
		"iam.account",          // canonical bare "account" (byte-loop: "iam_account")
		"iam.project",          // canonical bare "project"
		"iam.serviceAccount",   // canonical "iam_service_account"
		"compute.instance",     // canonical "compute_instance"
	}
	for _, d := range dotted {
		want, ok := authzmap.FGAObjectType(d)
		assert.True(t, ok, "authzmap must resolve closed-table type %q", d)

		got := fgaObjectForSmoke(d, "X")
		assert.Equal(t, want+":X", got,
			"verify-gate forward-smoke object for %q must equal the canonical authzmap-derived FGA object the reconciler records (no hand-rolled byte substitution)", d)
	}

	// Unknown / multi-dot keys: NO ledger row can ever exist (the reconciler never
	// records them), so the gate must yield an empty object (lookup that can't match)
	// rather than an arbitrary fabricated FGA object.
	assert.Empty(t, fgaObjectForSmoke("not.a.real.type", "Y"),
		"unknown closed-table type must not fabricate an FGA object")
}
