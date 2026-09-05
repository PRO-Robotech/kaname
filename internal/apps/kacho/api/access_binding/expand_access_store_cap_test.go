// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// expand_access_store_cap_test.go — ExpandAccess must never report a complete
// answer it cannot vouch for.
//
// # The defect this was written against
//
// The grant store of the day bounded its principal enumeration SERVER-side and
// returned NO continuation token: past that many grantees the response was an
// arbitrary prefix with no way to ask for the rest. A truncation flag computed by
// comparing the answer's length against OUR OWN trim could never observe that — our
// trim is at least as large as anything the store hands back, so the comparison was
// false by construction and the audit read "these are all the principals" over a
// prefix.
//
// # Why the probe stays after that store was removed
//
// Stage S6 removed the external engine. Its replacement enumerates BY PAGE WITH A
// CURSOR, so it has no incomplete answer to confess, and the second result of
// ListUsers is honestly false today — the defect above cannot be produced by the
// wiring in production.
//
// What is pinned here is not that store; it is the USE-CASE's contract: whatever the
// source says about completeness reaches the caller unchanged. That contract has a
// producer — the port's second result — and this probe is the only thing keeping
// ExpandAccess from swallowing it. Swallowing would be invisible for exactly as long
// as the production source reports false, and would surface as a silently-complete
// audit the day any source cannot vouch for its answer again.
//
// The lock is at the observable level: a grantee set the source declares cut must
// come back declared incomplete — never as complete.

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// listUsersCeiling — the size at which this fixture's source declares its answer
// cut. The number was the removed engine's default enumeration bound; it is kept
// because it is a realistic order of magnitude for a grantee set, not because
// anything in the tree still enforces it.
const listUsersCeiling = 1000

// cappedLister models a source at its ceiling: it holds MORE grantees than the
// ceiling and hands back exactly the ceiling, reporting the cut through the second
// result — the only channel a caller has for that fact.
type cappedLister struct {
	// returned — how many entries the store hands back. Reaching the ceiling
	// means the answer was cut.
	returned int
}

func (c *cappedLister) ListUsers(_ context.Context, _, _, _ string, _ []string) ([]string, bool, error) {
	out := make([]string, 0, c.returned)
	for i := 0; i < c.returned; i++ {
		out = append(out, fmt.Sprintf("user:usr%017d", i))
	}
	// The store reports the cut itself: the answer came back at its ceiling.
	return out, c.returned >= listUsersCeiling, nil
}

// An answer cut by the store must NOT be reported as complete.
func TestExpandAccess_StoreCappedAnswer_IsNotReportedComplete(t *testing.T) {
	uc := authorizedUC(&cappedLister{returned: listUsersCeiling})

	res, truncated, err := uc.Execute(authedCtx(), "compute_instance", "inst_cap", "viewer", 0)

	require.NoError(t, err)
	assert.True(t, truncated,
		"the store cut its own answer and offers no continuation; reporting completeness "+
			"turns a prefix of the grantees into 'these are all of them'")
	assert.Len(t, res, listUsersCeiling, "the prefix itself is still returned")
}

// Raising our own ceiling cannot widen a store-capped answer — and must not turn
// the truncation flag off.
func TestExpandAccess_StoreCappedAnswer_MaxResultsAboveCapStillTruncated(t *testing.T) {
	uc := authorizedUC(&cappedLister{returned: listUsersCeiling})

	_, truncated, err := uc.Execute(authedCtx(), "compute_instance", "inst_cap", "viewer", 10000)

	require.NoError(t, err)
	assert.True(t, truncated,
		"asking for more than the store will ever return does not make the answer complete")
}

// No weakening: an answer the store did NOT cut is still reported as complete,
// so the flag keeps meaning something.
func TestExpandAccess_ShortAnswer_ReportedComplete(t *testing.T) {
	uc := authorizedUC(&cappedLister{returned: 3})

	res, truncated, err := uc.Execute(authedCtx(), "compute_instance", "inst_small", "viewer", 0)

	require.NoError(t, err)
	assert.False(t, truncated, "an uncut answer must stay complete — otherwise the flag says nothing")
	assert.Len(t, res, 3)
}
