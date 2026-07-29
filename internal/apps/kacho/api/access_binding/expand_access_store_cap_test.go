// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// expand_access_store_cap_test.go — ExpandAccess must never report a complete
// answer it cannot vouch for.
//
// The grant store bounds its principal enumeration SERVER-side
// (OPENFGA_LIST_USERS_MAX_RESULTS, default 1000) and returns NO continuation
// token: past that many grantees the response is an arbitrary prefix and there
// is no way to ask for the rest. A truncation flag computed by comparing the
// answer's length against OUR OWN trim can never observe that — our trim is at
// least as large as anything the store will hand back, so the comparison is
// false by construction and the audit reads "these are all the principals" over
// a prefix.
//
// The lock is at the observable level: an object whose grantee set reaches the
// store's ceiling must come back declared incomplete — never as complete.

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fgaListUsersServerCap mirrors OpenFGA's default OPENFGA_LIST_USERS_MAX_RESULTS
// — the ceiling the store applies to its own answer.
const fgaListUsersServerCap = 1000

// cappedLister models the store at its ceiling: it holds MORE grantees than the
// cap and hands back exactly the cap, with nothing in the payload to say there
// is more — precisely what OpenFGA does.
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
	return out, c.returned >= fgaListUsersServerCap, nil
}

// An answer cut by the store must NOT be reported as complete.
func TestExpandAccess_StoreCappedAnswer_IsNotReportedComplete(t *testing.T) {
	uc := authorizedUC(&cappedLister{returned: fgaListUsersServerCap})

	res, truncated, err := uc.Execute(authedCtx(), "compute_instance", "inst_cap", "viewer", 0)

	require.NoError(t, err)
	assert.True(t, truncated,
		"the store cut its own answer and offers no continuation; reporting completeness "+
			"turns a prefix of the grantees into 'these are all of them'")
	assert.Len(t, res, fgaListUsersServerCap, "the prefix itself is still returned")
}

// Raising our own ceiling cannot widen a store-capped answer — and must not turn
// the truncation flag off.
func TestExpandAccess_StoreCappedAnswer_MaxResultsAboveCapStillTruncated(t *testing.T) {
	uc := authorizedUC(&cappedLister{returned: fgaListUsersServerCap})

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
