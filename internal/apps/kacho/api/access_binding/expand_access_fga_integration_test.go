// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// expand_access_fga_integration_test.go — real-OpenFGA proof that ExpandAccess
// resolves a GROUP userset
// into concrete member principals. Reuses the scope_grant real-FGA harness
// (startOpenFGA / fgaClient).

import (
	"context"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	abrepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

// realFGAFromHarness builds a production OpenFGAHTTPClient pointed at the test
// OpenFGA server started by startOpenFGA (the client's Endpoint is host:port,
// no scheme — the client prefixes http:// itself).
func realFGAFromHarness(t *testing.T, c *fgaClient) *clients.OpenFGAHTTPClient {
	t.Helper()
	endpoint := strings.TrimPrefix(c.base, "http://")
	// sanity: endpoint must be host:port
	if _, _, err := net.SplitHostPort(endpoint); err != nil {
		t.Fatalf("unexpected fga base %q: %v", c.base, err)
	}
	return &clients.OpenFGAHTTPClient{
		Endpoint:           endpoint,
		StoreID:            c.store,
		AuthorizationModel: c.modelID,
	}
}

// TestExpandAccess_E31_GroupExpandsToMembers — a binding granting `viewer` on an
// account to a GROUP, plus the group→member tuples, expands to the concrete
// member principals (not the group).
func TestExpandAccess_E31_GroupExpandsToMembers(t *testing.T) {
	c := startOpenFGA(t)
	c.write(t, hierarchyTuples())

	// Grant `viewer` on account:acc_A to group:grp_team#member, and wire two
	// members into the group. The auditor holds `admin` on account:acc_A — the
	// per-object grant-authority gate requires it before the expand.
	c.write(t, []abrepo.RelationTuple{
		{User: "group:grp_team#member", Relation: "viewer", Object: "account:acc_A"},
		{User: "user:usr_m1", Relation: "member", Object: "group:grp_team"},
		{User: "user:usr_m2", Relation: "member", Object: "group:grp_team"},
		{User: "user:usr_auditor", Relation: "admin", Object: "account:acc_A"},
	})

	fga := realFGAFromHarness(t, c)
	// repo nil — authority resolves purely through the FGA admin path (Path 2).
	uc := NewExpandAccessUseCase(fga).WithGrantAuthority(nil, fga, nil)
	ctx := operations.WithPrincipal(context.Background(), operations.Principal{ID: "usr_auditor", Type: "user"})

	principals, truncated, err := uc.Execute(ctx, "account", "acc_A", "viewer", 0)
	require.NoError(t, err)
	assert.False(t, truncated)

	ids := map[string]struct{}{}
	for _, p := range principals {
		ids[string(p.ID)] = struct{}{}
		assert.NotContains(t, string(p.ID), "grp_", "a group userset must NOT be a principal (E-31)")
	}
	assert.Contains(t, ids, "usr_m1", "group member usr_m1 must appear as a concrete principal")
	assert.Contains(t, ids, "usr_m2", "group member usr_m2 must appear as a concrete principal")
}

// TestExpandAccess_В3_ForeignObject_DeniedRealFGA — real-OpenFGA proof of the
// per-object grant-authority gate. The auditor
// holds `admin` on account:acc_A but NOT on account:acc_B. Expanding acc_B (a
// foreign object) must be DENIED with PERMISSION_DENIED, and NO effective
// principals are leaked — even though acc_B genuinely carries a viewer grant whose
// userset would otherwise resolve to a concrete principal.
func TestExpandAccess_В3_ForeignObject_DeniedRealFGA(t *testing.T) {
	c := startOpenFGA(t)
	c.write(t, hierarchyTuples())

	c.write(t, []abrepo.RelationTuple{
		// auditor is admin on acc_A only.
		{User: "user:usr_auditor", Relation: "admin", Object: "account:acc_A"},
		// acc_B carries a real viewer grant whose member would be revealed by an
		// unguarded expand.
		{User: "user:usr_secret_b", Relation: "viewer", Object: "account:acc_B"},
	})

	fga := realFGAFromHarness(t, c)
	uc := NewExpandAccessUseCase(fga).WithGrantAuthority(nil, fga, nil)
	ctx := operations.WithPrincipal(context.Background(), operations.Principal{ID: "usr_auditor", Type: "user"})

	// Sanity: the auditor CAN expand acc_A (has admin there).
	_, _, err := uc.Execute(ctx, "account", "acc_A", "viewer", 0)
	require.NoError(t, err, "auditor holds admin on acc_A → expand allowed")

	// The foreign object acc_B must be denied — no leak of usr_secret_b.
	principals, _, err := uc.Execute(ctx, "account", "acc_B", "viewer", 0)
	require.Error(t, err, "ExpandAccess on a foreign object MUST be denied (В3)")
	assert.Equal(t, codes.PermissionDenied, status.Code(err),
		"unauthorized expand → PERMISSION_DENIED")
	assert.Empty(t, principals, "no effective principals leaked on a foreign object")
}
