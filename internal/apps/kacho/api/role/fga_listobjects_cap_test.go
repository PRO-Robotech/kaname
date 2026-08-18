// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// fga_listobjects_cap_test.go — regression: the OpenFGA ListObjects hard cap
// silently truncates a tenant's OWN custom Role out of existence.
//
// OpenFGA bounds ListObjects server-side (OPENFGA_LIST_OBJECTS_MAX_RESULTS,
// default 1000) and offers NO continuation token, so "enumerate every id the
// subject may see, then match against it" is capped at 1000 objects PER TYPE
// PER STORE — cluster-wide, not per-tenant. A custom role outside the returned
// prefix becomes permanently invisible: Get → NOT_FOUND, List → absent, while
// the row and the grant both exist.
//
// The fake reproduces the asymmetry at the OpenFGA transport boundary:
//   - ListObjects       → truncating enumeration (what OpenFGA really does);
//   - CheckWithContext  → honest per-object oracle (same grants, no cap).
//
// Both answer from ONE authoritative grant set, so the test cannot pass by
// weakening authorization.

import (
	"context"
	"fmt"
	"sort"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzfilter"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	reporole "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
)

// roleFGAListObjectsCap mirrors OpenFGA's default OPENFGA_LIST_OBJECTS_MAX_RESULTS.
const roleFGAListObjectsCap = 1000

// cappedRoleFGA — fake clients.RelationQueries with the OpenFGA asymmetry.
type cappedRoleFGA struct {
	clients.RelationQueries
	granted          map[string]bool // "<relation>|<object>"
	listObjectsCalls atomic.Int64
	// checkCalls counts questions about a ROW of the page. subjectCalls counts the
	// one asked about the CALLER ("is he a cloud administrator", #645).
	//
	// They are counted apart because they scale differently and mixing them loses
	// both statements: the per-row number must not follow the population, the
	// per-request number must be a constant. A single total can be kept under a
	// bound by either of them shrinking while the other grows.
	checkCalls   atomic.Int64
	subjectCalls atomic.Int64
}

// newCappedRoleFGA grants `v_list` on the given bare iam_role ids.
func newCappedRoleFGA(vlistIDs ...string) *cappedRoleFGA {
	g := make(map[string]bool, len(vlistIDs))
	for _, id := range vlistIDs {
		g["v_list|iam_role:"+id] = true
	}
	return &cappedRoleFGA{granted: g}
}

func (c *cappedRoleFGA) ListObjects(_ context.Context, _, relation, objectType string,
	_ map[string]any, _ int) ([]string, error) {
	c.listObjectsCalls.Add(1)
	prefix := relation + "|" + objectType + ":"
	ids := make([]string, 0, len(c.granted))
	for k := range c.granted {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			ids = append(ids, k[len(prefix):])
		}
	}
	sort.Strings(ids)
	if len(ids) > roleFGAListObjectsCap {
		ids = ids[:roleFGAListObjectsCap]
	}
	return ids, nil
}

func (c *cappedRoleFGA) CheckWithContext(_ context.Context, _, relation, object string,
	_ map[string]any) (bool, error) {
	if relation == "system_admin" {
		c.subjectCalls.Add(1)
	} else {
		c.checkCalls.Add(1)
	}
	return c.granted[relation+"|"+object], nil
}

// capRoleScenario builds a grant store past the cap plus a repo holding the one
// custom role that really exists. The owned id sorts AFTER every filler id, so
// it is exactly what the truncation erases.
func capRoleScenario(t *testing.T) (*roleListFakeRepo, *cappedRoleFGA, string) {
	t.Helper()

	const ownedID = "rol00000000000zowned" // sorts after every all-numeric filler

	grantedIDs := make([]string, 0, roleFGAListObjectsCap+1)
	for i := 0; i < roleFGAListObjectsCap; i++ {
		grantedIDs = append(grantedIDs, fmt.Sprintf("rol%017d", i))
	}
	grantedIDs = append(grantedIDs, ownedID)

	repo := newRoleListFakeRepo()
	seedCustomRole(repo, ownedID, "acc-A")

	return repo, newCappedRoleFGA(grantedIDs...), ownedID
}

// Get of the caller's OWN granted custom role must succeed. Before the fix the
// enumeration truncates the id away and Get answers NOT_FOUND for a row that
// exists and is granted.
func TestGetRole_OwnRoleBeyondFGAListObjectsCap(t *testing.T) {
	repo, fga, ownedID := capRoleScenario(t)

	uc := NewGetRoleUseCase(repo).WithRelationStore(fga)
	got, err := uc.Execute(ctxUser("usr-u1"), domain.RoleID(ownedID))

	require.NoError(t, err, "granted, existing custom role must be readable by id; "+
		"404 here means visibility is gated on the truncated ListObjects enumeration")
	assert.Equal(t, ownedID, string(got.ID))
	assert.Zero(t, fga.listObjectsCalls.Load(),
		"Get must ask the DIRECT per-object question, not enumerate (O(universe), capped at 1000)")
}

// List must contain the caller's OWN granted custom role.
func TestListRoles_OwnRoleBeyondFGAListObjectsCap(t *testing.T) {
	repo, fga, ownedID := capRoleScenario(t)

	uc := NewListRolesUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100})

	require.NoError(t, err)
	assert.Contains(t, roleIDs(out), ownedID,
		"granted, existing custom role must appear in List; absence means the page "+
			"is filtered by the truncated ListObjects enumeration")
	assert.Zero(t, fga.listObjectsCalls.Load(),
		"List must resolve visibility from the PAGE, never by enumerating the universe")
	assert.LessOrEqual(t, fga.checkCalls.Load(), int64(2),
		"visibility must be checked for the rows on the page only (1 custom role, ≤2 relations)")
	assert.Equal(t, int64(1), fga.subjectCalls.Load(),
		"the question about the CALLER is asked once per request, outside any per-row loop")
}

// No weakening: an ungranted custom role stays absent from List and NOT_FOUND
// on Get, and a system role stays the catalog floor (no FGA consulted).
func TestRoleReads_UngrantedCustomStaysInvisibleUnderCap(t *testing.T) {
	repo, fga, _ := capRoleScenario(t)
	seedCustomRole(repo, "rol0000000000000scrt", "acc-A") // never granted
	seedSystemRole(repo, "rol0000000000000sys1")

	t.Run("List omits the ungranted custom role but keeps system", func(t *testing.T) {
		uc := NewListRolesUseCase(repo).WithRelationStore(fga)
		out, _, err := uc.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100})
		require.NoError(t, err)
		ids := roleIDs(out)
		assert.NotContains(t, ids, "rol0000000000000scrt", "ungranted custom role must stay hidden")
		assert.Contains(t, ids, "rol0000000000000sys1", "system roles stay the catalog floor")
	})

	t.Run("Get of the ungranted custom role is NOT_FOUND", func(t *testing.T) {
		uc := NewGetRoleUseCase(repo).WithRelationStore(fga)
		got, err := uc.Execute(ctxUser("usr-u1"), domain.RoleID("rol0000000000000scrt"))
		require.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err),
			"ungranted custom → NOT_FOUND (no existence leak)")
		assert.Empty(t, got.Rules, "no body leak on deny")
	})
}

// BatchCheckWithContext — the batched door onto the SAME oracle CheckWithContext
// answers from, so a verdict cannot depend on which door the filter chose.
//
// It is not optional politeness: authzfilter takes its batched path whenever the
// checker offers this method, so a stub that omitted it would leave every test in
// this file exercising a code path production does not take. It refuses an
// over-cap partition the way the relation store refuses one — an error, never a
// trim — so the stub is never more permissive than the thing it stands in for.
func (c *cappedRoleFGA) BatchCheckWithContext(ctx context.Context, subject, relation string,
	objects []string, condCtx map[string]any) ([]bool, error) {
	if len(objects) > authzfilter.MaxBatchChecksPerRequest {
		return nil, fmt.Errorf("batchCheck received %d checks, the maximum allowed is %d",
			len(objects), authzfilter.MaxBatchChecksPerRequest)
	}
	out := make([]bool, len(objects))
	for i, object := range objects {
		allowed, err := c.CheckWithContext(ctx, subject, relation, object, condCtx)
		if err != nil {
			return nil, err
		}
		out[i] = allowed
	}
	return out, nil
}
