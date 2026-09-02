// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// read_page_cost_test.go — role reads resolve visibility PER OBJECT, and their
// cost follows what is being READ, never the population of the type.
//
// # What this file used to assert, and why that statement no longer exists
//
// Its earlier name (fga_listobjects_cap_test.go) named the defect it was written
// against. The external relation engine answered "enumerate every object of this
// type the subject may see" with a server-side cap and NO continuation token, so a
// tenant's own custom role could fall outside the returned prefix and become
// permanently invisible — Get → NOT_FOUND, List → absent — while the row existed
// and the grant existed. The fake reproduced that asymmetry by offering a
// truncating enumeration beside an honest per-object oracle, and the assertions
// read: the enumeration was never called.
//
// The engine was removed in stage S6, and the enumeration went with it.
// clients.RelationQueries now carries CheckWithContext, BatchCheckWithContext and
// ListSubjects — there is no method that enumerates objects, so no iam read can
// call one. A counter of enumeration calls would therefore have NO PRODUCER:
// "the enumeration was not called" would be true by construction of the fake's own
// type and could not go red on anything. Such a test is worse than an absent one —
// it holds a slot and reports green.
//
// # What is asserted instead
//
// The live property is the same one, measured by something that does have a
// producer: COST. The number of per-object questions a read asks must be bounded by
// what is being read — the single role for Get, the rows of the page for List — and
// must not follow how many objects of the type the subject happens to hold. The
// fixture makes the two numbers impossible to confuse: the subject is granted
// roleTypePopulation objects while exactly ONE custom role exists in the
// repository, so a population-shaped read costs a thousand questions and a
// page-shaped read costs at most two.
//
// # One source of truth
//
// Every door of the fake answers from ONE grant set, so nothing here can pass by
// weakening authorization: an id outside that set is refused on every path at once.

import (
	"context"
	"fmt"
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

// roleTypePopulation — how many iam_role objects the subject is granted besides
// the single custom role that actually exists in the repository.
//
// The value is the cap the removed enumeration used to carry, kept deliberately:
// it is three orders of magnitude away from any page this test reads, so a read
// whose cost followed the population could never be mistaken for one whose cost
// follows the page.
const roleTypePopulation = 1000

// pageCostRoleRelations — fake clients.RelationQueries.
//
// The port is EMBEDDED rather than fully implemented on purpose: a method these
// reads do not use stays unimplemented instead of receiving a lenient stand-in.
// A fake wider than its subject hides exactly the drift it is placed to catch.
type pageCostRoleRelations struct {
	clients.RelationQueries
	granted map[string]bool // "<relation>|<object>"

	// objectCalls counts questions about a ROW being read. subjectCalls counts the
	// one asked about the CALLER ("is he a cloud administrator", #645).
	//
	// They are counted apart because they scale differently and mixing them loses
	// both statements: the per-row number must not follow the population, the
	// per-request number must be a constant. A single total can be kept under a
	// bound by either of them shrinking while the other grows.
	objectCalls  atomic.Int64
	subjectCalls atomic.Int64
}

// newPageCostRoleRelations grants `v_list` on the given bare iam_role ids.
func newPageCostRoleRelations(vlistIDs ...string) *pageCostRoleRelations {
	g := make(map[string]bool, len(vlistIDs))
	for _, id := range vlistIDs {
		g["v_list|iam_role:"+id] = true
	}
	return &pageCostRoleRelations{granted: g}
}

func (c *pageCostRoleRelations) CheckWithContext(_ context.Context, _, relation, object string,
	_ map[string]any) (bool, error) {
	if relation == "system_admin" {
		c.subjectCalls.Add(1)
	} else {
		c.objectCalls.Add(1)
	}
	return c.granted[relation+"|"+object], nil
}

// BatchCheckWithContext — the batched door onto the SAME oracle CheckWithContext
// answers from, so a verdict cannot depend on which door the filter chose.
//
// It is not optional politeness: authzfilter takes its batched path whenever the
// checker offers this method, so a fake omitting it would leave every test in this
// file exercising a code path production does not take.
//
// The refusal above authzfilter.MaxBatchChecksPerRequest keeps the fake from being
// SLACKER than the declaration it stands behind: that constant is the partition
// size authzfilter itself declares and splits a page against, so a filter that
// stopped honouring its own declaration goes red here instead of quietly changing
// the shape of the request. An error, never a trim — a short answer is
// indistinguishable from a page of denials, and a page of silent denials is the
// permanent-invisibility defect this file exists against.
func (c *pageCostRoleRelations) BatchCheckWithContext(ctx context.Context, subject, relation string,
	objects []string, condCtx map[string]any) ([]bool, error) {
	if len(objects) > authzfilter.MaxBatchChecksPerRequest {
		return nil, fmt.Errorf("batch of %d objects exceeds the declared partition size %d",
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

// crowdedRoleScenario builds a grant set far larger than any page, plus a repo
// holding the ONE custom role that really exists. The owned id sorts AFTER every
// filler id — the position the removed enumeration used to erase, kept so the
// fixture still describes the shape of the original defect.
func crowdedRoleScenario(t *testing.T) (*roleListFakeRepo, *pageCostRoleRelations, string) {
	t.Helper()

	const ownedID = "rol00000000000zowned" // sorts after every all-numeric filler

	grantedIDs := make([]string, 0, roleTypePopulation+1)
	for i := 0; i < roleTypePopulation; i++ {
		grantedIDs = append(grantedIDs, fmt.Sprintf("rol%017d", i))
	}
	grantedIDs = append(grantedIDs, ownedID)

	repo := newRoleListFakeRepo()
	seedCustomRole(repo, ownedID, "acc-A000000000000000")

	return repo, newPageCostRoleRelations(grantedIDs...), ownedID
}

// Get of the caller's OWN granted custom role must succeed, and must cost what
// reading ONE role costs.
func TestGetRole_OwnRoleAmongACrowdedType(t *testing.T) {
	repo, rel, ownedID := crowdedRoleScenario(t)

	uc := NewGetRoleUseCase(repo).WithRelationStore(rel)
	got, err := uc.Execute(ctxUser("usr-u1"), domain.RoleID(ownedID))

	require.NoError(t, err, "granted, existing custom role must be readable by id")
	assert.Equal(t, ownedID, string(got.ID))
	assert.LessOrEqual(t, rel.objectCalls.Load(), int64(2),
		"Get asked more questions than reading ONE role can need (iam_role is gated by "+
			"at most two relations): its cost followed the population of the type, not the "+
			"object being read — a thousand granted objects sit alongside precisely so "+
			"those two numbers cannot be confused")
}

// List must contain the caller's OWN granted custom role, and must cost what
// reading THIS PAGE costs.
func TestListRoles_OwnRoleAmongACrowdedType(t *testing.T) {
	repo, rel, ownedID := crowdedRoleScenario(t)

	uc := NewListRolesUseCase(repo).WithRelationStore(rel)
	out, _, err := uc.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100})

	require.NoError(t, err)
	assert.Contains(t, roleIDs(out), ownedID,
		"granted, existing custom role must appear in List; its absence means the page is "+
			"filtered by something other than the page itself")
	assert.LessOrEqual(t, rel.objectCalls.Load(), int64(2),
		"visibility must be resolved for the rows ON THE PAGE only (1 custom role, ≤2 relations)")
	assert.Equal(t, int64(1), rel.subjectCalls.Load(),
		"the question about the CALLER is asked once per request, outside any per-row loop")
}

// A page carrying only the catalog floor asks NOTHING about objects.
//
// This is the other half of the same property and it is needed separately: a read
// whose cost followed the population would ask its questions even when there is no
// custom row to judge, and the assertions above — which bound the cost from above —
// would stay green on a page that legitimately has nothing to judge.
func TestListRoles_SystemOnlyPageAsksNothingAboutObjects(t *testing.T) {
	repo := newRoleListFakeRepo()
	seedSystemRole(repo, "rol0000000000000sys1")
	seedSystemRole(repo, "rol0000000000000sys2")
	rel := newPageCostRoleRelations() // grants nothing at all

	uc := NewListRolesUseCase(repo).WithRelationStore(rel)
	out, _, err := uc.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100})

	require.NoError(t, err)
	assert.Len(t, roleIDs(out), 2, "system roles are the tenant-wide catalog floor")
	assert.Zero(t, rel.objectCalls.Load(),
		"a page with no custom row was still asked about objects — the questions are not "+
			"being asked about the page")
}

// No weakening: an ungranted custom role stays absent from List and NOT_FOUND on
// Get, and a system role stays the catalog floor (no relation question at all).
func TestRoleReads_UngrantedCustomStaysInvisibleInACrowdedType(t *testing.T) {
	repo, rel, _ := crowdedRoleScenario(t)
	seedCustomRole(repo, "rol0000000000000scrt", "acc-A000000000000000") // never granted
	seedSystemRole(repo, "rol0000000000000sys1")

	t.Run("List omits the ungranted custom role but keeps system", func(t *testing.T) {
		uc := NewListRolesUseCase(repo).WithRelationStore(rel)
		out, _, err := uc.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100})
		require.NoError(t, err)
		ids := roleIDs(out)
		assert.NotContains(t, ids, "rol0000000000000scrt", "ungranted custom role must stay hidden")
		assert.Contains(t, ids, "rol0000000000000sys1", "system roles stay the catalog floor")
	})

	t.Run("Get of the ungranted custom role is NOT_FOUND", func(t *testing.T) {
		uc := NewGetRoleUseCase(repo).WithRelationStore(rel)
		got, err := uc.Execute(ctxUser("usr-u1"), domain.RoleID("rol0000000000000scrt"))
		require.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err),
			"ungranted custom → NOT_FOUND (no existence leak)")
		assert.Empty(t, got.Rules, "no body leak on deny")
	})
}
