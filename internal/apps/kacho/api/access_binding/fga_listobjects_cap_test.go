// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// fga_listobjects_cap_test.go — regression: the OpenFGA ListObjects hard cap
// silently truncates a tenant's OWN AccessBinding out of existence.
//
// OpenFGA bounds ListObjects server-side (OPENFGA_LIST_OBJECTS_MAX_RESULTS,
// default 1000) and offers NO continuation token. Any authz path shaped as
// "enumerate every id the subject may see, then match/filter against it" is
// therefore capped at 1000 objects PER TYPE PER STORE — cluster-wide, not
// per-tenant (the live stand already holds 3693 iam_access_binding tuples). On
// such a store the enumeration returns an arbitrary 1000-id prefix and a
// binding outside that prefix becomes permanently invisible: Get → 403 and
// List → absent, while the row exists and the grant exists.
//
// The fake below reproduces exactly that asymmetry at the OpenFGA transport
// boundary — the boundary the defect lives at, so the SAME test body holds
// before and after the fix:
//   - ListObjects       → the truncating enumeration (what OpenFGA really does);
//   - CheckWithContext  → the honest per-object oracle (same grants, no cap).
//
// Both answer from ONE authoritative `granted` set, so the test can never pass
// by weakening authorization: an id absent from `granted` is denied by both.

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
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

// fgaListObjectsCap mirrors OpenFGA's default OPENFGA_LIST_OBJECTS_MAX_RESULTS.
const fgaListObjectsCap = 1000

// cappedFGAQueries — fake clients.RelationQueries with the OpenFGA asymmetry.
type cappedFGAQueries struct {
	clients.RelationQueries
	// granted — the authoritative truth: "<relation>|<object>" the subject holds.
	granted map[string]bool
	// listObjectsCalls / checkCalls — cost observability for the
	// "read must not enumerate the universe" regression.
	listObjectsCalls atomic.Int64
	checkCalls       atomic.Int64
}

// newCappedFGAQueries grants `viewer` on nothing and the READ relation on the given bare
// ids of type iam_access_binding (the D-6 label-selector grant shape).
func newCappedFGAQueries(vlistIDs ...string) *cappedFGAQueries {
	g := make(map[string]bool, len(vlistIDs))
	for _, id := range vlistIDs {
		g["v_get|iam_access_binding:"+id] = true
	}
	return &cappedFGAQueries{granted: g}
}

// ListObjects returns the truncated 1000-id prefix, exactly as OpenFGA does:
// the full authorised set sorted, then cut at the hard cap. No page token —
// OpenFGA's ListObjects has none, which is why the truncation is silent.
func (c *cappedFGAQueries) ListObjects(_ context.Context, _, relation, objectType string,
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
	if len(ids) > fgaListObjectsCap {
		ids = ids[:fgaListObjectsCap]
	}
	return ids, nil
}

// CheckWithContext answers each (subject, relation, object) DIRECTLY from the
// same authoritative set — no cap, no enumeration.
func (c *cappedFGAQueries) CheckWithContext(_ context.Context, _, relation, object string,
	_ map[string]any) (bool, error) {
	c.checkCalls.Add(1)
	return c.granted[relation+"|"+object], nil
}

// capBindingScenario builds a grant store whose iam_access_binding population
// exceeds the FGA cap and returns (repo, fga, ownedID). ownedID sorts AFTER
// every filler id, so it is exactly what the truncation erases.
//
// ownedID is the ONLY binding that exists as a row; the 1000 filler ids are
// grant-store objects of the same type belonging to the rest of the
// (long-lived) cluster — the real-world shape.
func capBindingScenario(t *testing.T) (*abFakeRepo, *cappedFGAQueries, domain.AccessBindingID) {
	t.Helper()

	const accountID = "acc00000000000cap01a"
	// "acb00000000000zowned" sorts after every all-numeric filler suffix.
	const ownedID = domain.AccessBindingID("acb00000000000zowned")

	grantedIDs := make([]string, 0, fgaListObjectsCap+1)
	for i := 0; i < fgaListObjectsCap; i++ {
		grantedIDs = append(grantedIDs, fmt.Sprintf("acb%017d", i))
	}
	grantedIDs = append(grantedIDs, string(ownedID))

	fga := newCappedFGAQueries(grantedIDs...)

	repo := newABFakeRepo("usr_acct_owner", accountID, "", "rol_v", "kacho.view", nil)
	owned := domain.AccessBinding{
		ID:           ownedID,
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID("usr_other"), // NOT the caller → self-floor cannot mask the bug
		RoleID:       domain.RoleID("rol_v"),
		ResourceType: domain.ResourceType("account"),
		ResourceID:   accountID,
	}
	repo.mu.Lock()
	repo.ab = &owned
	repo.lbsRows = []domain.AccessBinding{owned}
	repo.mu.Unlock()
	return repo, fga, ownedID
}

// capCallerCtx — the authenticated grantee (neither the binding's subject nor a
// scope authority; visibility comes ONLY from the label grant's read relation).
func capCallerCtx() context.Context { return newOwnerContext("usr_grantee") }

// Get of the caller's OWN granted binding must succeed. Before the fix the
// enumeration truncates the id away and Get answers PermissionDenied for a row
// that exists and is granted — the reported defect, at the observable level.
func TestABGet_OwnBindingBeyondFGAListObjectsCap(t *testing.T) {
	repo, fga, ownedID := capBindingScenario(t)

	uc := NewGetAccessBindingUseCase(repo).
		WithRelationStore(&scopedFGA{allow: map[string]bool{}}, nil). // no scope authority
		WithRelationQueries(fga)

	got, err := uc.Execute(capCallerCtx(), ownedID)

	require.NoError(t, err, "granted, existing binding must be readable by id; "+
		"403 here means visibility is gated on the truncated ListObjects enumeration")
	assert.Equal(t, ownedID, got.ID)
}

// Read-by-id must ask the DIRECT per-object question, never enumerate.
func TestABGet_DoesNotEnumerateUniverse(t *testing.T) {
	repo, fga, ownedID := capBindingScenario(t)

	uc := NewGetAccessBindingUseCase(repo).
		WithRelationStore(&scopedFGA{allow: map[string]bool{}}, nil).
		WithRelationQueries(fga)

	_, err := uc.Execute(capCallerCtx(), ownedID)
	require.NoError(t, err)
	assert.Zero(t, fga.listObjectsCalls.Load(),
		"Get must not call ListObjects (O(universe), capped at 1000)")
}

// List must contain the caller's OWN granted binding. Before the fix the row is
// filtered out because its id is not in the truncated enumeration.
func TestABList_OwnBindingBeyondFGAListObjectsCap(t *testing.T) {
	repo, fga, ownedID := capBindingScenario(t)

	uc := NewListUseCase(repo).
		WithRelationStore(&scopedFGA{allow: map[string]bool{}}).
		WithRelationQueries(fga)

	rows, _, err := uc.Execute(capCallerCtx(), repoab.ListFilter{PageSize: 100})
	require.NoError(t, err)
	assert.Contains(t, abIDs(rows), string(ownedID),
		"granted, existing binding must appear in List; absence means the page "+
			"is filtered by the truncated ListObjects enumeration")
}

// Cost regression: List must resolve visibility from the PAGE, never by
// enumerating every object the subject may see.
func TestABList_DoesNotEnumerateUniverse(t *testing.T) {
	repo, fga, _ := capBindingScenario(t)

	uc := NewListUseCase(repo).
		WithRelationStore(&scopedFGA{allow: map[string]bool{}}).
		WithRelationQueries(fga)

	_, _, err := uc.Execute(capCallerCtx(), repoab.ListFilter{PageSize: 100})
	require.NoError(t, err)

	assert.Zero(t, fga.listObjectsCalls.Load(),
		"List must not call ListObjects (O(universe), capped at 1000)")
	assert.LessOrEqual(t, fga.checkCalls.Load(), int64(2),
		"visibility must be checked for the rows on the page only (1 row seeded, ≤2 relations)")
}

// No weakening: an existing binding the caller was never granted stays absent
// from List and unreadable by id. This is the guard that stops the fix from
// "solving" truncation by simply showing everything.
func TestABReads_UngrantedBindingStaysInvisible(t *testing.T) {
	const accountID = "acc00000000000cap02a"
	const secretID = domain.AccessBindingID("acb0000000000000scrt")

	repo := newABFakeRepo("usr_acct_owner", accountID, "", "rol_v", "kacho.view", nil)
	secret := domain.AccessBinding{
		ID: secretID, SubjectType: domain.SubjectTypeUser, SubjectID: "usr_other",
		ResourceType: domain.ResourceType("account"), ResourceID: accountID,
	}
	repo.mu.Lock()
	repo.ab = &secret
	repo.lbsRows = []domain.AccessBinding{secret}
	repo.mu.Unlock()

	fga := newCappedFGAQueries() // grants NOTHING

	t.Run("List omits it", func(t *testing.T) {
		uc := NewListUseCase(repo).
			WithRelationStore(&scopedFGA{allow: map[string]bool{}}).
			WithRelationQueries(fga)
		rows, _, err := uc.Execute(capCallerCtx(), repoab.ListFilter{PageSize: 100})
		require.NoError(t, err)
		assert.NotContains(t, abIDs(rows), string(secretID),
			"ungranted binding must never appear in List")
	})

	t.Run("Get denies it", func(t *testing.T) {
		uc := NewGetAccessBindingUseCase(repo).
			WithRelationStore(&scopedFGA{allow: map[string]bool{}}, nil).
			WithRelationQueries(fga)
		_, err := uc.Execute(capCallerCtx(), secretID)
		require.Error(t, err)
		assert.Equal(t, codes.PermissionDenied, status.Code(err),
			"ungranted binding must stay unreadable by id")
	})
}

// ListByScope must surface the caller's granted binding even when the store is
// past the cap — and must not enumerate the universe to decide it.
func TestABListByScope_OwnBindingBeyondFGAListObjectsCap(t *testing.T) {
	repo, fga, ownedID := capBindingScenario(t)

	uc := NewListByScopeUseCase(repo).
		WithRelationStore(&scopedFGA{allow: map[string]bool{}}, nil).
		WithRelationQueries(fga)

	rows, _, err := uc.Execute(capCallerCtx(), "account", "acc00000000000cap01a",
		repoab.PageFilter{PageSize: 100})
	require.NoError(t, err, "a granted caller must not be denied by a truncated enumeration")
	assert.Contains(t, abIDs(rows), string(ownedID))
	assert.Zero(t, fga.listObjectsCalls.Load(), "ListByScope must not enumerate the universe")
}

// ListByAccount — same contract as ListByScope.
func TestABListByAccount_OwnBindingBeyondFGAListObjectsCap(t *testing.T) {
	repo, fga, ownedID := capBindingScenario(t)
	repo.mu.Lock()
	repo.lbaRows = repo.lbsRows
	repo.mu.Unlock()

	uc := NewListByAccountUseCase(repo).
		WithRelationStore(&scopedFGA{allow: map[string]bool{}}, nil).
		WithRelationQueries(fga)

	rows, _, err := uc.Execute(capCallerCtx(), "acc00000000000cap01a",
		repoab.AccountPageFilter{PageSize: 100})
	require.NoError(t, err, "a granted caller must not be denied by a truncated enumeration")
	assert.Contains(t, abIDs(rows), string(ownedID))
	assert.Zero(t, fga.listObjectsCalls.Load(), "ListByAccount must not enumerate the universe")
}

// BatchCheckWithContext — the batched door onto the SAME oracle CheckWithContext
// answers from, so a verdict cannot depend on which door the filter chose.
//
// It is not optional politeness: authzfilter takes its batched path whenever the
// checker offers this method, so a stub that omitted it would leave every test in
// this file exercising a code path production does not take. It refuses an
// over-cap partition the way the relation store refuses one — an error, never a
// trim — so the stub is never more permissive than the thing it stands in for.
func (c *cappedFGAQueries) BatchCheckWithContext(ctx context.Context, subject, relation string,
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
