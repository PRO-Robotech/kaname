// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// expand_access_test.go — unit
// tests for ExpandAccess: an object+relation is resolved into concrete principals
// (groups already expanded server-side by FGA ListUsers), groups themselves are
// NOT returned, and the set is deduplicated (a principal granted directly AND via
// a group appears once, E-30 no double-grant anomaly). The REAL graph traversal
// (computed usersets + scope_grant indirection + group expansion) is exercised by
// the real-OpenFGA integration suite; here a fake lister returns a fixed concrete
// set — modelling ListUsers' contract: it has ALREADY traversed the graph.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// fakeLister models the real FGA ListUsers: keyed by "type:id#relation" it returns
// the CONCRETE principals (user:/service_account:) that hold the relation, with
// groups/computed-usersets/scope_grant indirection ALREADY expanded by the server
// — so the use-case does NOT walk anything. The top-level query is recorded for
// request-forwarding assertions; `gotTypes` captures the user_filters passed.
type fakeLister struct {
	byNode   map[string][]string
	err      error
	gotType  string
	gotID    string
	gotRel   string
	gotTypes []string
	calls    int
}

func (f *fakeLister) ListUsers(_ context.Context, objectType, objectID, relation string, userTypes []string) ([]string, error) {
	if f.calls == 0 {
		f.gotType, f.gotID, f.gotRel, f.gotTypes = objectType, objectID, relation, userTypes
	}
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.byNode[objectType+":"+objectID+"#"+relation], nil
}

func authedCtx() context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{ID: "usr_auditor", Type: "user"})
}

func TestExpandAccess_E31_GroupExpandedToConcretePrincipals(t *testing.T) {
	// ListUsers returns the concrete principals with the group userset ALREADY
	// expanded (usr_u1, usr_u2 from the group + the direct user + the SA). The
	// duplicate usr_u1 (direct AND via group) collapses to one (E-30). A stray
	// "group:..." entry (defensive — concrete-type filters mean FGA won't emit
	// one) must be dropped, never surfaced as a principal.
	exp := &fakeLister{byNode: map[string][]string{
		"compute_instance:inst_x#v_delete": {
			"user:usr_u1",
			"user:usr_u1", // duplicate (direct + via group) → dedupe (E-30)
			"user:usr_u2",
			"service_account:sva_bot",
			"group:grp_g#member", // defensive: not a concrete principal → dropped
		},
	}}
	uc := NewExpandAccessUseCase(exp)

	res, truncated, err := uc.Execute(authedCtx(), "compute_instance", "inst_x", "v_delete", 0)
	require.NoError(t, err)
	assert.False(t, truncated)
	// Exactly {usr_u1, usr_u2, sva_bot}, no group.
	require.Len(t, res, 3)
	ids := map[string]domain.SubjectType{}
	for _, p := range res {
		ids[string(p.ID)] = p.Type
	}
	assert.Equal(t, domain.SubjectTypeUser, ids["usr_u1"])
	assert.Equal(t, domain.SubjectTypeUser, ids["usr_u2"])
	assert.Equal(t, domain.SubjectTypeServiceAccount, ids["sva_bot"])
	_, hasGroup := ids["grp_g"]
	assert.False(t, hasGroup, "group userset must NOT appear as a principal (E-31)")

	// The request is forwarded verbatim to the lister; the concrete-type filters
	// are passed (user + service_account, never group).
	assert.Equal(t, "compute_instance", exp.gotType)
	assert.Equal(t, "inst_x", exp.gotID)
	assert.Equal(t, "v_delete", exp.gotRel)
	assert.ElementsMatch(t, []string{"user", "service_account"}, exp.gotTypes,
		"ListUsers must be filtered to concrete principal types only (no group)")
}

func TestExpandAccess_FailClosedOnListerError(t *testing.T) {
	// A ListUsers transport / FGA error must fail closed: INTERNAL, no principals,
	// no leak of the underlying error text.
	exp := &fakeLister{err: errors.New("fga down: dial tcp refused")}
	uc := NewExpandAccessUseCase(exp)
	res, _, err := uc.Execute(authedCtx(), "account", "acc_x", "viewer", 0)
	require.Error(t, err)
	assert.Empty(t, res, "no principals on a fail-closed error")
	assert.NotContains(t, err.Error(), "dial tcp", "must not leak the FGA/transport error text")
}

func TestExpandAccess_AnonymousRejected(t *testing.T) {
	uc := NewExpandAccessUseCase(&fakeLister{})
	_, _, err := uc.Execute(context.Background(), "compute_instance", "inst_x", "v_delete", 0)
	require.Error(t, err, "anonymous caller must be rejected (viewer-floor gate)")
}

func TestExpandAccess_ValidatesRequest(t *testing.T) {
	uc := NewExpandAccessUseCase(&fakeLister{})
	ctx := authedCtx()
	_, _, err := uc.Execute(ctx, "", "inst_x", "v_delete", 0)
	require.Error(t, err, "empty object_type → INVALID_ARGUMENT")
	_, _, err = uc.Execute(ctx, "compute_instance", "", "v_delete", 0)
	require.Error(t, err, "empty object_id → INVALID_ARGUMENT")
	_, _, err = uc.Execute(ctx, "compute_instance", "inst_x", "", 0)
	require.Error(t, err, "empty relation → INVALID_ARGUMENT")
}

func TestExpandAccess_TruncatedWhenOverMax(t *testing.T) {
	exp := &fakeLister{byNode: map[string][]string{
		"compute_instance:inst_x#viewer": {"user:usr_a", "user:usr_b", "user:usr_c"},
	}}
	uc := NewExpandAccessUseCase(exp)
	res, truncated, err := uc.Execute(authedCtx(), "compute_instance", "inst_x", "viewer", 2)
	require.NoError(t, err)
	assert.True(t, truncated, "result over max_results must set truncated")
	assert.Len(t, res, 2)
}
