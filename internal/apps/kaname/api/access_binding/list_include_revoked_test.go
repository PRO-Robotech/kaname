// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// list_include_revoked_test.go — the canonical `List` must be able to show what
// the deprecated family shows.
//
// F10 soft-revoke DELIBERATELY retains the row (status='REVOKED') so a revoked
// grant stays auditable. `ListByAccount` and `ListByRole` expose it via
// `include_revoked`. The unified `List` — advertised as the replacement for that
// whole family — had no status control at all: its filter whitelist is
// {subject, role, scope, scopeId}. So the recommended read could not answer
// "who USED to hold this role", and an auditor had to fall back to the very RPCs
// `List` deprecates.
//
// The repo layer already honours `ListFilter.IncludeRevoked` (it appends
// `status <> 'REVOKED'` only when false) — the gap was purely that nothing on the
// API could set it.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
)

// Default (flag unset) keeps hiding revoked rows — a revoked grant is not a grant.
func TestABList_IncludeRevoked_DefaultsToFalse(t *testing.T) {
	repo := newABFakeRepo("usr_o", "acc_ir1", "", "rol_v", "kacho.view", nil)
	fga := newABQueriesStub()
	fga.set("v_list", "user:usr_x", []string{"acb000000000000keep1"})
	h := newListHandler(repo, fga)

	_, err := h.List(newOwnerContext("usr_x"), &iamv1.ListAccessBindingsRequest{PageSize: 10})
	require.NoError(t, err)
	assert.False(t, repo.lastListFilter.IncludeRevoked,
		"default must stay false — parity with ListByAccount/ListByRole")
}

// The flag reaches the repo filter, so the audit-retention read is available on
// the canonical path.
func TestABList_IncludeRevoked_ReachesRepoFilter(t *testing.T) {
	repo := newABFakeRepo("usr_o", "acc_ir2", "", "rol_v", "kacho.view", nil)
	fga := newABQueriesStub()
	fga.set("v_list", "user:usr_x", []string{"acb000000000000keep1"})
	h := newListHandler(repo, fga)

	_, err := h.List(newOwnerContext("usr_x"), &iamv1.ListAccessBindingsRequest{
		PageSize:       10,
		IncludeRevoked: true,
	})
	require.NoError(t, err)
	assert.True(t, repo.lastListFilter.IncludeRevoked,
		"include_revoked must reach the repo so retained REVOKED rows are returned")
}

// It COMPOSES with the single-predicate filter expression — the whole point of
// making it a dedicated field instead of a filter key ("show me subject X's
// revoked grants" needs both at once).
func TestABList_IncludeRevoked_ComposesWithFilterPredicate(t *testing.T) {
	repo := newABFakeRepo("usr_o", "acc_ir3", "", "rol_v", "kacho.view", nil)
	fga := newABQueriesStub()
	fga.set("v_list", "user:usr_x", []string{"acb000000000000keep1"})
	h := newListHandler(repo, fga)

	_, err := h.List(newOwnerContext("usr_x"), &iamv1.ListAccessBindingsRequest{
		PageSize:       10,
		Filter:         `subject="usr-42"`,
		IncludeRevoked: true,
	})
	require.NoError(t, err)
	assert.Equal(t, "usr-42", repo.lastListFilter.SubjectID)
	assert.True(t, repo.lastListFilter.IncludeRevoked)
}
