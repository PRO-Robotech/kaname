// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// f11_list_test.go — redesign-2026 F11 (IAM-1-32). The unified AccessBindingService.List:
//   - page format (page_size / page_token) is validated BEFORE the listauthz
//     visibility short-circuit — a garbage token / page_size>1000 is
//     INVALID_ARGUMENT regardless of grant state (and the FGA floor is never even
//     consulted);
//   - the optional whitelist filter (subject/role/scope/scopeId) rejects an
//     unknown key with INVALID_ARGUMENT and maps `scope` dotted→bare;
//   - visibility is the relation that gates a single-object read (anonymous → empty,
//     never a leak; a question that could not be answered → UNAVAILABLE), resolved
//     PER-OBJECT over the page the repo returned. It is never an enumeration of every
//     object of the type: that door does not exist any more (stage S6), and the reason
//     it was removed is why the order below matters — the enumeration was capped with
//     no continuation token, so a row past that population became permanently
//     invisible while its grant was live (internal/authzfilter).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// newListHandler builds a Handler whose ONLY wired use-case is the unified List,
// backed by the given repo + FGA queries stub. No RelationStore → the D-9
// cluster-admin super-gate is unwired (nil-safe) and only the per-object floor runs.
func newListHandler(repo *abFakeRepo, fga *abQueriesStub) *Handler {
	h := &Handler{}
	return h.WithList(NewListUseCase(repo).WithRelationQueries(fga))
}

// newListHandlerWithStore builds the unified-List Handler with BOTH the per-object
// floor (RelationQueries) and the cluster-admin super-gate (RelationStore) wired —
// the production shape (wiring.go).
func newListHandlerWithStore(repo *abFakeRepo, fga *abQueriesStub, rs clients.RelationStore) *Handler {
	h := &Handler{}
	return h.WithList(NewListUseCase(repo).WithRelationStore(rs).WithRelationQueries(fga))
}

// IAM-1-32: garbage page_token → INVALID_ARGUMENT, and the FGA floor is NOT consulted
// (format-validate happens BEFORE the listauthz short-circuit).
func TestABList_IAM_1_32_GarbageTokenBeforeAuthz(t *testing.T) {
	repo := newABFakeRepo("usr_o", "acc_l32", "", "rol_v", "kacho.view", nil)
	fga := newABQueriesStub()
	h := newListHandler(repo, fga)

	_, err := h.List(newOwnerContext("usr_x"), &iamv1.ListAccessBindingsRequest{PageToken: "%%%not-base64%%%"})
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Equal(t, 0, fga.calls(), "FGA listauthz must NOT be consulted before page-format validation")
}

// IAM-1-32: page_size>1000 → INVALID_ARGUMENT (rejected, not clamped).
func TestABList_IAM_1_32_PageSizeTooLarge(t *testing.T) {
	h := newListHandler(newABFakeRepo("usr_o", "acc_l32b", "", "rol_v", "kacho.view", nil), newABQueriesStub())
	_, err := h.List(newOwnerContext("usr_x"), &iamv1.ListAccessBindingsRequest{PageSize: 1001})
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// IAM-1-32: an unknown filter key → INVALID_ARGUMENT; a known dotted `scope` maps
// to the bare within-service anchor kind.
func TestABList_IAM_1_32_FilterWhitelist(t *testing.T) {
	repo := newABFakeRepo("usr_o", "acc_l32c", "", "rol_v", "kacho.view", nil)
	fga := newABQueriesStub()
	fga.set("v_get", "user:usr_x", []string{"acb000000000000keep1"})
	h := newListHandler(repo, fga)

	t.Run("unknown key rejected", func(t *testing.T) {
		_, err := h.List(newOwnerContext("usr_x"), &iamv1.ListAccessBindingsRequest{Filter: `bogus="x"`})
		require.Error(t, err)
		st, _ := status.FromError(err)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
	t.Run("scope dotted mapped to bare", func(t *testing.T) {
		_, err := h.List(newOwnerContext("usr_x"), &iamv1.ListAccessBindingsRequest{Filter: `scope="iam.account"`})
		require.NoError(t, err)
		assert.Equal(t, "account", repo.lastListFilter.ScopeType, "dotted iam.account → bare account")
	})
	t.Run("unknown dotted scope rejected", func(t *testing.T) {
		_, err := h.List(newOwnerContext("usr_x"), &iamv1.ListAccessBindingsRequest{Filter: `scope="iam.folder"`})
		require.Error(t, err)
		st, _ := status.FromError(err)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
	t.Run("subject filter mapped", func(t *testing.T) {
		_, err := h.List(newOwnerContext("usr_x"), &iamv1.ListAccessBindingsRequest{Filter: `subject="usr-42"`})
		require.NoError(t, err)
		assert.Equal(t, "usr-42", repo.lastListFilter.SubjectID)
	})
}

// IAM-1-32: visibility is the read relation applied per-object to the page — a caller
// sees exactly the bindings it may read by id, not the whole set.
func TestABList_IAM_1_32_VisibilityFilteredPerObject(t *testing.T) {
	repo := newABFakeRepo("usr_o", "acc_l32d", "", "rol_v", "kacho.view", nil)
	acbKeep := domain.AccessBinding{ID: "acb000000000000keep1", ResourceType: "account", ResourceID: "acc_l32d", SubjectID: "usr_a"}
	acbHide := domain.AccessBinding{ID: "acb000000000000hide2", ResourceType: "account", ResourceID: "acc_l32d", SubjectID: "usr_b"}
	seedABListByScope(repo, []domain.AccessBinding{acbKeep, acbHide})

	fga := newABQueriesStub()
	fga.set("v_get", "user:usr_member", []string{"acb000000000000keep1"})
	h := newListHandler(repo, fga)

	resp, err := h.List(newOwnerContext("usr_member"), &iamv1.ListAccessBindingsRequest{PageSize: 100})
	require.NoError(t, err)
	got := respIDs(resp)
	assert.Equal(t, []string{"acb000000000000keep1"}, got, "only the binding this caller may read by id is returned")
	// The repo page carried BOTH rows (the fake applies no visibility predicate);
	// hide2 is dropped by the use-case's per-object check, not by the SQL. Reading the
	// page first and asking about ITS rows is what replaced enumerating the type — see
	// internal/authzfilter.
	assert.Positive(t, fga.calls(), "visibility must be resolved per-object on the returned page")
}

// IAM-1-32: anonymous → empty page (no leak, no error); FGA error → UNAVAILABLE.
func TestABList_IAM_1_32_AnonEmpty_FGAErrorUnavailable(t *testing.T) {
	repo := newABFakeRepo("usr_o", "acc_l32e", "", "rol_v", "kacho.view", nil)
	seedABListByScope(repo, []domain.AccessBinding{{ID: "acb0000000000000any1", ResourceType: "account", ResourceID: "acc_l32e"}})

	t.Run("anonymous → empty", func(t *testing.T) {
		h := newListHandler(repo, newABQueriesStub())
		resp, err := h.List(context.Background(), &iamv1.ListAccessBindingsRequest{PageSize: 100})
		require.NoError(t, err)
		assert.Empty(t, resp.GetAccessBindings(), "anonymous caller gets an empty page, never a leak")
	})
	t.Run("FGA error → Unavailable", func(t *testing.T) {
		fga := newABQueriesStub()
		fga.err = status.Error(codes.Internal, "fga down")
		h := newListHandler(repo, fga)
		_, err := h.List(newOwnerContext("usr_x"), &iamv1.ListAccessBindingsRequest{PageSize: 100})
		require.Error(t, err)
		st, _ := status.FromError(err)
		assert.Equal(t, codes.Unavailable, st.Code(), "FGA error fails closed to UNAVAILABLE, never an unfiltered leak")
	})
}

// IAM-1-32 / D-9: a cluster super-admin holds NO per-object tuple on
// iam_access_binding (the access-cascade is contracted — see helpers.go
// requireGrantAuthority Path 0), so a purely per-object visibility push-down hands
// them an EMPTY page while every sibling read (Get / ListByScope / ListByAccount /
// ListByRole) short-circuits on requireGrantAuthority and returns the full set. The
// unified List must carry the same super-gate: the page is UNFILTERED (VisibleIDs
// push-down dropped, not an empty slice) while the declarative predicates still apply.
func TestABList_IAM_1_32_ClusterAdminUnfiltered(t *testing.T) {
	repo := newABFakeRepo("usr_o", "acc_l32f", "", "rol_v", "kacho.view", nil)
	acbA := domain.AccessBinding{ID: "acb00000000000000ca1", ResourceType: "account", ResourceID: "acc_l32f", SubjectID: "usr_a"}
	acbB := domain.AccessBinding{ID: "acb00000000000000ca2", ResourceType: "account", ResourceID: "acc_l32f", SubjectID: "usr_b"}
	seedABListByScope(repo, []domain.AccessBinding{acbA, acbB})

	t.Run("cluster-admin without per-object tuples sees the whole page", func(t *testing.T) {
		fga := newABQueriesStub() // ZERO per-object tuples — the post-contraction shape
		h := newListHandlerWithStore(repo, fga, onlyClusterAdmin())

		resp, err := h.List(clusterAdminCtx("usr_root"), &iamv1.ListAccessBindingsRequest{PageSize: 100})
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"acb00000000000000ca1", "acb00000000000000ca2"}, respIDs(resp),
			"cluster-admin must enumerate every binding (parity with ListByScope Path 0)")
		assert.Zero(t, fga.calls(),
			"the per-object visibility filter must be SKIPPED entirely for a cluster-admin, "+
				"not run and then overridden")
	})

	t.Run("cluster-admin keeps the declarative predicates", func(t *testing.T) {
		fga := newABQueriesStub()
		h := newListHandlerWithStore(repo, fga, onlyClusterAdmin())

		resp, err := h.List(clusterAdminCtx("usr_root"), &iamv1.ListAccessBindingsRequest{
			PageSize: 100, Filter: `subject="usr_b"`,
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"acb00000000000000ca2"}, respIDs(resp),
			"the super-gate lifts VISIBILITY only — the subject= predicate still narrows")
	})

	t.Run("non-cluster-admin with zero tuples still gets an empty page", func(t *testing.T) {
		fga := newABQueriesStub()
		// grants nothing at all — neither the cluster super-relation nor per-object tuples.
		h := newListHandlerWithStore(repo, fga, &scopedFGA{allow: map[string]bool{}})

		resp, err := h.List(clusterAdminCtx("usr_nobody"), &iamv1.ListAccessBindingsRequest{PageSize: 100})
		require.NoError(t, err)
		assert.Empty(t, resp.GetAccessBindings(),
			"the super-gate must be ADDITIVE — an ordinary caller keeps the per-object floor")
	})
}

func respIDs(resp *iamv1.ListAccessBindingsResponse) []string {
	out := make([]string, 0, len(resp.GetAccessBindings()))
	for _, b := range resp.GetAccessBindings() {
		out = append(out, b.GetId())
	}
	return out
}
