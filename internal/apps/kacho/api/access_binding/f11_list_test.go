// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// f11_list_test.go — redesign-2026 F11 (IAM-1-32). The unified AccessBindingService.List:
//   - page format (page_size / page_token) is validated BEFORE the listauthz
//     visibility short-circuit — a garbage token / page_size>1000 is
//     INVALID_ARGUMENT regardless of grant state (and the FGA floor is never even
//     consulted);
//   - the optional whitelist filter (subject/role/scope/scopeId) rejects an
//     unknown key with INVALID_ARGUMENT and maps `scope` dotted→bare;
//   - visibility is the caller's viewer ∪ v_list set (anonymous → empty, never a
//     leak; FGA error → UNAVAILABLE), pushed down as the repo VisibleIDs constraint.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// newListHandler builds a Handler whose ONLY wired use-case is the unified List,
// backed by the given repo + FGA queries stub.
func newListHandler(repo *abFakeRepo, fga *abQueriesStub) *Handler {
	h := &Handler{}
	return h.WithList(NewListUseCase(repo).WithRelationQueries(fga))
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
	fga.set("v_list", "user:usr_x", []string{"acb000000000000keep1"})
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

// IAM-1-32: visibility is viewer ∪ v_list, pushed down as VisibleIDs — a v_list-only
// caller sees exactly their matched bindings, not the whole set.
func TestABList_IAM_1_32_VisibilityPushdown(t *testing.T) {
	repo := newABFakeRepo("usr_o", "acc_l32d", "", "rol_v", "kacho.view", nil)
	acbKeep := domain.AccessBinding{ID: "acb000000000000keep1", ResourceType: "account", ResourceID: "acc_l32d", SubjectID: "usr_a"}
	acbHide := domain.AccessBinding{ID: "acb000000000000hide2", ResourceType: "account", ResourceID: "acc_l32d", SubjectID: "usr_b"}
	seedABListByScope(repo, []domain.AccessBinding{acbKeep, acbHide})

	fga := newABQueriesStub()
	fga.set("v_list", "user:usr_member", []string{"acb000000000000keep1"})
	h := newListHandler(repo, fga)

	resp, err := h.List(newOwnerContext("usr_member"), &iamv1.ListAccessBindingsRequest{PageSize: 100})
	require.NoError(t, err)
	got := respIDs(resp)
	assert.Equal(t, []string{"acb000000000000keep1"}, got, "only the v_list-visible binding is returned")
	assert.ElementsMatch(t, []string{"acb000000000000keep1"}, repo.lastListFilter.VisibleIDs,
		"the viewer∪v_list set is pushed down to the repo")
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

func respIDs(resp *iamv1.ListAccessBindingsResponse) []string {
	out := make([]string, 0, len(resp.GetAccessBindings()))
	for _, b := range resp.GetAccessBindings() {
		out = append(out, b.GetId())
	}
	return out
}
