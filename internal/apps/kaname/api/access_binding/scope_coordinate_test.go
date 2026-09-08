// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// scope_coordinate_test.go — ONE coordinate, ONE name.
//
// `AccessBinding` reserves the word "resource" for the `target` (WHICH OBJECTS
// under the anchor a grant applies to) and calls the anchor itself the SCOPE:
// `Create` takes `scope_type`/`scope_id` (dotted), the resource carries
// `scope_type`/`scope_id`. But the read side still spelled the SAME coordinate
// `resource_type`/`resource_id` (bare) on `ListByScope`, `ListAssignableRoles`
// and `SubjectPrivilege` — the legacy names therefore mean the EXACT OPPOSITE of
// what the documented model says, so a client reading the docs and writing
// `resource_type` believes it is selecting objects when it is selecting an anchor.
//
// Fix is ADDITIVE (wire-compatible): the canonical dotted `scope_type`/`scope_id`
// is accepted on the requests (winning when set) and ALWAYS populated on the
// responses next to the legacy pair.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ── request side: dotted scope_type wins, legacy bare pair still works ───────────

func TestScopeCoordinate_DottedPairPreferred(t *testing.T) {
	bare, id, err := scopeCoordinate("iam.account", "acc-1", "", "")
	require.NoError(t, err)
	assert.Equal(t, "account", bare, "dotted iam.account maps to the bare within-service anchor kind")
	assert.Equal(t, "acc-1", id)
}

func TestScopeCoordinate_LegacyBarePairFallback(t *testing.T) {
	bare, id, err := scopeCoordinate("", "", "project", "prj-1")
	require.NoError(t, err)
	assert.Equal(t, "project", bare, "an untouched legacy client keeps working")
	assert.Equal(t, "prj-1", id)
}

// The new pair WINS when both are supplied — one coordinate cannot resolve to two
// values, and the canonical name is the authority.
func TestScopeCoordinate_DottedWinsOverLegacy(t *testing.T) {
	bare, id, err := scopeCoordinate("iam.project", "prj-new", "account", "acc-old")
	require.NoError(t, err)
	assert.Equal(t, "project", bare)
	assert.Equal(t, "prj-new", id)
}

// An unknown dotted value is rejected sync — it must NOT silently fall through to
// the legacy pair (that would resolve a typo'd anchor to a different anchor).
func TestScopeCoordinate_UnknownDottedRejected(t *testing.T) {
	_, _, err := scopeCoordinate("iam.folder", "fld-1", "account", "acc-1")
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "scopeType")
}

// ── request side wired through the handler (ListByScope) ─────────────────────────

func TestABListByScope_AcceptsDottedScopePair(t *testing.T) {
	repo := newABFakeRepo("usr_o", "acc_sc1", "", "rol_v", "kacho.view", nil)
	seedABListByScope(repo, []domain.AccessBinding{
		{ID: "acb00000000000scope1", ResourceType: "account", ResourceID: "acc_sc1", SubjectID: "usr_a"},
	})
	h := NewHandler(nil, nil, nil, NewListByScopeUseCase(repo), nil, nil, nil)

	_, err := h.ListByScope(newOwnerContext("usr_o"), &iamv1.ListAccessBindingsByScopeRequest{
		ScopeType: "iam.account",
		ScopeId:   "acc_sc1",
	})
	require.NoError(t, err)
	assert.Equal(t, domain.ResourceType("account"), repo.lastByScopeType,
		"the dotted scopeType must reach the use-case as the bare anchor kind")
	assert.Equal(t, "acc_sc1", repo.lastByScopeID)
}

func TestABListByScope_LegacyResourcePairStillWorks(t *testing.T) {
	repo := newABFakeRepo("usr_o", "acc_sc2", "", "rol_v", "kacho.view", nil)
	seedABListByScope(repo, []domain.AccessBinding{
		{ID: "acb00000000000scope2", ResourceType: "account", ResourceID: "acc_sc2", SubjectID: "usr_a"},
	})
	h := NewHandler(nil, nil, nil, NewListByScopeUseCase(repo), nil, nil, nil)

	_, err := h.ListByScope(newOwnerContext("usr_o"), &iamv1.ListAccessBindingsByScopeRequest{
		ResourceType: "account",
		ResourceId:   "acc_sc2",
	})
	require.NoError(t, err)
	assert.Equal(t, domain.ResourceType("account"), repo.lastByScopeType)
	assert.Equal(t, "acc_sc2", repo.lastByScopeID)
}

// ── response side: SubjectPrivilege carries BOTH spellings ───────────────────────

func TestSubjectPrivilegeToProto_FillsBothScopeSpellings(t *testing.T) {
	got := subjectPrivilegeToProto(domain.SubjectPrivilege{
		BindingID:    "acb00000000000priv1",
		RoleID:       "rol00000000000view1",
		ResourceType: "project",
		ResourceID:   "prj-77",
		Scope:        domain.ScopeProject,
		Status:       domain.AccessBindingStatusActive,
		CreatedAt:    time.Now(),
	})

	assert.Equal(t, "iam.project", got.GetScopeType(),
		"canonical dotted scope_type — same spelling as AccessBinding.scope_type")
	assert.Equal(t, "prj-77", got.GetScopeId())
	// Back-compat: the legacy pair keeps its exact previous values.
	assert.Equal(t, "project", got.GetResourceType())
	assert.Equal(t, "prj-77", got.GetResourceId())
}
