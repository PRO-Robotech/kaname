// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// materialized_at_test.go — the materialization observable must actually reach the
// read paths, not just exist in the repo.
//
// A signal nobody can read is not a signal: the whole value of `materialized_at`
// is that the administrator polling after a grant can tell "still propagating"
// from "granted the wrong thing". So the List read path MUST stamp it, and it must
// stay a READ-side projection — never a barrier on the write (Operation.done is
// durability, not visibility; ban #9).

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestABList_MaterializedAt_ProjectedOnReadPath(t *testing.T) {
	repo := newABFakeRepo("usr_o", "acc_mat", "", "rol_v", "kacho.view", nil)
	live := domain.AccessBinding{ID: "acb00000000000live1", ResourceType: "account", ResourceID: "acc_mat", SubjectID: "usr_a"}
	fresh := domain.AccessBinding{ID: "acb0000000000fresh2", ResourceType: "account", ResourceID: "acc_mat", SubjectID: "usr_b"}
	seedABListByScope(repo, []domain.AccessBinding{live, fresh})

	at := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	repo.seedMaterializedAt(live.ID, at)

	fga := newABQueriesStub()
	fga.set("v_get", "user:usr_x", []string{string(live.ID), string(fresh.ID)})
	h := newListHandler(repo, fga)

	resp, err := h.List(newOwnerContext("usr_x"), &iamv1.ListAccessBindingsRequest{PageSize: 10})
	require.NoError(t, err)

	byID := map[string]*iamv1.AccessBinding{}
	for _, b := range resp.GetAccessBindings() {
		byID[b.GetId()] = b
	}

	gotLive := byID[string(live.ID)]
	require.NotNil(t, gotLive)
	require.NotNil(t, gotLive.GetMaterializedAt(),
		"a materialized binding must expose WHEN its access went live — that is the whole signal")
	assert.Equal(t, at.Unix(), gotLive.GetMaterializedAt().GetSeconds())

	gotFresh := byID[string(fresh.ID)]
	require.NotNil(t, gotFresh)
	assert.Nil(t, gotFresh.GetMaterializedAt(),
		"a binding with no ACTIVE member must read as unset (still propagating), never epoch-zero")
}
