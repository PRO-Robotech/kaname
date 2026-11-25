// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/stretchr/testify/require"
)

type moveUpdateChecker func(context.Context, string, string, string) (bool, error)

func (f moveUpdateChecker) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	return f(ctx, subject, relation, object)
}

func TestAccessLabelMoveChecksExactObjectUpdates(t *testing.T) {
	ctx := context.Background()
	actor := nativeBoundaryActor()
	project := domain.ResourceRef{Type: "iam.project", ID: "prj_copy"}
	repo := domain.ResourceRef{Type: "registry.repo", ID: "repo_copy"}
	expired := domain.ResourceRef{Type: "registry.repo", ID: "repo_expired"}
	updates := accessLabelMoveObjectUpdates{project: "project", repo: "reg_repo", expired: "reg_repo"}
	request := roleQuestionRequest()
	tx := roleQuestionFixture(0)
	budget := &relverdict.AdministrativeReadBudget{}
	request.selectorMove = &accessLabelSelectorMoveCapture{
		Before: request.role, copyUpdates: updates, proof: &accessLabelMoveRRProof{
			role: request.role.ID, updates: updates,
			source: &resourceSourceCapture{stageTX: tx, budget: budget, sealed: true},
		},
	}
	questions, _, err := discoverRoleNativeQuestions(ctx, tx, actor, request, budget)
	require.NoError(t, err)
	require.Zero(t, tx.calls, "перенос использует уже прочитанных носителей")
	require.Contains(t, questions.roots, nativePolicyQuestion{"user:usr_native", "v_update", "iam_role", "rol_target"})
	require.Contains(t, questions.roots, nativePolicyQuestion{"user:usr_native", "v_update", "project", "prj_copy"})
	require.Contains(t, questions.roots, nativePolicyQuestion{"user:usr_native", "v_update", "reg_repo", "repo_copy"})
	require.Contains(t, questions.roots, nativePolicyQuestion{"user:usr_native", "v_update", "reg_repo", "repo_expired"})

	var checked []string
	checker := moveUpdateChecker(func(_ context.Context, subject, relation, object string) (bool, error) {
		require.Equal(t, "user:usr_native", subject)
		require.Equal(t, "v_update", relation)
		checked = append(checked, object)
		return object != "reg_repo:repo_copy", nil
	})
	copies := accessLabelMoveCopies{project: {"team": "red"}, repo: {"team": "red"}}
	require.ErrorIs(t, updates.require(ctx, checker, actor, copies), iamerr.ErrPermissionDenied)
	require.Equal(t, []string{"project:prj_copy", "reg_repo:repo_copy"}, checked)

	unheld := domain.ResourceRef{Type: "other.repo", ID: repo.ID}
	checked = nil
	require.ErrorIs(t, updates.require(ctx, checker, actor, accessLabelMoveCopies{unheld: {"team": "red"}}), iamerr.ErrPermissionDenied)
	require.Empty(t, checked)

	checkErr := errors.New("native read unavailable")
	require.ErrorIs(t, updates.require(ctx, moveUpdateChecker(func(context.Context, string, string, string) (bool, error) {
		return false, checkErr
	}), actor, copies), checkErr)
}
