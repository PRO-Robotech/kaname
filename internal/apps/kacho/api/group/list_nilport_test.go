// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package group

// list_nilport_test.go — паритетная верификация fail-closed-ветки
// GroupService.List: незаконфигурированный FGA relation-порт (nil) обязан дать
// Unavailable, НИКОГДА unfiltered. Тот же инвариант уже проверен для FGA-ошибки
// (list_scope_test.go) и реализован одинаково в project/service_account/role/user
// List — подтверждает паритет edge-веток после снятия gateway call-gate.

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repogroup "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
)

// nil relation-порт (use-case без WithRelationStore) → Unavailable (fail-closed):
// страница групп никогда не отдается unfiltered.
func TestListGroups_NilRelationPort_Unavailable(t *testing.T) {
	repo := &scopeGroupRepo{groups: []domain.Group{
		{ID: "grp0000000000000aaaa", AccountID: grpScopeAcct},
	}}
	uc := NewListGroupsUseCase(repo) // relationQueries не сконфигурирован (nil)

	out, _, err := uc.Execute(ctxGrpUser(grpScopeUser), repogroup.ListFilter{AccountID: grpScopeAcct})
	require.Error(t, err)
	require.Empty(t, out)
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.Unavailable, st.Code(),
		"nil relation-порт → UNAVAILABLE fail-closed (никогда unfiltered)")
}
