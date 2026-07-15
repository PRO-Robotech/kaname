// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package project

// list_nilport_test.go — паритетная верификация fail-closed-ветки
// ProjectService.List: незаконфигурированный FGA relation-порт (nil) обязан дать
// Unavailable, НИКОГДА unfiltered/owner-only. Тот же инвариант уже проверен для
// FGA-ошибки (list_vlist_union_test.go) и реализован одинаково в
// group/service_account/role/user List — подтверждает паритет edge-веток.

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	repoproject "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
)

// nil relation-порт (use-case без WithRelationStore) → Unavailable (fail-closed):
// видимость никогда не резолвится через owner-only обходной путь.
func TestListProjects_NilRelationPort_Unavailable(t *testing.T) {
	repo := newListFakeRepo()
	seedAccount(repo, "acc-other", "usr-other") // usr-u1 НЕ владелец → нет owner-обхода
	seedProject(repo, "prj-a", "acc-other")

	uc := NewListProjectsUseCase(repo) // relationQueries не сконфигурирован (nil)

	out, _, err := uc.Execute(ctxAs("usr-u1"), repoproject.ListFilter{PageSize: 100})
	require.Error(t, err)
	require.Empty(t, out)
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.Unavailable, st.Code(),
		"nil relation-порт → UNAVAILABLE fail-closed (никогда unfiltered)")
}
