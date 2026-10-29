// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package toproto

// role_preview_holding_test.go — IAM-CCR-20, последнее «И»: роль, чей признак
// превью НЕ прочитан, в ответ не переводится — перевод отказывает и называет
// роль, по образцу отказа на непровязанном наборе глаголов типа.
//
// Близнец отличается одним фактом: признак прочитан. Без него отказ был бы
// неотличим от перевода, отказывающего всякой роли.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

func holdingProbeRole() domain.Role {
	return domain.Role{
		ID:        "rolccr20holding00001",
		AccountID: "acc2bkd71802av7dywa8",
		Name:      "ccr20",
		Rules: domain.Rules{{
			Module: "probe", Resources: []string{"thing"}, Verbs: []string{"get", "delete"},
		}},
		TypeVerbs: func(_, _ string) ([]string, bool) {
			return []string{"get", "list", "create", "update", "delete"}, true
		},
	}
}

func TestRoleTransfer_IAMCCR20_UnreadHoldingIsARefusal(t *testing.T) {
	unread := holdingProbeRole()
	var dst *iamv1.Role
	err := dto.Transfer(dto.FromTo(unread, &dst))
	require.Error(t, err,
		"роль без прочитанного признака превью переведена в ответ — тихий запасной путь "+
			"неотличим от честного превью")
	require.Contains(t, err.Error(), string(unread.ID), "отказ обязан назвать роль")

	// Близнец: признак прочитан, неудержан `delete`.
	read := holdingProbeRole()
	read.Holding = domain.PreviewHoldingOf(
		[]domain.RoleSegment{{RoleID: read.ID, ObjectType: "probe.thing", Verb: "delete"}}, []string{"create"})
	var ok *iamv1.Role
	require.NoError(t, dto.Transfer(dto.FromTo(read, &ok)), "близнец: прочитанный признак переводится")
	require.Equal(t, []string{"get"}, ok.GetAuthoredVerbs())
}
