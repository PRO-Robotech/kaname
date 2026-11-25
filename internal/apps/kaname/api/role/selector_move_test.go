// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestRoleSelectorMoveTransportRejectsIncompleteOrMixedUpdate(t *testing.T) {
	for _, tc := range []struct{ name, request string }{
		{"нет пакета", `{"updateMask":"accessLabelSelectorMove","resourceVersion":"42"}`},
		{"пустой пакет", `{"updateMask":"accessLabelSelectorMove","resourceVersion":"42","accessLabelSelectorMove":{}}`},
		{"не задан индекс правила", `{"updateMask":"accessLabelSelectorMove","resourceVersion":"42","accessLabelSelectorMove":{"positions":[{}]}}`},
		{"нет версии", `{"updateMask":"accessLabelSelectorMove","accessLabelSelectorMove":{"positions":[{"ruleIndex":0}]}}`},
		{"обычная маска", `{"updateMask":"rules","resourceVersion":"42","accessLabelSelectorMove":{"positions":[{"ruleIndex":0}]}}`},
		{"лишний путь", `{"updateMask":"accessLabelSelectorMove,rules","resourceVersion":"42","accessLabelSelectorMove":{"positions":[{"ruleIndex":0}]}}`},
		{"переданы обычные метки", `{"updateMask":"accessLabelSelectorMove","resourceVersion":"42","labels":{"team":"blue"},"accessLabelSelectorMove":{"positions":[{"ruleIndex":0}]}}`},
		{"переданы защищённые метки", `{"updateMask":"accessLabelSelectorMove","resourceVersion":"42","accessLabels":{"team":"blue"},"accessLabelSelectorMove":{"positions":[{"ruleIndex":0}]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &iamv1.UpdateRoleRequest{}
			require.NoError(t, protojson.Unmarshal([]byte(tc.request), req))
			// Обработчик обязан отклонить форму до обращения к хранилищу.
			got, err := (&Handler{}).Update(context.Background(), req)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
			require.Nil(t, got)
		})
	}
}

func TestRoleSelectorMoveTransportUsesVersionAndPosition(t *testing.T) {
	req := &iamv1.UpdateRoleRequest{}
	require.NoError(t, protojson.Unmarshal([]byte(`{
		"updateMask":"accessLabelSelectorMove",
		"resourceVersion":"42",
		"accessLabelSelectorMove":{"positions":[{"ruleIndex":0},{"ruleIndex":0,"childIndex":0}]}
	}`), req))
	require.Equal(t, "42", req.GetResourceVersion())
	// Старая версия Update отвергает новую маску, даже если отбросит новый тег.
	require.Error(t, shared.ValidateUpdateMask(req.GetUpdateMask().GetPaths(), roleMutableFields, roleImmutableFields))
	positions, err := roleSelectorMovePositions(req.GetAccessLabelSelectorMove())
	require.NoError(t, err)
	require.Len(t, positions, 2)
	require.Nil(t, positions[0].ChildIndex)
	require.NotNil(t, positions[1].ChildIndex)
	require.Zero(t, *positions[1].ChildIndex)

	rules := domain.Rules{{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"},
		Children: domain.Rules{{Resources: []string{"user"}, Verbs: []string{"get"}}}}}
	bound, err := roleSelectorMoveFingerprints(rules, positions)
	require.NoError(t, err)
	require.Equal(t, rules[0].Fingerprint(), bound[0].Fingerprint)
	require.Equal(t, rules[0].Children[0].Fingerprint(), bound[1].Fingerprint)
	require.Empty(t, positions[1].Fingerprint)
	*positions[1].ChildIndex = 1
	require.Zero(t, *bound[1].ChildIndex)
	_, err = roleSelectorMoveFingerprints(rules, positions)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}
