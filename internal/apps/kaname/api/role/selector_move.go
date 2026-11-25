// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

import (
	"math"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func roleSelectorMovePositions(input *iamv1.RoleAccessLabelSelectorMove) ([]domain.AccessLabelSelectorMove, error) {
	positions := input.GetPositions()
	if len(positions) == 0 || len(positions) > domain.MaxAccessLabelSelectorMoves {
		return nil, status.Error(codes.InvalidArgument, "Invalid number of selector move positions")
	}
	moves := make([]domain.AccessLabelSelectorMove, 0, len(positions))
	for _, position := range positions {
		if position == nil || position.RuleIndex == nil || position.GetRuleIndex() >= domain.MaxRules ||
			position.GetChildIndex() > math.MaxInt32 {
			return nil, status.Error(codes.InvalidArgument, "Invalid selector move position")
		}
		move := domain.AccessLabelSelectorMove{RuleIndex: int(position.GetRuleIndex())}
		if position.ChildIndex != nil {
			child := int(position.GetChildIndex())
			move.ChildIndex = &child
		}
		moves = append(moves, move)
	}
	return moves, nil
}

// Закрепляем запрос фонового обработчика за прочитанной версией роли.
// Отпечаток внутреннего хранения остаётся внутри Kaname.
func roleSelectorMoveFingerprints(rules domain.Rules, requested []domain.AccessLabelSelectorMove) ([]domain.AccessLabelSelectorMove, error) {
	moves := slices.Clone(requested)
	for i := range moves {
		move := &moves[i]
		if move.RuleIndex < 0 || move.RuleIndex >= len(rules) {
			return nil, status.Error(codes.InvalidArgument, "Selector move rule position out of range")
		}
		rule := &rules[move.RuleIndex]
		if move.ChildIndex != nil {
			child := *move.ChildIndex
			if child < 0 || child >= len(rule.Children) {
				return nil, status.Error(codes.InvalidArgument, "Selector move child position out of range")
			}
			rule = &rule.Children[child]
			move.ChildIndex = &child
		}
		if move.Fingerprint == "" {
			move.Fingerprint = rule.Fingerprint()
		}
	}
	return moves, nil
}
