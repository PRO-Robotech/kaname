// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"context"
	"errors"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Нейтральный контракт не создаёт импорт PG→API, в том числе в in-package tests.
type ResourceDecisionRunner = kaname.ResourceDecisionRunner

// Setter вызывается при сборке до конкурентного использования UC. Явная
// настройка, включая nil, исключает возврат к старому beginner или pool gate.
func (uc *RegisterResourceUseCase) WithResourceDecisionRunner(runner ResourceDecisionRunner) error {
	if uc == nil {
		return errors.New("resource registrar is absent")
	}
	uc.resourceDecisionConfigured = true
	uc.resourceDecision = runner
	if runner == nil {
		return errors.New("resource decision runner is absent")
	}
	return nil
}

func (uc *RegisterResourceUseCase) runResourceDecision(ctx context.Context, in kaname.ResourceDecisionIntent) (kaname.ResourceDecisionResult, error) {
	if uc == nil || !uc.resourceDecisionConfigured || uc.resourceDecision == nil {
		return kaname.ResourceDecisionResult{}, iamerr.Wrapf(iamerr.ErrUnavailable, "iam datastore unavailable")
	}
	result, err := uc.resourceDecision.RunResourceDecision(ctx, in.Snapshot())
	var field *kaname.ResourceDecisionFieldError
	if errors.As(err, &field) {
		return kaname.ResourceDecisionResult{}, shared.InvalidArg(field.Field, field.Description)
	}
	return result, err
}
