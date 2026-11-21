// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package grantpolicy

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// RequireScopeAdministration сохраняет обычный административный gate для
// metadata-only mutation. Не выдаёт capability-v1 и не судит новую выдачу.
func RequireScopeAdministration(ctx context.Context, w kaname.SemanticAuthorityWriter, actor domain.Subject, scope domain.ScopeAnchor) error {
	if scope.ID == "" {
		return denied()
	}
	proof, err := CollectWitnessedLowerBound(ctx, w, actor)
	if err != nil {
		return err
	}
	allowed, err := administrative(ctx, w, proof, scope)
	if err != nil {
		return err
	}
	if !allowed {
		return proof.insufficient()
	}
	return ctx.Err()
}
