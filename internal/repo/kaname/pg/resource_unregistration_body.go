// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Unregister использует ту же owner-private программу и последовательные
// command obligations, что Register. Legacy live readers после final clock
// больше не выбирают DELETE, publication fallback или audit/reconcile эффекты.
func (p *resourceUnregistrationPreparation) apply(ctx context.Context, tx *resourceDecisionTx) (kaname.ResourceDecisionResult, error) {
	var out kaname.ResourceDecisionResult
	if p == nil || p.registration == nil || p.registration.input.Action != kaname.ResourceDecisionUnregister {
		return out, kaname.ErrSourceUnconfirmed
	}
	if err := p.registration.assertBody(ctx, tx); err != nil {
		return out, err
	}
	return p.registration.applyPreparedDirect(ctx, tx)
}
