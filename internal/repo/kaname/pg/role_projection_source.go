// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

func (w *preparedRoleWriteTx) RoleProjectionCheckpointSource(ctx context.Context, id domain.RoleID) (kaname.RoleProjectionSourceSnapshot, kaname.SourceReadCost, error) {
	zero := kaname.RoleProjectionSourceSnapshot{}
	if err := ctx.Err(); err != nil {
		return zero, kaname.SourceReadCost{}, err
	}
	if !w.canReadAccessLabelSource() || !w.policyGuards["role:"+string(id)] {
		return zero, kaname.SourceReadCost{}, kaname.ErrSourceUnconfirmed
	}
	var snapshot kaname.RoleProjectionSourceSnapshot
	_, cost, err := w.semanticAuthorityWriteTx.roleProjectionCheckpoint(ctx, id, &snapshot)
	if err != nil {
		return zero, cost, err
	}
	if snapshot.RoleID != id || snapshot.RowXmin == "" || snapshot.RowCTID == "" {
		return zero, cost, kaname.ErrSourceUnconfirmed
	}
	if err = ctx.Err(); err != nil {
		return zero, cost, err
	}
	return snapshot, cost, nil
}

var _ kaname.RoleProjectionSourceReader = (*preparedRoleWriteTx)(nil)
