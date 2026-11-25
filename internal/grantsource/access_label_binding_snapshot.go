// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantsource

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

func collectAccessLabelBindingSnapshots(ctx context.Context, w kaname.AccessLabelBindingSourceReader, actor domain.Subject, at time.Time, bindings []CompiledBinding, checkpoints map[domain.RoleID]granteffect.ProjectionCheckpoint, budget *sourceBudget) error {
	if !w.AccessLabelBindingSourcesEnabled() {
		return ctx.Err()
	}
	var captured map[domain.AccessBindingID]kaname.CapturedAccessLabelBindingSource
	for i := range bindings {
		if err := ctx.Err(); err != nil {
			return err
		}
		compiled := &bindings[i]
		source := &compiled.Source
		source.BindingSnapshot = nil
		if source.Role == nil || source.CapabilityVersion != 1 || source.RoleSnapshot == nil || !compiled.Effects.Complete() || compiled.Effects.Identity() != w.SemanticBundle().Identity() {
			continue
		}
		checkpoint, confirmed := checkpoints[source.Role.ID]
		if !confirmed || source.RoleSnapshot.RoleID != source.Role.ID || source.RoleSnapshot.Checkpoint != checkpoint {
			return kaname.ErrSourceUnconfirmed
		}
		hasApply := false
		for _, effect := range compiled.Effects.Effects() {
			if effect.Kind == granteffect.ApplyAccessLabel {
				hasApply = true
				break
			}
		}
		if !hasApply {
			continue
		}
		receipt := captured[source.Binding.ID]
		if nilSource(receipt) {
			if !budget.pageAvailable() {
				return ErrBindingSourceLimit
			}
			var cost kaname.SourceReadCost
			var err error
			receipt, cost, err = w.CaptureAccessLabelBindingSource(ctx, actor, at, source.Binding, source.CapabilityVersion)
			// Все расходы, включая mismatch/ошибку, относятся к тому же sourceBudget.
			if !budget.chargeCost(cost) {
				return ErrBindingSourceLimit
			}
			if err != nil {
				return err
			}
			if cost.Reads < 1 || cost.Rows < 2 || nilSource(receipt) {
				return kaname.ErrSourceUnconfirmed
			}
			if captured == nil {
				captured = map[domain.AccessBindingID]kaname.CapturedAccessLabelBindingSource{}
			}
			captured[source.Binding.ID] = receipt
		}
		if err := receipt.Validate(w, actor, at, source.Binding, source.CapabilityVersion); err != nil {
			return err
		}
		snapshot := receipt.Snapshot()
		if snapshot.BindingID != source.Binding.ID || snapshot.RoleID != source.Role.ID || snapshot.CapabilityVersion != 1 || snapshot.RowXmin == "" || snapshot.RowCTID == "" {
			return kaname.ErrSourceUnconfirmed
		}
		source.BindingSnapshot = receipt
	}
	return ctx.Err()
}
