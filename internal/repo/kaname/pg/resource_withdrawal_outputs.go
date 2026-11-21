// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"cmp"
	"context"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Переписываемая роль затрагивает все прежние носители, включая PENDING и
// истёкшие строки со стоящим materialized ledger. Их объекты добавляют OLD
// effect scopes и fold holders до выбора coordinator, не D1/installation.
func (c *resourceWithdrawalCapture) captureOutputs(ctx context.Context, p *resourceParentCapture, f *resourceFootprint) ([]*resourceOutputCapture, error) {
	if c == nil || p == nil || c.source != p.source || c.source.sealed || f == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	coordinates := map[domain.ResourceRef]bool{}
	factTargets := map[string]bool{}
	for id := range c.bindings {
		members, ok := c.source.entries[resourceSourceKey{kind: resourceSourceBindingMembers, typ: "binding", id: id}]
		if !ok {
			return nil, kaname.ErrSourceUnconfirmed
		}
		ledger, ok := c.source.entries[resourceSourceKey{kind: resourceSourceBindingLedger, typ: "binding", id: id}]
		if !ok {
			return nil, kaname.ErrSourceUnconfirmed
		}
		keys, tuples, err := resourceBindingDiffCoordinates(id, members, ledger)
		if err != nil {
			return nil, err
		}
		for _, row := range tuples {
			if err := c.source.budget.Charge(1, 0); err != nil {
				return nil, err
			}
			if _, _, ok := resourceFoldCoordinate(row.Tuple.Object); !ok {
				return nil, kaname.ErrSourceUnconfirmed
			}
			factTargets[row.Tuple.Object] = true
		}
		for key := range keys {
			coordinates[key] = true
		}
	}
	if err := c.source.budget.Charge(len(coordinates), 0); err != nil {
		return nil, err
	}
	keys := make([]domain.ResourceRef, 0, len(coordinates))
	for key := range coordinates {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b domain.ResourceRef) int {
		if n := cmp.Compare(a.Type, b.Type); n != 0 {
			return n
		}
		return cmp.Compare(a.ID, b.ID)
	})
	var outputs []*resourceOutputCapture
	for _, key := range keys {
		catalog, err := p.catalog(ctx, key.Type)
		if err != nil {
			return nil, err
		}
		row, known := catalog.selected()
		if !known || row.identity.Dotted != key.Type {
			return nil, kaname.ErrSourceUnconfirmed
		}
		output, err := captureResourceOutput(ctx, p, row, key.ID)
		if err != nil {
			return nil, err
		}
		if err = output.addFootprint(ctx, p, f); err != nil {
			return nil, err
		}
		outputs = append(outputs, output)
	}
	// Ledger хранит отдельно координату materialized member и реальный target
	// tuple. Отзыв обязан закрыть holders второго, даже для structural ledger
	// без member и для container tuple на другом объекте.
	for _, ref := range resourceSortedSet(factTargets) {
		typ, id, _ := resourceFoldCoordinate(ref)
		catalog, err := p.catalog(ctx, typ)
		if err != nil {
			return nil, err
		}
		row, known := catalog.selected()
		if !known || row.identity.ObjectType != typ {
			return nil, kaname.ErrSourceUnconfirmed
		}
		for _, candidate := range catalog.rows {
			if candidate.identity.Dotted != row.identity.Dotted || candidate.identity.ObjectType != typ {
				return nil, kaname.ErrSourceUnconfirmed
			}
		}
		key := domain.ResourceRef{Type: row.identity.Dotted, ID: id}
		if coordinates[key] {
			continue
		}
		output, err := captureResourceOutput(ctx, p, row, id)
		if err != nil {
			return nil, err
		}
		if err = output.addFootprint(ctx, p, f); err != nil {
			return nil, err
		}
		outputs = append(outputs, output)
		coordinates[key] = true
	}
	return outputs, ctx.Err()
}
