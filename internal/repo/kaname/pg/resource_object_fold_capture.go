// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Координата member не обязана совпадать с Tuple.Object: container/scope_self
// и retained ledger могут удерживать fact другого объекта. Обе TTL-ветви
// требуют его полного holder census до entry. Это не добавляет materialization
// candidates: прочитанные holders участвуют только в SOURCE/OUTPUT защите.
func (p *resourceObjectPreparation) captureFoldOutputs(ctx context.Context, parents *resourceParentCapture) error {
	if p == nil || p.effects == nil || parents == nil || parents.source != p.source || p.source.sealed {
		return kaname.ErrSourceUnconfirmed
	}
	seen := make(map[domain.ResourceRef]bool, len(p.outputs))
	for _, out := range p.outputs {
		if out == nil {
			return kaname.ErrSourceUnconfirmed
		}
		seen[out.object] = true
	}
	refs := map[string]bool{}
	for _, binding := range p.effects.Bindings {
		for _, commands := range [][]reconcile.BindingCommand{binding.Live, binding.Expired} {
			for _, command := range commands {
				if command.Kind != "write" && command.Kind != "delete" {
					continue
				}
				for _, tuple := range command.Tuples {
					if err := p.source.budget.Charge(1, 0); err != nil {
						return err
					}
					if _, _, ok := resourceFoldCoordinate(tuple.Object); !ok {
						return kaname.ErrSourceUnconfirmed
					}
					refs[tuple.Object] = true
				}
			}
		}
	}
	for _, ref := range resourceSortedSet(refs) {
		typ, id, _ := resourceFoldCoordinate(ref)
		capture, err := parents.catalog(ctx, typ)
		if err != nil {
			return err
		}
		cat, ok := capture.selected()
		if !ok || cat.identity.ObjectType != typ {
			return kaname.ErrSourceUnconfirmed
		}
		for _, row := range capture.rows {
			if row.identity.Dotted != cat.identity.Dotted || row.identity.ObjectType != typ {
				return kaname.ErrSourceUnconfirmed
			}
		}
		coordinate := domain.ResourceRef{Type: cat.identity.Dotted, ID: id}
		if seen[coordinate] {
			continue
		}
		out, err := captureResourceOutput(ctx, parents, cat, id)
		if err != nil {
			return err
		}
		p.outputs = append(p.outputs, out)
		seen[coordinate] = true
	}
	return ctx.Err()
}

func resourceFoldCoordinate(ref string) (string, string, bool) {
	typ, id, ok := strings.Cut(ref, ":")
	return typ, id, ok && nativeQuestionToken(typ) && nativeQuestionToken(id) && !strings.Contains(typ, ".") && !strings.Contains(id, ":")
}
