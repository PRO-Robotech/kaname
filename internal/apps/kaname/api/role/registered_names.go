// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// heldNamesOf — ключи объектов, названные правилами роли и зарегистрированные
// на приёме (kaname#963, приёмка `unregistration-revokes-its-grants.md`, Р8,
// URG-26). Запись роли держит их замком строки регистрации и отказывает (Т2),
// если снятие успело раньше записи. nil-порт — судить нечем (не провязан).
func heldNamesOf(ctx context.Context, keys shared.RegisteredKeys, rules domain.Rules) ([]domain.RuleNameHold, error) {
	if keys == nil {
		return nil, nil
	}
	named := rules.NamedKeys()
	if len(named) == 0 {
		return nil, nil
	}
	refs := make([]domain.ResourceRef, 0, len(named))
	for _, n := range named {
		refs = append(refs, n.Ref)
	}
	present, err := keys.RegisteredOf(ctx, refs)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	live := make(map[domain.ResourceRef]struct{}, len(present))
	for _, p := range present {
		live[p] = struct{}{}
	}
	var out []domain.RuleNameHold
	for _, n := range named {
		if _, ok := live[n.Ref]; ok {
			out = append(out, n)
		}
	}
	return out, nil
}
