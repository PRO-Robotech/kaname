// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Совпавшие кандидаты дополняют holders, включая новые materializations.
// Ни selector match, ни наличие старого member не являются permission proof;
// все captured carriers входят в общий mutation footprint до admission.
func (c *resourceOutputCapture) captureMatchingBindings(ctx context.Context, parents *resourceParentCapture, object domain.MirrorObject, present bool) error {
	if c == nil || c.selected == nil || parents == nil || parents.source == nil || parents.source.sealed || object.ObjectType != c.object.Type || object.ObjectID != c.object.ID {
		return kaname.ErrSourceUnconfirmed
	}
	if !present {
		return ctx.Err()
	}
	key := resourceSourceKey{kind: resourceSourceMatchingMirrorBindings, typ: object.ObjectType, id: object.ObjectID}
	if domain.FeedSourceForType(object.ObjectType) == domain.FeedIAMDirect {
		key.kind = resourceSourceMatchingIAMBindings
		projection, err := json.Marshal(struct {
			Accounts []string `json:"accounts"`
			Project  string   `json:"project"`
		}{object.ParentAccountIDs, object.ParentProjectID})
		if err != nil {
			return err
		}
		key.projection = string(projection)
	}
	rows, err := parents.source.read(ctx, parents.tx, key)
	if err != nil {
		return err
	}
	ids := make(map[string]bool)
	for _, row := range rows {
		var value struct {
			BindingID string `json:"binding_id"`
		}
		if err := json.Unmarshal(row.value, &value); err != nil {
			return err
		}
		if !nativeQuestionToken(value.BindingID) {
			return kaname.ErrSourceUnconfirmed
		}
		ids[value.BindingID] = true
		c.selected[value.BindingID] = true
	}
	return c.captureBindings(ctx, parents, ids)
}
