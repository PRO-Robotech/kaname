// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Локальность mirror доказывается до первого fence из того же RR capture.
// Retained OLD расширяет footprint, но не меняет desired или containment.
// SQL независимо повторяет доказательство; возвращаемое bool не полномочие.
func (s *bindingSequenceCapture) captureMirrorLocality(ctx context.Context, facts *catalog.Facts, typ, id string, input reconcile.CapturedObjectDiff, commands []reconcile.BindingCommand) (bool, error) {
	if s == nil || s.parents == nil || s.parents.source == nil || s.parents.source.sealed || facts == nil ||
		!nativeQuestionToken(typ) || !nativeQuestionToken(id) || input.Binding.BindingID != s.binding ||
		input.Binding.Scope.Type != "account" || domain.FeedSourceForType(typ) == domain.FeedIAMDirect {
		return false, kaname.ErrSourceUnconfirmed
	}
	model, live := facts.FGAObjectType(typ)
	if !live {
		// Подлинная старая координата сохраняет прежний GLOBAL verifier.
		return false, nil
	}
	matching, aliases := 0, 0
	for _, row := range facts.Resources() {
		if row.Module+"."+row.Resource == typ {
			matching++
		}
		if row.ObjectType == model {
			aliases++
		}
	}
	if matching != 1 || aliases != 1 || !nativeQuestionToken(model) {
		return false, kaname.ErrSourceUnconfirmed
	}
	out := &resourceOutputCapture{object: domain.ResourceRef{Type: typ, ID: id}, modelType: model}
	footprint := newResourceFootprint()
	if err := out.addObjectScopes(ctx, s.parents, footprint); err != nil {
		return false, err
	}
	if len(footprint.mutation) == 0 {
		return false, kaname.ErrSourceUnconfirmed
	}
	local := len(footprint.mutation) == 1
	for account := range footprint.mutation {
		if string(account) != input.Binding.Scope.ID {
			local = false
		}
	}
	// Даже при member-only diff OLD ledger и каждый вид команды участвуют
	// в проверке точного адреса. Совпадение namespace без ID недостаточно.
	exact := model + ":" + id
	coord := reconcile.MemberCoord{ObjectType: typ, ObjectID: id}
	for _, row := range input.Current {
		if row.BindingID != s.binding || row.ObjectType != typ || row.ObjectID != id {
			return false, kaname.ErrSourceUnconfirmed
		}
	}
	for _, row := range input.Ledger {
		if row.Member != coord {
			return false, kaname.ErrSourceUnconfirmed
		}
		if row.Tuple.Object != exact {
			local = false
		}
	}
	for _, member := range input.Desired {
		if member.ObjectType != typ || member.ObjectID != id {
			return false, kaname.ErrSourceUnconfirmed
		}
		for _, tuple := range member.Tuples {
			if tuple.Object != exact {
				local = false
			}
		}
	}
	for _, command := range commands {
		for _, member := range command.Members {
			if member.BindingID != s.binding || member.ObjectType != typ || member.ObjectID != id {
				return false, kaname.ErrSourceUnconfirmed
			}
		}
		for _, ref := range command.Refs {
			if ref.BindingID != s.binding || ref.Member != coord {
				return false, kaname.ErrSourceUnconfirmed
			}
			if ref.Tuple.Object != exact {
				local = false
			}
		}
		for _, row := range command.Rows {
			if row.Member != coord {
				return false, kaname.ErrSourceUnconfirmed
			}
			if row.Tuple.Object != exact {
				local = false
			}
		}
		for _, tuple := range command.Tuples {
			if tuple.Object != exact {
				local = false
			}
		}
	}
	return local, nil
}
