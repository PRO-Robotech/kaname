// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantcoverage

import (
	"strings"
	"unicode/utf8"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func validate(req Request) Result {
	if req.Empty != RejectEmpty && req.Empty != ProveEmpty {
		return failure(Invalid, ReasonMalformed, RequestSide, -1)
	}
	// Вычитание после отдельной проверки исключает переполнение суммы длин.
	if len(req.Actor.Effects) > MaxEffects || len(req.Proposed.Effects) > MaxEffects-len(req.Actor.Effects) {
		return failure(Invalid, ReasonLimit, RequestSide, -1)
	}
	v := validator{bytes: MaxInputBytes, entries: MaxSelectorEntries}
	if reason := v.identity(req.Identity); reason != ReasonNone {
		return failure(Invalid, reason, RequestSide, -1)
	}
	sets := []struct {
		side Side
		set  EffectSet
	}{
		{ActorSide, req.Actor}, {ProposedSide, req.Proposed},
	}
	for _, item := range sets {
		if reason := v.identity(item.set.Identity); reason != ReasonNone {
			return failure(Invalid, reason, item.side, -1)
		}
		for i, effect := range item.set.Effects {
			if reason := v.effect(effect); reason != ReasonNone {
				return failure(Invalid, reason, item.side, i)
			}
		}
	}
	// Даже пустая предлагаемая сторона не обходит проверку полноты и identity.
	for _, item := range sets {
		if !item.set.Complete {
			return failure(NotProved, ReasonIncomplete, item.side, -1)
		}
		if item.set.Identity != req.Identity {
			return failure(NotProved, ReasonIdentity, item.side, -1)
		}
		for i, effect := range item.set.Effects {
			if effect.Kind == Unsupported {
				return failure(NotProved, ReasonUnsupported, item.side, i)
			}
		}
	}
	return success()
}

type validator struct{ bytes, entries int }

func (v *validator) identity(id Identity) Reason {
	if r := v.token(id.ModelID); r != ReasonNone {
		return r
	}
	if r := v.token(id.CatalogID); r != ReasonNone {
		return r
	}
	return v.token(id.ProjectorVersion)
}

func (v *validator) effect(e Effect) Reason {
	if e.Kind == Unsupported {
		if e.Anchor != (Anchor{}) || !emptyResource(e.Resource) || e.RoleID != "" {
			return ReasonMalformed
		}
		return v.token(e.UnsupportedReason)
	}
	if e.UnsupportedReason != "" {
		return ReasonMalformed
	}
	if !domain.IsScopeAnchorKind(e.Anchor.Type) {
		return ReasonMalformed
	}
	if r := v.token(e.Anchor.ID); r != ReasonNone {
		return r
	}
	// Best-effort fallback не достижим: вид уже проверен закрытым словарём.
	if domain.DeriveFromResourceType(e.Anchor.Type).ValidateAgainst(e.Anchor.Type, e.Anchor.ID) != nil {
		return ReasonMalformed
	}
	switch e.Kind {
	case CreateBinding:
		if !emptyResource(e.Resource) || e.RoleID != "" {
			return ReasonMalformed
		}
	case BindRole:
		if !emptyResource(e.Resource) {
			return ReasonMalformed
		}
		return v.token(string(e.RoleID))
	case ResourceUse:
		if e.RoleID != "" {
			return ReasonMalformed
		}
		return v.resource(e.Resource)
	default:
		return ReasonMalformed
	}
	return ReasonNone
}

func (v *validator) resource(r Resource) Reason {
	if reason := v.token(r.Module); reason != ReasonNone {
		return reason
	}
	if reason := v.token(r.Type); reason != ReasonNone {
		return reason
	}
	switch r.Action.Kind {
	case Verb, Relation:
		if reason := v.token(r.Action.Name); reason != ReasonNone {
			return reason
		}
	case AllVerbs:
		if r.Action.Name != "" {
			return ReasonMalformed
		}
	default:
		return ReasonMalformed
	}
	objects := r.Region.Objects
	switch objects.Kind {
	case AllObjects:
		if len(objects.IDs) != 0 {
			return ReasonMalformed
		}
	case ObjectIDs:
		if len(objects.IDs) == 0 {
			return ReasonMalformed
		}
	default:
		return ReasonMalformed
	}
	if !v.consumeEntries(len(objects.IDs)) || !v.consumeEntries(len(r.Region.Labels)) {
		return ReasonLimit
	}
	for _, id := range objects.IDs {
		if reason := v.token(id); reason != ReasonNone {
			return reason
		}
	}
	for key, value := range r.Region.Labels {
		if key == "" {
			return ReasonMalformed
		}
		if reason := v.text(key); reason != ReasonNone {
			return reason
		}
		if reason := v.text(value); reason != ReasonNone {
			return reason
		}
	}
	creator := r.Region.Creator
	switch creator.Kind {
	case AnyCreator:
		if creator.Subject != (domain.Subject{}) {
			return ReasonMalformed
		}
	case ExactCreator:
		if creator.Subject.Type != domain.SubjectTypeUser && creator.Subject.Type != domain.SubjectTypeServiceAccount {
			return ReasonMalformed
		}
		if reason := v.token(string(creator.Subject.ID)); reason != ReasonNone {
			return reason
		}
		if creator.Subject.Validate() != nil {
			return ReasonMalformed
		}
	default:
		return ReasonMalformed
	}
	return ReasonNone
}

func emptyResource(r Resource) bool {
	return r.Module == "" && r.Type == "" && r.Action == (Action{}) &&
		r.Region.Objects.Kind == 0 && len(r.Region.Objects.IDs) == 0 &&
		len(r.Region.Labels) == 0 && r.Region.Creator == (Creator{})
}

func (v *validator) consumeEntries(n int) bool {
	if n > v.entries {
		return false
	}
	v.entries -= n
	return true
}
func (v *validator) token(s string) Reason {
	if r := v.text(s); r != ReasonNone {
		return r
	}
	if s == "" || s == "*" || strings.TrimSpace(s) != s || strings.ContainsAny(s, "\x00\r\n\t") {
		return ReasonMalformed
	}
	return ReasonNone
}
func (v *validator) text(s string) Reason {
	if len(s) > MaxStringBytes || len(s) > v.bytes {
		return ReasonLimit
	}
	v.bytes -= len(s)
	if !utf8.ValidString(s) {
		return ReasonMalformed
	}
	return ReasonNone
}
