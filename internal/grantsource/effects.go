// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantsource

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// CompiledBinding сохраняет отдельный носитель и полный исходный набор получателей.
// Несколько носителей одной выдачи могут иметь разные эффекты и обязательства.
type CompiledBinding struct {
	Source  BindingSource
	Effects granteffect.Set
}

// BindingEffects — только компонент обычных и системных выдач для actor. Даже
// полный Effects не доказывает полноту полномочий, прохождение барьеров или
// допустимость выдачи: здесь нет остальных источников, согласованного набора
// аккаунта и публичной проверки.
type BindingEffects struct {
	Bindings []CompiledBinding
	Effects  granteffect.Set
}

// CollectAndCompileBindings получает носителей только через CollectBindings в
// переданном writer. Actor задаёт контекст сбора; получатель группы сохраняется
// группой и не приобретает свойств вошедшей через неё служебной учётки.
func CollectAndCompileBindings(ctx context.Context, w kaname.AuthorityWriter, c *granteffect.Compiler, actor domain.Subject) (BindingEffects, error) {
	if c == nil {
		return BindingEffects{}, fmt.Errorf("%w: missing effect compiler", ErrBindingSourceInvalid)
	}
	sources, err := CollectBindings(ctx, w, actor)
	if err != nil {
		return BindingEffects{}, err
	}
	out := BindingEffects{Bindings: make([]CompiledBinding, 0, len(sources))}
	sets := make([]granteffect.Set, 0, len(sources))
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return BindingEffects{}, err
		}
		// Членство группы уже отобрано collector. Прямой носитель обязан
		// совпасть типом И идентификатором; одного совпадения ID недостаточно.
		if source.Recipient.Type != domain.SubjectTypeGroup && source.Recipient != actor {
			return BindingEffects{}, fmt.Errorf("%w: direct recipient differs from actor", ErrBindingSourceInvalid)
		}
		b := source.Binding
		// То же отображение, что у producer scopeAnchorFor: область хранится
		// парой resource_type/resource_id, а не полем Scope старой проекции.
		scope := domain.ScopeAnchor{Type: string(b.ResourceType), ID: b.ResourceID}
		if !domain.IsScopeAnchorKind(scope.Type) || domain.DeriveFromResourceType(scope.Type).ValidateAgainst(scope.Type, scope.ID) != nil {
			return BindingEffects{}, fmt.Errorf("%w: binding %s scope", ErrBindingSourceInvalid, b.ID)
		}
		var effects granteffect.Set
		if source.Role == nil {
			if b.RoleID != "" || b.GrantedRelation == "" || !b.System || len(b.Target.Resources) != 0 {
				return BindingEffects{}, fmt.Errorf("%w: binding %s direct form", ErrBindingSourceInvalid, b.ID)
			}
			effects = c.CompileDirect(granteffect.Direct{
				SourceID: string(b.ID), ObjectType: scope.Type, ObjectID: scope.ID,
				Relation: b.GrantedRelation, Recipient: source.Recipient,
			})
		} else {
			effects = c.Compile(granteffect.Binding{
				SourceID: string(b.ID), Role: *source.Role, Scope: scope,
				Target: b.Target, Recipient: source.Recipient, Subjects: b.Subjects,
				CapabilityVersion: source.CapabilityVersion,
			})
		}
		out.Bindings = append(out.Bindings, CompiledBinding{Source: source, Effects: effects})
		sets = append(sets, effects)
	}
	// Union сохраняет обязательства каждого носителя. Пустой сбор остаётся
	// без удостоверенной identity; адаптер не фабрикует Complete/Ready.
	out.Effects = granteffect.Union(sets...)
	return out, nil
}
