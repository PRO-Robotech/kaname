// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantsource

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
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
	return collectAndCompileBindings(ctx, w, c, actor, &sourceBudget{}, &granteffect.UnionBuilder{})
}

// effectCompiler не раскрывает mutable Compiler и одинаково принимает Bundle.
type effectCompiler interface {
	Compile(granteffect.Binding) granteffect.Set
	CompileDirect(granteffect.Direct) granteffect.Set
}

func collectAndCompileBindings(ctx context.Context, w kaname.AuthorityWriter, c effectCompiler, actor domain.Subject, budget *sourceBudget, builder *granteffect.UnionBuilder) (BindingEffects, error) {
	sources, err := collectBindings(ctx, w, actor, budget)
	if err != nil {
		return BindingEffects{}, err
	}
	out := BindingEffects{}
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
		if err := builder.Add(effects); err != nil {
			return BindingEffects{}, fmt.Errorf("%w: %w", ErrBindingSourceLimit, err)
		}
		out.Bindings = append(out.Bindings, CompiledBinding{Source: source, Effects: effects})
	}
	// Union сохраняет обязательства каждого носителя. Пустой сбор остаётся
	// без удостоверенной identity; адаптер не фабрикует Complete/Ready.
	out.Effects = builder.Build()
	return out, nil
}

// sourceBudget считает чтения и строки group/binding/direct/creator,
// subjects/versions и прочитанных ролей одного сбора, включая пустые страницы
// и повторяющиеся строки.
// Нулевое значение готово к работе; лимит не задаётся вызывающим API.
type sourceBudget struct {
	pages, rows int
	shared      func(kaname.SourceReadCost) error
}

func (b *sourceBudget) pageAvailable() bool { return b.pages < maxBindingSourcePages }
func (b *sourceBudget) charge(n int) bool {
	if !b.pageAvailable() || n < 0 || n > maxBindingSourceRows-b.rows {
		return false
	}
	if b.shared != nil && b.shared(kaname.SourceReadCost{Rows: n, Reads: 1}) != nil {
		return false
	}
	b.pages++
	b.rows += n
	return true
}

// ActorEffects — доступные компоненты actor, не полная authority (kaname#1034).
// Component содержит все binding/direct эффекты и незакрытые obligations.
// Creators остаются evidence селекторов, а не независимой выдачей.
// Identity/DecisionAt описывают источник вычисления, не DB attestation.
type ActorEffects struct {
	Producers          []kaname.ProducerSource
	ProducerPopulation kaname.CapturedProducerPopulation
	RoleCheckpoints    map[domain.RoleID]granteffect.ProjectionCheckpoint
	Actor              domain.Subject
	Identity           grantcoverage.Identity
	DecisionAt         time.Time
	Bindings           []CompiledBinding
	Structural         StructuralSources
	Component          granteffect.Set
}

func nilSource(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}

// CollectSemanticActor использует только writer и его immutable bundle. Ни
// внешний Compiler, ни caller-provided полнота/Ready на вход не принимаются.
// Все классы делят бюджет сбора и UnionBuilder; отказ возвращает нулевой исход.
// Действующие writers не переключаются, публичный gate здесь не открывается.
func CollectSemanticActor(ctx context.Context, w kaname.SemanticAuthorityWriter, actor domain.Subject) (ActorEffects, error) {
	if err := ctx.Err(); err != nil {
		return ActorEffects{}, err
	}
	if nilSource(w) {
		return ActorEffects{}, ErrBindingSourceInvalid
	}
	bundle := w.SemanticBundle()
	if err := bundle.Validate(); err != nil {
		return ActorEffects{}, err
	}
	fence := w.AuthorityFence()
	if nilSource(fence) || fence.DecisionAt().IsZero() {
		return ActorEffects{}, ErrBindingSourceInvalid
	}
	at := fence.DecisionAt()
	var population kaname.CapturedProducerPopulation
	if reader, ok := w.(kaname.CapturedProducerPopulationReader); ok {
		var err error
		population, err = reader.CapturedProducerPopulation(ctx, actor)
		if err != nil {
			return ActorEffects{}, err
		}
		if population != nil {
			if err := population.Validate(w, actor, at); err != nil {
				return ActorEffects{}, err
			}
		}
	}
	budget := &sourceBudget{}
	// Подключённый writer сохраняет единый бюджет RR discovery, повторных
	// census и native вопросов; caller не может передать собственный allowance.
	if shared, ok := w.(interface {
		ChargeSourceRead(kaname.SourceReadCost) error
	}); ok {
		budget.shared = shared.ChargeSourceRead
	}
	builder := &granteffect.UnionBuilder{}
	provenance, hasProvenance := w.(kaname.SemanticSourceReader)
	if hasProvenance {
		cost, err := provenance.AdmitSourceActor(ctx, actor)
		if err != nil {
			return ActorEffects{}, err
		}
		if !budget.chargeCost(cost) {
			return ActorEffects{}, ErrBindingSourceLimit
		}
	}
	bindings, err := collectAndCompileBindings(ctx, w, bundle, actor, budget, builder)
	if err != nil {
		return ActorEffects{}, err
	}
	structural, err := collectAndCompileStructuralSources(ctx, w, bundle, actor, budget, builder)
	if err != nil {
		return ActorEffects{}, err
	}
	var producers []kaname.ProducerSource
	var checkpoints map[domain.RoleID]granteffect.ProjectionCheckpoint
	extra := []granteffect.Obligation{{Code: "role_projection_checkpoint", Detail: "authored rules, relevant catalog dependencies and projector checkpoint are not confirmed"}}
	if hasProvenance {
		var e error
		producers, checkpoints, extra, e = collectActorProvenance(ctx, provenance, bundle, actor, bindings.Bindings, budget, builder)
		if e != nil {
			return ActorEffects{}, e
		}
	}
	if err = ctx.Err(); err != nil {
		return ActorEffects{}, err
	}
	// Реальный semantic writer закрепляет эти величины. Подмена адаптером в ходе
	// сбора не должна выдать результат с identity чужого набора или иным expiry.
	currentFence := w.AuthorityFence()
	if w.SemanticBundle() != bundle || nilSource(currentFence) || !currentFence.DecisionAt().Equal(at) {
		return ActorEffects{}, kaname.ErrSemanticIdentityUnavailable
	}
	component := structural.Component
	if hasProvenance {
		component = granteffect.WithObligations(builder.Build(), StructuralSourceObligations()...)
	}
	if (len(bindings.Bindings) > 0 || len(structural.Sources.Direct) > 0) && component.Identity() != bundle.Identity() {
		return ActorEffects{}, kaname.ErrSemanticIdentityUnavailable
	}
	// Полнота чтения строк не подтверждает живую role projection. Этот шов
	// добавляется к неослабленным registration/creator/protocol obligations.
	component = granteffect.WithObligations(component, extra...)
	if population != nil {
		if err := population.Validate(w, actor, at); err != nil {
			return ActorEffects{}, err
		}
		component = granteffect.WithObligations(component, granteffect.Obligation{Code: "captured_producer_population", Detail: "RR captured positive sources only; current original population is not complete"})
	}
	return ActorEffects{ProducerPopulation: population, Producers: producers, RoleCheckpoints: checkpoints, Actor: actor, Identity: bundle.Identity(), DecisionAt: at, Bindings: bindings.Bindings, Structural: structural.Sources, Component: component}, nil
}
