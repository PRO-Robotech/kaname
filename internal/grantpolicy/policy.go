// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package grantpolicy принимает решение только на переданном coordinated writer.
// Полнота census и достаточность подтверждённого подмножества — разные свойства.
package grantpolicy

import (
	"context"
	"fmt"
	"time"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/grantsource"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// WitnessedLowerBound не объявляет исходный census полным. Поля proof закрыты:
// caller не может подставить Complete=true либо эффекты чужого writer.
type WitnessedLowerBound struct {
	census  grantsource.ActorEffects
	effects granteffect.Set
	bundle  *granteffect.Bundle
	at      time.Time
	admin   []granteffect.Effect
}

func (p WitnessedLowerBound) Census() grantsource.ActorEffects { return p.census }
func (p WitnessedLowerBound) Effects() granteffect.Set         { return p.effects }

func Actor(ctx context.Context) domain.Subject {
	p := operations.PrincipalFromContext(ctx)
	return domain.Subject{Type: domain.SubjectType(p.Type), ID: domain.SubjectID(p.ID)}
}
func denied() error      { return iamerr.Wrapf(iamerr.ErrPermissionDenied, "Grant authority denied") }
func unavailable() error { return iamerr.Wrapf(iamerr.ErrUnavailable, "Grant authority unavailable") }

// CollectWitnessedLowerBound дочитывает все страницы до первой проверки права.
// Неизвестный дополнительный grant не является отрицательным правилом в admitted
// union-модели. Такой источник не доказывает ничего; unknown context, ошибки
// чтения, admission, identity и budget завершают весь сбор отказом.
func CollectWitnessedLowerBound(ctx context.Context, w kaname.SemanticAuthorityWriter, actor domain.Subject) (WitnessedLowerBound, error) {
	if w == nil || w.SemanticBundle() == nil || w.AuthorityFence() == nil || w.SemanticRelationChecker() == nil {
		return WitnessedLowerBound{}, unavailable()
	}
	if _, ok := w.(kaname.SemanticSourceReader); !ok {
		return WitnessedLowerBound{}, unavailable()
	}
	c, err := grantsource.CollectSemanticActor(ctx, w, actor)
	if err != nil {
		return WitnessedLowerBound{}, err
	}
	b := w.SemanticBundle()
	u := &granteffect.UnionBuilder{}
	add := func(s granteffect.Set) error {
		if !s.Complete() {
			return nil
		}
		return u.Add(s)
	}
	for _, v := range c.Bindings {
		if v.Source.Role != nil {
			if _, ok := c.RoleCheckpoints[v.Source.Role.ID]; !ok {
				continue
			}
			if !creatorSourceSupported(*v.Source.Role, v.Source.Recipient) {
				continue
			}
		}
		if err = add(v.Effects); err != nil {
			return WitnessedLowerBound{}, err
		}
	}
	for _, s := range c.Structural.Direct {
		if err = add(b.CompileDirect(granteffect.Direct{SourceID: string(s.SourceKind) + ":" + s.SourceID, ObjectType: s.ObjectType, ObjectID: s.ObjectID, Relation: s.Relation, Recipient: s.Recipient, Condition: granteffect.Condition{Name: s.Condition.Name, Parameters: s.Condition.Parameters}})); err != nil {
			return WitnessedLowerBound{}, err
		}
	}
	for _, s := range c.Producers {
		if s.Issue != "" {
			switch s.Issue {
			case "producer_receipt", "producer_object", "producer_version", "publication_state", "versionless_retirement_action", "producer_retirement":
				// Canonical reader доказал, что этот положительный producer сейчас не usable.
				continue
			default:
				// Неизвестный scope/catalog/context нельзя списать как лишний grant.
				return WitnessedLowerBound{}, kaname.ErrSourceUnconfirmed
			}
		}
		r := s.Receipt
		if err = add(b.CompileDirect(granteffect.Direct{SourceID: fmt.Sprintf("%s:%s:%s:%s", r.Kind, r.Module, r.ObjectType, r.ObjectID), ObjectType: r.ObjectType, ObjectID: r.ObjectID, Relation: r.Relation, Recipient: r.Subject, Condition: granteffect.Condition{Name: r.ConditionName, Parameters: r.ConditionParameters}})); err != nil {
			return WitnessedLowerBound{}, err
		}
	}
	if err = ctx.Err(); err != nil {
		return WitnessedLowerBound{}, err
	}
	proof := WitnessedLowerBound{census: c, effects: u.Build(), bundle: b, at: c.DecisionAt}
	proof.admin, err = administrativePrimitives(proof)
	if err != nil {
		return WitnessedLowerBound{}, err
	}
	return proof, nil
}
func (p WitnessedLowerBound) valid(w kaname.SemanticAuthorityWriter) bool {
	if w == nil {
		return false
	}
	if p.census.ProducerPopulation != nil && p.census.ProducerPopulation.Validate(w, p.census.Actor, p.at) != nil {
		return false
	}
	return p.bundle != nil && w.SemanticBundle() == p.bundle && w.AuthorityFence() != nil && p.at.Equal(w.AuthorityFence().DecisionAt()) && p.census.Identity == p.bundle.Identity()
}
func check(ctx context.Context, w kaname.SemanticAuthorityWriter, actor domain.Subject, relation, object string) (bool, error) {
	if actor.Validate() != nil || actor.ID == "*" || (actor.Type != domain.SubjectTypeUser && actor.Type != domain.SubjectTypeServiceAccount) || w == nil || w.SemanticRelationChecker() == nil {
		return false, unavailable()
	}
	return w.SemanticRelationChecker().Check(ctx, string(actor.Type)+":"+string(actor.ID), relation, object)
}
func capability(ctx context.Context, w kaname.SemanticAuthorityWriter, actor domain.Subject, scope domain.ScopeAnchor, kind domain.GrantCapabilityKind, role domain.RoleID) (bool, error) {
	ref, err := grantcapability.Encode(grantcapability.Coordinate{Kind: kind, Anchor: scope, RoleID: role})
	if err != nil {
		return false, err
	}
	return check(ctx, w, actor, ref.Relation, ref.Object())
}

// RequireBinding — D1. D3 сохраняет прежний административный потолок, D2
// независимо разрешает названную роль, но ни одна ветвь не отменяет shape.
func RequireBinding(ctx context.Context, w kaname.SemanticAuthorityWriter, actor domain.Subject, proposed granteffect.Binding) error {
	proof, err := CollectWitnessedLowerBound(ctx, w, actor)
	if err != nil {
		return err
	}
	// Новая выдача всегда судится с новым meta-смыслом, даже если вызывающий
	// передал нулевую версию исторического carrier.
	proposed.CapabilityVersion = 1
	subjects := proposed.Subjects
	if len(subjects) == 0 {
		subjects = []domain.Subject{proposed.Recipient}
	}
	subjects, err = domain.NormalizeSubjects(subjects, "", "")
	if err != nil {
		return err
	}
	proposed.Subjects = subjects
	for _, recipient := range subjects {
		proposed.Recipient = recipient
		if err = requireBinding(ctx, w, proof, proposed); err != nil {
			return err
		}
	}
	return ctx.Err()
}
func requireBinding(ctx context.Context, w kaname.SemanticAuthorityWriter, p WitnessedLowerBound, proposed granteffect.Binding) error {
	if !p.valid(w) {
		return unavailable()
	}
	if err := validateProposed(proposed); err != nil {
		return err
	}
	admin, err := administrative(ctx, w, p, proposed.Scope)
	if err != nil {
		return err
	}
	if admin {
		return nil
	}
	create, err := capability(ctx, w, p.census.Actor, proposed.Scope, domain.GrantCapabilityCreateBinding, "")
	if err != nil {
		return err
	}
	if !create || !witnessedCapability(p, proposed.Scope, granteffect.CreateBinding, "") {
		return p.insufficient()
	}
	bind, err := capability(ctx, w, p.census.Actor, proposed.Scope, domain.GrantCapabilityBindRole, proposed.Role.ID)
	if err != nil {
		return err
	}
	if bind && witnessedCapability(p, proposed.Scope, granteffect.BindRole, proposed.Role.ID) {
		return nil
	}
	return requireCoverage(p, proposed)
}
func validateProposed(b granteffect.Binding) error {
	if b.Role.ID == "" || b.SourceID == "" || !domain.IsScopeAnchorKind(b.Scope.Type) || domain.DeriveFromResourceType(b.Scope.Type).ValidateAgainst(b.Scope.Type, b.Scope.ID) != nil || b.Recipient.Validate() != nil {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "Invalid proposed grant")
	}
	if err := b.Target.Validate(); err != nil {
		return err
	}
	_, caps, err := domain.SplitGrantCapabilityRules(b.Role.Rules)
	if err != nil {
		return err
	}
	if len(caps) > 0 && len(b.Target.Resources) > 0 {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "Meta capability carrier requires allInScope")
	}
	return nil
}
func requireCoverage(p WitnessedLowerBound, b granteffect.Binding) error {
	proposed := p.bundle.Compile(b)
	if granteffect.Prove(p.effects, proposed).Status != grantcoverage.Proved {
		return p.insufficient()
	}
	return nil
}

func (p WitnessedLowerBound) insufficient() error {
	if p.census.ProducerPopulation != nil {
		return kaname.ErrCapturedProducerInsufficient
	}
	return denied()
}

// Native meta-arm и подтверждённая текущая проекция должны согласоваться.
// Старая строка meta projection без checkpoint не является D2 source.
func witnessedCapability(p WitnessedLowerBound, scope domain.ScopeAnchor, kind granteffect.Kind, role domain.RoleID) bool {
	for _, e := range p.effects.Effects() {
		if e.Kind == kind && e.Anchor == scope && e.RoleID == role && e.Condition.Name == "" && e.Condition.Parameters == "" {
			return true
		}
	}
	return false
}
func creatorSourceSupported(r domain.Role, recipient domain.Subject) bool {
	for _, rule := range r.Rules {
		if rule.CreatedBySubject && (recipient.Type != domain.SubjectTypeServiceAccount || rule.Module != "iam" || len(rule.Resources) != 1 || rule.Resources[0] != "serviceAccount") {
			return false
		}
	}
	return true
}
