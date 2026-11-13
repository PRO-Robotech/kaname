// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantsource

import (
	"context"
	"errors"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

var ErrStructuralSourceLimit = errors.New("structural source resource limit exceeded")

const maxStructuralSourceRows = maxBindingSourceRows
const maxStructuralSourcePages = maxBindingSourcePages

// StructuralSources — компонент источников, не полная authority actor.
// Отсутствие Complete/Ready намеренно: обязательства других semantic classes
// нельзя погасить полнотой обхода трёх реализованных direct производителей.
type StructuralSources struct {
	Direct   []kaname.CanonicalDirectSource
	Creators []kaname.CanonicalCreatorSource
}

// StructuralSourceObligations возвращает независимую копию именованных швов.
// Эти обязательства должны войти в будущий общий coordinator до public gate.
func StructuralSourceObligations() []granteffect.Obligation {
	return []granteffect.Obligation{
		{Code: "registration_publication_source", Detail: "current registration/publication receipt with module, tuple, source_version and authoritative ownership"},
		{Code: "creator_selector_evidence", Detail: "creator rows are evidence for binding selectors, never independent direct grants"},
		{Code: "authority_writer_protocol", Detail: "all writers, exact partition census, bundle and DB strict attestation before cutover"},
	}
}

func CollectStructuralSources(ctx context.Context, w kaname.AuthorityWriter, actor domain.Subject) (StructuralSources, error) {
	return collectStructuralSources(ctx, w, actor, &sourceBudget{})
}
func collectStructuralSources(ctx context.Context, w kaname.AuthorityWriter, actor domain.Subject, budget *sourceBudget) (StructuralSources, error) {
	if w == nil || w.AuthorityFence() == nil || w.AuthorityFence().DecisionAt().IsZero() || actor.Validate() != nil || actor.ID == "*" || (actor.Type != domain.SubjectTypeUser && actor.Type != domain.SubjectTypeServiceAccount) {
		return StructuralSources{}, kaname.ErrCanonicalSourceInvalid
	}
	out := StructuralSources{}
	// Каждый вид имеет свой cursor; общий бюджет считает и direct, и creator.
	for _, creators := range []bool{false, true} {
		token := ""
		seen := map[string]bool{"": true}
		for {
			if err := ctx.Err(); err != nil {
				return StructuralSources{}, err
			}
			if !budget.pageAvailable() {
				return StructuralSources{}, ErrStructuralSourceLimit
			}
			filter := kaname.CanonicalSourceFilter{Actor: actor, After: token, Limit: kaname.MaxCanonicalSourcePage}
			var next string
			var err error
			pageRows := 0
			if creators {
				var ss []kaname.CanonicalCreatorSource
				ss, next, err = w.CanonicalCreatorSources(ctx, filter)
				if err == nil {
					for _, s := range ss {
						if s.SourceID == "" || s.SourceID != s.ObjectID || s.ObjectID == "" || s.AccountID == "" || s.ObjectType != "iam_service_account" || s.Creator != actor {
							return StructuralSources{}, kaname.ErrCanonicalSourceInvalid
						}
					}
				}
				pageRows = len(ss)
				out.Creators = append(out.Creators, ss...)
			} else {
				var ss []kaname.CanonicalDirectSource
				ss, next, err = w.CanonicalDirectSources(ctx, filter)
				if err == nil {
					for _, s := range ss {
						if e := validateStructuralSource(s, actor); e != nil {
							return StructuralSources{}, e
						}
						if s.ExpiresAt != nil && !s.ExpiresAt.After(w.AuthorityFence().DecisionAt()) {
							return StructuralSources{}, kaname.ErrCanonicalSourceInvalid
						}
					}
				}
				pageRows = len(ss)
				out.Direct = append(out.Direct, ss...)
			}
			if err != nil {
				return StructuralSources{}, err
			}
			if !budget.charge(pageRows) {
				return StructuralSources{}, ErrStructuralSourceLimit
			}
			if next == "" {
				break
			}
			if seen[next] {
				return StructuralSources{}, fmt.Errorf("%w: repeated cursor", kaname.ErrCanonicalSourceInvalid)
			}
			seen[next] = true
			token = next
		}
	}
	return out, nil
}
func validateStructuralSource(s kaname.CanonicalDirectSource, actor domain.Subject) error {
	if s.SourceID == "" || s.ObjectID == "" || s.Recipient != actor || s.Condition.Name != "" || s.Condition.Parameters != "" {
		return kaname.ErrCanonicalSourceInvalid
	}
	switch s.SourceKind {
	case kaname.CanonicalAccountOwner:
		if actor.Type != domain.SubjectTypeUser || s.ObjectType != "account" || s.Relation != "owner" || string(s.AccountID) != s.ObjectID || s.SourceID != s.ObjectID || s.ExpiresAt != nil {
			return kaname.ErrCanonicalSourceInvalid
		}
	case kaname.CanonicalClusterAdmin:
		if s.ObjectType != "cluster" || s.ObjectID != domain.ClusterSingletonID || s.Relation != "system_admin" || s.AccountID != "" {
			return kaname.ErrCanonicalSourceInvalid
		}
	case kaname.CanonicalUserSelf:
		if actor.Type != domain.SubjectTypeUser || s.ObjectType != "iam_user" || s.ObjectID != string(actor.ID) || s.SourceID != s.ObjectID || s.Relation != "subject" || s.AccountID != "" || s.ExpiresAt != nil {
			return kaname.ErrCanonicalSourceInvalid
		}
	default:
		return kaname.ErrCanonicalSourceInvalid
	}
	return nil
}

// StructuralEffects не обещает полноту actor: Component содержит direct
// эффекты и незакрытые обязательства будущего coordinator. Сырые rows от caller
// функция не принимает: источник всегда перечитывается через AuthorityWriter.
type StructuralEffects struct {
	Sources     StructuralSources
	Component   granteffect.Set
	Obligations []granteffect.Obligation
}

func CollectAndCompileStructuralSources(ctx context.Context, w kaname.AuthorityWriter, c *granteffect.Compiler, actor domain.Subject) (StructuralEffects, error) {
	if c == nil {
		return StructuralEffects{}, kaname.ErrCanonicalSourceInvalid
	}
	return collectAndCompileStructuralSources(ctx, w, c, actor, &sourceBudget{}, &granteffect.UnionBuilder{})
}
func collectAndCompileStructuralSources(ctx context.Context, w kaname.AuthorityWriter, c effectCompiler, actor domain.Subject, budget *sourceBudget, builder *granteffect.UnionBuilder) (StructuralEffects, error) {
	ss, err := collectStructuralSources(ctx, w, actor, budget)
	if err != nil {
		return StructuralEffects{}, err
	}
	for _, s := range ss.Direct {
		if err := ctx.Err(); err != nil {
			return StructuralEffects{}, err
		}
		effects := c.CompileDirect(granteffect.Direct{SourceID: string(s.SourceKind) + ":" + s.SourceID, ObjectType: s.ObjectType, ObjectID: s.ObjectID, Relation: s.Relation, Recipient: s.Recipient, Condition: granteffect.Condition{Name: s.Condition.Name, Parameters: s.Condition.Parameters}})
		if err := builder.Add(effects); err != nil {
			return StructuralEffects{}, fmt.Errorf("%w: %w", ErrStructuralSourceLimit, err)
		}
	}
	return StructuralEffects{Sources: ss, Component: granteffect.WithObligations(builder.Build(), StructuralSourceObligations()...), Obligations: StructuralSourceObligations()}, nil
}
