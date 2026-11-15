// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"slices"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type entryAuthorityWriteTx struct {
	*authorityWriteTx
	bundle *granteffect.Bundle
}

func (w *entryAuthorityWriteTx) SemanticBundle() *granteffect.Bundle { return w.bundle }

func (r *Repository) CoordinatedEntryWriter(ctx context.Context, in kaname.AuthorityWriteIntent) (kaname.EntryAuthorityWriter, error) {
	w, err := r.coordinatedAuthorityWriter(ctx, in, "decision")
	if err != nil {
		return nil, err
	}
	return &entryAuthorityWriteTx{authorityWriteTx: w, bundle: in.Bundle}, nil
}

// Один actor и явные native roots ограничивают публичный preplanned порт.
// Дополнительные роли не становятся allow: snapshot захватывает их owner/source
// epochs, а RoleProjectionCheckpoint по-прежнему проверяет настоящий producer.
func semanticReadRequest(in kaname.AuthorityWriteIntent, read kaname.SemanticReadIntent) (policyWriteRequest, error) {
	if err := validateAuthorityIntent(in); err != nil {
		return policyWriteRequest{}, err
	}
	if read.Actor.Validate() != nil || read.Actor.ID == "*" || (read.Actor.Type != domain.SubjectTypeUser && read.Actor.Type != domain.SubjectTypeServiceAccount) || len(read.Roles) > kaname.MaxAuthorityOwnershipRefs || len(read.Native) > policyDiscoveryGuards {
		return policyWriteRequest{}, kaname.ErrInvalidAuthorityFencePlan
	}
	var questions *nativePolicyQuestions
	if len(read.Native) != 0 {
		questions = newNativePolicyQuestions()
	}
	for _, question := range read.Native {
		typ, id, ok := strings.Cut(question.Object, ":")
		if !ok {
			return policyWriteRequest{}, kaname.ErrInvalidAuthorityFencePlan
		}
		if err := questions.add(read.Actor, question.Relation, typ, id); err != nil {
			return policyWriteRequest{}, err
		}
	}
	for _, role := range read.Roles {
		if !nativeQuestionToken(string(role)) {
			return policyWriteRequest{}, kaname.ErrInvalidAuthorityFencePlan
		}
	}
	return policyWriteRequest{actor: read.Actor, kind: in.Kind, owners: slices.Clone(in.Owners), additionalAccounts: slices.Clone(in.Plan.Accounts), global: in.Plan.Mode == kaname.AuthorityFenceGlobal, readRoles: slices.Clone(read.Roles), nativeQuestions: questions}, nil
}

func (r *Repository) PreparedAuthorityDecisionWriter(ctx context.Context, in kaname.AuthorityWriteIntent, read kaname.SemanticReadIntent) (kaname.SemanticAuthorityWriter, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	request, err := semanticReadRequest(in, read)
	if err != nil {
		return nil, err
	}
	factory, err := NewGrantPolicyWriters(ctx, r, in.Bundle)
	if err != nil {
		return nil, err
	}
	opened, err := factory.openPolicyWriter(ctx, request)
	if err != nil {
		return nil, err
	}
	semantic := opened.(*semanticAuthorityWriteTx)
	return &plannedSemanticWriteTx{semanticAuthorityWriteTx: semantic, actor: read.Actor, nativeDeclared: len(read.Native) != 0}, nil
}

// Snapshot уже содержит закрытый набор вопросов, включая пустой (никакого
// native Check). Actor source APIs не могут расширить его другим principal.
type plannedSemanticWriteTx struct {
	*semanticAuthorityWriteTx
	actor            domain.Subject
	nativeDeclared   bool
	additionalActors map[domain.Subject]bool
}

// Пустой список вопросов означает запрет native dispatch, а не старый
// неограниченный checker. Срок жизни wrapper проверяется до обращения к SQL.
func (w *plannedSemanticWriteTx) SemanticRelationChecker() kaname.RelationChecker {
	return plannedSemanticChecker{w}
}

type plannedSemanticChecker struct{ w *plannedSemanticWriteTx }

func (c plannedSemanticChecker) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	w := c.w
	if w == nil || w.semanticAuthorityWriteTx == nil || w.closed || !w.nativeDeclared || w.nativeRead == nil || w.nativeRead.boundary == nil || w.checker == nil {
		return false, kaname.ErrSourceUnconfirmed
	}
	return w.checker.Check(ctx, subject, relation, object)
}

func (w *plannedSemanticWriteTx) validActor(actor domain.Subject) bool {
	return w != nil && w.semanticAuthorityWriteTx != nil && !w.closed && actor.Validate() == nil && ((w.actor.Validate() == nil && actor == w.actor) || w.additionalActors[actor])
}
func (w *plannedSemanticWriteTx) AdmitSourceActor(ctx context.Context, actor domain.Subject) (kaname.SourceReadCost, error) {
	if !w.validActor(actor) {
		return kaname.SourceReadCost{}, kaname.ErrSourceUnconfirmed
	}
	return w.semanticAuthorityWriteTx.AdmitSourceActor(ctx, actor)
}
func (w *plannedSemanticWriteTx) ProducerSources(ctx context.Context, f kaname.CanonicalSourceFilter) (kaname.ProducerSourcePage, string, error) {
	if !w.validActor(f.Actor) {
		return kaname.ProducerSourcePage{}, "", kaname.ErrSourceUnconfirmed
	}
	return w.semanticAuthorityWriteTx.ProducerSources(ctx, f)
}
func (w *plannedSemanticWriteTx) CanonicalDirectSources(ctx context.Context, f kaname.CanonicalSourceFilter) ([]kaname.CanonicalDirectSource, string, error) {
	if !w.validActor(f.Actor) {
		return nil, "", kaname.ErrSourceUnconfirmed
	}
	return w.semanticAuthorityWriteTx.CanonicalDirectSources(ctx, f)
}
func (w *plannedSemanticWriteTx) CanonicalCreatorSources(ctx context.Context, f kaname.CanonicalSourceFilter) ([]kaname.CanonicalCreatorSource, string, error) {
	if !w.validActor(f.Actor) {
		return nil, "", kaname.ErrSourceUnconfirmed
	}
	return w.semanticAuthorityWriteTx.CanonicalCreatorSources(ctx, f)
}
func (w *plannedSemanticWriteTx) RoleProjectionCheckpoint(ctx context.Context, id domain.RoleID) (granteffect.ProjectionCheckpoint, kaname.SourceReadCost, error) {
	if w == nil || w.semanticAuthorityWriteTx == nil || w.closed {
		return granteffect.ProjectionCheckpoint{}, kaname.SourceReadCost{}, kaname.ErrSourceUnconfirmed
	}
	// Exact role guard приходит из общего RR source plan, не из caller boolean.
	if !w.policyGuards["role:"+string(id)] {
		return granteffect.ProjectionCheckpoint{}, kaname.SourceReadCost{}, kaname.ErrSourceUnconfirmed
	}
	return w.semanticAuthorityWriteTx.RoleProjectionCheckpoint(ctx, id)
}

var _ kaname.EntryAuthorityWriter = (*entryAuthorityWriteTx)(nil)
var _ kaname.SemanticSourceReader = (*plannedSemanticWriteTx)(nil)
