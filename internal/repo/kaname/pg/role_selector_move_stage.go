// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

type roleSelectorMoveStage struct {
	facts    *catalog.Facts
	actor    domain.Subject
	captured accessLabelSelectorMoveCapture
	replay   *accessLabelMoveSourceReplay
}

func (p *GrantPolicyWriters) roleMutationCatalog() (*catalog.Facts, error) {
	var halves catalog.Halves
	if err := json.Unmarshal(p.bundle.CanonicalCatalog(), &halves); err != nil {
		return nil, err
	}
	return catalog.NewFacts(halves)
}

// Тело правки берётся из той же редакции роли, что и перепись объектов.
// Список moves не принимает готовых карт меток или правил от вызывающего.
func (p *GrantPolicyWriters) stageRoleSelectorMove(
	ctx context.Context, tx pgx.Tx, id domain.RoleID, version string,
	moves []domain.AccessLabelSelectorMove, actor domain.Subject, tuples kaname.RoleTupleBuilder,
) (*roleMutationStage, error) {
	if p == nil || p.repo == nil || tx == nil || !nativeQuestionToken(string(id)) || version == "" || len(moves) == 0 ||
		actor.Validate() != nil || actor.ID == "*" || (actor.Type != domain.SubjectTypeUser && actor.Type != domain.SubjectTypeServiceAccount) {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	lifetime, err := newResourceAttemptLifetime(tx.Conn(), p.bundle)
	if err != nil {
		return nil, err
	}
	facts, err := p.roleMutationCatalog()
	if err != nil {
		return nil, err
	}
	budget := &relverdict.AdministrativeReadBudget{}
	if err = chargeNativePolicyBudget(budget, 0, 1); err != nil {
		return nil, err
	}
	// Унаследованный ролевой stage подтверждает RR позднее. Перенос читает
	// больше источников раньше, поэтому удостоверяем режим до первой переписи.
	var isolation string
	if err = tx.QueryRow(ctx, "SELECT current_setting('transaction_isolation')").Scan(&isolation); err != nil {
		return nil, err
	}
	if isolation != "repeatable read" {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	source, err := newResourceSourceCapture(tx, budget, lifetime)
	if err != nil {
		return nil, err
	}
	parents, err := newResourceParentCapture(tx, source)
	if err != nil {
		return nil, err
	}
	captured, err := parents.captureAccessLabelSelectorMove(ctx, facts, id, version, moves)
	if err != nil {
		return nil, err
	}
	if _, err = accessLabelMoveRoleScope(captured.Before); err != nil {
		return nil, err
	}
	replay, err := parents.sealAccessLabelMoveReplay(captured)
	if err != nil {
		return nil, err
	}
	role := captured.Before
	role.Rules = captured.ProposedRules
	request := kaname.RoleMutationRequest{
		Role: role, Rules: true, Tuples: tuples, Update: true, UpdateMask: []string{"rules"}, ExpectedVersion: version,
	}
	move := &roleSelectorMoveStage{facts: facts, actor: actor, captured: captured, replay: replay}
	return p.stageRoleMutation(ctx, tx, request, actor, move)
}

func (s *roleSelectorMoveStage) budget() *relverdict.AdministrativeReadBudget {
	return s.replay.parents.source.budget
}

// Копии, проекции и новые выдачи используют одни финальные часы. Отдельно
// владелец подтверждает apply для ключей и сохранённые источники кортежей.
type roleSelectorMoveChanges struct {
	copies accessLabelMoveCopies
	access accessLabelMoveEffect
	grants []roleSelectorMoveGrant
	owner  *roleSelectorMoveOwnerDecision
}

func (s *roleSelectorMoveStage) compileChanges(
	ctx context.Context, w *semanticAuthorityWriteTx, projected roleSelectorMoveGrantProjections,
) (roleSelectorMoveChanges, error) {
	var empty roleSelectorMoveChanges
	if s == nil || s.replay == nil || s.replay.parents == nil || s.replay.parents.source == nil || w == nil ||
		!s.replay.parents.source.lifetime.valid(w.authorityWriteTx, w.bundle) || w.producerBudget != s.budget() {
		return empty, kaname.ErrSourceUnconfirmed
	}
	checker := w.SemanticRelationChecker()
	if checker == nil {
		return empty, kaname.ErrSourceUnconfirmed
	}
	allowed, err := checker.Check(ctx, subjectPolicyKey(s.actor), "v_update", "iam_role:"+string(s.captured.Before.ID))
	if err != nil {
		return empty, err
	}
	if !allowed {
		return empty, iamerr.ErrPermissionDenied
	}
	at, budget := w.fence.decisionAt, s.budget()
	targets, err := s.captured.copyTargetsAt(ctx, at, budget)
	if err != nil {
		return empty, err
	}
	copyPlan, err := planAccessLabelMoveCopies(ctx, s.captured.Moves, targets, s.captured.Graphs, budget)
	if err != nil {
		return empty, err
	}
	copies := copyPlan.labels
	if err = s.replay.requireObjectUpdates(ctx, w, s.actor, copies); err != nil {
		return empty, err
	}
	scopes := slices.Concat(s.captured.Carriers, s.captured.Collateral)
	// Внешние сохранённые кортежи здесь не считаются доказанными. Владелец
	// сверяет Removed и ResidualFold с их действующими источниками до удаления.
	effect, err := compileAccessLabelMoveEffect(ctx, s.facts, scopes, s.captured.Graphs, copyPlan, nil, at, budget)
	if err != nil {
		return empty, err
	}
	grants, err := accessLabelMoveGrantResidual(ctx, s.captured, effect.Bindings, at, budget)
	if err != nil {
		return empty, err
	}
	modelGrants, err := s.compileGrantEffects(ctx, w.bundle, grants, budget)
	if err != nil {
		return empty, err
	}
	changes := roleSelectorMoveChanges{copies: copies, access: effect, grants: modelGrants}
	if err = s.requireGrantEffects(ctx, w, projected, changes); err != nil {
		return empty, err
	}
	changes.owner, err = s.recordOwnerDecision(ctx, w, copies)
	if err != nil {
		return empty, err
	}
	return changes, ctx.Err()
}

type roleSelectorMoveGrant struct {
	accessLabelMoveGrant
	model granteffect.Set
}

// Примитив относится к точному объекту, подтверждённому графом RR. Эффект
// модели всё ещё требует покрытия актёром на срок и в области этой привязки.
func (s *roleSelectorMoveStage) compileGrantEffects(
	ctx context.Context, bundle *granteffect.Bundle, grants []accessLabelMoveGrant,
	budget *relverdict.AdministrativeReadBudget,
) ([]roleSelectorMoveGrant, error) {
	if len(grants) == 0 {
		return nil, ctx.Err()
	}
	if len(grants) > granteffect.MaxEffects {
		return nil, kaname.ErrSourceReadLimit
	}
	resources := s.facts.Resources()
	if err := budget.Charge(len(resources)+len(grants), 0); err != nil {
		return nil, err
	}
	dottedTypes := make(map[string]string, len(resources))
	for _, entry := range resources {
		dotted := entry.Module + "." + entry.Resource
		if prior, found := dottedTypes[entry.ObjectType]; found && prior != dotted {
			return nil, kaname.ErrSourceUnconfirmed
		}
		dottedTypes[entry.ObjectType] = dotted
	}
	result := make([]roleSelectorMoveGrant, 0, len(grants))
	totalEffects, totalBytes := 0, 0
	for _, grant := range grants {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		typ, id, valid := resourceFoldCoordinate(grant.Tuple.Object)
		ref := domain.ResourceRef{Type: dottedTypes[typ], ID: id}
		graph, found := s.captured.Graphs[ref]
		if !valid || !found || !graph.Present || graph.Object.ObjectType != ref.Type || graph.Object.ObjectID != ref.ID {
			return nil, kaname.ErrSourceUnconfirmed
		}
		effects := bundle.CompileScopedMaterializedTuple(grant.BindingID, graph.Object, grant.Scope, grant.Recipient, grant.Tuple)
		count, size, steps := effects.Cost()
		totalEffects += count
		totalBytes += size
		if totalEffects > granteffect.MaxEffects || totalBytes > granteffect.MaxInputBytes {
			return nil, kaname.ErrSourceReadLimit
		}
		if err := chargeNativePolicyBudget(budget, count+steps, 0); err != nil {
			return nil, err
		}
		if !effects.Complete() || count == 0 {
			return nil, kaname.ErrSourceUnconfirmed
		}
		result = append(result, roleSelectorMoveGrant{accessLabelMoveGrant: grant, model: effects})
	}
	return result, ctx.Err()
}
