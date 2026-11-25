// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/hierarchy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// Для плана копирования читаем только источники, требуемые выбранными позициями.
func (p *resourceParentCapture) captureAccessLabelMoveCopyGraph(ctx context.Context, ref domain.ResourceRef, moves []domain.ValidatedAccessLabelSelectorMove, indices []int) (accessLabelMoveGraph, error) {
	object, present, err := p.captureObjectProjection(ctx, ref.Type, ref.ID)
	if err != nil {
		return accessLabelMoveGraph{}, err
	}
	if !present || object.ObjectType != ref.Type || object.ObjectID != ref.ID || len(indices) == 0 {
		return accessLabelMoveGraph{}, kaname.ErrSourceUnconfirmed
	}
	graph := accessLabelMoveGraph{Object: object, Present: true}
	for _, index := range indices {
		if index < 0 || index >= len(moves) {
			return accessLabelMoveGraph{}, kaname.ErrSourceUnconfirmed
		}
		_, child := moves[index].Position()
		if child >= 0 && ref.Type == domain.ScopeTypeProjectDotted && graph.Project == nil {
			project, err := p.captureProjectObjectGraph(ctx, ref.ID)
			if err != nil {
				return accessLabelMoveGraph{}, err
			}
			graph.Project = &project
		}
	}
	return graph, ctx.Err()
}

// Для ребёнка iam.project исходные обычные метки берём из графа, а
// защищённые метки — из собственной строки той же координаты. Конкретный
// выбранный контейнер подтверждает перепись до вызова этой функции.
func accessLabelMoveCopySource(move domain.ValidatedAccessLabelSelectorMove, graph accessLabelMoveGraph) (domain.MirrorObject, error) {
	if !graph.Present || graph.Object.ObjectType == "" || graph.Object.ObjectID == "" {
		return domain.MirrorObject{}, kaname.ErrSourceUnconfirmed
	}
	object := graph.Object
	_, child := move.Position()
	if child >= 0 && object.ObjectType == domain.ScopeTypeProjectDotted {
		project := graph.Project
		if project == nil || project.Object == nil || project.ConfirmedAbsent != (domain.ResourceRef{}) ||
			project.Object.ObjectType != object.ObjectType || project.Object.ObjectID != object.ObjectID ||
			len(project.Ancestors) > hierarchy.MaxStoredParentLinks {
			return domain.MirrorObject{}, kaname.ErrSourceUnconfirmed
		}
		hasAccount := false
		for _, ancestor := range project.Ancestors {
			if ancestor.ObjectType == domain.ScopeTypeAccountDotted && nativeQuestionToken(ancestor.ObjectID) {
				hasAccount = true
				break
			}
		}
		if !hasAccount {
			return domain.MirrorObject{}, kaname.ErrSourceUnconfirmed
		}
		object = *project.Object
		object.AccessLabels = graph.Object.AccessLabels
	}
	if !move.MatchesObject(object) {
		return domain.MirrorObject{}, kaname.ErrSourceUnconfirmed
	}
	return object, nil
}

// Каждая позиция читает свой источник обычных меток. Полная карта защищённых
// меток накапливается для одной координаты, поэтому несовместимые позиции
// дают тот же отказ, что и конфликт с ранее сохранённой меткой доступа.
func mergeAccessLabelMoveCopies(
	ctx context.Context, graph accessLabelMoveGraph, moves []domain.ValidatedAccessLabelSelectorMove,
	indices []int, budget *relverdict.AdministrativeReadBudget,
) (map[string]string, bool, error) {
	if budget == nil || len(indices) == 0 {
		return nil, false, kaname.ErrSourceUnconfirmed
	}
	if err := budget.Charge(1+len(indices), 0); err != nil {
		return nil, false, err
	}
	labels := graph.Object.AccessLabels
	changed := false
	for _, index := range indices {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		if index < 0 || index >= len(moves) {
			return nil, false, kaname.ErrSourceUnconfirmed
		}
		object, err := accessLabelMoveCopySource(moves[index], graph)
		if err != nil {
			return nil, false, err
		}
		object.AccessLabels = labels
		next, added, err := moves[index].CopyAccessLabels(object)
		if err != nil {
			return nil, false, err
		}
		if added {
			if err := budget.Charge(len(next), 0); err != nil {
				return nil, false, err
			}
			labels, changed = next, true
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if !changed {
		return nil, false, nil
	}
	return labels, true, nil
}
