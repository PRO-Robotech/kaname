// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"maps"
	"slices"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

type accessLabelMoveRetainedSource struct {
	output       *resourceOutputCapture
	graph        accessLabelMoveGraph
	memberGraphs map[domain.ResourceRef]accessLabelMoveGraph
	// У корня собственная таблица. Его существование не создаёт объект materializer.
	clusterPresent bool
}

// Ключ результата — точная координата в модели FGA. Журнал называет её
// отдельно от координаты члена, в том числе когда член уже исчез.
func (p *resourceParentCapture) captureAccessLabelMoveRetainedSources(
	ctx context.Context, captured accessLabelSelectorMoveCapture,
) (map[domain.ResourceRef]accessLabelMoveRetainedSource, error) {
	if p == nil || p.source == nil || p.source.sealed || p.source.budget == nil || captured.Graphs == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	coords, err := accessLabelMoveRetainedCoordinates(ctx, captured, p.source.budget)
	if err != nil {
		return nil, err
	}
	result := make(map[domain.ResourceRef]accessLabelMoveRetainedSource)
	graphs := maps.Clone(captured.Graphs)
	roleCapture := resourceWithdrawalCapture{source: p.source, roles: make(map[string][]resourceSourceRow)}
	for _, input := range coords {
		row, err := p.accessLabelMoveOutputCatalog(ctx, input)
		if err != nil {
			return nil, err
		}
		model := domain.ResourceRef{Type: row.identity.ObjectType, ID: input.ID}
		if _, seen := result[model]; seen {
			continue
		}
		output, err := captureResourceOutput(ctx, p, row, input.ID)
		if err != nil {
			return nil, err
		}
		source := accessLabelMoveRetainedSource{output: output}
		if model.Type == "cluster" {
			rows, err := p.source.read(ctx, p.tx, resourceSourceKey{kind: resourceSourceRoleMoveCluster, typ: model.Type, id: model.ID})
			if err != nil {
				return nil, err
			}
			roots, err := resourceDecodeRows[struct {
				ID string `json:"id"`
			}](rows)
			if err != nil || len(roots) > 1 || (len(roots) == 1 && roots[0].ID != model.ID) {
				return nil, kaname.ErrSourceUnconfirmed
			}
			source.clusterPresent = len(roots) == 1
		} else {
			source.graph, err = p.captureAccessLabelMoveRetainedGraph(ctx, graphs, output.object)
			if err != nil {
				return nil, err
			}
		}
		// Точный fact ledger называет также выдачи вне перемещаемой роли и
		// collateral census. Их физический член может лежать на другом объекте.
		if err := p.source.budget.Charge(len(output.bindings)+len(output.roles), 0); err != nil {
			return nil, err
		}
		for _, id := range slices.Sorted(maps.Keys(output.bindings)) {
			if _, err = p.source.read(ctx, p.tx, resourceSourceKey{kind: resourceSourceBindingMembers, typ: "binding", id: id}); err != nil {
				return nil, err
			}
		}
		for _, id := range slices.Sorted(maps.Keys(output.roles)) {
			if err = roleCapture.captureRole(ctx, p, id); err != nil {
				return nil, err
			}
		}
		source.memberGraphs, err = p.captureAccessLabelMoveRetainedMembers(ctx, model, graphs)
		if err != nil {
			return nil, err
		}
		result[model] = source
	}
	return result, ctx.Err()
}

func (p *resourceParentCapture) captureAccessLabelMoveRetainedGraph(
	ctx context.Context, graphs map[domain.ResourceRef]accessLabelMoveGraph, ref domain.ResourceRef,
) (accessLabelMoveGraph, error) {
	if graph, ok := graphs[ref]; ok {
		return graph, nil
	}
	graph, err := p.captureAccessLabelMoveGraph(ctx, ref)
	if err != nil {
		return accessLabelMoveGraph{}, err
	}
	graphs[ref] = graph
	return graph, nil
}

// Координата члена выдачи указывает на источник кортежа. Она может
// отличаться от назначения кортежа, например при выводе прав на предка.
func (p *resourceParentCapture) captureAccessLabelMoveRetainedMembers(
	ctx context.Context, output domain.ResourceRef, graphs map[domain.ResourceRef]accessLabelMoveGraph,
) (map[domain.ResourceRef]accessLabelMoveGraph, error) {
	rows := p.source.entries[resourceSourceKey{kind: resourceSourceFactLedgerHolders, typ: output.Type, id: output.ID}]
	if err := p.source.budget.Charge(len(rows), 0); err != nil {
		return nil, err
	}
	holders, err := resourceDecodeRows[struct {
		Type string `json:"member_object_type"`
		ID   string `json:"member_object_id"`
	}](rows)
	if err != nil {
		return nil, err
	}
	members := make(map[domain.ResourceRef]accessLabelMoveGraph)
	for _, holder := range holders {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if holder.Type == "" && holder.ID == "" {
			continue
		}
		if !strings.Contains(holder.Type, ".") || !nativeQuestionToken(holder.ID) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		member := domain.ResourceRef{Type: holder.Type, ID: holder.ID}
		graph, err := p.captureAccessLabelMoveRetainedGraph(ctx, graphs, member)
		if err != nil {
			return nil, err
		}
		members[member] = graph
	}
	return members, nil
}

func accessLabelMoveRetainedCoordinates(ctx context.Context, captured accessLabelSelectorMoveCapture, budget *relverdict.AdministrativeReadBudget) ([]domain.ResourceRef, error) {
	seen := make(map[domain.ResourceRef]bool)
	if err := budget.Charge(len(captured.Graphs)+len(captured.Carriers)+len(captured.Collateral), 0); err != nil {
		return nil, err
	}
	for key, graph := range captured.Graphs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !graph.Present {
			continue
		}
		if key.Type != graph.Object.ObjectType || key.ID != graph.Object.ObjectID || !strings.Contains(key.Type, ".") {
			return nil, kaname.ErrSourceUnconfirmed
		}
		seen[key] = true
		ancestors := graph.ancestors()
		if err := budget.Charge(len(ancestors), 0); err != nil {
			return nil, err
		}
		for _, a := range ancestors {
			if !strings.Contains(a.ObjectType, ".") {
				return nil, kaname.ErrSourceUnconfirmed
			}
			seen[domain.ResourceRef{Type: a.ObjectType, ID: a.ObjectID}] = true
		}
	}
	for _, scopes := range [][]accessLabelSelectorMoveScope{captured.Carriers, captured.Collateral} {
		for _, scope := range scopes {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if err := budget.Charge(len(scope.Carrier.Ledger), 0); err != nil {
				return nil, err
			}
			for _, entry := range scope.Carrier.Ledger {
				model, id, ok := resourceFoldCoordinate(entry.Tuple.Object)
				if !ok {
					return nil, kaname.ErrSourceUnconfirmed
				}
				seen[domain.ResourceRef{Type: model, ID: id}] = true
			}
		}
	}
	return sortedRefs(slices.Collect(maps.Keys(seen))), ctx.Err()
}

func (p *resourceParentCapture) accessLabelMoveOutputCatalog(ctx context.Context, input domain.ResourceRef) (resourceCatalogRow, error) {
	var zero resourceCatalogRow
	if !nativeQuestionToken(input.Type) || !nativeQuestionToken(input.ID) {
		return zero, kaname.ErrSourceUnconfirmed
	}
	if input.Type == "cluster" || input.Type == "iam.cluster" {
		if input.ID != domain.ClusterSingletonID {
			return zero, kaname.ErrSourceUnconfirmed
		}
		// В модели cluster_root есть, но ресурса в словаре для него нет.
		// iam.cluster — структурная координата члена containerMembers.
		// Проверяем отсутствие обеих записей перед обращением к обеим проекциям.
		for _, typ := range []string{"cluster", "iam.cluster"} {
			aliases, err := p.catalog(ctx, typ)
			if err != nil {
				return zero, err
			}
			if len(aliases.rows) != 0 {
				return zero, kaname.ErrSourceUnconfirmed
			}
		}
		return resourceCatalogRow{identity: domain.CatalogTypeIdentity{ObjectType: "cluster", Dotted: "iam.cluster"}}, nil
	}
	first, err := p.catalog(ctx, input.Type)
	if err != nil {
		return zero, err
	}
	row, found := first.selected()
	if !found || row.identity.ObjectType == "cluster" || row.identity.Dotted == "iam.cluster" {
		return zero, kaname.ErrSourceUnconfirmed
	}
	model, dotted := row.identity.ObjectType, row.identity.Dotted
	if !nativeQuestionToken(model) || strings.Contains(model, ".") || !nativeQuestionToken(dotted) || !strings.Contains(dotted, ".") ||
		(input.Type != model && input.Type != dotted) {
		return zero, kaname.ErrSourceUnconfirmed
	}
	// Поиск в обе стороны исключает случай, когда выбор live по dotted
	// скрывает retired с той же координатой FGA и другим именем ресурса.
	for _, typ := range []string{row.identity.Dotted, row.identity.ObjectType} {
		aliases, err := p.catalog(ctx, typ)
		if err != nil {
			return zero, err
		}
		if len(aliases.rows) == 0 {
			return zero, kaname.ErrSourceUnconfirmed
		}
		for _, alias := range aliases.rows {
			if alias.identity != row.identity {
				return zero, kaname.ErrSourceUnconfirmed
			}
		}
	}
	return row, nil
}
