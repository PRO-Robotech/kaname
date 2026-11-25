// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/hierarchy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/resourceeffect"
)

// Для вложенного проекта ребёнок берётся из зеркала, а контейнер из accounts.
// Удерживаем все строки рёбер до дедупликации родителей, как при прямой переписи.
func (p *resourceParentCapture) captureProjectObjectGraph(ctx context.Context, id string) (resourceeffect.ProjectGraphProjection, error) {
	const projectType, accountType = domain.ScopeTypeProjectDotted, domain.ScopeTypeAccountDotted
	var graph resourceeffect.ProjectGraphProjection
	child, found, err := p.captureObjectProjectionFrom(ctx, projectType, id, resourceSourceMirror)
	if err != nil {
		return graph, err
	}
	if !found {
		graph.ConfirmedAbsent = domain.ResourceRef{Type: projectType, ID: id}
		return graph, ctx.Err()
	}
	child.AccessLabels = nil
	graph.Object = &child
	childCatalog, err := p.catalog(ctx, projectType)
	if err != nil {
		return graph, err
	}
	root, known := childCatalog.selected()
	if !known || !root.live {
		return graph, ctx.Err()
	}
	if root.identity.Dotted != projectType {
		return graph, kaname.ErrSourceUnconfirmed
	}
	rows, err := p.source.read(ctx, p.tx, resourceSourceKey{kind: resourceSourceParentEdges, typ: root.identity.ObjectType, id: id})
	if err != nil || len(rows) == 0 {
		return graph, err
	}
	edges, err := resourceDecodeRows[resourceObjectParentEdge](rows)
	if err != nil || len(edges) > hierarchy.MaxStoredParentLinks {
		return graph, kaname.ErrSourceUnconfirmed
	}
	accountCatalog, err := p.catalog(ctx, accountType)
	if err != nil {
		return graph, err
	}
	account, known := accountCatalog.selected()
	if !known || !account.live {
		return graph, ctx.Err()
	}
	if account.identity.Dotted != accountType {
		return graph, kaname.ErrSourceUnconfirmed
	}
	slices.SortFunc(edges, func(a, b resourceObjectParentEdge) int { return a.Depth - b.Depth })
	seen := make(map[string]bool)
	previous := 0
	for _, edge := range edges {
		if edge.Depth <= previous || edge.Depth > hierarchy.MaxStoredParentLinks || !nativeQuestionToken(edge.Type) || !nativeQuestionToken(edge.ID) {
			return graph, kaname.ErrSourceUnconfirmed
		}
		previous = edge.Depth
		if edge.Type != account.identity.ObjectType || seen[edge.ID] {
			continue
		}
		seen[edge.ID] = true
		parent, present, err := p.captureObjectProjection(ctx, accountType, edge.ID)
		if err != nil {
			return graph, err
		}
		if present {
			graph.Ancestors = append(graph.Ancestors, parent)
		}
	}
	return graph, ctx.Err()
}

type resourceObjectParentEdge struct {
	Type  string `json:"parent_type"`
	ID    string `json:"parent_id"`
	Depth int    `json:"depth"`
}

// Материализатор использует сохранённые рёбра, как AncestorsSnapshot. Это не
// admission новой регистрации: текущий pointer graph не заменяет эту проекцию.
// Каждая отсутствующая строка и обе стороны catalog JOIN входят в RR witness.
func (p *resourceParentCapture) captureObjectAncestors(ctx context.Context, typ, id string, present bool) ([]domain.MirrorObject, error) {
	if p == nil || p.source == nil || p.source.sealed {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if !present || domain.FeedSourceForType(typ) == domain.FeedIAMDirect {
		return nil, ctx.Err()
	}
	catalog, err := p.catalog(ctx, typ)
	if err != nil {
		return nil, err
	}
	root, ok := catalog.selected()
	if !ok || !root.live {
		return nil, nil
	}
	return p.captureStoredObjectAncestors(ctx, root, id)
}

func (p *resourceParentCapture) captureStoredObjectAncestors(ctx context.Context, root resourceCatalogRow, id string) ([]domain.MirrorObject, error) {
	rows, err := p.source.read(ctx, p.tx, resourceSourceKey{kind: resourceSourceParentEdges, typ: root.identity.ObjectType, id: id})
	if err != nil {
		return nil, err
	}
	edges, err := resourceDecodeRows[resourceObjectParentEdge](rows)
	if err != nil {
		return nil, err
	}
	if len(edges) > hierarchy.MaxStoredParentLinks {
		return nil, kaname.ErrSourceUnconfirmed
	}
	slices.SortFunc(edges, func(a, b resourceObjectParentEdge) int { return a.Depth - b.Depth })
	seen := map[string]bool{}
	previous := 0
	var out []domain.MirrorObject
	for _, e := range edges {
		if e.Depth < 1 || e.Depth > hierarchy.MaxStoredParentLinks || e.Depth == previous || !nativeQuestionToken(e.Type) || !nativeQuestionToken(e.ID) || seen[e.Type+":"+e.ID] {
			return nil, kaname.ErrSourceUnconfirmed
		}
		previous = e.Depth
		seen[e.Type+":"+e.ID] = true
		parentCatalog, err := p.catalog(ctx, e.Type)
		if err != nil {
			return nil, err
		}
		parent, ok := parentCatalog.selected()
		if !ok || !parent.live {
			continue
		}
		object, found, err := p.captureObjectProjection(ctx, parent.identity.Dotted, e.ID)
		if err != nil {
			return nil, err
		}
		if found {
			out = append(out, object)
		}
	}
	return out, ctx.Err()
}
