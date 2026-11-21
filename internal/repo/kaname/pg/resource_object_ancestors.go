// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/hierarchy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

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
	rows, err := p.source.read(ctx, p.tx, resourceSourceKey{kind: resourceSourceParentEdges, typ: root.identity.ObjectType, id: id})
	if err != nil {
		return nil, err
	}
	type edge struct {
		Type  string `json:"parent_type"`
		ID    string `json:"parent_id"`
		Depth int    `json:"depth"`
	}
	edges, err := resourceDecodeRows[edge](rows)
	if err != nil {
		return nil, err
	}
	if len(edges) > hierarchy.MaxStoredParentLinks {
		return nil, kaname.ErrSourceUnconfirmed
	}
	slices.SortFunc(edges, func(a, b edge) int { return a.Depth - b.Depth })
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
