// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Перечень сохраняет и потенциально удаляемые объекты без mirror: старый UC
// снимает их оставшуюся цепь/owned pointers, но не объявляет регистрацию удалённой.
// Реальный compiler отдельно решает по версии родителя, применяется ли cascade.
type resourceCapturedDescendant struct {
	modelType, id string
	catalog       resourceCatalogRow
	mirrorPresent bool
	scopes        []domain.ContainerScope
}

func captureResourceDescendants(ctx context.Context, parents *resourceParentCapture, parent resourceCatalogRow, id string) ([]resourceCapturedDescendant, error) {
	if parents == nil || parent.identity.Module == "" {
		return nil, kaname.ErrSourceUnconfirmed
	}
	rows, err := parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceDescendantEdges, typ: parent.identity.ObjectType, id: id})
	if err != nil {
		return nil, err
	}
	type edge struct {
		Type string `json:"object_type"`
		ID   string `json:"object_id"`
	}
	edges, err := resourceDecodeRows[edge](rows)
	if err != nil {
		return nil, err
	}
	seen := make(map[domain.ResourceRef]bool)
	var out []resourceCapturedDescendant
	for _, edge := range edges {
		if !nativeQuestionToken(edge.Type) || !nativeQuestionToken(edge.ID) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		key := domain.ResourceRef{Type: edge.Type, ID: edge.ID}
		if seen[key] {
			continue
		}
		seen[key] = true
		catalog, err := parents.catalog(ctx, edge.Type)
		if err != nil {
			return nil, err
		}
		selected, known := catalog.selected()
		// Неизвестный либо чужой тип нельзя удалить заодно с родителем модуля.
		// Само ребро всё равно захвачено: его изменение требует restage до clock.
		if !known || selected.identity.Module != parent.identity.Module {
			continue
		}
		_, present, err := parents.mirror(ctx, edge.Type, edge.ID)
		if err != nil {
			return nil, err
		}
		scopes, err := parents.savedScopes(ctx, edge.Type, edge.ID)
		if err != nil {
			return nil, err
		}
		if present && len(scopes) == 0 {
			return nil, kaname.ErrSourceUnconfirmed
		}
		for _, scope := range scopes {
			if !scope.Registered || scope.AccountID == "" {
				return nil, kaname.ErrSourceUnconfirmed
			}
		}
		out = append(out, resourceCapturedDescendant{modelType: edge.Type, id: edge.ID, catalog: selected, mirrorPresent: present, scopes: scopes})
	}
	slices.SortFunc(out, func(a, b resourceCapturedDescendant) int {
		if a.modelType < b.modelType {
			return -1
		}
		if a.modelType > b.modelType {
			return 1
		}
		if a.id < b.id {
			return -1
		}
		if a.id > b.id {
			return 1
		}
		return 0
	})
	return out, nil
}
