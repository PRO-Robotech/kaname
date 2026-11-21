// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/hierarchy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Полный ordered H строится общим domain compiler. Здесь читается только граф
// действующих серверных указателей; сохранённые scopes/permanent binding
// остаются отдельным источником registration authority и не дописывают H.
func (c *resourceParentCapture) hierarchies(ctx context.Context, anchor string) ([]domain.ParentHierarchy, bool, error) {
	if c == nil || c.source == nil || c.source.budget == nil || c.source.sealed {
		return nil, false, kaname.ErrSourceUnconfirmed
	}
	graph := make(domain.ParentHierarchyGraph)
	queue := []string{anchor}
	edges := 0
	for i := 0; i < len(queue); i++ {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		ref := queue[i]
		if _, exists := graph[ref]; exists {
			continue
		}
		if len(graph) >= domain.MaxParentHierarchyNodes {
			return nil, false, domain.ErrParentHierarchyInvalid
		}
		typ, id, ok := strings.Cut(ref, ":")
		if !ok || !nativeQuestionToken(typ) || !nativeQuestionToken(id) {
			return nil, false, domain.ErrParentHierarchyInvalid
		}
		if err := chargeNativePolicyBudget(c.source.budget, 1, 0); err != nil {
			return nil, false, err
		}
		node := domain.ParentHierarchyNode{Ref: ref}
		if typ == "project" {
			scope, err := c.project(ctx, id)
			if err != nil {
				return nil, false, err
			}
			if !scope.Registered {
				if ref == anchor {
					return nil, false, nil
				}
				return nil, false, domain.ErrParentHierarchyIncomplete
			}
			node.Scope = scope
			graph[ref] = node
			continue
		}
		mirror, found, err := c.mirror(ctx, typ, id)
		if err != nil {
			return nil, false, err
		}
		if !found {
			if ref == anchor {
				return nil, false, nil
			}
			return nil, false, domain.ErrParentHierarchyIncomplete
		}
		project := mirror.Project
		if project == "" {
			project, err = c.chainProject(ctx, typ, id)
			if err != nil {
				return nil, false, err
			}
		}
		node.Scope = domain.ContainerScope{Registered: true, ProjectID: project}
		if project != "" {
			scope, err := c.project(ctx, project)
			if err != nil {
				return nil, false, err
			}
			if !scope.Registered {
				return nil, false, domain.ErrParentHierarchyIncomplete
			}
			node.Scope.AccountID = scope.AccountID
			catalog, err := c.catalog(ctx, typ)
			if err != nil {
				return nil, false, err
			}
			selected, ok := catalog.selected()
			if !ok {
				return nil, false, domain.ErrParentHierarchyIncomplete
			}
			node.Parents, err = c.pointers(ctx, typ, id, selected.policy, true)
			if err != nil {
				return nil, false, err
			}
			if len(node.Parents) > hierarchy.MaxImmediateParents {
				return nil, false, domain.ErrParentHierarchyInvalid
			}
			if err := chargeNativePolicyBudget(c.source.budget, len(node.Parents), 0); err != nil {
				return nil, false, err
			}
			edges += len(node.Parents)
			if edges > domain.MaxParentHierarchyEdges {
				return nil, false, domain.ErrParentHierarchyInvalid
			}
			queue = append(queue, node.Parents...)
		}
		// DP14: без сохранённого project ceiling указатели не расширяют H.
		graph[ref] = node
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	branches, err := domain.BuildParentHierarchies(anchor, graph)
	if err != nil {
		return nil, false, err
	}
	slots := len(branches)
	for _, branch := range branches {
		slots += len(branch.Links)
	}
	if err := chargeNativePolicyBudget(c.source.budget, slots, 0); err != nil {
		return nil, false, err
	}
	return branches, true, nil
}
