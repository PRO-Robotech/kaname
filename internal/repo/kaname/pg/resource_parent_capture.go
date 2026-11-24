// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/hierarchy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

// Только RR collector владеет этими данными. Все промежуточные ключи обхода,
// включая отсутствующие проекты/контейнеры, сохраняются для held-RC recheck.
// Обход не вызывает SQL recursive function, которая могла бы выполнить полный
// неограниченный walk до внешнего LIMIT.
type resourceParentCapture struct {
	tx       pgx.Tx
	source   *resourceSourceCapture
	catalogs map[string]*resourceCatalogCapture
}

func newResourceParentCapture(tx pgx.Tx, source *resourceSourceCapture) (*resourceParentCapture, error) {
	if source == nil || source.sealed || tx == nil || source.conn != tx.Conn() || tx != source.stageTX || source.lifetime == nil || source.lifetime.ended || source.lifetime.prepared != nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	return &resourceParentCapture{tx: tx, source: source, catalogs: make(map[string]*resourceCatalogCapture)}, nil
}
func resourceDecodeRows[T any](rows []resourceSourceRow) ([]T, error) {
	out := make([]T, 0, len(rows))
	for _, row := range rows {
		var value T
		if err := json.Unmarshal(row.value, &value); err != nil {
			return nil, kaname.ErrSourceUnconfirmed
		}
		out = append(out, value)
	}
	return out, nil
}
func (c *resourceParentCapture) catalog(ctx context.Context, typ string) (*resourceCatalogCapture, error) {
	if c == nil || c.source == nil || c.source.sealed || c.source.lifetime == nil || c.source.lifetime.ended || c.source.lifetime.prepared != nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if value, ok := c.catalogs[typ]; ok {
		return value, nil
	}
	value, err := readResourceCatalog(ctx, c.tx, typ, c.source.budget)
	if err != nil {
		return nil, err
	}
	c.catalogs[typ] = value
	return value, nil
}
func (c *resourceParentCapture) project(ctx context.Context, id string) (domain.ContainerScope, error) {
	rows, err := c.source.read(ctx, c.tx, resourceSourceKey{kind: resourceSourceProject, typ: "project", id: id})
	if err != nil {
		return domain.ContainerScope{}, err
	}
	type project struct {
		ID      string `json:"id"`
		Account string `json:"account_id"`
	}
	projects, err := resourceDecodeRows[project](rows)
	if err != nil {
		return domain.ContainerScope{}, err
	}
	if len(projects) == 0 {
		return domain.ContainerScope{}, nil
	}
	if len(projects) != 1 || projects[0].ID != id || !nativeQuestionToken(projects[0].Account) {
		return domain.ContainerScope{}, kaname.ErrSourceUnconfirmed
	}
	return domain.ContainerScope{Registered: true, ProjectID: id, AccountID: projects[0].Account}, nil
}

type resourceParentMirror struct {
	Project string `json:"parent_project_id"`
}

func (c *resourceParentCapture) mirror(ctx context.Context, typ, id string) (resourceParentMirror, bool, error) {
	catalog, err := c.catalog(ctx, typ)
	if err != nil {
		return resourceParentMirror{}, false, err
	}
	selected, ok := catalog.selected()
	if !ok {
		return resourceParentMirror{}, false, nil
	}
	rows, err := c.source.read(ctx, c.tx, resourceSourceKey{kind: resourceSourceMirror, typ: selected.identity.Dotted, id: id})
	if err != nil {
		return resourceParentMirror{}, false, err
	}
	mirrors, err := resourceDecodeRows[resourceParentMirror](rows)
	if err != nil {
		return resourceParentMirror{}, false, err
	}
	if len(mirrors) > 1 {
		return resourceParentMirror{}, false, kaname.ErrSourceUnconfirmed
	}
	if len(mirrors) == 0 {
		return resourceParentMirror{}, false, nil
	}
	return mirrors[0], true, nil
}
func (c *resourceParentCapture) chainProject(ctx context.Context, typ, id string) (string, error) {
	rows, err := c.source.read(ctx, c.tx, resourceSourceKey{kind: resourceSourceParentEdges, typ: typ, id: id})
	if err != nil {
		return "", err
	}
	type edge struct {
		Type  string `json:"parent_type"`
		ID    string `json:"parent_id"`
		Depth int    `json:"depth"`
	}
	edges, err := resourceDecodeRows[edge](rows)
	if err != nil {
		return "", err
	}
	var nearest edge
	for _, edge := range edges {
		if edge.Depth < 1 || edge.Depth > hierarchy.MaxStoredParentLinks || !nativeQuestionToken(edge.ID) {
			return "", kaname.ErrSourceUnconfirmed
		}
		if edge.Type != "project" {
			continue
		}
		if nearest.Depth == edge.Depth && nearest.ID != edge.ID {
			return "", kaname.ErrSourceUnconfirmed
		}
		if nearest.Depth == 0 || edge.Depth < nearest.Depth {
			nearest = edge
		}
	}
	return nearest.ID, nil
}
func (c *resourceParentCapture) permanentProject(ctx context.Context, typ, id string) (string, error) {
	rows, err := c.source.read(ctx, c.tx, resourceSourceKey{kind: resourceSourceProjectBinding, typ: typ, id: id})
	if err != nil {
		return "", err
	}
	type binding struct {
		Project string `json:"project_id"`
	}
	bindings, err := resourceDecodeRows[binding](rows)
	if err != nil {
		return "", err
	}
	if len(bindings) > 1 {
		return "", kaname.ErrSourceUnconfirmed
	}
	if len(bindings) == 0 {
		return "", nil
	}
	if !nativeQuestionToken(bindings[0].Project) {
		return "", kaname.ErrSourceUnconfirmed
	}
	return bindings[0].Project, nil
}
func (c *resourceParentCapture) storedProjects(ctx context.Context, typ, id string) ([]string, error) {
	rows, err := c.source.read(ctx, c.tx, resourceSourceKey{kind: resourceSourceRegistrationScopes, typ: typ, id: id})
	if err != nil {
		return nil, err
	}
	type scope struct {
		Project string `json:"project_id"`
	}
	scopes, err := resourceDecodeRows[scope](rows)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if !nativeQuestionToken(scope.Project) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		ids = append(ids, scope.Project)
	}
	slices.Sort(ids)
	return slices.Compact(ids), nil
}
func (c *resourceParentCapture) pointers(ctx context.Context, typ, id string, policy domain.WritePolicy, matchTypes bool) ([]string, error) {
	rows, err := c.source.read(ctx, c.tx, resourceSourceKey{kind: resourceSourcePointerFacts, typ: typ, id: id})
	if err != nil {
		return nil, err
	}
	type fact struct {
		Subject  string `json:"subject"`
		Relation string `json:"relation"`
	}
	facts, err := resourceDecodeRows[fact](rows)
	if err != nil {
		return nil, err
	}
	var subjects []string
	for _, fact := range facts {
		pointer, ok := policy.Pointer(fact.Relation)
		if !ok {
			continue
		}
		subjectType, subjectID, ok := strings.Cut(fact.Subject, ":")
		if !ok || !nativeQuestionToken(subjectType) || !nativeQuestionToken(subjectID) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if matchTypes && pointer.Type != subjectType {
			continue
		}
		subjects = append(subjects, fact.Subject)
	}
	slices.Sort(subjects)
	return slices.Compact(subjects), nil
}

// Канонический fallback старых регистраций сохраняет precedence SQL reader:
// явные scopes; затем reachable зарегистрированные контейнеры; затем постоянная
// привязка корня. Общий visited убирает повторные обходы, но не отбрасывает
// достижимый проект; при цикле он не выдумывает аккаунт из утверждений клиента.
func (c *resourceParentCapture) savedScopes(ctx context.Context, typ, id string) ([]domain.ContainerScope, error) {
	explicit, err := c.storedProjects(ctx, typ, id)
	if err != nil {
		return nil, err
	}
	if len(explicit) > 0 {
		out := make([]domain.ContainerScope, 0, len(explicit))
		for _, project := range explicit {
			scope, err := c.project(ctx, project)
			if err != nil {
				return nil, err
			}
			scope.Registered = true
			scope.ProjectID = project
			out = append(out, scope)
		}
		return out, nil
	}
	queue := []string{typ + ":" + id}
	seen := make(map[string]bool)
	projects := make(map[string]domain.ContainerScope)
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		anchor := queue[0]
		queue = queue[1:]
		if seen[anchor] {
			continue
		}
		seen[anchor] = true
		nodeType, nodeID, ok := strings.Cut(anchor, ":")
		if !ok || !nativeQuestionToken(nodeType) || !nativeQuestionToken(nodeID) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if nodeType == "project" {
			scope, err := c.project(ctx, nodeID)
			if err != nil {
				return nil, err
			}
			if scope.Registered {
				projects[nodeID] = scope
			}
			continue
		}
		mirror, found, err := c.mirror(ctx, nodeType, nodeID)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		project := mirror.Project
		if project == "" {
			project, err = c.chainProject(ctx, nodeType, nodeID)
			if err != nil {
				return nil, err
			}
		}
		if project == "" {
			project, err = c.permanentProject(ctx, nodeType, nodeID)
			if err != nil {
				return nil, err
			}
		}
		if project != "" {
			queue = append(queue, "project:"+project)
			continue
		}
		saved, err := c.storedProjects(ctx, nodeType, nodeID)
		if err != nil {
			return nil, err
		}
		if len(saved) > 0 {
			for _, project := range saved {
				queue = append(queue, "project:"+project)
			}
			continue
		}
		catalog, err := c.catalog(ctx, nodeType)
		if err != nil {
			return nil, err
		}
		selected, ok := catalog.selected()
		if !ok {
			return nil, kaname.ErrSourceUnconfirmed
		}
		parents, err := c.pointers(ctx, nodeType, nodeID, selected.policy, true)
		if err != nil {
			return nil, err
		}
		queue = append(queue, parents...)
	}
	if len(projects) == 0 {
		project, err := c.permanentProject(ctx, typ, id)
		if err != nil {
			return nil, err
		}
		if project != "" {
			scope, err := c.project(ctx, project)
			if err != nil {
				return nil, err
			}
			if scope.Registered {
				projects[project] = scope
			}
		}
	}
	ids := make([]string, 0, len(projects))
	for project := range projects {
		ids = append(ids, project)
	}
	slices.Sort(ids)
	out := make([]domain.ContainerScope, 0, len(ids))
	for _, project := range ids {
		out = append(out, projects[project])
	}
	return out, nil
}

func (c *resourceParentCapture) derive(ctx context.Context, subject, relation, object string, policy domain.WritePolicy, claim domain.ParentClaim) ([]domain.ParentHierarchy, []domain.ContainerScope, error) {
	_, id, ok := strings.Cut(object, ":")
	if !ok || !nativeQuestionToken(id) {
		return nil, nil, kaname.ErrSourceUnconfirmed
	}
	anchors := []string{subject}
	if _, isPointer := policy.Pointer(relation); !isPointer {
		var err error
		anchors, err = c.pointers(ctx, policy.ObjectType, id, policy, false)
		if err != nil {
			return nil, nil, err
		}
	}
	var hierarchies []domain.ParentHierarchy
	var scopes []domain.ContainerScope
	seen := make(map[string]bool)
	for _, anchor := range anchors {
		if seen[anchor] {
			continue
		}
		seen[anchor] = true
		branches, found, err := c.hierarchies(ctx, anchor)
		if err != nil {
			return nil, nil, err
		}
		if !found {
			continue
		}
		for _, h := range branches {
			if !h.Admits(claim) {
				continue
			}
			hierarchies = append(hierarchies, h)
			if h.AccountID != "" {
				scopes = append(scopes, domain.ContainerScope{Registered: true, ProjectID: h.ProjectID, AccountID: h.AccountID})
				continue
			}
			if len(h.Links) != 1 {
				return nil, nil, kaname.ErrSourceUnconfirmed
			}
			typ, id, ok := strings.Cut(h.Links[0], ":")
			if !ok || typ == "project" {
				return nil, nil, kaname.ErrSourceUnconfirmed
			}
			saved, err := c.savedScopes(ctx, typ, id)
			if err != nil {
				return nil, nil, err
			}
			for _, scope := range saved {
				if !scope.Registered || scope.AccountID == "" {
					return nil, nil, kaname.ErrSourceUnconfirmed
				}
			}
			if len(saved) == 0 {
				return nil, nil, kaname.ErrSourceUnconfirmed
			}
			scopes = append(scopes, saved...)
		}
	}
	if len(hierarchies) == 0 {
		return nil, nil, iamerr.ParentScopeMismatch(object, policy.ObjectType, id)
	}
	return hierarchies, scopes, nil
}
