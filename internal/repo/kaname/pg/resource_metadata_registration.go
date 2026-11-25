// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/hierarchy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

func (c *resourceSourceCapture) metadataRegistrationSources(ctx context.Context, tx pgx.Tx) (*resourceParentCapture, error) {
	if c.metadataParents != nil {
		return c.metadataParents, nil
	}
	parents, err := newResourceParentCapture(tx, c)
	if err != nil {
		return nil, err
	}
	// RLS или подмена таблицы не должны скрыть строки регистрации и привязок.
	err = checkMetadataSourceTableShapes(ctx, parents, []string{
		"kaname.access_bindings", "kaname.accounts", "kaname.catalog_resource", "kaname.catalog_verb", "kaname.object_project_binding",
		"kaname.producer_source_receipt", "kaname.projects", "kaname.relation_fact", "kaname.resource_mirror",
		"kaname.resource_parent_edge", "kaname.resource_registration_pointer", "kaname.resource_registration_retirement",
		"kaname.resource_registration_scope", "kaname.role_rule_selectors", "kaname.roles",
	})
	if err != nil {
		return nil, err
	}
	c.metadataParents = parents
	return parents, nil
}

func (p *resourceParentCapture) confirmMetadataRegistration(ctx context.Context, dotted, id, project, account string) error {
	catalog, err := p.catalog(ctx, dotted)
	if err != nil {
		return err
	}
	selected, ok := catalog.selected()
	if !ok || !selected.live || selected.identity.Dotted != dotted || selected.identity.Module == "iam" {
		return kaname.ErrSourceUnconfirmed
	}
	// Используем предикаты штатной регистрации, включая пустые наборы. Версии
	// подтверждений и отзыва принадлежат отдельным кортежам, поэтому здесь их
	// сохраняем целиком для повторной сверки, без сравнения с версией зеркала.
	if err = captureResourceDirectSources(ctx, p, selected, id, kaname.ResourceDecisionRegister); err != nil {
		return err
	}
	modelType := selected.identity.ObjectType
	boundProject, err := p.permanentProject(ctx, modelType, id)
	if err != nil {
		return err
	}
	if boundProject != "" && boundProject != project {
		return kaname.ErrSourceUnconfirmed
	}

	scopeRows, err := p.source.read(ctx, p.tx, resourceSourceKey{kind: resourceSourceRegistrationScopes, typ: modelType, id: id})
	if err != nil {
		return err
	}
	type registrationScope struct {
		Project string `json:"project_id"`
		Account string `json:"account_id"`
	}
	scopes, err := resourceDecodeRows[registrationScope](scopeRows)
	if err != nil {
		return err
	}
	for _, scope := range scopes {
		if scope.Project != project || scope.Account != account {
			return kaname.ErrSourceUnconfirmed
		}
	}

	edgeRows, err := p.source.read(ctx, p.tx, resourceSourceKey{kind: resourceSourceParentEdges, typ: modelType, id: id})
	if err != nil {
		return err
	}
	type parentEdge struct {
		Type  string `json:"parent_type"`
		ID    string `json:"parent_id"`
		Depth int    `json:"depth"`
	}
	edges, err := resourceDecodeRows[parentEdge](edgeRows)
	if err != nil {
		return err
	}
	for _, edge := range edges {
		if edge.Depth < 1 || edge.Depth > hierarchy.MaxStoredParentLinks ||
			!nativeQuestionToken(edge.Type) || !nativeQuestionToken(edge.ID) ||
			(edge.Type == "project" && edge.ID != project) ||
			(edge.Type == "account" && edge.ID != account) {
			return kaname.ErrSourceUnconfirmed
		}
	}
	return nil
}
