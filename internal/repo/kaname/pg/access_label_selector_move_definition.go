// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// До построения возможных копий убираем уже истёкших носителей. Сверка
// решения ниже не позволяет использовать часы, предшествующие RR.
func (p *resourceParentCapture) filterAccessLabelMoveTargets(
	ctx context.Context, census accessLabelMoveTargetCensus,
) (accessLabelMoveTargetCensus, time.Time, error) {
	hasExpiring := slices.ContainsFunc(census, func(item accessLabelMoveBindingTargets) bool {
		return item.carrier.Binding.ExpiresAt != nil
	})
	if !hasExpiring {
		return census, time.Time{}, ctx.Err()
	}
	if err := p.source.budget.Charge(len(census), 1); err != nil {
		return nil, time.Time{}, err
	}
	var at time.Time
	if err := p.tx.QueryRow(ctx, `SELECT pg_catalog.transaction_timestamp()`).Scan(&at); err != nil {
		return nil, time.Time{}, err
	}
	if at.IsZero() {
		return nil, time.Time{}, kaname.ErrSourceUnconfirmed
	}
	eligible := make(accessLabelMoveTargetCensus, 0, len(census))
	for _, item := range census {
		if item.carrier.canSelectAt(at) {
			eligible = append(eligible, item)
		}
	}
	return eligible, at, ctx.Err()
}

func (p *resourceParentCapture) captureAccessLabelMoveDefinitionTargets(
	ctx context.Context, captured accessLabelSelectorMoveCapture,
) (map[domain.ResourceRef][]int, error) {
	role := captured.Before
	anchor, err := accessLabelMoveRoleScope(role)
	if err != nil {
		return nil, err
	}
	account := string(role.AccountID)
	if anchor.Type == "project" {
		account, err = p.accessLabelMoveProjectAccount(ctx, anchor.ID)
		if err != nil {
			return nil, err
		}
	}
	key := resourceSourceKey{kind: resourceSourceAccount, typ: "account", id: account}
	rows, err := p.source.read(ctx, p.tx, key)
	if err != nil {
		return nil, err
	}
	var owner struct {
		ID string `json:"id"`
	}
	if len(rows) != 1 || json.Unmarshal(rows[0].value, &owner) != nil || owner.ID != account {
		return nil, kaname.ErrSourceUnconfirmed
	}
	scope := reconcile.BindingScope{Scope: anchor, Target: domain.AccessTarget{AllInScope: true}}
	source := resourceSourceKey{kind: resourceSourceRoleSelectorObjects, id: string(role.ID)}
	selectors, err := accessLabelMoveSelectors(captured, p.source.budget)
	if err != nil {
		return nil, err
	}
	targets := make(map[domain.ResourceRef][]int)
	for i, selector := range selectors {
		if err = p.addAccessLabelMoveTargets(ctx, source, scope, selector, captured.Moves[i], i, targets); err != nil {
			return nil, err
		}
	}
	return targets, ctx.Err()
}

func accessLabelMoveRoleScope(role domain.Role) (domain.ScopeAnchor, error) {
	// System/module роли не имеют области определения для tenant Role.Update.
	if role.IsSystem || role.ClusterID != "" || role.OwnerModule != "" || (role.AccountID == "") == (role.ProjectID == "") {
		return domain.ScopeAnchor{}, kaname.ErrSourceUnconfirmed
	}
	if role.ProjectID != "" {
		return domain.ScopeAnchor{Type: "project", ID: string(role.ProjectID)}, nil
	}
	return domain.ScopeAnchor{Type: "account", ID: string(role.AccountID)}, nil
}

// Для зеркала явный account override не должен расходиться с физическим
// проектом. Перепись содержит версию родительского проекта и его аккаунта.
func (p *resourceParentCapture) confirmAccessLabelMoveDefinitionProject(ctx context.Context, object domain.MirrorObject) error {
	if object.ParentProjectID == "" || domain.FeedSourceForType(object.ObjectType) != domain.FeedMirror {
		return nil
	}
	account, err := p.accessLabelMoveProjectAccount(ctx, object.ParentProjectID)
	if err != nil {
		return err
	}
	if len(object.ParentAccountIDs) != 1 || object.ParentAccountIDs[0] != account {
		return kaname.ErrSourceUnconfirmed
	}
	return ctx.Err()
}

func (p *resourceParentCapture) accessLabelMoveProjectAccount(ctx context.Context, id string) (string, error) {
	project, err := p.project(ctx, id)
	if err != nil {
		return "", err
	}
	if !project.Registered {
		return "", kaname.ErrSourceUnconfirmed
	}
	return project.AccountID, nil
}

// Не расширяем read footprint после RR. Если последний носитель истёк за
// время ожидания блокировок, новая попытка снимет область определения.
func (captured accessLabelSelectorMoveCapture) copyTargetsAt(
	ctx context.Context, at time.Time, budget *relverdict.AdministrativeReadBudget,
) (map[domain.ResourceRef][]int, error) {
	if !captured.targetsSnapshotAt.IsZero() && at.Before(captured.targetsSnapshotAt) {
		return nil, kaname.ErrAuthorityClassificationChanged
	}
	targets, err := captured.BindingTargets.targetsAt(ctx, at, budget)
	if err != nil || targets != nil {
		return targets, err
	}
	if captured.DefinitionTargets == nil {
		return nil, kaname.ErrAuthorityClassificationChanged
	}
	result := make(map[domain.ResourceRef][]int, len(captured.DefinitionTargets))
	for ref, indices := range captured.DefinitionTargets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := budget.Charge(1+len(indices), 0); err != nil {
			return nil, err
		}
		result[ref] = slices.Clone(indices)
	}
	return result, ctx.Err()
}
