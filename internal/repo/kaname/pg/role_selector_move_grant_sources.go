// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type roleSelectorMoveBindingSource struct {
	Before, After granteffect.Binding
	Changes       bool
	Pending       bool
	ExpiresAt     *time.Time
}

type roleSelectorMoveGrantProjection struct {
	role      domain.Role
	confirmed bool
}

type roleSelectorMoveGrantProjections struct {
	move   *roleSelectorMoveStage
	writer *authorityWriteTx
	roles  map[domain.RoleID]roleSelectorMoveGrantProjection
}

// Проекции читаются после сверки RR на том же удерживаемом писателе.
// Истечение выдач проверяется позднее, по единому времени решения.
func (s *roleSelectorMoveStage) verifyGrantProjections(
	ctx context.Context, w *semanticAuthorityWriteTx,
) (roleSelectorMoveGrantProjections, error) {
	var zero roleSelectorMoveGrantProjections
	source := s.grantCapture()
	if source == nil || w == nil || source.lifetime == nil || !source.lifetime.beforeDecision(w.authorityWriteTx) ||
		source.lifetime.bundle != w.bundle || source.budget != w.producerBudget {
		return zero, kaname.ErrSourceUnconfirmed
	}
	roles := make(map[domain.RoleID]roleSelectorMoveGrantProjection)
	for _, scopes := range [][]accessLabelSelectorMoveScope{s.captured.Carriers, s.captured.Collateral} {
		if err := chargeNativePolicyBudget(source.budget, len(scopes), 0); err != nil {
			return zero, err
		}
		for _, scope := range scopes {
			if err := ctx.Err(); err != nil {
				return zero, err
			}
			if !scope.Carrier.canSelect() {
				continue
			}
			id := scope.Carrier.Binding.RoleID
			if _, seen := roles[id]; seen {
				continue
			}
			role, err := selectorMoveGrantRole(source, id)
			if err != nil {
				return zero, err
			}
			var confirmed bool
			if role.Lifecycle.State == domain.RoleLifecycleDeclared {
				_, cost, checkErr := w.RoleProjectionCheckpoint(ctx, id)
				if err = w.ChargeSourceRead(cost); err != nil {
					return zero, err
				}
				if checkErr != nil && !errors.Is(checkErr, kaname.ErrSourceUnconfirmed) {
					return zero, checkErr
				}
				confirmed = checkErr == nil
			}
			roles[id] = roleSelectorMoveGrantProjection{role: role, confirmed: confirmed}
		}
	}
	return roleSelectorMoveGrantProjections{move: s, writer: w.authorityWriteTx, roles: roles}, ctx.Err()
}

func (s *roleSelectorMoveStage) grantCapture() *resourceSourceCapture {
	if s == nil || s.replay == nil || s.replay.parents == nil {
		return nil
	}
	source := s.replay.parents.source
	if source == nil || !source.sealed || source.budget == nil || s.captured.proof == nil || s.captured.proof.source != source {
		return nil
	}
	return source
}

func selectorMoveGrantRole(source *resourceSourceCapture, id domain.RoleID) (domain.Role, error) {
	key := resourceSourceKey{kind: resourceSourceRole, typ: "role", id: string(id)}
	rows := source.entries[key]
	var lifecycle struct {
		Live *bool `json:"live"`
	}
	if len(rows) != 1 || json.Unmarshal(rows[0].value, &lifecycle) != nil || lifecycle.Live == nil {
		return domain.Role{}, kaname.ErrSourceUnconfirmed
	}
	role, err := resourceCapturedRole(rows[0].value)
	if err != nil || role.ID != id {
		return domain.Role{}, kaname.ErrSourceUnconfirmed
	}
	role.Lifecycle.State = domain.RoleLifecycleWithdrawn
	if *lifecycle.Live {
		role.Lifecycle.State = domain.RoleLifecycleDeclared
	}
	return role, nil
}

// Для модели используются авторские правила целиком. Сохранённая раскладка
// materializer может удалять ветви, нужные модели для проверки будущих выдач.
func (s *roleSelectorMoveStage) grantBindingSources(
	ctx context.Context, w *semanticAuthorityWriteTx, projected roleSelectorMoveGrantProjections,
	effects []accessLabelMoveBindingEffect,
) ([]roleSelectorMoveBindingSource, error) {
	source := s.grantCapture()
	if source == nil || w == nil || projected.move != s || projected.writer != w.authorityWriteTx ||
		source.budget != w.producerBudget || !source.lifetime.valid(w.authorityWriteTx, w.bundle) ||
		len(effects) != len(s.captured.Carriers)+len(s.captured.Collateral) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	var out []roleSelectorMoveBindingSource
	at := w.fence.decisionAt
	effectIndex := 0
	var proposed domain.Role
	versions, err := selectorMoveGrantCapabilityVersions(ctx, source, s.captured.Before.ID, s.captured.Carriers)
	if err != nil {
		return nil, err
	}
	for i, scopes := range [][]accessLabelSelectorMoveScope{s.captured.Carriers, s.captured.Collateral} {
		if err := chargeNativePolicyBudget(source.budget, len(scopes), 0); err != nil {
			return nil, err
		}
		for _, scope := range scopes {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			effect := effects[effectIndex]
			effectIndex++
			b := scope.Carrier.Binding
			moved := i == 0
			eligible := scope.Carrier.canSelectAt(at)
			pending := eligible && !scope.Carrier.activeAt(at)
			if effect.BindingID != b.ID || (b.RoleID == s.captured.Before.ID) != moved || effect.Pending != pending {
				return nil, kaname.ErrSourceUnconfirmed
			}
			if !eligible {
				continue
			}
			projection, known := projected.roles[b.RoleID]
			if !known || projection.role.ID != b.RoleID {
				return nil, kaname.ErrSourceUnconfirmed
			}
			// Даже без локальных новых кортежей меняется покрытие будущих
			// дочерних объектов под скопированными предками.
			if projection.role.Lifecycle.State == domain.RoleLifecycleWithdrawn && !moved {
				continue
			}
			if !projection.confirmed {
				return nil, kaname.ErrSourceUnconfirmed
			}
			version, known := versions[b.ID]
			if !moved {
				rows := source.entries[resourceSourceKey{kind: resourceSourceBinding, typ: "binding", id: string(b.ID)}]
				if len(rows) != 1 {
					return nil, kaname.ErrSourceUnconfirmed
				}
				id, role, v, err := selectorMoveGrantCapabilityVersion(rows[0])
				if err != nil || id != b.ID || role != b.RoleID {
					return nil, kaname.ErrSourceUnconfirmed
				}
				version, known = v, true
			}
			if !known {
				return nil, kaname.ErrSourceUnconfirmed
			}
			if err = chargeNativePolicyBudget(source.budget, len(b.Subjects), 0); err != nil {
				return nil, err
			}
			subjects, err := domain.NormalizeSubjects(b.Subjects, "", "")
			if err != nil {
				return nil, kaname.ErrSourceUnconfirmed
			}
			if len(subjects) > granteffect.MaxEffects-len(out) {
				return nil, kaname.ErrSourceReadLimit
			}
			before := granteffect.Binding{SourceID: string(b.ID), Role: projection.role, Scope: scopeAnchorFor(b),
				Target: b.Target, Subjects: subjects, CapabilityVersion: version}
			after := before
			if moved {
				if proposed.ID == "" {
					next, err := s.facts.ProjectRoleMutationRules(s.captured.ProposedRules, domain.PolicyOfRole(before.Role.IsSystem, before.Role.OwnerModule))
					if err != nil {
						return nil, err
					}
					proposed = before.Role
					proposed.Rules = s.captured.ProposedRules
					proposed.Permissions = next.Permissions
				}
				after.Role = proposed
			}
			for _, recipient := range subjects {
				before.Recipient, after.Recipient = recipient, recipient
				out = append(out, roleSelectorMoveBindingSource{Before: before, After: after, Changes: moved, Pending: pending, ExpiresAt: b.ExpiresAt})
			}
		}
	}
	return out, ctx.Err()
}

// Собственные выдачи захвачены полным предикатом role_id, соседние по id.
// Версию берём из этих же физических строк и сохраняем на обеих сторонах.
func selectorMoveGrantCapabilityVersions(
	ctx context.Context, source *resourceSourceCapture, roleID domain.RoleID, carriers []accessLabelSelectorMoveScope,
) (map[domain.AccessBindingID]int, error) {
	rows, present := source.entries[resourceSourceKey{kind: resourceSourceRoleBindings, typ: "role", id: string(roleID)}]
	if !present || len(rows) != len(carriers) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if err := chargeNativePolicyBudget(source.budget, len(rows), 0); err != nil {
		return nil, err
	}
	versions := make(map[domain.AccessBindingID]int, len(rows))
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		id, role, version, err := selectorMoveGrantCapabilityVersion(row)
		if _, duplicate := versions[id]; err != nil || role != roleID || duplicate {
			return nil, kaname.ErrSourceUnconfirmed
		}
		versions[id] = version
	}
	return versions, nil
}

func selectorMoveGrantCapabilityVersion(row resourceSourceRow) (domain.AccessBindingID, domain.RoleID, int, error) {
	var record struct {
		ID      domain.AccessBindingID `json:"id"`
		Role    domain.RoleID          `json:"role_id"`
		Version *int                   `json:"grant_capability_version"`
	}
	if json.Unmarshal(row.value, &record) != nil || !nativeQuestionToken(string(record.ID)) || !nativeQuestionToken(string(record.Role)) ||
		record.Version == nil || (*record.Version != 0 && *record.Version != 1) {
		return "", "", 0, kaname.ErrSourceUnconfirmed
	}
	return record.ID, record.Role, *record.Version, nil
}
