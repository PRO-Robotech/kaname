// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/stretchr/testify/require"
)

func TestAccessLabelMoveDefinitionTargetsUseHeldAccountAndProject(t *testing.T) {
	const typ = "registry.registries"
	role := domain.Role{ID: "rol-move", AccountID: "acc-move", Rules: domain.Rules{{
		Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"team": "red"},
	}}}
	_, moves, err := role.Rules.PlanAccessLabelSelectorMoves([]domain.AccessLabelSelectorMove{{
		Fingerprint: role.Rules[0].Fingerprint(),
	}}, domain.PolicyOfRole(false, ""), domain.ModuleSetOf("registry"))
	require.NoError(t, err)
	p := parentCaptureFixture(t)
	scope := domain.ScopeAnchor{Type: "account", ID: string(role.AccountID)}
	anchor := resourceSourceKey{kind: resourceSourceAccount, typ: scope.Type, id: scope.ID}
	parentCaptureRows(t, p, anchor, map[string]string{"id": scope.ID})

	predicate := resourceSelectorPredicate{RuleFP: role.Rules[0].Fingerprint(), Arm: domain.ArmLabels,
		Scope: scope, Labels: role.Rules[0].MatchLabels, Targets: []string{}}
	raw, err := json.Marshal(predicate)
	require.NoError(t, err)
	key := resourceSourceKey{kind: resourceSourceRoleSelectorObjects, typ: typ, id: string(role.ID), projection: string(raw)}
	query, args, err := resourceSourceSQL(key, 9)
	require.NoError(t, err)
	require.Contains(t, query, "COALESCE(NULLIF(o.parent_account_id,''),p.account_id,'')=$7::text")
	require.Contains(t, query, "AND ($6::text='cluster'")
	require.Contains(t, query, "OR p.account_id=$7::text")
	require.Equal(t, scope.ID, args[6])
	require.Equal(t, 9, args[1])

	const id = "target"
	project := resourceSourceKey{kind: resourceSourceProject, typ: "project", id: "prj-move"}
	parentCaptureRows(t, p, key, map[string]string{"object_type": typ, "object_id": id})
	parentCaptureRows(t, p, project, map[string]string{"id": project.id, "account_id": scope.ID})
	mirror := resourceSourceKey{kind: resourceSourceMirror, typ: typ, id: id}
	putMirror := func(account string) {
		parentCaptureRows(t, p, mirror, map[string]any{"object_type": typ, "object_id": id, "parent_project_id": project.id,
			"parent_account_id": account, "labels": role.Rules[0].MatchLabels})
	}
	putMirror(scope.ID)
	captured := accessLabelSelectorMoveCapture{Before: role, Moves: moves}
	targets, err := p.captureAccessLabelMoveDefinitionTargets(t.Context(), captured)
	require.NoError(t, err)
	require.Equal(t, map[domain.ResourceRef][]int{{Type: typ, ID: id}: {0}}, targets)
	_, _, err = makeResourceProposalEnvelope(json.RawMessage("{}"), p, resourceFenceFootprint{})
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "протокол ресурса не удостоверяет область роли")

	parentCaptureRows(t, p, project, map[string]string{"id": project.id, "account_id": "acc-foreign"})
	_, err = p.captureAccessLabelMoveDefinitionTargets(t.Context(), captured)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "явный аккаунт зеркала не перекрывает физический проект")

	parentCaptureRows(t, p, project, map[string]string{"id": project.id, "account_id": scope.ID})
	putMirror("acc-foreign")
	_, err = p.captureAccessLabelMoveDefinitionTargets(t.Context(), captured)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "подходящий проект не скрывает чужой явный аккаунт")

	captured.Before.AccountID, captured.Before.ProjectID = "", domain.ProjectID(project.id)
	projectScope := domain.ScopeAnchor{Type: "project", ID: project.id}
	predicate.Scope = projectScope
	raw, err = json.Marshal(predicate)
	require.NoError(t, err)
	key.projection = string(raw)
	parentCaptureRows(t, p, key)
	parentCaptureRows(t, p, anchor)
	_, err = p.captureAccessLabelMoveDefinitionTargets(t.Context(), captured)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "пустая область проекта требует свидетельства аккаунта")

	parentCaptureRows(t, p, anchor, map[string]string{"id": scope.ID})
	targets, err = p.captureAccessLabelMoveDefinitionTargets(t.Context(), captured)
	require.NoError(t, err)
	require.NotNil(t, targets)
	require.Empty(t, targets)

	captured.Before.OwnerModule = "registry"
	_, err = p.captureAccessLabelMoveDefinitionTargets(t.Context(), captured)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}

func TestAccessLabelMoveCopyTargetsDoNotWidenAfterClockWait(t *testing.T) {
	at := time.Unix(1234, 0)
	expires := at.Add(time.Second)
	ref := domain.ResourceRef{Type: "iam.project", ID: "prj-target"}
	captured := accessLabelSelectorMoveCapture{
		BindingTargets: accessLabelMoveTargetCensus{{
			carrier: accessLabelSelectorMoveCarrier{Binding: domain.AccessBinding{
				Status: domain.AccessBindingStatusPending, ExpiresAt: &expires,
			}},
		}},
	}
	budget := &relverdict.AdministrativeReadBudget{}
	targets, err := captured.copyTargetsAt(t.Context(), at, budget)
	require.NoError(t, err)
	require.NotNil(t, targets)
	require.Empty(t, targets, "пустая выдача оставляет свою область")

	_, err = captured.copyTargetsAt(t.Context(), expires, budget)
	require.ErrorIs(t, err, kaname.ErrAuthorityClassificationChanged, "новую область снимаем новой попыткой")

	captured.DefinitionTargets = map[domain.ResourceRef][]int{ref: {0}}
	targets, err = captured.copyTargetsAt(t.Context(), expires, budget)
	require.NoError(t, err)
	require.Equal(t, captured.DefinitionTargets, targets)
	targets[ref][0] = 11
	require.Equal(t, []int{0}, captured.DefinitionTargets[ref], "удержанный результат снимка остаётся неизменным")
}
