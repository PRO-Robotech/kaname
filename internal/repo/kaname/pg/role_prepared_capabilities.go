// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

func exactPreparedRoleCapabilities(actual, expected []domain.GrantCapabilityRule) bool {
	if len(actual) != len(expected) {
		return false
	}
	counts := make(map[domain.GrantCapabilityRule]int, len(expected))
	for _, cap := range expected {
		counts[cap]++
	}
	for _, cap := range actual {
		if counts[cap] == 0 {
			return false
		}
		counts[cap]--
	}
	return true
}

// Разделяем только способы записи: apply уже применён pinned AFTER trigger,
// create/bind остаются в старых таблицах. Полный ввод сверяется ДО разделения.
func preparedLegacyCapabilities(caps []domain.GrantCapabilityRule) ([]domain.GrantCapabilityRule, bool, error) {
	legacy := make([]domain.GrantCapabilityRule, 0, len(caps))
	apply := false
	for _, cap := range caps {
		switch cap.Kind {
		case domain.GrantCapabilityCreateBinding, domain.GrantCapabilityBindRole:
			legacy = append(legacy, cap)
		case domain.GrantCapabilityApplyAccessLabel:
			if cap.DefinitionID == "" || cap.BoundRoleID != "" || !grantCapabilityFP.MatchString(cap.RuleFP) {
				return nil, false, kaname.ErrSourceUnconfirmed
			}
			apply = true
		default:
			return nil, false, kaname.ErrSourceUnconfirmed
		}
	}
	return legacy, apply, nil
}

func (w *preparedRoleWriteTx) liveRoleAttempt() bool {
	return w != nil && w.stage != nil && w.semanticAuthorityWriteTx != nil &&
		w.authorityWriteTx != nil && w.writeTx != nil && w.tx != nil && w.conn != nil && !w.closed
}

func (w *preparedRoleWriteTx) approvedApplyContent() bool {
	return w.liveRoleAttempt() && w.canReadAccessLabelSource() &&
		w.stage.accessLabelMode == roleAccessLabelApply && w.contentApprovalRecorded && !w.roleWriteSucceeded
}

// ProjectRoleMutationRules возвращает уже вычисленный полный stage image.
// Самостоятельного разрешения или повторной компиляции правил здесь нет.
func (w *preparedRoleWriteTx) ProjectRoleMutationRules(ctx context.Context, role domain.Role) (catalog.GrantProjection, error) {
	if err := ctx.Err(); err != nil {
		return catalog.GrantProjection{}, err
	}
	if !w.liveRoleAttempt() || w.roleWriteStarted || (!w.stage.request.Create && !w.stage.request.Rules) {
		return catalog.GrantProjection{}, kaname.ErrSourceUnconfirmed
	}
	expected := w.stage.request.Role
	if role.ID != expected.ID || role.AccountID != expected.AccountID || role.ProjectID != expected.ProjectID ||
		role.ClusterID != expected.ClusterID || role.IsSystem != expected.IsSystem || role.OwnerModule != expected.OwnerModule {
		return catalog.GrantProjection{}, kaname.ErrSourceUnconfirmed
	}
	requestedRules, err := rulesToJSON(role.Rules)
	if err != nil {
		return catalog.GrantProjection{}, err
	}
	preparedRules, err := rulesToJSON(expected.Rules)
	if err != nil {
		return catalog.GrantProjection{}, err
	}
	if !bytes.Equal(requestedRules, preparedRules) {
		return catalog.GrantProjection{}, kaname.ErrSourceUnconfirmed
	}
	_, apply, err := preparedLegacyCapabilities(w.stage.projection.Capabilities)
	if err != nil {
		return catalog.GrantProjection{}, err
	}
	if err = w.stage.accessLabelMode.requireSupported(); err != nil {
		return catalog.GrantProjection{}, err
	}
	if (w.stage.accessLabelMode == roleAccessLabelApply) != apply ||
		(w.stage.accessLabelMode != roleAccessLabelOrdinary &&
			(!w.canReadAccessLabelSource() || !w.contentApprovalRecorded || w.roleWriteSucceeded)) {
		return catalog.GrantProjection{}, kaname.ErrSourceUnconfirmed
	}
	// Копия не даёт body изменить сохранённую проекцию через slice/map aliases.
	raw, err := json.Marshal(w.stage.projection)
	if err != nil {
		return catalog.GrantProjection{}, err
	}
	var result catalog.GrantProjection
	if err = json.Unmarshal(raw, &result); err != nil {
		return catalog.GrantProjection{}, err
	}
	return result, nil
}

func (w *preparedRoleRowWriter) LockGrantAuthoringAxes(ctx context.Context, caps []domain.GrantCapabilityRule) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.owner == nil || w.owner.stage == nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	for _, cap := range caps {
		if !slices.Contains(w.owner.stage.projection.Capabilities, cap) {
			return kaname.ErrInvalidAuthorityFencePlan
		}
	}
	legacy, apply, err := preparedLegacyCapabilities(caps)
	if err != nil {
		return err
	}
	if apply && (!exactPreparedRoleCapabilities(caps, w.owner.stage.projection.Capabilities) || !w.owner.approvedApplyContent()) {
		return kaname.ErrSourceUnconfirmed
	}
	raw, ok := w.WriterIface.(*roleWriter)
	if !ok {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	// Apply axis/definition locks уже подтверждены owner prepare + content stamp
	// до final clock. Raw путь продолжает судить только прежние create/bind axes.
	return raw.LockGrantAuthoringAxes(ctx, legacy)
}

func (w *preparedRoleRowWriter) ReplaceGrantCapabilities(ctx context.Context, id domain.RoleID, caps []domain.GrantCapabilityRule) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !w.owner.liveRoleAttempt() || !w.owner.roleWriteSucceeded || w.owner.grantCapabilitiesReplaced ||
		id != w.owner.stage.request.Role.ID || !exactPreparedRoleCapabilities(caps, w.owner.stage.projection.Capabilities) {
		return kaname.ErrSourceUnconfirmed
	}
	if err := w.owner.stage.accessLabelMode.requireSupported(); err != nil {
		return err
	}
	legacy, apply, err := preparedLegacyCapabilities(caps)
	if err != nil {
		return err
	}
	if (w.owner.stage.accessLabelMode == roleAccessLabelApply) != apply ||
		(w.owner.stage.accessLabelMode != roleAccessLabelOrdinary && !w.owner.contentApprovalRecorded) {
		return kaname.ErrSourceUnconfirmed
	}
	raw, ok := w.WriterIface.(*roleWriter)
	if !ok {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	// Успех INSERT/UPDATE означает завершение pinned AFTER origin apply.
	// Deferred completion ещё проверит всю exact проекцию при commit.
	// Здесь нет прямой записи private apply таблицы и нет права опустить её:
	// полный набор выше равен stage, raw получает лишь свой create/bind остаток.
	// w.owner.applied не проверяем: штатный Update уже reconciled tuples.
	if err = raw.ReplaceGrantCapabilities(ctx, id, legacy); err != nil {
		return err
	}
	w.owner.grantCapabilitiesReplaced = true
	return nil
}
