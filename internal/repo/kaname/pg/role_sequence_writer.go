// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
	roleport "github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
)

func roleSequenceInput(request kaname.RoleMutationRequest) ([]byte, error) {
	r := request.Role
	rules, err := rulesToJSON(r.Rules)
	if err != nil {
		return nil, err
	}
	labels, err := marshalLabels(r.Labels)
	if err != nil {
		return nil, err
	}
	mask := append([]string{}, request.UpdateMask...)
	return json.Marshal(map[string]any{
		"create": request.Create, "rules": request.Rules, "retier": request.Tuples != nil,
		"mask": mask, "version": request.ExpectedVersion,
		"role": map[string]any{"id": string(r.ID), "account_id": string(r.AccountID), "project_id": string(r.ProjectID),
			"name": string(r.Name), "description": string(r.Description), "rules": json.RawMessage(rules),
			"permissions": stringSlice(r.Permissions), "labels": json.RawMessage(labels)},
	})
}
func (s *roleMutationStage) prepareSequenceProgram(ctx context.Context, w *authorityWriteTx) error {
	if s == nil || s.plan == nil || s.plan.nativeBudget == nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	raw, err := roleSequenceInput(s.request)
	if err != nil {
		return err
	}
	var costJSON []byte
	if err = w.tx.QueryRow(ctx, `SELECT kaname.authority_role_sequence_prepare_v3($1::jsonb,$2,$3)`, raw,
		s.plan.nativeBudget.RemainingRows(), s.plan.nativeBudget.RemainingReads()).Scan(&costJSON); err != nil {
		return err
	}
	var cost struct {
		Rows  int `json:"rows"`
		Reads int `json:"reads"`
	}
	if err = json.Unmarshal(costJSON, &cost); err != nil {
		return err
	}
	return chargeNativePolicyBudget(s.plan.nativeBudget, cost.Rows, cost.Reads)
}
func (w *preparedRoleWriteTx) RolesW() roleport.WriterIface {
	return &preparedRoleRowWriter{WriterIface: w.semanticAuthorityWriteTx.RolesW(), owner: w}
}

type preparedRoleRowWriter struct {
	roleport.WriterIface
	owner *preparedRoleWriteTx
}

func (w *preparedRoleRowWriter) stamp(ctx context.Context, r domain.Role, create bool, mask []string, version string) (time.Time, error) {
	if w.owner == nil || w.owner.stage == nil {
		return time.Time{}, kaname.ErrInvalidAuthorityFencePlan
	}
	expected := w.owner.stage.request
	if expected.Create != create || expected.Role.ID != r.ID || (!create && (!expected.Update ||
		expected.ExpectedVersion != version || !slices.Equal(expected.UpdateMask, mask))) {
		return time.Time{}, kaname.ErrInvalidAuthorityFencePlan
	}
	expected.Role = r
	raw, err := roleSequenceInput(expected)
	if err != nil {
		return time.Time{}, err
	}
	var stamp time.Time
	err = w.owner.tx.QueryRow(ctx, `SELECT kaname.authority_role_sequence_stamp_v3($1::jsonb)`, raw).Scan(&stamp)
	return stamp, err
}
func (w *preparedRoleRowWriter) Insert(ctx context.Context, r domain.Role) (domain.Role, error) {
	stamp, err := w.stamp(ctx, r, true, nil, "")
	if err != nil {
		return domain.Role{}, err
	}
	raw, ok := w.WriterIface.(*roleWriter)
	if !ok {
		return domain.Role{}, kaname.ErrInvalidAuthorityFencePlan
	}
	return raw.insertAt(ctx, r, stamp)
}
func (w *preparedRoleRowWriter) UpdateCAS(ctx context.Context, r domain.Role, mask []string, version string) (domain.Role, error) {
	stamp, err := w.stamp(ctx, r, false, mask, version)
	if err != nil {
		return domain.Role{}, err
	}
	raw, ok := w.WriterIface.(*roleWriter)
	if !ok {
		return domain.Role{}, kaname.ErrInvalidAuthorityFencePlan
	}
	return raw.updateCASAt(ctx, r, mask, version, stamp)
}

// Отзыв использует уже принятое время, а не новое clock_timestamp в emitter.
func emitPreparedBindingDelete(ctx context.Context, w *authorityWriteTx, tuples []ab.RelationTuple) error {
	if w == nil || w.fence.decisionAt.IsZero() {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	exact := make([]clients.RelationTuple, 0, len(tuples))
	for _, tuple := range tuples {
		exact = append(exact, clients.RelationTuple{User: tuple.User, Relation: tuple.Relation, Object: tuple.Object})
	}
	return mapErr(fga_outbox.EmitDecisionTx(ctx, w.tx, fga_outbox.EventTypeDelete, exact, w.fence.decisionAt), "", "")
}

// Декоратор времени сохраняет reference-порт только для уже закрытого stage.
// Физические SHARE locks owner/axis/reference получены lockMutation до finalclock.
func (w *preparedRoleRowWriter) LockGrantAuthoringAxes(ctx context.Context, caps []domain.GrantCapabilityRule) error {
	if w.owner == nil || w.owner.stage == nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	for _, cap := range caps {
		found := false
		for _, expected := range w.owner.stage.projection.Capabilities {
			if cap.Kind == expected.Kind && cap.BoundRoleID == expected.BoundRoleID {
				found = true
				break
			}
		}
		if !found {
			return kaname.ErrInvalidAuthorityFencePlan
		}
	}
	refs, ok := w.WriterIface.(roleport.GrantReferenceReader)
	if !ok {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	return refs.LockGrantAuthoringAxes(ctx, caps)
}
func (w *preparedRoleRowWriter) LockGrantOwnerAccount(ctx context.Context, r domain.Role) (domain.AccountID, error) {
	if w.owner == nil || w.owner.stage == nil {
		return "", kaname.ErrInvalidAuthorityFencePlan
	}
	expected := w.owner.stage.request.Role
	if r.ID != expected.ID || r.AccountID != expected.AccountID || r.ProjectID != expected.ProjectID || r.IsSystem != expected.IsSystem {
		return "", kaname.ErrInvalidAuthorityFencePlan
	}
	refs, ok := w.WriterIface.(roleport.GrantReferenceReader)
	if !ok {
		return "", kaname.ErrInvalidAuthorityFencePlan
	}
	return refs.LockGrantOwnerAccount(ctx, r)
}
func (w *preparedRoleRowWriter) LockGrantReference(ctx context.Context, id domain.RoleID) (roleport.GrantReference, error) {
	if w.owner == nil || w.owner.stage == nil {
		return roleport.GrantReference{}, kaname.ErrInvalidAuthorityFencePlan
	}
	found := false
	for _, cap := range w.owner.stage.projection.Capabilities {
		if cap.Kind == domain.GrantCapabilityBindRole && cap.BoundRoleID == id {
			found = true
			break
		}
	}
	if !found {
		return roleport.GrantReference{}, kaname.ErrInvalidAuthorityFencePlan
	}
	refs, ok := w.WriterIface.(roleport.GrantReferenceReader)
	if !ok {
		return roleport.GrantReference{}, kaname.ErrInvalidAuthorityFencePlan
	}
	return refs.LockGrantReference(ctx, id)
}

var _ roleport.GrantReferenceReader = (*preparedRoleRowWriter)(nil)
