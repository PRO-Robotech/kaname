// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
	roleport "github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
)

const roleSequencePrepareSQL = `SELECT kaname.authority_role_sequence_prepare_v3($1::jsonb,$2,$3)`

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
	// Обычная подпись не содержит свидетельства переноса. Такой запрос
	// должен пройти отдельную проверку источников и эффектов владельцем.
	if s.selectorMove != nil {
		return kaname.ErrSourceUnconfirmed
	}
	raw, err := roleSequenceInput(s.request)
	if err != nil {
		return err
	}
	raw, err = s.roleAccessLabelAuthorityInput(raw)
	if err != nil {
		return err
	}
	var costJSON []byte
	if err = w.tx.QueryRow(ctx, roleSequencePrepareSQL, raw,
		s.plan.nativeBudget.RemainingRows(), s.plan.nativeBudget.RemainingReads()).Scan(&costJSON); err != nil {
		return err
	}
	var cost struct {
		Rows            int                 `json:"rows"`
		Reads           int                 `json:"reads"`
		AccessLabelMode roleAccessLabelMode `json:"access_label_mode"`
	}
	if err = json.Unmarshal(costJSON, &cost); err != nil {
		return err
	}
	if err = chargeNativePolicyBudget(s.plan.nativeBudget, cost.Rows, cost.Reads); err != nil {
		return err
	}
	// Режим вычисляет owner из OLD/NEW, а не caller из предложенных правил.
	// Он обязателен для любого prepare, включая обычное изменение metadata.
	if err = cost.AccessLabelMode.requireSupported(); err != nil {
		return err
	}
	s.accessLabelMode = cost.AccessLabelMode
	return nil
}
func (w *preparedRoleWriteTx) RolesW() roleport.WriterIface {
	return &preparedRoleRowWriter{WriterIface: w.semanticAuthorityWriteTx.RolesW(), owner: w}
}

type preparedRoleRowWriter struct {
	roleport.WriterIface
	owner *preparedRoleWriteTx
}

func (w *preparedRoleRowWriter) stamp(ctx context.Context, r domain.Role, create bool, mask []string, version string) (time.Time, json.RawMessage, error) {
	if w.owner == nil || w.owner.stage == nil {
		return time.Time{}, nil, kaname.ErrInvalidAuthorityFencePlan
	}
	expected := w.owner.stage.request
	if expected.Create != create || expected.Role.ID != r.ID || (!create && (!expected.Update ||
		expected.ExpectedVersion != version || !slices.Equal(expected.UpdateMask, mask))) {
		return time.Time{}, nil, kaname.ErrInvalidAuthorityFencePlan
	}
	expected.Role = r
	raw, err := roleSequenceInput(expected)
	if err != nil {
		return time.Time{}, nil, err
	}
	var image json.RawMessage
	if move := w.owner.stage.selectorMove; move != nil {
		if create || move.replay == nil || !slices.Equal(mask, []string{"rules"}) || version == "" || version != move.replay.version {
			return time.Time{}, nil, kaname.ErrSourceUnconfirmed
		}
		rules, err := rulesToJSON(r.Rules)
		if err != nil {
			return time.Time{}, nil, err
		}
		if !bytes.Equal(rules, move.replay.rules) {
			return time.Time{}, nil, kaname.ErrSourceUnconfirmed
		}
		image = move.replay.image
		raw, err = replaceSelectorMoveRules(raw, image)
		if err != nil {
			return time.Time{}, nil, err
		}
	}
	var stamp time.Time
	err = w.owner.tx.QueryRow(ctx, `SELECT kaname.authority_role_sequence_stamp_v3($1::jsonb)`, raw).Scan(&stamp)
	return stamp, image, err
}
func (w *preparedRoleRowWriter) Insert(ctx context.Context, r domain.Role) (domain.Role, error) {
	stamp, _, err := w.stamp(ctx, r, true, nil, "")
	if err != nil {
		return domain.Role{}, err
	}
	raw, ok := w.WriterIface.(*roleWriter)
	if !ok {
		return domain.Role{}, kaname.ErrInvalidAuthorityFencePlan
	}
	w.owner.roleWriteStarted = true
	inserted, err := raw.insertAt(ctx, r, stamp)
	if err == nil {
		w.owner.roleWriteSucceeded = true
	}
	return inserted, err
}
func (w *preparedRoleRowWriter) UpdateCAS(ctx context.Context, r domain.Role, mask []string, version string) (domain.Role, error) {
	stamp, image, err := w.stamp(ctx, r, false, mask, version)
	if err != nil {
		return domain.Role{}, err
	}
	raw, ok := w.WriterIface.(*roleWriter)
	if !ok {
		return domain.Role{}, kaname.ErrInvalidAuthorityFencePlan
	}
	w.owner.roleWriteStarted = true
	updated, err := raw.updateCASAt(ctx, r, mask, version, stamp, image)
	if err == nil {
		w.owner.roleWriteSucceeded = true
	}
	return updated, err
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

// Receipt envelope используется только prepare. Базовый roleSequenceInput и
// stamp остаются прежними: frozen.request сравнивает именно исходную мутацию.
func (s *roleMutationStage) roleAccessLabelAuthorityInput(raw []byte) ([]byte, error) {
	newDefinitions := make(map[domain.AccessLabelDefinitionID]bool)
	for _, cap := range s.projection.Capabilities {
		if cap.Kind == domain.GrantCapabilityApplyAccessLabel {
			newDefinitions[cap.DefinitionID] = true
		}
	}
	// При обновлении правил owner сверяет прежнюю проекцию. Пустой NEW
	// может снять последнее защищённое правило и всё равно требует actor.
	if len(newDefinitions) == 0 && (!s.request.Update || !s.request.Rules) {
		return raw, nil
	}
	if s.plan == nil || s.plan.native == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	actor := s.plan.request.actor
	if actor.Validate() != nil || (actor.Type != domain.SubjectTypeUser && actor.Type != domain.SubjectTypeServiceAccount) || !nativeQuestionToken(string(actor.ID)) {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	subject := string(actor.Type) + ":" + string(actor.ID)
	coordinates := make(map[[3]string]struct{})
	for q := range s.plan.native.questions {
		if q.objectType != grantcapability.AccessLabelObjectType || q.relation != grantcapability.ApplyAccessLabelRelation {
			continue
		}
		c, err := grantcapability.Decode(grantcapability.Reference{ObjectType: q.objectType, ObjectID: q.objectID, Relation: q.relation})
		if err != nil {
			return nil, err
		}
		if !newDefinitions[c.DefinitionID] {
			continue
		}
		if q.subject != subject || c.Kind != domain.GrantCapabilityApplyAccessLabel {
			return nil, kaname.ErrSourceUnconfirmed
		}
		coordinates[[3]string{c.Anchor.Type, c.Anchor.ID, string(c.DefinitionID)}] = struct{}{}
	}
	if len(coordinates) > nativeQuestionLimit {
		return nil, kaname.ErrSourceReadLimit
	}
	keys := make([][3]string, 0, len(coordinates))
	for key := range coordinates {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b [3]string) int {
		for i := range a {
			if a[i] < b[i] {
				return -1
			}
			if a[i] > b[i] {
				return 1
			}
		}
		return 0
	})
	questions := make([]map[string]string, 0, len(keys))
	for _, key := range keys {
		questions = append(questions, map[string]string{"scope_kind": key[0], "scope_id": key[1], "definition_id": key[2]})
	}
	authority, err := json.Marshal(map[string]any{
		"actor": map[string]string{"type": string(actor.Type), "id": string(actor.ID)}, "questions": questions,
	})
	if err != nil {
		return nil, err
	}
	if len(authority) > 8388608 {
		return nil, kaname.ErrSourceReadLimit
	}
	var input map[string]json.RawMessage
	if err := json.Unmarshal(raw, &input); err != nil {
		return nil, err
	}
	input["_access_label_authority"] = authority
	return json.Marshal(input)
}
