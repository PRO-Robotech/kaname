// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// В одной попытке SQL сперва удерживает строки, затем runner сверяет RR и
// получает финальные часы. Передача в другую транзакцию запрещена.
type roleSelectorMoveAuthorization struct {
	move        *roleSelectorMoveStage
	writer      *authorityWriteTx
	preparedAt  time.Time
	checked     bool
	decided     bool
	projections roleSelectorMoveGrantProjections
	retained    *roleSelectorMoveRetainedProof
}

const (
	pendingNoCopyPrepareTransport = "pending_no_copy_v1"
	activeNoCopyPrepareTransport  = "active_project_no_copy_v1"
)

func (s *roleSelectorMoveStage) sourceTransport() string {
	if s != nil && len(s.captured.Carriers) == 1 && s.captured.Carriers[0].Carrier.Binding.Status == domain.AccessBindingStatusActive {
		return activeNoCopyPrepareTransport
	}
	return pendingNoCopyPrepareTransport
}

// Владелец БД резервирует физические источники на тех же часах RC, на которых
// затем сверяются Grant, проекции и удержанные кортежи из снимка RR.
func (s *roleMutationStage) holdSelectorMove(ctx context.Context, w *semanticAuthorityWriteTx) (*roleSelectorMoveAuthorization, error) {
	if s == nil || s.plan == nil || w == nil || w.authorityWriteTx == nil ||
		s.plan.nativeBudget == nil || s.plan.nativeBudget != w.producerBudget {
		return nil, kaname.ErrSourceUnconfirmed
	}
	authorization, request, hold, err := s.prepareSelectorMoveInput(ctx, w.authorityWriteTx)
	if err != nil {
		return nil, err
	}
	input, err := json.Marshal(struct {
		Transport string          `json:"_selector_move"`
		Request   json.RawMessage `json:"request"`
		Hold      json.RawMessage `json:"hold"`
	}{Transport: s.selectorMove.sourceTransport(), Request: request, Hold: hold})
	if err != nil {
		return nil, err
	}
	if len(input) > granteffect.MaxInputBytes {
		return nil, kaname.ErrSourceReadLimit
	}
	budget := w.producerBudget
	var receipt json.RawMessage
	if err := w.tx.QueryRow(ctx, roleSequencePrepareSQL, input, budget.RemainingRows(), budget.RemainingReads()).Scan(&receipt); err != nil {
		return nil, err
	}
	if err := chargeSelectorMovePrepareReceiptFor(budget, receipt, s.selectorMove.sourceTransport()); err != nil {
		return nil, err
	}
	if err := authorization.confirmHeldSources(ctx, w); err != nil {
		return nil, err
	}
	// Mode входит в уже проверенную owner-квитанцию held prepare.
	s.accessLabelMode = roleAccessLabelOrdinary
	return authorization, nil
}

func chargeSelectorMovePrepareReceipt(budget *relverdict.AdministrativeReadBudget, raw json.RawMessage) error {
	return chargeSelectorMovePrepareReceiptFor(budget, raw, pendingNoCopyPrepareTransport)
}

func chargeSelectorMovePrepareReceiptFor(budget *relverdict.AdministrativeReadBudget, raw json.RawMessage, transport string) error {
	var cost struct {
		Transport string              `json:"selector_move_transport"`
		Mode      roleAccessLabelMode `json:"access_label_mode"`
		Rows      int                 `json:"rows"`
		Reads     int                 `json:"reads"`
	}
	if err := json.Unmarshal(raw, &cost); err != nil {
		return err
	}
	// Протокол v1 учитывает четыре строки и четыре чтения адаптера
	// плюс непустую перепись владельца. SQL возвращает их общую стоимость.
	if cost.Transport != transport || cost.Mode != roleAccessLabelOrdinary || cost.Rows <= 4 || cost.Reads <= 4 {
		return kaname.ErrSourceUnconfirmed
	}
	return chargeNativePolicyBudget(budget, cost.Rows, cost.Reads)
}

// Для обычного API сериализация protobuf/domain может нормализовать поля
// правил. При переносе передаём только проверенный физический образ PostgreSQL.
func (s *roleMutationStage) prepareSelectorMoveInput(
	ctx context.Context, w *authorityWriteTx,
) (*roleSelectorMoveAuthorization, json.RawMessage, json.RawMessage, error) {
	if s == nil || s.selectorMove == nil || w == nil || w.fence.mode != kaname.AuthorityFenceGlobal || w.fence.decisionAt.IsZero() {
		return nil, nil, nil, kaname.ErrSourceUnconfirmed
	}
	move := s.selectorMove
	source := move.grantCapture()
	if source == nil || source.budget != w.producerBudget {
		return nil, nil, nil, kaname.ErrSourceUnconfirmed
	}
	if err := move.replay.prepareRequest(ctx, w, s.request); err != nil {
		return nil, nil, nil, err
	}
	moveInput, err := move.ownerInput(ctx, w)
	if err != nil {
		return nil, nil, nil, err
	}
	request, err := roleSequenceInput(s.request)
	if err != nil {
		return nil, nil, nil, err
	}
	request, err = replaceSelectorMoveRules(request, move.replay.image)
	if err != nil {
		return nil, nil, nil, err
	}
	request, err = s.roleAccessLabelAuthorityInput(request)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(request)+len(moveInput) > granteffect.MaxInputBytes {
		return nil, nil, nil, kaname.ErrSourceReadLimit
	}
	return &roleSelectorMoveAuthorization{move: move, writer: w, preparedAt: w.fence.decisionAt}, request, moveInput, ctx.Err()
}

func replaceSelectorMoveRules(raw, rules json.RawMessage) (json.RawMessage, error) {
	var request, role map[string]json.RawMessage
	var image []json.RawMessage
	if json.Unmarshal(raw, &request) != nil || json.Unmarshal(request["role"], &role) != nil ||
		len(role) == 0 || json.Unmarshal(rules, &image) != nil || len(image) == 0 {
		return nil, kaname.ErrSourceUnconfirmed
	}
	role["rules"] = rules
	encoded, err := json.Marshal(role)
	if err != nil {
		return nil, err
	}
	request["role"] = encoded
	return json.Marshal(request)
}

// confirmHeldSources вызывается после SQL-резерва и до нового decision_at.
// Физические предикаты и закрытый набор их оград удерживает SQL-владелец.
func (a *roleSelectorMoveAuthorization) confirmHeldSources(ctx context.Context, w *semanticAuthorityWriteTx) error {
	if a == nil || w == nil || w.authorityWriteTx != a.writer || a.checked || a.decided || !a.preparedAt.Equal(w.fence.decisionAt) {
		return kaname.ErrSourceUnconfirmed
	}
	a.checked = true
	source := a.move.grantCapture()
	if source == nil || source.budget != w.producerBudget {
		return kaname.ErrSourceUnconfirmed
	}
	if err := source.recheck(ctx, a.writer); err != nil {
		return err
	}
	projected, err := a.move.verifyGrantProjections(ctx, w)
	if err != nil {
		return err
	}
	retained, err := a.move.prepareRetainedTupleProof(ctx, w)
	if err != nil {
		return err
	}
	a.projections, a.retained = projected, retained
	return ctx.Err()
}

type roleSelectorMoveRetainedTuple struct {
	tuple  domain.MembershipTuple
	holder domain.TargetMember
}

type roleSelectorMoveAuthorizedChanges struct {
	changes  roleSelectorMoveChanges
	copies   json.RawMessage
	retained []roleSelectorMoveRetainedTuple
}

func (a *roleSelectorMoveAuthorization) decide(ctx context.Context, w *semanticAuthorityWriteTx) (roleSelectorMoveAuthorizedChanges, error) {
	var empty roleSelectorMoveAuthorizedChanges
	if a == nil || w == nil || w.authorityWriteTx != a.writer || a.retained == nil || a.decided || !w.fence.decisionAt.After(a.preparedAt) {
		return empty, kaname.ErrSourceUnconfirmed
	}
	a.decided = true
	source := a.move.grantCapture()
	if source == nil || source.budget != w.producerBudget {
		return empty, kaname.ErrSourceUnconfirmed
	}
	if err := source.lifetime.bind(a.writer); err != nil {
		return empty, err
	}
	changes, err := a.move.compileChanges(ctx, w, a.projections)
	if err != nil {
		return empty, err
	}
	copies, err := changes.owner.copyInput(w)
	if err != nil {
		return empty, err
	}
	retained, err := a.positiveRetention(ctx, w, changes.access)
	if err != nil {
		return empty, err
	}
	return roleSelectorMoveAuthorizedChanges{changes: changes, copies: copies, retained: retained}, ctx.Err()
}

// Отсутствие положительного свидетельства не разрешает снятие кортежа.
// Кандидаты остаются в исходном diff и должны быть сверены SQL-владельцем.
func (a *roleSelectorMoveAuthorization) positiveRetention(
	ctx context.Context, w *semanticAuthorityWriteTx, effect accessLabelMoveEffect,
) ([]roleSelectorMoveRetainedTuple, error) {
	budget := a.move.budget()
	candidates := make(map[domain.MembershipTuple]bool)
	for _, tuples := range [][]domain.MembershipTuple{effect.Removed, effect.ResidualFold} {
		if err := budget.Charge(len(tuples), 0); err != nil {
			return nil, err
		}
		for _, tuple := range tuples {
			candidates[tuple] = true
		}
	}
	for _, command := range effect.Commands {
		if command.Kind == "delete" {
			if err := budget.Charge(len(command.Tuples), 0); err != nil {
				return nil, err
			}
			for _, tuple := range command.Tuples {
				candidates[tuple] = true
			}
		}
	}
	var retained []roleSelectorMoveRetainedTuple
	for _, tuple := range selectorMoveTupleDifference(candidates, nil) {
		holder, err := a.retained.requireTuple(ctx, w, tuple)
		if errors.Is(err, kaname.ErrSourceUnconfirmed) {
			continue
		}
		if err != nil {
			return nil, err
		}
		retained = append(retained, roleSelectorMoveRetainedTuple{tuple: tuple, holder: holder})
	}
	return retained, ctx.Err()
}

// pendingSourceInput передаёт физические координаты из уже рассчитанного
// решения на тех же финальных часах. Форму перепроверяет SQL-владелец.
func (d roleSelectorMoveAuthorizedChanges) pendingSourceInput(ctx context.Context, w *semanticAuthorityWriteTx) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	owner := d.changes.owner
	copies, err := owner.copyInput(w)
	if err != nil {
		return nil, err
	}
	effect := d.changes.access
	if !bytes.Equal(copies, []byte("[]")) || !bytes.Equal(copies, d.copies) ||
		len(effect.Bindings) != 1 || len(effect.Commands)+len(effect.Added)+len(effect.Removed)+len(effect.ResidualFold)+len(d.retained) != 0 ||
		len(owner.move.captured.Carriers) != 1 || len(owner.move.captured.Collateral) != 0 {
		return nil, kaname.ErrSourceUnconfirmed
	}
	carrier := owner.move.captured.Carriers[0].Carrier.Binding
	binding := effect.Bindings[0]
	if !binding.Pending || binding.BindingID == "" || binding.BindingID != carrier.ID ||
		carrier.RoleID != owner.move.captured.Before.ID || carrier.Status != domain.AccessBindingStatusPending ||
		carrier.ExpiresAt != nil || carrier.RevokedAt != nil || carrier.ResourceType != "account" ||
		carrier.ResourceID == "" || carrier.Target.AllInScope || len(carrier.Target.Resources) != 1 || len(binding.Coordinates) != 2 {
		return nil, kaname.ErrSourceUnconfirmed
	}
	account := domain.ResourceRef{Type: "iam.account", ID: carrier.ResourceID}
	project := carrier.Target.Resources[0]
	if project.Type != "iam.project" || project.ID == "" {
		return nil, kaname.ErrSourceUnconfirmed
	}
	// compileAccessLabelMoveEffect сохраняет канонический порядок координат
	// из RR; у закрытой формы это сначала аккаунт, затем его проект.
	for i, ref := range []domain.ResourceRef{account, project} {
		c := binding.Coordinates[i]
		if c.Resource != ref || !c.Present {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if err := chargeNativePolicyBudget(w.producerBudget, 1+len(c.Before)+len(c.Proposed), 0); err != nil {
			return nil, err
		}
	}
	sets, err := json.Marshal(map[domain.AccessBindingID][]accessLabelMoveCoordinateEffect{binding.BindingID: binding.Coordinates})
	if err != nil {
		return nil, err
	}
	// _authority_role_move_pending_sources_v1 ограничивает карту 64 КиБ.
	if len(sets) > 65536 {
		return nil, kaname.ErrSourceReadLimit
	}
	return sets, ctx.Err()
}

// activeProjectSourceInput передаёт результат штатного Grant и reconcile для одного
// проекта. Владелец заново строит все четыре команды из физических OLD и NEW.
func (d roleSelectorMoveAuthorizedChanges) activeProjectSourceInput(ctx context.Context, w *semanticAuthorityWriteTx) (json.RawMessage, error) {
	owner, effect := d.changes.owner, d.changes.access
	copies, err := owner.copyInput(w)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(copies, []byte("[]")) || !bytes.Equal(d.copies, copies) || len(d.retained)+len(effect.Added)+len(effect.Removed)+len(effect.ResidualFold) != 0 ||
		len(owner.move.captured.Carriers) != 1 || len(owner.move.captured.Collateral) != 0 || len(effect.Bindings) != 1 || len(effect.Commands) != 4 {
		return nil, kaname.ErrSourceUnconfirmed
	}
	carrier, binding := owner.move.captured.Carriers[0].Carrier.Binding, effect.Bindings[0]
	if carrier.Status != domain.AccessBindingStatusActive || carrier.ExpiresAt != nil || carrier.RevokedAt != nil || carrier.RoleID != owner.move.captured.Before.ID ||
		carrier.ResourceType != "account" || carrier.ResourceID == "" || carrier.Target.AllInScope || len(carrier.Target.Resources) != 1 ||
		carrier.Target.Resources[0].Type != "iam.project" || carrier.Target.Resources[0].ID == "" || binding.Pending || binding.BindingID != carrier.ID || len(binding.Coordinates) != 2 ||
		effect.Commands[0].Kind != "members" || effect.Commands[1].Kind != "write" || effect.Commands[2].Kind != "record" || effect.Commands[3].Kind != "member_delete" {
		return nil, kaname.ErrSourceUnconfirmed
	}
	for i, ref := range []domain.ResourceRef{{Type: "iam.account", ID: carrier.ResourceID}, carrier.Target.Resources[0]} {
		c := binding.Coordinates[i]
		if !c.Present || c.Resource != ref {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if err := chargeNativePolicyBudget(w.producerBudget, 1+len(c.Before)+len(c.Proposed), 0); err != nil {
			return nil, err
		}
	}
	raw, err := json.Marshal(map[string]any{"coordinates": binding.Coordinates, "commands": effect.Commands})
	if err != nil {
		return nil, err
	}
	if len(raw) > 131072 {
		return nil, kaname.ErrSourceReadLimit
	}
	return raw, ctx.Err()
}
