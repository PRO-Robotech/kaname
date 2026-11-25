// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

type accessLabelSelectorMoveCarrier struct {
	Binding     domain.AccessBinding
	Members     []domain.TargetMember
	Ledger      []reconcile.LedgerRow
	Coordinates map[domain.ResourceRef]bool
}

func (c accessLabelSelectorMoveCarrier) activeAt(at time.Time) bool {
	b := c.Binding
	return !at.IsZero() && b.Status == domain.AccessBindingStatusActive && b.RevokedAt == nil &&
		(b.ExpiresAt == nil || b.ExpiresAt.After(at))
}

func (c accessLabelSelectorMoveCarrier) canSelect() bool {
	b := c.Binding
	return b.RevokedAt == nil && (b.Status == domain.AccessBindingStatusActive || b.Status == domain.AccessBindingStatusPending)
}

func (c accessLabelSelectorMoveCarrier) canSelectAt(at time.Time) bool {
	return !at.IsZero() && c.canSelect() && (c.Binding.ExpiresAt == nil || c.Binding.ExpiresAt.After(at))
}

// Снимаем полный role_id predicate и физические строки каждой выдачи, в том
// числе PENDING, истёкшие и REVOKED. Хранимые members и ledger входят в OLD
// census независимо от текущей активности. Версии строк и пустые результаты
// остаются в общем RR capture для сверки под оградой.
func readAccessLabelSelectorMoveCarriers(ctx context.Context, tx pgx.Tx, source *resourceSourceCapture, roleID domain.RoleID) ([]accessLabelSelectorMoveCarrier, error) {
	rows, err := source.read(ctx, tx, resourceSourceKey{kind: resourceSourceRoleBindings, typ: "role", id: string(roleID)})
	if err != nil {
		return nil, err
	}
	bindings := make([]domain.AccessBinding, 0, len(rows))
	seen := make(map[domain.AccessBindingID]bool, len(rows))
	for _, row := range rows {
		binding, err := resourceCapturedBinding(row.value)
		if err != nil {
			return nil, err
		}
		if binding.RoleID != roleID || seen[binding.ID] {
			return nil, kaname.ErrSourceUnconfirmed
		}
		seen[binding.ID] = true
		bindings = append(bindings, binding)
	}
	slices.SortFunc(bindings, func(a, b domain.AccessBinding) int { return cmp.Compare(a.ID, b.ID) })

	result := make([]accessLabelSelectorMoveCarrier, 0, len(bindings))
	for _, binding := range bindings {
		carrier, err := readAccessLabelSelectorMoveCarrier(ctx, tx, source, binding)
		if err != nil {
			return nil, err
		}
		result = append(result, carrier)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func readAccessLabelSelectorMoveCarrier(
	ctx context.Context, tx pgx.Tx, source *resourceSourceCapture, binding domain.AccessBinding,
) (accessLabelSelectorMoveCarrier, error) {
	var empty accessLabelSelectorMoveCarrier
	if !nativeQuestionToken(string(binding.ID)) || !nativeQuestionToken(string(binding.RoleID)) ||
		!nativeQuestionToken(string(binding.ResourceType)) || !nativeQuestionToken(binding.ResourceID) ||
		binding.Scope == domain.ScopeUnspecified || binding.GrantedRelation != "" ||
		binding.CreatedAt.IsZero() || binding.Status.Validate() != nil ||
		(binding.Status == domain.AccessBindingStatusRevoked) != (binding.RevokedAt != nil) ||
		(binding.RevokedAt == nil && binding.RevokedByUserID != nil) {
		return empty, kaname.ErrSourceUnconfirmed
	}
	if binding.Status != domain.AccessBindingStatusRevoked &&
		binding.Scope.ValidateAgainst(string(binding.ResourceType), binding.ResourceID) != nil {
		return empty, kaname.ErrSourceUnconfirmed
	}
	id := string(binding.ID)
	subjectRows, err := source.read(ctx, tx, resourceSourceKey{kind: resourceSourceBindingSubjects, typ: "binding", id: id})
	if err != nil {
		return empty, err
	}
	binding.Subjects, err = accessLabelSelectorMoveSubjects(binding, subjectRows)
	if err != nil {
		return empty, err
	}
	memberRows, err := source.read(ctx, tx, resourceSourceKey{kind: resourceSourceBindingMembers, typ: "binding", id: id})
	if err != nil {
		return empty, err
	}
	ledgerRows, err := source.read(ctx, tx, resourceSourceKey{kind: resourceSourceBindingLedger, typ: "binding", id: id})
	if err != nil {
		return empty, err
	}
	coordinates, ledger, err := resourceBindingDiffCoordinates(id, memberRows, ledgerRows)
	if err != nil {
		return empty, err
	}
	members, err := accessLabelSelectorMoveMembers(binding, memberRows)
	if err != nil {
		return empty, err
	}
	for _, row := range ledger {
		if _, _, ok := resourceFoldCoordinate(row.Tuple.Object); !ok {
			return empty, kaname.ErrSourceUnconfirmed
		}
	}
	return accessLabelSelectorMoveCarrier{Binding: binding, Members: members, Ledger: ledger, Coordinates: coordinates}, ctx.Err()
}

func accessLabelSelectorMoveSubjects(binding domain.AccessBinding, captured []resourceSourceRow) ([]domain.Subject, error) {
	type subjectRow struct {
		BindingID    domain.AccessBindingID `json:"binding_id"`
		Type         domain.SubjectType     `json:"subject_type"`
		ID           domain.SubjectID       `json:"subject_id"`
		Ordinal      *int                   `json:"ordinal"`
		ResourceType domain.ResourceType    `json:"resource_type"`
		ResourceID   string                 `json:"resource_id"`
	}
	rows, err := resourceDecodeRows[subjectRow](captured)
	if err != nil {
		return nil, err
	}
	pairPresent := false
	for _, row := range rows {
		if row.BindingID != binding.ID || row.ResourceType != binding.ResourceType || row.ResourceID != binding.ResourceID ||
			row.Ordinal == nil || *row.Ordinal < 0 ||
			(!nativeQuestionToken(string(row.ID)) && !(row.ID == "*" && binding.System && row.Type == domain.SubjectTypeUser)) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		pairPresent = pairPresent || (row.Type == binding.SubjectType && row.ID == binding.SubjectID)
	}
	if !pairPresent {
		return nil, kaname.ErrSourceUnconfirmed
	}
	// Сортировка как в ListSubjects. SQL требует присутствия пары выдачи в
	// наборе, её положение в этом порядке не входит в ограничение.
	slices.SortFunc(rows, func(a, b subjectRow) int {
		if n := cmp.Compare(*a.Ordinal, *b.Ordinal); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Type, b.Type); n != 0 {
			return n
		}
		return cmp.Compare(a.ID, b.ID)
	})
	subjects := make([]domain.Subject, 0, len(rows))
	for _, row := range rows {
		subjects = append(subjects, domain.Subject{Type: row.Type, ID: row.ID})
	}
	normalized, err := domain.NormalizeSubjects(subjects, "", "")
	if err != nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	return normalized, nil
}

func accessLabelSelectorMoveMembers(binding domain.AccessBinding, captured []resourceSourceRow) ([]domain.TargetMember, error) {
	type memberRow struct {
		BindingID  domain.AccessBindingID    `json:"binding_id"`
		RoleID     domain.RoleID             `json:"role_id"`
		RuleFP     string                    `json:"rule_fp"`
		ObjectType string                    `json:"object_type"`
		ObjectID   string                    `json:"object_id"`
		Status     domain.VerificationStatus `json:"verification_status"`
	}
	rows, err := resourceDecodeRows[memberRow](captured)
	if err != nil {
		return nil, err
	}
	members := make([]domain.TargetMember, 0, len(rows))
	type memberKey struct{ fingerprint, typ, id string }
	seen := make(map[memberKey]bool, len(rows))
	for _, row := range rows {
		key := memberKey{row.RuleFP, row.ObjectType, row.ObjectID}
		if row.BindingID != binding.ID || row.RoleID != binding.RoleID || row.RuleFP == "" || seen[key] {
			return nil, kaname.ErrSourceUnconfirmed
		}
		switch row.Status {
		case domain.VerificationPending, domain.VerificationActive, domain.VerificationRejected:
		default:
			return nil, kaname.ErrSourceUnconfirmed
		}
		seen[key] = true
		members = append(members, domain.TargetMember{BindingID: row.BindingID, RoleID: row.RoleID, RuleFP: row.RuleFP,
			ObjectType: row.ObjectType, ObjectID: row.ObjectID, VerificationStatus: row.Status})
	}
	return members, nil
}
