// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// Обычный reconcile рассчитывает запись членов и журнала из фактического OLD,
// даже когда эффективное право не меняется. Строки уровня самой выдачи (без
// координаты члена) остаются в штатной последовательности роли.
func selectorMoveCapturedDiff(
	scope accessLabelSelectorMoveScope, coordinates []accessLabelMoveCoordinateEffect, active bool,
	residual map[domain.MembershipTuple]bool, budget *relverdict.AdministrativeReadBudget,
) (reconcile.CapturedObjectDiff, []reconcile.LedgerRow, error) {
	var empty reconcile.CapturedObjectDiff
	carrier := scope.Carrier
	if len(coordinates) != len(scope.Coordinates) {
		return empty, nil, kaname.ErrSourceUnconfirmed
	}
	if err := budget.Charge(len(carrier.Members)+len(carrier.Ledger), 0); err != nil {
		return empty, nil, err
	}
	input := reconcile.CapturedObjectDiff{
		Binding:  scope.Proposed,
		Live:     make(map[reconcile.MemberCoord]bool, len(scope.Coordinates)),
		Current:  carrier.Members,
		Converge: true,
	}
	proposedLedger := make(map[reconcile.LedgerRow]bool)
	for i, effect := range coordinates {
		key := reconcile.MemberCoord{ObjectType: effect.Resource.Type, ObjectID: effect.Resource.ID}
		if _, duplicate := input.Live[key]; duplicate || effect.Resource != scope.Coordinates[i] ||
			(!effect.Present && (len(effect.Before) != 0 || len(effect.Proposed) != 0)) {
			return empty, nil, kaname.ErrSourceUnconfirmed
		}
		input.Live[key] = effect.Present
		if !active {
			continue
		}
		if err := budget.Charge(len(effect.Proposed), 0); err != nil {
			return empty, nil, err
		}
		for _, member := range effect.Proposed {
			if member.ObjectType != key.ObjectType || member.ObjectID != key.ObjectID {
				return empty, nil, kaname.ErrSourceUnconfirmed
			}
			input.Desired = append(input.Desired, reconcile.DesiredMember{
				Derivation: member.Derivation, RuleFP: member.RuleFP, ObjectType: member.ObjectType,
				ObjectID: member.ObjectID, Status: member.Status, Tuples: member.Tuples,
			})
			if member.Status == domain.VerificationActive {
				for _, tuple := range member.Tuples {
					proposedLedger[reconcile.LedgerRow{Member: key, Tuple: tuple}] = true
				}
			}
		}
	}
	activeMembers := make(map[reconcile.MemberCoord]bool, len(carrier.Members))
	for _, row := range carrier.Members {
		coordinate := reconcile.MemberCoord{ObjectType: row.ObjectType, ObjectID: row.ObjectID}
		if _, captured := input.Live[coordinate]; !captured || row.BindingID != carrier.Binding.ID || row.RoleID != carrier.Binding.RoleID {
			return empty, nil, kaname.ErrSourceUnconfirmed
		}
		if row.VerificationStatus == domain.VerificationActive {
			activeMembers[coordinate] = true
		}
	}
	var orphaned []reconcile.LedgerRow
	for _, row := range carrier.Ledger {
		if row.Member == (reconcile.MemberCoord{}) {
			continue
		}
		_, captured := input.Live[row.Member]
		_, _, tupleObject := resourceFoldCoordinate(row.Tuple.Object)
		if !captured || !tupleObject || row.Tuple.User == "" || row.Tuple.Relation == "" {
			return empty, nil, kaname.ErrSourceUnconfirmed
		}
		switch {
		case !active:
			// Неактивная выдача сохраняет историю и не удерживает факт.
			residual[row.Tuple] = true
		case activeMembers[row.Member] || proposedLedger[row]:
			input.Ledger = append(input.Ledger, row)
		default:
			// У строки без ACTIVE-члена нет старого участника, который мог
			// бы снять её обычным diff. Удаляем точную запись до свёртки.
			orphaned = append(orphaned, row)
			residual[row.Tuple] = true
		}
	}
	return input, orphaned, nil
}
