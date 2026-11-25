// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/resourceeffect"
)

type accessLabelMoveGrant struct {
	BindingID domain.AccessBindingID
	RoleID    domain.RoleID
	Scope     domain.ScopeAnchor
	Recipient domain.Subject
	Tuple     domain.MembershipTuple
	Pending   bool
	ExpiresAt *time.Time
}

// accessLabelMoveGrantResidual принимает результаты compileAccessLabelMoveEffect
// из того же снимка, с тем же наложением копий и финальным временем решения.
// Остаток перечисляет физические кортежи, для которых нет тождественной прежней
// выдачи достаточной длительности. Семантическое покрытие моделью, права actor
// и будущие совпадения селекторов требуют самостоятельных доказательств.
func accessLabelMoveGrantResidual(
	ctx context.Context, captured accessLabelSelectorMoveCapture, effects []accessLabelMoveBindingEffect,
	at time.Time, budget *relverdict.AdministrativeReadBudget,
) ([]accessLabelMoveGrant, error) {
	if captured.Before.ID == "" || at.IsZero() || budget == nil || len(effects) != len(captured.Carriers)+len(captured.Collateral) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if err := budget.Charge(len(effects), 0); err != nil {
		return nil, err
	}
	byID := make(map[domain.AccessBindingID]accessLabelMoveBindingEffect, len(effects))
	for _, effect := range effects {
		if _, duplicate := byID[effect.BindingID]; duplicate {
			return nil, kaname.ErrSourceUnconfirmed
		}
		byID[effect.BindingID] = effect
	}
	residual := materializedGrantResidual{activeOld: make(map[domain.MembershipTuple]*time.Time)}
	for i, scopes := range [][]accessLabelSelectorMoveScope{captured.Carriers, captured.Collateral} {
		for _, scope := range scopes {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			carrier := scope.Carrier
			b := carrier.Binding
			effect, found := byID[b.ID]
			if !found || b.ID == "" || b.RoleID == "" || (i == 0) != (b.RoleID == captured.Before.ID) ||
				scope.Before.BindingID != b.ID || scope.Proposed.BindingID != b.ID ||
				scope.Before.RoleID != string(b.RoleID) || scope.Proposed.RoleID != string(b.RoleID) ||
				scope.Before.Scope != scopeAnchorFor(b) || scope.Proposed.Scope != scope.Before.Scope ||
				!slices.Equal(scope.Before.Subjects, b.Subjects) || !slices.Equal(scope.Proposed.Subjects, b.Subjects) {
				return nil, kaname.ErrSourceUnconfirmed
			}
			delete(byID, b.ID)
			eligible := carrier.canSelectAt(at)
			if effect.Pending != (eligible && !carrier.activeAt(at)) || len(effect.Coordinates) != len(scope.Coordinates) {
				return nil, kaname.ErrSourceUnconfirmed
			}
			if err := budget.Charge(len(effect.Coordinates), 0); err != nil {
				return nil, err
			}
			for i, coordinate := range effect.Coordinates {
				if coordinate.Resource != scope.Coordinates[i] ||
					((!eligible || !coordinate.Present) && (len(coordinate.Before) != 0 || len(coordinate.Proposed) != 0)) {
					return nil, kaname.ErrSourceUnconfirmed
				}
			}
			if !eligible {
				continue
			}
			if err := residual.add(ctx, b, effect.Pending, effect.Coordinates, budget); err != nil {
				return nil, err
			}
		}
	}
	return residual.remaining(ctx)
}

type materializedGrantResidual struct {
	// Only active OLD can cover another carrier. nil marks unlimited lifetime.
	activeOld map[domain.MembershipTuple]*time.Time
	wanted    []accessLabelMoveGrant
}

func materializedGrantRecipients(b domain.AccessBinding, budget *relverdict.AdministrativeReadBudget) (map[string]domain.Subject, error) {
	if err := budget.Charge(len(b.Subjects), 0); err != nil {
		return nil, err
	}
	subjects, err := domain.NormalizeSubjects(b.Subjects, "", "")
	if err != nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	recipients := make(map[string]domain.Subject, len(subjects))
	for _, subject := range subjects {
		recipients[domain.FGASubjectRef(string(subject.Type), string(subject.ID))] = subject
	}
	return recipients, nil
}

func (r *materializedGrantResidual) add(ctx context.Context, b domain.AccessBinding, pending bool, coordinates []accessLabelMoveCoordinateEffect, budget *relverdict.AdministrativeReadBudget) error {
	recipients, err := materializedGrantRecipients(b, budget)
	if err != nil {
		return err
	}
	before, proposed := make(map[domain.MembershipTuple]bool), make(map[domain.MembershipTuple]bool)
	for _, coordinate := range coordinates {
		if err := addAccessLabelMoveGrantTuples(ctx, before, coordinate.Resource, coordinate.Before, recipients, budget); err != nil {
			return err
		}
		if err := addAccessLabelMoveGrantTuples(ctx, proposed, coordinate.Resource, coordinate.Proposed, recipients, budget); err != nil {
			return err
		}
	}
	if !pending {
		for tuple := range before {
			until, ok := r.activeOld[tuple]
			if !ok || (until != nil && (b.ExpiresAt == nil || b.ExpiresAt.After(*until))) {
				r.activeOld[tuple] = b.ExpiresAt
			}
		}
	}
	// Собственный OLD годится также у PENDING: активация и окончание
	// одного носителя одинаковы для обеих версий его правил.
	for _, tuple := range selectorMoveTupleDifference(proposed, before) {
		r.wanted = append(r.wanted, accessLabelMoveGrant{
			BindingID: b.ID, RoleID: b.RoleID, Scope: scopeAnchorFor(b), Recipient: recipients[tuple.User],
			Tuple: tuple, Pending: pending, ExpiresAt: b.ExpiresAt,
		})
	}
	return nil
}

func (r *materializedGrantResidual) remaining(ctx context.Context) ([]accessLabelMoveGrant, error) {
	wanted := slices.DeleteFunc(r.wanted, func(grant accessLabelMoveGrant) bool {
		until, present := r.activeOld[grant.Tuple]
		return present && (until == nil || grant.ExpiresAt != nil && !until.Before(*grant.ExpiresAt))
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return wanted, nil
}

func addAccessLabelMoveGrantTuples(
	ctx context.Context, tuples map[domain.MembershipTuple]bool, resource domain.ResourceRef,
	members []resourceeffect.ObjectDesiredMember, recipients map[string]domain.Subject, budget *relverdict.AdministrativeReadBudget,
) error {
	if err := budget.Charge(len(members), 0); err != nil {
		return err
	}
	for _, member := range members {
		if err := ctx.Err(); err != nil {
			return err
		}
		if member.ObjectType != resource.Type || member.ObjectID != resource.ID {
			return kaname.ErrSourceUnconfirmed
		}
		if err := budget.Charge(len(member.Tuples), 0); err != nil {
			return err
		}
		if member.Status != domain.VerificationActive {
			if member.Status != domain.VerificationRejected || len(member.Tuples) != 0 {
				return kaname.ErrSourceUnconfirmed
			}
			continue
		}
		for _, tuple := range member.Tuples {
			_, _, valid := resourceFoldCoordinate(tuple.Object)
			if _, found := recipients[tuple.User]; !found || !valid || !nativeQuestionToken(tuple.Relation) {
				return kaname.ErrSourceUnconfirmed
			}
			tuples[tuple] = true
		}
	}
	return nil
}
