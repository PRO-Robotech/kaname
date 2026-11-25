// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

// Только ROLE caller задаёт proposed content. Метаданные не превращаются в
// rules mutation; нижний RoleAuthorityWriter объявляет полный контракт.
type roleNativeRequest struct {
	role            domain.Role
	create, content bool
	selectorMove    *accessLabelSelectorMoveCapture
}

// Весь список вопросов строится в RR ДО общего epoch token и coordinator.
// Никакой eligibility-фильтрации по времени: decision_at ещё не установлен.
// Возвращённый rows добавляется к общему census, budget разделён с discovery.
func discoverRoleNativeQuestions(ctx context.Context, tx pgx.Tx, actor domain.Subject, request roleNativeRequest, budget *relverdict.AdministrativeReadBudget) (*nativePolicyQuestions, int, error) {
	if tx == nil || budget == nil {
		return nil, 0, kaname.ErrInvalidAuthorityFencePlan
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	role := request.role
	if !request.content {
		role.Rules = nil
	}
	// У исходной роли и всех носителей одна и та же подтверждаемая форма правил.
	_, capabilities, err := domain.SplitGrantCapabilityRules(role.Rules)
	if err != nil {
		return nil, 0, err
	}
	questions := newNativePolicyQuestions()
	if err := questions.roleBase(actor, role, request.create, capabilities); err != nil {
		return nil, 0, err
	}
	if request.selectorMove != nil {
		move := request.selectorMove
		if request.create || !request.content || role.ID == "" || move.Before.ID != role.ID || move.proof == nil || move.proof.role != role.ID {
			return nil, 0, kaname.ErrInvalidAuthorityFencePlan
		}
		if err := move.declareNativeQuestions(ctx, tx, questions, actor, capabilities, budget); err != nil {
			return nil, 0, err
		}
		return questions, 0, nil
	}
	if request.create || !request.content {
		return questions, 0, nil
	}
	if role.ID == "" {
		return nil, 0, kaname.ErrInvalidAuthorityFencePlan
	}
	after := ""
	total := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, total, err
		}
		if err := chargeNativePolicyBudget(budget, 0, 1); err != nil {
			return nil, total, err
		}
		rows, err := tx.Query(ctx, `SELECT id,resource_type,resource_id FROM kaname.access_bindings WHERE role_id=$1 AND id COLLATE "C">$2 COLLATE "C" ORDER BY id COLLATE "C" LIMIT $3`, string(role.ID), after, policyDiscoveryPage)
		if err != nil {
			return nil, total, err
		}
		count := 0
		for rows.Next() {
			if err = ctx.Err(); err != nil {
				rows.Close()
				return nil, total, err
			}
			var binding domain.AccessBinding
			if err = rows.Scan(&binding.ID, &binding.ResourceType, &binding.ResourceID); err != nil {
				rows.Close()
				return nil, total, err
			}
			if err = chargeNativePolicyBudget(budget, 1, 0); err != nil {
				rows.Close()
				return nil, total, err
			}
			total++
			count++
			if string(binding.ID) <= after {
				rows.Close()
				return nil, total, kaname.ErrCanonicalSourceInvalid
			}
			after = string(binding.ID)
			if err = questions.roleCarrier(actor, binding, capabilities); err != nil {
				rows.Close()
				return nil, total, err
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, total, err
		}
		if err = ctx.Err(); err != nil {
			return nil, total, err
		}
		if count < policyDiscoveryPage {
			return questions, total, nil
		}
	}
}

// Перенос уже прочитал полную популяцию данной роли. Обычный повторный
// role_id scan здесь не нужен. Для соседних ролей вопросы строятся из
// их исходных правил, которые удерживаются тем же RR replay.
func (move *accessLabelSelectorMoveCapture) declareNativeQuestions(
	ctx context.Context, tx pgx.Tx, questions *nativePolicyQuestions, actor domain.Subject,
	capabilities []domain.GrantCapabilityRule, budget *relverdict.AdministrativeReadBudget,
) error {
	source := move.proof.source
	if source == nil || source.stageTX != tx || source.budget != budget || !source.sealed {
		return kaname.ErrSourceUnconfirmed
	}
	if err := move.proof.updates.declare(ctx, questions, actor, budget); err != nil {
		return err
	}
	for _, scope := range move.Carriers {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := budget.Charge(1, 0); err != nil {
			return err
		}
		b := scope.Carrier.Binding
		if b.ID == "" || b.RoleID != move.Before.ID {
			return kaname.ErrSourceUnconfirmed
		}
		if err := questions.roleCarrier(actor, b, capabilities); err != nil {
			return err
		}
	}
	roles := make(map[domain.RoleID]domain.Role)
	for _, scope := range move.Collateral {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := budget.Charge(1, 0); err != nil {
			return err
		}
		b := scope.Carrier.Binding
		if b.ID == "" || b.RoleID == "" || b.RoleID == move.Before.ID {
			return kaname.ErrSourceUnconfirmed
		}
		role, found := roles[b.RoleID]
		if !found {
			key := resourceSourceKey{kind: resourceSourceRole, typ: "role", id: string(b.RoleID)}
			rows := source.entries[key]
			if len(rows) != 1 {
				return kaname.ErrSourceUnconfirmed
			}
			var err error
			role, err = resourceCapturedRole(rows[0].value)
			if err != nil {
				return err
			}
			if role.ID != b.RoleID {
				return kaname.ErrSourceUnconfirmed
			}
			roles[b.RoleID] = role
		}
		if err := questions.bindingRole(actor, scopeAnchorFor(b), role); err != nil {
			return err
		}
	}
	return ctx.Err()
}
