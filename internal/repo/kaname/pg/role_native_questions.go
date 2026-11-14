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
	questions := newNativePolicyQuestions()
	if err := questions.roleBase(actor, role, request.create); err != nil {
		return nil, 0, err
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
			if err = questions.roleCarrier(actor, binding); err != nil {
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
