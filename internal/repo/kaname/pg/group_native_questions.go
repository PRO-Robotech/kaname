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

// Полный вход добавления участника. CRUD/removal не имеют этого purpose и
// сохраняют прежние participant ports, без заявления о закрытом native read.
type groupAdditionNativeRequest struct{ member domain.GroupMember }

// Два keyset scan соответствуют primary pair OR дополнительному subjects set.
// Повторный header начисляется повторно: это реально выполненное чтение.
// JOIN читает не больше одной typed group-subject строки на carrier (PK).
// Ни status, ни expiry не сокращают RR census до final decision_at.
var groupNativeCarrierQueries = [...]string{
	`SELECT b.id,b.resource_type,b.resource_id,b.role_id FROM kaname.access_bindings b WHERE b.subject_type='group' AND b.subject_id=$1 AND b.id COLLATE "C">$2 COLLATE "C" ORDER BY b.id COLLATE "C" LIMIT $3`,
	`SELECT b.id,b.resource_type,b.resource_id,b.role_id FROM kaname.access_binding_subjects s JOIN kaname.access_bindings b ON b.id=s.binding_id WHERE s.subject_type='group' AND s.subject_id=$1 AND b.id COLLATE "C">$2 COLLATE "C" ORDER BY b.id COLLATE "C" LIMIT $3`,
}

func discoverGroupNativeQuestions(ctx context.Context, tx pgx.Tx, actor domain.Subject, request groupAdditionNativeRequest, budget *relverdict.AdministrativeReadBudget) (*nativePolicyQuestions, int, error) {
	m := request.member
	if tx == nil || budget == nil || m.Validate() != nil || (m.MemberType != domain.SubjectTypeUser && m.MemberType != domain.SubjectTypeServiceAccount) {
		return nil, 0, kaname.ErrInvalidAuthorityFencePlan
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	if err := chargeNativePolicyBudget(budget, 0, 1); err != nil {
		return nil, 0, err
	}
	g := domain.Group{ID: m.GroupID}
	if err := tx.QueryRow(ctx, `SELECT account_id FROM kaname.groups WHERE id=$1`, string(m.GroupID)).Scan(&g.AccountID); err != nil {
		return nil, 0, err
	}
	if err := chargeNativePolicyBudget(budget, 1, 0); err != nil {
		return nil, 0, err
	}
	total := 1
	questions := newNativePolicyQuestions()
	if err := questions.groupBase(actor, g); err != nil {
		return nil, total, err
	}
	for phase, query := range groupNativeCarrierQueries {
		after := ""
		for {
			if err := ctx.Err(); err != nil {
				return nil, total, err
			}
			if err := chargeNativePolicyBudget(budget, 0, 1); err != nil {
				return nil, total, err
			}
			rows, err := tx.Query(ctx, query, string(m.GroupID), after, policyDiscoveryPage)
			if err != nil {
				return nil, total, err
			}
			count := 0
			for rows.Next() {
				if err = ctx.Err(); err != nil {
					rows.Close()
					return nil, total, err
				}
				var b domain.AccessBinding
				if err = rows.Scan(&b.ID, &b.ResourceType, &b.ResourceID, &b.RoleID); err != nil {
					rows.Close()
					return nil, total, err
				}
				physical := 1 + phase // дополнительная строка subjects плюс header.
				if err = chargeNativePolicyBudget(budget, physical, 0); err != nil {
					rows.Close()
					return nil, total, err
				}
				total += physical
				count++
				if string(b.ID) <= after {
					rows.Close()
					return nil, total, kaname.ErrCanonicalSourceInvalid
				}
				after = string(b.ID)
				if err = questions.groupCarrier(actor, b); err != nil {
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
				break
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, total, err
	}
	return questions, total, nil
}
