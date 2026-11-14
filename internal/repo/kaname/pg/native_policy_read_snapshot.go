// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

type nativePolicyReadSnapshot struct{ tx pgx.Tx }

func (s nativePolicyReadSnapshot) account(ctx context.Context, node nativeReadNode) (string, error) {
	// Закрытые ownership lookups: unknown module shape остаётся GLOBAL и не
	// получает локальный account по случайно совпавшему mirror object ID.
	switch node.typ {
	case "account", "project", "iam_role", "iam_access_binding", "iam_group", "iam_service_account", "cluster":
	default:
		return "", nil
	}
	var account string
	err := s.tx.QueryRow(ctx, `SELECT coalesce(kaname.authority_policy_object_account($1,$2),'')`, node.typ, node.id).Scan(&account)
	return account, err
}
func (s nativePolicyReadSnapshot) parents(ctx context.Context, node, after nativeReadNode, limit int) ([]nativeReadNode, error) {
	rows, err := s.tx.Query(ctx, `SELECT DISTINCT parent_type COLLATE "C",parent_id COLLATE "C"
 FROM kaname.resource_scope_edge WHERE object_type=$1 AND object_id=$2
 AND (parent_type COLLATE "C",parent_id COLLATE "C")>($3::text COLLATE "C",$4::text COLLATE "C")
 ORDER BY 1,2 LIMIT $5`, node.typ, node.id, after.typ, after.id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]nativeReadNode, 0, limit)
	for rows.Next() {
		var n nativeReadNode
		if err = rows.Scan(&n.typ, &n.id); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// Использует RR caller connection и никогда не открывает вторую connection.
// Token ещё НЕ защищён. Caller объединяет guards/account refs с полным actor
// plan ДО coordinator; protect + query scope binding — обязательные seams.
func discoverNativeReadBoundary(ctx context.Context, tx pgx.Tx, bundle *granteffect.Bundle, questions *nativePolicyQuestions, budget *nativeReadBudget) (*nativeReadBoundary, error) {
	if tx == nil || budget == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if err := budget.charge(0, 1); err != nil {
		return nil, err
	}
	var isolation string
	if err := tx.QueryRow(ctx, `SELECT current_setting('transaction_isolation')`).Scan(&isolation); err != nil {
		return nil, err
	}
	if isolation != "repeatable read" {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	p, err := captureNativeReadBoundary(ctx, bundle, questions, nativePolicyReadSnapshot{tx}, budget)
	if err != nil {
		return nil, err
	}
	if err = budget.charge(0, 1); err != nil {
		return nil, err
	}
	keys := p.guardKeys()
	if err = tx.QueryRow(ctx, `SELECT kaname.authority_policy_epoch_read($1::text[])`, keys).Scan(&p.epochs); err != nil {
		return nil, err
	}
	if err = budget.charge(len(keys), 0); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return p, nil
}
