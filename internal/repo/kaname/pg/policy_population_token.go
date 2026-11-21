// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

// Это immutable RR свидетельство полного census, не разрешение и не held
// latch. Numeric SUM сохраняется десятичной строкой без потери точности.
// Защищённое сравнение выполняет только v2 entry/protector после SHARE.
type policyPopulationToken struct {
	generation string
	count      int
	revision   string
}

func unsignedDecimal(s string) bool {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return false
	}
	for i := range s {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func (t policyPopulationToken) valid() bool {
	return t.count > 0 && t.count <= policyDiscoveryRows && unsignedDecimal(t.generation) && t.generation != "0" && unsignedDecimal(t.revision)
}

// SQL helper читает root generation и ограниченный COUNT/SUM одним snapshot.
// При sentinel он отказывает целиком. Не сортирует inventory и не обещает
// ограничение physical pages либо invisible MVCC tuples.
func readPolicyPopulationToken(ctx context.Context, tx pgx.Tx, budget *relverdict.AdministrativeReadBudget) (policyPopulationToken, error) {
	var token policyPopulationToken
	if err := ctx.Err(); err != nil {
		return token, err
	}
	if tx == nil || budget == nil {
		return token, kaname.ErrSourceUnconfirmed
	}
	remaining := budget.RemainingRows()
	if remaining == 0 {
		return token, kaname.ErrSourceReadLimit
	}
	if err := chargeNativePolicyBudget(budget, 0, 1); err != nil {
		return token, err
	}
	if err := tx.QueryRow(ctx, `SELECT generation, row_count, revision_sum FROM kaname.authority_policy_population_read($1)`, remaining).Scan(&token.generation, &token.count, &token.revision); err != nil {
		return policyPopulationToken{}, err
	}
	if !token.valid() || token.count > remaining {
		return policyPopulationToken{}, kaname.ErrSourceUnconfirmed
	}
	if err := chargeNativePolicyBudget(budget, token.count, 0); err != nil {
		return policyPopulationToken{}, err
	}
	return token, ctx.Err()
}

func (t policyPopulationToken) json() ([]byte, error) {
	if !t.valid() {
		return nil, kaname.ErrSourceUnconfirmed
	}
	return json.Marshal(struct {
		Generation string `json:"generation"`
		Count      int    `json:"count"`
		Revision   string `json:"revision"`
	}{t.generation, t.count, t.revision})
}
