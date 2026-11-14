// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

type delegationBudgetRow func(...any) error

func (r delegationBudgetRow) Scan(dst ...any) error { return r(dst...) }

type delegationBudgetTx struct{ policyScanTx }

func (tx *delegationBudgetTx) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	return delegationBudgetRow(func(dst ...any) error {
		switch {
		case strings.Contains(query, "transaction_isolation"):
			*dst[0].(*string) = "repeatable read"
		case strings.Contains(query, "authority_protocol_discover"):
			*dst[0].(*[]string) = []string{"local"}
			*dst[1].(*bool) = false
		default:
			return fmt.Errorf("unexpected query after row budget: %s", query)
		}
		return nil
	})
}

// Второй actor не получает второй бюджет: реальный discover/scan останавливает
// его уже на первой строке сверх общей границы, до последующих source queries.
func TestDelegationPolicyCreatorSharesEarlyPhysicalRowBudget(t *testing.T) {
	for _, consumed := range []int{policyDiscoveryRows - 1, policyDiscoveryRows} {
		t.Run(fmt.Sprint(consumed), func(t *testing.T) {
			tx := &delegationBudgetTx{policyScanTx: policyScanTx{remaining: 256}}
			p := &GrantPolicyWriters{repo: &Repository{}}
			plan, err := p.discoverPolicyPlanWithRows(context.Background(), tx, policyWriteRequest{actor: domain.Subject{Type: domain.SubjectTypeUser, ID: "creator"}, kind: kaname.AuthorityDelegation}, consumed)
			require.ErrorIs(t, err, errPolicyDiscoveryBudget)
			require.Nil(t, plan)
			require.Equal(t, 1, tx.pages)
			require.Equal(t, policyDiscoveryRows-consumed+1, tx.returned)
		})
	}
	p := scanPlan()
	p.rows = policyDiscoveryRows - 1
	require.NoError(t, p.scan(context.Background(), &policyScanTx{remaining: 1}, "source"))
	require.Equal(t, policyDiscoveryRows, p.rows)
	require.ErrorIs(t, p.scan(context.Background(), &policyScanTx{remaining: 1}, "next-source"), errPolicyDiscoveryBudget)
}
