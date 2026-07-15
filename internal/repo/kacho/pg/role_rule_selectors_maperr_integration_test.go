// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// role_rule_selectors_maperr_integration_test.go — db#2: ReplaceRuleSelectors must
// route a Postgres CHECK violation (23514) through mapErr → ErrInvalidArg, not bare
// fmt.Errorf(%w) which surfaces as INTERNAL. A selector whose match_labels fails the
// role_rule_selectors_labels_valid CHECK (kacho_labels_valid: bad key format) is the
// 23514 path. RED before the fix (bare-wrapped pgx error is not ErrInvalidArg), GREEN
// after.
//
// Run: `make test` (testcontainers Postgres 16). Skipped under -short.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

func TestDB2_ReplaceRuleSelectors_CheckViolation_MapsInvalidArgument(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "db2owner")
	acc := seedAccount(t, ctx, repo, "db2-acc", owner)
	roleID := seedCustomRoleSQL(t, ctx, pool, acc.ID, "db2_role")

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()

	// match_labels with an illegal key ("BAD KEY": uppercase + space) marshals to
	// valid JSON but fails kacho_labels_valid → CHECK role_rule_selectors_labels_valid
	// → SQLSTATE 23514. The repo must translate that to ErrInvalidArg.
	bad := []domain.RuleSelector{{
		RuleFP:      "fp_db2",
		Arm:         domain.ArmLabels,
		ObjectTypes: []string{"compute.instance"},
		MatchLabels: map[string]string{"BAD KEY": "v"},
	}}
	rerr := w.RolesW().ReplaceRuleSelectors(ctx, roleID, bad)
	require.Error(t, rerr, "invalid match_labels must violate the CHECK")
	assert.True(t, errors.Is(rerr, iamerr.ErrInvalidArg),
		"23514 CHECK violation must map to ErrInvalidArg (not INTERNAL): got %v", rerr)
}
