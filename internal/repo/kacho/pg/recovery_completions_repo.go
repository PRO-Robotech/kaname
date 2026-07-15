// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// recovery_completions_repo.go — kacho_iam.recovery_completions (migration 0015):
// idempotency ledger for the Kratos recovery-completed webhook
// (InternalUserService.OnRecoveryCompleted).
//
// Within-service invariants — DB-level (ban #10):
//   - PK recovery_jti                         → ON CONFLICT DO NOTHING dedup-gate,
//     PK row-lock serializes concurrent deliveries of one recovery_jti.
//   - CHECK length(recovery_jti/external_id/user_id) + revoked_session_count>=0.
//
// Write-only adapter: the gate INSERT must run inside the recovery writer-tx
// (atomic with re-enable + revoke-all + audit), so it is exposed via the
// tx-scoped writeTx.InsertRecoveryCompletion, NOT a pool-scoped repo. There is
// no read path — Operation.metadata is computed from the deterministic matched
// set, not read back from the ledger.

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

const recoveryCols = "recovery_jti, external_id, user_id, revoked_session_count"

// insertRecoveryCompletionTx — idempotency-gate INSERT on a caller-owned tx.
//
//	INSERT … VALUES (…) ON CONFLICT (recovery_jti) DO NOTHING RETURNING …
//	-- 1 row  → inserted=true  (new flow)
//	-- 0 rows → inserted=false → backstop SELECT the existing row.
//
// CTE-form gives a single result set + atomicity regardless of insert-vs-conflict
// (mirrors InsertPending). The PK row-lock serializes concurrent deliveries.
func insertRecoveryCompletionTx(ctx context.Context, tx pgx.Tx, rc domain.RecoveryCompletion) (domain.RecoveryCompletion, bool, error) {
	q := fmt.Sprintf(`
		WITH ins AS (
			INSERT INTO recovery_completions (recovery_jti, external_id, user_id, revoked_session_count)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (recovery_jti) DO NOTHING
			RETURNING %s
		)
		SELECT %s, true AS inserted FROM ins
		UNION ALL
		SELECT %s, false AS inserted FROM recovery_completions
		WHERE recovery_jti = $1 AND NOT EXISTS (SELECT 1 FROM ins)
		LIMIT 1`, recoveryCols, recoveryCols, recoveryCols)

	row := tx.QueryRow(ctx, q,
		rc.RecoveryJTI, string(rc.ExternalID), string(rc.UserID), rc.RevokedSessionCount,
	)
	var (
		out      domain.RecoveryCompletion
		inserted bool
	)
	if err := scanRecoveryCompletionWithInserted(row, &out, &inserted); err != nil {
		return domain.RecoveryCompletion{}, false, mapErr(err, "", rc.RecoveryJTI)
	}
	return out, inserted, nil
}

func scanRecoveryCompletionWithInserted(row scanner, out *domain.RecoveryCompletion, inserted *bool) error {
	var (
		externalID sql.NullString
		userID     sql.NullString
	)
	if err := row.Scan(&out.RecoveryJTI, &externalID, &userID, &out.RevokedSessionCount, inserted); err != nil {
		return err
	}
	if externalID.Valid {
		out.ExternalID = domain.ExternalSubject(externalID.String)
	}
	if userID.Valid {
		out.UserID = domain.UserID(userID.String)
	}
	return nil
}
