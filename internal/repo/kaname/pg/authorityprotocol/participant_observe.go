// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authorityprotocol

import (
	"context"
	"errors"
	"strings"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Observe the primary error before rollback can add a second cause. The
// original error still returns unchanged through the existing transaction path.
func observeParticipantOpen(ctx context.Context, stage string, err error) {
	kaname.ObserveInstallationOpenFailure(ctx, func() kaname.InstallationOpenFailure {
		return kaname.InstallationOpenFailure{Stage: stage, Class: participantOpenCause(err)}
	})
}

func participantOpenCause(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "Canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "DeadlineExceeded"
	case errors.Is(err, kaname.ErrInvalidAuthorityFencePlan):
		return "invalid-fence"
	case errors.Is(err, kaname.ErrSemanticIdentityUnavailable):
		return "semantic-identity"
	case errors.Is(err, pgx.ErrNoRows):
		return "no-row"
	case errors.Is(err, pgx.ErrTxClosed):
		return "transaction-closed"
	}
	var db *pgconn.PgError
	if errors.As(err, &db) && db != nil {
		switch db.Code {
		case "40P01":
			return "deadlock"
		case "40001":
			return "serialization"
		case "42501":
			return "sql-permission"
		case "42883":
			return "sql-undefined-function"
		case "42P01":
			return "sql-undefined-table"
		case "55P03":
			return "sql-lock-unavailable"
		case "57014":
			return "sql-query-canceled"
		case "25001", "55000":
			return "sql-state"
		}
		if strings.HasPrefix(db.Code, "08") {
			return "sql-connection"
		}
		return "sql-other"
	}
	var connect *pgconn.ConnectError
	if errors.As(err, &connect) {
		return "connection-open"
	}
	var scan pgx.ScanArgError
	if errors.As(err, &scan) {
		return "result-scan"
	}
	if errors.Is(err, kaname.ErrSourceUnconfirmed) {
		return "source-unconfirmed"
	}
	return "other"
}
