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
		failure := kaname.InstallationOpenFailure{Stage: stage, Class: participantOpenCause(err)}
		if failure.Class == "sql-query-canceled" {
			var db *pgconn.PgError
			if errors.As(err, &db) {
				failure.Cancel = participantQueryCancel(ctx, db)
			}
		}
		return failure
	})
}

// PostgreSQL uses the same SQLSTATE for a statement timeout and a CancelRequest.
func participantQueryCancel(ctx context.Context, db *pgconn.PgError) kaname.InstallationQueryCancel {
	d := kaname.InstallationQueryCancel{Reason: "other", Context: "active", Site: "unclassified"}
	switch db.Message {
	case "canceling statement due to statement timeout":
		d.Reason = "statement-timeout"
	case "canceling statement due to user request":
		d.Reason = "user-request"
	}
	switch ctx.Err() {
	case context.Canceled:
		d.Context = "canceled"
	case context.DeadlineExceeded:
		d.Context = "deadline"
	}
	// An outer function frame only says that the call was on the stack. Match
	// only the first SQL statement in a bounded PostgreSQL context.
	if len(db.Where) > 4096 {
		return d
	}
	line, rest, ok := strings.Cut(db.Where, "\n")
	if !ok || len(line) > 256 || !strings.HasPrefix(rest, "PL/pgSQL function ") {
		return d
	}
	stmt, ok := strings.CutPrefix(line, `SQL statement "`)
	if !ok {
		return d
	}
	stmt, ok = strings.CutSuffix(stmt, `"`)
	if !ok {
		return d
	}
	switch strings.ToLower(strings.Join(strings.Fields(stmt), " ")) {
	case "select pg_advisory_xact_lock(1262569283,0)":
		d.Site = "global-coordinator"
	case "select pg_advisory_xact_lock(1262569292,0)":
		d.Site = "consumer-admission"
	case "select * from kaname.authority_writer_protocol where singleton for share":
		d.Site = "protocol-row"
	case "select * from kaname.authority_semantic_identity where singleton for share":
		d.Site = "identity-row"
	case "lock table kaname.authority_producer_population_latch in share mode":
		d.Site = "population-latch"
	}
	return d
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
