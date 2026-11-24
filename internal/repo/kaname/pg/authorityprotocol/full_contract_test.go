// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package authorityprotocol

import (
	"context"
	"errors"
	"strings"
	"testing"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type publicationConfirmationRow struct {
	matches bool
	err     error
}

func (r publicationConfirmationRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*dest[0].(*bool) = r.matches
	return nil
}

type fullInstallationQuery struct {
	sql  string
	args []any
}

type fullInstallationTx struct {
	participantTx
	queries      []fullInstallationQuery
	confirmation publicationConfirmationRow
}

func (tx *fullInstallationTx) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	tx.queries = append(tx.queries, fullInstallationQuery{query, append([]any(nil), args...)})
	if len(tx.queries) == 1 {
		return tx.row
	}
	return tx.confirmation
}

func TestFullInstallationEntryPinsIdentityAndRejectsOldABIReceipt(t *testing.T) {
	readErr := errors.New("publication journal cannot be read")
	for _, tc := range []struct {
		name       string
		abi        int
		revision   int64
		confirmed  bool
		readErr    error
		expected   error
		queryCount int
	}{
		{name: "old ABI", abi: 2, expected: kaname.ErrSemanticIdentityUnavailable, queryCount: 1},
		{name: "empty journal", abi: 3, confirmed: true, queryCount: 2},
		{name: "pinned revision", abi: 3, revision: 17, confirmed: true, queryCount: 2},
		{name: "changed revision", abi: 3, revision: 17, expected: kaname.ErrSourceUnconfirmed, queryCount: 2},
		{name: "journal unavailable", abi: 3, revision: 17, readErr: readErr, expected: readErr, queryCount: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &fullInstallationTx{
				participantTx: participantTx{row: participantRow{abi: tc.abi}},
				confirmation:  publicationConfirmationRow{matches: tc.confirmed, err: tc.readErr},
			}
			contract := &FullContract{model: "fixed-model", catalog: "fixed-catalog", projector: "fixed-projector", revision: tc.revision}
			if tc.revision != 0 {
				contract.digest = "sha256:fixed-model"
			}
			begin := func(_ context.Context, options pgx.TxOptions) (pgx.Tx, error) {
				if options.IsoLevel != pgx.ReadCommitted {
					t.Fatalf("writer isolation: %s", options.IsoLevel)
				}
				return tx, nil
			}
			got, err := openParticipantProfile(context.Background(), begin, kaname.AuthorityRole, contract)
			if len(tx.queries) != tc.queryCount {
				t.Fatalf("entry and confirmation queries: %+v", tx.queries)
			}
			entry := tx.queries[0]
			if !strings.Contains(entry.sql, "authority_installation_enter_v3") || len(entry.args) != 4 ||
				entry.args[1] != contract.model || entry.args[2] != contract.catalog || entry.args[3] != contract.projector {
				t.Fatalf("identity selection: %+v", entry)
			}
			if tc.queryCount == 2 {
				confirmation := tx.queries[1]
				if !strings.Contains(confirmation.sql, "NOT pg_is_in_recovery()") ||
					!strings.Contains(confirmation.sql, "revision = $1 AND digest = $2 AND catalog_id = $3") ||
					!strings.Contains(confirmation.sql, "ORDER BY revision DESC LIMIT 1") || len(confirmation.args) != 3 ||
					confirmation.args[0] != tc.revision || confirmation.args[1] != contract.digest || confirmation.args[2] != contract.catalog {
					t.Fatalf("publication selection: %+v", confirmation)
				}
			}
			if tc.expected != nil {
				if got != nil || !errors.Is(err, tc.expected) || tx.rollbackCalls != 1 {
					t.Fatalf("refused entry: %v %v", got, err)
				}
			} else if got != tx || err != nil || tx.rollbackCalls != 0 {
				t.Fatalf("successful entry: %v %v", got, err)
			}
		})
	}
}

func TestFullInstallationContextNeverBorrowsAnotherPool(t *testing.T) {
	profile := &FullContract{pool: &pgxpool.Pool{}, model: "model", catalog: "catalog", projector: "projector"}
	tx, err := OpenParticipant(profile.Context(context.Background()), &pgxpool.Pool{}, kaname.AuthorityCluster)
	if tx != nil || !errors.Is(err, kaname.ErrInvalidAuthorityFencePlan) {
		t.Fatalf("foreign pool: %v %v", tx, err)
	}
	tx, err = OpenParticipant((*FullContract)(nil).Context(context.Background()), profile.pool, kaname.AuthorityCluster)
	if tx != nil || !errors.Is(err, kaname.ErrInvalidAuthorityFencePlan) {
		t.Fatalf("configured nil: %v %v", tx, err)
	}
}
