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

type fullInstallationTx struct {
	participantTx
	query string
	args  []any
}

func (tx *fullInstallationTx) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	tx.query, tx.args = query, append([]any{}, args...)
	return tx.row
}
func TestFullInstallationEntryPinsIdentityAndRejectsOldABIReceipt(t *testing.T) {
	for _, abi := range []int{2, 3} {
		tx := &fullInstallationTx{participantTx: participantTx{row: participantRow{abi: abi}}}
		contract := &FullContract{model: "fixed-model", catalog: "fixed-catalog", projector: "fixed-projector"}
		got, err := openParticipantProfile(context.Background(), func(context.Context, pgx.TxOptions) (pgx.Tx, error) { return tx, nil }, kaname.AuthorityRole, contract)
		if !strings.Contains(tx.query, "authority_installation_enter_v3") || len(tx.args) != 4 || tx.args[1] != "fixed-model" || tx.args[2] != "fixed-catalog" || tx.args[3] != "fixed-projector" {
			t.Fatalf("identity selection: %s %#v", tx.query, tx.args)
		}
		if abi == 2 {
			if got != nil || !errors.Is(err, kaname.ErrSemanticIdentityUnavailable) || tx.rollbackCalls != 1 {
				t.Fatalf("old ABI: %v %v", got, err)
			}
		} else if got != tx || err != nil || tx.rollbackCalls != 0 {
			t.Fatalf("full ABI: %v %v", got, err)
		}
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
