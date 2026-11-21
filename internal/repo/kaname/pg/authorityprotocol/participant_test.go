// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authorityprotocol

import (
	"context"
	"errors"
	"testing"
	"time"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

type participantRow struct {
	abi    int
	err    error
	cancel context.CancelFunc
}

func (r participantRow) Scan(dest ...any) error {
	if r.cancel != nil {
		r.cancel()
	}
	if r.err != nil {
		return r.err
	}
	*dest[0].(*int) = r.abi
	return nil
}

type participantTx struct {
	pgx.Tx
	row                participantRow
	rollbackErr        error
	rollbackCalls      int
	rollbackContextErr error
	cleanupDuration    time.Duration
}

func (tx *participantTx) QueryRow(context.Context, string, ...any) pgx.Row { return tx.row }
func (tx *participantTx) Rollback(ctx context.Context) error {
	tx.rollbackCalls++
	tx.rollbackContextErr = ctx.Err()
	if until, ok := ctx.Deadline(); ok {
		tx.cleanupDuration = time.Until(until)
	}
	return tx.rollbackErr
}
func TestParticipantEntryCanceledAfterSQLStillRollsBack(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tx := &participantTx{row: participantRow{abi: 2, cancel: cancel}}
	begin := func(context.Context, pgx.TxOptions) (pgx.Tx, error) { return tx, nil }
	got, err := openParticipant(ctx, begin, kaname.AuthorityCatalog)
	if got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, %v", got, err)
	}
	if tx.rollbackCalls != 1 || tx.rollbackContextErr != nil || tx.cleanupDuration <= 0 || tx.cleanupDuration > 5*time.Second {
		t.Fatalf("cleanup: %+v", tx)
	}
}
func TestParticipantEntryPreservesFailureAndCleanup(t *testing.T) {
	entryErr := errors.New("entry unavailable")
	cleanupErr := errors.New("cleanup unavailable")
	tx := &participantTx{row: participantRow{err: entryErr}, rollbackErr: cleanupErr}
	got, err := openParticipant(context.Background(), func(context.Context, pgx.TxOptions) (pgx.Tx, error) { return tx, nil }, kaname.AuthorityRole)
	if got != nil || !errors.Is(err, entryErr) || !errors.Is(err, cleanupErr) {
		t.Fatalf("got %v, %v", got, err)
	}
}
func TestParticipantEntryCannotAcceptWrongABI(t *testing.T) {
	tx := &participantTx{row: participantRow{abi: 1}}
	got, err := openParticipant(context.Background(), func(context.Context, pgx.TxOptions) (pgx.Tx, error) { return tx, nil }, kaname.AuthorityBinding)
	if got != nil || !errors.Is(err, kaname.ErrSemanticIdentityUnavailable) || tx.rollbackCalls != 1 {
		t.Fatalf("got %v, %v", got, err)
	}
}
func TestParticipantEntryDoesNotRetryOrOwnSuccessfulBody(t *testing.T) {
	tx := &participantTx{row: participantRow{abi: 2}}
	calls := 0
	got, err := openParticipant(context.Background(), func(_ context.Context, options pgx.TxOptions) (pgx.Tx, error) {
		calls++
		if options.IsoLevel != pgx.ReadCommitted {
			t.Fatal(options)
		}
		return tx, nil
	}, kaname.AuthorityIdentity)
	if got != tx || err != nil || calls != 1 || tx.rollbackCalls != 0 {
		t.Fatalf("got %v, %v; calls=%d cleanup=%d", got, err, calls, tx.rollbackCalls)
	}
}
func TestParticipantEntryRejectsResourceBeforePool(t *testing.T) {
	calls := 0
	_, err := openParticipant(context.Background(), func(context.Context, pgx.TxOptions) (pgx.Tx, error) { calls++; return nil, nil }, kaname.AuthorityResource)
	if !errors.Is(err, kaname.ErrInvalidAuthorityFencePlan) || calls != 0 {
		t.Fatalf("calls=%d, err=%v", calls, err)
	}
}
