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
	"github.com/jackc/pgx/v5/pgconn"
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

func TestParticipantOpenObservationPreservesPrimaryErrorAndCleanup(t *testing.T) {
	secretDetail := "fixture-dsn-or-postgres-detail"
	sqlErr := &pgconn.PgError{Code: "57014", Message: secretDetail, Detail: secretDetail}
	unknownSQL := &pgconn.PgError{Code: "XX999", Message: secretDetail, Detail: secretDetail}
	beginErr := errors.New(secretDetail)
	cleanupErr := &pgconn.PgError{Code: "40P01", Message: secretDetail}
	for _, tc := range []struct {
		name, stage, class string
		profile            *FullContract
		beginErr, entryErr error
		cleanupErr         error
		abi                int
		cancelAfterSQL     bool
		want               error
	}{
		{name: "begin", stage: "open-begin", class: "other", beginErr: beginErr, want: beginErr},
		{name: "v2", stage: "open-enter-v2", class: "sql-query-canceled", entryErr: sqlErr, want: sqlErr},
		{name: "v3", stage: "open-enter-v3", class: "sql-other", profile: &FullContract{}, entryErr: unknownSQL, cleanupErr: cleanupErr, want: unknownSQL},
		{name: "mismatch", stage: "open-abi-mismatch", class: "semantic-identity", profile: &FullContract{}, abi: 2, want: kaname.ErrSemanticIdentityUnavailable},
		{name: "context", stage: "open-context", class: "Canceled", abi: 2, cancelAfterSQL: true, want: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var observed []kaname.InstallationOpenFailure
			ctx = kaname.WithInstallationOpenObserver(ctx, func(failure kaname.InstallationOpenFailure) {
				observed = append(observed, failure)
			})
			tx := &participantTx{row: participantRow{abi: tc.abi, err: tc.entryErr}, rollbackErr: tc.cleanupErr}
			if tc.cancelAfterSQL {
				tx.row.cancel = cancel
			}
			begins := 0
			got, err := openParticipantProfile(ctx, func(context.Context, pgx.TxOptions) (pgx.Tx, error) {
				begins++
				if tc.beginErr != nil {
					return nil, tc.beginErr
				}
				return tx, nil
			}, kaname.AuthorityRole, tc.profile)
			if got != nil || err == nil || begins != 1 || !errors.Is(err, tc.want) {
				t.Fatalf("transaction=%v begins=%d primary=%t", got, begins, errors.Is(err, tc.want))
			}
			if tc.cleanupErr == nil && err != tc.want {
				t.Fatal("observation changed raw error identity")
			}
			if tc.cleanupErr != nil {
				var failure interface{ PreparedCleanupFailed() bool }
				if !errors.As(err, &failure) || !failure.PreparedCleanupFailed() || !errors.Is(err, tc.cleanupErr) {
					t.Fatal("cleanup cause or retry fence lost")
				}
			}
			wantRollback := 1
			if tc.beginErr != nil {
				wantRollback = 0
			}
			if tx.rollbackCalls != wantRollback || tx.rollbackContextErr != nil {
				t.Fatal("rollback or detached rollback context changed")
			}
			want := kaname.InstallationOpenFailure{Stage: tc.stage, Class: tc.class}
			if tc.class == "sql-query-canceled" {
				want.Cancel = kaname.InstallationQueryCancel{Reason: "other", Context: "active", Site: "unclassified"}
			}
			if len(observed) != 1 || observed[0] != want {
				t.Fatalf("unexpected bounded observation: %+v", observed)
			}
		})
	}
}

// These fixtures contain secondary SQL and detail that must never become labels.
func TestParticipantQueryCancelClassifiesOnlyPrimaryBackendEvidence(t *testing.T) {
	type detail = kaname.InstallationQueryCancel
	const frame = "\nPL/pgSQL function kaname.authority_installation_enter_v2(text) line 35 at PERFORM"
	const coordinator = `SQL statement "SELECT pg_advisory_xact_lock(1262569283,0)"`
	const nextFrame = "\nSQL statement \"SELECT another_private_function()\"" + frame
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer stop()
	for _, tc := range []struct {
		ctx            context.Context
		message, where string
		want           detail
	}{
		{context.Background(), "canceling statement due to statement timeout", coordinator + frame + nextFrame,
			detail{Reason: "statement-timeout", Context: "active", Site: "global-coordinator"}},
		{canceled, "canceling statement due to user request", `SQL statement "SELECT pg_advisory_xact_lock(1262569292,0)"` + frame,
			detail{Reason: "user-request", Context: "canceled", Site: "consumer-admission"}},
		{expired, "canceling statement due to user request", `SQL statement "SELECT *     FROM kaname.authority_writer_protocol WHERE singleton FOR SHARE"` + frame,
			detail{Reason: "user-request", Context: "deadline", Site: "protocol-row"}},
		{context.Background(), "canceling statement due to statement timeout", `SQL statement "SELECT * FROM kaname.authority_semantic_identity WHERE singleton FOR SHARE"` + frame,
			detail{Reason: "statement-timeout", Context: "active", Site: "identity-row"}},
		{context.Background(), "canceling statement due to statement timeout", `SQL statement "LOCK TABLE kaname.authority_producer_population_latch IN SHARE MODE"` + frame,
			detail{Reason: "statement-timeout", Context: "active", Site: "population-latch"}},
		{canceled, "canceling statement due to statement timeout", "private detail" + frame + "\n" + coordinator + frame,
			detail{Reason: "statement-timeout", Context: "canceled", Site: "unclassified"}},
		{context.Background(), "canceling statement due to user request PRIVATE", coordinator + " trailing PRIVATE" + frame,
			detail{Reason: "other", Context: "active", Site: "unclassified"}},
	} {
		var got kaname.InstallationOpenFailure
		ctx := kaname.WithInstallationOpenObserver(tc.ctx, func(f kaname.InstallationOpenFailure) { got = f })
		observeParticipantOpen(ctx, "open-enter-v2", &pgconn.PgError{Code: "57014", Message: tc.message, Where: tc.where, Detail: "private detail"})
		if got.Stage != "open-enter-v2" || got.Class != "sql-query-canceled" || got.Cancel != tc.want {
			t.Fatalf("unexpected bounded fields %+v; want %+v", got, tc.want)
		}
	}
}
