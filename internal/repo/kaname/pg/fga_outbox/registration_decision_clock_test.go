// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package fga_outbox

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type registrationClockCall struct {
	sql  string
	args []any
}
type registrationClockTX struct {
	pgx.Tx
	calls []registrationClockCall
}

func (tx *registrationClockTX) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tx.calls = append(tx.calls, registrationClockCall{sql: sql, args: append([]any(nil), args...)})
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}
func (tx *registrationClockTX) QueryRow(context.Context, string, ...any) pgx.Row {
	panic("protected registration emission attempted a clock/source reread")
}

func TestRegistrationDecisionDeleteKeepsOneClockAndDeliveryMode(t *testing.T) {
	decision := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	for _, ordered := range []bool{false, true} {
		name := "legacy"
		version := time.Time{}
		if ordered {
			name = "ordered"
			version = decision.Add(-time.Hour)
		}
		t.Run(name, func(t *testing.T) {
			tx := &registrationClockTX{}
			err := EmitRegistrationDecisionDeleteTx(context.Background(), tx, []clients.RelationTuple{{User: "account:a", Relation: "owner", Object: "vpc_address:x"}}, version, decision)
			if err != nil {
				t.Fatal(err)
			}
			if len(tx.calls) != 2 {
				t.Fatalf("calls=%d", len(tx.calls))
			}
			if !strings.Contains(tx.calls[0].sql, "UPDATE kaname.producer_source_receipt") {
				t.Fatal("receipt retirement must precede journal")
			}
			if got, ok := tx.calls[0].args[4].(time.Time); !ok || !got.Equal(decision) {
				t.Fatalf("retirement clock=%v", tx.calls[0].args[4])
			}
			journal := tx.calls[1]
			if got, ok := journal.args[len(journal.args)-1].(time.Time); !ok || !got.Equal(decision) {
				t.Fatalf("journal clock=%v", journal.args)
			}
			if ordered {
				if got := journal.args[4].(time.Time); !got.Equal(version) {
					t.Fatal("delivery version replaced by decision")
				}
			} else {
				payloads := journal.args[1].([]string)
				if len(payloads) != 1 || strings.Contains(payloads[0], "source_version") {
					t.Fatalf("legacy mode changed: %v", payloads)
				}
			}
		})
	}
}

func TestRegistrationDecisionDeleteRejectsMissingClockBeforeSQL(t *testing.T) {
	tx := &registrationClockTX{}
	if err := EmitRegistrationDecisionDeleteTx(context.Background(), tx, nil, time.Time{}, time.Time{}); err == nil {
		t.Fatal("missing clock accepted")
	}
	if len(tx.calls) != 0 {
		t.Fatal("SQL before decision validation")
	}
}
