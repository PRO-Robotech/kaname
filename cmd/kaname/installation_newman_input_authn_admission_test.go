// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Raw authn rows stay protected in memory. Only complete hashes, row counts,
// column names and primary clocks may survive teardown. No credential body,
// token, replay nonce or arbitrary audit payload is serialized.
type rid11AuthnSnapshot struct {
	Started  time.Time                    `json:"primaryStartedAt"`
	Finished time.Time                    `json:"primaryFinishedAt"`
	Raw      map[string][]rid09PrimaryRow `json:"-"`
	Columns  map[string][]string          `json:"columns"`
	Counts   map[string]int               `json:"counts"`
	SHA256   map[string]string            `json:"sha256"`
}

var rid11AuthnColumns = map[string]string{
	"client_assertion_replay": "client_id assertion_id expires_at redeemed_at",
	"access_tokens":           "jti family_id family_live issued_at expires_at",
	"audit_outbox":            "id event_type tenant_account_id event_payload status attempts created_at next_attempt_at sent_at last_error",
}

func rid11RecordThenObserve(record, observer func() error) error {
	if record == nil || observer == nil {
		return errors.New("RID11 admission observer missing")
	}
	if record() != nil {
		return errors.New("RID11 complete FD5 capture failed")
	}
	if observer() != nil {
		return errors.New("RID11 primary admission census failed")
	}
	return nil
}
func rid11CaptureAuthn(ctx context.Context, f *installationNativeWorld) (rid11AuthnSnapshot, error) {
	out := rid11AuthnSnapshot{Raw: map[string][]rid09PrimaryRow{}, Columns: map[string][]string{}, Counts: map[string]int{}, SHA256: map[string]string{}}
	fail := func() (rid11AuthnSnapshot, error) {
		return out, errors.New("RID11 protected authn primary census failed")
	}
	if ctx.Err() != nil {
		return fail()
	}
	tx, err := f.given.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return fail()
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	var recovery bool
	if tx.QueryRow(ctx, "SELECT pg_is_in_recovery(),clock_timestamp()").Scan(&recovery, &out.Started) != nil || recovery {
		return fail()
	}
	for _, table := range []string{"client_assertion_replay", "access_tokens", "audit_outbox"} {
		cols, e := tx.Query(ctx, `SELECT a.attname FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kaname' AND c.relname=$1 AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum`, table)
		if e != nil {
			return fail()
		}
		names := []string{}
		for cols.Next() {
			var name string
			if cols.Scan(&name) != nil {
				cols.Close()
				return fail()
			}
			names = append(names, name)
		}
		e = cols.Err()
		cols.Close()
		if e != nil || !rid11SameColumns(names, rid11AuthnColumns[table]) {
			return fail()
		}
		out.Columns[table] = names
		rows, e := tx.Query(ctx, "SELECT to_jsonb(r) FROM "+pgx.Identifier{"kaname", table}.Sanitize()+" r ORDER BY to_jsonb(r)::text")
		if e != nil {
			return fail()
		}
		raw := []rid09PrimaryRow{}
		for rows.Next() {
			var data []byte
			if rows.Scan(&data) != nil {
				rows.Close()
				return fail()
			}
			var r rid09PrimaryRow
			if json.Unmarshal(data, &r) != nil || !rid03Columns(r, rid11AuthnColumns[table]) {
				rows.Close()
				return fail()
			}
			raw = append(raw, r)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return fail()
		}
		out.Raw[table] = raw
		out.Counts[table] = len(raw)
		out.SHA256[table] = rid03EvidenceHash(raw)
	}
	if tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&out.Finished) != nil || out.Started.IsZero() || out.Finished.Before(out.Started) {
		return fail()
	}
	if tx.Commit(ctx) != nil || ctx.Err() != nil {
		return fail()
	}
	return out, nil
}
func rid11SameColumns(names []string, want string) bool {
	row := rid09PrimaryRow{}
	for _, name := range names {
		if _, exists := row[name]; exists {
			return false
		}
		row[name] = json.RawMessage("null")
	}
	return rid03Columns(row, want)
}
func rid11AuthnShape(a rid11AuthnSnapshot) bool {
	if a.Started.IsZero() || a.Finished.Before(a.Started) || len(a.Raw) != 3 || len(a.Columns) != 3 || len(a.Counts) != 3 || len(a.SHA256) != 3 {
		return false
	}
	for table, cols := range rid11AuthnColumns {
		rows, exists := a.Raw[table]
		if !exists || rows == nil || !rid11SameColumns(a.Columns[table], cols) || a.Counts[table] != len(rows) || a.SHA256[table] != rid03EvidenceHash(rows) {
			return false
		}
		for _, row := range rows {
			if !rid03Columns(row, cols) {
				return false
			}
		}
	}
	return true
}
func rid11AuthnUnchanged(a, b rid11AuthnSnapshot) bool {
	return rid11AuthnShape(a) && rid11AuthnShape(b) && !b.Started.Before(a.Finished) && reflect.DeepEqual(a.Columns, b.Columns) && reflect.DeepEqual(a.Raw["client_assertion_replay"], b.Raw["client_assertion_replay"]) && reflect.DeepEqual(a.Raw["access_tokens"], b.Raw["access_tokens"]) && rid11AuditHistoryValid(a, b)
}

// Source contract: corelib v1.15.0 audit/shipper.go shipBatch, backoff,
// buildShipperSQL. The fixture buildAuditShipper supplies only Table, hence
// production defaults BackoffMin=1s/BackoffMax=5m. This is transport progress,
// never a new authn/business action or a physical-SQL-zero claim.
func rid11AuditImmutable(row rid09PrimaryRow) rid09PrimaryRow {
	out := rid09PrimaryRow{}
	for _, key := range []string{"id", "event_type", "tenant_account_id", "event_payload", "created_at"} {
		out[key] = row[key]
	}
	return out
}
func rid11AuditTransport(row rid09PrimaryRow) rid09PrimaryRow {
	out := rid09PrimaryRow{}
	for _, key := range []string{"status", "attempts", "sent_at", "last_error", "next_attempt_at"} {
		out[key] = row[key]
	}
	return out
}
func rid11AuditParts(rows []rid09PrimaryRow) (string, string) {
	immutable, transport := []rid09PrimaryRow{}, []rid09PrimaryRow{}
	for _, row := range rows {
		immutable = append(immutable, rid11AuditImmutable(row))
		r := rid11AuditTransport(row)
		r["id"] = row["id"]
		transport = append(transport, r)
	}
	return rid03EvidenceHash(immutable), rid03EvidenceHash(transport)
}
func rid11SanitizedCause(s *string) bool {
	if s == nil {
		return false
	}
	var b strings.Builder
	for _, r := range strings.ToValidUTF8(*s, "\uFFFD") {
		if b.Len() >= 1000 {
			b.WriteString("…")
			break
		}
		if r == 0 || (r < 0x20 && r != '\n' && r != '\t') {
			b.WriteRune(' ')
			continue
		}
		b.WriteRune(r)
	}
	return b.String() == *s
}
func rid11AuditRowShape(r rid09PrimaryRow, upper time.Time) bool {
	if !rid03Columns(r, rid11AuthnColumns["audit_outbox"]) {
		return false
	}
	id, a := rid03Cell[string](r, "id")
	event, b := rid03Cell[string](r, "event_type")
	tenant, c := rid03Cell[*string](r, "tenant_account_id")
	payload, d := rid03Cell[map[string]any](r, "event_payload")
	status, e := rid03Cell[string](r, "status")
	attempts, f := rid03Cell[int64](r, "attempts")
	created, g := rid03Cell[time.Time](r, "created_at")
	next, h := rid03Cell[time.Time](r, "next_attempt_at")
	sent, i := rid03Cell[*time.Time](r, "sent_at")
	cause, j := rid03Cell[*string](r, "last_error")
	if !(a && b && c && d && e && f && g && h && i && j) || id == "" || event == "" || (tenant != nil && *tenant == "") || payload == nil || attempts < 0 || created.IsZero() || created.After(upper) || next.IsZero() {
		return false
	}
	if status == "sent" {
		return attempts > 0 && sent != nil && !sent.IsZero() && !sent.Before(created) && !sent.After(upper) && cause == nil
	}
	return status == "pending" && sent == nil && (cause == nil || rid11SanitizedCause(cause))
}
func rid11AuditTransition(a, b rid09PrimaryRow, beforeUpper, afterUpper time.Time) bool {
	if !rid11AuditRowShape(a, beforeUpper) || !rid11AuditRowShape(b, afterUpper) || !reflect.DeepEqual(rid11AuditImmutable(a), rid11AuditImmutable(b)) {
		return false
	}
	oldAttempts, _ := rid03Cell[int64](a, "attempts")
	attempts, _ := rid03Cell[int64](b, "attempts")
	if rid03S(a, "status") == "sent" || attempts == oldAttempts {
		return reflect.DeepEqual(a, b)
	}
	if attempts < oldAttempts {
		return false
	}
	oldNext, _ := rid03Cell[time.Time](a, "next_attempt_at")
	next, _ := rid03Cell[time.Time](b, "next_attempt_at")
	created, _ := rid03Cell[time.Time](b, "created_at")
	// Claim SQL requires next_attempt_at <= transaction now(), and any
	// committed claim transaction starts no later than the independent after
	// primary upper bound. Do not require it to start after the BEFORE read.
	if oldNext.After(afterUpper) || next.Before(oldNext) {
		return false
	}
	if rid03S(b, "status") == "sent" {
		sent, _ := rid03Cell[*time.Time](b, "sent_at")
		// claim and sent use the same tx's now(); a pre-baseline transaction can
		// commit later, so no unjustified sent_at >= before snapshot constraint.
		if sent.Before(oldNext) || next.After(*sent) {
			return false
		}
		return attempts-oldAttempts != 1 || next.Equal(oldNext)
	}
	// Failed defer SQL rolls back its savepoint but commits claim's increment:
	// all four other transport fields remain exact on this documented stuck path.
	onlyClaim := true
	for _, key := range []string{"status", "sent_at", "last_error", "next_attempt_at"} {
		if !reflect.DeepEqual(a[key], b[key]) {
			onlyClaim = false
		}
	}
	if onlyClaim {
		return true
	}
	cause, _ := rid03Cell[*string](b, "last_error")
	if !rid11SanitizedCause(cause) {
		return false
	}
	wait := time.Second
	for n := int64(1); n < attempts && wait < 5*time.Minute; n++ {
		wait *= 2
	}
	if wait > 5*time.Minute {
		wait = 5 * time.Minute
	}
	clock := next.Add(-wait)
	return !clock.Before(created) && !clock.Before(oldNext) && !clock.After(afterUpper)
}
func rid11AuditHistoryValid(a, b rid11AuthnSnapshot) bool {
	old := map[string]rid09PrimaryRow{}
	for _, row := range a.Raw["audit_outbox"] {
		id := rid03S(row, "id")
		if id == "" || old[id] != nil {
			return false
		}
		old[id] = row
	}
	if len(old) != len(b.Raw["audit_outbox"]) {
		return false
	}
	seen := map[string]bool{}
	for _, row := range b.Raw["audit_outbox"] {
		id := rid03S(row, "id")
		if seen[id] || old[id] == nil || !rid11AuditTransition(old[id], row, a.Finished, b.Finished) {
			return false
		}
		seen[id] = true
	}
	return len(seen) == len(old)
}
