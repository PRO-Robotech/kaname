// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/clientassertion"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
)

func rid06FailedUnitCell(value any) json.RawMessage { raw, _ := json.Marshal(value); return raw }

func rid06FailedUnitBind(s *rid03NewmanSnapshot, table string, rows []rid09PrimaryRow) {
	entry := ridWholeTable{Columns: strings.Fields(rid11AuthnColumns[table]), Rows: []string{}}
	if table == "operations" {
		entry.Columns = strings.Fields(rid06OperationColumns)
		s.Raw[table] = rows
		s.Whole.operationSQLRows = nil
	} else {
		s.Whole.replaySQLRows = nil
	}
	for _, row := range rows {
		raw, _ := json.Marshal(row)
		entry.Rows = append(entry.Rows, rid06ByteSHA(raw))
		if table == "operations" {
			s.Whole.operationSQLRows = append(s.Whole.operationSQLRows, raw)
		} else {
			s.Whole.replaySQLRows = append(s.Whole.replaySQLRows, raw)
		}
	}
	sort.Strings(entry.Rows)
	s.Whole.Bookkeeping[table] = entry
}

func rid06FailedUnitFixture(mode string) (rid06FailedStartupExpected, rid06FailedStartupLogs, rid03NewmanSnapshot, rid03NewmanSnapshot) {
	at := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	e := rid06FailedStartupExpected{CaseID: "registry-installation-rid06-" + mode + "-SEQUENTIAL-FAILED-STARTUP", RunID: "rid06-failed-startup-unit-20261104", TestExecutableSHA256: strings.Repeat("a", 64), ClientSHA256: installationIdentitySHA("private-unit-client"), CredentialExpiresAt: at.Add(time.Hour), CreatorID: "creator", TenantID: "tenant", DelegateID: "issuer", OldDelegationID: "revoked-gd", Accounts: []string{"tenant"}}
	if mode == "S2" {
		e.Accounts = []string{"system", "other", "tenant"}
	}
	makeSnapshot := func(after bool) rid03NewmanSnapshot {
		start := at.Add(-2 * time.Second)
		stated := at.Add(-time.Minute)
		if after {
			start = at.Add(2 * time.Second)
			stated = at.Add(time.Second)
		}
		whole := ridWholeDeliverySnapshot{PrimaryStartedAt: start, PrimaryFinishedAt: start.Add(time.Second), Delivery: map[string]ridWholeTable{"domain": {Columns: []string{"id"}, Rows: []string{strings.Repeat("b", 64)}}}, Bookkeeping: map[string]ridWholeTable{}, Separation: map[string]string{}, OwnCeilings: ridWholeOwnCeilings{Raw: ridWholeTable{Columns: []string{"kind", "limit_value", "stated_at"}, Rows: []string{strings.Repeat("c", 64)}}, Semantic: map[string]string{"kind": strings.Repeat("d", 64)}, StatedAt: map[string]time.Time{"kind": stated}}}
		for name, reason := range ridWholeBookkeeping {
			whole.Bookkeeping[name] = ridWholeTable{Columns: []string{"id"}, Rows: []string{}}
			whole.Separation[name] = reason
		}
		return rid03NewmanSnapshot{Whole: whole, Raw: map[string][]rid09PrimaryRow{"grant_delegations": {}}, BusinessAudit: []rid09PrimaryRow{}}
	}
	a, b := makeSnapshot(false), makeSnapshot(true)
	oldReplay := rid09PrimaryRow{"client_id": rid06FailedUnitCell("old-client"), "assertion_id": rid06FailedUnitCell("old-assertion"), "expires_at": rid06FailedUnitCell(at.Add(time.Minute)), "redeemed_at": rid06FailedUnitCell(at.Add(-time.Minute))}
	newReplay := rid09PrimaryRow{"client_id": rid06FailedUnitCell("private-unit-client"), "assertion_id": rid06FailedUnitCell("private-unit-assertion"), "expires_at": rid06FailedUnitCell(at.Add(time.Minute)), "redeemed_at": rid06FailedUnitCell(at.Add(time.Second))}
	rid06FailedUnitBind(&a, "client_assertion_replay", []rid09PrimaryRow{oldReplay})
	rid06FailedUnitBind(&b, "client_assertion_replay", []rid09PrimaryRow{oldReplay, newReplay})
	oldOp := rid09PrimaryRow{}
	for _, key := range strings.Fields(rid06OperationColumns) {
		oldOp[key] = rid06FailedUnitCell(nil)
	}
	oldOp["id"] = rid06FailedUnitCell("old-operation")
	ops := []rid09PrimaryRow{oldOp}
	for _, account := range e.Accounts {
		row := rid09PrimaryRow{}
		for _, key := range strings.Fields(rid06OperationColumns) {
			row[key] = rid06FailedUnitCell(nil)
		}
		resource := "new-gd-" + account
		meta, _ := anypb.New(&iamv1.CreateGrantDelegationMetadata{AccountId: account, GrantDelegationId: resource})
		for key, value := range map[string]any{"id": "operation-" + account, "description": "installation", "created_at": at, "modified_at": at.Add(time.Second), "created_by": e.CreatorID, "principal_type": "service_account", "principal_id": e.CreatorID, "principal_display_name": e.CreatorID, "done": true, "metadata_type": meta.TypeUrl, "metadata_data": "\\x" + hex.EncodeToString(meta.Value), "resource_id": resource, "account_id": account} {
			row[key] = rid06FailedUnitCell(value)
		}
		if account == e.TenantID {
			row["error_code"] = rid06FailedUnitCell(9)
			row["error_message"] = rid06FailedUnitCell("failed precondition")
		} else {
			response, _ := anypb.New(&iamv1.GrantDelegation{Id: resource, AccountId: account, Delegate: &iamv1.Subject{Id: e.DelegateID}})
			row["response_type"] = rid06FailedUnitCell(response.TypeUrl)
			row["response_data"] = rid06FailedUnitCell("\\x" + hex.EncodeToString(response.Value))
			gd := rid09PrimaryRow{"id": rid06FailedUnitCell(resource), "account_id": rid06FailedUnitCell(account), "delegate_id": rid06FailedUnitCell(e.DelegateID), "status": rid06FailedUnitCell("ACTIVE")}
			a.Raw["grant_delegations"] = append(a.Raw["grant_delegations"], gd)
			b.Raw["grant_delegations"] = append(b.Raw["grant_delegations"], gd)
		}
		ops = append(ops, row)
	}
	rid06FailedUnitBind(&a, "operations", []rid09PrimaryRow{oldOp})
	rid06FailedUnitBind(&b, "operations", ops)
	logs := rid06FailedStartupLogs{ProcessDir: "serve-003/process", BinarySHA256: strings.Repeat("e", 64), StdoutSHA256: strings.Repeat("f", 64), StderrSHA256: strings.Repeat("0", 64), AcceptedAt: at.Add(time.Second), Event: installationAssertionInput{ClientSHA256: e.ClientSHA256, AssertionSHA256: installationIdentitySHA("private-unit-assertion"), IssuedAt: at, ExpiresAt: at.Add(time.Minute)}}
	return e, logs, a, b
}

// Каждая отрицательная проба меняет один факт законного полного запуска.
func TestRID06FailedStartupProof(t *testing.T) {
	for _, name := range []string{"lawful-S1", "lawful-S2", "lawful-key-expiry", "wrong-client", "wrong-assertion", "wrong-run", "wrong-case", "wrong-executable", "extra-replay", "deleted-replay", "modified-old-replay", "duplicate-old-replay", "raw-replay-sha", "replay-columns", "expiry", "redemption-before", "redemption-after", "issued-before", "reversed-clocks", "zero-clock", "zero-issued", "zero-event-time", "event-before", "event-after", "zero-replay-expiry", "zero-redemption", "noncanonical-time", "other-bookkeeping", "audit-mutation", "domain-mutation", "business-mutation", "operation-deletion", "old-operation-mutation", "duplicate-old-operation", "operation-wrong-creator", "operation-wrong-code", "operation-response-on-failure", "operation-metadata", "raw-operation-sha", "raw-operation-mismatch", "ceiling-semantic", "ceiling-clock", "separation", "missing-bookkeeping"} {
		t.Run(name, func(t *testing.T) {
			mode := "S1"
			if name == "lawful-S2" {
				mode = "S2"
			}
			e, logs, a, b := rid06FailedUnitFixture(mode)
			caseID, runID, executable := e.CaseID, e.RunID, e.TestExecutableSHA256
			replay := func() []rid09PrimaryRow {
				out := []rid09PrimaryRow{}
				for _, raw := range b.Whole.replaySQLRows {
					var row rid09PrimaryRow
					require.NoError(t, json.Unmarshal(raw, &row))
					out = append(out, row)
				}
				return out
			}
			switch name {
			case "lawful-key-expiry":
				e.CredentialExpiresAt = logs.Event.IssuedAt.Add(30 * time.Second)
				logs.Event.ExpiresAt = e.CredentialExpiresAt
				rows := replay()
				rows[1]["expires_at"] = rid06FailedUnitCell(e.CredentialExpiresAt)
				rid06FailedUnitBind(&b, "client_assertion_replay", rows)
			case "wrong-client":
				logs.Event.ClientSHA256 = installationIdentitySHA("foreign-client")
			case "wrong-assertion":
				logs.Event.AssertionSHA256 = installationIdentitySHA("foreign-assertion")
			case "wrong-run":
				e.RunID = "foreign-valid-owned-run-20261104"
			case "wrong-case":
				e.CaseID = "registry-installation-rid06-S2-SEQUENTIAL-FAILED-STARTUP"
			case "wrong-executable":
				e.TestExecutableSHA256 = strings.Repeat("9", 64)
			case "extra-replay", "deleted-replay", "modified-old-replay", "duplicate-old-replay", "expiry", "redemption-before", "redemption-after", "zero-replay-expiry", "zero-redemption", "noncanonical-time":
				rows := replay()
				switch name {
				case "extra-replay":
					extra := rid09PrimaryRow{}
					for k, v := range rows[1] {
						extra[k] = v
					}
					extra["assertion_id"] = rid06FailedUnitCell("extra")
					rows = append(rows, extra)
				case "deleted-replay":
					rows = rows[1:]
				case "modified-old-replay":
					rows[0]["expires_at"] = rid06FailedUnitCell(logs.Event.ExpiresAt.Add(time.Second))
				case "duplicate-old-replay":
					rows = append(rows, rows[0])
				case "expiry":
					rows[1]["expires_at"] = rid06FailedUnitCell(logs.Event.ExpiresAt.Add(time.Second))
				case "redemption-before":
					rows[1]["redeemed_at"] = rid06FailedUnitCell(a.Whole.PrimaryFinishedAt.Add(-time.Nanosecond))
				case "redemption-after":
					rows[1]["redeemed_at"] = rid06FailedUnitCell(b.Whole.PrimaryStartedAt.Add(time.Nanosecond))
				case "zero-replay-expiry":
					rows[1]["expires_at"] = rid06FailedUnitCell(time.Time{})
				case "zero-redemption":
					rows[1]["redeemed_at"] = rid06FailedUnitCell(time.Time{})
				case "noncanonical-time":
					rows[1]["redeemed_at"] = rid06FailedUnitCell("2026-11-04 10:00:01Z")
				}
				rid06FailedUnitBind(&b, "client_assertion_replay", rows)
			case "raw-replay-sha":
				b.Whole.Bookkeeping["client_assertion_replay"].Rows[0] = strings.Repeat("9", 64)
			case "replay-columns":
				b.Whole.Bookkeeping["client_assertion_replay"].Columns[0] = "unknown"
			case "issued-before":
				logs.Event.IssuedAt = a.Whole.PrimaryFinishedAt.Add(-time.Minute)
			case "reversed-clocks":
				b.Whole.PrimaryStartedAt = a.Whole.PrimaryFinishedAt.Add(-time.Second)
			case "zero-clock":
				a.Whole.PrimaryStartedAt = time.Time{}
			case "zero-issued":
				logs.Event.IssuedAt = time.Time{}
			case "zero-event-time":
				logs.AcceptedAt = time.Time{}
			case "event-before":
				logs.AcceptedAt = a.Whole.PrimaryFinishedAt.Add(-time.Nanosecond)
			case "event-after":
				logs.AcceptedAt = b.Whole.PrimaryStartedAt.Add(time.Nanosecond)
			case "other-bookkeeping":
				b.Whole.Bookkeeping["access_tokens"] = ridWholeTable{Columns: []string{"id"}, Rows: []string{strings.Repeat("9", 64)}}
			case "audit-mutation":
				b.Whole.Bookkeeping["audit_outbox"] = ridWholeTable{Columns: []string{"id"}, Rows: []string{strings.Repeat("9", 64)}}
			case "domain-mutation":
				b.Whole.Delivery["domain"] = ridWholeTable{Columns: []string{"id"}, Rows: []string{strings.Repeat("9", 64)}}
			case "business-mutation":
				b.BusinessAudit = append(b.BusinessAudit, rid09PrimaryRow{"event": rid06FailedUnitCell("extra")})
			case "operation-deletion", "old-operation-mutation", "duplicate-old-operation", "operation-wrong-creator", "operation-wrong-code", "operation-response-on-failure", "operation-metadata":
				rows := b.Raw["operations"]
				switch name {
				case "operation-deletion":
					rows = rows[:1]
				case "old-operation-mutation":
					rows[0]["description"] = rid06FailedUnitCell("changed")
				case "duplicate-old-operation":
					rows = append(rows, rows[0])
				case "operation-wrong-creator":
					rows[1]["principal_id"] = rid06FailedUnitCell("foreign")
				case "operation-wrong-code":
					rows[1]["error_code"] = rid06FailedUnitCell(13)
				case "operation-response-on-failure":
					rows[1]["response_type"] = rid06FailedUnitCell("foreign")
				case "operation-metadata":
					rows[1]["metadata_data"] = rid06FailedUnitCell("\\x00")
				}
				rid06FailedUnitBind(&b, "operations", rows)
			case "raw-operation-sha":
				b.Whole.Bookkeeping["operations"].Rows[0] = strings.Repeat("9", 64)
			case "raw-operation-mismatch":
				b.Raw["operations"] = b.Raw["operations"][:1]
			case "ceiling-semantic":
				b.Whole.OwnCeilings.Semantic["kind"] = strings.Repeat("9", 64)
			case "ceiling-clock":
				b.Whole.OwnCeilings.StatedAt["kind"] = b.Whole.PrimaryStartedAt.Add(time.Second)
			case "separation":
				b.Whole.Separation["audit_outbox"] = "foreign"
			case "missing-bookkeeping":
				delete(b.Whole.Bookkeeping, "refresh_tokens")
			}
			proof, ok := rid06BuildFailedStartup(caseID, runID, executable, e, logs, a, b)
			want := strings.HasPrefix(name, "lawful-")
			require.Equal(t, want, ok)
			if !want {
				require.Empty(t, proof)
				return
			}
			raw, err := json.Marshal(proof)
			require.NoError(t, err)
			for _, secret := range []string{"private-unit-client", "private-unit-assertion", "old-assertion", "privateKeyPem", "accessToken", "replaySQLRows", "operationSQLRows"} {
				require.NotContains(t, string(raw), secret)
			}
			require.Len(t, proof.Operations, len(e.Accounts))
		})
	}
}

func TestInstallationAcceptedAssertionObservation(t *testing.T) {
	for _, name := range []string{"success", "disabled", "nil-logger", "failed-verify", "failed-issue", "wrong-client", "wrong-assertion", "wrong-expiry"} {
		t.Run(name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			var output bytes.Buffer
			level := slog.LevelDebug
			if name == "disabled" {
				level = slog.LevelInfo
			}
			a := &installationAuthentication{key: key, credential: installationCredential{ClientID: "secret-client", KeyID: "secret-key", PrivateKeyPEM: "secret-pem"}, assertionAudience: "https://kaname.local", logger: slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: level}))}
			raw, input, err := a.freshAssertionInput(domain.AssertionClient{ID: a.credential.ClientID})
			require.NoError(t, err)
			var claims jwt.RegisteredClaims
			_, err = jwt.ParseWithClaims(raw, &claims, func(*jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithValidMethods([]string{"ES256"}))
			require.NoError(t, err)
			require.Equal(t, installationIdentitySHA(claims.ID), input.AssertionSHA256)
			require.True(t, claims.IssuedAt.Time.Equal(input.IssuedAt))
			require.True(t, claims.ExpiresAt.Time.Equal(input.ExpiresAt))
			result := clientassertion.Result{Outcome: clientassertion.OutcomeAccepted, Client: domain.AssertionClient{ID: claims.Issuer}, AssertionID: claims.ID, ExpiresAt: claims.ExpiresAt.Time}
			issued := true
			switch name {
			case "nil-logger":
				a.logger = nil
			case "failed-verify":
				result.Outcome = clientassertion.OutcomeReplayed
			case "failed-issue":
				issued = false
			case "wrong-client":
				input.ClientSHA256 = installationIdentitySHA("foreign")
			case "wrong-assertion":
				input.AssertionSHA256 = installationIdentitySHA("foreign")
			case "wrong-expiry":
				input.ExpiresAt = input.ExpiresAt.Add(time.Second)
			}
			a.observeAcceptedAssertion(context.Background(), input, result, issued)
			if name != "success" {
				require.Empty(t, output.String())
				return
			}
			event, _, ok := rid06FailedLogEvent(output.Bytes(), nil)
			require.True(t, ok)
			require.Equal(t, input, event)
			for _, secret := range []string{raw, claims.ID, "secret-client", "secret-key", "secret-pem"} {
				require.NotContains(t, output.String(), secret)
			}
			_, _, ok = rid06FailedLogEvent(append(append([]byte{}, output.Bytes()...), output.Bytes()...), nil)
			require.False(t, ok)
		})
	}
}

// Разное представление зоны не меняет instant и не подавляет законное наблюдение.
func TestRID06ObservationInstantEquality(t *testing.T) {
	for _, name := range []string{"same-instant-different-location", "different-instant"} {
		t.Run(name, func(t *testing.T) {
			_, logs, _, _ := rid06FailedUnitFixture("S1")
			input := logs.Event
			other := input.ExpiresAt.In(time.FixedZone("unit-offset", 3*60*60))
			want := name == "same-instant-different-location"
			if !want {
				other = other.Add(time.Second)
			}
			require.Equal(t, want, input.ExpiresAt.Equal(other))
			require.NotSame(t, input.ExpiresAt.Location(), other.Location())
			var output bytes.Buffer
			a := &installationAuthentication{logger: slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))}
			verified := clientassertion.Result{Outcome: clientassertion.OutcomeAccepted, Client: domain.AssertionClient{ID: "private-unit-client"}, AssertionID: "private-unit-assertion", ExpiresAt: other}
			a.observeAcceptedAssertion(context.Background(), input, verified, true)
			if want {
				_, _, ok := rid06FailedLogEvent(output.Bytes(), nil)
				require.True(t, ok)
			} else {
				require.Empty(t, output.String())
			}
		})
	}
}

type rid06ClientDiagnosticCapture struct {
	output  bytes.Buffer
	refused bool
}

func (c *rid06ClientDiagnosticCapture) Errorf(format string, args ...any) {
	_, _ = fmt.Fprintf(&c.output, format, args...)
}
func (c *rid06ClientDiagnosticCapture) FailNow() { c.refused = true }

// Настоящая проверка до запуска вызывается с перехватом её диагностики.
func TestRID06CredentialMismatchRedaction(t *testing.T) {
	for _, name := range []string{"matching-client", "mismatched-client"} {
		t.Run(name, func(t *testing.T) {
			expected, actual := "expected-sensitive-client-sentinel", "expected-sensitive-client-sentinel"
			if name == "mismatched-client" {
				actual = "actual-sensitive-client-sentinel"
			}
			capture := &rid06ClientDiagnosticCapture{}
			rid06RequireExpectedClient(capture, expected, actual)
			require.Equal(t, name == "mismatched-client", capture.refused)
			for _, sentinel := range []string{expected, actual} {
				require.NotContains(t, capture.output.String(), sentinel)
			}
			if capture.refused {
				require.Contains(t, capture.output.String(), "installation credential identity mismatch (redacted)")
			} else {
				require.Empty(t, capture.output.String())
			}
		})
	}
}
