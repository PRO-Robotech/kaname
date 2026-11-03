// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"github.com/golang-jwt/jwt/v5"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRID11LiteralOwnership(t *testing.T) {
	seen := map[string]bool{}
	worlds, tokens, intermediate := 0, 0, 0
	for _, twin := range []bool{false, true} {
		for _, c := range rid11Cases(twin) {
			worlds++
			for _, stage := range rid11OwnedStages(c) {
				id := rid11PublicCaseID(c, stage)
				r, ok := rid11PublicRules[id]
				require.True(t, ok && !seen[id])
				seen[id] = true
				require.Equal(t, c.Mode, r.Mode)
				require.Equal(t, c.Variant, r.Variant)
				require.Equal(t, c.Active, r.Active)
				require.Equal(t, c.Twin, r.Twin)
				require.Equal(t, stage, r.Stage)
				if r.Token401 {
					tokens++
				}
				if stage == "KEY-REVOKED-C-LIVE" {
					intermediate++
					require.True(t, !r.CreatorAbsent && r.EmptyKeyList && !r.Token401)
				}
			}
		}
	}
	require.Equal(t, 62, worlds)
	require.Equal(t, 128, len(seen))
	require.Equal(t, 128, len(rid11PublicRules))
	require.Equal(t, 12, tokens)
	require.Equal(t, 4, intermediate)
}
func TestRID11ClosedSecretLiterals(t *testing.T) {
	ids := []string{}
	for id := range rid11PublicRules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			r := rid11PublicRules[id]
			v := map[string]any{"jwtRIDOperator": "O"}
			want := []string{"O"}
			if r.Token401 {
				v["rid11ClientAssertion"] = "A"
				v["rid11IssuanceOrigin"] = "https://localhost:9096"
				want = append(want, "A")
			}
			got, err := ridNewmanClientSecrets("registry-installation-rid11", id, v)
			require.NoError(t, err)
			require.Equal(t, want, got)
			policy, err := ridNewmanParentRequestPolicy(id, "https://localhost:9098", "https://localhost:9096", v)
			require.NoError(t, err)
			require.Equal(t, r.Token401, policy != nil)
		})
	}
}
func TestRID11SecretReject(t *testing.T) {
	for _, name := range []string{"unknown-phase", "missing-O", "empty-O", "type-O", "missing-A", "empty-A", "type-A", "oversize-A", "READ-A", "TWIN-A", "creator", "issuer", "other-proof", "wrong-origin-var"} {
		t.Run(name, func(t *testing.T) {
			id := "registry-installation-rid11-BAD-SIGNATURE-S1-ABSENT-NEGATIVE-AFTER"
			v := map[string]any{"jwtRIDOperator": "O", "rid11ClientAssertion": "A"}
			switch name {
			case "unknown-phase":
				id += "-OTHER"
			case "missing-O":
				delete(v, "jwtRIDOperator")
			case "empty-O":
				v["jwtRIDOperator"] = ""
			case "type-O":
				v["jwtRIDOperator"] = 1
			case "missing-A":
				delete(v, "rid11ClientAssertion")
			case "empty-A":
				v["rid11ClientAssertion"] = ""
			case "type-A":
				v["rid11ClientAssertion"] = 1
			case "oversize-A":
				v["rid11ClientAssertion"] = strings.Repeat("A", 16385)
			case "READ-A":
				id = strings.TrimSuffix(id, "AFTER") + "BEFORE"
			case "TWIN-A":
				id = strings.Replace(id, "NEGATIVE", "TWIN", 1)
			case "creator":
				v["jwtRIDCreator"] = "C"
			case "issuer":
				v["jwtRIDIssuer"] = "I"
			case "other-proof":
				v["rid05ClientAssertion"] = "A"
			case "wrong-origin-var":
				v["rid01IssuanceOrigin"] = "https://localhost:9096"
			}
			_, err := ridNewmanClientSecrets("registry-installation-rid11", id, v)
			require.Error(t, err)
		})
	}
}
func TestRID11OriginReject(t *testing.T) {
	for _, name := range []string{"wrong-phase", "wrong-leaf", "wrong-method", "wrong-path", "wrong-port", "different-host", "remote", "credentials", "query", "fragment", "dynamic-token-port", "public-fallback"} {
		t.Run(name, func(t *testing.T) {
			id := "registry-installation-rid11-REVOKED-KEY-S2-ACTIVE-NEGATIVE-AFTER"
			public := "https://localhost:9098"
			v := map[string]any{"rid11IssuanceOrigin": "https://localhost:9096"}
			p := &ridNewmanRequestPolicy{CaseID: id, RequestName: id + " :: input-standing-key-token-refusal", Method: "POST", Path: "/iam/v1/token", Origin: "https://localhost:9096"}
			switch name {
			case "wrong-phase":
				id = strings.TrimSuffix(id, "AFTER") + "BEFORE"
			case "wrong-leaf":
				p.RequestName += "-other"
			case "wrong-method":
				p.Method = "GET"
			case "wrong-path":
				p.Path = "/iam/v1/token/"
			case "wrong-port":
				p.Origin = "https://localhost:9196"
			case "different-host":
				p.Origin = "https://127.0.0.1:9096"
			case "remote":
				p.Origin = "https://remote.invalid:9096"
			case "credentials":
				p.Origin = "https://user@localhost:9096"
			case "query":
				p.Origin += "?x=1"
			case "fragment":
				p.Origin += "#x"
			case "dynamic-token-port":
				public = "https://localhost:23456"
			case "public-fallback":
				p.Origin = public
			}
			require.Error(t, ridNewmanValidateRequestPolicy(id, public, p, v))
		})
	}
}
func TestRID11ObserverCompleteCapture(t *testing.T) {
	var inventory bytes.Buffer
	called := false
	err := rid11RecordThenObserve(func() error { return ridNewmanRecordBearers(&inventory, []string{"unit-O", "unit-assertion"}) }, func() error {
		called = true
		dec := json.NewDecoder(&inventory)
		for _, want := range []string{"unit-O", "unit-assertion"} {
			var pair []string
			if dec.Decode(&pair) != nil || !reflect.DeepEqual(pair, []string{"", want}) {
				return errors.New("incomplete capture")
			}
		}
		return nil
	})
	require.NoError(t, err)
	require.True(t, called)
}
func TestRID11ObserverFailures(t *testing.T) {
	for _, name := range []string{"capture-error", "snapshot-error", "missing-capture", "missing-observer"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			record := func() error { return nil }
			observe := func() error { calls++; return nil }
			switch name {
			case "capture-error":
				record = func() error { return errors.New("private-value-not-returned") }
			case "snapshot-error":
				observe = func() error { calls++; return errors.New("private-value-not-returned") }
			case "missing-capture":
				record = nil
			case "missing-observer":
				observe = nil
			}
			err := rid11RecordThenObserve(record, observe)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "private-value")
			if name != "snapshot-error" {
				require.Zero(t, calls)
			}
		})
	}
}
func TestRID11ObserverBridgeOrdering(t *testing.T) {
	raw, err := os.ReadFile("installation_newman_bridge_test.go")
	require.NoError(t, err)
	s := string(raw)
	pos := []int{strings.Index(s, "f.renewOperator(t, f.given.ctx)"), strings.Index(s, "rid11RecordThenObserve(func() error"), strings.Index(s, "keyBytes, err := os.ReadFile(in.Key)"), strings.Index(s, "admitted = true"), strings.Index(s, "c.release(t, string(payload))")}
	for i, n := range pos {
		require.GreaterOrEqual(t, n, 0)
		if i > 0 {
			require.Greater(t, n, pos[i-1])
		}
	}
	require.Contains(t, s, "return ridRunNewmanPhaseModeObserved(t, f, stem, caseID, label, variables, probe, budget, nil)")
	require.Contains(t, s, "if observer == nil {\n\t\trequire.NoError(t, ridNewmanRecordBearers(c.secretInventory, bearers))")
	require.Contains(t, s, "rid11TokenCase(caseID) && observer != nil")
}
func rid11UnitAuthn() rid11AuthnSnapshot {
	at := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	s := rid11AuthnSnapshot{Started: at, Finished: at.Add(time.Second), Raw: map[string][]rid09PrimaryRow{}, Columns: map[string][]string{}, Counts: map[string]int{}, SHA256: map[string]string{}}
	for table, cols := range rid11AuthnColumns {
		s.Raw[table] = []rid09PrimaryRow{}
		s.Columns[table] = strings.Fields(cols)
		s.Counts[table] = 0
		s.SHA256[table] = rid03EvidenceHash(s.Raw[table])
	}
	return s
}
func TestRID11AuthnProtectedBaseline(t *testing.T) {
	for _, name := range []string{"exact", "missing-table", "unknown-table", "unknown-column", "missing-column", "duplicate-column", "missing-clock", "reverse-clock", "overlap", "new-replay", "new-access-token", "new-audit", "changed-old-audit", "counter-forged", "hash-forged", "nil-raw"} {
		t.Run(name, func(t *testing.T) {
			a, b := rid11UnitAuthn(), rid11UnitAuthn()
			b.Started = a.Finished.Add(time.Second)
			b.Finished = b.Started.Add(time.Second)
			switch name {
			case "missing-table":
				delete(b.Raw, "audit_outbox")
			case "unknown-table":
				b.Raw["future"] = []rid09PrimaryRow{}
			case "unknown-column":
				b.Columns["audit_outbox"] = append(b.Columns["audit_outbox"], "future")
			case "missing-column":
				b.Columns["audit_outbox"] = b.Columns["audit_outbox"][1:]
			case "duplicate-column":
				b.Columns["audit_outbox"] = append(b.Columns["audit_outbox"], "id")
			case "missing-clock":
				b.Started = time.Time{}
			case "reverse-clock":
				b.Finished = b.Started.Add(-time.Second)
			case "overlap":
				b.Started = a.Started
			case "new-replay", "new-access-token", "new-audit", "changed-old-audit":
				table := map[string]string{"new-replay": "client_assertion_replay", "new-access-token": "access_tokens", "new-audit": "audit_outbox", "changed-old-audit": "audit_outbox"}[name]
				row := rid09PrimaryRow{}
				for _, key := range strings.Fields(rid11AuthnColumns[table]) {
					row[key] = json.RawMessage("null")
				}
				b.Raw[table] = []rid09PrimaryRow{row}
				b.Counts[table] = 1
				b.SHA256[table] = rid03EvidenceHash(b.Raw[table])
				if name == "changed-old-audit" {
					old := rid09PrimaryRow{}
					for k, v := range row {
						old[k] = v
					}
					old["status"] = json.RawMessage(`"pending"`)
					a.Raw[table] = []rid09PrimaryRow{old}
					a.Counts[table] = 1
					a.SHA256[table] = rid03EvidenceHash(a.Raw[table])
				}
			case "counter-forged":
				b.Counts["audit_outbox"] = 1
			case "hash-forged":
				b.SHA256["audit_outbox"] = "forged"
			case "nil-raw":
				b.Raw["audit_outbox"] = nil
			}
			require.Equal(t, name == "exact", rid11AuthnUnchanged(a, b))
		})
	}
}
func TestRID11AuthnReceiptNoRaw(t *testing.T) {
	s := rid11UnitAuthn()
	s.Raw["audit_outbox"] = []rid09PrimaryRow{{"event_payload": json.RawMessage(`"unit-protected-value"`)}}
	data, err := json.Marshal(s)
	require.NoError(t, err)
	require.NotContains(t, string(data), "unit-protected-value")
	require.NotContains(t, string(data), "event_payload\":")
}
func TestRID11IndependentIssuer(t *testing.T) {
	for _, name := range []string{"present", "absent", "wrong-account", "creator", "stock", "disabled", "duplicate", "wrong-name"} {
		t.Run(name, func(t *testing.T) {
			sa := map[string]any{"id": "I", "accountId": "SYS", "name": "rid-public-issuer", "enabled": true}
			rows := []map[string]any{sa}
			wantOK, wantPresent := true, true
			switch name {
			case "absent":
				rows = nil
				wantPresent = false
			case "wrong-account":
				sa["accountId"] = "TENANT"
				wantPresent = false
			case "creator":
				sa["id"] = "C"
				wantOK = false
			case "stock":
				sa["id"] = "BOOT"
				wantOK = false
			case "disabled":
				sa["enabled"] = false
				wantOK = false
			case "duplicate":
				rows = append(rows, sa)
				wantOK = false
			case "wrong-name":
				sa["name"] = "stock-writer"
				wantPresent = false
			}
			found, ok := rid11NamedIssuer(rid09NewmanProjection{ServiceAccounts: rows}, "SYS", "C", []string{"BOOT"})
			require.Equal(t, wantOK, ok)
			if ok {
				require.Equal(t, wantPresent, found != nil)
			}
		})
	}
}

func rid11UnitAuditRow() rid09PrimaryRow {
	at := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	raw, _ := json.Marshal(map[string]any{"id": "evt-unit", "event_type": "iam.sa_key.revoked", "tenant_account_id": "SYS", "event_payload": map[string]any{"key_id": "unit-key"}, "created_at": at, "status": "pending", "attempts": 0, "next_attempt_at": at, "sent_at": nil, "last_error": nil})
	var row rid09PrimaryRow
	_ = json.Unmarshal(raw, &row)
	return row
}
func rid11UnitSet(row rid09PrimaryRow, key string, value any) {
	raw, _ := json.Marshal(value)
	row[key] = raw
}
func TestRID11AuditTransport(t *testing.T) {
	for _, name := range []string{"unchanged-pending", "sent-after-claim", "pre-baseline-tx-sent", "terminal-sent-unchanged", "claim-only-stuck", "claim-only-old-next-future", "claim-only-due-at-upper", "deferred", "defer-clock-before-old-next", "pre-baseline-tx-deferred", "multiple-retries-deferred", "multiple-retries-sent", "id-changed", "event-changed", "tenant-changed", "payload-changed", "created-changed", "unknown-column", "missing-column", "status-regression", "attempts-regression", "equal-attempt-status-change", "sent-missing-clock", "sent-future", "sent-before-created", "sent-error", "sent-wrong-next-single-attempt", "next-regression", "defer-no-error", "defer-control-error", "defer-too-long-error", "defer-forged-clock", "defer-zero-clock", "attempts-fractional", "payload-array", "sent-mutated-attempts"} {
		t.Run(name, func(t *testing.T) {
			a, b := rid11UnitAuditRow(), rid11UnitAuditRow()
			at, _ := rid03Cell[time.Time](a, "created_at")
			lower, upper := at.Add(10*time.Second), at.Add(30*time.Second)
			want := false
			sent := func(attempts int, clock time.Time) {
				rid11UnitSet(b, "attempts", attempts)
				rid11UnitSet(b, "status", "sent")
				rid11UnitSet(b, "sent_at", clock)
			}
			deferRow := func(attempts int, next time.Time) {
				rid11UnitSet(b, "attempts", attempts)
				rid11UnitSet(b, "next_attempt_at", next)
				rid11UnitSet(b, "last_error", "safe unit diagnostic")
			}
			switch name {
			case "unchanged-pending":
				want = true
			case "sent-after-claim":
				sent(1, at.Add(20*time.Second))
				want = true
			case "pre-baseline-tx-sent":
				sent(1, at.Add(5*time.Second))
				want = true
			case "terminal-sent-unchanged":
				sent(1, at.Add(5*time.Second))
				a = rid11UnitAuditRow()
				for k, v := range b {
					a[k] = append(json.RawMessage{}, v...)
				}
				want = true
			case "claim-only-stuck":
				rid11UnitSet(b, "attempts", 1)
				want = true
			case "claim-only-old-next-future":
				rid11UnitSet(a, "next_attempt_at", upper.Add(time.Second))
				rid11UnitSet(b, "next_attempt_at", upper.Add(time.Second))
				rid11UnitSet(b, "attempts", 1)
			case "claim-only-due-at-upper":
				rid11UnitSet(a, "next_attempt_at", upper)
				rid11UnitSet(b, "next_attempt_at", upper)
				rid11UnitSet(b, "attempts", 1)
				want = true
			case "defer-clock-before-old-next":
				rid11UnitSet(a, "next_attempt_at", at.Add(20*time.Second))
				deferRow(1, at.Add(20500*time.Millisecond))
			case "pre-baseline-tx-deferred":
				rid11UnitSet(a, "next_attempt_at", at.Add(2*time.Second))
				deferRow(1, at.Add(6*time.Second))
				want = true
			case "deferred":
				deferRow(1, at.Add(21*time.Second))
				want = true
			case "multiple-retries-deferred":
				deferRow(10, at.Add(320*time.Second))
				want = true
			case "multiple-retries-sent":
				sent(3, at.Add(20*time.Second))
				rid11UnitSet(b, "next_attempt_at", at.Add(15*time.Second))
				want = true
			case "id-changed":
				rid11UnitSet(b, "id", "other")
			case "event-changed":
				rid11UnitSet(b, "event_type", "iam.sa_key.issued")
			case "tenant-changed":
				rid11UnitSet(b, "tenant_account_id", "OTHER")
			case "payload-changed":
				rid11UnitSet(b, "event_payload", map[string]any{"key_id": "other"})
			case "created-changed":
				rid11UnitSet(b, "created_at", at.Add(time.Second))
			case "unknown-column":
				rid11UnitSet(b, "future", true)
			case "missing-column":
				delete(b, "last_error")
			case "status-regression":
				sent(1, at.Add(5*time.Second))
				a = b
				b = rid11UnitAuditRow()
				rid11UnitSet(b, "attempts", 2)
			case "attempts-regression":
				rid11UnitSet(a, "attempts", 2)
				rid11UnitSet(b, "attempts", 1)
			case "equal-attempt-status-change":
				sent(1, at.Add(20*time.Second))
				rid11UnitSet(a, "attempts", 1)
			case "sent-missing-clock":
				sent(1, at.Add(20*time.Second))
				rid11UnitSet(b, "sent_at", nil)
			case "sent-future":
				sent(1, upper.Add(time.Nanosecond))
			case "sent-before-created":
				sent(1, at.Add(-time.Second))
			case "sent-error":
				sent(1, at.Add(20*time.Second))
				rid11UnitSet(b, "last_error", "should have cleared")
			case "sent-wrong-next-single-attempt":
				sent(1, at.Add(20*time.Second))
				rid11UnitSet(b, "next_attempt_at", at.Add(time.Second))
			case "next-regression":
				deferRow(1, at.Add(-time.Second))
			case "defer-no-error":
				deferRow(1, at.Add(21*time.Second))
				rid11UnitSet(b, "last_error", nil)
			case "defer-control-error":
				deferRow(1, at.Add(21*time.Second))
				rid11UnitSet(b, "last_error", "bad\x01cause")
			case "defer-too-long-error":
				deferRow(1, at.Add(21*time.Second))
				rid11UnitSet(b, "last_error", strings.Repeat("é", 1000))
			case "defer-forged-clock":
				deferRow(1, upper.Add(2*time.Second))
			case "defer-zero-clock":
				deferRow(1, time.Time{})
			case "attempts-fractional":
				rid11UnitSet(b, "attempts", 1.5)
			case "payload-array":
				rid11UnitSet(b, "event_payload", []string{})
			case "sent-mutated-attempts":
				sent(1, at.Add(5*time.Second))
				a = rid11UnitAuditRow()
				for k, v := range b {
					a[k] = v
				}
				rid11UnitSet(b, "attempts", 2)
			}
			require.Equal(t, want, rid11AuditTransition(a, b, lower, upper))
		})
	}
}
func TestRID11AuditIdentitySet(t *testing.T) {
	for _, name := range []string{"same", "append", "remove", "duplicate", "wrong-ID"} {
		t.Run(name, func(t *testing.T) {
			a, b := rid11UnitAuthn(), rid11UnitAuthn()
			a.Raw["audit_outbox"] = []rid09PrimaryRow{rid11UnitAuditRow()}
			b.Raw["audit_outbox"] = []rid09PrimaryRow{rid11UnitAuditRow()}
			switch name {
			case "append":
				r := rid11UnitAuditRow()
				rid11UnitSet(r, "id", "new-id")
				b.Raw["audit_outbox"] = append(b.Raw["audit_outbox"], r)
			case "remove":
				b.Raw["audit_outbox"] = []rid09PrimaryRow{}
			case "duplicate":
				b.Raw["audit_outbox"] = append(b.Raw["audit_outbox"], rid11UnitAuditRow())
			case "wrong-ID":
				rid11UnitSet(b.Raw["audit_outbox"][0], "id", "other")
			}
			require.Equal(t, name == "same", rid11AuditHistoryValid(a, b))
		})
	}
}
func TestRID11AuditSanitizedBytes(t *testing.T) {
	for _, name := range []string{"empty", "tabs-newlines", "multibyte-below-cap", "truncated-ascii", "truncated-multibyte", "control", "nul", "invalid-UTF8", "oversize"} {
		t.Run(name, func(t *testing.T) {
			s := ""
			want := true
			switch name {
			case "tabs-newlines":
				s = "safe\n\ttext"
			case "multibyte-below-cap":
				s = strings.Repeat("é", 499)
			case "truncated-ascii":
				s = strings.Repeat("x", 1000) + "…"
			case "truncated-multibyte":
				s = strings.Repeat("x", 999) + "😀…"
			case "control":
				s = "bad\x01"
				want = false
			case "nul":
				s = "bad\x00"
				want = false
			case "invalid-UTF8":
				s = string([]byte{0xff})
				want = false
			case "oversize":
				s = strings.Repeat("x", 1007)
				want = false
			}
			require.Equal(t, want, rid11SanitizedCause(&s))
		})
	}
}

func TestRID11SameInputSigningKey(t *testing.T) {
	for _, name := range []string{"same-key", "faulted-native-key"} {
		t.Run(name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			wrong, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			supplied := key
			if name == "faulted-native-key" {
				supplied = wrong
			}
			der, err := x509.MarshalECPrivateKey(supplied)
			require.NoError(t, err)
			input := installationCredential{ClientID: "native-input-C-client", KeyID: "native-input-C-kid", PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))}
			raw, err := json.Marshal(input)
			require.NoError(t, err)
			path := filepath.Join(t.TempDir(), "protected-input.json")
			require.NoError(t, os.WriteFile(path, raw, 0600))
			f := &installationNativeWorld{}
			proof, expiry := rid11FreshInputAssertion(t, f, path)
			require.Len(t, f.secrets, 1)
			require.True(t, f.secrets[0] == proof)
			token, err := jwt.ParseWithClaims(proof, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
				if token.Method != jwt.SigningMethodES256 {
					return nil, errors.New("unexpected algorithm")
				}
				return &supplied.PublicKey, nil
			})
			require.NoError(t, err)
			claims, ok := token.Claims.(*jwt.RegisteredClaims)
			require.True(t, ok && token.Valid)
			require.Equal(t, input.ClientID, claims.Issuer)
			require.Equal(t, input.ClientID, claims.Subject)
			require.Equal(t, input.KeyID, token.Header["kid"])
			require.Equal(t, tokenpolicy.TokenTypeClientAssertion, token.Header["typ"])
			require.Equal(t, jwt.ClaimStrings{"https://kaname.local"}, claims.Audience)
			require.True(t, claims.ExpiresAt.Time.Equal(expiry))
			require.Equal(t, 60*time.Second, claims.ExpiresAt.Sub(claims.IssuedAt.Time))
			if name == "faulted-native-key" {
				_, err := jwt.Parse(proof, func(*jwt.Token) (any, error) { return &key.PublicKey, nil })
				require.Error(t, err, "mutated native key must not fall back to the valid registered seed key")
			}
		})
	}
}

func TestRID11AuthnLawfulTransportReceipt(t *testing.T) {
	a, b := rid11UnitAuthn(), rid11UnitAuthn()
	b.Started = a.Finished.Add(time.Second)
	b.Finished = b.Started.Add(time.Second)
	old, now := rid11UnitAuditRow(), rid11UnitAuditRow()
	rid11UnitSet(now, "status", "sent")
	rid11UnitSet(now, "attempts", 1)
	rid11UnitSet(now, "sent_at", a.Started.Add(500*time.Millisecond))
	a.Raw["audit_outbox"] = []rid09PrimaryRow{old}
	b.Raw["audit_outbox"] = []rid09PrimaryRow{now}
	for _, s := range []*rid11AuthnSnapshot{&a, &b} {
		s.Counts["audit_outbox"] = 1
		s.SHA256["audit_outbox"] = rid03EvidenceHash(s.Raw["audit_outbox"])
	}
	require.True(t, rid11AuthnUnchanged(a, b))
	ai, at := rid11AuditParts(a.Raw["audit_outbox"])
	bi, bt := rid11AuditParts(b.Raw["audit_outbox"])
	require.Equal(t, ai, bi)
	require.NotEqual(t, at, bt)
}

func TestRID11NativeInstallerAudit(t *testing.T) {
	for _, name := range []string{"exact-native-create", "idempotent-zero", "missing-event", "duplicate-event", "wrong-event", "wrong-actor", "wrong-tenant", "wrong-GD", "wrong-I", "wrong-role", "unknown-payload", "unknown-column", "future-event", "old-history-lost"} {
		t.Run(name, func(t *testing.T) {
			at := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
			payload := map[string]any{"actor": "C", "delegation_id": "GD", "account_id": "A", "delegate": "I", "module": "registry", "role_ids": []string{"ROLE"}, "target_types": []string{"registry.registries"}, "subject_types": []string{"service_account"}}
			row := rid09PrimaryRow{}
			rid11UnitSet(row, "id", "evt_0123456789ABCDEFGHJKMNP")
			rid11UnitSet(row, "event_type", "iam.grant_delegation.created")
			rid11UnitSet(row, "tenant_account_id", "A")
			rid11UnitSet(row, "created_at", at.Add(time.Second))
			rid11UnitSet(row, "event_payload", payload)
			before := []rid09PrimaryRow{}
			after := []rid09PrimaryRow{row}
			pairs := map[string]string{"A": "GD"}
			want := false
			switch name {
			case "exact-native-create":
				want = true
			case "idempotent-zero":
				before = after
				pairs = map[string]string{}
				want = true
			case "missing-event":
				after = nil
			case "duplicate-event":
				after = append(after, row)
			case "wrong-event":
				rid11UnitSet(row, "event_type", "iam.access_binding.granted")
			case "wrong-actor":
				payload["actor"] = "O"
			case "wrong-tenant":
				rid11UnitSet(row, "tenant_account_id", "OTHER")
			case "wrong-GD":
				payload["delegation_id"] = "OTHER"
			case "wrong-I":
				payload["delegate"] = "C"
			case "wrong-role":
				payload["role_ids"] = []string{"EXTRA"}
			case "unknown-payload":
				payload["extra"] = true
			case "unknown-column":
				rid11UnitSet(row, "future", true)
			case "future-event":
				rid11UnitSet(row, "created_at", at.Add(time.Hour))
			case "old-history-lost":
				old := rid09PrimaryRow{}
				for k, v := range row {
					old[k] = v
				}
				rid11UnitSet(old, "id", "evt_1123456789ABCDEFGHJKMNP")
				before = []rid09PrimaryRow{old}
			}
			rid11UnitSet(row, "event_payload", payload)
			require.Equal(t, want, rid11InstallerAuditValid(before, after, "C", "I", "ROLE", pairs, at, at.Add(2*time.Second)))
		})
	}
}
