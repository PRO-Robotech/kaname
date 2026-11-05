// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type rid01RedactionUnitFixture struct {
	phase, keyID       string
	before, after, pre rid01NewmanSnapshot
	profile            rid01KeyRedactionProfile
	original, current  *iamv1.IssueSAKeyResponse
}

func rid01UnitCell(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return raw
}
func rid01UnitResponseCell(t *testing.T, v *iamv1.IssueSAKeyResponse) json.RawMessage {
	t.Helper()
	raw, err := proto.Marshal(v)
	require.NoError(t, err)
	return rid01UnitCell(t, "\\x"+hex.EncodeToString(raw))
}
func (x *rid01RedactionUnitFixture) rehash() {
	for _, s := range []*rid01NewmanSnapshot{&x.before, &x.after, &x.pre} {
		for id, row := range s.OperationRawRows {
			s.Operations[id] = rid01RedactionHash(row)
		}
	}
}
func (x *rid01RedactionUnitFixture) currentCell(t *testing.T) {
	t.Helper()
	x.after.OperationRawRows[x.keyID]["response_data"] = rid01UnitResponseCell(t, x.current)
}
func rid01RedactionUnit(t *testing.T) *rid01RedactionUnitFixture {
	t.Helper()
	profile, err := rid01ResolveRedactionProfile([]string{"KANAME_API_SERVER__ENDPOINT=tcp://127.0.0.1:9090"}, nil)
	require.NoError(t, err)
	clock := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	modified := clock.Add(-profile.Settled - time.Minute)
	original := &iamv1.IssueSAKeyResponse{Key: &iamv1.ServiceAccountOAuthClient{Id: "unit-client", SvaId: "unit-service-account", Description: "stable nested key", ExpiresAt: timestamppb.New(clock.Add(time.Hour)), CreatedAt: timestamppb.New(modified), CreatedByUserId: "unit-creator", Name: "stable name", Labels: map[string]string{"label": "stable"}}, ClientId: "unit-client", KeyId: "unit-client", Algorithm: "ES256", PublicKeyPem: "unit-public-key", Audiences: []string{"https://kaname.local"}, PrivateKeyPem: "unit-private-secret", ClientSecret: "unit-client-secret", Secret: "unit-base-secret"}
	// Неизвестные поля намеренно есть и в принятом близнеце:
	// компаратор должен сохранять неизвестные байты верхнего уровня и вложений.
	original.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	original.Key.ProtoReflect().SetUnknown([]byte{0xa8, 0x06, 0x02})
	current := proto.Clone(original).(*iamv1.IssueSAKeyResponse)
	current.PrivateKeyPem = ""
	current.ClientSecret = ""
	current.Secret = ""
	typ, err := anypb.New(&iamv1.IssueSAKeyResponse{})
	require.NoError(t, err)
	keyID := "unit-key-operation"
	row := rid09PrimaryRow{"id": rid01UnitCell(t, keyID), "done": rid01UnitCell(t, true), "response_type": rid01UnitCell(t, typ.TypeUrl), "response_data": rid01UnitResponseCell(t, original), "modified_at": rid01UnitCell(t, modified), "created_at": rid01UnitCell(t, modified.Add(-time.Second)), "metadata_type": rid01UnitCell(t, "stable-metadata"), "metadata_data": rid01UnitCell(t, "\\x00"), "principal_type": rid01UnitCell(t, "service_account"), "principal_id": rid01UnitCell(t, "unit-service-account"), "resource_id": rid01UnitCell(t, "unit-client"), "account_id": rid01UnitCell(t, "unit-system"), "unknown_future_column": rid01UnitCell(t, map[string]any{"stable": "retained"})}
	after := rid09PrimaryRow{}
	for k, v := range row {
		after[k] = append(json.RawMessage{}, v...)
	}
	after["response_data"] = rid01UnitResponseCell(t, current)
	other := rid09PrimaryRow{"id": rid01UnitCell(t, "unit-other-operation"), "done": rid01UnitCell(t, true), "response_data": rid01UnitCell(t, "\\x0102"), "modified_at": rid01UnitCell(t, modified)}
	otherAfter := rid09PrimaryRow{}
	for k, v := range other {
		otherAfter[k] = append(json.RawMessage{}, v...)
	}
	beforeSnapshot := rid01NewmanSnapshot{Operations: map[string]string{}, OperationRawRows: map[string]rid09PrimaryRow{keyID: row, "unit-other-operation": other}}
	beforeSnapshot.Whole.PrimaryStartedAt = clock
	beforeSnapshot.Whole.PrimaryFinishedAt = clock.Add(time.Second)
	afterSnapshot := rid01NewmanSnapshot{Operations: map[string]string{}, OperationRawRows: map[string]rid09PrimaryRow{keyID: after, "unit-other-operation": otherAfter}}
	x := &rid01RedactionUnitFixture{phase: rid01KeyRedactionCase, keyID: keyID, before: beforeSnapshot, after: afterSnapshot, pre: beforeSnapshot, profile: profile, original: original, current: current}
	x.rehash()
	return x
}
func TestRID01ExactTypedKeyRedaction(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *rid01RedactionUnitFixture)
		want   bool
	}{
		{"exact-clone-cleared-twin", nil, true},
		{"wrong-ID", func(t *testing.T, x *rid01RedactionUnitFixture) { x.keyID = "unit-other-operation" }, false},
		{"wrong-phase", func(t *testing.T, x *rid01RedactionUnitFixture) {
			x.phase = "registry-installation-rid01-RENEWAL-AFTER"
		}, false},
		{"wrong-type", func(t *testing.T, x *rid01RedactionUnitFixture) {
			for _, s := range []*rid01NewmanSnapshot{&x.before, &x.after} {
				s.OperationRawRows[x.keyID]["response_type"] = rid01UnitCell(t, "type.googleapis.com/other.IssueSAKeyResponse")
			}
		}, false},
		{"modified-at-changed", func(t *testing.T, x *rid01RedactionUnitFixture) {
			x.after.OperationRawRows[x.keyID]["modified_at"] = rid01UnitCell(t, x.pre.Whole.PrimaryStartedAt)
		}, false},
		{"unknown-SQL-column-changed", func(t *testing.T, x *rid01RedactionUnitFixture) {
			x.after.OperationRawRows[x.keyID]["unknown_future_column"] = rid01UnitCell(t, "changed")
		}, false},
		{"missing-SQL-column", func(t *testing.T, x *rid01RedactionUnitFixture) {
			delete(x.after.OperationRawRows[x.keyID], "unknown_future_column")
		}, false},
		{"extra-SQL-column", func(t *testing.T, x *rid01RedactionUnitFixture) {
			x.after.OperationRawRows[x.keyID]["unexpected_column"] = rid01UnitCell(t, 1)
		}, false},
		{"nonsecret-proto-changed", func(t *testing.T, x *rid01RedactionUnitFixture) { x.current.Algorithm = "different"; x.currentCell(t) }, false},
		{"nested-key-changed", func(t *testing.T, x *rid01RedactionUnitFixture) {
			x.current.Key.CreatedAt = timestamppb.New(x.pre.Whole.PrimaryStartedAt)
			x.currentCell(t)
		}, false},
		{"unknown-proto-changed", func(t *testing.T, x *rid01RedactionUnitFixture) {
			x.current.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x02})
			x.currentCell(t)
		}, false},
		{"nested-unknown-proto-changed", func(t *testing.T, x *rid01RedactionUnitFixture) {
			x.current.Key.ProtoReflect().SetUnknown(nil)
			x.currentCell(t)
		}, false},
		{"secret-replacement", func(t *testing.T, x *rid01RedactionUnitFixture) {
			x.current.PrivateKeyPem = "unit-replacement-secret"
			x.currentCell(t)
		}, false},
		{"private-key-not-removed", func(t *testing.T, x *rid01RedactionUnitFixture) {
			x.current.PrivateKeyPem = x.original.PrivateKeyPem
			x.currentCell(t)
		}, false},
		{"client-secret-not-removed", func(t *testing.T, x *rid01RedactionUnitFixture) {
			x.current.ClientSecret = x.original.ClientSecret
			x.currentCell(t)
		}, false},
		{"base-secret-not-removed", func(t *testing.T, x *rid01RedactionUnitFixture) {
			x.current.Secret = x.original.Secret
			x.currentCell(t)
		}, false},
		{"no-actual-secret-before", func(t *testing.T, x *rid01RedactionUnitFixture) {
			x.original.PrivateKeyPem = ""
			x.original.ClientSecret = ""
			x.original.Secret = ""
			x.before.OperationRawRows[x.keyID]["response_data"] = rid01UnitResponseCell(t, x.original)
		}, false},
		{"not-settled-at-pre-restore-clock", func(t *testing.T, x *rid01RedactionUnitFixture) {
			at := x.pre.Whole.PrimaryStartedAt.Add(-x.profile.Settled)
			for _, s := range []*rid01NewmanSnapshot{&x.before, &x.after} {
				s.OperationRawRows[x.keyID]["modified_at"] = rid01UnitCell(t, at)
			}
		}, false},
		{"outside-sweep-window", func(t *testing.T, x *rid01RedactionUnitFixture) {
			at := x.pre.Whole.PrimaryFinishedAt.Add(-x.profile.Window)
			for _, s := range []*rid01NewmanSnapshot{&x.before, &x.after} {
				s.OperationRawRows[x.keyID]["modified_at"] = rid01UnitCell(t, at)
			}
		}, false},
		{"missing-pre-restore-clock", func(t *testing.T, x *rid01RedactionUnitFixture) { x.pre.Whole.PrimaryStartedAt = time.Time{} }, false},
		{"reversed-pre-restore-clock", func(t *testing.T, x *rid01RedactionUnitFixture) {
			x.pre.Whole.PrimaryFinishedAt = x.pre.Whole.PrimaryStartedAt.Add(-time.Second)
		}, false},
		{"unsupported-profile", func(t *testing.T, x *rid01RedactionUnitFixture) { x.profile.Settled += time.Second }, false},
		{"missing-key-row", func(t *testing.T, x *rid01RedactionUnitFixture) { delete(x.after.OperationRawRows, x.keyID) }, false},
		{"extra-Operation", func(t *testing.T, x *rid01RedactionUnitFixture) {
			x.after.OperationRawRows["unexpected-operation"] = rid09PrimaryRow{"id": rid01UnitCell(t, "unexpected-operation")}
			x.after.Operations["unexpected-operation"] = ""
		}, false},
		{"other-Operation-changed", func(t *testing.T, x *rid01RedactionUnitFixture) {
			x.after.OperationRawRows["unit-other-operation"]["modified_at"] = rid01UnitCell(t, x.pre.Whole.PrimaryStartedAt)
		}, false},
		{"pre-restore-not-zero", func(t *testing.T, x *rid01RedactionUnitFixture) {
			x.pre.Operations = map[string]string{}
			x.pre.OperationRawRows = map[string]rid09PrimaryRow{}
		}, false},
		{"malformed-bytea", func(t *testing.T, x *rid01RedactionUnitFixture) {
			x.after.OperationRawRows[x.keyID]["response_data"] = rid01UnitCell(t, "\\xnothex")
		}, false},
		{"null-bytea", func(t *testing.T, x *rid01RedactionUnitFixture) {
			x.after.OperationRawRows[x.keyID]["response_data"] = json.RawMessage("null")
		}, false},
		{"malformed-proto", func(t *testing.T, x *rid01RedactionUnitFixture) {
			x.after.OperationRawRows[x.keyID]["response_data"] = rid01UnitCell(t, "\\xff")
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := rid01RedactionUnit(t)
			beforeBytes, err := proto.Marshal(x.original)
			require.NoError(t, err)
			if tc.change != nil {
				tc.change(t, x)
			}
			x.rehash()
			originalRowsSHA := rid01RedactionHash(x.before.OperationRawRows)
			proof, err := rid01ProveKeyRedaction(x.phase, x.keyID, x.before, x.after, x.pre, x.profile)
			if tc.want {
				require.NoError(t, err)
				require.NotNil(t, proof)
				require.True(t, proof.ActualSecretsGone)
				require.Equal(t, originalRowsSHA, rid01RedactionHash(x.before.OperationRawRows), "comparator never mutates original raw rows")
				require.True(t, proof.AllOtherColumnsEqual)
				require.True(t, proof.FullTypedNonsecretAndUnknownEqual)
				afterBytes, e := proto.Marshal(x.original)
				require.NoError(t, e)
				require.True(t, string(beforeBytes) == string(afterBytes), "comparator must not mutate original before message")
				safe, e := json.Marshal(proof)
				require.NoError(t, e)
				for _, secret := range []string{"unit-private-secret", "unit-client-secret", "unit-base-secret"} {
					require.False(t, strings.Contains(string(safe), secret), "proof must not carry secret values")
				}
			} else {
				require.Error(t, err)
				require.Nil(t, proof)
				for _, secret := range []string{"unit-private-secret", "unit-client-secret", "unit-base-secret", "unit-replacement-secret"} {
					require.False(t, strings.Contains(err.Error(), secret), "failure must be constant and sanitized")
				}
			}
		})
	}
}
func TestRID01ActualRedactionProfile(t *testing.T) {
	for _, tc := range []struct {
		name  string
		env   []string
		extra map[string]any
		want  bool
	}{
		{"native-empty-ExtraConfig", []string{"KANAME_API_SERVER__ENDPOINT=tcp://127.0.0.1:9090"}, nil, true},
		{"native-empty-map", nil, map[string]any{}, true},
		{"canonical-SA-override", []string{"KANAME_AUTHN__SAKEY_REDACT_GRACE=120s"}, nil, false},
		{"canonical-user-override", []string{"KANAME_AUTHN__USERTOKEN_REDACT_GRACE=120s"}, nil, false},
		{"legacy-SA-override", []string{"KANAME_SAKEY_REDACT_GRACE=120s"}, nil, false},
		{"legacy-user-override", []string{"KANAME_USERTOKEN_REDACT_GRACE=120s"}, nil, false},
		{"unknown-redaction-env", []string{"KANAME_UNKNOWN_REDACT_GRACE=1s"}, nil, false},
		{"empty-override", []string{"KANAME_SAKEY_REDACT_GRACE="}, nil, false},
		{"file-authn-override", nil, map[string]any{"authn": map[string]any{"sakey-redact-grace": "120s"}}, false},
		{"unsupported-file-profile", nil, map[string]any{"unrecognized-profile": true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := rid01ResolveRedactionProfile(tc.env, tc.extra)
			if !tc.want {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Positive(t, p.SAKeyGrace)
			require.Positive(t, p.UserTokenGrace)
			longest := p.SAKeyGrace
			if p.UserTokenGrace > longest {
				longest = p.UserTokenGrace
			}
			require.Equal(t, longest+secretSweepMargin, p.Settled)
			require.Equal(t, secretSweepWindow, p.Window)
			require.NotEmpty(t, p.EnvironmentSHA256)
			require.NotEmpty(t, p.ExtraConfigSHA256)
		})
	}
}
