// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRIDNewmanBearerAdmission(t *testing.T) {
	for _, tc := range []struct {
		name, stem string
		variables  map[string]any
		want       []string
	}{
		{"operator-only", "registry-installation-rid08", map[string]any{"jwtRIDOperator": "operator"}, []string{"operator"}},
		{"creator-owner", "registry-installation-rid10", map[string]any{"jwtRIDOperator": "operator", "jwtRIDCreator": "creator"}, []string{"operator", "creator"}},
		{"creator-missing", "registry-installation-rid10", map[string]any{"jwtRIDOperator": "operator"}, nil},
		{"creator-empty", "registry-installation-rid10", map[string]any{"jwtRIDOperator": "operator", "jwtRIDCreator": ""}, nil},
		{"creator-wrong-type", "registry-installation-rid10", map[string]any{"jwtRIDOperator": "operator", "jwtRIDCreator": 1}, nil},
		{"creator-outside-owner-cases", "registry-installation-rid08", map[string]any{"jwtRIDOperator": "operator", "jwtRIDCreator": "creator"}, nil},
		{"undeclared-actor", "registry-installation-rid10", map[string]any{"jwtRIDOperator": "operator", "jwtRIDCreator": "creator", "jwtRIDOther": "other"}, nil},
		{"operator-missing", "registry-installation-rid08", map[string]any{}, nil},
		{"operator-oversized", "registry-installation-rid08", map[string]any{"jwtRIDOperator": strings.Repeat("s", (16<<10)+1)}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ridNewmanClientSecrets(tc.stem, tc.stem+"-UNIT", tc.variables)
			if tc.want == nil {
				require.Error(t, err)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestRIDNewmanAnonymousInventoryAdmission(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		keep bool
		want bool
	}{
		{"complete", "[\"\",\"operator\"]\n[\"\",\"creator\"]\n[\"key\",\"operator\"]\n", false, true},
		{"world-known-creator-is-not-fd5", "[\"key\",\"operator\"]\n", false, false},
		{"key-missing", "[\"\",\"operator\"]\n[\"\",\"creator\"]\n", false, false},
		{"truncated-after-capture", "[\"\",\"operator\"]\n[\"\",\"creator\"]\n[", false, false},
		{"wrong-record-shape", "[\"key\",\"operator\",\"creator\"]\n", false, false},
		{"still-linked", "[\"key\",\"operator\"]\n[\"\",\"creator\"]\n", true, false},
		{"empty", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.OpenFile(filepath.Join(t.TempDir(), "inventory"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
			require.NoError(t, err)
			t.Cleanup(func() { _ = f.Close() })
			if !tc.keep {
				require.NoError(t, os.Remove(f.Name()))
			}
			_, err = io.WriteString(f, tc.raw)
			require.NoError(t, err)
			before, err := f.Seek(0, io.SeekCurrent)
			require.NoError(t, err)
			err = ridNewmanAuditAnonymousInventory(f, []string{"operator", "creator", "key"})
			if tc.want {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			after, err := f.Seek(0, io.SeekCurrent)
			require.NoError(t, err)
			require.Equal(t, before, after, "audit must not move the shared FD5 cursor")
		})
	}
	t.Run("capture-preserves-record-protocol", func(t *testing.T) {
		var raw strings.Builder
		require.NoError(t, ridNewmanRecordBearers(&raw, []string{"operator", "creator"}))
		decoder := json.NewDecoder(strings.NewReader(raw.String()))
		for _, token := range []string{"operator", "creator"} {
			var record []string
			require.NoError(t, decoder.Decode(&record))
			require.Equal(t, []string{"", token}, record)
		}
	})
}

func TestRIDNewmanAssertionAnonymousInventory(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      bool
	}{
		{"complete-assertion-record", "[\"\",\"operator\"]\n[\"\",\"assertion\"]\n[\"key\",\"operator\"]\n", true},
		{"world-known-assertion-not-FD5", "[\"\",\"operator\"]\n[\"key\",\"operator\"]\n", false},
		{"assertion-truncated", "[\"\",\"operator\"]\n[\"key\",\"operator\"]\n[", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.OpenFile(filepath.Join(t.TempDir(), "inventory"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
			require.NoError(t, err)
			t.Cleanup(func() { _ = f.Close() })
			require.NoError(t, os.Remove(f.Name()))
			_, err = io.WriteString(f, tc.raw)
			require.NoError(t, err)
			err = ridNewmanAuditAnonymousInventory(f, []string{"operator", "assertion", "key"})
			if tc.want {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

// Исходные контроли только безопасности; значения — фиктивные строки, а не токены фикстуры.
func TestRID03NewmanSecretAdmission(t *testing.T) {
	for _, tc := range []struct {
		name, caseID string
		variables    map[string]any
		want         []string
	}{
		{"I-positive-S1", "registry-installation-rid03-S1-GRANT-ACT", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": "I"}, []string{"O", "I"}},
		{"I-negative-S2", "registry-installation-rid03-S2-ROLE-DENIED-ACT", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": "I"}, []string{"O", "I"}},
		{"C-exact-twin", "registry-installation-rid03-S2-CREATOR-GD-TWIN-ACT", map[string]any{"jwtRIDOperator": "O", "jwtRIDCreator": "C"}, []string{"O", "C"}},
		{"O-only-VERIFY", "registry-installation-rid03-S1-GRANT-VERIFY", map[string]any{"jwtRIDOperator": "O"}, []string{"O"}},
		{"I-missing", "registry-installation-rid03-S1-GRANT-ACT", map[string]any{"jwtRIDOperator": "O"}, nil},
		{"I-empty", "registry-installation-rid03-S1-GRANT-ACT", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": ""}, nil},
		{"I-type", "registry-installation-rid03-S1-GRANT-ACT", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": 1}, nil},
		{"I-oversize", "registry-installation-rid03-S1-GRANT-ACT", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": strings.Repeat("x", 16385)}, nil},
		{"C-on-I-ACT", "registry-installation-rid03-S1-GRANT-ACT", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": "I", "jwtRIDCreator": "C"}, nil},
		{"I-on-C-ACT", "registry-installation-rid03-S1-CREATOR-GD-TWIN-ACT", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": "I"}, nil},
		{"I-on-VERIFY", "registry-installation-rid03-S1-GRANT-VERIFY", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": "I"}, nil},
		{"C-on-VERIFY", "registry-installation-rid03-S1-CREATOR-GD-TWIN-VERIFY", map[string]any{"jwtRIDOperator": "O", "jwtRIDCreator": "C"}, nil},
		{"I-outside-RID03", "registry-installation-rid08-EMPTY-N0", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": "I"}, nil},
		{"unknown-phase", "registry-installation-rid03-S1-GRANT-AFTER", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": "I"}, nil},
		{"unknown-mode", "registry-installation-rid03-S3-GRANT-ACT", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": "I"}, nil},
		{"assertion-on-I-ACT", "registry-installation-rid03-S1-GRANT-ACT", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": "I", "rid01ClientAssertion": "assertion"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stem := strings.Join(strings.Split(tc.caseID, "-")[:3], "-")
			got, err := ridNewmanClientSecrets(stem, tc.caseID, tc.variables)
			if tc.want == nil {
				require.Error(t, err)
				require.Nil(t, got)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.want, got)
			}
		})
	}
}
func TestRID03NewmanLiteralAdmissionCensus(t *testing.T) {
	require.Len(t, rid03NewmanActors, 44)
	for _, id := range rid03ExpectedLiteralCases {
		t.Run(id, func(t *testing.T) {
			actor, ok := rid03NewmanActor(id)
			require.True(t, ok)
			variables := map[string]any{"jwtRIDOperator": "O"}
			want := []string{"O"}
			if actor == "I" {
				variables["jwtRIDIssuer"] = "I"
				want = append(want, "I")
			}
			if actor == "C" {
				variables["jwtRIDCreator"] = "C"
				want = append(want, "C")
			}
			got, err := ridNewmanClientSecrets("registry-installation-rid03", id, variables)
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}

// Независимый литеральный порядок теста; не выводится из допущенных элементов карты.
var rid03ExpectedLiteralCases = []string{
	"registry-installation-rid03-S1-GRANT-ACT",
	"registry-installation-rid03-S1-GRANT-VERIFY",
	"registry-installation-rid03-S1-ROLE-DENIED-ACT",
	"registry-installation-rid03-S1-ROLE-DENIED-VERIFY",
	"registry-installation-rid03-S1-ROLE-TWIN-ACT",
	"registry-installation-rid03-S1-ROLE-TWIN-VERIFY",
	"registry-installation-rid03-S1-TARGET-DENIED-ACT",
	"registry-installation-rid03-S1-TARGET-DENIED-VERIFY",
	"registry-installation-rid03-S1-TARGET-TWIN-ACT",
	"registry-installation-rid03-S1-TARGET-TWIN-VERIFY",
	"registry-installation-rid03-S1-SUBJECT-DENIED-ACT",
	"registry-installation-rid03-S1-SUBJECT-DENIED-VERIFY",
	"registry-installation-rid03-S1-SUBJECT-TWIN-ACT",
	"registry-installation-rid03-S1-SUBJECT-TWIN-VERIFY",
	"registry-installation-rid03-S1-ISSUER-GD-DENIED-ACT",
	"registry-installation-rid03-S1-ISSUER-GD-DENIED-VERIFY",
	"registry-installation-rid03-S1-CREATOR-GD-TWIN-ACT",
	"registry-installation-rid03-S1-CREATOR-GD-TWIN-VERIFY",
	"registry-installation-rid03-S1-AUTHENTICATED-DENIED-ACT",
	"registry-installation-rid03-S1-AUTHENTICATED-DENIED-VERIFY",
	"registry-installation-rid03-S1-ANONYMOUS-TWIN-ACT",
	"registry-installation-rid03-S1-ANONYMOUS-TWIN-VERIFY",
	"registry-installation-rid03-S2-GRANT-ACT",
	"registry-installation-rid03-S2-GRANT-VERIFY",
	"registry-installation-rid03-S2-ROLE-DENIED-ACT",
	"registry-installation-rid03-S2-ROLE-DENIED-VERIFY",
	"registry-installation-rid03-S2-ROLE-TWIN-ACT",
	"registry-installation-rid03-S2-ROLE-TWIN-VERIFY",
	"registry-installation-rid03-S2-TARGET-DENIED-ACT",
	"registry-installation-rid03-S2-TARGET-DENIED-VERIFY",
	"registry-installation-rid03-S2-TARGET-TWIN-ACT",
	"registry-installation-rid03-S2-TARGET-TWIN-VERIFY",
	"registry-installation-rid03-S2-SUBJECT-DENIED-ACT",
	"registry-installation-rid03-S2-SUBJECT-DENIED-VERIFY",
	"registry-installation-rid03-S2-SUBJECT-TWIN-ACT",
	"registry-installation-rid03-S2-SUBJECT-TWIN-VERIFY",
	"registry-installation-rid03-S2-ISSUER-GD-DENIED-ACT",
	"registry-installation-rid03-S2-ISSUER-GD-DENIED-VERIFY",
	"registry-installation-rid03-S2-CREATOR-GD-TWIN-ACT",
	"registry-installation-rid03-S2-CREATOR-GD-TWIN-VERIFY",
	"registry-installation-rid03-S2-AUTHENTICATED-DENIED-ACT",
	"registry-installation-rid03-S2-AUTHENTICATED-DENIED-VERIFY",
	"registry-installation-rid03-S2-ANONYMOUS-TWIN-ACT",
	"registry-installation-rid03-S2-ANONYMOUS-TWIN-VERIFY",
}
