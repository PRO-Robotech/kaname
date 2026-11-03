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
			got, err := ridNewmanClientBearers(tc.stem, tc.variables)
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
