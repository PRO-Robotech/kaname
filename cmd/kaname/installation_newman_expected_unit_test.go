// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRIDNewmanExternalIdentitySelection(t *testing.T) {
	fixture := func(t *testing.T) (string, []ridNewmanExpected) {
		t.Helper()
		dir := t.TempDir()
		all := make([]ridNewmanExpected, 12)
		for n := range all {
			all[n] = ridNewmanExpected{Node: strings.Repeat("a", 64), Runner: strings.Repeat("b", 64), Tree: strings.Repeat("c", 64), Test: strings.Repeat("d", 64), Collection: fmt.Sprintf("%064x", n+1)}
			raw, err := json.Marshal(all[n])
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("registry-installation-rid%02d.json", n+1)), raw, 0600))
		}
		return dir, all
	}
	t.Run("all-twelve-select-literal-collection-with-shared-toolchain", func(t *testing.T) {
		dir, all := fixture(t)
		for n := range all {
			got, err := ridNewmanExpectedForCollection("", dir, fmt.Sprintf("registry-installation-rid%02d", n+1))
			require.NoError(t, err)
			require.Equal(t, all[n], got)
		}
	})
	t.Run("single-rid-external-flat-file", func(t *testing.T) {
		dir, all := fixture(t)
		got, err := ridNewmanExpectedForCollection(filepath.Join(dir, "registry-installation-rid08.json"), "", "registry-installation-rid08")
		require.NoError(t, err)
		require.Equal(t, all[7], got)
	})
	for _, kind := range []string{"neither", "both", "relative-file", "relative-dir", "invalid-stem", "missing", "extra", "wrong-name", "symlink-file", "symlink-dir", "fifo-file", "mixed-toolchain", "mixed-test-binary", "duplicate-json-field", "unknown-json-field", "missing-json-field", "trailing-json", "oversize", "invalid-sha"} {
		t.Run("refuse-"+kind, func(t *testing.T) {
			dir, all := fixture(t)
			file, stem := "", "registry-installation-rid08"
			selected := filepath.Join(dir, stem+".json")
			switch kind {
			case "neither":
				dir = ""
			case "both":
				file = selected
			case "relative-file":
				file, dir = "identity.json", ""
			case "relative-dir":
				dir = "identities"
			case "invalid-stem":
				stem = "../registry-installation-rid08"
			case "missing":
				require.NoError(t, os.Remove(selected))
			case "extra":
				require.NoError(t, os.WriteFile(filepath.Join(dir, "extra.json"), []byte("{}"), 0600))
			case "wrong-name":
				require.NoError(t, os.Rename(selected, filepath.Join(dir, "registry-installation-rid13.json")))
			case "symlink-file":
				require.NoError(t, os.Remove(selected))
				require.NoError(t, os.Symlink(filepath.Join(dir, "registry-installation-rid01.json"), selected))
			case "symlink-dir":
				link := filepath.Join(t.TempDir(), "linked-identities")
				require.NoError(t, os.Symlink(dir, link))
				dir = link
			case "fifo-file":
				require.NoError(t, os.Remove(selected))
				require.NoError(t, syscall.Mkfifo(selected, 0600))
			case "mixed-toolchain", "mixed-test-binary":
				changed := all[0]
				if kind == "mixed-toolchain" {
					changed.Node = strings.Repeat("e", 64)
				} else {
					changed.Test = strings.Repeat("e", 64)
				}
				raw, err := json.Marshal(changed)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(dir, "registry-installation-rid01.json"), raw, 0600))
			case "duplicate-json-field", "unknown-json-field", "missing-json-field", "trailing-json", "oversize", "invalid-sha":
				raw, err := os.ReadFile(selected)
				require.NoError(t, err)
				text := string(raw)
				switch kind {
				case "duplicate-json-field":
					text = strings.TrimSuffix(text, "}") + `,"nodeSHA256":"` + all[7].Node + `"}`
				case "unknown-json-field":
					text = strings.TrimSuffix(text, "}") + `,"unexpected":"value"}`
				case "missing-json-field":
					text = strings.Replace(text, `"nodeSHA256":"`+all[7].Node+`",`, "", 1)
				case "trailing-json":
					text += "{}"
				case "oversize":
					text += strings.Repeat(" ", 16385)
				case "invalid-sha":
					text = strings.Replace(text, all[7].Node, "invalid", 1)
				}
				require.NoError(t, os.WriteFile(selected, []byte(text), 0600))
			}
			_, err := ridNewmanExpectedForCollection(file, dir, stem)
			require.Error(t, err)
		})
	}
}
