// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLeafProductionImportClosureControls(t *testing.T) {
	for _, tc := range []struct {
		name, root, middle string
		red, broken        bool
	}{
		{"только test import", "package main", "", false, false},
		{"blank import", "package main; import _ \"example.test/leaf/helper\"", "", true, false},
		{"прямой import", `package main; import helper "example.test/leaf/helper"; var _ = helper.X`, "", true, false},
		{"двухшаговый import", "package main; import _ \"example.test/leaf/middle\"", "package middle; import renamed \"example.test/leaf/helper\"; var _ = renamed.X", true, false},
		{"пустой root", "", "", false, true},
		{"неразрешённый import", "package main; import _ \"example.test/leaf/missing\"", "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			sources := map[string]string{"go.mod": "module example.test/leaf\n", "helper/dial.go": "package renamed; import rpc \"google.golang.org/grpc\"; const X = 1; func dial(){ rpc.NewClient(\"example.invalid\") }", "cmd/kaname/test_test.go": "package main; import _ \"example.test/leaf/helper\""}
			if tc.root != "" {
				sources["cmd/kaname/main.go"] = tc.root
			}
			if tc.middle != "" {
				sources["middle/middle.go"] = tc.middle
			}
			var paths []string
			for name, src := range sources {
				p := filepath.Join(dir, name)
				require.NoError(t, os.MkdirAll(filepath.Dir(p), 0700))
				require.NoError(t, os.WriteFile(p, []byte(src), 0600))
				if filepath.Ext(p) == ".go" {
					paths = append(paths, p)
				}
			}
			reached, err := productionImportClosure(dir, paths, "cmd/kaname")
			if tc.broken {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			dials := 0
			for p := range reached {
				src, err := os.ReadFile(p)
				require.NoError(t, err)
				lines, err := grpcAliasDials(p, src)
				require.NoError(t, err)
				dials += len(lines)
			}
			require.Equal(t, tc.red, dials > 0)
		})
	}
}

func TestLeafProductionCorpusReadAndParseFailures(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.test/leaf\n"), 0600))
	p := filepath.Join(dir, "missing.go")
	_, err := productionImportClosure(dir, []string{p}, ".")
	require.Error(t, err)
	require.NoError(t, os.WriteFile(p, []byte("package"), 0600))
	_, err = productionImportClosure(dir, []string{p}, ".")
	require.Error(t, err)
}
