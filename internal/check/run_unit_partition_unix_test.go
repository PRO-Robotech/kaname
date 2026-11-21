// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package check_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/testsupport/execstub"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// Настоящий прогонщик и канонический verifier читают события двойника Go.
// Будущие Test/Example/Fuzz и пакет без проб проверяют полноту дополнения.
const unitFakeGo = `#!/usr/bin/env python3
import json, os, pathlib, re, sys
args = sys.argv[1:]
with open('calls.jsonl', 'a') as out:
    out.write(json.dumps(args) + '\n')
check = 'github.com/PRO-Robotech/kaname/internal/check'
inventory = json.loads(pathlib.Path('inventory.fixture.json').read_text())
defect = os.environ.get('UNIT_DEFECT', '')
if defect == 'inventory-missing':
    inventory[check].remove('TestCensusDirectProducerRouteControls')
if defect == 'collision':
    inventory['example.test/other'].append('TestCensusDirectProducerRouteControls')
packages = list(inventory) if './...' in args else [check]
listing = '-list' in args
mode = 'inventory' if listing else 'test' if '-skip' in args else 'tree' if 'TestNoDeferredWorkInTheTree' in args[args.index('-run')+1] else 'census'
if not listing and defect == 'missing-package':
    packages = [p for p in packages if p != 'example.test/other']
for package in packages:
    def emit(action, name=None, output=None):
        e = dict(Package=package, Action=action)
        if name is not None: e['Test'] = name
        if output is not None: e['Output'] = output
        print(json.dumps(e))
    emit('start')
    names = inventory[package]
    if listing:
        for name in names: emit('output', output=name+'\n')
    else:
        if '-run' in args: names = [n for n in names if re.search(args[args.index('-run')+1], n)]
        if '-skip' in args: names = [n for n in names if not re.search(args[args.index('-skip')+1], n)]
        if defect == mode+'-missing': names = names[1:]
        if defect == mode+'-duplicate': names = names + names[:1]
        if defect == 'test-leak' and package == check: names = names + ['TestNoDeferredWorkInTheTree']
        for name in names:
            emit('run', name)
            emit('fail' if defect in (mode+'-red', mode+'-verdict') else 'skip' if defect == mode+'-skip' or name == 'TestShortContainer' else 'pass', name)
    emit('fail' if defect in (mode+'-red', mode+'-verdict') else 'pass' if names else 'skip')
sys.exit(1 if defect == mode+'-red' else 2 if defect == mode+'-rc2' else 0)
`

var unitCensusNames = []string{
	"TestCensusDirectProducerRouteControls", "TestCensusDirectProducerProductionEdges",
	"TestCensusDirectProducerDecisionConfiguration", "TestCensusDirectProducerTerminalBranches",
	"TestCensusDirectProducerWriteIntent", "TestCensusDirectProducerErrorBinding",
	"TestCensusDirectProducerBooleanContinuation", "TestCensusDirectProducerConditionEvaluation",
	"TestCensusRPCProducerRouteControls", "TestCensusRPCProductionBindingCounterexamples",
	"TestCensusRPCObserverAndParenthesesControls",
}

type unitFixture struct{ root string }

func newUnitFixture(t *testing.T) unitFixture {
	t.Helper()
	root := t.TempDir()
	wd, err := os.Getwd()
	require.NoError(t, err)
	module, err := platformtree.ModuleRootFrom(wd)
	require.NoError(t, err)
	for _, name := range []string{"run-unit.py", "go-test-verdict.py"} {
		body, readErr := os.ReadFile(filepath.Join(module, ".github/scripts", name))
		require.NoError(t, readErr)
		execstub.Write(t, filepath.Join(root, ".github/scripts", name), string(body))
	}
	execstub.Write(t, filepath.Join(root, "bin/go"), unitFakeGo)
	execstub.Write(t, filepath.Join(root, "bin/git"), "#!/bin/sh\nprintf '%s\\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	names := append([]string{}, unitCensusNames...)
	names = append(names, "TestNoDeferredWorkInTheTree", "TestFutureAfterPartition", "Example", "FuzzFutureAfterPartition", "TestShortContainer")
	body, err := json.Marshal(map[string][]string{shardCheckPackage: names, "example.test/other": {"TestOther"}, "example.test/empty": {},
		"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict": {"TestMatrixVolumeReportIsFreshAndItsSubjectHasNotMoved", "TestMatrixVolumeFreshnessGateCanFailAndCanStaySilent"},
		"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/scalegrid":  {"TestScaleGridFullReportIsFreshAndItsSubjectHasNotMoved", "TestScaleGridFreshnessGateCanFailAndCanStaySilent"},
		"github.com/PRO-Robotech/kaname/tools/authzformbench":               {"TestBenchReportsAreFreshAndTheirInstrumentHasNotMoved", "TestBenchFreshnessGateCanFailAndCanStaySilent"}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, "inventory.fixture.json"), body, 0o600))
	return unitFixture{root: root}
}

const shardCheckPackage = "github.com/PRO-Robotech/kaname/internal/check"

func (f unitFixture) run(t *testing.T, part, defect string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	outdir := filepath.Join(f.root, "evidence", part)
	if part == "aggregate" {
		outdir = filepath.Join(f.root, "evidence")
	}
	cmd := exec.CommandContext(ctx, "python3", filepath.Join(f.root, ".github/scripts/run-unit.py"), part, outdir) // #nosec G204 -- собственная песочница
	cmd.Dir = f.root
	cmd.Env = append(os.Environ(), "PATH="+filepath.Join(f.root, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GITHUB_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "GITHUB_RUN_ID=123", "GITHUB_RUN_ATTEMPT=1", "UNIT_DEFECT="+defect)
	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "двойник завис: %s", out)
	if err == nil {
		return 0, string(out)
	}
	var exit *exec.ExitError
	require.True(t, errors.As(err, &exit), "%v: %s", err, out)
	return exit.ExitCode(), string(out)
}

func TestRunUnitPartitionCoversFutureNamesAndKeepsRaceBudgets(t *testing.T) {
	f := newUnitFixture(t)
	for _, part := range []string{"main", "census", "aggregate"} {
		rc, out := f.run(t, part, "")
		require.Zero(t, rc, out)
	}
	body, err := os.ReadFile(filepath.Join(f.root, "calls.jsonl"))
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	require.Len(t, lines, 5)
	censusPattern := "^(" + strings.Join(unitCensusNames, "|") + ")$"
	skipPattern := "^(TestNoDeferredWorkInTheTree|" + strings.Join(unitCensusNames, "|") + ")$"
	common := []string{"-race", "-short", "-count=1", "-timeout", "45m"}
	want := [][]string{
		append(append([]string{"test", "./..."}, common...), "-list", ".", "-json"),
		{"test", "./internal/check", "-run", "^(TestNoDeferredWorkInTheTree)$", "-short", "-count=1", "-timeout", "4m", "-json"},
		append(append([]string{"test", "./..."}, common...), "-skip", skipPattern, "-json"),
		append(append([]string{"test", "./internal/check"}, common...), "-list", ".", "-json"),
		append(append([]string{"test", "./internal/check"}, common...), "-run", censusPattern, "-json"),
	}
	for i, line := range lines {
		var args []string
		require.NoError(t, json.Unmarshal([]byte(line), &args))
		require.Equal(t, want[i], args)
	}
	for _, line := range lines {
		var args []string
		require.NoError(t, json.Unmarshal([]byte(line), &args))
		require.Contains(t, args, "-short")
		require.Contains(t, args, "-count=1")
		if strings.Contains(line, "4m") {
			require.NotContains(t, args, "-race")
			require.Contains(t, args, "^(TestNoDeferredWorkInTheTree)$")
		} else {
			require.Contains(t, args, "-race")
			require.Contains(t, args, "45m")
		}
	}
	body, err = os.ReadFile(filepath.Join(f.root, "evidence/union.json"))
	require.NoError(t, err)
	var union map[string]any
	require.NoError(t, json.Unmarshal(body, &union))
	require.Equal(t, float64(16), union["internalCheckTOP"])
	require.Equal(t, float64(11), union["census"])
	require.Equal(t, float64(4), union["complement"])
}

func TestRunUnitPartitionRejectsMissingDuplicateSkippedAndForeignCoverage(t *testing.T) {
	for _, defect := range []string{"inventory-missing", "collision", "missing-package", "test-missing", "test-duplicate", "test-leak", "test-skip", "tree-skip", "census-missing", "census-duplicate", "census-skip"} {
		t.Run(defect, func(t *testing.T) {
			f := newUnitFixture(t)
			part := "main"
			if strings.HasPrefix(defect, "census-") {
				part = "census"
			}
			rc, out := f.run(t, part, defect)
			require.NotZero(t, rc, out)
		})
	}
}

func TestRunUnitPartitionKeepsRawCodesAndRunsComplementAfterTreeFailure(t *testing.T) {
	for _, defect := range []string{"tree-red", "tree-rc2", "tree-verdict", "test-red", "test-verdict", "census-rc2"} {
		t.Run(defect, func(t *testing.T) {
			f := newUnitFixture(t)
			part, raw := "main", "deferred-tree"
			if strings.HasPrefix(defect, "test-") {
				raw = "test"
			}
			if strings.HasPrefix(defect, "census-") {
				part, raw = "census", "census-test"
			}
			rc, out := f.run(t, part, defect)
			require.NotZero(t, rc, out)
			body, err := os.ReadFile(filepath.Join(f.root, "evidence", part, raw+".rc.json"))
			require.NoError(t, err)
			var codes map[string]int
			require.NoError(t, json.Unmarshal(body, &codes))
			want := 1
			if strings.HasSuffix(defect, "rc2") {
				want = 2
			}
			if strings.HasSuffix(defect, "verdict") {
				want = 0
			}
			require.Equal(t, want, codes["go"])
			if want == 2 {
				require.Zero(t, codes["canonical"])
			} else {
				require.Equal(t, 1, codes["canonical"])
			}
			if part == "main" {
				_, err = os.Stat(filepath.Join(f.root, "evidence/main/test.rc.json"))
				require.NoError(t, err)
			}
		})
	}
}

func TestRunUnitPartitionAggregateRejectsMissingSourceAndTamperedStreams(t *testing.T) {
	for _, defect := range []string{"missing", "source", "inventory", "raw", "code"} {
		t.Run(defect, func(t *testing.T) {
			f := newUnitFixture(t)
			for _, part := range []string{"main", "census"} {
				if defect == "missing" && part == "census" {
					continue
				}
				rc, out := f.run(t, part, "")
				require.Zero(t, rc, out)
			}
			base := filepath.Join(f.root, "evidence/census")
			switch defect {
			case "source":
				body, err := os.ReadFile(filepath.Join(base, "context.json"))
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(base, "context.json"), []byte(strings.ReplaceAll(string(body), "aaaaaaaa", "bbbbbbbb")), 0o600))
			case "inventory":
				body, err := os.ReadFile(filepath.Join(base, "inventory.json"))
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(base, "inventory.json"), []byte(strings.ReplaceAll(string(body), "TestFutureAfterPartition", "TestChangedInventory")), 0o600))
			case "raw":
				require.NoError(t, os.WriteFile(filepath.Join(base, "census-test.json"), []byte("{}\n"), 0o600))
			case "code":
				require.NoError(t, os.WriteFile(filepath.Join(base, "census-test.rc.json"), []byte(`{"go":true,"canonical":0}`), 0o600))
			}
			rc, out := f.run(t, "aggregate", "")
			require.NotZero(t, rc, out)
			_, err := os.Stat(filepath.Join(f.root, "evidence/union.json"))
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}
