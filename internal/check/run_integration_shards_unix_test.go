// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package check_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/testsupport/execstub"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

const shardAccessBinding = "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
const shardSlowPattern = "^(TestFullBind_FB21_GroupAdditionChecksTheLastBindingPage|TestFullBind_FB31_SourceExpiryAfterHeldWriterClockDoesNotShortenGrant)$"

// Двойник исполняет контракт аргументов и событий; реальные БД и сроки он не судит.
const shardFakeGo = `#!/usr/bin/env python3
import json, os, pathlib, signal, sys
args = sys.argv[1:]
packages = pathlib.Path(os.environ["FAKE_PACKAGES"]).read_text().splitlines()
if args[0] == "list":
    suffix = "::github.com/PRO-Robotech/corelib/pgtest" if "-f" in args else ""
    print("\n".join(p + suffix for p in packages))
    sys.exit(0)
if args[0] != "test":
    sys.exit(97)
with open(os.environ["FAKE_CALLS"], "a") as out:
    out.write(json.dumps(args) + "\n")
mode = "run" if "-run" in args else "skip" if "-skip" in args else "all"
if os.environ.get("FAKE_SIGNAL") == mode:
    os.kill(os.getppid(), signal.SIGTERM)
    sys.exit(0)
for package in (a for a in args if a in packages):
    def emit(action, name=None):
        event = {"Package": package, "Action": action}
        if name:
            event["Test"] = name
        print(json.dumps(event))
    emit("start")
    names = ["TestComplement", "ExampleComplement", "FuzzComplement"]
    if mode == "run":
        names = args[args.index("-run") + 1][2:-2].split("|")
    defect = os.environ.get("FAKE_DEFECT", "")
    if defect == mode + "-empty":
        names = []
    if defect == "run-missing":
        names = names[:1]
    if defect == "run-renamed":
        names[-1] = "TestRenamed"
    if defect == "skip-leak":
        names.append("TestFullBind_FB21_GroupAdditionChecksTheLastBindingPage")
    for name in names:
        emit("run", name)
        emit("skip" if defect == "run-skipped" else "pass", name)
    emit("pass")
sys.exit(int(os.environ.get("FAKE_FIRST_RC", "0")) if mode == "all" else 0)
`

type shardOutcome struct {
	rc       int
	calls    [][]string
	evidence string
	output   string
}

func runShardFixture(t *testing.T, script, shard string, plan, moveOwner bool, extra ...string) shardOutcome {
	t.Helper()
	box := t.TempDir()
	root := filepath.Join(box, "root")
	execstub.Write(t, filepath.Join(root, runIntegrationRel), script)
	wd, err := os.Getwd()
	require.NoError(t, err)
	module, err := platformtree.ModuleRootFrom(wd)
	require.NoError(t, err)
	for _, name := range []string{"classify-integration-outcome.sh", "go-test-verdict.py"} {
		body, readErr := os.ReadFile(filepath.Join(module, ".github/scripts", name))
		require.NoError(t, readErr)
		execstub.Write(t, filepath.Join(root, ".github/scripts", name), string(body))
	}
	packages := []string{shardAccessBinding}
	weights := "11 " + shardAccessBinding + "\n"
	for i := 0; i < 10; i++ {
		p := fmt.Sprintf("example.test/p%d", i)
		packages = append(packages, p)
		weight := 10
		if moveOwner && i == 0 {
			weight = 12
		}
		weights += fmt.Sprintf("%d %s\n", weight, p)
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, ".github/integration-shard-weights.txt"), []byte(weights), 0o600))
	inventory := filepath.Join(box, "packages")
	require.NoError(t, os.WriteFile(inventory, []byte(strings.Join(packages, "\n")), 0o600))
	bin := filepath.Join(box, "bin")
	execstub.Write(t, filepath.Join(bin, "go"), shardFakeGo)
	traces := filepath.Join(box, "tmp")
	require.NoError(t, os.Mkdir(traces, 0o700))
	calls := filepath.Join(box, "calls")
	evidence := filepath.Join(box, "evidence")
	args := []string{"--default-signal=" + runIntegrationSignals, "bash", filepath.Join(root, runIntegrationRel)}
	if plan {
		args = append(args, "--plan")
	}
	ctx, cancel := context.WithTimeout(context.Background(), runIntegrationTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "env", args...) // #nosec G204 -- собственная песочница
	cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"TMPDIR=" + traces, "INTEGRATION_EVIDENCE_DIR=" + evidence, "FAKE_CALLS=" + calls,
		"FAKE_PACKAGES=" + inventory, "INTEGRATION_SHARD=" + shard}, extra...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "двойник завис: %s", out)
	o := shardOutcome{evidence: evidence, output: string(out)}
	if err != nil {
		var exitErr *exec.ExitError
		require.True(t, errors.As(err, &exitErr), "%v: %s", err, out)
		o.rc = exitErr.ExitCode()
	}
	body, err := os.ReadFile(calls)
	if !errors.Is(err, os.ErrNotExist) {
		require.NoError(t, err)
		for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
			var call []string
			require.NoError(t, json.Unmarshal([]byte(line), &call))
			o.calls = append(o.calls, call)
		}
	}
	left, err := os.ReadDir(traces)
	require.NoError(t, err)
	require.Empty(t, left, "общая ловушка обязана снять временный каталог")
	return o
}

func shardEvidence(t *testing.T, o shardOutcome, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(o.evidence, name))
	require.NoError(t, err)
	return string(body)
}

func TestRunIntegrationShardsTwoSlowCasesCoverTheWholePlan(t *testing.T) {
	script := runIntegrationSource(t)
	seen := make(map[string]int)
	for shard := 0; shard < 5; shard++ {
		o := runShardFixture(t, script, fmt.Sprintf("%d/5", shard), false, false)
		require.Zero(t, o.rc, o.output)
		wantCalls := 1
		if shard < 2 {
			wantCalls = 2
		}
		require.Len(t, o.calls, wantCalls)
		for _, call := range o.calls {
			require.Contains(t, call, "-race")
			require.Contains(t, strings.Join(call, " "), "-timeout 25m -p 1")
			filtered := false
			for i, arg := range call {
				if arg == "-run" || arg == "-skip" {
					filtered = true
					require.Equal(t, shardSlowPattern, call[i+1])
					require.Equal(t, []string{shardAccessBinding}, call[i+2:])
					require.Equal(t, map[int]string{0: "-skip", 1: "-run"}[shard], arg)
				}
				if strings.HasPrefix(arg, "example.test/") || arg == shardAccessBinding {
					seen[arg]++
				}
			}
			if !filtered {
				require.NotContains(t, call, shardAccessBinding)
			}
		}
		if shard < 2 {
			require.Equal(t, "0\n", shardEvidence(t, o, "go-test-access-binding-exit-code.txt"))
			require.Contains(t, shardEvidence(t, o, "test.json"), "Test")
			_, err := os.Stat(filepath.Join(o.evidence, "go-test-exit-code.txt"))
			require.True(t, errors.Is(err, os.ErrNotExist), "агрегат не первичный код Go")
		}
	}
	require.Len(t, seen, 11)
	for p, count := range seen {
		want := 1
		if p == shardAccessBinding {
			want = 2
		}
		require.Equal(t, want, count, p)
	}
}

func TestRunIntegrationShardsRejectEmptyOrWrongNamedPart(t *testing.T) {
	for _, defect := range []string{"run-empty", "run-missing", "run-renamed", "run-skipped", "skip-empty", "skip-leak"} {
		t.Run(defect, func(t *testing.T) {
			shard := "1/5"
			if strings.HasPrefix(defect, "skip") {
				shard = "0/5"
			}
			o := runShardFixture(t, runIntegrationSource(t), shard, false, false, "FAKE_DEFECT="+defect)
			require.Equal(t, 2, o.rc, o.output)
			require.Contains(t, o.output, "не подтверждена именованными TOP")
		})
	}
}

func TestRunIntegrationShardsKeepActualCodesAndContinueAfterFailure(t *testing.T) {
	o := runShardFixture(t, runIntegrationSource(t), "1/5", false, false, "FAKE_FIRST_RC=37")
	require.Equal(t, 37, o.rc, o.output)
	require.Len(t, o.calls, 2)
	require.Equal(t, "37\n", shardEvidence(t, o, "go-test-packages-exit-code.txt"))
	require.Equal(t, "0\n", shardEvidence(t, o, "go-test-access-binding-exit-code.txt"))
	require.Equal(t, "37\n", shardEvidence(t, o, "runner-exit-code.txt"))
}

func TestRunIntegrationShardsPlanFallbackAndUnpartitionedMode(t *testing.T) {
	o := runShardFixture(t, runIntegrationSource(t), "0/5", true, true)
	require.Zero(t, o.rc, o.output)
	require.Empty(t, o.calls, "--plan не запускает go test")
	plan := shardEvidence(t, o, "execution-plan.tsv")
	require.Contains(t, plan, "1\t"+shardAccessBinding+"\tskip\t"+shardSlowPattern)
	require.Contains(t, plan, "0\t"+shardAccessBinding+"\trun\t"+shardSlowPattern)
	for _, shard := range []string{"", "0/1"} {
		o := runShardFixture(t, runIntegrationSource(t), shard, false, false)
		require.Zero(t, o.rc, o.output)
		require.Len(t, o.calls, 1)
		require.NotContains(t, o.calls[0], "-run")
		require.NotContains(t, o.calls[0], "-skip")
		require.Contains(t, o.calls[0], shardAccessBinding)
	}
}

func TestRunIntegrationShardsSignalCannotBecomePass(t *testing.T) {
	for _, mode := range []string{"all", "run"} {
		o := runShardFixture(t, runIntegrationSource(t), "1/5", false, false, "FAKE_SIGNAL="+mode)
		require.Equal(t, 143, o.rc, o.output)
		wantCalls := 1
		if mode == "run" {
			wantCalls = 2
		}
		require.Len(t, o.calls, wantCalls)
	}
}

func TestRunIntegrationShardsPlanValidatorRejectsHolesDuplicatesAndForeignFilters(t *testing.T) {
	marker := "# Отдельный валидатор проверяет полноту, владельцев, фильтры и отсутствие дублей."
	for i, mutation := range []string{
		"rows.pop()",
		"rows.append(rows[0])",
		"rows.append((0, 'unknown', 'all', '-'))",
		"rows[1] = (rows[1][0], rows[1][1], 'run', pattern)",
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			script := runIntegrationSource(t)
			require.Contains(t, script, marker)
			script = strings.Replace(script, marker, mutation+"\n"+marker, 1)
			o := runShardFixture(t, script, "0/5", true, false)
			require.Equal(t, 2, o.rc, o.output)
			require.Empty(t, o.calls)
		})
	}
}
