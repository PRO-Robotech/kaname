// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package check_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/testsupport/execstub"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

const shardAccessBinding = "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
const shardPG = "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
const shardMigrations = "github.com/PRO-Robotech/kaname/internal/migrations"
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
outcome = os.environ.get("FAKE_FIRST_OUTCOME" if mode == "all" else "FAKE_SECOND_OUTCOME", "")
if outcome == "unavailable":
    print("integration Postgres unavailable")
    sys.exit(1)
if outcome == "incomplete":
    print("{broken")
real_fail = os.environ.get("FAKE_FIRST_FAIL" if mode == "all" else "FAKE_SECOND_FAIL") == "1"
for package in (a for a in args if a in packages):
    def emit(action, name=None):
        identity = "example.test/foreign" if os.environ.get("FAKE_DEFECT") == "run-wrong-package" and mode == "run" else package
        event = {"Package": identity, "Action": action}
        if name:
            event["Test"] = name
        print(json.dumps(event))
    emit("start")
    names = ["TestComplement", "ExampleComplement", "FuzzComplement"]
    if os.environ.get("FAKE_TWELVE") == "1":
        names += ["TestFutureAfterSplit", "ExampleFutureAfterSplit", "FuzzFutureAfterSplit", "TestRoleRightsStayNamed_FutureAfterSplit", "TestGrantDelegation_FutureAfterSplit"]
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
    if defect == "skip-selected" and mode == "skip":
        names.append(args[args.index("-skip") + 1][2:-2].split("|")[0])
    if defect == "run-nonjson" and mode == "run":
        print("не-JSON после внешне успешного потока")
    for name in names:
        emit("run", name)
        skipped = defect == "run-skipped" or (defect == "run-one-skipped" and mode == "run" and name == names[-1])
        emit("fail" if real_fail else "skip" if skipped else "pass", name)
        if defect == "run-duplicate" and mode == "run" and name == names[-1]:
            emit("run", name)
            emit("pass", name)
    emit("fail" if real_fail else "pass")
rc = int(os.environ.get("FAKE_FIRST_RC", "0")) if mode == "all" else 0
sys.exit(1 if real_fail else rc)
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
	for _, option := range extra {
		if option == "FAKE_TWELVE=1" {
			packages = append(packages, shardPG, shardMigrations)
			weights += "10 " + shardPG + "\n10 " + shardMigrations + "\n"
		}
		if strings.HasPrefix(option, "FAKE_MIGRATIONS_WEIGHT=") {
			weight, parseErr := strconv.Atoi(strings.TrimPrefix(option, "FAKE_MIGRATIONS_WEIGHT="))
			require.NoError(t, parseErr)
			require.Positive(t, weight)
			packages = append(packages, shardMigrations)
			weights += fmt.Sprintf("%d %s\n", weight, shardMigrations)
		}
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
	for _, first := range []string{"unavailable", "incomplete"} {
		t.Run(first+" then real failure", func(t *testing.T) {
			firstRaw, firstResult := "1\n", 75
			if first == "incomplete" {
				firstRaw, firstResult = "0\n", 2
			}
			// Близнец подтверждает исход первой команды; один факт добавляет RED второй.
			control := runShardFixture(t, runIntegrationSource(t), "1/5", false, false, "FAKE_FIRST_OUTCOME="+first)
			require.Equal(t, firstResult, control.rc, control.output)
			o := runShardFixture(t, runIntegrationSource(t), "1/5", false, false,
				"FAKE_FIRST_OUTCOME="+first, "FAKE_SECOND_FAIL=1")
			require.Equal(t, 1, o.rc, o.output)
			require.Len(t, o.calls, 2)
			require.Equal(t, firstRaw, shardEvidence(t, o, "go-test-packages-exit-code.txt"))
			require.Equal(t, "1\n", shardEvidence(t, o, "go-test-access-binding-exit-code.txt"))
			require.Equal(t, "1\n", shardEvidence(t, o, "runner-exit-code.txt"))
			require.Contains(t, shardEvidence(t, o, "go-test-access-binding.json"), `"Action": "fail"`)
			// Перестановка команд не должна менять доказанный RED.
			reversed := runShardFixture(t, runIntegrationSource(t), "1/5", false, false,
				"FAKE_FIRST_FAIL=1", "FAKE_SECOND_OUTCOME="+first)
			require.Equal(t, 1, reversed.rc, reversed.output)
			require.Len(t, reversed.calls, 2)
			require.Equal(t, "1\n", shardEvidence(t, reversed, "go-test-packages-exit-code.txt"))
			require.Equal(t, firstRaw, shardEvidence(t, reversed, "go-test-access-binding-exit-code.txt"))
			require.Equal(t, "1\n", shardEvidence(t, reversed, "runner-exit-code.txt"))
			require.Contains(t, shardEvidence(t, reversed, "go-test-packages.json"), `"Action": "fail"`)
		})
	}
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

func TestRunIntegrationShardsMigrationsAreExclusiveWithoutLosingTail(t *testing.T) {
	// Малый и большой вес: изоляция не должна зависеть от позиции в сортировке.
	for _, weight := range []string{"1", "200"} {
		t.Run(weight, func(t *testing.T) {
			seen := make(map[string]int)
			for shard := 0; shard < 5; shard++ {
				o := runShardFixture(t, runIntegrationSource(t), fmt.Sprintf("%d/5", shard), false, false,
					"FAKE_MIGRATIONS_WEIGHT="+weight)
				require.Zero(t, o.rc, o.output)
				plan := strings.Split(strings.TrimSpace(shardEvidence(t, o, "execution-plan.tsv")), "\n")
				require.Len(t, plan, 13, "12 владельцев пакетов и одна дополнительная AB часть")
				isolated := 0
				for _, row := range plan {
					fields := strings.Split(row, "\t")
					require.Len(t, fields, 4)
					if fields[0] == "2" {
						require.Equal(t, []string{"2", shardMigrations, "all", "-"}, fields)
						isolated++
					}
				}
				require.Equal(t, 1, isolated)
				if shard == 1 {
					// В маленьком составе 805 с пары уже занимают получателя:
					// обычные пакеты уходят в другие части, но шард не пуст.
					require.Len(t, o.calls, 1)
					require.Contains(t, o.calls[0], "-run")
					require.Equal(t, shardAccessBinding, o.calls[0][len(o.calls[0])-1])
					owners := shardEvidence(t, o, "shard-plan.tsv")
					for _, row := range strings.Split(strings.TrimSpace(owners), "\n") {
						require.False(t, strings.HasPrefix(row, "1\t"), row)
					}
				}
				if shard == 2 {
					require.Len(t, o.calls, 1)
					require.Equal(t, shardMigrations, o.calls[0][len(o.calls[0])-1])
				}
				for _, call := range o.calls {
					require.Contains(t, call, "-race")
					require.Contains(t, strings.Join(call, " "), "-timeout 25m -p 1")
					for i, arg := range call {
						if arg == "-run" || arg == "-skip" {
							require.Equal(t, map[int]string{0: "-skip", 1: "-run"}[shard], arg)
							require.Equal(t, shardSlowPattern, call[i+1])
							require.Equal(t, []string{shardAccessBinding}, call[i+2:])
						}
						if arg == shardAccessBinding || arg == shardMigrations || strings.HasPrefix(arg, "example.test/") {
							seen[arg]++
						}
					}
				}
			}
			want := map[string]int{shardAccessBinding: 2, shardMigrations: 1}
			for i := 0; i < 10; i++ {
				want[fmt.Sprintf("example.test/p%d", i)] = 1
			}
			require.Equal(t, want, seen, "хвост перенесён, а не потерян или повторён")
		})
	}
}

func TestRunIntegrationShardsRejectMigrationsWrongOwnerAndExtraTail(t *testing.T) {
	marker := "# Отдельный валидатор проверяет полноту, владельцев, фильтры и отсутствие дублей."
	for _, mutation := range []struct {
		name string
		code string
		want string
	}{
		{"wrong-owner", "original = [(0 if p == migration else s, p) for s, p in original]\nrows = [(0 if p == migration else s, p, mode, regex) for s, p, mode, regex in rows]", "migrations должен занимать index 2"},
		{"extra-tail", "original = [(2 if p == 'example.test/p0' else s, p) for s, p in original]\nrows = [(2 if p == 'example.test/p0' else s, p, mode, regex) for s, p, mode, regex in rows]", "migrations должен занимать index 2"},
		{"missing-tail", "rows = [row for row in rows if row[1] != 'example.test/p0']", "неполное или повторное исполнение пакета"},
		{"empty-recipient", "rows = [row for row in rows if row[0] != 1]", "неполное или повторное исполнение пакета"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			script := runIntegrationSource(t)
			require.Contains(t, script, marker)
			// Первые две инъекции сохраняют обычную полноту/согласованность
			// original и rows, но нарушают независимый контракт изоляции.
			script = strings.Replace(script, marker, mutation.code+"\n"+marker, 1)
			o := runShardFixture(t, script, "0/5", true, false, "FAKE_MIGRATIONS_WEIGHT=200")
			require.Equal(t, 2, o.rc, o.output)
			require.Contains(t, o.output, mutation.want)
			require.Empty(t, o.calls)
		})
	}
}

func TestRunIntegrationShardsMigrationsOtherTotalsKeepLPT(t *testing.T) {
	for _, total := range []int{1, 2, 3, 4, 6} {
		t.Run(strconv.Itoa(total), func(t *testing.T) {
			o := runShardFixture(t, runIntegrationSource(t), fmt.Sprintf("0/%d", total), true, false,
				"FAKE_MIGRATIONS_WEIGHT=200")
			require.Zero(t, o.rc, o.output)
			require.Empty(t, o.calls)
			// При другом N самый тяжёлый пакет по-прежнему начинает LPT на 0.
			plan := shardEvidence(t, o, "execution-plan.tsv")
			require.Contains(t, plan, "0\t"+shardMigrations+"\tall\t-\n")
			wantUnits := 13
			if total == 1 {
				wantUnits = 12
				require.NotContains(t, plan, "\trun\t")
				require.NotContains(t, plan, "\tskip\t")
			}
			require.Len(t, strings.Split(strings.TrimSpace(plan), "\n"), wantUnits)
		})
	}
}

// Каждый будущий неизвестный Test/Example/Fuzz обязан остаться только в дополнении.
func TestRunIntegrationShardsTwelvePartsCoverOwnersAndFutureCases(t *testing.T) {
	seen := make(map[string]int)
	var execution string
	for shard := 0; shard < 12; shard++ {
		o := runShardFixture(t, runIntegrationSource(t), fmt.Sprintf("%d/12", shard), false, false, "FAKE_TWELVE=1")
		require.Zero(t, o.rc, o.output)
		plan := shardEvidence(t, o, "execution-plan.tsv")
		if shard == 0 {
			execution = plan
		}
		require.Equal(t, execution, plan, "все задания строят один полный план")
		rows := strings.Split(strings.TrimSpace(plan), "\n")
		require.Len(t, rows, 19, "13 владельцев и шесть дополнительных единиц")
		owners := make(map[string]int)
		for _, row := range strings.Split(strings.TrimSpace(shardEvidence(t, o, "shard-plan.tsv")), "\n") {
			fields := strings.Split(row, "\t")
			require.Len(t, fields, 3)
			owners[fields[2]]++
		}
		require.Len(t, owners, 13)
		for name, count := range owners {
			require.Equal(t, 1, count, name)
		}
		units := 0
		for _, row := range rows {
			fields := strings.Split(row, "\t")
			require.Len(t, fields, 4)
			if fields[0] == strconv.Itoa(shard) {
				units++
			}
			// Отпечатки фиксируют полный reviewed exact set, а не разрешают весь prefix.
			if fields[1] == shardAccessBinding && (fields[0] == "1" || fields[0] == "3") {
				require.Equal(t, "run", fields[2])
				wantCount, wantHash := 21, "e382e381f8274d0083b49fc83a6393c1d1430478ca66a3cae19d924f29aa50fd"
				if fields[0] == "3" {
					wantCount, wantHash = 65, "dda2da13c8d30fb257c96d884f25b945787e8885cb3648c87252b5b94daac310"
				}
				require.Len(t, strings.Split(fields[3][2:len(fields[3])-2], "|"), wantCount)
				require.Equal(t, wantHash, fmt.Sprintf("%x", sha256.Sum256([]byte(fields[3]))), "точный состав перенесённой части")
			}
			if fields[1] == shardAccessBinding && fields[0] == "4" {
				require.Equal(t, "skip", fields[2])
				require.Regexp(t, fields[3], "TestRoleRights_S1P8_ActualGrantReadPlans", "дополнение не повторяет перенесённый TOP")
			}
			if fields[0] == "2" || fields[1] == shardMigrations {
				require.Equal(t, []string{"2", shardMigrations, "all", "-"}, fields)
			}
		}
		require.Positive(t, units, "непустота судится по исполнению")
		require.NotEmpty(t, o.calls)
		for _, call := range o.calls {
			require.Contains(t, call, "-race")
			require.Contains(t, strings.Join(call, " "), "-timeout 25m -p 1")
			for _, arg := range call {
				if arg == shardAccessBinding || arg == shardPG || arg == shardMigrations || strings.HasPrefix(arg, "example.test/") {
					seen[arg]++
				}
			}
		}
		if (shard != 2 && shard < 8) || shard == 11 {
			raw := shardEvidence(t, o, fmt.Sprintf("go-test-partition-%d.json", shard))
			if shard == 3 {
				require.Contains(t, raw, "TestRoleRights_S1P8_ActualGrantReadPlans")
				require.Contains(t, raw, "TestFullBind_FB31_SourceExpiryAfterHeldWriterClockDoesNotShortenGrant")
			}
			if shard == 11 {
				require.Contains(t, raw, "TestFullServiceAccountStateWholeAttemptInjectedBodyOutcomes")
				require.Contains(t, raw, "TestRoleActualUpdateFinalDecisionAfterLegacyWait")
			}
			for _, future := range []string{"TestFutureAfterSplit", "ExampleFutureAfterSplit", "FuzzFutureAfterSplit", "TestRoleRightsStayNamed_FutureAfterSplit", "TestGrantDelegation_FutureAfterSplit"} {
				if shard == 4 || shard == 7 {
					require.Contains(t, raw, future)
				} else {
					require.NotContains(t, raw, future)
				}
			}
		}
	}
	want := map[string]int{shardAccessBinding: 4, shardPG: 4, shardMigrations: 1}
	for i := 0; i < 10; i++ {
		want[fmt.Sprintf("example.test/p%d", i)] = 1
	}
	require.Equal(t, want, seen)
	for _, pkg := range []string{shardAccessBinding, shardPG} {
		var selectors []*regexp.Regexp
		var modes []string
		candidates := []string{"TestFutureAfterSplit", "ExampleFutureAfterSplit", "FuzzFutureAfterSplit", "TestRoleRights_S1P8_ActualGrantReadPlans", "TestRoleRights_S1P8_ActualGrantReadPlansFuture", "TestRoleRightsStayNamed_FutureAfterSplit", "TestGrantDelegation_FutureAfterSplit"}
		for _, row := range strings.Split(strings.TrimSpace(execution), "\n") {
			fields := strings.Split(row, "\t")
			if fields[1] != pkg {
				continue
			}
			require.True(t, strings.HasPrefix(fields[3], "^(") && strings.HasSuffix(fields[3], ")$"))
			selectors = append(selectors, regexp.MustCompile(fields[3]))
			modes = append(modes, fields[2])
			if fields[2] == "run" {
				candidates = append(candidates, strings.Split(fields[3][2:len(fields[3])-2], "|")...)
			}
		}
		for _, name := range candidates {
			count := 0
			for i, selector := range selectors {
				matches := selector.MatchString(name)
				if modes[i] == "skip" {
					matches = !matches
				}
				if matches {
					count++
				}
			}
			require.Equal(t, 1, count, pkg+"::"+name)
		}
	}
}

func TestRunIntegrationShardsTwelveNamedPartsFailClosed(t *testing.T) {
	script := runIntegrationSource(t)
	// Двойники используют отдельные песочницы. Держим не больше двух
	// одновременно, включая их очистку.
	slots := make(chan struct{}, 2)
	for _, shard := range []int{0, 1, 3, 5, 11} {
		for _, defect := range []string{"run-empty", "run-missing", "run-renamed", "run-skipped", "run-one-skipped", "run-duplicate", "run-nonjson", "run-wrong-package"} {
			t.Run(fmt.Sprintf("%d/%s", shard, defect), func(t *testing.T) {
				t.Parallel()
				slots <- struct{}{}
				t.Cleanup(func() { <-slots })
				o := runShardFixture(t, script, fmt.Sprintf("%d/12", shard), false, false,
					"FAKE_TWELVE=1", "FAKE_DEFECT="+defect)
				require.Equal(t, 2, o.rc, o.output)
			})
		}
	}
	for _, shard := range []int{4, 7} {
		o := runShardFixture(t, script, fmt.Sprintf("%d/12", shard), false, false,
			"FAKE_TWELVE=1", "FAKE_DEFECT=skip-selected")
		require.Equal(t, 2, o.rc, o.output)
	}
}

func TestRunIntegrationShardsTwelvePlanRejectsLostDuplicateAndForeignUnits(t *testing.T) {
	marker := "# Независимая проверка 12 частей: владельцы и единицы исполнения различаются."
	for i, mutation := range []string{
		"rows.pop()",
		"rows.append(rows[0])",
		"owners.append(owners[0])",
		"owners[0] = (1, owners[0][1], owners[0][2])",
		"rows = [(2 if p == ab else s, p, mode, regex) for s, p, mode, regex in rows]",
		"rows[0] = (rows[0][0], rows[0][1], 'skip', '^(TestFutureAfterSplit)$')",
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			script := runIntegrationSource(t)
			require.Contains(t, script, marker)
			script = strings.Replace(script, marker, mutation+"\n"+marker, 1)
			o := runShardFixture(t, script, "0/12", true, false, "FAKE_TWELVE=1")
			require.Equal(t, 2, o.rc, o.output)
			require.Empty(t, o.calls)
		})
	}
}
