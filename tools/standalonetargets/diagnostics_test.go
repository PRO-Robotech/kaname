// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package standalonetargets_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
	"github.com/PRO-Robotech/kaname/tools/standalonetargets"
)

// Поток строится в форме настоящего go test -json; сам producer не подменяется.
func diagnosticEvent(action, pkg, test, output string) string {
	e := map[string]string{"Action": action, "Package": pkg}
	if test != "" {
		e["Test"] = test
	}
	if output != "" {
		e["Output"] = output
	}
	body, err := json.Marshal(e)
	if err != nil {
		panic(err)
	}
	return string(body) + "\n"
}

type diagnosticResult struct {
	code    int
	output  string
	capture string
}

// Внешний каталог переживает удаление фикстуры; PATH меняется лишь у дочернего процесса.
func runDiagnosticProducer(t *testing.T, stdout, stderr string, goCode int, brokenParser, brokenCapture bool) diagnosticResult {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	root, err := standalonetargets.ModuleRootFrom(wd)
	require.NoError(t, err)
	fixture := t.TempDir()
	capture, err := os.MkdirTemp(t.TempDir(), "target-")
	require.NoError(t, err)
	if brokenCapture {
		capture = filepath.Join(capture, "не-каталог")
		require.NoError(t, os.WriteFile(capture, []byte("занято"), 0o600))
	}
	bin := filepath.Join(fixture, "bin")
	require.NoError(t, os.Mkdir(bin, 0o700))
	for name, body := range map[string]string{"stdout": stdout, "stderr": stderr} {
		require.NoError(t, os.WriteFile(filepath.Join(fixture, name), []byte(body), 0o600))
	}
	fake := "#!/bin/bash\nprintf '%s\\n' \"$@\" > \"$DIAGNOSTIC_FIXTURE/args\"\n" +
		"cat \"$DIAGNOSTIC_FIXTURE/stdout\"\ncat \"$DIAGNOSTIC_FIXTURE/stderr\" >&2\n" +
		fmt.Sprintf("exit %d\n", goCode)
	require.NoError(t, os.WriteFile(filepath.Join(bin, "go"), []byte(fake), 0o700))
	if brokenParser {
		require.NoError(t, os.WriteFile(filepath.Join(bin, "python3"),
			[]byte("#!/bin/bash\necho 'разборщик отказал: контроль' >&2\nexit 7\n"), 0o700))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", filepath.Join(root, "scripts/test-standalone.sh"))
	cmd.Dir = fixture
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if key != "PATH" && key != "STANDALONE_DIAGNOSTICS_DIR" && key != "DIAGNOSTIC_FIXTURE" {
			cmd.Env = append(cmd.Env, item)
		}
	}
	cmd.Env = append(cmd.Env, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"DIAGNOSTIC_FIXTURE="+fixture, "STANDALONE_DIAGNOSTICS_DIR="+capture)
	out, runErr := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "фикстура producer превысила ограничение времени")
	code := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		require.ErrorAs(t, runErr, &exitErr, "producer не запустился")
		code = exitErr.ExitCode()
	}
	args, readErr := os.ReadFile(filepath.Join(fixture, "args"))
	if !brokenCapture && !brokenParser {
		require.NoError(t, readErr, "фикстура не дошла до fake-go")
		require.Equal(t, "test\n./...\n-short\n-count=1\n-json\n", string(args), "изменился судимый набор или флаги")
	}
	require.NoError(t, os.RemoveAll(fixture))
	t.Logf("producer: код %d, вывод %d байт; внешний capture %s", code, len(out), capture)
	return diagnosticResult{code: code, output: string(out), capture: capture}
}

func TestStandaloneDiagnosticPreservesCallerUmask(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)
	root, err := standalonetargets.ModuleRootFrom(wd)
	require.NoError(t, err)
	for _, tc := range []struct {
		mask string
		mode os.FileMode
	}{
		{mask: "022", mode: 0o644},
		{mask: "077", mode: 0o600},
	} {
		t.Run("маска_вызывающей_оболочки_"+tc.mask, func(t *testing.T) {
			base := t.TempDir()
			fixture, capture := filepath.Join(base, "fixture"), filepath.Join(base, "private")
			bin := filepath.Join(fixture, "bin")
			require.NoError(t, os.MkdirAll(bin, 0o700))
			stream := diagnosticEvent("run", "example.test/umask", "TestContext", "") +
				diagnosticEvent("pass", "example.test/umask", "TestContext", "") + diagnosticEvent("pass", "example.test/umask", "", "")
			require.NoError(t, os.WriteFile(filepath.Join(fixture, "stdout"), []byte(stream), 0o600))
			// Обычная shell-redirection создаёт файл с 0666, ограниченными унаследованной маской.
			fake := "#!/bin/bash\nset -eu\n: > \"$DIAGNOSTIC_FIXTURE/child-file\"\numask > \"$DIAGNOSTIC_FIXTURE/child-mask\"\ncat \"$DIAGNOSTIC_FIXTURE/stdout\"\n"
			require.NoError(t, os.WriteFile(filepath.Join(bin, "go"), []byte(fake), 0o700))
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			// Маска меняется только в явном subprocess, никогда в процессе Go test.
			cmd := exec.CommandContext(ctx, "bash", "--noprofile", "--norc", "-c",
				`umask "$1"; : > "$DIAGNOSTIC_FIXTURE/caller-file"; exec bash "$2"`,
				"контроль-umask", tc.mask, filepath.Join(root, "scripts/test-standalone.sh"))
			cmd.Dir = fixture
			for _, item := range os.Environ() {
				key, _, _ := strings.Cut(item, "=")
				if key != "PATH" && key != "STANDALONE_DIAGNOSTICS_DIR" && key != "DIAGNOSTIC_FIXTURE" {
					cmd.Env = append(cmd.Env, item)
				}
			}
			cmd.Env = append(cmd.Env, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"DIAGNOSTIC_FIXTURE="+fixture, "STANDALONE_DIAGNOSTICS_DIR="+capture)
			out, runErr := cmd.CombinedOutput()
			require.NoError(t, ctx.Err())
			require.NoError(t, runErr, "законный поток не захвачен: %s", out)
			caller, err := os.Stat(filepath.Join(fixture, "caller-file"))
			require.NoError(t, err)
			require.Equal(t, tc.mode, caller.Mode().Perm(), "предпосылка: оболочка не установила заданную маску")
			child, err := os.Stat(filepath.Join(fixture, "child-file"))
			require.NoError(t, err)
			assert.Equal(t, tc.mode, child.Mode().Perm(), "collector изменил файловую семантику дочернего Go")
			mask, err := os.ReadFile(filepath.Join(fixture, "child-mask"))
			require.NoError(t, err)
			assert.Equal(t, "0"+tc.mask, strings.TrimSpace(string(mask)), "дочерний процесс получил другую umask")
			files := 0
			require.NoError(t, filepath.WalkDir(capture, func(path string, entry fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				info, err := entry.Info()
				if err != nil {
					return err
				}
				if entry.IsDir() {
					assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(), "приватный каталог: %s", path)
				} else {
					files++
					assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "приватный файл: %s", path)
				}
				return nil
			}))
			assert.Equal(t, 5, files, "проверены все пять файлов полного приватного capture")
		})
	}
}

// Этот мост использует действительный runner; authority не берётся из marker.
func diagnosticRunTarget(t *testing.T, dir string) ([]standalonetargets.Finding, []standalonetargets.Unmet, error) {
	t.Helper()
	return standalonetargets.RunTargetsWithCapture(dir, []standalonetargets.Target{{Name: "test-standalone", Desc: "пробы"}}, makeCaptureRunner(t))
}

func TestStandaloneDiagnosticInvocationBoundary(t *testing.T) {
	const pkg, name = "example.test/authority", "TestContext"
	baseline := runDiagnosticProducer(t, diagnosticEvent("fail", pkg, name, "")+diagnosticEvent("fail", pkg, "", ""), "", 1, false, false)
	manifest, _, _ := criticalDiagnosticDocuments(t, baseline)
	foreign, err := os.MkdirTemp(t.TempDir(), "target-")
	require.NoError(t, err)
	foreignProducer := filepath.Join(foreign, "producer-foreign")
	require.NoError(t, os.Mkdir(foreignProducer, 0o700))
	for _, filename := range []string{"manifest.json", "stdout.jsonl", "stderr.log", "go.rc", "census.json"} {
		body, err := os.ReadFile(filepath.Join(filepath.Dir(manifest), filename))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(foreignProducer, filename), body, 0o600))
	}
	for _, mode := range []string{"owned", "foreign-target", "escape", "producer-symlink", "manifest-symlink", "sidecar-symlink", "public-file", "public-directory"} {
		t.Run(mode, func(t *testing.T) {
			fixture, capture := t.TempDir(), t.TempDir()
			t.Setenv("STANDALONE_DIAGNOSTICS_DIR", capture)
			t.Setenv("DIAGNOSTIC_FOREIGN", foreignProducer)
			t.Setenv("DIAGNOSTIC_MODE", mode)
			// Все байты и hashes законны; меняется только связь с текущим owned target.
			script := `#!/bin/bash
set -eu
owned="$STANDALONE_DIAGNOSTICS_DIR/producer-owned"
mkdir -m 700 "$owned"
cp "$DIAGNOSTIC_FOREIGN/"* "$owned/"
chmod 600 "$owned/"*
marker="$owned/manifest.json"
case "$DIAGNOSTIC_MODE" in
foreign-target) marker="$DIAGNOSTIC_FOREIGN/manifest.json" ;;
escape) marker="$owned/../producer-owned/manifest.json" ;;
producer-symlink) mv "$owned" "$STANDALONE_DIAGNOSTICS_DIR/real-producer"; ln -s real-producer "$owned" ;;
manifest-symlink) mv "$marker" "$owned/real-manifest"; ln -s real-manifest "$marker" ;;
sidecar-symlink) mv "$owned/stdout.jsonl" "$owned/real-stdout"; ln -s real-stdout "$owned/stdout.jsonl" ;;
public-file) chmod 644 "$owned/stdout.jsonl" ;;
public-directory) chmod 755 "$owned" ;;
esac
printf 'Диагностика standalone: %s\n' "$marker"
exit 1
`
			require.NoError(t, os.WriteFile(filepath.Join(fixture, "control.sh"), []byte(script), 0o700))
			require.NoError(t, os.WriteFile(filepath.Join(fixture, "Makefile"), []byte("test-standalone:\n\t@bash control.sh\n"), 0o600))
			findings, unmet, err := diagnosticRunTarget(t, fixture)
			require.NoError(t, err)
			require.Empty(t, unmet)
			require.Len(t, findings, 1)
			if mode == "owned" {
				assert.True(t, findings[0].Probes, "законный текущий capture потерял классификацию")
				assert.Contains(t, findings[0].String(), "именованные отказы")
			} else {
				assert.False(t, findings[0].Probes, "чужой либо небезопасный capture объявлен доказательством текущего запуска")
				assert.Contains(t, findings[0].String(), "неизвестный исход")
			}
		})
	}
}

func diagnosticFiles(t *testing.T, dir string) string {
	t.Helper()
	var body strings.Builder
	require.NoError(t, filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		body.Write(data)
		body.WriteByte('\n')
		return nil
	}))
	return body.String()
}

func diagnosticFinding(t *testing.T, result diagnosticResult, nestedOutput string) string {
	t.Helper()
	findings, unmet, err := standalonetargets.RunTargetsWithCapture("синтетическая посадка",
		[]standalonetargets.Target{{Name: "test-standalone", Desc: "пробы модуля"}},
		diagnosticCaptureCallback(t, result, nestedOutput))
	require.NoError(t, err)
	assert.Empty(t, unmet, "отказ пакета превратился в необязательный третий исход")
	if !assert.Len(t, findings, 1, "отказ producer исчез из находок") {
		return ""
	}
	return findings[0].String()
}

// Фикстура владеет capture независимо от marker; consumer получает handle напрямую.
func diagnosticCaptureCallback(t *testing.T, result diagnosticResult, suffix string) func(string, string) (standalonetargets.TargetResult, error) {
	t.Helper()
	return func(_, _ string) (standalonetargets.TargetResult, error) {
		root, _ := os.OpenRoot(result.capture)
		return standalonetargets.TargetResult{Code: result.code, Output: result.output + suffix, Capture: root}, nil
	}
}

// Проверяется диагностический смысл, а не форма нового manifest: имя доступно читателю
// либо непосредственно в находке, либо по явно напечатанному внешнему пути.
func assertDiagnosticReachable(t *testing.T, finding string, result diagnosticResult, identities []string) {
	t.Helper()
	readable := finding
	if strings.Contains(finding, result.capture) {
		readable += diagnosticFiles(t, result.capture)
	}
	for _, identity := range identities {
		assert.Contains(t, readable, identity, "outer gate потерял диагностическую единицу")
	}
}

func TestStandaloneDiagnosticPackageOnlyPreservesPrimaryEvidence(t *testing.T) {
	const pkgA = "example.test/diagnostic/packageA"
	const pkgB = "example.test/diagnostic/packageB"
	const primaryA = "первичный отказ альфа: контроль-A"
	const primaryB = "первичный отказ бета: контроль-B"
	const stderr = "не-JSON stderr: контроль-C\n"
	stream := diagnosticEvent("output", pkgA, "", primaryA+"\n") + diagnosticEvent("fail", pkgA, "", "") +
		diagnosticEvent("output", pkgB, "", primaryB+"\n") + diagnosticEvent("fail", pkgB, "", "")
	result := runDiagnosticProducer(t, stream, stderr, 1, false, false)
	assert.NotZero(t, result.code)
	finding := diagnosticFinding(t, result, "")
	assertDiagnosticReachable(t, finding, result, []string{pkgA, pkgB, primaryA, primaryB})
	raw := diagnosticFiles(t, result.capture)
	assert.Contains(t, raw, stream, "исходный JSONL утрачен после удаления фикстуры")
	assert.Contains(t, raw, stderr, "исходный stderr утрачен после удаления фикстуры")
	assert.False(t, standalonetargets.IsProbeFailure(result.output), "ноль named failures объявлен падением именованных проб")
	for _, text := range []string{"пакет не собрался", "делят кэш", "ДОШЛА ДО КОНЦА", "те же пробы красны"} {
		assert.NotContains(t, result.output+finding, text, "причина назначена без первичных доказательств")
	}
}

func TestStandaloneDiagnosticMixedFailuresKeepEveryIdentity(t *testing.T) {
	const pkgA = "example.test/diagnostic/namedA"
	const pkgB = "example.test/diagnostic/packageOnlyB"
	const primary = "первая причина до хвоста: контроль-45"
	stream := diagnosticEvent("output", pkgA, "TestFailure00", primary+"\n")
	identities := []string{pkgA, pkgB, primary, "безымянная причина B"}
	for i := 0; i < 45; i++ {
		name := fmt.Sprintf("TestFailure%02d", i)
		stream += diagnosticEvent("fail", pkgA, name, "")
		identities = append(identities, name)
	}
	stream += diagnosticEvent("fail", pkgA, "", "") +
		diagnosticEvent("output", pkgB, "", "безымянная причина B\n") + diagnosticEvent("fail", pkgB, "", "")
	result := runDiagnosticProducer(t, stream, "", 1, false, false)
	assert.NotZero(t, result.code)
	finding := diagnosticFinding(t, result, "")
	assertDiagnosticReachable(t, finding, result, identities)
	assert.Contains(t, diagnosticFiles(t, result.capture), stream, "полный поток смешанных отказов не сохранён")
}

func TestStandaloneDiagnosticIncompleteNeverPasses(t *testing.T) {
	pass := diagnosticEvent("pass", "example.test/diagnostic/pass", "TestPass", "") +
		diagnosticEvent("pass", "example.test/diagnostic/pass", "", "")
	for _, tc := range []struct {
		name    string
		stream  string
		goCode  int
		parser  bool
		capture bool
	}{
		{name: "повреждённое событие после успеха", stream: pass + "{повреждённый-json}\n"},
		{name: "не-JSON stdout после успеха", stream: pass + "потерянный текст вне JSON\n"},
		{name: "нет терминала второго пакета", stream: pass + diagnosticEvent("start", "example.test/unfinished", "", "")},
		{name: "нет терминала начатой пробы", stream: diagnosticEvent("run", "example.test/pending", "TestPending", "") + diagnosticEvent("pass", "example.test/pending", "", "")},
		{name: "ошибка разборщика после успеха", stream: pass, parser: true},
		{name: "невозможность capture после успеха", stream: pass, capture: true},
		{name: "Go отказал без терминального пакета", stream: diagnosticEvent("start", "example.test/diagnostic/unfinished", "", ""), goCode: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := runDiagnosticProducer(t, tc.stream, "", tc.goCode, tc.parser, tc.capture)
			assert.NotZero(t, result.code, "неполная диагностика выдала успех")
			assert.NotContains(t, result.output, "пробы модуля зелены", "ошибка диагностики названа зелёным прогоном")
		})
	}
}

func TestStandaloneDiagnosticPackageFailureCannotBecomeUnmet(t *testing.T) {
	stream := diagnosticEvent("output", "example.test/diagnostic/failure", "", "первичный отказ\n") +
		diagnosticEvent("fail", "example.test/diagnostic/failure", "", "")
	result := runDiagnosticProducer(t, stream, "", 1, false, false)
	assert.NotZero(t, result.code)
	// Соседний вложенный вывод не имеет права снять structured failure producer.
	diagnosticFinding(t, result, "\nУСЛОВИЕ НЕ СОЗДАНО: строка соседней вложенной проверки\n")
}

func TestStandaloneDiagnosticPositiveTwinCountsBothSkipKinds(t *testing.T) {
	const pkg = "example.test/diagnostic/twin"
	stream := diagnosticEvent("pass", pkg, "TestPass", "") +
		diagnosticEvent("output", pkg, "TestUnmet", "УСЛОВИЕ НЕ СОЗДАНО: синтетическая предпосылка\n") +
		diagnosticEvent("skip", pkg, "TestUnmet", "") +
		diagnosticEvent("output", pkg, "TestShort", "обычный short-пропуск\n") +
		diagnosticEvent("skip", pkg, "TestShort", "") + diagnosticEvent("pass", pkg, "", "")
	result := runDiagnosticProducer(t, stream, "", 0, false, false)
	assert.Zero(t, result.code, result.output)
	assert.Contains(t, result.output, "пакетов исполнено 1")
	assert.Contains(t, result.output, "пакетов с отказом 0")
	assert.Contains(t, result.output, "по непостроенной предпосылке 1")
	assert.Contains(t, result.output, "пропущено по флагам прогона 1")
	assert.Contains(t, result.output, "проб упало 0")
	findings, unmet, err := standalonetargets.RunTargets("синтетическая посадка",
		[]standalonetargets.Target{{Name: "test-standalone", Desc: "пробы модуля"}},
		func(_, _ string) (int, string, error) { return result.code, result.output, nil })
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.Empty(t, unmet)
}

func TestStandaloneDiagnosticRunnerProducerExportKeepsBothInvocations(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)
	root, err := standalonetargets.ModuleRootFrom(wd)
	require.NoError(t, err)
	fixture, capture := t.TempDir(), t.TempDir()
	bin := filepath.Join(fixture, "bin")
	require.NoError(t, os.Mkdir(bin, 0o700))
	stream := diagnosticEvent("output", "example.test/runner", "", "первичная причина из runner\n") +
		diagnosticEvent("fail", "example.test/runner", "", "")
	require.NoError(t, os.WriteFile(filepath.Join(fixture, "events"), []byte(stream), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(bin, "go"),
		[]byte("#!/bin/bash\ncat \"$DIAGNOSTIC_EVENTS\"\nexit 1\n"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(fixture, "Makefile"),
		[]byte("test-standalone:\n\t@bash '"+filepath.Join(root, "scripts/test-standalone.sh")+"'\n"), 0o600))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DIAGNOSTIC_EVENTS", filepath.Join(fixture, "events"))
	t.Setenv("STANDALONE_DIAGNOSTICS_DIR", capture)
	for i := 0; i < 2; i++ {
		code, out, err := makeRunner(t)(fixture, "test-standalone")
		require.NoError(t, err)
		require.NotZero(t, code)
		require.Contains(t, out, capture, "runner не передал внешний путь producer")
	}
	require.NoError(t, os.RemoveAll(fixture))
	entries, err := os.ReadDir(capture)
	require.NoError(t, err)
	require.Len(t, entries, 2, "повторный invocation перезаписал capture")
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(capture, entry.Name(), "target.log"))
		require.NoError(t, err)
		require.Contains(t, string(body), "Диагностика standalone:")
	}
	public := filepath.Join(t.TempDir(), "public")
	cmd := exec.Command("python3", filepath.Join(root, ".github/scripts/standalone-diagnostics.py"), capture, public)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "настоящий exporter отказал на сохранённом runner→producer capture: %s", out)
	var report struct {
		Complete bool              `json:"complete"`
		Captures []json.RawMessage `json:"captures"`
	}
	body, err := os.ReadFile(filepath.Join(public, "export.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(body, &report))
	require.True(t, report.Complete)
	require.Len(t, report.Captures, 4, "exporter потерял runner или producer одного запуска")
	require.Contains(t, diagnosticFiles(t, public), "первичная причина из runner")
}

func TestStandaloneDiagnosticInterruptionLeavesIncompleteRaw(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)
	root, err := standalonetargets.ModuleRootFrom(wd)
	require.NoError(t, err)
	fixture, capture := t.TempDir(), t.TempDir()
	bin := filepath.Join(fixture, "bin")
	require.NoError(t, os.Mkdir(bin, 0o700))
	stream := diagnosticEvent("output", "example.test/interrupted", "", "байты до прерывания\n")
	require.NoError(t, os.WriteFile(filepath.Join(fixture, "events"), []byte(stream), 0o600))
	// Сигнал посылается после записи байтов; временная задержка не нужна.
	fake := "#!/bin/bash\ncat \"$DIAGNOSTIC_EVENTS\"\nkill -TERM \"$PPID\"\nexit 143\n"
	require.NoError(t, os.WriteFile(filepath.Join(bin, "go"), []byte(fake), 0o700))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", filepath.Join(root, "scripts/test-standalone.sh"))
	cmd.Dir = fixture
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if key != "PATH" && key != "STANDALONE_DIAGNOSTICS_DIR" && key != "DIAGNOSTIC_EVENTS" {
			cmd.Env = append(cmd.Env, item)
		}
	}
	cmd.Env = append(cmd.Env, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"STANDALONE_DIAGNOSTICS_DIR="+capture, "DIAGNOSTIC_EVENTS="+filepath.Join(fixture, "events"))
	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err())
	require.Error(t, err, "прерывание превратилось в успех: %s", out)
	require.NoError(t, os.RemoveAll(fixture))
	require.Contains(t, diagnosticFiles(t, capture), stream, "байты до сигнала потеряны")
	manifests, err := filepath.Glob(filepath.Join(capture, "producer-*", "manifest.json"))
	require.NoError(t, err)
	require.Len(t, manifests, 1)
	body, err := os.ReadFile(manifests[0])
	require.NoError(t, err)
	var m struct {
		Complete bool `json:"complete"`
		GoRC     *int `json:"goRC"`
	}
	require.NoError(t, json.Unmarshal(body, &m))
	require.False(t, m.Complete, "прерванный поток назван завершённым")
	require.NotNil(t, m.GoRC)
	require.NotZero(t, *m.GoRC)
}

func TestStandaloneDiagnosticUserMarkersCannotForgeClassification(t *testing.T) {
	stream := diagnosticEvent("output", "example.test/pass", "TestPass", "ПРОБЫ УПАЛИ: проза\nУСЛОВИЕ НЕ СОЗДАНО: проза\n") +
		diagnosticEvent("pass", "example.test/pass", "TestPass", "") + diagnosticEvent("pass", "example.test/pass", "", "")
	result := runDiagnosticProducer(t, stream, "", 0, false, false)
	require.Zero(t, result.code, result.output)
	// Даже метка в начале строки без подтверждённого capture не доказывает named failure.
	findings, unmet, err := standalonetargets.RunTargets("синтетическая посадка",
		[]standalonetargets.Target{{Name: "test-standalone", Desc: "пробы"}},
		func(_, _ string) (int, string, error) {
			return 2, "ПРОБЫ УПАЛИ: проза\nУСЛОВИЕ НЕ СОЗДАНО: проза\n", nil
		})
	require.NoError(t, err)
	require.Empty(t, unmet)
	require.Len(t, findings, 1)
	require.False(t, findings[0].Probes)
	require.Contains(t, findings[0].String(), "неизвестный исход")
}

func TestStandaloneDiagnosticMissingGoNamesToolFailure(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)
	root, err := standalonetargets.ModuleRootFrom(wd)
	require.NoError(t, err)
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)
	cmd := exec.Command(bash, filepath.Join(root, "scripts/test-standalone.sh"))
	cmd.Env = []string{"PATH=" + t.TempDir()}
	out, err := cmd.CombinedOutput()
	require.Error(t, err)
	require.Contains(t, string(out), "go не найден")
	require.False(t, standalonetargets.IsProbeFailure(string(out)))
}

func TestStandaloneDiagnosticBuildFailureIsPackageFailure(t *testing.T) {
	stream := diagnosticEvent("build-output", "example.test/build", "", "первичный вывод сборки\n") +
		diagnosticEvent("build-fail", "example.test/build", "", "")
	result := runDiagnosticProducer(t, stream, "", 1, false, false)
	require.NotZero(t, result.code)
	finding := diagnosticFinding(t, result, "")
	require.Contains(t, finding, "отказы пакетов")
	require.False(t, standalonetargets.IsProbeFailure(result.output))
	assertDiagnosticReachable(t, finding, result, []string{"example.test/build", "первичный вывод сборки"})
}

func TestStandaloneDiagnosticRunnerStreamsBeforeCompletion(t *testing.T) {
	fixture, capture := t.TempDir(), t.TempDir()
	t.Setenv("STANDALONE_DIAGNOSTICS_DIR", capture)
	// Проверяющий процесс читается из самого recipe до его завершения.
	probe := "import json,os,pathlib; p=pathlib.Path(os.environ['STANDALONE_DIAGNOSTICS_DIR']); " +
		"assert json.loads((p/'runner.json').read_text())['complete'] is False; " +
		"assert 'байты до конца' in (p/'target.log').read_text(); print('поток прочитан до завершения')"
	makefile := "show:\n\t@echo 'байты до конца'\n\t@python3 -c \"" + probe + "\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(fixture, "Makefile"), []byte(makefile), 0o600))
	code, out, err := makeRunner(t)(fixture, "show")
	require.NoError(t, err)
	require.Zero(t, code, out)
	require.Contains(t, out, "поток прочитан до завершения")
}

func criticalDiagnosticDocuments(t *testing.T, result diagnosticResult) (string, map[string]any, map[string]any) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(result.capture, "producer-*", "manifest.json"))
	require.NoError(t, err)
	require.Len(t, paths, 1)
	documents := make([]map[string]any, 2)
	for i, path := range []string{paths[0], filepath.Join(filepath.Dir(paths[0]), "census.json")} {
		body, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &documents[i]))
	}
	return paths[0], documents[0], documents[1]
}

func criticalDiagnosticWrite(t *testing.T, path string, value any) {
	t.Helper()
	body, err := json.Marshal(value)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, body, 0o600))
}

func TestStandaloneDiagnosticCriticalBuildEventsSeparateImportPath(t *testing.T) {
	const pkg = "example.test/build"
	const build = "example.test/build [example.test/build.test]"
	t.Run("законный близнец без build-output", func(t *testing.T) {
		result := runDiagnosticProducer(t, diagnosticEvent("start", pkg, "", "")+diagnosticEvent("pass", pkg, "", ""), "", 0, false, false)
		_, manifest, census := criticalDiagnosticDocuments(t, result)
		assert.Zero(t, result.code)
		assert.Equal(t, true, manifest["complete"])
		assert.Empty(t, census["unterminatedPackages"])
	})
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprintf("отказ=%t", failed), func(t *testing.T) {
			buildPath := "example.test/dependency"
			if failed {
				buildPath = build
			}
			event, err := json.Marshal(map[string]string{"Action": "build-output", "ImportPath": buildPath, "Output": "первичный вывод сборки\n"})
			require.NoError(t, err)
			stream := string(event) + "\n"
			code, action := 0, "pass"
			if failed {
				// Точная форма BuildEvent: ImportPath, затем связь FailedBuild в TestEvent.
				stream += string(event) + "\n" + `{"Action":"build-fail","ImportPath":"` + build + `"}` + "\n"
				code, action = 1, "fail"
			}
			stream += diagnosticEvent("start", pkg, "", "") + diagnosticEvent("output", pkg, "", "контекст пакета\n")
			terminal := map[string]string{"Action": action, "Package": pkg}
			if failed {
				terminal["FailedBuild"] = build
			}
			body, err := json.Marshal(terminal)
			require.NoError(t, err)
			stream += string(body) + "\n"
			result := runDiagnosticProducer(t, stream, "", code, false, false)
			_, manifest, census := criticalDiagnosticDocuments(t, result)
			assert.Equal(t, true, manifest["complete"], "build-output не требует несуществующего build-pass")
			assert.Empty(t, census["unterminatedPackages"])
			if failed {
				assert.Equal(t, []any{pkg}, census["failedPackages"], "один тестовый пакет посчитан дважды через build identity")
				assertDiagnosticReachable(t, diagnosticFinding(t, result, ""), result, []string{pkg, build, "первичный вывод сборки"})
			} else {
				assert.Zero(t, result.code, result.output)
				assert.Equal(t, "pass", manifest["outcome"])
				assert.Empty(t, census["failedPackages"])
			}
		})
	}
}

func TestStandaloneDiagnosticCriticalRepeatedExecutions(t *testing.T) {
	const pkg, name = "example.test/repeated", "TestRepeated"
	for _, tc := range []struct {
		name       string
		actions    []string
		passes     float64
		failed     bool
		unfinished bool
	}{
		{name: "одно исполнение", actions: []string{"pass"}, passes: 1},
		{name: "два успеха", actions: []string{"pass", "pass"}, passes: 2},
		{name: "отказ затем успех", actions: []string{"fail", "pass"}, passes: 1, failed: true},
		{name: "старый terminal не закрывает новый run", actions: []string{"pass"}, passes: 1, unfinished: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stream string
			for _, action := range tc.actions {
				stream += diagnosticEvent("run", pkg, name, "") + diagnosticEvent(action, pkg, name, "")
			}
			if tc.unfinished {
				stream += diagnosticEvent("run", pkg, name, "")
			}
			code, action := 0, "pass"
			if tc.failed {
				code, action = 1, "fail"
			}
			stream += diagnosticEvent(action, pkg, "", "")
			result := runDiagnosticProducer(t, stream, "", code, false, false)
			_, manifest, census := criticalDiagnosticDocuments(t, result)
			assert.Equal(t, tc.passes, census["passedTests"], "перепись потеряла повторное исполнение")
			if tc.unfinished {
				assert.NotZero(t, result.code)
				assert.Equal(t, false, manifest["complete"])
				assert.Equal(t, []any{map[string]any{"package": pkg, "test": name}}, census["unterminatedTests"])
			} else {
				assert.Equal(t, true, manifest["complete"])
				if tc.failed {
					assert.Equal(t, []any{map[string]any{"package": pkg, "test": name}}, census["namedFailures"], "новый pass стёр старый fail")
					assert.Empty(t, census["packageOnlyFailures"])
					assert.True(t, standalonetargets.IsProbeFailure(result.output), "именованный отказ утрачен классификатором")
				} else {
					assert.Zero(t, result.code)
					assert.Empty(t, census["namedFailures"])
				}
			}
		})
	}
}

func TestStandaloneDiagnosticCriticalGateRejectsRehashedContradictions(t *testing.T) {
	const pkg, name = "example.test/diagnostics", "TestContext"
	stream := diagnosticEvent("run", pkg, name, "") + diagnosticEvent("fail", pkg, name, "") + diagnosticEvent("fail", pkg, "", "")
	baseline := runDiagnosticProducer(t, stream, "", 1, false, false)
	manifestPath, _, _ := criticalDiagnosticDocuments(t, baseline)
	for _, mutation := range []string{"законный близнец", "parseRC", "captureRC", "helperRC", "outcome", "packageOnlyFailures", "passedTests", "otherSkips", "unmetSkips", "passedPackages", "skippedPackages", "unterminatedPackages", "unterminatedTests", "hidden_package_start", "hidden_test_run"} {
		t.Run(mutation, func(t *testing.T) {
			capture, err := os.MkdirTemp(t.TempDir(), "target-")
			require.NoError(t, err)
			directory := filepath.Join(capture, "producer-control")
			require.NoError(t, os.Mkdir(directory, 0o700))
			for _, filename := range []string{"manifest.json", "census.json", "stdout.jsonl", "stderr.log", "go.rc"} {
				body, err := os.ReadFile(filepath.Join(filepath.Dir(manifestPath), filename))
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(directory, filename), body, 0o600))
			}
			result := diagnosticResult{code: 1, capture: capture, output: "Диагностика standalone: " + filepath.Join(directory, "manifest.json") + "\n"}
			path, manifest, census := criticalDiagnosticDocuments(t, result)
			switch mutation {
			case "parseRC", "captureRC", "helperRC":
				manifest[mutation] = 2
			case "outcome":
				manifest["outcome"] = "pass"
			case "packageOnlyFailures", "unterminatedPackages":
				census[mutation] = []string{pkg}
			case "unterminatedTests", "unmetSkips":
				census[mutation] = []map[string]string{{"package": pkg, "test": name}}
			case "passedTests", "otherSkips", "passedPackages", "skippedPackages":
				census[mutation] = 1
			case "hidden_package_start", "hidden_test_run":
				extra := diagnosticEvent("start", "example.test/unfinished", "", "")
				if mutation == "hidden_test_run" {
					extra = diagnosticEvent("run", pkg, name, "")
				}
				require.NoError(t, os.WriteFile(filepath.Join(directory, "stdout.jsonl"), []byte(stream+extra), 0o600))
				census["events"] = census["events"].(float64) + 1
			}
			criticalDiagnosticWrite(t, filepath.Join(directory, "census.json"), census)
			// Hashes подтверждают новые байты, поэтому отказ обязан быть семантическим.
			files := manifest["files"].(map[string]any)
			for _, filename := range []string{"census.json", "stdout.jsonl"} {
				body, err := os.ReadFile(filepath.Join(directory, filename))
				require.NoError(t, err)
				sum := sha256.Sum256(body)
				files[filename] = map[string]any{"bytes": len(body), "sha256": hex.EncodeToString(sum[:])}
			}
			criticalDiagnosticWrite(t, path, manifest)
			findings, unmet, err := standalonetargets.RunTargetsWithCapture("синтетическая посадка", []standalonetargets.Target{{Name: "test-standalone", Desc: "пробы"}}, diagnosticCaptureCallback(t, result, ""))
			require.NoError(t, err)
			require.Empty(t, unmet)
			require.Len(t, findings, 1)
			if mutation == "законный близнец" {
				assert.True(t, findings[0].Probes)
				assert.Contains(t, findings[0].String(), "именованные отказы")
			} else {
				assert.False(t, findings[0].Probes, "противоречивый capture объявлен доказанным именованным отказом")
				assert.Contains(t, findings[0].String(), "неизвестный исход", "повреждённая семантика получила штатную классификацию")
			}
		})
	}
}

// Пересчёт hashes не изменяет семантику проверяемых JSON-документов.
func reviewR2Rehash(t *testing.T, path string, manifest map[string]any) {
	t.Helper()
	files := manifest["files"].(map[string]any)
	for _, name := range []string{"census.json", "stdout.jsonl", "stderr.log", "go.rc"} {
		body, err := os.ReadFile(filepath.Join(filepath.Dir(path), name))
		require.NoError(t, err)
		sum := sha256.Sum256(body)
		files[name] = map[string]any{"bytes": len(body), "sha256": hex.EncodeToString(sum[:])}
	}
	criticalDiagnosticWrite(t, path, manifest)
}

func TestStandaloneDiagnosticReviewR2UnscopedBuildEvents(t *testing.T) {
	const pkg, name = "example.test/diagnostics", "TestContext"
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprintf("общая сборка отказ=%t", failed), func(t *testing.T) {
			stream := "{\"ImportPath\":\"\",\"Action\":\"build-output\",\"Output\":\"WORK=/tmp/go-build123\\n\"}\n"
			code, events, outcome, buildStatus := 0, 5, "pass", "output"
			if failed {
				stream += "{\"ImportPath\":\"\",\"Action\":\"build-fail\",\"Output\":\"отказ общей сборки\\n\"}\n"
				code, events, outcome, buildStatus = 1, 6, "package", "fail"
			}
			stream += diagnosticEvent("start", pkg, "", "") + diagnosticEvent("run", pkg, name, "") + diagnosticEvent("pass", pkg, name, "") + diagnosticEvent("pass", pkg, "", "")
			result := runDiagnosticProducer(t, stream, "", code, false, false)
			path, manifest, census := criticalDiagnosticDocuments(t, result)
			t.Run("producer", func(t *testing.T) {
				assert.Equal(t, code, result.code)
				assert.Equal(t, true, manifest["complete"])
				assert.Equal(t, outcome, manifest["outcome"])
				assert.Equal(t, float64(0), census["nonJSON"])
				assert.Equal(t, map[string]any{"": buildStatus}, census["builds"])
				assert.Equal(t, map[string]any{pkg: "pass"}, census["packages"])
				assert.Empty(t, census["namedFailures"])
				assert.Empty(t, census["failedPackages"])
			})
			t.Run("независимый Go consumer", func(t *testing.T) {
				// Законный capture задан независимо: ошибка producer не маскирует ошибку consumer.
				expected := map[string]any{
					"events": events, "nonJSON": 0, "unterminatedPackages": []string{}, "unterminatedTests": []any{},
					"packages": map[string]string{pkg: "pass"}, "failedPackages": []string{}, "namedFailures": []any{},
					"packageOnlyFailures": []string{}, "passedTests": 1, "failedTests": 0, "testExecutions": 1,
					"unmetSkips": []any{}, "otherSkips": 0, "passedPackages": 1, "skippedPackages": 0,
					"builds": map[string]string{"": buildStatus}, "failedBuilds": map[string]string{},
				}
				criticalDiagnosticWrite(t, filepath.Join(filepath.Dir(path), "census.json"), expected)
				manifest["complete"], manifest["captureStatus"], manifest["censusStatus"] = true, "complete", "complete"
				manifest["parseRC"], manifest["captureRC"], manifest["helperRC"], manifest["outcome"] = 0, 0, code, outcome
				reviewR2Rehash(t, path, manifest)
				// Внешняя оболочка может отказать и после успешного Go: это позволяет наблюдать
				// подтверждение pass-capture через публичный consumer без нового тестового API.
				observed := diagnosticResult{code: 1, capture: result.capture, output: "Диагностика standalone: " + path + "\n"}
				finding := diagnosticFinding(t, observed, "")
				if failed {
					assert.Contains(t, finding, "отказы пакетов без именованных отказов проб")
					assert.NotContains(t, finding, "неизвестный исход")
				} else {
					assert.Contains(t, finding, "полный capture: "+path, "законный pass-capture отклонён независимым consumer")
				}
				assert.Contains(t, diagnosticFiles(t, result.capture), "WORK=/tmp/go-build123")
			})
		})
	}
	for _, invalid := range []string{`{"Action":"pass","Package":""}`, `{"Action":"pass"}`} {
		t.Run("незаконный TestEvent "+invalid, func(t *testing.T) {
			stream := invalid + "\n" + diagnosticEvent("fail", pkg, name, "") + diagnosticEvent("fail", pkg, "", "")
			result := runDiagnosticProducer(t, stream, "", 1, false, false)
			_, manifest, census := criticalDiagnosticDocuments(t, result)
			assert.Equal(t, false, manifest["complete"])
			assert.Equal(t, float64(1), census["nonJSON"])
			assert.Contains(t, diagnosticFinding(t, result, ""), "неизвестный исход")
		})
	}
}

func TestStandaloneDiagnosticReviewR2DuplicateMembers(t *testing.T) {
	const pkg, name = "example.test/diagnostics", "TestContext"
	stream := diagnosticEvent("output", pkg, name, "первичная причина\n") + diagnosticEvent("fail", pkg, name, "") + diagnosticEvent("fail", pkg, "", "")
	baseline := runDiagnosticProducer(t, stream, "", 1, false, false)
	baselinePath, _, _ := criticalDiagnosticDocuments(t, baseline)
	for _, mutation := range []string{"unique", "captureRC-2-0", "captureRC-0-2", "parseRC-2-0", "parseRC-0-2", "census", "event"} {
		t.Run(mutation, func(t *testing.T) {
			capture, err := os.MkdirTemp(t.TempDir(), "target-")
			require.NoError(t, err)
			directory := filepath.Join(capture, "producer-review-r2")
			require.NoError(t, os.Mkdir(directory, 0o700))
			for _, filename := range []string{"manifest.json", "census.json", "stdout.jsonl", "stderr.log", "go.rc"} {
				body, err := os.ReadFile(filepath.Join(filepath.Dir(baselinePath), filename))
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(directory, filename), body, 0o600))
			}
			result := diagnosticResult{code: 1, capture: capture, output: "Диагностика standalone: " + filepath.Join(directory, "manifest.json") + "\n"}
			path, manifest, _ := criticalDiagnosticDocuments(t, result)
			if mutation == "census" || mutation == "event" {
				filename, needle, replacement := "census.json", `"test": "TestContext"`, `"test": "TestOther", "test": "TestContext"`
				if mutation == "event" {
					filename, needle, replacement = "stdout.jsonl", `"Action":"output"`, `"Action":"run","Action":"output"`
				}
				file := filepath.Join(directory, filename)
				body, err := os.ReadFile(file)
				require.NoError(t, err)
				require.Contains(t, string(body), needle, "предпосылка байтовой мутации")
				require.NoError(t, os.WriteFile(file, []byte(strings.Replace(string(body), needle, replacement, 1)), 0o600))
			}
			reviewR2Rehash(t, path, manifest)
			if strings.HasPrefix(mutation, "captureRC-") || strings.HasPrefix(mutation, "parseRC-") {
				parts := strings.Split(mutation, "-")
				body, err := os.ReadFile(path)
				require.NoError(t, err)
				needle := `"` + parts[0] + `":0`
				replacement := `"` + parts[0] + `":` + parts[1] + `,"` + parts[0] + `":` + parts[2]
				require.Contains(t, string(body), needle)
				require.NoError(t, os.WriteFile(path, []byte(strings.Replace(string(body), needle, replacement, 1)), 0o600))
			}
			findings, unmet, err := standalonetargets.RunTargetsWithCapture("синтетическая посадка", []standalonetargets.Target{{Name: "test-standalone", Desc: "пробы"}}, diagnosticCaptureCallback(t, result, ""))
			require.NoError(t, err)
			require.Empty(t, unmet)
			require.Len(t, findings, 1)
			if mutation == "unique" {
				assert.True(t, findings[0].Probes)
				assert.Contains(t, findings[0].String(), "именованные отказы")
			} else {
				assert.False(t, findings[0].Probes, "неоднозначный JSON получил доверенную классификацию")
				assert.Contains(t, findings[0].String(), "неизвестный исход")
			}
		})
	}
}

func TestStandaloneDiagnosticCriticalCIExecutesPythonNegativeControls(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)
	root, err := platformtree.ModuleRootFrom(wd)
	require.NoError(t, err)
	body, err := os.ReadFile(filepath.Join(root, ".github/workflows/ci.yml"))
	require.NoError(t, err)
	var workflow struct {
		Jobs map[string]struct {
			Env   map[string]string `yaml:"env"`
			Steps []struct {
				ID              string            `yaml:"id"`
				Run             string            `yaml:"run"`
				If              string            `yaml:"if"`
				ContinueOnError bool              `yaml:"continue-on-error"`
				Env             map[string]string `yaml:"env"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(body, &workflow))
	job, ok := workflow.Jobs["standalone"]
	require.True(t, ok, "предмет проверки отсутствует: standalone job")
	require.NotEmpty(t, job.Steps)
	// У job.env ещё нет runner context. Новые выражения требуют отдельной предпосылки,
	// а не молчаливой подстановки фикстурой несуществующего контекста.
	for key, value := range job.Env {
		require.NotContains(t, value, "${{", "неподдержанная предпосылка job.env %s; runner.temp доступен только после назначения runner", key)
	}
	runCase := func(t *testing.T, broken bool) {
		fixture := t.TempDir()
		bin := filepath.Join(fixture, "bin")
		scripts := filepath.Join(fixture, ".github/scripts")
		require.NoError(t, os.MkdirAll(scripts, 0o700))
		require.NoError(t, os.Mkdir(bin, 0o700))
		// Исполняется настоящий run-step, но тяжёлый Go и публикация здесь не предмет.
		goProbe := "#!/bin/sh\nset -eu\nif [ \"$1\" = test ]; then\n test \"${STANDALONE_DIAGNOSTICS_DIR-}\" = \"$RUNNER_TEMP/standalone-private\"\n printf '%s' \"$STANDALONE_DIAGNOSTICS_DIR\" > \"$RUNNER_TEMP/producer-path\"\nfi\n"
		require.NoError(t, os.WriteFile(filepath.Join(bin, "go"), []byte(goProbe), 0o700))
		exportProbe := "import os, pathlib, sys\nbase = pathlib.Path(os.environ['RUNNER_TEMP'])\nexpected = str(base / 'standalone-private')\nassert sys.argv[1:] == [expected, str(base / 'standalone-public')], 'неверные границы экспорта'\nassert os.environ.get('STANDALONE_DIAGNOSTICS_DIR') == expected, 'export не получил private env'\nassert (base / 'producer-path').read_text() == expected, 'producer и export используют разные capture'\n(base / 'export-path').write_text(expected)\n"
		require.NoError(t, os.WriteFile(filepath.Join(scripts, "standalone-diagnostics.py"), []byte(exportProbe), 0o600))
		truth := "True"
		if broken {
			truth = "False"
		}
		control := "import unittest\nclass Control(unittest.TestCase):\n def test_injected(self):\n  print('DIAGNOSTIC_CONTROL_EXECUTED')\n  self.assertTrue(" + truth + ", 'контрольный отказ Python')\nif __name__ == '__main__': unittest.main()\n"
		require.NoError(t, os.WriteFile(filepath.Join(scripts, "standalone-diagnostics_test.py"), []byte(control), 0o600))
		// Сначала удостоверяем саму инъекцию; ниже проверяется только её достижимость из CI.
		probe := exec.Command("python3", filepath.Join(scripts, "standalone-diagnostics_test.py"))
		probeOutput, probeErr := probe.CombinedOutput()
		require.Contains(t, string(probeOutput), "DIAGNOSTIC_CONTROL_EXECUTED")
		require.Equal(t, broken, probeErr != nil, "фикстура unittest не создала заданный исход: %s", probeOutput)
		// Штатный discovery тоже настоящий: его DEFAULT_PATTERNS не подменяются.
		runner, err := os.ReadFile(filepath.Join(root, ".github/scripts/run-python-probes.py"))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(scripts, "run-python-probes.py"), runner, 0o600))
		for _, relative := range []string{"tests/newman/scripts/twin_test.py", "tests/authz-fixtures/twin_test.py"} {
			path := filepath.Join(fixture, relative)
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
			require.NoError(t, os.WriteFile(path, []byte("if __name__ == '__main__':\n raise SystemExit(0)\n"), 0o600))
		}
		seen, failed, steps := false, false, 0
		outcomes := map[string]string{}
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}
			condition := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(step.If), "${{"), "}}"))
			switch condition {
			case "", "success()":
				if failed {
					continue
				}
			case "always()", "!cancelled()", "true":
			case "false":
				continue
			default:
				guard := regexp.MustCompile(`^always\(\) && steps\.([A-Za-z0-9_-]+)\.outcome == 'success'$`).FindStringSubmatch(condition)
				require.Len(t, guard, 2, "условие CI-step требует явной семантики в контрольной фикстуре: %q", condition)
				if outcomes[guard[1]] != "success" {
					continue
				}
			}
			steps++
			script := strings.ReplaceAll(step.Run, "${{ runner.temp }}", fixture)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			cmd := exec.CommandContext(ctx, "bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script)
			cmd.Dir = fixture
			// Только действительный YAML задаёт capture env; окружение ROOT не подменяет его.
			stepEnv := map[string]string{}
			for key, value := range job.Env {
				stepEnv[key] = value
			}
			for key, value := range step.Env {
				value = strings.ReplaceAll(value, "${{ runner.temp }}", fixture)
				require.NotContains(t, value, "${{", "неподдержанная предпосылка step.env %s", key)
				stepEnv[key] = value
			}
			for _, item := range os.Environ() {
				key, _, _ := strings.Cut(item, "=")
				_, overridden := stepEnv[key]
				if !overridden && key != "PATH" && key != "RUNNER_TEMP" && key != "STANDALONE_DIAGNOSTICS_DIR" {
					cmd.Env = append(cmd.Env, item)
				}
			}
			cmd.Env = append(cmd.Env, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "RUNNER_TEMP="+fixture)
			for key, value := range stepEnv {
				cmd.Env = append(cmd.Env, key+"="+value)
			}
			out, runErr := cmd.CombinedOutput()
			require.NoError(t, ctx.Err(), "CI-step превысил срок: %s", out)
			cancel()
			outcomes[step.ID] = "success"
			if runErr != nil {
				outcomes[step.ID] = "failure"
			}
			if strings.Contains(string(out), "DIAGNOSTIC_CONTROL_EXECUTED") {
				seen = true
				if runErr != nil && !step.ContinueOnError {
					failed = true
				}
			} else {
				require.NoError(t, runErr, "сломалась подпорка другого CI-step: %s", out)
			}
		}
		t.Logf("разобрано и исполнено run-steps: %d; Python-control достигнут: %t", steps, seen)
		assert.True(t, seen, "CI standalone не исполнил контроль именно из standalone-diagnostics_test.py")
		assert.Equal(t, broken, failed, "инъекция assertion не управляет исходом настоящего CI path")
		if !broken {
			publishedFrom, err := os.ReadFile(filepath.Join(fixture, "export-path"))
			require.NoError(t, err, "после успешных controls шаг экспорта не достигнут")
			assert.Equal(t, filepath.Join(fixture, "standalone-private"), string(publishedFrom))
		} else {
			_, err := os.Stat(filepath.Join(fixture, "producer-path"))
			assert.True(t, os.IsNotExist(err), "Go не должен запускаться после отказа controls")
			_, err = os.Stat(filepath.Join(fixture, "export-path"))
			assert.True(t, os.IsNotExist(err), "экспорт не должен запускаться после отказа controls")
		}
	}
	for _, broken := range []bool{false, true} {
		t.Run(fmt.Sprintf("инъекция_отказа=%t", broken), func(t *testing.T) {
			runCase(t, broken)
		})
	}
}
