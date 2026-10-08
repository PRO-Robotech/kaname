// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

// run_integration_cleanup_unix_test.go — КОНТЕЙНЕРНОЕ ЗАДАНИЕ НЕ ОСТАВЛЯЕТ
// СЛЕДОВ ВО ВРЕМЕННОМ КАТАЛОГЕ НИ НА ОДНОМ ПУТИ ВЫХОДА (задача
// PRO-Robotech/kaname#671).
//
// Предмет: `.github/scripts/run-integration.sh` заводит временные файлы (поток
// ошибок обоих `go list`, журнал `go test`). Здесь стояли ТРИ ловушки `EXIT`,
// и каждая следующая ЗАМЕНЯЛА предыдущую: ловушка журнала забыла файл ошибок
// разбора импортов, и тот оставался во временном каталоге на каждом прогоне,
// дошедшем до `go test`, — штатном, красном и прерванном.
//
// Проба ИСПОЛНЯЕТ сценарий из дерева, а не читает его текст: копия сценария
// кладётся в песочницу рядом с двойником классификатора, в `PATH` первым стоит
// двойник `go`, `TMPDIR` — свой каталог пробы. По каждому пути выхода
// судятся две величины, и обе печатаются:
//
//   - «следов во время прогона» — сколько записей лежало в `TMPDIR`, когда
//     двойник `go` был позван. Ноль здесь означал бы, что сценарий пишет НЕ
//     туда, куда смотрит проба, и «ноль после» не стоил бы ничего;
//   - «следов после» — сколько осталось по выходе. Обязано быть нулём.
//
// Прерывание доставляется СНАРУЖИ — тем же сигналом, каким его шлёт отмена
// задания или терминал, — в момент, когда идёт `go test`: двойник сообщает о
// себе через именованный канал и ждёт, пока проба не пошлёт сигнал. Ожидания
// по часам нет.
//
// Способность упасть — `run_integration_cleanup_injection_unix_test.go`.
package check_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// runIntegrationRel — координата сценария в дереве модуля.
const runIntegrationRel = ".github/scripts/run-integration.sh"

// runIntegrationTimeout — срок одного прогона в песочнице. Двойники отвечают
// мгновенно; срок нужен, чтобы зависший сценарий дал отказ пробы с координатой,
// а не таймаут пакета.
const runIntegrationTimeout = 60 * time.Second

// fakeGo — двойник `go`. Отвечает на три вызова сценария так, как отвечает
// настоящий, и на каждом вызове записывает, сколько записей лежит в TMPDIR.
const fakeGo = `#!/usr/bin/env bash
set -u
printf '%s\n' "$(ls -A "$TMPDIR" | wc -l)" >>"$FAKE_CENSUS"
if [ "$1" = list ] && [ "${2:-}" = -f ]; then
    if [ -n "${FAKE_IMPORTS_RC:-}" ]; then echo "двойник: разбор импортов сорвался" >&2; exit "$FAKE_IMPORTS_RC"; fi
    if [ -n "${FAKE_NO_DB:-}" ]; then echo 'example.test/a:: '; exit 0; fi
    echo 'example.test/a::github.com/PRO-Robotech/corelib/pgtest '
    exit 0
fi
if [ "$1" = list ]; then
    if [ -n "${FAKE_LIST_RC:-}" ]; then echo "двойник: перечень пакетов сорвался" >&2; exit "$FAKE_LIST_RC"; fi
    echo 'example.test/a'
    exit 0
fi
if [ "$1" = test ]; then
    echo 'ok  	example.test/a	0.01s'
    if [ -n "${FAKE_READY:-}" ]; then
        echo ready >"$FAKE_READY"
        read -r _ <"$FAKE_RELEASE"
    fi
    exit "${FAKE_TEST_RC:-0}"
fi
echo "двойник go: вызов не предусмотрен: $*" >&2
exit 97
`

// fakeClassifier — двойник классификатора: вердикт — код `go test`.
const fakeClassifier = "#!/usr/bin/env bash\nexit \"$1\"\n"

// runIntegrationPath — путь выхода сценария и то, как его вызвать.
type runIntegrationPath struct {
	name   string
	env    []string
	signal syscall.Signal // 0 — без прерывания
	wantRC int
}

// runIntegrationPaths — ВСЕ пути выхода сценария, на которых временные файлы
// уже заведены: три отказа отбора, исход `go test` в обе стороны и прерывание
// каждым из сигналов, которыми задание снимают.
var runIntegrationPaths = []runIntegrationPath{
	{name: "go test зелёный", wantRC: 0},
	{name: "go test красный", env: []string{"FAKE_TEST_RC=1"}, wantRC: 1},
	{name: "перечень пакетов сорвался", env: []string{"FAKE_LIST_RC=1"}, wantRC: 2},
	{name: "разбор импортов сорвался", env: []string{"FAKE_IMPORTS_RC=1"}, wantRC: 2},
	{name: "проб на базе не найдено", env: []string{"FAKE_NO_DB=1"}, wantRC: 2},
	{name: "прерывание SIGINT во время go test", signal: syscall.SIGINT, wantRC: 128 + int(syscall.SIGINT)},
	{name: "прерывание SIGTERM во время go test", signal: syscall.SIGTERM, wantRC: 128 + int(syscall.SIGTERM)},
	{name: "прерывание SIGHUP во время go test", signal: syscall.SIGHUP, wantRC: 128 + int(syscall.SIGHUP)},
}

// runIntegrationSource — сценарий из дерева.
func runIntegrationSource(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(runIntegrationRel))) // #nosec G304 -- координата объявлена постоянной
	require.NoErrorf(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: %s не прочитан", runIntegrationRel)
	return string(raw)
}

// runIntegrationOutcome — что судится по одному пути выхода.
type runIntegrationOutcome struct {
	rc     int
	out    string
	during int      // наибольшее число записей в TMPDIR при вызовах двойника
	calls  int      // сколько раз двойник был позван
	left   []string // что осталось в TMPDIR по выходе
}

func writeExecutable(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o700)) // #nosec G306 -- исполняемый двойник в t.TempDir()
}

// runIntegrationIn — исполняет `script` в песочнице по пути `p`.
func runIntegrationIn(t *testing.T, script string, p runIntegrationPath) runIntegrationOutcome {
	t.Helper()
	box := t.TempDir()
	root := filepath.Join(box, "root")
	writeExecutable(t, filepath.Join(root, filepath.FromSlash(runIntegrationRel)), script)
	writeExecutable(t, filepath.Join(root, ".github", "scripts", "classify-integration-outcome.sh"), fakeClassifier)
	bin := filepath.Join(box, "bin")
	writeExecutable(t, filepath.Join(bin, "go"), fakeGo)
	traces := filepath.Join(box, "tmp")
	require.NoError(t, os.Mkdir(traces, 0o700))
	census := filepath.Join(box, "census")

	env := []string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"TMPDIR=" + traces,
		"FAKE_CENSUS=" + census,
	}
	env = append(env, p.env...)

	var ready, release string
	if p.signal != 0 {
		ready = filepath.Join(box, "ready")
		release = filepath.Join(box, "release")
		require.NoError(t, syscall.Mkfifo(ready, 0o600))
		require.NoError(t, syscall.Mkfifo(release, 0o600))
		env = append(env, "FAKE_READY="+ready, "FAKE_RELEASE="+release)
	}

	ctx, cancel := context.WithTimeout(context.Background(), runIntegrationTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", filepath.Join(root, filepath.FromSlash(runIntegrationRel))) // #nosec G204 -- путь в t.TempDir()
	cmd.Env = env
	cmd.WaitDelay = 5 * time.Second
	// Вывод читается и до выхода сценария (в тексте отказа), поэтому буфер
	// защищён от записи потоком копирования exec.
	var out lockedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	require.NoError(t, cmd.Start(), "проверка НЕ ИСПОЛНЯЛАСЬ: сценарий не запущен")

	if p.signal != 0 {
		// Двойник `go test` открыл канал — значит идёт прогон проб, и все
		// временные файлы уже заведены.
		got, err := readFIFO(ctx, ready)
		require.NoErrorf(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: сценарий не дошёл до go test:\n%s", out.String())
		require.Equal(t, "ready\n", got)
		require.NoError(t, cmd.Process.Signal(p.signal))
		require.NoError(t, os.WriteFile(release, []byte("go\n"), 0o600))
	}

	err := cmd.Wait()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: сценарий не завершился за %s:\n%s", runIntegrationTimeout, out.String())
	}
	rc := 0
	if err != nil {
		var exitErr *exec.ExitError
		require.Truef(t, errors.As(err, &exitErr), "проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
		rc = exitErr.ExitCode()
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			rc = 128 + int(ws.Signal())
		}
	}

	o := runIntegrationOutcome{rc: rc, out: out.String()}
	raw, err := os.ReadFile(census) // #nosec G304 -- путь в t.TempDir()
	require.NoErrorf(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: двойник go не позван ни разу:\n%s", o.out)
	for _, line := range strings.Fields(string(raw)) {
		n, convErr := strconv.Atoi(line)
		require.NoError(t, convErr)
		o.calls++
		o.during = max(o.during, n)
	}
	entries, err := os.ReadDir(traces)
	require.NoError(t, err)
	for _, e := range entries {
		o.left = append(o.left, e.Name())
	}
	sort.Strings(o.left)
	return o
}

// lockedBuffer — буфер вывода, безопасный для чтения во время записи.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// readFIFO — читает именованный канал, не дольше срока контекста.
func readFIFO(ctx context.Context, path string) (string, error) {
	type result struct {
		b   []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		b, err := os.ReadFile(path) // #nosec G304 -- путь в t.TempDir()
		ch <- result{b, err}
	}()
	select {
	case r := <-ch:
		return string(r.b), r.err
	case <-ctx.Done():
		return "", fmt.Errorf("канал %s не открыт: %w", path, ctx.Err())
	}
}

// auditRunIntegration — находки по всем путям выхода. Пустой перечень — ни
// одного следа ни на одном пути; перепись — по строке на путь.
func auditRunIntegration(t *testing.T, script string) (findings, census []string) {
	t.Helper()
	for _, p := range runIntegrationPaths {
		o := runIntegrationIn(t, script, p)
		census = append(census, fmt.Sprintf("%s: код %d · вызовов go %d · следов во время прогона %d · следов после %d",
			p.name, o.rc, o.calls, o.during, len(o.left)))
		// Предпосылка: временные файлы заведены там, куда смотрит проба.
		// Без неё «ноль после» ничего не доказывает.
		require.Positivef(t, o.during,
			"проверка НЕ ИСПОЛНЯЛАСЬ (%s): во время прогона в TMPDIR не было ни одной записи — сценарий пишет не туда:\n%s",
			p.name, o.out)
		if len(o.left) > 0 {
			findings = append(findings, fmt.Sprintf("%s: во временном каталоге остались следы %v", p.name, o.left))
		}
		if o.rc != p.wantRC {
			findings = append(findings, fmt.Sprintf("%s: код выхода %d, ожидался %d", p.name, o.rc, p.wantRC))
		}
	}
	return findings, census
}

// TestRunIntegrationLeavesNoTracesOnAnyExitPath — НЕСУЩЕЕ утверждение: по
// каждому пути выхода, с прерыванием и без, во временном каталоге не остаётся
// ничего, а код выхода — свой у каждого пути.
func TestRunIntegrationLeavesNoTracesOnAnyExitPath(t *testing.T) {
	t.Parallel()
	findings, census := auditRunIntegration(t, runIntegrationSource(t))
	for _, line := range census {
		t.Log("перепись: " + line)
	}
	require.Len(t, census, len(runIntegrationPaths), "осмотрены не все пути выхода")
	require.Emptyf(t, findings, "следы и коды по путям выхода:\n%s", strings.Join(findings, "\n"))
}
