// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// release_build_refuses_dev_mode_test.go — выпускной бинарь не исполняет
// режима разработки и опт-ина «круг отправителей не сужаем» (kaname#985).
//
// Проба собирает НАСТОЯЩИЙ бинарь службы дважды — выпускной (без меток) и
// тестовый (`-tags kaname_testbuild`) — и запускает его процессом: признак
// тестовой сборки есть свойство сборки, и бинарь проб Go его несёт всегда, то
// есть изнутри `go test` выпускную сборку не изобразить.
//
// Граница названа: «старт» тестовой сборки здесь — отсутствие отказа стража
// сборки; до базы и слушателей процесс без полной настройки не доходит, и
// подъём целиком судят наборы проб стенда.
package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// releaseRefusalMarker — подстрока отказа стража сборки.
const releaseRefusalMarker = "refused by a release build"

// buildKanameBinary собирает бинарь службы из этого пакета.
func buildKanameBinary(t *testing.T, tags string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "kaname")
	args := []string{"build", "-o", bin}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	args = append(args, ".")
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("сборка бинаря (метки %q) не удалась — условие пробы не создано: %v\n%s", tags, err, out)
	}
	return bin
}

// runKanameBinary запускает бинарь с ОДНОЙ лишь заданной настройкой: окружение
// процесса проб не наследуется, чтобы чужая переменная не решила исход.
func runKanameBinary(t *testing.T, bin string, env ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}, env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("процесс не завершился за 60 с — исход стража не наблюдён:\n%s", stderr.String())
	}
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, stderr.String()
	case errors.As(err, &exit):
		return exit.ExitCode(), stderr.String()
	default:
		t.Fatalf("процесс не запустился: %v", err)
		return -1, ""
	}
}

// TestReleaseBuild_RefusesDevModeAndTheForwarderOptIn — DoD kaname#985.
func TestReleaseBuild_RefusesDevModeAndTheForwarderOptIn(t *testing.T) {
	release := buildKanameBinary(t, "")
	testBuild := buildKanameBinary(t, "kaname_testbuild")

	for _, tc := range []struct {
		name    string
		bin     string
		env     []string
		refused bool
	}{
		{name: "выпуск, режим разработки", bin: release,
			env: []string{"KANAME_AUTHN__MODE=dev"}, refused: true},
		{name: "выпуск, боевой режим, опт-ин круга", bin: release,
			env: []string{"KANAME_AUTHN__MODE=production", "KANAME_AUTHN__TRUST_ANY_FORWARDER=true"}, refused: true},
		{name: "близнец: выпуск, боевой режим", bin: release,
			env: []string{"KANAME_AUTHN__MODE=production"}},
		{name: "близнец: тестовая сборка, режим разработки", bin: testBuild,
			env: []string{"KANAME_AUTHN__MODE=dev"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out := runKanameBinary(t, tc.bin, tc.env...)
			has := strings.Contains(out, releaseRefusalMarker)
			switch {
			case tc.refused && (code == 0 || !has):
				t.Fatalf("ожидался отказ старта стражем сборки: код %d, отказ стража в журнале %v\n%s", code, has, out)
			case !tc.refused && has:
				t.Fatalf("законная сборка отвергнута стражем сборки (код %d):\n%s", code, out)
			}
			t.Logf("код выхода %d · отказ стража сборки %v", code, has)
		})
	}
}
