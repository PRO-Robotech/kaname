// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"bytes"
	"context"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const (
	narrowingRPC      = "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1/InternalIAMService/Check"
	narrowingProducer = "github.com/PRO-Robotech/kaname/internal/moduleidentity.Roster.FromContext"
	narrowingHandler  = "(*github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam.Handler).Check"
	narrowingTable    = "internal/authzguard/front_admission.go"
)

// Проверяем действующее сужение Check через зарегистрированный RPC. У близнеца меняется
// только таблица, из которой обработчик и внутренний фронт получают допуск.
func TestCallerIdentityAdmissionRequiresCheckNarrowingDeclaration(t *testing.T) {
	root := moduleRoot(t)
	if phase, requested := os.LookupEnv("KANAME_REGISTERED_CHECK_PHASE"); requested {
		callerNarrowingDiagnostic(t, root, phase)
		return
	}

	missing := callerMissingCheckRow(t, root)
	where := callerCheckCoordinate(t, root)
	callerCheckFrontControls(t, root)
	ctx, cancel := callerFullTreeTestContext(t)
	defer cancel()
	lawful := callerCheckWitness(t, ctx, root, "с записью")
	want := callerLawfulCheckFindings(t, lawful, where)
	negative := callerCheckWitness(t, ctx, missing, "без записи")
	if !slices.Equal(negative.Findings, want) {
		t.Fatalf("снята только запись сужения Check: находки %q, ожидались %q", negative.Findings, want)
	}
}

func callerMissingCheckRow(t *testing.T, root string) string {
	t.Helper()
	missing := callerActualTree(t, root)
	table := filepath.Join(missing, narrowingTable)
	data, err := os.ReadFile(table)
	if err != nil {
		t.Fatal(err)
	}
	entry := []byte("\tinternalCheckMethod: {moduleidentity.ProfileDataPlane},\n")
	if bytes.Count(data, entry) != 1 {
		t.Fatal("ожидалась одна запись сужения Check для профиля плоскости данных")
	}
	if err := os.WriteFile(table, bytes.Replace(data, entry, nil, 1), 0o600); err != nil {
		t.Fatal(err)
	}
	return missing
}

// Координату задаёт настоящий вызов обработчика, независимо от отчёта гейта.
func callerCheckCoordinate(t *testing.T, root string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(root, callerHandlerSource))
	if err != nil {
		t.Fatal(err)
	}
	call := []byte("h.modules.FromContext(ctx)")
	if bytes.Count(src, call) != 1 {
		t.Fatal("ожидался один вызов чтения личности модуля в обработчике Check")
	}
	file := token.NewFileSet().AddFile(callerHandlerSource, -1, len(src))
	file.SetLinesForContent(src)
	return file.Position(file.Pos(bytes.Index(src, call))).String()
}

func callerCheckFrontControls(t *testing.T, root string) {
	t.Helper()
	callerRunNamed(t, root, "./internal/authzguard", callerAdmissionTest)
	callerRunNamed(t, root, "./internal/restfront", callerNarrowingControl)
}

func callerCheckWitness(t *testing.T, ctx context.Context, root, label string) check.CheckNarrowingWitness {
	t.Helper()
	t.Logf("Check %s: обход начат", label)
	started := time.Now()
	witness, err := check.CheckNarrowingWitnessForTest(ctx, root, liveCallerDeclarations())
	t.Logf("Check %s: обход занял %s", label, time.Since(started))
	if err != nil {
		t.Fatal(err)
	}
	return witness
}

func callerLawfulCheckFindings(t *testing.T, lawful check.CheckNarrowingWitness, where string) []string {
	t.Helper()
	if len(lawful.Findings) != 0 {
		t.Fatalf("законный близнец Check: %v", lawful.Findings)
	}
	var want []string
	var sawHandler bool
	for _, read := range lawful.Reads {
		if read.RPC != narrowingRPC || read.Producer != narrowingProducer {
			continue
		}
		if read.Site == narrowingHandler && read.Coordinate == where {
			sawHandler = true
		}
		want = append(want, read.Coordinate+": чтение личности без объявления "+narrowingRPC+" -> "+narrowingProducer+" @ "+read.Site)
	}
	if !sawHandler {
		t.Fatalf("законный близнец не обнаружил %s в %s", narrowingHandler, where)
	}
	slices.Sort(want)
	return want
}
