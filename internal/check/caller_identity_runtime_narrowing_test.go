// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"bytes"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// Проверяем действующее сужение Check через зарегистрированный RPC. У близнеца меняется
// только таблица, из которой обработчик и внутренний фронт получают допуск.
func TestCallerIdentityAdmissionRequiresCheckNarrowingDeclaration(t *testing.T) {
	const (
		rpc      = "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1/InternalIAMService/Check"
		producer = "github.com/PRO-Robotech/kaname/internal/moduleidentity.Roster.FromContext"
		handler  = "(*github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam.Handler).Check"
	)
	root := moduleRoot(t)
	missing := callerActualTree(t, root)
	table := filepath.Join(missing, "internal/authzguard/front_admission.go")
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

	// Координату задаёт настоящий вызов обработчика, независимо от отчёта гейта.
	path := filepath.Join(root, callerHandlerSource)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	call := []byte("h.modules.FromContext(ctx)")
	if bytes.Count(src, call) != 1 {
		t.Fatal("ожидался один вызов чтения личности модуля в обработчике Check")
	}
	file := token.NewFileSet().AddFile(callerHandlerSource, -1, len(src))
	file.SetLinesForContent(src)
	where := file.Position(file.Pos(bytes.Index(src, call))).String()

	callerRunNamed(t, root, "./internal/authzguard", callerAdmissionTest)
	callerRunNamed(t, root, "./internal/restfront", callerNarrowingControl)
	ctx, cancel := callerFullTreeTestContext(t)
	defer cancel()
	t.Log("Check с записью: обход начат")
	started := time.Now()
	lawful, err := check.CheckNarrowingWitnessForTest(ctx, root, liveCallerDeclarations())
	t.Logf("Check с записью: обход занял %s", time.Since(started))
	if err != nil {
		t.Fatal(err)
	}
	if len(lawful.Findings) != 0 {
		t.Fatalf("законный близнец Check: %v", lawful.Findings)
	}
	var want []string
	var sawHandler bool
	for _, read := range lawful.Reads {
		if read.RPC != rpc || read.Producer != producer {
			continue
		}
		if read.Site == handler && read.Coordinate == where {
			sawHandler = true
		}
		want = append(want, read.Coordinate+": чтение личности без объявления "+rpc+" -> "+producer+" @ "+read.Site)
	}
	if !sawHandler {
		t.Fatalf("законный близнец не обнаружил %s в %s", handler, where)
	}
	slices.Sort(want)
	t.Log("Check без записи: обход начат")
	started = time.Now()
	negative, err := check.CheckNarrowingWitnessForTest(ctx, missing, liveCallerDeclarations())
	t.Logf("Check без записи: обход занял %s", time.Since(started))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(negative.Findings, want) {
		t.Fatalf("снята только запись сужения Check: находки %q, ожидались %q", negative.Findings, want)
	}
}
