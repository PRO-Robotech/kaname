// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package modelrender_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/modelrender"
)

// sweep_test.go — обход закрытого набора, ведомость послаблений и три исхода
// (Н-02, Н-05; сценарий B-08; инъекции C-08, C-09).

// синтетический канон: два блока, оба принадлежат модулю vpc по закрытой таблице.
const twoBlockCanon = `model
  schema 1.1

type vpc_network
  relations
    define project: [project]
    define super_admin: super_admin from project
    define admin: [user, service_account, group#member] or super_admin
    define editor: [user, service_account, group#member] or admin
    define viewer: [user, service_account, group#member] or editor
    define v_get: [user, service_account, group#member] or super_admin

type vpc_subnet
  relations
    define project: [project]
    define super_admin: super_admin from project
    define admin: [user, service_account, group#member] or super_admin
    define editor: [user, service_account, group#member] or admin
    define viewer: [user, service_account, group#member] or editor
    define v_get: [user, service_account, group#member] or super_admin
`

// manifestFor — манифест модуля, порождающий ровно блоки twoBlockCanon.
func manifestFor(module string, resources ...string) string {
	var sb strings.Builder
	sb.WriteString("apiVersion: iam/v1\nmodule: " + module + "\nresources:\n")
	for _, r := range resources {
		sb.WriteString("  - name: " + strings.TrimPrefix(r, "vpc_") + "\n")
		sb.WriteString("    objectType: " + r + "\n")
		sb.WriteString("    parent: project\n")
		sb.WriteString("    producer: derived\n")
		sb.WriteString("    verbs:\n      - get\n")
	}
	return sb.String()
}

func writeManifest(t *testing.T, root, module, body string) {
	t.Helper()
	dir := filepath.Join(root, "modules", module)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("каталог модуля %s: %v", module, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), []byte(body), 0o600); err != nil {
		t.Fatalf("манифест %s: %v", module, err)
	}
}

// allWaivers — ведомость на весь закрытый набор, каждая запись с номером задачи.
func allWaivers(except ...string) []modelrender.Waiver {
	skip := map[string]bool{}
	for _, m := range except {
		skip[m] = true
	}
	var out []modelrender.Waiver
	for _, m := range domain.KnownModules() {
		if !skip[m] {
			out = append(out, modelrender.Waiver{Module: m, Issue: 1091})
		}
	}
	return out
}

// TestC08NothingToRenderIsVoidNotSuccess — обходу нечего сверять, разрешение
// ведомости в силе: исход 2 (VOID), НЕ 0.
//
// «Зелёный под послаблением» неотличим от настоящего зелёного ПО КОДУ ВОЗВРАТА —
// а именно код читает оболочка. VOID отличим машинно.
func TestC08NothingToRenderIsVoidNotSuccess(t *testing.T) {
	root := helperTree(t, twoBlockCanon)

	census, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, allWaivers())

	if code != modelrender.SweepVoid {
		t.Fatalf("исход %d, ожидался %d (VOID); находки: %v", code, modelrender.SweepVoid, findings)
	}
	if len(findings) != 0 {
		t.Fatalf("VOID с находками: %v", findings)
	}
	if census.ModulesInSet != len(domain.KnownModules()) || census.ManifestsFound != 0 {
		t.Fatalf("перепись не называет обе величины: %s", census)
	}
	t.Logf("перепись VOID: %s", census)
}

// TestC08NothingToRenderWithoutTheWaiverIsAFinding — то же дерево при СНЯТОМ
// разрешении: исход 1, и каждый модуль назван поимённо.
//
// Вторая половина C-08. Без неё «прошло» было бы неотличимо от «не читало» весь
// срок до приезда манифестов.
func TestC08NothingToRenderWithoutTheWaiverIsAFinding(t *testing.T) {
	root := helperTree(t, twoBlockCanon)

	_, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, nil)

	if code != modelrender.SweepFinding {
		t.Fatalf("исход %d, ожидался %d (находка)", code, modelrender.SweepFinding)
	}
	if len(findings) != len(domain.KnownModules()) {
		t.Fatalf("находок %d, ожидалось %d — по одной на модуль набора",
			len(findings), len(domain.KnownModules()))
	}
	for _, m := range domain.KnownModules() {
		named := false
		for _, f := range findings {
			if f.Module == m {
				named = true
			}
		}
		if !named {
			t.Errorf("модуль %s не назван поимённо ни одной находкой", m)
		}
	}
}

// TestC09ModuleOfTheClosedSetWithoutAManifestIsNamed — пять манифестов из шести,
// у шестого записи ведомости нет: находка С ИМЕНЕМ МОДУЛЯ.
func TestC09ModuleOfTheClosedSetWithoutAManifestIsNamed(t *testing.T) {
	root := helperTree(t, twoBlockCanon)
	modules := domain.KnownModules()
	missing := modules[len(modules)-1]
	for _, m := range modules[:len(modules)-1] {
		body := manifestFor(m)
		if m == "vpc" {
			body = manifestFor(m, "vpc_network", "vpc_subnet")
		}
		writeManifest(t, root, m, body)
	}

	_, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, nil)

	if code != modelrender.SweepFinding {
		t.Fatalf("исход %d, ожидался %d (находка)", code, modelrender.SweepFinding)
	}
	if len(findings) != 1 || findings[0].Module != missing {
		t.Fatalf("находки %v, ожидалась ровно одна про модуль %s", findings, missing)
	}
}

// TestC09TheSameMissingManifestWithALedgerRecordPasses — законный близнец первый:
// тот же снятый манифест, но С записью ведомости — исход 0.
//
// Без него ведомость не проверяется ВОВСЕ: отличие находки от разрешённого
// позаписно осталось бы недоказанным.
func TestC09TheSameMissingManifestWithALedgerRecordPasses(t *testing.T) {
	root := helperTree(t, twoBlockCanon)
	modules := domain.KnownModules()
	missing := modules[len(modules)-1]
	for _, m := range modules[:len(modules)-1] {
		body := manifestFor(m)
		if m == "vpc" {
			body = manifestFor(m, "vpc_network", "vpc_subnet")
		}
		writeManifest(t, root, m, body)
	}

	census, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, []modelrender.Waiver{{Module: missing, Issue: 1091}})

	if code != modelrender.SweepOK {
		t.Fatalf("исход %d, ожидался %d; находки: %v", code, modelrender.SweepOK, findings)
	}
	if census.Waived != 1 {
		t.Fatalf("перепись не сосчитала прощённое: %s", census)
	}
}

// TestC09SixModulesSixManifestsPass — законный близнец второй: набор покрыт
// целиком, исход 0.
//
// Отвечает на вопрос «краснеет ли обход на ЛЮБОМ дереве» — без него молчание
// предыдущих проб неотличимо от молчания мёртвого.
func TestC09SixModulesSixManifestsPass(t *testing.T) {
	root := helperTree(t, twoBlockCanon)
	for _, m := range domain.KnownModules() {
		body := manifestFor(m)
		if m == "vpc" {
			body = manifestFor(m, "vpc_network", "vpc_subnet")
		}
		writeManifest(t, root, m, body)
	}

	census, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, nil)

	if code != modelrender.SweepOK {
		t.Fatalf("исход %d, ожидался %d; находки: %v", code, modelrender.SweepOK, findings)
	}
	if census.BlocksCompared != 2 {
		t.Fatalf("сверено блоков %d, ожидалось 2: %s", census.BlocksCompared, census)
	}
	if census.BytesCompared == 0 {
		t.Fatalf("перепись не назвала байт: %s", census)
	}
	t.Logf("перепись: %s", census)
}

// TestN05ALedgerRecordWithNothingToForgiveIsAFinding — САМОИСТЕЧЕНИЕ послабления:
// запись ведомости на модуль, чей манифест приехал, есть находка.
//
// Послабление без предиката снятия не истекло бы никогда, а истёкшее и не снятое
// — слепая зона, выданная вперёд.
func TestN05ALedgerRecordWithNothingToForgiveIsAFinding(t *testing.T) {
	root := helperTree(t, twoBlockCanon)
	for _, m := range domain.KnownModules() {
		body := manifestFor(m)
		if m == "vpc" {
			body = manifestFor(m, "vpc_network", "vpc_subnet")
		}
		writeManifest(t, root, m, body)
	}

	_, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, []modelrender.Waiver{{Module: "vpc", Issue: 1091}})

	if code != modelrender.SweepFinding {
		t.Fatalf("исход %d, ожидался %d: запись ведомости пережила свой предмет", code, modelrender.SweepFinding)
	}
	if len(findings) != 1 || !strings.Contains(findings[0].Detail, "прощать") {
		t.Fatalf("находка не называет предмет самоистечения: %v", findings)
	}
}

// TestN05ALedgerRecordWithoutAnIssueIsAFinding — послабление без номера задачи
// есть послабление огульное: у него нет предиката снятия.
func TestN05ALedgerRecordWithoutAnIssueIsAFinding(t *testing.T) {
	root := helperTree(t, twoBlockCanon)

	_, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, []modelrender.Waiver{{Module: "vpc"}})

	if code != modelrender.SweepFinding {
		t.Fatalf("исход %d, ожидался %d: запись без номера прошла", code, modelrender.SweepFinding)
	}
	found := false
	for _, f := range findings {
		if f.Module == "vpc" && strings.Contains(f.Detail, "номер") {
			found = true
		}
	}
	if !found {
		t.Fatalf("находка не называет отсутствие номера: %v", findings)
	}
}

// TestN05AWaiverForAModuleOutsideTheClosedSetIsAFinding — ведомость не вправе
// прощать то, чего обход не обходит: запись на модуль вне набора не имеет предмета.
func TestN05AWaiverForAModuleOutsideTheClosedSetIsAFinding(t *testing.T) {
	root := helperTree(t, twoBlockCanon)

	_, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, append(allWaivers(),
		modelrender.Waiver{Module: "geo", Issue: 1091}))

	if code != modelrender.SweepFinding {
		t.Fatalf("исход %d, ожидался %d: запись на модуль вне набора прошла", code, modelrender.SweepFinding)
	}
	named := false
	for _, f := range findings {
		if f.Module == "geo" {
			named = true
		}
	}
	if !named {
		t.Fatalf("находка не называет модуль вне набора: %v", findings)
	}
}
