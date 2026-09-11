// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// acceptance_probe_coordinate_injection_test.go — доказательство способности
// гейта УПАСТЬ и СМОЛЧАТЬ.
//
// Инъекция подаётся судящему ядру значениями и синтетическому дереву в своём
// временном каталоге: писать в индекс, настройки или дерево, из которого
// запущена проба, запрещено. Ронять она обязана ТОЛЬКО проверяемое — поэтому
// вход собирается из законных документов, у которых снято ровно одно
// свойство.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/gitenv"
	"github.com/PRO-Robotech/kaname/internal/check"
)

// liveProbeNames — объявления, играющие роль дерева проб. Две формы записи
// координаты, обе законные: полное имя и идентификатор сценария.
var liveProbeNames = []string{
	"TestIAMCT112_CatalogProbesDoNotDeferEverything",
	"TestIAMCT112_SecondProbeOfTheSameScenario",
	"TestMODMR10RolesSectionLoads",
}

// TestAcceptanceProbeCoordinateInjection — три прогона на одной оси: контроль,
// инъекция, законный близнец.
func TestAcceptanceProbeCoordinateInjection(t *testing.T) {
	findings := func(body string) []string {
		return check.JudgeProbeCoordinates(
			map[string]string{"docs/engineering/acceptance/x.md": body},
			liveProbeNames, nil).Findings
	}

	// ── Прогон 1. КОНТРОЛЬ: обе законные формы координаты живы ────────────────
	control := "Полное имя: `TestMODMR10RolesSectionLoads` — положительный контроль.\n" +
		"Идентификатором сценария: `TestIAMCT112` — отбирает семейство.\n" +
		"С подпробой: `TestIAMCT112/случай` — судится основание.\n"
	if f := findings(control); len(f) != 0 {
		t.Fatalf("КОНТРОЛЬ: гейт покраснел на живых координатах — он ловит форму, "+
			"а не существо: %v", f)
	}

	// ── Прогон 2. ИНЪЕКЦИЯ: координата не резолвится ──────────────────────────
	dead := control + "Мёртвая: `TestMODMR10RolesSectionLoadsAndRulesAreIsomorphicToDomainRule`.\n"
	f := findings(dead)
	if len(f) != 1 {
		t.Fatalf("ИНЪЕКЦИЯ: находок %d, ожидалась ровно одна — гейт ловит не то, "+
			"что инъекция сняла: %v", len(f), f)
	}
	if !strings.Contains(f[0], "TestMODMR10RolesSectionLoadsAndRulesAreIsomorphicToDomainRule") {
		t.Errorf("находка не называет мёртвую координату: %q", f[0])
	}
	if !strings.Contains(f[0], "x.md:4") {
		t.Errorf("находка не называет место (документ и строку): %q", f[0])
	}

	// ── Прогон 3. ЗАКОННЫЕ БЛИЗНЕЦЫ: то же имя, но НЕ координата ──────────────
	twins := control +
		"Проба TestMODMR10RolesSectionLoadsAndRulesAreIsomorphicToDomainRule снята " +
		"вместе со своим предметом — это проза, а не адрес.\n" +
		"Предикат внутри пролёта кода: " +
		"`go test -run '^TestMODMR10RolesSectionLoadsAndRulesAreIsomorphicToDomainRule$'`\n" +
		"```sh\ngo test ./... -run TestMODMR10RolesSectionLoadsAndRulesAreIsomorphicToDomainRule\n```\n"
	if f := findings(twins); len(f) != 0 {
		t.Errorf("ЗАКОННЫЙ БЛИЗНЕЦ: гейт покраснел на прозе разбора либо на предикате — "+
			"он судит слово, а не координату: %v", f)
	}

	// ── Самоистечение послабления: оба конца ─────────────────────────────────
	used := check.JudgeProbeCoordinates(
		map[string]string{"a.md": "`TestGoneForGood`"}, liveProbeNames,
		[]check.DeadProbeCoordinate{{Name: "TestGoneForGood", Issue: 1}}).Findings
	if len(used) != 0 {
		t.Errorf("послабление С ПРЕДМЕТОМ обязано молчать: %v", used)
	}
	for name, why := range map[string]string{
		"TestGoneForGood":              "имя больше не стоит ни в одной приёмке",
		"TestMODMR10RolesSectionLoads": "имя снова резолвится функцией в дереве",
	} {
		got := check.JudgeProbeCoordinates(
			map[string]string{"a.md": "`TestMODMR10RolesSectionLoads`"}, liveProbeNames,
			[]check.DeadProbeCoordinate{{Name: name, Issue: 1}}).Findings
		if len(got) != 1 || !strings.Contains(got[0], why) {
			t.Errorf("послабление БЕЗ ПРЕДМЕТА (%s) не найдено либо названо не тем: %v", name, got)
		}
	}
}

// TestAcceptanceProbeCoordinateWalkersInjection — вторая половина: обходчики
// действительно находят корпус и объявления. Ядро выше судит поданные
// значения и о том, ОТКУДА они взялись, не утверждает ничего.
//
// Отличие от монорепо-версии: там синтетика несла ДВА каталога приёмок разных
// служб (`services/iam/…`, `services/nlb/…`), потому что обходчик смотрел под
// `services/*`. Самостоятельный клон службы каталог `services/` не несёт
// вовсе — обходчик смотрит под `docs/engineering/acceptance` от корня модуля,
// и синтетика ниже это отражает: один каталог приёмок, документ вне него
// корпусом не является.
func TestAcceptanceProbeCoordinateWalkersInjection(t *testing.T) {
	root := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if out, err := gitenv.Command(root, args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(rel, body string) {
		t.Helper()
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("init", "--quiet", "-b", "main")
	run("config", "user.email", "gate@example.invalid")
	run("config", "user.name", "gate")

	write("docs/engineering/acceptance/live.md", "`TestSynthetic`\n`TestSyntheticGone`\n")
	// Приёмка ВНЕ каталога приёмок корпусом не является.
	write("docs/engineering/design.md", "`TestNotACoordinate`\n")
	write("internal/x/x_test.go", "package x\n\nfunc TestSynthetic(t *testing.T) {}\n")
	run("add", "-A")
	run("commit", "--quiet", "-m", "синтетика")

	docs, err := check.AcceptanceDocsOfTree(root)
	if err != nil {
		t.Fatalf("обходчик приёмок отказал: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("обходчик приёмок нашёл %d документов, ожидался 1 (файл вне каталога приёмок "+
			"и файл не с суффиксом .md корпусом не являются): %v", len(docs), docs)
	}
	declared, err := check.DeclaredProbesOfTree(root)
	if err != nil {
		t.Fatalf("обходчик объявлений отказал: %v", err)
	}
	if len(declared) != 1 || declared[0] != "TestSynthetic" {
		t.Fatalf("обходчик объявлений нашёл %v, ожидалось [TestSynthetic]", declared)
	}
	c := check.JudgeProbeCoordinates(docs, declared, nil)
	if c.Coordinates != 2 || c.Resolved != 1 || len(c.Findings) != 1 {
		t.Fatalf("перепись синтетики: координат %d (ожидалось 2), резолвится %d (1), "+
			"находок %d (1)", c.Coordinates, c.Resolved, len(c.Findings))
	}
	if !strings.Contains(c.Findings[0], "TestSyntheticGone") {
		t.Errorf("находка не называет мёртвую координату: %q", c.Findings[0])
	}
}
