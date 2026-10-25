// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// migration_cites_approved_acceptance_injection_test.go — инъекция гейта
// TestNewMigrationCitesAnApprovedAcceptance (PRO-Robotech/kaname#1010): ядро
// краснеет с координатой на каждом нарушении и молчит на законном близнеце той
// же формы. Вход синтетический — живое дерево здесь не трогается.
package check_test

import (
	"strings"
	"testing"
)

// mcaWorld — три приёмки: одобренная на текущей редакции, отвергнутая на
// текущей и одобренная на ПРЕЖНЕЙ редакции (правленая после вердикта).
func mcaWorld() (map[string][]byte, []acceptanceRecord) {
	approved := []byte("# Приёмка: одобренная\n")
	rejected := []byte("# Приёмка: отвергнутая\n")
	edited := []byte("# Приёмка: правленая после вердикта, редакция 2\n")
	docs := map[string][]byte{
		acceptanceHomeRel + "/approved-one.md": approved,
		acceptanceHomeRel + "/rejected-one.md": rejected,
		acceptanceHomeRel + "/edited-one.md":   edited,
	}
	records := []acceptanceRecord{
		{Path: acceptanceHomeRel + "/approved-one.md", SHA256: fingerprint(approved), Verdict: "APPROVED", File: "r1.yaml"},
		{Path: acceptanceHomeRel + "/rejected-one.md", SHA256: fingerprint(rejected), Verdict: "CHANGES_REQUESTED", File: "r2.yaml"},
		{Path: acceptanceHomeRel + "/edited-one.md", SHA256: fingerprint([]byte("# Приёмка: редакция 1\n")), Verdict: "APPROVED", File: "r3.yaml"},
	}
	return docs, records
}

const mcaMig = "internal/migrations/20991231000000_injected.sql"

func mcaAudit(t *testing.T, body string) ([]string, int) {
	t.Helper()
	docs, records := mcaWorld()
	return migrationAcceptanceAudit(map[string]string{mcaMig: body}, docs, records)
}

func mcaRequireOneFinding(t *testing.T, findings []string, wants ...string) {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("ждали ровно одну находку, получили %d: %q", len(findings), findings)
	}
	for _, w := range append([]string{mcaMig}, wants...) {
		if !strings.Contains(findings[0], w) {
			t.Fatalf("находка не называет %q: %s", w, findings[0])
		}
	}
}

func TestMigrationAcceptanceInjection_NoCitationIsFound(t *testing.T) {
	t.Parallel()
	findings, _ := mcaAudit(t, "-- миграция без основания\nALTER TABLE x ADD COLUMN y int;\n")
	mcaRequireOneFinding(t, findings, "не цитирует")
}

func TestMigrationAcceptanceInjection_BareNameOutsideTheHomeIsNotACitation(t *testing.T) {
	t.Parallel()
	findings, citations := mcaAudit(t, "-- см. README.md и change-graph.md\nSELECT 1;\n")
	if citations != 0 {
		t.Fatalf("голое имя вне дома приёмок засчитано цитатой: %d", citations)
	}
	mcaRequireOneFinding(t, findings, "не цитирует")
}

func TestMigrationAcceptanceInjection_RejectedAcceptanceIsFound(t *testing.T) {
	t.Parallel()
	findings, _ := mcaAudit(t, "-- САНКЦИЯ: приёмка "+acceptanceHomeRel+"/rejected-one.md\n")
	mcaRequireOneFinding(t, findings, "rejected-one.md", "CHANGES_REQUESTED", "r2.yaml")
}

func TestMigrationAcceptanceInjection_ApprovalOfAPriorEditionIsFound(t *testing.T) {
	t.Parallel()
	findings, _ := mcaAudit(t, "-- САНКЦИЯ: приёмка "+acceptanceHomeRel+"/edited-one.md\n")
	mcaRequireOneFinding(t, findings, "edited-one.md", "записи ревью нет", "другие отпечатки: 1")
}

func TestMigrationAcceptanceInjection_MissingDocumentIsFound(t *testing.T) {
	t.Parallel()
	findings, _ := mcaAudit(t, "-- САНКЦИЯ: приёмка "+acceptanceHomeRel+"/never-written.md\n")
	mcaRequireOneFinding(t, findings, "never-written.md", "нет")
}

func TestMigrationAcceptanceInjection_OneUnapprovedAmongApprovedIsFound(t *testing.T) {
	t.Parallel()
	findings, citations := mcaAudit(t, "-- САНКЦИЯ: "+acceptanceHomeRel+"/approved-one.md;\n"+
		"-- опора: rejected-one.md\n")
	if citations != 2 {
		t.Fatalf("цитат две (полный путь и голое имя), засчитано %d", citations)
	}
	mcaRequireOneFinding(t, findings, "rejected-one.md")
}

// Законные близнецы: те же формы цитаты, документ одобрен на текущей редакции.
func TestMigrationAcceptanceInjection_ApprovedTwinIsSilent(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"полный путь":   "-- САНКЦИЯ: приёмка " + acceptanceHomeRel + "/approved-one.md, редакция 1\n",
		"голое имя":     "-- приёмка `approved-one.md` (задача #1)\n",
		"начало строки": "approved-one.md\n",
	} {
		findings, citations := mcaAudit(t, body)
		if len(findings) != 0 {
			t.Errorf("%s: законный близнец дал находки: %q", name, findings)
		}
		if citations != 1 {
			t.Errorf("%s: цитата одобренной приёмки не распознана (цитат %d)", name, citations)
		}
	}
}

func TestMigrationAcceptanceInjection_NothingAddedIsSilent(t *testing.T) {
	t.Parallel()
	docs, records := mcaWorld()
	findings, citations := migrationAcceptanceAudit(map[string]string{}, docs, records)
	if len(findings) != 0 || citations != 0 {
		t.Fatalf("без добавленных миграций судить нечего, а вышло находок %d, цитат %d", len(findings), citations)
	}
}

func TestMigrationAcceptanceInjection_RecordFormsAreRead(t *testing.T) {
	t.Parallel()
	for _, rel := range []string{
		"docs/specs/reviews/approved-one/abc.yaml",
		"docs/changes/kn-1/reviews/acceptance/abc.yaml",
	} {
		if !isReviewRecordFile(rel) {
			t.Errorf("место записей ревью не узнано: %s", rel)
		}
	}
	for _, rel := range []string{
		"docs/changes/kn-1/reviews/post-diff/x/abc.yaml",
		"docs/specs/reviews/approved-one/README.md",
		"internal/migrations/x.yaml",
	} {
		if isReviewRecordFile(rel) {
			t.Errorf("чужое место засчитано записью ревью: %s", rel)
		}
	}

	own := []byte("schema_version: 1\nkind: acceptance_review\nsubject:\n  repository: PRO-Robotech/kaname\n" +
		"  path: docs/engineering/acceptance/approved-one.md\n  sha256: ABCDEF\nverdict: APPROVED\n")
	r, ok, err := parseAcceptanceRecord("r.yaml", own)
	if err != nil || !ok {
		t.Fatalf("запись своей службы не прочитана: ok=%v err=%v", ok, err)
	}
	if r.Path != "docs/engineering/acceptance/approved-one.md" || r.SHA256 != "abcdef" || r.Verdict != "APPROVED" {
		t.Fatalf("запись прочитана не так: %+v", r)
	}
	foreign := []byte(strings.Replace(string(own), "PRO-Robotech/kaname", "PRO-Robotech/kacho", 1))
	if _, ok, _ := parseAcceptanceRecord("r.yaml", foreign); ok {
		t.Fatal("запись о документе другого репозитория засчитана")
	}
	if _, _, err := parseAcceptanceRecord("r.yaml", []byte("kind: [\n")); err == nil {
		t.Fatal("неразбираемая запись прошла молча")
	}
}
