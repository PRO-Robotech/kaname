// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// migration_cites_approved_acceptance_test.go — ГЕЙТ КЛАССА: миграция, НОВАЯ
// относительно ствола, цитирует приёмку с ДЕЙСТВУЮЩИМ одобрением
// (PRO-Robotech/kaname#1010).
//
// # Почему гейт заведён здесь
//
// Одноимённый гейт монорепо (`kacho:internal/repohygiene/acceptanceledger_test.go`)
// отбирает миграции по подстроке `/internal/migrations/` своего дерева, то есть
// `services/**/internal/migrations`; дерева этой службы он не читает вовсе.
// Здесь запрет #1 для миграции («схема — только по одобренной приёмке») не
// держало ничего, кроме внимания. Дом — `internal/check`, рядом с двумя
// соседними гейтами о добавленных миграциях; `trunkRef` и
// `addedMigrationFiles` берутся у них, второй редакции «что считать
// добавленным» не заводится.
//
// # Что такое «действующее одобрение»
//
// Вердикт — утверждение о РЕВИЗИИ документа, которую читал проверяющий, и
// привязан он к отпечатку этой ревизии (SHA-256 файла), а не к имени документа:
// правка после вердикта его не переносит (`acceptance_edit_after_verdict.go`).
// Поэтому одобрение действует, только если запись ревью с вердиктом APPROVED
// названа ТЕКУЩИМ отпечатком цитируемого документа. Записи ревью этой службы
// живут в двух местах — `docs/specs/reviews/<приёмка>/<отпечаток>.yaml` и
// `docs/changes/<задача>/reviews/acceptance/<отпечаток>.yaml`; обе формы
// выведены обходом дерева и читаются одним разбором.
//
// # Что такое «цитирует»
//
// Цитата — имя документа приёмки в тексте миграции в одной из двух форм,
// найденных переписью каталога: полный путь `docs/engineering/acceptance/<имя>.md`
// и голое `<имя>.md`, если документ с таким именем лежит в доме приёмок. Голое
// имя, не разрешающееся в приёмку (`README.md`, правило), цитатой не считается.
// Каждая цитированная приёмка обязана быть одобрена: миграция, называющая
// основанием документ без санкции, кодирует по нему.
//
// # Почему только ДОБАВЛЕННЫЕ
//
// Момент, который проверяет запрет #1, — момент изменения. Миграции, уже
// стоящие в стволе, этот момент прошли, и править их нельзя (запрет #5); их
// состояние печатается переписью, а не судится.
//
// Способность упасть и способность смолчать доказаны инъекцией —
// migration_cites_approved_acceptance_injection_test.go.
package check_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// acceptanceHomeRel — дом документов приёмок. Одно объявление координаты.
const acceptanceHomeRel = "docs/engineering/acceptance"

// approvedVerdict — слово вердикта, дающее санкцию.
const approvedVerdict = "APPROVED"

// acceptanceRecord — запись ревью приёмки: какой документ, на каком отпечатке,
// какой вердикт и в каком файле это сказано.
type acceptanceRecord struct {
	Path    string
	SHA256  string
	Verdict string
	File    string
}

var (
	reAcceptanceFullPath = regexp.MustCompile(regexp.QuoteMeta(acceptanceHomeRel) + `/([A-Za-z0-9._-]+\.md)`)
	// Голое имя: слева не часть пути и не часть имени.
	reAcceptanceBareName = regexp.MustCompile(`(?:^|[^A-Za-z0-9._/-])([a-z0-9][a-z0-9._-]*\.md)`)
)

// isReviewRecordFile — путь принадлежит одному из двух мест записей ревью.
func isReviewRecordFile(rel string) bool {
	if !strings.HasSuffix(rel, ".yaml") {
		return false
	}
	if strings.HasPrefix(rel, "docs/specs/reviews/") {
		return true
	}
	if ok, _ := path.Match("docs/changes/*/reviews/acceptance/*.yaml", rel); ok {
		return true
	}
	return false
}

// parseAcceptanceRecord разбирает запись ревью. Запись чужого вида или чужого
// репозитория — ok=false: о приёмках этой службы она ничего не говорит.
func parseAcceptanceRecord(rel string, src []byte) (acceptanceRecord, bool, error) {
	var doc struct {
		Kind    string `yaml:"kind"`
		Subject struct {
			Repository string `yaml:"repository"`
			Path       string `yaml:"path"`
			SHA256     string `yaml:"sha256"`
		} `yaml:"subject"`
		Verdict string `yaml:"verdict"`
	}
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return acceptanceRecord{}, false, fmt.Errorf("%s: запись ревью не разбирается: %w", rel, err)
	}
	if doc.Kind != "acceptance_review" || doc.Subject.Repository != "PRO-Robotech/kaname" {
		return acceptanceRecord{}, false, nil
	}
	return acceptanceRecord{
		Path: doc.Subject.Path, SHA256: strings.ToLower(doc.Subject.SHA256),
		Verdict: strings.TrimSpace(doc.Verdict), File: rel,
	}, true, nil
}

// citedAcceptances — приёмки, которые цитирует текст миграции: полный путь
// (даже несуществующий — его отсутствие есть находка) и голое имя, если оно
// разрешается в документ дома.
func citedAcceptances(text string, docs map[string][]byte) []string {
	seen := map[string]bool{}
	for _, m := range reAcceptanceFullPath.FindAllStringSubmatch(text, -1) {
		seen[acceptanceHomeRel+"/"+m[1]] = true
	}
	for _, m := range reAcceptanceBareName.FindAllStringSubmatch(text, -1) {
		rel := acceptanceHomeRel + "/" + m[1]
		if _, ok := docs[rel]; ok {
			seen[rel] = true
		}
	}
	out := make([]string, 0, len(seen))
	for rel := range seen {
		out = append(out, rel)
	}
	sort.Strings(out)
	return out
}

// fingerprint — отпечаток редакции документа: SHA-256 его байтов.
func fingerprint(src []byte) string {
	sum := sha256.Sum256(src)
	return hex.EncodeToString(sum[:])
}

// migrationAcceptanceAudit — ядро гейта, отделённое от дерева НАМЕРЕННО:
// инъекция прогоняет его на синтетическом входе. Вход — тексты ДОБАВЛЕННЫХ
// миграций, байты документов приёмок, записи ревью. Выход — находки с
// координатой и число цитат.
func migrationAcceptanceAudit(added map[string]string, docs map[string][]byte, records []acceptanceRecord) (findings []string, citations int) {
	byKey := map[string][]acceptanceRecord{}
	byPath := map[string]int{}
	for _, r := range records {
		byKey[r.Path+"@"+r.SHA256] = append(byKey[r.Path+"@"+r.SHA256], r)
		byPath[r.Path]++
	}
	rels := make([]string, 0, len(added))
	for rel := range added {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		cited := citedAcceptances(added[rel], docs)
		citations += len(cited)
		if len(cited) == 0 {
			findings = append(findings, fmt.Sprintf("%s: не цитирует ни одной приёмки (%s/<имя>.md) — "+
				"основание схемы не названо", rel, acceptanceHomeRel))
			continue
		}
		for _, doc := range cited {
			src, ok := docs[doc]
			if !ok {
				findings = append(findings, fmt.Sprintf("%s: цитирует %s — такого документа в доме приёмок нет", rel, doc))
				continue
			}
			fp := fingerprint(src)
			recs := byKey[doc+"@"+fp]
			if len(recs) == 0 {
				findings = append(findings, fmt.Sprintf("%s: цитирует %s — на текущий отпечаток %s записи ревью нет "+
					"(записей на другие отпечатки: %d); вердикт о прежней редакции на эту не переносится",
					rel, doc, fp, byPath[doc]))
				continue
			}
			for _, r := range recs {
				if r.Verdict != approvedVerdict {
					findings = append(findings, fmt.Sprintf("%s: цитирует %s — на текущем отпечатке %s вердикт «%s» (%s), "+
						"а не %s", rel, doc, fp, r.Verdict, r.File, approvedVerdict))
				}
			}
		}
	}
	return findings, citations
}

func TestNewMigrationCitesAnApprovedAcceptance(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}
	tree := gateTree(t, root)

	read := func(rel string) []byte {
		b, rerr := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- путь из индекса git этого модуля
		if rerr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %s назван индексом и не читается: %v", rel, rerr)
		}
		return b
	}

	var dirMigrations int
	docs := map[string][]byte{}
	var records []acceptanceRecord
	var recordFiles int
	for _, rel := range tree.tree.SortedFiles() {
		switch {
		case check.IsMigrationFile(rel):
			dirMigrations++
		case strings.HasPrefix(rel, acceptanceHomeRel+"/") && strings.HasSuffix(rel, ".md"):
			docs[rel] = read(rel)
		case isReviewRecordFile(rel):
			recordFiles++
			r, ok, perr := parseAcceptanceRecord(rel, read(rel))
			if perr != nil {
				t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", perr)
			}
			if ok {
				records = append(records, r)
			}
		}
	}

	// Предпосылки: пустой обход любой из трёх сторон давал бы «находок ноль»
	// по причине «прочитано ноль».
	if dirMigrations == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: индекс не назвал ни одной миграции в %s — дом "+
			"миграций переехал, гейт стережёт координату, которой нет", check.MigrationsDirRel)
	}
	if len(docs) == 0 || len(records) == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: приёмок в %s — %d, записей ревью — %d (файлов записей %d): "+
			"без обеих сторон «одобрена» не решается ни для одной цитаты",
			acceptanceHomeRel, len(docs), len(records), recordFiles)
	}

	base, ok := trunkRef(root)
	if !ok {
		t.Logf("перепись дерева: миграций %d · приёмок %d · записей ревью %d", dirMigrations, len(docs), len(records))
		t.Skipf("УСЛОВИЕ НЕ СОЗДАНО (не находка): ствол %s в этом клоне не разрешается — состав "+
			"ДОБАВЛЕННОГО установить нечем; о находках вердикта НЕТ ни зелёного, ни красного", trunkRefName)
	}
	added := map[string]string{}
	for rel := range addedMigrationFiles(t, root, base) {
		if !check.IsMigrationFile(rel) {
			continue
		}
		if !tree.has(rel) {
			continue // добавлена и снята следующим коммитом ветки
		}
		added[rel] = string(read(rel))
	}

	findings, citations := migrationAcceptanceAudit(added, docs, records)
	t.Logf("осмотрено: миграций каталога %d, из них добавлено относительно %s — %d; цитат приёмок в "+
		"добавленных %d; приёмок в доме %d; записей ревью %d (файлов %d); находок %d",
		dirMigrations, base, len(added), citations, len(docs), len(records), recordFiles, len(findings))

	if len(findings) > 0 {
		t.Fatalf("ДОБАВЛЕННАЯ миграция без действующего одобрения приёмки — %d находка(и):\n  %s\n\n"+
			"Схема меняется только по одобренной приёмке (запрет #1). Исход один: получить вердикт "+
			"APPROVED на текущую редакцию цитируемого документа либо не вносить миграцию.",
			len(findings), strings.Join(findings, "\n  "))
	}
}
