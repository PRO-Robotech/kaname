// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// quota_reader_grant_test.go — владелец считаемого вида ОБЯЗАН быть
// читателем пределов.
//
// Порт с монорепо (`internal/repohygiene/quotareadergrant_test.go`, снят
// вынесением службы — `kacho#2597`). Дословно: предикат, обе формы записи
// членства (литералами и идентификаторами после сведения цепочки миграций).
// Изменилось: пакет (`repohygiene_test` → `check_test`), обход дерева
// (`repoRootFor(t)` → `platformtree.Require(t)`, см. шапку
// `nested_quota_charger_test.go` — тот же кросс-сервисный довод).
//
// # ПРЕДМЕТ (дословно из монорепо)
//
// Списание квоты живёт у владельца типа, а величина — у iam. Значит на
// первой мутации владелец идёт к соседу за потолком, и если права звать
// резолв у него нет, отказ приходит fail-closed: НИ ОДНА его мутация не
// проходит.
package check_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestEveryQuotaChargingOwnerIsAQuotaReader — сам гейт.
func TestEveryQuotaChargingOwnerIsAQuotaReader(t *testing.T) {
	root := platformtree.Require(t)
	files, err := treecorpus.UnderWithSuffix(filepath.Join(root, "services"), ".sql")
	if err != nil {
		t.Fatalf("перечень миграций берётся у индекса дерева, а не обходом диска: %v", err)
	}

	charging := map[string]string{}
	readers := map[string]string{}

	chargeRe := regexp.MustCompile(`kacho_quota_count\(`)
	readerRe := regexp.MustCompile(`'kacho-([a-z]+)'`)

	migrationsSeen := 0
	for _, path := range files {
		if !strings.Contains(path, "/internal/migrations/") {
			continue
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Fatalf("чтение %s: %v", path, rerr)
		}
		migrationsSeen++
		body := string(raw)

		rel := path
		if i := strings.Index(path, "/services/"); i >= 0 {
			rel = path[i+1:]
		}

		if strings.HasPrefix(rel, "services/iam/") {
			for domain := range quotaReaderDomainsByID(body) {
				readers[domain] = rel
			}
			if !strings.Contains(body, "module.quota_readers") {
				continue
			}
			for _, m := range readerRe.FindAllStringSubmatch(body, -1) {
				if m[1] == "system" {
					continue
				}
				readers[m[1]] = rel
			}
			continue
		}

		if chargeRe.MatchString(body) {
			parts := strings.Split(rel, "/")
			if len(parts) > 1 {
				charging[parts[1]] = rel
			}
		}
	}

	if migrationsSeen == 0 {
		t.Fatal("гейт не прочитал НИ ОДНОЙ миграции — он объявил бы «ноль находок», ничего не осмотрев")
	}
	if len(charging) == 0 {
		t.Fatalf("гейт не нашёл ни одного домена со списанием: либо имя триггера сменилось, "+
			"либо предикат перестал его ловить. Осмотрено миграций: %d", migrationsSeen)
	}

	var missing []string
	for domain, where := range charging {
		if _, ok := readers[domain]; !ok {
			missing = append(missing, domain+" — списывает квоту ("+where+"), но не назван читателем пределов")
		}
	}
	sort.Strings(missing)

	t.Logf("перепись: миграций осмотрено %d; доменов со списанием %d (%s); читателей пределов %d (%s); "+
		"владелец величин из счёта списывающих исключён намеренно — резолва к самому себе нет",
		migrationsSeen, len(charging), joinKeys(charging), len(readers), joinKeys(readers))

	if len(missing) > 0 {
		t.Fatalf("владелец считаемого вида обязан быть читателем пределов — иначе КАЖДАЯ его "+
			"мутация отвергается fail-closed на пути материализации, и это не видно ни одной "+
			"его собственной пробе:\n%s", strings.Join(missing, "\n"))
	}
}

func joinKeys(m map[string]string) string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// quotaReaderDomainsByID — домены, чьи служебные учётки состоят в группе
// читателей пределов, когда членство записано ИДЕНТИФИКАТОРАМИ (вторая
// законная форма — свод, а не рукописная миграция).
func quotaReaderDomainsByID(body string) map[string]string {
	out := map[string]string{}

	var groupID string
	for _, m := range reSquashGroupRow.FindAllStringSubmatch(body, -1) {
		if m[2] == quotaReaderGroupName {
			groupID = m[1]
			break
		}
	}
	if groupID == "" {
		return out
	}

	accounts := map[string]string{}
	for _, m := range reSquashServiceAccountRow.FindAllStringSubmatch(body, -1) {
		accounts[m[1]] = m[2]
	}

	for _, m := range reSquashGroupMemberRow.FindAllStringSubmatch(body, -1) {
		if m[1] != groupID || m[2] != "service_account" {
			continue
		}
		name, ok := accounts[m[3]]
		if !ok {
			continue
		}
		d := strings.TrimPrefix(name, "kacho-")
		if d == name || d == "system" {
			continue
		}
		out[d] = name
	}
	return out
}

// quotaReaderGroupName — имя группы читателей пределов в СТРОКЕ.
const quotaReaderGroupName = "module-quota-readers"

var (
	reSquashGroupRow = regexp.MustCompile(
		`INSERT INTO kaname\.groups \([^)]*\) VALUES \('([^']+)', '[^']*', '([^']+)'`)
	reSquashServiceAccountRow = regexp.MustCompile(
		`INSERT INTO kaname\.service_accounts \([^)]*\) VALUES \('([^']+)', '[^']*', '([^']+)'`)
	reSquashGroupMemberRow = regexp.MustCompile(
		`INSERT INTO kaname\.group_members \([^)]*\) VALUES \('([^']+)', '([^']+)', '([^']+)'`)
)
