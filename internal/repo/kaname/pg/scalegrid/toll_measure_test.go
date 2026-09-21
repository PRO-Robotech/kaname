// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid_test

// toll_measure_test.go — ВРЕМЕННЫЙ ЗАМЕР: сколько миграций под отпечатком
// сторожат ПРЕДМЕТ, а сколько попали в него тем, что ССЫЛАЮТСЯ на измеряемую
// таблицу из чужого DDL.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/scalegrid"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

func TestTollMeasure(t *testing.T) {
	root, _ := platformtree.RequireCorpus(t)
	fp, err := scalegrid.ComputeFingerprint(root)
	if err != nil {
		t.Fatalf("отпечаток: %v", err)
	}
	var sql []string
	for _, f := range fp.Files {
		if strings.HasSuffix(f, ".sql") {
			sql = append(sql, f)
		}
	}
	t.Logf("таблиц выведено %d: %v", len(fp.Tables), fp.Tables)
	t.Logf("файлов под отпечатком %d, из них .sql %d", len(fp.Files), len(sql))

	// СУБЪЕКТ DDL — то, над чем стоит глагол: `CREATE|ALTER|DROP ... TABLE x`,
	// `ON x`, `INDEX ... ON x`. Ссылка (`REFERENCES x`) субъектом НЕ является.
	subject := 0
	var refOnly []string
	for _, rel := range sql {
		b, rerr := os.ReadFile(filepath.Join(root, rel))
		if rerr != nil {
			if b, rerr = os.ReadFile(rel); rerr != nil {
				t.Logf("НЕ ПРОЧИТАН: %s (%v)", rel, rerr)
				continue
			}
		}
		src := string(b)
		isSubject := false
		for _, tbl := range fp.Tables {
			pat := regexp.MustCompile(`(?is)\b(?:CREATE|ALTER|DROP)\b[^;]{0,120}?\b(?:TABLE|INDEX[^;]{0,60}?ON|TRIGGER[^;]{0,60}?ON|VIEW)\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?` + regexp.QuoteMeta(tbl) + `\b`)
			if pat.MatchString(src) {
				isSubject = true
				break
			}
		}
		if isSubject {
			subject++
		} else {
			refOnly = append(refOnly, filepath.Base(rel))
		}
	}
	t.Logf("из .sql под отпечатком: измеряемая таблица — СУБЪЕКТ DDL в %d, только ССЫЛКА в %d",
		subject, len(refOnly))
	for _, f := range refOnly {
		t.Logf("   только ссылка: %s", f)
	}
}
