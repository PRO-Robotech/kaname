// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

// recovery_path_mark_writers_test.go — AWI-10 (задача PRO-Robotech/kaname#608):
// у отметки открытого пути два писателя, оба названы; третий — находка с
// координатой; пустой обход — отказ.

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// recoveryPathMark — объявление предмета. Имя колонки живёт здесь, в файле
// пробы, а не в коде гейта (шапка гейта).
var recoveryPathMark = check.RecoveryPathMarkDecl{
	Column:        "recovery_path_opened_at",
	ClearerFile:   "internal/repo/kaname/pg/recovery_code_repo.go",
	MigrationFile: "20261005030000_active_identity_has_a_way_in.sql",
}

func TestTheRecoveryPathMarkHasTwoNamedWriters(t *testing.T) {
	t.Parallel()
	c, err := check.RecoveryPathMarkWriters(prodGoFiles(t, moduleRoot(t)), migrations.FS, recoveryPathMark)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Logf("перепись: файлов Go %d · миграций %d · упоминаний в Go %d · снимающих %v · миграций, называющих отметку, %v",
		c.GoFiles, c.SQLFiles, c.GoMentions, c.Clearers, c.SQLMentioners)
	for _, f := range c.Findings {
		t.Error(f)
	}
}

const rpClearer = `package pg
const closeSQL = "UPDATE users SET recovery_path_opened_at = NULL WHERE id = $1"
`

func rpMigrations(extra map[string]string) fstest.MapFS {
	m := fstest.MapFS{
		"0001_initial.sql": {Data: []byte("CREATE TABLE users (id text);")},
		"20261005030000_active_identity_has_a_way_in.sql": {Data: []byte("ALTER TABLE users ADD COLUMN recovery_path_opened_at timestamptz;")},
	}
	for k, v := range extra {
		m[k] = &fstest.MapFile{Data: []byte(v)}
	}
	return m
}

// Законный близнец: один снимающий оператор, один перенос — молчит.
func TestRecoveryPathMarkInjection_LawfulTwinIsSilent(t *testing.T) {
	t.Parallel()
	c, err := check.RecoveryPathMarkWriters(map[string]string{
		recoveryPathMark.ClearerFile: rpClearer,
		"internal/apps/x/doc.go":     "package x\n// recovery_path_opened_at в комментарии — не писатель\n",
	}, rpMigrations(nil), recoveryPathMark)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Findings) != 0 || len(c.Clearers) != 1 {
		t.Fatalf("законный близнец обязан молчать: %v · снимающих %v", c.Findings, c.Clearers)
	}
}

// Каждый дефект краснеет и называет координату.
func TestRecoveryPathMarkInjection_EveryDefectIsFound(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		goFiles map[string]string
		sql     map[string]string
		want    string
	}{
		"третий писатель — установка продуктом": {
			goFiles: map[string]string{
				recoveryPathMark.ClearerFile: rpClearer,
				"internal/apps/x/open.go":    "package x\nconst q = `UPDATE users SET recovery_path_opened_at = now()`\n",
			},
			want: "internal/apps/x/open.go:2",
		},
		"установка в файле снимающего": {
			goFiles: map[string]string{
				recoveryPathMark.ClearerFile: rpClearer + "const openSQL = \"UPDATE users SET recovery_path_opened_at = $2\"\n",
			},
			want: recoveryPathMark.ClearerFile + ":3",
		},
		"обрывок склейки": {
			goFiles: map[string]string{
				recoveryPathMark.ClearerFile: rpClearer,
				"internal/apps/x/split.go":   "package x\nconst q = \"UPDATE users SET recovery_path_opened_at\" + \" = now()\"\n",
			},
			want: "internal/apps/x/split.go:2",
		},
		"вторая миграция ставит отметку": {
			goFiles: map[string]string{recoveryPathMark.ClearerFile: rpClearer},
			sql:     map[string]string{"20271231000000_more.sql": "UPDATE users SET recovery_path_opened_at = now();"},
			want:    "20271231000000_more.sql",
		},
		"снимающего нет": {
			goFiles: map[string]string{"internal/apps/x/none.go": "package x\n"},
			want:    "снимающих операторов отметки",
		},
		"пустой обход": {
			goFiles: map[string]string{},
			want:    "обход пуст",
		},
	}
	for name, tc := range cases {
		c, err := check.RecoveryPathMarkWriters(tc.goFiles, rpMigrations(tc.sql), recoveryPathMark)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		found := false
		for _, f := range c.Findings {
			if strings.Contains(f, tc.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: дефект не найден (ждали %q): %v", name, tc.want, c.Findings)
		}
	}
}
