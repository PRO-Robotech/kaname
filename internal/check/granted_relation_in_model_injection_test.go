// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// granted_relation_in_model_injection_test.go — доказательство, что гейт выдачи
// отношения СПОСОБЕН упасть и СПОСОБЕН смолчать (задача #17, семейство
// `grantedrelationinmodel`).
//
// Гейт зелен на сегодняшнем дереве, и это ничего не доказывает: зелёным он был
// бы и с предикатом, который ничего не ищет. Поэтому его извлечение прогоняется
// здесь на синтетике, где ответ известен заранее.
//
// Инъекция зовёт ТУ ЖЕ функцию, что и гейт, а не свою копию.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// injModel — модель-фикстура: у типа `cluster` объявлено `quota_reader`, у
// `group` — `member`. Отношения `phantom_reader` нет ни у кого.
const injModel = `
model
  schema 1.1

type user

type group
    relations
        define member: [user, service_account]

type cluster
    relations
        define system_admin: [user, service_account]
        define quota_reader: [service_account, group#member] or system_admin
`

// buildGrantTree — синтетический корень: миграция и применяемая модель.
func buildGrantTree(t *testing.T, sql, model string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range map[string]string{
		check.MigrationsDirRel + "/0999_injection.sql": sql,
		check.AppliedModelRelPath:                      model,
	} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatalf("фикстура не собрана: %v", err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("фикстура не собрана: %v", err)
		}
	}
	return root
}

// TestGrantedRelationGate_InjectionBothWays — обе способности по каждой оси.
func TestGrantedRelationGate_InjectionBothWays(t *testing.T) {
	t.Parallel()

	rels := check.RelationsByType(injModel)
	if len(rels) != 3 || !rels["cluster"]["quota_reader"] {
		t.Fatalf("предпосылка фикстуры: модель обязана разбираться, иначе проба ничего не "+
			"проверяет (типов %d)", len(rels))
	}

	cases := []struct {
		name        string
		sql         string
		wantFinding bool
		wantPair    string
		wantText    string
	}{
		{
			// ЗАКОННЫЙ БЛИЗНЕЦ — ровно та же форма записи, отношение существует.
			// Без него гейт ловил бы форму, а не существо, и первый же законный
			// кортеж сделал бы его ложно-красным.
			name: "законная выдача существующего отношения — гейт молчит",
			sql: `INSERT INTO kaname.fga_outbox (event_type, payload, created_at) VALUES
  ('fga.tuple.write',
   jsonb_build_object(
     'user',     'group:grp1#member',
     'relation', 'quota_reader',
     'object',   'cluster:cluster_root'),
   now());`,
			wantFinding: false,
			wantPair:    "cluster#quota_reader",
		},
		{
			// ВОЗВРАЩЁННЫЙ ДЕФЕКТ — отношения в модели нет.
			name: "выдача отношения, которого в модели нет — находка",
			sql: `INSERT INTO kaname.fga_outbox (event_type, payload, created_at) VALUES
  ('fga.tuple.write',
   jsonb_build_object(
     'user',     'group:grp1#member',
     'relation', 'phantom_reader',
     'object',   'cluster:cluster_root'),
   now());`,
			wantFinding: true,
			wantPair:    "cluster#phantom_reader",
			wantText:    "ОТНОШЕНИЯ",
		},
		{
			// Тип целиком неизвестен — тоже находка, и с ДРУГИМ текстом: два
			// разных предмета не сваливаются в одно сообщение.
			name: "выдача на типе, которого в модели нет — находка",
			sql: `INSERT INTO kaname.fga_outbox (event_type, payload, created_at) VALUES
  ('fga.tuple.write',
   jsonb_build_object(
     'user',     'user:u1',
     'relation', 'member',
     'object',   'phantom_type:x'),
   now());`,
			wantFinding: true,
			wantPair:    "phantom_type#member",
			wantText:    "НЕТ ТИПА",
		},
		{
			// ВТОРАЯ ФОРМА записи кортежа — готовый объект JSON. Её производит
			// сведённая первичная миграция; распознаватель, знающий только
			// конструктор, не нашёл бы НИЧЕГО и остался бы на вид рабочим.
			name: "вторая форма кортежа (готовый объект) — распознаётся",
			sql: `INSERT INTO kaname.fga_outbox (event_type, payload) VALUES
  ('fga.tuple.write', '{"user": "user:u1", "object": "cluster:root", "relation": "phantom_reader"}');`,
			wantFinding: true,
			wantPair:    "cluster#phantom_reader",
			wantText:    "ОТНОШЕНИЯ",
		},
		{
			// Законный близнец ВТОРОЙ формы: та же запись, отношение существует.
			name: "вторая форма кортежа с существующим отношением — молчание",
			sql: `INSERT INTO kaname.fga_outbox (event_type, payload) VALUES
  ('fga.tuple.write', '{"user": "user:u1", "object": "cluster:root", "relation": "quota_reader"}');`,
			wantFinding: false,
			wantPair:    "cluster#quota_reader",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := buildGrantTree(t, tc.sql, injModel)
			grants, read, blocks, err := check.GrantsFromMigrations(root)
			if err != nil {
				t.Fatalf("фикстура не прочитана: %v", err)
			}
			// Извлечение обязано СРАБОТАТЬ в обоих случаях — иначе «нет находки»
			// означало бы «ничего не прочитано», а не «всё в порядке».
			if read != 1 || blocks != 1 || len(grants) != 1 {
				t.Fatalf("извлечение сломано: миграций %d, блоков %d, пар %d — вердикт "+
					"беспредметен", read, blocks, len(grants))
			}
			if got := grants[0].ObjectType + "#" + grants[0].Relation; got != tc.wantPair {
				t.Fatalf("извлечена пара %q вместо %q", got, tc.wantPair)
			}

			missing := check.MissingGrantedRelations(grants, rels)
			if tc.wantFinding != (len(missing) == 1) {
				t.Fatalf("инъекция: ожидали находка=%v для пары %s, получено %d:\n  %s",
					tc.wantFinding, tc.wantPair, len(missing), strings.Join(missing, "\n  "))
			}
			if !tc.wantFinding {
				return
			}
			// Находка обязана НАЗЫВАТЬ КООРДИНАТУ, иначе по ней нельзя
			// действовать, и предмет — иначе два разных случая читаются одним.
			if !strings.Contains(missing[0], "0999_injection.sql") {
				t.Errorf("находка не несёт путь файла: %s", missing[0])
			}
			if !strings.Contains(missing[0], tc.wantText) {
				t.Errorf("находка не называет предмет (%s): %s", tc.wantText, missing[0])
			}
		})
	}
}

// TestGrantedRelationGate_JSONFormIsNotMistakenForDSL — предпосылка разбора
// модели: строки готовой формы в JSON НЕ читаются как объявления типа или
// отношения. Читались бы — гейт «находил» бы отношения там, где их нет, и молчал
// бы на настоящем расхождении.
func TestGrantedRelationGate_JSONFormIsNotMistakenForDSL(t *testing.T) {
	t.Parallel()

	const jsonish = `
data:
  model.json: |
    {"type_definitions":[{"type":"cluster","relations":{"quota_reader":{}}}]}
`
	if got := check.RelationsByType(jsonish); len(got) != 0 {
		t.Fatalf("готовая форма в JSON прочитана как DSL (%d типов) — гейт объявлял бы "+
			"отношения существующими там, где их нет: %v", len(got), got)
	}
	t.Log("предпосылка: форма в JSON за объявление НЕ зачтена")
}

// TestGrantedRelationGate_EmptyWalkIsRefused — пустой обход не «находок нет», а
// «прочитано ноль».
func TestGrantedRelationGate_EmptyWalkIsRefused(t *testing.T) {
	t.Parallel()

	if _, _, _, err := check.GrantsFromMigrations(t.TempDir()); err == nil {
		t.Error("дерево без каталога миграций прочиталось без ошибки — «ноль находок» стало бы " +
			"неотличимо от «ноль прочитанного»")
	}

	// Миграция без записи в очередь — законный близнец пустого обхода: она есть,
	// но предметом не является, и гейт обязан отличать это от слепоты. Отличает
	// не он сам, а его вызывающий: величина «миграций осмотрено» здесь ноль.
	root := buildGrantTree(t, "CREATE TABLE kaname.users (id text primary key);", injModel)
	grants, read, _, err := check.GrantsFromMigrations(root)
	if err != nil {
		t.Fatalf("фикстура не прочитана: %v", err)
	}
	if read != 0 || len(grants) != 0 {
		t.Fatalf("миграция без записи в очередь зачтена в осмотренное: миграций %d, пар %d",
			read, len(grants))
	}
	t.Log("законный близнец: миграция без очереди в осмотренное не зачтена")
}
