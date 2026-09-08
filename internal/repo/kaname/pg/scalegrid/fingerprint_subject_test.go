// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMigrationTouchesStructure_ProvenByInjection — отбор миграций под отпечаток
// сужен до СТРУКТУРНЫХ правок и доказан в обе стороны.
//
// Предмет — цена ложного попадания: каждая пересъёмка отчётов около двух часов
// прогона, и обесценивал их файл, измеряемого пути не касавшийся. Проба на
// синтетическом входе, поэтому не зависит от того, что сегодня лежит в дереве.
func TestMigrationTouchesStructure_ProvenByInjection(t *testing.T) {
	tables := []string{"access_bindings", "role_rule_selectors"}

	cases := []struct {
		name string
		sql  string
		want bool
	}{
		{
			name: "индекс на измеряемой таблице — влияет",
			sql:  "CREATE INDEX access_bindings_scope_idx ON kaname.access_bindings (scope_type, scope_id);",
			want: true,
		},
		{
			name: "снятие колонки измеряемой таблицы — влияет",
			sql:  "ALTER TABLE kaname.role_rule_selectors DROP COLUMN legacy_tier;",
			want: true,
		},
		{
			name: "имя таблицы ТОЛЬКО в комментарии — не влияет",
			// Самый частый вид ложного попадания: миграция объясняет, ПОЧЕМУ
			// она соседнюю таблицу не трогает, — и попадала под отпечаток
			// именно этим объяснением.
			sql: "-- Здесь намеренно не трогаем access_bindings: у неё свой владелец.\n" +
				"CREATE TABLE kaname.quota_usage (id text PRIMARY KEY);",
			want: false,
		},
		{
			name: "блочный комментарий с именем таблицы — не влияет",
			sql:  "/* role_rule_selectors переписывается отдельной задачей */\nINSERT INTO kaname.limits (id) VALUES ('lim-1');",
			want: false,
		},
		{
			name: "посев данных в измеряемую таблицу — не влияет",
			// Данные меняют то, ЧТО намеряли; отпечаток отвечает на «изменилось
			// ли ТО, ЧЕМ мерили». Стоимость прогона на новых данных меряет сам
			// прогон, и отчёт от посева ложным не становится.
			sql:  "INSERT INTO kaname.access_bindings (id, role_id) VALUES ('acb-1', 'rol-1');",
			want: false,
		},
		{
			name: "DDL над ЧУЖОЙ таблицей — не влияет",
			sql:  "CREATE INDEX fga_outbox_pending_idx ON kaname.fga_outbox (sent_at) WHERE sent_at IS NULL;",
			want: false,
		},
		{
			name: "имя измеряемой таблицы как ПРЕФИКС чужого имени — не влияет",
			// Граница слова: `access_bindings_archive` — другая таблица.
			sql:  "CREATE TABLE kaname.access_bindings_archive (id text PRIMARY KEY);",
			want: false,
		},
		{
			name: "временная таблица ИЗ ВЫБОРКИ измеряемой — не влияет",
			// #1833. `CREATE TEMP TABLE … ON COMMIT DROP AS SELECT … FROM <измеряемая>`
			// несёт в ОДНОМ операторе и `CREATE`, и `DROP`, и имя измеряемой
			// таблицы — но DDL идёт над ВРЕМЕННОЙ таблицей, а измеряемая только
			// ЧИТАЕТСЯ. Плана чтения это не меняет, значит отчёт не устаревает.
			sql: "CREATE TEMP TABLE _sys_rule ON COMMIT DROP AS\n" +
				"  SELECT id, scope_type FROM kaname.access_bindings WHERE role_id IS NOT NULL;",
			want: false,
		},
		{
			name: "временная таблица без ON COMMIT — тоже не влияет",
			// Слово `DROP` из формы не обязательно: одного `CREATE` над временной
			// таблицей довольно, чтобы прежний предикат взял оператор целиком.
			sql:  "CREATE TEMPORARY TABLE _seg_scan AS SELECT verb FROM kaname.role_rule_selectors;",
			want: false,
		},
		{
			name: "снятие временной таблицы по имени — не влияет",
			sql:  "DROP TABLE IF EXISTS _seg_scan;\nSELECT count(*) FROM kaname.access_bindings;",
			want: false,
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: постоянная таблица из выборки измеряемой — влияет",
			// Форма та же, слова `TEMP` нет. Такая таблица живёт в схеме и
			// меняет её структуру — отпечаток обязан её взять. Без этого случая
			// починка выродилась бы в «не брать CREATE … AS SELECT вовсе».
			sql:  "CREATE TABLE kaname.access_bindings_snapshot AS SELECT * FROM kaname.access_bindings;",
			want: true,
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: временная таблица И правка измеряемой — влияет",
			// Оператор с временной таблицей отсеивается, СОСЕДНИЙ — нет.
			sql: "CREATE TEMP TABLE _scan ON COMMIT DROP AS SELECT id FROM kaname.access_bindings;\n" +
				"ALTER TABLE kaname.access_bindings ADD COLUMN note text;",
			want: true,
		},
		{
			name: "DDL и упоминание в РАЗНЫХ операторах — не влияет",
			// Оператор разбирается целиком: DDL есть, но не над измеряемой.
			sql: "INSERT INTO kaname.access_bindings (id) VALUES ('acb-2');\n" +
				"CREATE INDEX limits_kind_idx ON kaname.limits (kind);",
			want: false,
		},
	}

	var influencing, ignored int
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := migrationTouchesStructure(c.sql, tables)
			if got != c.want {
				t.Fatalf("вердикт %v, ожидался %v", got, c.want)
			}
			if got {
				influencing++
			} else {
				ignored++
			}
		})
	}

	t.Logf("перепись инъекции: случаев %d; признано влияющими %d; отсеяно %d", len(cases), influencing, ignored)
	if influencing == 0 || ignored == 0 {
		t.Fatal("инъекция односторонняя: предикат, отвечающий одинаково на всё, прошёл бы её")
	}
}

// TestScaffoldingExclusionSelfExpires — исключение оснастки живёт, пока у него
// есть предмет, и доказано в обе стороны.
//
// Без этой пробы исключение было бы обычным послаблением: перечень имён, про
// который никто не узнает, если файл начнёт делать то, ради чего его исключать
// перестали.
func TestScaffoldingExclusionSelfExpires(t *testing.T) {
	// Корень дерева — от каталога пакета вверх до `go.mod`. Внутренний пакет
	// собственного корня не знает, а звать git ради него значило бы завести
	// зависимость от окружения там, где хватает подъёма по каталогам.
	root := repoRootFromPackageDir(t)

	// (1) Сегодняшнее дерево: исключение законно и множество СУЖЕНО.
	all, err := nonTestGoFiles(root, gridDir)
	if err != nil {
		t.Fatalf("состав каталога сетки: %v", err)
	}
	kept, err := withoutScaffolding(root, all)
	if err != nil {
		t.Fatalf("исключение оснастки отвергнуто на живом дереве: %v", err)
	}
	t.Logf("перепись: не-тестовых файлов каталога сетки %d; под отпечатком остаётся %d; объявлено оснасткой %d",
		len(all), len(kept), len(fingerprintScaffolding))
	if len(kept) >= len(all) {
		t.Fatal("множество не сузилось: исключение не применилось ни к одному файлу — значит оно беспредметно")
	}
	if len(kept) == 0 {
		t.Fatal("под отпечатком не осталось ничего: исключение съело предмет замера целиком")
	}

	// (2) Файл, объявленный оснасткой, ПЕРЕСТАЛ ею быть — исключение истекает.
	if _, err := withoutScaffolding(t.TempDir(), []string{gridDir + "/fingerprint.go"}); err == nil {
		t.Fatal("исключение принято на дереве, где исключаемого файла нет — оно молча покрывало бы пустоту")
	}

	// (3) Признак «перестал быть оснасткой» берётся с РАЗОБРАННОГО дерева.
	//
	// Первая редакция читала текст — и объявила находкой сам файл отпечатка:
	// слова `SELECT|INSERT|…` живут в нём строковым литералом. Гейт, сработавший
	// на собственном объяснении, — тот самый класс, который мы ловим.
	if ok, why := scaffoldingStillHolds("x.go", []byte(
		"package x\nimport \"github.com/jackc/pgx/v5/pgxpool\"\nvar P *pgxpool.Pool\n")); ok {
		t.Fatal("импорт пакета базы не распознан: исключение не истекло бы, начни оснастка мерить")
	} else if why == "" {
		t.Fatal("отказ без причины: читатель не узнает, чем именно файл перестал быть оснасткой")
	}
	if ok, _ := scaffoldingStillHolds("y.go", []byte(
		"package y\nfunc f(db any) { rows, _ := db.(interface{ Query(string) (any, error) }).Query(\"SELECT 1\") ; _ = rows }\n")); ok {
		t.Fatal("вызов Query не распознан: обращение к базе прошло бы за оснастку")
	}

	// Законный близнец: SQL в ЛИТЕРАЛЕ и в комментарии — не обращение к базе.
	// Оснастка вправе цитировать запрос, объясняя, почему сама его не шлёт.
	if ok, why := scaffoldingStillHolds("z.go", []byte(
		"package z\n// здесь нет ни одного SELECT — предмет отпечатка иной\nconst q = \"SELECT 1 FROM kaname.access_bindings\"\n")); !ok {
		t.Fatalf("цитата запроса принята за обращение к базе (%s): исключение истекло бы на собственном объяснении", why)
	}

	// Нечитаемый файл — ОТКАЗ, а не молчание: вынести из-под отпечатка то, чего
	// не прочитали, значит объявить свежим отчёт о неизвестно чём.
	if ok, _ := scaffoldingStillHolds("broken.go", []byte("package ??? {")); ok {
		t.Fatal("неразбираемый файл принят за оснастку — отпечаток потерял бы его молча")
	}
}

// repoRootFromPackageDir — корень дерева подъёмом от каталога пакета.
func repoRootFromPackageDir(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("рабочий каталог: %v", err)
	}
	// Корнем берётся САМЫЙ ВНЕШНИЙ `go.mod`, а не первый встречный: у службы
	// теперь СВОЙ модуль, и подъём «до первого» останавливался бы в её каталоге,
	// а пути ниже называют место В ДЕРЕВЕ МОНОРЕПО — от корня.
	outermost := ""
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			outermost = dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	if outermost != "" {
		return outermost
	}
	t.Fatal("корень дерева не найден: подъём от каталога пакета не встретил go.mod")
	return ""
}
