// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid

import "testing"

// КРАСНОЕ ДО КОДА — отбор миграций сужается до СУБЪЕКТА оператора определения.
//
// Прежний предикат брал оператор, если в нём ГДЕ УГОДНО встречалось имя
// измеряемой таблицы. Раздел ссылок чужого определения — `REFERENCES
// kaname.<измеряемая>` — этим и ловился: DDL идёт над ЧУЖОЙ таблицей, а
// измеряемая названа лишь как адресат ключа. Плана ЧТЕНИЯ измеряемой таблицы
// это не меняет.
//
// Красное здесь — не поломка фикстуры: положительные близнецы тех же форм в
// этой же таблице зелены, и каждый отрицательный отличается от своего близнеца
// РОВНО ОДНИМ фактом — тем, по какую сторону оператора стоит измеряемое имя.
func TestMigrationTouchesStructure_SubjectNotMention(t *testing.T) {
	tables := []string{"access_bindings", "role_rule_selectors", "users"}

	cases := []struct {
		name string
		sql  string
		want bool
	}{
		// ── ССЫЛКА НА ИЗМЕРЯЕМУЮ ТАБЛИЦУ — НЕ ЕЁ ПРАВКА ────────────────────
		{
			name: "REFERENCES измеряемой внутри CREATE TABLE чужой — не влияет",
			sql: "CREATE TABLE kaname.human_sessions (\n" +
				"    id      text NOT NULL,\n" +
				"    user_id text NOT NULL,\n" +
				"    CONSTRAINT human_sessions_user_fk FOREIGN KEY (user_id)\n" +
				"        REFERENCES kaname.users(id) ON DELETE CASCADE\n" +
				");",
			want: false,
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: та же форма, но субъект — измеряемая — влияет",
			// Отличие от случая выше РОВНО ОДНО: имя измеряемой таблицы стоит
			// не в разделе ссылок, а на месте субъекта определения.
			sql: "CREATE TABLE kaname.users (\n" +
				"    id      text NOT NULL,\n" +
				"    account_id text NOT NULL,\n" +
				"    CONSTRAINT users_account_fk FOREIGN KEY (account_id)\n" +
				"        REFERENCES kaname.accounts(id) ON DELETE CASCADE\n" +
				");",
			want: true,
		},
		{
			name: "ключ на ЧУЖОЙ таблице, ссылающийся на измеряемую — не влияет",
			sql: "ALTER TABLE ONLY kaname.access_binding_emitted_tuples\n" +
				"    ADD CONSTRAINT aget_binding_id_fkey FOREIGN KEY (binding_id)\n" +
				"    REFERENCES kaname.access_bindings(id) ON DELETE CASCADE;",
			want: false,
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: тот же ключ, но НА измеряемой таблице — влияет",
			sql: "ALTER TABLE ONLY kaname.access_bindings\n" +
				"    ADD CONSTRAINT access_bindings_role_fk FOREIGN KEY (role_id)\n" +
				"    REFERENCES kaname.roles(id) ON DELETE RESTRICT;",
			want: true,
		},
		{
			name: "представление, ЧИТАЮЩЕЕ измеряемую — не влияет",
			// Плана чтения самой измеряемой таблицы новое представление не меняет.
			sql: "CREATE VIEW kaname.binding_digest AS\n" +
				"  SELECT id, role_id FROM kaname.access_bindings WHERE revoked_at IS NULL;",
			want: false,
		},
		{
			name: "функция, ЧИТАЮЩАЯ измеряемую — не влияет",
			sql: "CREATE FUNCTION kaname.binding_count() RETURNS bigint LANGUAGE sql AS $$\n" +
				"  SELECT count(*) FROM kaname.access_bindings;\n" +
				"$$;",
			want: false,
		},
		{
			name: "последовательность, ПРИВЯЗАННАЯ к колонке измеряемой — не влияет",
			sql:  "ALTER SEQUENCE kaname.binding_seq OWNED BY kaname.access_bindings.id;",
			want: false,
		},

		// ── ОБРАТНАЯ СЛЕПОТА: формы, которые ДЕЙСТВИТЕЛЬНО меняют план ─────
		{
			name: "снятие индекса измеряемой таблицы — влияет",
			// Имя индекса таблицу не называет: `kaname.access_bindings_scope_idx`
			// не совпадает с `kaname.access_bindings` по границе слова. Прежний
			// предикат этого не брал ВОВСЕ — слепая зона, найденная сужением.
			sql:  "DROP INDEX kaname.access_bindings_scope_idx;",
			want: true,
		},
		{
			name: "переименование индекса измеряемой таблицы — влияет",
			sql:  "ALTER INDEX kaname.access_bindings_scope_idx RENAME TO access_bindings_scope2_idx;",
			want: true,
		},
		{
			name: "снятие СХЕМЫ целиком — влияет",
			// Измеряемых таблиц после этого нет ни одной, а имя ни одной из них
			// в операторе не встречается.
			sql:  "DROP SCHEMA IF EXISTS kaname CASCADE;",
			want: true,
		},
		{
			name: "переименование измеряемой таблицы — влияет",
			sql:  "ALTER TABLE kaname.access_bindings RENAME TO access_grants;",
			want: true,
		},
		{
			name: "переименование ЧУЖОЙ таблицы В имя измеряемой — влияет",
			// Имя измеряемой стоит справа от RENAME TO — и после оператора
			// измеряемой таблицей становится другая строка на диске.
			sql:  "ALTER TABLE kaname.legacy_grants RENAME TO access_bindings;",
			want: true,
		},
		{
			name: "смена типа колонки измеряемой — влияет",
			sql:  "ALTER TABLE kaname.access_bindings ALTER COLUMN scope TYPE text;",
			want: true,
		},
		{
			name: "смена владельца измеряемой — влияет",
			sql:  "ALTER TABLE kaname.access_bindings OWNER TO kaname_rw;",
			want: true,
		},
		{
			name: "параметр хранения измеряемой — влияет",
			sql:  "ALTER TABLE IF EXISTS kaname.access_bindings SET (fillfactor = 70);",
			want: true,
		},
		{
			name: "статистика планировщика по колонке измеряемой — влияет",
			sql:  "ALTER TABLE kaname.access_bindings ALTER COLUMN labels SET STATISTICS 500;",
			want: true,
		},
		{
			name: "индекс с оговорками CONCURRENTLY/ONLY на измеряемой — влияет",
			sql: "CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS access_bindings_x_idx\n" +
				"  ON ONLY kaname.access_bindings USING btree (id);",
			want: true,
		},
		{
			name: "снятие нескольких таблиц одним оператором, измеряемая среди них — влияет",
			sql:  "DROP TABLE IF EXISTS kaname.limits, kaname.access_bindings CASCADE;",
			want: true,
		},
		{
			name: "секция, подшиваемая к измеряемой таблице — влияет",
			sql:  "CREATE TABLE kaname.access_bindings_2026 PARTITION OF kaname.access_bindings FOR VALUES IN ('2026');",
			want: true,
		},
		{
			name: "замена представления, которое ЧИТАЕТ запрос вердикта — влияет",
			sql: "CREATE OR REPLACE VIEW kaname.role_rule_selectors AS\n" +
				"  SELECT role_id, rule_fp FROM kaname.role_rule_source;",
			want: true,
		},
		{
			name: "имя измеряемой в КАВЫЧКАХ — влияет",
			sql:  `ALTER TABLE "kaname"."access_bindings" ADD COLUMN note text;`,
			want: true,
		},
		{
			name: "ДИНАМИЧЕСКИЙ DDL по каталогу — влияет (предмет статически не выводится)",
			// Предмет оператора — `%I`, подставляемое обходом каталога. Вывести
			// его из текста нельзя НИКАКИМ разбором, поэтому исход осторожный:
			// «влияет». Молчание здесь было бы слепотой, а не сужением.
			sql: "DO $$\nDECLARE r record;\nBEGIN\n" +
				"  FOR r IN SELECT tbl, name FROM pg_constraint LOOP\n" +
				"    EXECUTE format('ALTER TABLE kaname.%I DROP CONSTRAINT %I', r.tbl, r.name);\n" +
				"  END LOOP;\nEND;\n$$;",
			want: true,
		},

		// ── ГРАНИЦЫ ОПЕРАТОРА: разделитель внутри литерала и тела ──────────
		{
			name: "точка с запятой ВНУТРИ литерала не теряет следующий оператор",
			sql: "COMMENT ON TABLE kaname.limits IS 'сначала одно; потом другое';\n" +
				"CREATE INDEX access_bindings_new_idx ON kaname.access_bindings (created_at);",
			want: true,
		},
		{
			name: "точка с запятой ВНУТРИ тела функции не теряет следующий оператор",
			sql: "CREATE FUNCTION kaname.noop() RETURNS void LANGUAGE plpgsql AS $body$\n" +
				"BEGIN\n  PERFORM 1;\n  RETURN;\nEND;\n$body$;\n" +
				"ALTER TABLE kaname.access_bindings ADD COLUMN y integer;",
			want: true,
		},
		{
			name: "тело функции с DDL-словами, но БЕЗ исполнения — не влияет",
			// Законный близнец динамического DDL: слова те же, `EXECUTE` нет.
			sql: "CREATE FUNCTION kaname.explain() RETURNS text LANGUAGE sql AS $body$\n" +
				"  SELECT 'здесь мог бы стоять ALTER TABLE kaname.access_bindings'::text;\n" +
				"$body$;",
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
	t.Logf("перепись инъекции: случаев %d; признано влияющими %d; отсеяно %d",
		len(cases), influencing, ignored)
	if influencing == 0 || ignored == 0 {
		t.Fatal("инъекция односторонняя: предикат, отвечающий одинаково на всё, прошёл бы её")
	}
}

// TestDdlRecogniser_UnknownFormIsCautiousNotSilent — незнакомая форма даёт
// ОСТОРОЖНЫЙ исход, а не молчание, и называет себя.
//
// Половина пары обязательна: без неё «распознаватель знает все формы» нечем
// отличить от «распознаватель отвечает на всё одинаково».
func TestDdlRecogniser_UnknownFormIsCautiousNotSilent(t *testing.T) {
	tables := []string{"access_bindings"}

	// Дефект: вид объекта, которого распознаватель не знает. Имени измеряемой
	// таблицы в операторе НЕТ ВОВСЕ — значит осторожный исход приходит именно
	// от незнания формы, а не от совпадения имени.
	unknownForm := "CREATE QUANTUM STORAGE kaname.limits_warp (id text);"
	s := ddlStatementOf(unknownForm, corpusIndex{})
	if s.unknownObject == "" {
		t.Fatalf("незнакомый вид объекта не назван: распознаватель промолчал бы о форме, "+
			"которой не знает (оператор: %s)", unknownForm)
	}
	if !migrationTouches(unknownForm, tables, scopeReadPlan, corpusIndex{}) {
		t.Fatal("незнакомая форма отсеяна МОЛЧА: это слепота, а не сужение")
	}
	t.Logf("незнакомый вид объекта назван: %q — исход осторожный", s.unknownObject)

	// ЗАКОННЫЙ БЛИЗНЕЦ той же формы: вид объекта известен и таблицей не является.
	known := "CREATE SEQUENCE kaname.limits_warp_seq;"
	if got := ddlStatementOf(known, corpusIndex{}); got.unknownObject != "" {
		t.Fatalf("известный вид объекта назван незнакомым (%q): осторожный исход стал бы "+
			"правилом, и сужение выродилось бы в прежний перебор", got.unknownObject)
	}
	if migrationTouches(known, tables, scopeReadPlan, corpusIndex{}) {
		t.Fatal("известная форма без измеряемого субъекта взята под отпечаток")
	}

	// Чужая таблица через обёртку — не измеряемая; измеряемая через ту же
	// обёртку — измеряемая. Одно-фактная пара.
	if migrationTouches("CREATE FOREIGN TABLE kaname.remote_limits (id text) SERVER s;",
		tables, scopeReadPlan, corpusIndex{}) {
		t.Fatal("внешняя таблица с ЧУЖИМ именем взята под отпечаток")
	}
	if !migrationTouches("CREATE FOREIGN TABLE kaname.access_bindings (id text) SERVER s;",
		tables, scopeReadPlan, corpusIndex{}) {
		t.Fatal("внешняя таблица с именем ИЗМЕРЯЕМОЙ отсеяна: вид обёртки не отменяет субъекта")
	}
}
