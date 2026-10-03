// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// people_address_writers_migration_injection_test.go — способность половины
// гейта `TestPeopleAddressHasNoWriterInServiceCode`, судящей МИГРАЦИИ, упасть и
// смолчать, доказанная исполнением (задача PRO-Robotech/kaname#471):
//
//   - НАСТОЯЩИЙ вход: миграция дерева, пишущая в строки людей, скопирована
//     НОВОЙ миграцией, в которой изменён ОДИН факт — к списку SET добавлена
//     отметка подтверждения либо адрес (находка называет файл новой миграции и
//     колонку), либо другая колонка той же строки (законный близнец — молчит);
//   - каждая законная форма записи адреса и отметки в миграции — находка с
//     координатой; каждая форма, которую разбор не решает, — находка «не
//     решается»; законные близнецы тех же форм — молчат;
//   - ведомость применённых миграций — настоящими файлами дерева: запись с
//     предметом молчит, запись, потерявшая предмет, — находка, писатель,
//     дописанный в применённую миграцию, — находка;
//   - пустой обход миграций и миграции без операторов записи в строки людей —
//     находка, а не зелёное; перепись называет оба вида входа.
package check_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

const (
	// peopleMigrationRel — настоящая миграция, пишущая в лежащие строки людей.
	peopleMigrationRel = "internal/migrations/20260916012708_invite_row_carries_its_deadline.sql"
	// injectedMigrationRel — НОВАЯ миграция инъекции: номер старше любого
	// применённого.
	injectedMigrationRel = "internal/migrations/29991231235959_people_rows_injected.sql"
	// secondInjectedRel — вторая новая миграция (привязка через границу файла).
	secondInjectedRel = "internal/migrations/29991231235960_people_rows_injected_trigger.sql"

	// Применённые миграции дерева, чьи места названы ведомостью.
	seedIdentityRel  = "internal/migrations/20260913144108_seed_identity_leaves_the_platform_brand.sql"
	loginMethodsRel  = "internal/migrations/20260915111233_login_methods_live_in_their_own_rows.sql"
	clusterAnchorRel = "internal/migrations/20260906085136_cluster_anchor_gets_a_way_back.sql"

	// peopleMigrationAnchor — миграция с оператором записи в строки людей: без
	// неё корпус без миграций дал бы находку «обход миграций пуст».
	peopleMigrationAnchor    = "-- +goose Up\nDELETE FROM kaname.users WHERE id = 'usr-anchor';\n"
	peopleMigrationAnchorRel = "internal/migrations/20000101000000_anchor.sql"
)

// Колонки, о которых говорит находка.
const (
	addressColumnWord = "kaname.users.email)"
	markColumnWord    = "kaname.users.email_verified_at"
)

func realTreeFile(t *testing.T, rel string) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	return string(b)
}

// withGoAnchor — корпус миграций с непроверочным Go, несущим оператор записи в
// строки людей: без него корпус дал бы находку пустого обхода Go.
func withGoAnchor(files map[string]string) check.TreeCorpus {
	c := check.TreeCorpus{"internal/anchor/anchor.go": peopleAnchor}
	for rel, body := range files {
		c[rel] = body
	}
	return c
}

// mutateIn — src с одной заменой; не легла — прогон «не выполнился».
func mutateIn(t *testing.T, rel, src, from, to string) string {
	t.Helper()
	if strings.Count(src, from) != 1 {
		t.Fatalf("НЕ-ВЫПОЛНИЛОСЬ: инъекция не легла — якорь %q в %s встречается не один раз", from, rel)
	}
	return strings.Replace(src, from, to, 1)
}

// TestPeopleAddressMigrationInjection_NewMigrationWithOneChangedFact — новая
// миграция, скопированная с настоящей: отметка либо адрес в списке SET —
// находка, называющая файл новой миграции и колонку; другая колонка той же
// строки — молчание. Прогонов на случай три: контроль, инъекция, близнец.
func TestPeopleAddressMigrationInjection_NewMigrationWithOneChangedFact(t *testing.T) {
	t.Parallel()
	src := realTreeFile(t, peopleMigrationRel)
	control, _ := judgePeople(t, withGoAnchor(map[string]string{peopleMigrationRel: src}))
	if len(control) != 0 {
		t.Fatalf("НЕ-ВЫПОЛНИЛОСЬ: контроль (настоящая миграция) дал находки: %v", control)
	}

	const setLine = "   SET invite_expires_at = created_at + interval '7 days'\n"
	const downLine = "    DROP COLUMN IF EXISTS invite_expires_at;\n"
	cases := []struct {
		name, from, to, twin, column string
		conditions                   bool
	}{
		{
			name:   "отметка в списке SET",
			from:   setLine,
			to:     "   SET invite_expires_at = created_at + interval '7 days', email_verified_at = now()\n",
			twin:   "   SET invite_expires_at = created_at + interval '7 days', display_name = display_name\n",
			column: markColumnWord,
		},
		{
			name:       "адрес в списке SET",
			from:       setLine,
			to:         "   SET invite_expires_at = created_at + interval '7 days', email = lower(email)\n",
			twin:       "   SET invite_expires_at = created_at + interval '7 days', labels = labels\n",
			column:     addressColumnWord,
			conditions: true,
		},
		{
			name:   "откат пишет отметку",
			from:   downLine,
			to:     downLine + "UPDATE kaname.users SET email_verified_at = NULL;\n",
			twin:   downLine + "UPDATE kaname.users SET invite_expires_at = NULL;\n",
			column: markColumnWord,
		},
	}
	for _, tc := range cases {
		injected, _ := judgePeople(t, withGoAnchor(map[string]string{
			peopleMigrationRel:   src,
			injectedMigrationRel: mutateIn(t, peopleMigrationRel, src, tc.from, tc.to),
		}))
		added := newFindings(control, injected)
		if len(added) != 1 {
			t.Errorf("%s: инъекция дала новых находок %d, ждали 1: %v", tc.name, len(added), added)
			continue
		}
		got := added[0]
		if !strings.HasPrefix(got, injectedMigrationRel+":") || !strings.Contains(got, tc.column) {
			t.Errorf("%s: находка не называет файл новой миграции и колонку %s: %s", tc.name, tc.column, got)
		}
		if tc.conditions {
			for _, cond := range peopleAddressConditions {
				if !strings.Contains(got, cond) {
					t.Errorf("%s: текст отказа не называет условие %q: %s", tc.name, cond, got)
				}
			}
		}

		twin, _ := judgePeople(t, withGoAnchor(map[string]string{
			peopleMigrationRel:   src,
			injectedMigrationRel: mutateIn(t, peopleMigrationRel, src, tc.from, tc.twin),
		}))
		if extra := newFindings(control, twin); len(extra) != 0 {
			t.Errorf("%s: законный близнец (другая колонка той же строки) дал находки: %v", tc.name, extra)
		}
	}
}

// judgeNewMigration — вердикт над корпусом из якоря Go, якоря миграций и одной
// новой миграции.
func judgeNewMigration(t *testing.T, body string) ([]string, check.PeopleAddressCensus) {
	t.Helper()
	return judgePeople(t, withGoAnchor(map[string]string{
		peopleMigrationAnchorRel: peopleMigrationAnchor,
		injectedMigrationRel:     body,
	}))
}

// TestPeopleAddressMigrationInjection_EveryLawfulFormIsFound — каждая законная
// форма записи адреса и отметки в миграции — находка писателя с координатой
// новой миграции.
func TestPeopleAddressMigrationInjection_EveryLawfulFormIsFound(t *testing.T) {
	t.Parallel()
	forms := map[string]string{
		"UPDATE отметки":       "UPDATE kaname.users SET email_verified_at = now() WHERE email_verified_at IS NULL;",
		"UPDATE адреса":        "UPDATE kaname.users SET email = lower(email);",
		"ON CONFLICT":          "INSERT INTO kaname.users (id, email) VALUES ('u', 'a@b.c') ON CONFLICT (id) DO UPDATE SET email_verified_at = now();",
		"MERGE":                "MERGE INTO kaname.users u USING staged s ON u.id = s.id WHEN MATCHED THEN UPDATE SET email_verified_at = s.at;",
		"разделы goose":        "-- +goose Up\n-- +goose StatementBegin\nUPDATE kaname.users\n   SET email_verified_at = now();\n-- +goose StatementEnd\n",
		"блок DO после THEN":   "DO $$ BEGIN IF true THEN UPDATE kaname.users SET email_verified_at = now() WHERE id = 'u'; END IF; END $$;",
		"тело функции":         "CREATE FUNCTION kaname.mark(p text) RETURNS void LANGUAGE sql AS $$ UPDATE kaname.users SET email_verified_at = now() WHERE id = p $$;",
		"динамический SQL":     "DO $$ BEGIN EXECUTE 'UPDATE kaname.users SET email_verified_at = now()'; END $$;",
		"правило":              "CREATE RULE r AS ON INSERT TO kaname.audit DO ALSO UPDATE kaname.users SET email_verified_at = now() WHERE id = NEW.id;",
		"колонка с умолчанием": "ALTER TABLE kaname.users DROP COLUMN email_verified_at, ADD COLUMN email_verified_at timestamptz DEFAULT now();",
		"умолчание отметки":    "ALTER TABLE kaname.users ALTER COLUMN email_verified_at SET DEFAULT now();",
		"тип с выражением":     "ALTER TABLE kaname.users ALTER COLUMN email_verified_at TYPE timestamptz USING coalesce(email_verified_at, created_at);",
		"переименование":       "ALTER TABLE kaname.users RENAME COLUMN invite_expires_at TO email_verified_at;",
		"таблица в людей":      "ALTER TABLE kaname.staged_people RENAME TO users;",
		"триггер ставит":       "CREATE FUNCTION kaname.f() RETURNS trigger LANGUAGE plpgsql AS $$\nBEGIN\n  NEW.email_verified_at := now();\n  RETURN NEW;\nEND;\n$$;\nCREATE TRIGGER t BEFORE UPDATE ON kaname.users FOR EACH ROW EXECUTE FUNCTION kaname.f();",
		"триггер заведения":    "CREATE FUNCTION kaname.f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.email_verified_at := now(); RETURN NEW; END $$;\nCREATE TRIGGER t BEFORE INSERT ON kaname.users FOR EACH ROW EXECUTE FUNCTION kaname.f();",
		"триггер меняет адрес": "CREATE OR REPLACE FUNCTION kaname.f() RETURNS trigger AS $body$ BEGIN NEW.email := lower(NEW.email); RETURN NEW; END $body$ LANGUAGE plpgsql;\nCREATE TRIGGER t BEFORE INSERT OR UPDATE ON kaname.users FOR EACH ROW EXECUTE PROCEDURE kaname.f();",
	}
	for name, body := range forms {
		findings, census := judgeNewMigration(t, body)
		if len(census.Writers) != 1 || len(census.Undecided) != 0 || len(findings) != 1 {
			t.Errorf("форма %q: писателей %d, не решается %d, находок %d — ждали 1 · 0 · 1: %v",
				name, len(census.Writers), len(census.Undecided), len(findings), findings)
			continue
		}
		if !strings.HasPrefix(findings[0], injectedMigrationRel+":") {
			t.Errorf("форма %q: находка не называет файл новой миграции: %s", name, findings[0])
		}
	}

	// Координата — строка записи, а не строка начала тела функции.
	findings, _ := judgeNewMigration(t, forms["триггер ставит"])
	if len(findings) != 1 || !strings.HasPrefix(findings[0], injectedMigrationRel+":3 ") {
		t.Errorf("координата присваивания в теле функции не называет его строку (ждали :3): %v", findings)
	}

	// Привязка через границу файла: функция в одной новой миграции, триггер —
	// в другой; находка называет место присваивания.
	findings, _ = judgePeople(t, withGoAnchor(map[string]string{
		peopleMigrationAnchorRel: peopleMigrationAnchor,
		injectedMigrationRel:     "CREATE FUNCTION kaname.g() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.email_verified_at := now(); RETURN NEW; END $$;",
		secondInjectedRel:        "CREATE TRIGGER t BEFORE UPDATE ON kaname.users FOR EACH ROW EXECUTE FUNCTION kaname.g();",
	}))
	if len(findings) != 1 || !strings.HasPrefix(findings[0], injectedMigrationRel+":") || strings.Contains(findings[0], "разбор не решает") {
		t.Errorf("привязка триггера из другой миграции не решена: %v", findings)
	}
}

// triggerOverPeople — подпрограмма триггера с телом body и её привязка к
// строкам людей до смены строки.
func triggerOverPeople(body string) string {
	return "CREATE FUNCTION kaname.f() RETURNS trigger LANGUAGE plpgsql AS $$\n" + body + "\n$$;\n" +
		"CREATE TRIGGER t BEFORE UPDATE ON kaname.users FOR EACH ROW EXECUTE FUNCTION kaname.f();"
}

// lineOf — строка файла, на которой стоит первое вхождение marker; нет —
// прогон «не выполнился».
func lineOf(t *testing.T, src, marker string) int {
	t.Helper()
	i := strings.Index(src, marker)
	if i < 0 {
		t.Fatalf("НЕ-ВЫПОЛНИЛОСЬ: метки %q в тексте инъекции нет", marker)
	}
	return 1 + strings.Count(src[:i], "\n")
}

// TestPeopleAddressMigrationInjection_TriggerRowWrittenPastTheAssignment —
// строка, которую пишет база, — та, которую ВЕРНУЛА подпрограмма триггера, и
// менять её можно не только присваиванием `NEW.колонка := …` в начале
// оператора. Каждая форма ниже исполнена на Postgres 16 и ставит отметку либо
// пишет адрес в лежащую строку; каждая — находка с координатой своей строки:
// писатель, если колонка названа, «не решается», если строка пишется целиком.
func TestPeopleAddressMigrationInjection_TriggerRowWrittenPastTheAssignment(t *testing.T) {
	t.Parallel()
	forms := []struct {
		name, body, at string
		// column — слово колонки в находке писателя; пусто — «не решается».
		column string
	}{
		{name: "возврат копии строки, изменённой в переменной",
			body: "DECLARE r kaname.users;\nBEGIN\n  r := NEW;\n  r.email_verified_at := now();\n  RETURN r;\nEND;", at: "RETURN r"},
		{name: "возврат строки, собранной выражением",
			body: "BEGIN\n  RETURN jsonb_populate_record(NEW, jsonb_build_object('email_verified_at', now()));\nEND;", at: "RETURN jsonb"},
		{name: "возврат не строки под CASE",
			body: "DECLARE r kaname.users := NEW;\nBEGIN\n  r.email_verified_at := now();\n  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE r END;\nEND;",
			at:   "RETURN CASE"},
		{name: "псевдоним строки",
			body: "DECLARE r ALIAS FOR new;\nBEGIN\n  r.email_verified_at := now();\n  RETURN NEW;\nEND;", at: "r.email_verified_at",
			column: markColumnWord},
		{name: "псевдоним псевдонима",
			body: "DECLARE a ALIAS FOR NEW;\n  b ALIAS FOR a;\nBEGIN\n  b.email := lower(b.email);\n  RETURN b;\nEND;", at: "b.email :=",
			column: addressColumnWord},
		{name: "строка под меткой подпрограммы",
			body: "BEGIN\n  f.new.email_verified_at := now();\n  RETURN NEW;\nEND;", at: "f.new", column: markColumnWord},
		{name: "цель GET DIAGNOSTICS",
			body: "BEGIN\n  GET DIAGNOSTICS NEW.email = ROW_COUNT;\n  RETURN NEW;\nEND;", at: "NEW.email =", column: addressColumnWord},
		{name: "цель FOR по запросу",
			body: "BEGIN\n  FOR NEW IN SELECT u.* FROM kaname.users u LOOP\n  END LOOP;\n  RETURN NEW;\nEND;", at: "FOR NEW"},
		{name: "цель FOR под меткой цикла",
			body: "BEGIN\n  <<fill>> FOR NEW.email_verified_at IN SELECT now() LOOP\n  END LOOP fill;\n  RETURN NEW;\nEND;",
			at:   "<<fill>>", column: markColumnWord},
		{name: "цель FOREACH",
			body: "BEGIN\n  FOREACH NEW.email_verified_at IN ARRAY ARRAY[now()] LOOP\n  END LOOP;\n  RETURN NEW;\nEND;",
			at:   "FOREACH", column: markColumnWord},
		{name: "выходной аргумент CALL — строка",
			body: "BEGIN\n  CALL kaname.set_mark(NEW);\n  RETURN NEW;\nEND;", at: "CALL"},
		{name: "выходной аргумент CALL — колонка по имени",
			body: "BEGIN\n  CALL kaname.set_ts(1, t => NEW.email_verified_at);\n  RETURN NEW;\nEND;", at: "CALL",
			column: markColumnWord},
		{name: "OLD изменён и возвращён",
			body: "BEGIN\n  OLD.email_verified_at := now();\n  RETURN OLD;\nEND;", at: "OLD.email_verified_at", column: markColumnWord},
	}
	for _, tc := range forms {
		src := triggerOverPeople(tc.body)
		findings, census := judgeNewMigration(t, src)
		wantW, wantU := 0, 1
		if tc.column != "" {
			wantW, wantU = 1, 0
		}
		if len(census.Writers) != wantW || len(census.Undecided) != wantU || len(findings) != 1 {
			t.Errorf("форма %q: писателей %d, не решается %d, находок %d — ждали %d · %d · 1: %v",
				tc.name, len(census.Writers), len(census.Undecided), len(findings), wantW, wantU, findings)
			continue
		}
		prefix := fmt.Sprintf("%s:%d ", injectedMigrationRel, lineOf(t, src, tc.at))
		if !strings.HasPrefix(findings[0], prefix) {
			t.Errorf("форма %q: находка не называет строку формы (ждали %q): %s", tc.name, prefix, findings[0])
		}
		switch {
		case tc.column != "" && !strings.Contains(findings[0], tc.column):
			t.Errorf("форма %q: находка писателя не называет колонку %s: %s", tc.name, tc.column, findings[0])
		case tc.column == "" && !strings.Contains(findings[0], "разбор не решает"):
			t.Errorf("форма %q: находка не названа формой «не решается»: %s", tc.name, findings[0])
		}
	}
}

// TestPeopleAddressMigrationInjection_TriggerBodyTheParseDoesNotRead — триггер
// над строками людей зовёт подпрограмму, тела которой разбор не читает: тела
// нет в корпусе (подпрограмма расширения пишет колонку, названную аргументом)
// либо тело на другом языке. Какие колонки пишет возвращённая строка, разбор не
// решает — находка с координатой объявления триггера (тела нет) либо
// подпрограммы (тело не прочитано).
func TestPeopleAddressMigrationInjection_TriggerBodyTheParseDoesNotRead(t *testing.T) {
	t.Parallel()
	forms := map[string]struct{ body, at string }{
		"тело вне корпуса": {
			body: "CREATE TRIGGER t BEFORE UPDATE ON kaname.users FOR EACH ROW EXECUTE FUNCTION moddatetime(email_verified_at);",
			at:   "CREATE TRIGGER"},
		"тело на другом языке": {
			body: "CREATE FUNCTION kaname.f() RETURNS trigger LANGUAGE plpython3u AS $$\nTD[\"new\"][\"email_verified_at\"] = \"now\"\nreturn \"MODIFY\"\n$$;\n" +
				"CREATE TRIGGER t BEFORE UPDATE ON kaname.users FOR EACH ROW EXECUTE PROCEDURE kaname.f();",
			at: "CREATE FUNCTION"},
	}
	for name, tc := range forms {
		findings, census := judgeNewMigration(t, tc.body)
		if len(census.Writers) != 0 || len(census.Undecided) != 1 || len(findings) != 1 {
			t.Errorf("форма %q: писателей %d, не решается %d, находок %d — ждали 0 · 1 · 1: %v",
				name, len(census.Writers), len(census.Undecided), len(findings), findings)
			continue
		}
		prefix := fmt.Sprintf("%s:%d ", injectedMigrationRel, lineOf(t, tc.body, tc.at))
		if !strings.HasPrefix(findings[0], prefix) || !strings.Contains(findings[0], "разбор не решает") {
			t.Errorf("форма %q: находка не названа формой «не решается» со строкой объявления триггера (%q): %s",
				name, prefix, findings[0])
		}
	}
}

// TestPeopleAddressMigrationInjection_TriggerRowTwinsAreSilent — законные
// близнецы тех же форм: возвращается сама строка триггера либо ничего, цель
// присваивания — не строка триггера либо другая её колонка, тело прочитано.
func TestPeopleAddressMigrationInjection_TriggerRowTwinsAreSilent(t *testing.T) {
	t.Parallel()
	twins := map[string]string{
		"RETURN NEW":        triggerOverPeople("BEGIN\n  RETURN NEW;\nEND;"),
		"RETURN NULL":       triggerOverPeople("BEGIN\n  RETURN NULL;\nEND;"),
		"RETURN OLD":        triggerOverPeople("BEGIN\n  RETURN OLD;\nEND;"),
		"RETURN (NEW)":      triggerOverPeople("BEGIN\n  RETURN (NEW);\nEND;"),
		"RETURN CASE строк": triggerOverPeople("BEGIN\n  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE CASE WHEN true THEN NEW END END;\nEND;"),
		"строка под меткой возвращена": triggerOverPeople("BEGIN\n  RETURN f.new;\nEND;"),
		"псевдоним только читается": triggerOverPeople("DECLARE r ALIAS FOR new;\nBEGIN\n  IF r.email IS NULL THEN RAISE EXCEPTION 'нет адреса'; END IF;\n" +
			"  RETURN r;\nEND;"),
		"псевдоним параметра":          triggerOverPeople("DECLARE a ALIAS FOR $1;\nBEGIN\n  a := 1;\n  RETURN NEW;\nEND;"),
		"другая колонка под меткой":    triggerOverPeople("BEGIN\n  f.new.display_name := 'x';\n  RETURN NEW;\nEND;"),
		"GET DIAGNOSTICS в переменную": triggerOverPeople("DECLARE n int;\nBEGIN\n  GET DIAGNOSTICS n = ROW_COUNT;\n  RETURN NEW;\nEND;"),
		"FOR по переменной": triggerOverPeople("DECLARE v record;\nBEGIN\n  FOR v IN SELECT u.* FROM kaname.users u LOOP\n  END LOOP;\n" +
			"  FOR i IN 1..3 LOOP\n  END LOOP;\n  RETURN NEW;\nEND;"),
		"CALL с выражением над строкой": triggerOverPeople("BEGIN\n  CALL kaname.note(lower(NEW.email), NEW.display_name);\n  RETURN NEW;\nEND;"),
		"язык строкой": "CREATE FUNCTION kaname.f() RETURNS trigger LANGUAGE 'plpgsql' AS $$ BEGIN RETURN NEW; END $$;\n" +
			"CREATE TRIGGER t BEFORE UPDATE ON kaname.users FOR EACH ROW EXECUTE FUNCTION kaname.f();",
		"подпрограмма не триггера возвращает значение": "CREATE FUNCTION kaname.g() RETURNS jsonb LANGUAGE plpgsql AS $$ " +
			"BEGIN RETURN jsonb_build_object('email_verified_at', now()); END $$;",
		"тело вне корпуса у чужой таблицы": "CREATE TRIGGER t BEFORE UPDATE ON kaname.audit FOR EACH ROW EXECUTE FUNCTION moddatetime(changed_at);",
	}
	for name, body := range twins {
		findings, census := judgeNewMigration(t, body)
		if len(findings) != 0 {
			t.Errorf("близнец %q дал находки (%s): %v", name, census, findings)
		}
	}
}

// TestPeopleAddressMigrationInjection_UndecidedFormIsAFinding — форма, в которой
// таблица, колонка либо привязка собирается вне текста миграции, — находка «не
// решается» с координатой новой миграции.
func TestPeopleAddressMigrationInjection_UndecidedFormIsAFinding(t *testing.T) {
	t.Parallel()
	forms := map[string]string{
		"таблица и колонка из данных": "DO $$ BEGIN EXECUTE format('UPDATE kaname.%I SET %I = now()', 'users', 'email_verified_at'); END $$;",
		"склейка динамического SQL":   "DO $$ BEGIN EXECUTE 'UPDATE kaname.users SET ' || quote_ident('x') || ' = now()'; END $$;",
		"функция без триггера":        "CREATE FUNCTION kaname.f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.email_verified_at := now(); RETURN NEW; END $$;",
		"функция без триггера возвращает не строку": "CREATE FUNCTION kaname.f() RETURNS trigger LANGUAGE plpgsql AS $$ " +
			"BEGIN RETURN jsonb_populate_record(NEW, '{}'); END $$;",
		"переименование в данные": "DO $$ BEGIN EXECUTE format('ALTER TABLE kaname.users RENAME COLUMN invite_expires_at TO %I', 'x'); END $$;",
	}
	for name, body := range forms {
		findings, census := judgeNewMigration(t, body)
		if len(census.Writers) != 0 || len(census.Undecided) == 0 || len(findings) == 0 {
			t.Errorf("форма %q: писателей %d, не решается %d — ждали 0 и не меньше 1: %v",
				name, len(census.Writers), len(census.Undecided), findings)
			continue
		}
		for _, f := range findings {
			if !strings.Contains(f, "разбор не решает") || !strings.HasPrefix(f, injectedMigrationRel+":") {
				t.Errorf("форма %q: находка не названа формой «не решается» с координатой новой миграции: %s", name, f)
			}
		}
	}
}

// TestPeopleAddressMigrationInjection_LawfulTwinsAreSilent — законные близнецы
// в миграции: заведение колонки и строки, отметка в условии, чужая таблица,
// снятие умолчания и колонки, триггер чужой таблицы, сравнение в теле триггера,
// комментарий.
func TestPeopleAddressMigrationInjection_LawfulTwinsAreSilent(t *testing.T) {
	t.Parallel()
	twins := map[string]string{
		"заведение колонки отметки": "ALTER TABLE kaname.users ADD COLUMN email_verified_at timestamp with time zone;",
		"умолчание NULL":            "ALTER TABLE kaname.users ADD COLUMN email_verified_at timestamptz DEFAULT NULL;",
		"заведение строки":          "INSERT INTO kaname.users (id, email, email_verified_at) VALUES ('u', 'a@b.c', now());",
		"отметка в условии":         "UPDATE kaname.users SET invite_expires_at = now() WHERE email_verified_at IS NULL;",
		"чужая таблица":             "UPDATE kaname.email_verification_codes SET email = lower(email);",
		"снятие умолчания":          "ALTER TABLE kaname.users ALTER COLUMN email_verified_at DROP DEFAULT;",
		"умолчание снято в NULL":    "ALTER TABLE kaname.users ALTER COLUMN email_verified_at SET DEFAULT NULL;",
		"снятие колонки":            "ALTER TABLE kaname.users DROP COLUMN email_verified_at;",
		"тип без выражения":         "ALTER TABLE kaname.users ALTER COLUMN email TYPE text;",
		"ограничение":               "ALTER TABLE ONLY kaname.users ADD CONSTRAINT users_email_check CHECK (length(email) > 2);",
		"другая колонка":            "ALTER TABLE kaname.users ALTER COLUMN labels TYPE jsonb USING labels::jsonb, ADD COLUMN note text DEFAULT '';",
		"таблица в чужую схему":     "ALTER TABLE other.staged RENAME TO users;",
		"триггер чужой таблицы": "CREATE FUNCTION kaname.f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.email := lower(NEW.email); RETURN NEW; END $$;\n" +
			"CREATE TRIGGER t BEFORE UPDATE ON kaname.email_verification_codes FOR EACH ROW EXECUTE FUNCTION kaname.f();",
		"сравнение в теле триггера": "CREATE FUNCTION kaname.f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.email IS DISTINCT FROM OLD.email THEN NEW.display_name := NEW.email; END IF; RETURN NEW; END $$;\n" +
			"CREATE TRIGGER t BEFORE UPDATE ON kaname.users FOR EACH ROW WHEN (OLD.email IS DISTINCT FROM NEW.email) EXECUTE FUNCTION kaname.f();",
		"комментарий":      "-- UPDATE kaname.users SET email_verified_at = now();\nCOMMENT ON COLUMN kaname.users.email_verified_at IS 'UPDATE kaname.users SET email_verified_at = now()';",
		"формат сообщения": "DO $$ BEGIN RAISE NOTICE 'UPDATE kaname.users SET email_verified_at = now() — %', 1; RAISE 'SET email = x'; END $$;",
	}
	for name, body := range twins {
		findings, census := judgeNewMigration(t, body)
		if len(findings) != 0 {
			t.Errorf("близнец %q дал находки (%s): %v", name, census, findings)
		}
	}
}

// TestPeopleAddressMigrationInjection_AppliedLedgerByRealFiles — ведомость
// применённых миграций настоящими файлами дерева: запись с предметом молчит;
// запись, потерявшая предмет, — находка с координатой записи; писатель,
// дописанный в применённую миграцию, — находка, ведомостью не прощённая.
func TestPeopleAddressMigrationInjection_AppliedLedgerByRealFiles(t *testing.T) {
	t.Parallel()
	applied := map[string]string{
		seedIdentityRel:  realTreeFile(t, seedIdentityRel),
		loginMethodsRel:  realTreeFile(t, loginMethodsRel),
		clusterAnchorRel: realTreeFile(t, clusterAnchorRel),
	}
	control, census := judgePeople(t, withGoAnchor(applied))
	if len(control) != 0 {
		t.Fatalf("применённые миграции, чьи места названы ведомостью, дали находки: %v", control)
	}
	for _, word := range []string{"исходники Go", "миграции", "названо ведомостью"} {
		if !strings.Contains(census.String(), word) {
			t.Errorf("перепись не называет %q: %s", word, census)
		}
	}

	// Запись, потерявшая предмет: писатель адреса в применённой миграции
	// заменён писателем другой колонки на той же строке.
	lost := map[string]string{}
	for rel, body := range applied {
		lost[rel] = body
	}
	lost[seedIdentityRel] = mutateIn(t, seedIdentityRel, applied[seedIdentityRel],
		"UPDATE kaname.users SET email = 'system@system.invalid' WHERE",
		"UPDATE kaname.users SET display_name = 'system@system.invalid' WHERE")
	got, _ := judgePeople(t, withGoAnchor(lost))
	if len(got) != 1 || !strings.HasPrefix(got[0], seedIdentityRel+":145") || !strings.Contains(got[0], "ведомост") {
		t.Errorf("запись ведомости без предмета — ждали одну находку с координатой %s:145: %v", seedIdentityRel, got)
	}

	// Писатель, дописанный в применённую миграцию (правка применённой): та же
	// строка, ещё одна колонка — находка, ведомость её не прощает.
	edited := map[string]string{}
	for rel, body := range applied {
		edited[rel] = body
	}
	edited[seedIdentityRel] = mutateIn(t, seedIdentityRel, applied[seedIdentityRel],
		"UPDATE kaname.users SET display_name = 'System (module SA owner)' WHERE",
		"UPDATE kaname.users SET display_name = 'System (module SA owner)', email_verified_at = now() WHERE")
	got, _ = judgePeople(t, withGoAnchor(edited))
	if len(got) != 1 || !strings.HasPrefix(got[0], seedIdentityRel+":") || !strings.Contains(got[0], markColumnWord) {
		t.Errorf("писатель, дописанный в применённую миграцию, — ждали одну находку писателя отметки: %v", got)
	}
}

// TestPeopleAddressMigrationInjection_EmptyMigrationWalkIsNotAVerdict — корпус
// без миграций и миграции без операторов записи в строки людей — находка.
func TestPeopleAddressMigrationInjection_EmptyMigrationWalkIsNotAVerdict(t *testing.T) {
	t.Parallel()
	findings, _ := judgePeople(t, withGoAnchor(nil))
	if len(findings) != 1 || !strings.Contains(findings[0], "обход миграций пуст") {
		t.Errorf("пустой обход миграций — не вердикт: %v", findings)
	}
	findings, _ = judgePeople(t, withGoAnchor(map[string]string{
		injectedMigrationRel: "CREATE TABLE kaname.x (id text);",
	}))
	if len(findings) != 1 || !strings.Contains(findings[0], "в миграциях операторов записи в строки людей не найдено") {
		t.Errorf("миграции без операторов записи в строки людей — не вердикт: %v", findings)
	}
}
