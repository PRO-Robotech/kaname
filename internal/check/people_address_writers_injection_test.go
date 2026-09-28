// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// people_address_writers_injection_test.go — способность гейта
// `TestPeopleAddressHasNoWriterInServiceCode` упасть и смолчать, доказанная
// исполнением (задача PRO-Robotech/kaname#464):
//
//   - НАСТОЯЩИЙ вход: файл писателя строк людей из дерева, в котором изменён
//     ОДИН факт — к списку SET добавлена колонка адреса (находка с координатой и
//     тремя условиями глагола смены адреса) либо другая колонка той же строки
//     (законный близнец — молчит). Прогонов три: контроль, инъекция, близнец;
//     инъекция обязана добавить к контролю ровно одну находку;
//   - НАСТОЯЩИЙ вход, продолженный во время исполнения: к списку SET того же
//     файла приставлен хвост, в значение элемента поставлена подстановка либо
//     условие отбора по адресу записано звеном-присваиванием (находка «не
//     решается» с координатой и ветвью); тот же хвост и та же подстановка после
//     слова, закрывающего список, и условие выражением над колонкой — законный
//     близнец, молчит;
//   - каждая законная форма записи адреса — находка; каждая форма, которую
//     разбор не решает, — находка «не решается», в том числе список SET,
//     полный в литерале и продолженный во время исполнения (`+=`, склейка с
//     переменной, `strings.Join`, построитель, подстановка в значении), и
//     звено-присваивание адреса без оператора; законные близнецы тех же
//     форм — молчат;
//   - пустой обход и корпус без операторов записи в строки людей — находка, а
//     не зелёное; неразобранный файл — ошибка, а не молчание.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// peopleWriterRel — настоящий файл писателя строк людей.
const peopleWriterRel = "internal/repo/kaname/pg/user_repo.go"

// peopleAddressConditions — три условия, которые текст отказа обязан назвать.
var peopleAddressConditions = []string{
	"перепрос открытых соединений края",
	"тем же вопросом, что путь запроса",
	"на прежний адрес",
	"ступень подтверждения личности",
}

func realPeopleWriter(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(peopleWriterRel)))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	return string(b)
}

// realWriterCorpus — настоящий файл писателя строк людей и якорь миграций: без
// него корпус без миграций дал бы находку «обход миграций пуст».
func realWriterCorpus(src string) check.TreeCorpus {
	return check.TreeCorpus{peopleWriterRel: src, peopleMigrationAnchorRel: peopleMigrationAnchor}
}

func judgePeople(t *testing.T, corpus check.TreeCorpus) ([]string, check.PeopleAddressCensus) {
	t.Helper()
	findings, census, err := check.JudgePeopleAddressWriters(corpus)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	return findings, census
}

// newFindings — находки run, которых нет в control.
func newFindings(control, run []string) []string {
	seen := map[string]int{}
	for _, f := range control {
		seen[f]++
	}
	var out []string
	for _, f := range run {
		if seen[f] > 0 {
			seen[f]--
			continue
		}
		out = append(out, f)
	}
	return out
}

// mutate — src с одной заменой; не легла — прогон «не выполнился».
func mutate(t *testing.T, src, from, to string) string {
	t.Helper()
	if strings.Count(src, from) != 1 {
		t.Fatalf("НЕ-ВЫПОЛНИЛОСЬ: инъекция не легла — якорь %q в %s встречается не один раз", from, peopleWriterRel)
	}
	return strings.Replace(src, from, to, 1)
}

// TestPeopleAddressWriterInjection_RealWriterWithOneChangedFact — настоящий
// файл, ветви UPDATE и ON CONFLICT: колонка адреса — находка с координатой и
// условиями; другая колонка той же строки — молчание.
func TestPeopleAddressWriterInjection_RealWriterWithOneChangedFact(t *testing.T) {
	t.Parallel()
	src := realPeopleWriter(t)
	control, census := judgePeople(t, realWriterCorpus(src))
	if census.Go.SetLists[check.SetListUpdate] == 0 || census.Go.SetLists[check.SetListConflict] == 0 {
		t.Fatalf("НЕ-ВЫПОЛНИЛОСЬ: в настоящем файле не прочитаны списки SET обеих ветвей: %s", census)
	}

	cases := []struct {
		name, from, to, fn, branch string
	}{
		{
			name:   "UPDATE",
			from:   "UPDATE users SET labels = $2 WHERE id = $1",
			to:     "UPDATE users SET labels = $2, email = $3 WHERE id = $1",
			fn:     "userWriter.UpdateLabels",
			branch: check.SetListUpdate,
		},
		{
			name:   "ON CONFLICT",
			from:   "SET display_name = users.display_name,",
			to:     "SET display_name = users.display_name, email = EXCLUDED.email,",
			fn:     "userWriter.InsertPending",
			branch: check.SetListConflict,
		},
	}
	for _, tc := range cases {
		injected, _ := judgePeople(t, realWriterCorpus(mutate(t, src, tc.from, tc.to)))
		added := newFindings(control, injected)
		if len(added) != 1 {
			t.Fatalf("%s: инъекция колонки адреса дала новых находок %d, ждали 1: %v", tc.name, len(added), added)
		}
		got := added[0]
		if !strings.HasPrefix(got, peopleWriterRel+":") || !strings.Contains(got, tc.fn+"()") || !strings.Contains(got, tc.branch) {
			t.Errorf("%s: находка не называет координату, функцию %s и ветвь %s: %s", tc.name, tc.fn, tc.branch, got)
		}
		for _, cond := range peopleAddressConditions {
			if !strings.Contains(got, cond) {
				t.Errorf("%s: текст отказа не называет условие %q: %s", tc.name, cond, got)
			}
		}

		twinTo := strings.Replace(tc.to, "email = $3", "display_name = $3", 1)
		twinTo = strings.Replace(twinTo, "email = EXCLUDED.email", "labels = EXCLUDED.labels", 1)
		twin, _ := judgePeople(t, realWriterCorpus(mutate(t, src, tc.from, twinTo)))
		if extra := newFindings(control, twin); len(extra) != 0 {
			t.Errorf("%s: законный близнец (другая колонка той же строки) дал находки: %v", tc.name, extra)
		}
	}
}

// TestPeopleAddressWriterInjection_RealWriterExtendedAtRunTime — настоящий
// файл, ветви UPDATE и ON CONFLICT: список SET, полный в литерале, продолжен во
// время исполнения — хвостом за списком либо подстановкой в значении элемента;
// звено условия отбора по адресу записано присваиванием. Инъекция — ровно одна
// новая находка «не решается» с координатой, функцией и ветвью; близнец — тот
// же хвост либо та же подстановка после слова, закрывающего список, и условие
// выражением над колонкой — молчит.
func TestPeopleAddressWriterInjection_RealWriterExtendedAtRunTime(t *testing.T) {
	t.Parallel()
	src := realPeopleWriter(t)
	control, census := judgePeople(t, realWriterCorpus(src))
	if census.Go.SetLists[check.SetListUpdate] == 0 || census.Go.SetLists[check.SetListConflict] == 0 {
		t.Fatalf("НЕ-ВЫПОЛНИЛОСЬ: в настоящем файле не прочитаны списки SET обеих ветвей: %s", census)
	}

	cases := []struct {
		name, from, to, twin, fn, branch string
	}{
		{
			name:   "UPDATE, хвост за списком",
			from:   "`UPDATE users SET labels = $2 WHERE id = $1 RETURNING %s`",
			to:     "`UPDATE users SET labels = $2` + tail + ` WHERE id = $1 RETURNING %s`",
			twin:   "`UPDATE users SET labels = $2 WHERE id = $1` + tail + ` RETURNING %s`",
			fn:     "userWriter.UpdateLabels",
			branch: check.SetListUpdate,
		},
		{
			name:   "UPDATE, подстановка в значении",
			from:   "`UPDATE users SET labels = $2 WHERE id = $1 RETURNING %s`",
			to:     "`UPDATE users SET labels = %s WHERE id = $1 RETURNING %s`",
			twin:   "`UPDATE users SET labels = $2 WHERE id = %s RETURNING %s`",
			fn:     "userWriter.UpdateLabels",
			branch: check.SetListUpdate,
		},
		{
			// Звено условия отбора `email = $N` неотличимо от звена списка SET;
			// дерево пишет его выражением над колонкой.
			name:   "звено-присваивание адреса",
			from:   `fmt.Sprintf("lower(email) = lower($%d)", argIdx)`,
			to:     `fmt.Sprintf("email = $%d", argIdx)`,
			twin:   `fmt.Sprintf("lower(email) = $%d", argIdx)`,
			fn:     "userReader.List",
			branch: "звено списка присваиваний",
		},
		{
			name:   "ON CONFLICT, хвост за списком",
			from:   "       END\n\t\t\tRETURNING %s, (xmax = 0) AS inserted",
			to:     "       END` + tail + `\n\t\t\tRETURNING %s, (xmax = 0) AS inserted",
			twin:   "       END\n\t\t\tRETURNING %s` + tail + `, (xmax = 0) AS inserted",
			fn:     "userWriter.InsertPending",
			branch: check.SetListConflict,
		},
	}
	for _, tc := range cases {
		injected, _ := judgePeople(t, realWriterCorpus(mutate(t, src, tc.from, tc.to)))
		added := newFindings(control, injected)
		if len(added) != 1 {
			t.Errorf("%s: инъекция дала новых находок %d, ждали 1: %v", tc.name, len(added), added)
			continue
		}
		got := added[0]
		if !strings.HasPrefix(got, peopleWriterRel+":") || !strings.Contains(got, tc.fn+"()") ||
			!strings.Contains(got, tc.branch) || !strings.Contains(got, "разбор не решает") {
			t.Errorf("%s: находка не называет координату, функцию %s, ветвь %s и форму «не решается»: %s", tc.name, tc.fn, tc.branch, got)
		}

		twin, _ := judgePeople(t, realWriterCorpus(mutate(t, src, tc.from, tc.twin)))
		if extra := newFindings(control, twin); len(extra) != 0 {
			t.Errorf("%s: законный близнец дал находки: %v", tc.name, extra)
		}
	}
}

// peopleAnchor — оператор записи в строки людей, без которого корпус из одного
// файла дал бы находку «операторов не найдено»; якорь миграций — рядом с
// половиной миграций (people_address_writers_migration_injection_test.go).
const peopleAnchor = "package anchor\n\nfunc drop() { _ = \"DELETE FROM users WHERE id = $1\" }\n"

func peopleProbe(body string) check.TreeCorpus {
	return check.TreeCorpus{
		"internal/anchor/anchor.go":   peopleAnchor,
		"internal/probe/pg/writer.go": "package pg\n\nfunc (w *userWriter) Probe(col, tbl, rest, cols string) {\n\t" + body + "\n}\n",
		peopleMigrationAnchorRel:      peopleMigrationAnchor,
	}
}

// TestPeopleAddressWriterInjection_EveryLawfulFormIsFound — каждая законная
// форма записи адреса в существующую строку — находка с координатой.
func TestPeopleAddressWriterInjection_EveryLawfulFormIsFound(t *testing.T) {
	t.Parallel()
	forms := map[string]string{
		"UPDATE":           `_ = "UPDATE users SET email = $1 WHERE id = $2"`,
		"со схемой":        `_ = "UPDATE kaname.users SET email = $1"`,
		"ONLY и псевдоним": `_ = "UPDATE ONLY users u SET email = lower(u.email)"`,
		"в кавычках":       `_ = "UPDATE \"kaname\".\"users\" AS u SET \"email\" = $1"`,
		"регистр":          `_ = "update Users set EMAIL = $1"`,
		"кортеж":           `_ = "UPDATE users SET (display_name, email) = ($1, $2)"`,
		"после CASE":       `_ = "UPDATE users SET display_name = CASE WHEN $1 = '' THEN display_name ELSE $1 END, email = $2"`,
		"с FROM":           `_ = "UPDATE users AS u SET display_name = $1, email = $2 FROM other o WHERE o.id = u.id"`,
		"в CTE":            `_ = "WITH x AS (UPDATE users SET email = $1 RETURNING id) SELECT id FROM x"`,
		"ON CONFLICT":      `_ = "INSERT INTO users (id, email) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email"`,
		"MERGE":            `_ = "MERGE INTO users u USING incoming s ON u.id = s.id WHEN MATCHED THEN UPDATE SET email = s.email"`,
		"склейка":          `_ = "UPDATE users " + "SET email = $1"`,
		"константа":        "const set = \"email = $1\"\n\t_ = \"UPDATE users SET \" + set",
		"константа и обращение": "const q = \"UPDATE users SET email = $1\"\n\t_ = q",
		"формат":        `_ = fmt.Sprintf("UPDATE users SET email = $1 RETURNING %s", cols)`,
		"строка SQL":    `_ = "DO $$ BEGIN UPDATE users SET email = 'x' WHERE id = 'y'; END $$"`,
		"сырой литерал": "_ = `\n\t\tUPDATE users\n\t\t   SET email = $1\n\t\t WHERE id = $2`",

		// Оператор PL/pgSQL после THEN и действие правила после DO — оператор, а
		// не действие конфликта либо MERGE: за словом стоит таблица, а не SET.
		"PL/pgSQL после THEN": `_ = "DO $$ BEGIN IF true THEN UPDATE kaname.users SET email = 'x' WHERE id = 'y'; END IF; END $$"`,
		"правило DO UPDATE":   `_ = "CREATE RULE r AS ON INSERT TO audit DO UPDATE users SET email = NEW.email WHERE id = NEW.id"`,

		// Определение схемы, переписывающее значения лежащих строк.
		"колонка адреса с умолчанием":   `_ = "ALTER TABLE kaname.users ADD COLUMN IF NOT EXISTS email text DEFAULT 'x'"`,
		"вычисляемая колонка адреса":    `_ = "ALTER TABLE users ADD email text GENERATED ALWAYS AS (lower(display_name)) STORED"`,
		"смена типа с выражением":       `_ = "ALTER TABLE users ALTER COLUMN email TYPE text USING lower(email)"`,
		"SET DATA TYPE с выражением":    `_ = "ALTER TABLE ONLY users ALTER email SET DATA TYPE text USING trim(email)"`,
		"смена выражения":               `_ = "ALTER TABLE users ALTER COLUMN email SET EXPRESSION AS (lower(display_name))"`,
		"переименование в адрес":        `_ = "ALTER TABLE IF EXISTS users RENAME COLUMN legacy_email TO email"`,
		"таблица переименована в людей": `_ = "ALTER TABLE staged_people RENAME TO users"`,

		// Присваивание строке триггера, привязанного к строкам людей на смене.
		"присваивание NEW в триггере": "_ = `CREATE FUNCTION kaname.f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.email := lower(NEW.email); RETURN NEW; END $$;\n" +
			"CREATE TRIGGER t BEFORE INSERT OR UPDATE ON kaname.users FOR EACH ROW EXECUTE FUNCTION kaname.f()`",
		"присваивание NEW знаком =": "_ = `CREATE OR REPLACE FUNCTION f() RETURNS trigger AS $$ BEGIN IF true THEN NEW.email = 'x'; END IF; RETURN NEW; END $$ LANGUAGE plpgsql;\n" +
			"CREATE TRIGGER t BEFORE UPDATE OF display_name ON users FOR EACH ROW EXECUTE PROCEDURE f()`",
		"умолчание адреса": `_ = "ALTER TABLE users ALTER COLUMN email SET DEFAULT ''"`,
		"триггер заведения строки": "_ = `CREATE FUNCTION f() RETURNS trigger AS $$ BEGIN NEW.email := lower(NEW.email); RETURN NEW; END $$ LANGUAGE plpgsql;\n" +
			"CREATE TRIGGER t BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION f()`",
		"SELECT INTO NEW": "_ = `CREATE FUNCTION f() RETURNS trigger AS $$ BEGIN SELECT lower(o.email) INTO STRICT NEW.email FROM other o; RETURN NEW; END $$ LANGUAGE plpgsql;\n" +
			"CREATE TRIGGER t BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION f()`",
	}
	for name, body := range forms {
		findings, census := judgePeople(t, peopleProbe(body))
		if len(census.Writers) != 1 || len(census.Undecided) != 0 || len(findings) != 1 {
			t.Errorf("форма %q: писателей %d, не решается %d, находок %d — ждали 1 · 0 · 1: %v",
				name, len(census.Writers), len(census.Undecided), len(findings), findings)
			continue
		}
		if !strings.HasPrefix(findings[0], "internal/probe/pg/writer.go:") || !strings.Contains(findings[0], "userWriter.Probe()") {
			t.Errorf("форма %q: находка без координаты: %s", name, findings[0])
		}
	}
	// Строка сырого литерала — строка колонки, а не начала литерала.
	findings, _ := judgePeople(t, peopleProbe(forms["сырой литерал"]))
	if len(findings) != 1 || !strings.HasPrefix(findings[0], "internal/probe/pg/writer.go:6 ") {
		t.Errorf("координата в сыром литерале не называет строку колонки (ждали :6): %v", findings)
	}
}

// TestPeopleAddressWriterInjection_UndecidedFormIsAFinding — форма, в которой
// колонка либо таблица собирается вне свёрнутого текста, список SET продолжен
// во время исполнения либо звено-присваивание адреса приставлено к оператору вне
// текста, — находка «не решается» с координатой и функцией, а не молчание.
func TestPeopleAddressWriterInjection_UndecidedFormIsAFinding(t *testing.T) {
	t.Parallel()
	forms := map[string]string{
		"список SET в переменной":      `_ = "UPDATE users SET " + col + " = $1"`,
		"колонка подстановкой":         `_ = fmt.Sprintf("UPDATE users SET %s = $1 WHERE id = $2", col)`,
		"таблица подстановкой":         `_ = fmt.Sprintf("UPDATE %s SET email = $1", tbl)`,
		"хвост списка в переменной":    `_ = "UPDATE users SET display_name = $1, " + rest`,
		"список SET вне текста":        `_ = "UPDATE users " + rest`,
		"оператор вне текста":          `_ = "UPDATE " + tbl + " SET email = $1"`,
		"вставка вне текста":           `_ = "INSERT INTO " + tbl + " (id) VALUES ($1) ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email"`,
		"кортеж с подстановкой":        `_ = fmt.Sprintf("UPDATE users SET (display_name, %s) = ($1, $2)", col)`,
		"подстановка списка целиком":   `_ = fmt.Sprintf("UPDATE users SET %s WHERE id = $1", rest)`,
		"подстановка после псевдонима": `_ = fmt.Sprintf("UPDATE users u %s", rest)`,

		// Список SET, полный в литерале и продолженный во время исполнения.
		"список дописан +=":                      "q := \"UPDATE users SET labels = $2\"\n\tq += \", email = $3\"\n\t_ = q",
		"хвост за полным списком":                `_ = "UPDATE users SET labels = $2" + rest`,
		"подстановка в значении":                 `_ = fmt.Sprintf("UPDATE users SET labels = %s WHERE id = $1", rest)`,
		"хвост за списком конфликта":             `_ = "INSERT INTO users (id) VALUES ($1) ON CONFLICT (id) DO UPDATE SET labels = $2" + rest`,
		"звенья strings.Join":                    `_ = strings.Join([]string{"UPDATE users SET labels = $1", "email = $2"}, ", ")`,
		"константа и хвост":                      "const q = \"UPDATE users SET labels = $2\"\n\t_ = q + rest",
		"построитель":                            "var b strings.Builder\n\tb.WriteString(\"UPDATE users SET labels = $2\")\n\tb.WriteString(rest)\n\t_ = b.String()",
		"таблица подстановкой, список не закрыт": `_ = fmt.Sprintf("UPDATE %s SET display_name = $1", tbl)`,

		// Звено-присваивание адреса без оператора.
		"звено-присваивание":           `_ = "email = $2"`,
		"звено за подстановкой":        `_ = fmt.Sprintf("%s, email = $3", rest)`,
		"звено-кортеж":                 `_ = "(display_name, email) = ($1, $2)"`,
		"звено-константа за значением": "const set = \"email = $3\"\n\t_ = strings.Join([]string{rest, set}, \", \")",
		"константа за переменной":      "const column = \"email\"\n\t_ = \"UPDATE \" + tbl + \" SET \" + column + \" = $1\"",

		// Определение схемы с подстановкой: колонка либо таблица вне текста.
		"переименование в подстановку": `_ = fmt.Sprintf("ALTER TABLE users RENAME COLUMN legacy TO %s", col)`,
		"таблица подстановкой в DDL":   `_ = fmt.Sprintf("ALTER TABLE %s RENAME COLUMN legacy TO email", tbl)`,
		"подстановка вместо колонки":   `_ = fmt.Sprintf("ALTER TABLE users ALTER COLUMN %s TYPE text USING lower(%s)", col, col)`,

		// Присваивание строке триггера, чью привязку разбор не решает.
		"функция без триггера": "_ = `CREATE FUNCTION f() RETURNS trigger AS $$ BEGIN NEW.email := 'x'; RETURN NEW; END $$ LANGUAGE plpgsql`",
		"запись строки целиком": "_ = `CREATE FUNCTION f() RETURNS trigger AS $$ BEGIN NEW := jsonb_populate_record(NEW, '{}'); RETURN NEW; END $$ LANGUAGE plpgsql;\n" +
			"CREATE TRIGGER t BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION f()`",
		"строка триггера целиком через INTO": "_ = `CREATE FUNCTION f() RETURNS trigger AS $$ BEGIN SELECT * INTO NEW FROM staged s WHERE s.id = NEW.id; RETURN NEW; END $$ LANGUAGE plpgsql;\n" +
			"CREATE TRIGGER t BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION f()`",
		"таблица из подстановки в людей": `_ = fmt.Sprintf("ALTER TABLE %s RENAME TO users", tbl)`,
		"триггер над подстановкой": "_ = fmt.Sprintf(`CREATE FUNCTION f() RETURNS trigger AS $$ BEGIN NEW.email := 'x'; RETURN NEW; END $$ LANGUAGE plpgsql;\n" +
			"CREATE TRIGGER t BEFORE UPDATE ON %s FOR EACH ROW EXECUTE FUNCTION f()`, tbl)",
	}
	for name, body := range forms {
		findings, census := judgePeople(t, peopleProbe(body))
		if len(census.Writers) != 0 || len(census.Undecided) == 0 || len(findings) == 0 {
			t.Errorf("форма %q: писателей %d, не решается %d — ждали 0 и не меньше 1: %v",
				name, len(census.Writers), len(census.Undecided), findings)
			continue
		}
		for _, f := range findings {
			if !strings.Contains(f, "разбор не решает") || !strings.HasPrefix(f, "internal/probe/pg/writer.go:") ||
				!strings.Contains(f, "userWriter.Probe()") {
				t.Errorf("форма %q: находка не названа формой «не решается» с координатой и функцией: %s", name, f)
			}
		}
	}
}

// TestPeopleAddressWriterInjection_LawfulTwinsAreSilent — законные близнецы:
// адрес в условии, в цели конфликта, в заведении строки; другая таблица, другая
// схема, другая колонка; блокировка, триггер, право, настройка сеанса, текст
// ошибки, комментарии; продолжение после закрытого списка SET и звено без
// присваивания адреса — молчат.
func TestPeopleAddressWriterInjection_LawfulTwinsAreSilent(t *testing.T) {
	t.Parallel()
	twins := map[string]string{
		"отметка, адрес в условии":    `_ = "UPDATE users SET email_verified_at = $3 WHERE id = $1 AND email = $2"`,
		"адрес в функции условия":     `_ = "UPDATE users SET display_name = $1 WHERE lower(email) = lower($2)"`,
		"заведение строки":            `_ = "INSERT INTO users (id, email) VALUES ($1, $2)"`,
		"адрес в цели конфликта":      `_ = "INSERT INTO users (id, email) VALUES ($1, $2) ON CONFLICT (lower(email)) DO UPDATE SET display_name = users.display_name RETURNING id"`,
		"другая таблица":              `_ = "UPDATE memberships SET email = $1"`,
		"другое имя":                  `_ = "UPDATE users_archive SET email = $1"`,
		"другая схема":                `_ = "UPDATE other.users SET email = $1"`,
		"другая колонка в кавычках":   `_ = "UPDATE users SET \"Email\" = $1 WHERE id = $2"`,
		"конфликт чужой вставки":      `_ = "INSERT INTO memberships (id) VALUES ($1) ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email"`,
		"блокировка":                  `_ = "SELECT email FROM users WHERE id = $1 FOR UPDATE"`,
		"комментарий SQL":             "_ = \"SELECT id FROM users -- UPDATE users SET email = $1\\n\"",
		"комментарий Go":              "// UPDATE users SET email = $1\n\t_ = col",
		"формат в RETURNING":          `_ = fmt.Sprintf("UPDATE users SET labels = $2 WHERE id = $1 RETURNING %s", cols)`,
		"таблица подстановкой":        `_ = fmt.Sprintf("UPDATE %s SET display_name = $1 WHERE id = $2", tbl)`,
		"событие триггера":            `_ = "CREATE TRIGGER t BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION f()"`,
		"право":                       `_ = "GRANT SELECT, UPDATE ON users TO reader"`,
		"действие ключа":              `_ = "ALTER TABLE memberships ADD FOREIGN KEY (user_id) REFERENCES users (id) ON UPDATE SET NULL"`,
		"настройка сеанса":            `_ = "SET search_path = kaname"`,
		"текст ошибки":                `_ = errors.New("update users: row vanished")`,
		"адрес в RETURNING":           `_ = "UPDATE users SET display_name = $1 WHERE id = $2 RETURNING id, email"`,
		"адрес в RETURNING конфликта": `_ = "INSERT INTO users (id, email) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET labels = $3 RETURNING id, email"`,
		"адрес в строке вне SET":      `_ = "SELECT 'email' FROM users"`,

		// Близнецы форм, продолженных во время исполнения, — каждый меняет ОДИН
		// факт против своей формы «не решается»: продолжение после слова,
		// закрывающего список SET, колонки в него не допишет; звено без
		// присваивания адреса в голове элемента — не звено списка SET.
		"закрытый список и хвост":                `_ = "UPDATE users SET labels = $2 WHERE id = $1" + rest`,
		"закрытый точкой с запятой":              `_ = "UPDATE users SET labels = $2;" + rest`,
		"закрытый конфликт и хвост":              `_ = "INSERT INTO users (id) VALUES ($1) ON CONFLICT (id) DO UPDATE SET labels = $2 RETURNING id" + rest`,
		"подстановка в условии":                  `_ = fmt.Sprintf("UPDATE users SET labels = $1 WHERE id = %s", rest)`,
		"закрытая константа и хвост":             "const q = \"UPDATE users SET labels = $2 WHERE id = $1\"\n\t_ = q + rest",
		"построитель закрытого списка":           "var b strings.Builder\n\tb.WriteString(\"UPDATE users SET labels = $2 WHERE id = $1\")\n\tb.WriteString(rest)\n\t_ = b.String()",
		"звено другой колонки":                   `_ = fmt.Sprintf("%s, display_name = $3", rest)`,
		"звено перечня колонок":                  `_ = fmt.Sprintf("%s, email", rest)`,
		"звено условия":                          `_ = " AND email = $2"`,
		"звено колонок вставки":                  `_ = "(display_name, email) VALUES ($1, $2)"`,
		"звено-константа другой колонки":         "const set = \"display_name = $3\"\n\t_ = strings.Join([]string{rest, set}, \", \")",
		"константа другой колонки за переменной": "const column = \"display_name\"\n\t_ = \"UPDATE \" + tbl + \" SET \" + column + \" = $1\"",
		"звено условия выражением над колонкой":  `_ = fmt.Sprintf("lower(email) = lower($%d)", n)`,
		"адрес не в голове сообщения":            `_ = fmt.Errorf("subject not found by email=%s", col)`,

		// Близнецы определения схемы: новая колонка без значения, умолчание для
		// новых строк, ограничение, тип без выражения, адрес прочь, чужая таблица.
		"колонка адреса без умолчания":     `_ = "ALTER TABLE kaname.users ADD COLUMN IF NOT EXISTS email text"`,
		"умолчание NULL":                   `_ = "ALTER TABLE users ADD COLUMN email text DEFAULT NULL"`,
		"ограничение над адресом":          `_ = "ALTER TABLE ONLY kaname.users ADD CONSTRAINT users_email_check CHECK (length(email) > 2)"`,
		"умолчание адреса снято":           `_ = "ALTER TABLE users ALTER COLUMN email DROP DEFAULT, ALTER COLUMN email SET NOT NULL, ALTER COLUMN email SET DEFAULT NULL"`,
		"тип без выражения":                `_ = "ALTER TABLE users ALTER COLUMN email TYPE text COLLATE \"C\""`,
		"адрес переименован прочь":         `_ = "ALTER TABLE users RENAME COLUMN email TO email_legacy"`,
		"переименование чужой колонки":     `_ = "ALTER TABLE memberships RENAME COLUMN note TO email"`,
		"таблица людей переименована":      `_ = "ALTER TABLE users RENAME TO users_archive"`,
		"переименование ограничения":       `_ = "ALTER TABLE users RENAME CONSTRAINT users_email_check TO users_address_check"`,
		"выражение другой колонки":         `_ = "ALTER TABLE users ALTER COLUMN labels TYPE jsonb USING labels::jsonb"`,
		"оператор PL/pgSQL другой колонки": `_ = "DO $$ BEGIN IF true THEN UPDATE kaname.users SET display_name = 'x' WHERE id = 'y'; END IF; END $$"`,

		// Близнецы присваивания строке триггера.
		"триггер чужой таблицы": "_ = `CREATE FUNCTION f() RETURNS trigger AS $$ BEGIN NEW.email := lower(NEW.email); RETURN NEW; END $$ LANGUAGE plpgsql;\n" +
			"CREATE TRIGGER t BEFORE UPDATE ON kaname.email_verification_codes FOR EACH ROW EXECUTE FUNCTION f()`",
		"адрес в условии триггера": "_ = `CREATE FUNCTION f() RETURNS trigger AS $$ DECLARE v text; BEGIN v := NEW.email; IF NEW.email IS DISTINCT FROM OLD.email THEN NEW.display_name := v; END IF; RETURN NEW; END $$ LANGUAGE plpgsql;\n" +
			"CREATE TRIGGER t BEFORE UPDATE ON users FOR EACH ROW WHEN (OLD.email IS DISTINCT FROM NEW.email) EXECUTE FUNCTION f()`",
	}
	for name, body := range twins {
		findings, census := judgePeople(t, peopleProbe(body))
		if len(findings) != 0 {
			t.Errorf("близнец %q дал находки (%s): %v", name, census, findings)
		}
	}
}

// TestPeopleAddressWriterInjection_EmptyWalkIsNotAVerdict — пустой обход и
// корпус без операторов записи в строки людей — находка; неразобранный файл и
// файл вне обоих видов входа — ошибка.
func TestPeopleAddressWriterInjection_EmptyWalkIsNotAVerdict(t *testing.T) {
	t.Parallel()
	findings, _ := judgePeople(t, check.TreeCorpus{})
	joined := strings.Join(findings, "\n")
	if len(findings) != 2 || !strings.Contains(joined, "обход пуст — ни одного файла Go") || !strings.Contains(joined, "обход миграций пуст") {
		t.Errorf("пустой обход обоих видов входа — не вердикт, по находке на вид: %v", findings)
	}
	findings, _ = judgePeople(t, check.TreeCorpus{
		"internal/x/x.go":        "package x\n\nvar _ = \"SELECT 1\"\n",
		peopleMigrationAnchorRel: peopleMigrationAnchor,
	})
	if len(findings) != 1 || !strings.HasPrefix(findings[0], "операторов записи в строки людей не найдено") {
		t.Errorf("корпус Go без операторов записи в строки людей — не вердикт: %v", findings)
	}
	if _, _, err := check.JudgePeopleAddressWriters(check.TreeCorpus{"internal/x/x.go": "package x\n\nfunc {"}); err == nil {
		t.Error("неразобранный файл — ошибка, а не молчание")
	}
	if _, _, err := check.JudgePeopleAddressWriters(check.TreeCorpus{"internal/migrations/README.md": "UPDATE users SET email = 1"}); err == nil {
		t.Error("файл вне обоих видов входа — ошибка, а не молчание")
	}
}
