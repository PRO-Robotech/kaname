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
//   - каждая законная форма записи адреса — находка; каждая форма, которую
//     разбор не решает, — находка «не решается»; законные близнецы тех же
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
	control, census := judgePeople(t, check.TreeCorpus{peopleWriterRel: src})
	if census.SetLists[check.SetListUpdate] == 0 || census.SetLists[check.SetListConflict] == 0 {
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
		injected, _ := judgePeople(t, check.TreeCorpus{peopleWriterRel: mutate(t, src, tc.from, tc.to)})
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
		twin, _ := judgePeople(t, check.TreeCorpus{peopleWriterRel: mutate(t, src, tc.from, twinTo)})
		if extra := newFindings(control, twin); len(extra) != 0 {
			t.Errorf("%s: законный близнец (другая колонка той же строки) дал находки: %v", tc.name, extra)
		}
	}
}

// peopleAnchor — оператор записи в строки людей, без которого корпус из одного
// файла дал бы находку «операторов не найдено».
const peopleAnchor = "package anchor\n\nfunc drop() { _ = \"DELETE FROM users WHERE id = $1\" }\n"

func peopleProbe(body string) check.TreeCorpus {
	return check.TreeCorpus{
		"internal/anchor/anchor.go":   peopleAnchor,
		"internal/probe/pg/writer.go": "package pg\n\nfunc (w *userWriter) Probe(col, tbl, rest, cols string) {\n\t" + body + "\n}\n",
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
// колонка либо таблица собирается вне свёрнутого текста, — находка «не
// решается», а не молчание.
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
	}
	for name, body := range forms {
		findings, census := judgePeople(t, peopleProbe(body))
		if len(census.Writers) != 0 || len(census.Undecided) == 0 || len(findings) == 0 {
			t.Errorf("форма %q: писателей %d, не решается %d — ждали 0 и не меньше 1: %v",
				name, len(census.Writers), len(census.Undecided), findings)
			continue
		}
		for _, f := range findings {
			if !strings.Contains(f, "разбор не решает") || !strings.HasPrefix(f, "internal/probe/pg/writer.go:") {
				t.Errorf("форма %q: находка не названа формой «не решается» с координатой: %s", name, f)
			}
		}
	}
}

// TestPeopleAddressWriterInjection_LawfulTwinsAreSilent — законные близнецы:
// адрес в условии, в цели конфликта, в заведении строки; другая таблица, другая
// схема, другая колонка; блокировка, триггер, право, настройка сеанса, текст
// ошибки, комментарии — молчат.
func TestPeopleAddressWriterInjection_LawfulTwinsAreSilent(t *testing.T) {
	t.Parallel()
	twins := map[string]string{
		"отметка, адрес в условии":    `_ = "UPDATE users SET email_verified_at = $3 WHERE id = $1 AND email = $2"`,
		"адрес в функции условия":     `_ = "UPDATE users SET display_name = $1 WHERE lower(email) = lower($2)"`,
		"заведение строки":            `_ = "INSERT INTO users (id, email) VALUES ($1, $2)"`,
		"адрес в цели конфликта":      `_ = "INSERT INTO users (id, email) VALUES ($1, $2) ON CONFLICT (lower(email)) DO UPDATE SET display_name = users.display_name"`,
		"другая таблица":              `_ = "UPDATE memberships SET email = $1"`,
		"другое имя":                  `_ = "UPDATE users_archive SET email = $1"`,
		"другая схема":                `_ = "UPDATE other.users SET email = $1"`,
		"другая колонка в кавычках":   `_ = "UPDATE users SET \"Email\" = $1"`,
		"конфликт чужой вставки":      `_ = "INSERT INTO memberships (id) VALUES ($1) ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email"`,
		"блокировка":                  `_ = "SELECT email FROM users WHERE id = $1 FOR UPDATE"`,
		"комментарий SQL":             "_ = \"SELECT id FROM users -- UPDATE users SET email = $1\\n\"",
		"комментарий Go":              "// UPDATE users SET email = $1\n\t_ = col",
		"формат в RETURNING":          `_ = fmt.Sprintf("UPDATE users SET labels = $2 WHERE id = $1 RETURNING %s", cols)`,
		"таблица подстановкой":        `_ = fmt.Sprintf("UPDATE %s SET display_name = $1", tbl)`,
		"событие триггера":            `_ = "CREATE TRIGGER t BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION f()"`,
		"право":                       `_ = "GRANT SELECT, UPDATE ON users TO reader"`,
		"действие ключа":              `_ = "ALTER TABLE memberships ADD FOREIGN KEY (user_id) REFERENCES users (id) ON UPDATE SET NULL"`,
		"настройка сеанса":            `_ = "SET search_path = kaname"`,
		"текст ошибки":                `_ = errors.New("update users: row vanished")`,
		"адрес в RETURNING":           `_ = "UPDATE users SET display_name = $1 WHERE id = $2 RETURNING id, email"`,
		"адрес в RETURNING конфликта": `_ = "INSERT INTO users (id, email) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET labels = $3 RETURNING id, email"`,
		"адрес в строке вне SET":      `_ = "SELECT 'email' FROM users"`,
	}
	for name, body := range twins {
		findings, census := judgePeople(t, peopleProbe(body))
		if len(findings) != 0 {
			t.Errorf("близнец %q дал находки (%s): %v", name, census, findings)
		}
	}
}

// TestPeopleAddressWriterInjection_EmptyWalkIsNotAVerdict — пустой обход и
// корпус без операторов записи в строки людей — находка; неразобранный файл —
// ошибка.
func TestPeopleAddressWriterInjection_EmptyWalkIsNotAVerdict(t *testing.T) {
	t.Parallel()
	findings, _ := judgePeople(t, check.TreeCorpus{})
	if len(findings) != 1 || !strings.Contains(findings[0], "обход пуст") {
		t.Errorf("пустой обход — не вердикт: %v", findings)
	}
	findings, _ = judgePeople(t, check.TreeCorpus{"internal/x/x.go": "package x\n\nvar _ = \"SELECT 1\"\n"})
	if len(findings) != 1 || !strings.Contains(findings[0], "операторов записи в строки людей не найдено") {
		t.Errorf("корпус без операторов записи в строки людей — не вердикт: %v", findings)
	}
	if _, _, err := check.JudgePeopleAddressWriters(check.TreeCorpus{"internal/x/x.go": "package x\n\nfunc {"}); err == nil {
		t.Error("неразобранный файл — ошибка, а не молчание")
	}
}
