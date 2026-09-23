// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// human_session_forced_exit_reason_integration_test.go — СЛОВАРЬ ПРИЧИН
// СНЯТИЯ СЕССИИ ПОЛУЧАЕТ ЧЕТВЁРТОЕ ЗНАЧЕНИЕ (задача kaname#334; приёмка
// `docs/engineering/acceptance/forced-exit-has-its-own-session-end-reason.md`,
// KN-SER-06…09; решения Р4, Р5).
//
// ─────────────────────────────────────────────────────────────────────────────
// ИСПЫТУЕМЫЙ — НОВАЯ МИГРАЦИЯ, И ЕЁ ВЕРСИЯ ПРОБЕ НЕИЗВЕСТНА
//
// Версию назначит реализация, поэтому проба ищет испытуемого в каталоге по
// СОДЕРЖАНИЮ: миграция, чей накат (без комментариев) называет ограничение
// `human_sessions_ended_reason_check` и значение `'admin-force-logout'`. Такой
// миграции ровно одна либо нет ни одной; две — сломанный вопрос, а не ответ.
// «Версия, предшествующая новой», — старшая версия каталога ниже неё; пока
// испытуемого нет — голова каталога.
//
// Порядок в каждой пробе несущий: сначала строится и проверяется «Дано», и
// только потом спрашивается испытуемый. Обратный порядок дал бы сломанной
// фикстуре выдать себя за отсутствующую миграцию.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПЕРЕЧЕНЬ ДОМЕНА ЧИТАЕТСЯ РАЗБОРОМ ИСХОДНИКА
//
// KN-SER-07 сверяет базу с перечнем словаря снятия сессии, объявленным
// доменом. Перечень заводит реализация, и прямой вызов не собрался бы до неё
// — несобранная проба даёт «не выполнилось», а не красный. Поэтому перечень
// читается разбором `internal/domain`: функция `HumanSessionEndReasons() []string`,
// отдающая составной литерал, собранный из КОНСТАНТ ПО ИМЕНИ. Разбор держит и
// форму: литерал вместо константы, переменная вместо функции — находки.
package migrations_test

import (
	"database/sql"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

const (
	// serEndedReasonCheck — ограничение словаря причин снятия.
	serEndedReasonCheck = "human_sessions_ended_reason_check"
	// serForcedExit — четвёртое значение словаря (приёмка, Р1), дословно.
	serForcedExit = "admin-force-logout"
	// serCutoffOnlyReason — причина ОТСЕЧКИ, в словарь снятия не входит (§0.2).
	serCutoffOnlyReason = "second-factor-reset"
	// serDomainListFunc — имя перечня словаря снятия в домене.
	serDomainListFunc = "HumanSessionEndReasons"
	// serDomainDir — пакет домена от каталога этой пробы.
	serDomainDir = "../domain"
)

// serCatalog — каталог миграций и испытуемый в нём.
type serCatalog struct {
	versions []int64
	// forced — версия миграции, вводящей слово; 0 — такой нет.
	forced int64
	file   string
}

func (c serCatalog) found() bool { return c.forced != 0 }

// preceding — старшая версия ниже испытуемого; без испытуемого — голова.
func (c serCatalog) preceding() int64 {
	var best int64
	for _, v := range c.versions {
		if (!c.found() || v < c.forced) && v > best {
			best = v
		}
	}
	return best
}

func serReadCatalog(t *testing.T) serCatalog {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	require.NoError(t, err, "Дано: каталог миграций читается")
	var c serCatalog
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "_")
		require.True(t, ok, "Дано: имя миграции %s без версии", name)
		v, err := strconv.ParseInt(prefix, 10, 64)
		require.NoError(t, err, "Дано: версия миграции %s", name)
		c.versions = append(c.versions, v)
		body, err := fs.ReadFile(migrations.FS, name)
		require.NoError(t, err, "Дано: тело миграции %s", name)
		up := migrations.MigrationUpSection(string(body))
		if strings.Contains(up, serEndedReasonCheck) && strings.Contains(up, "'"+serForcedExit+"'") {
			require.Zero(t, c.forced, "Дано: слово вводят ДВЕ миграции (%s и %s) — вопрос «предшествующая версия» не имеет ответа", c.file, name)
			c.forced, c.file = v, name
		}
	}
	require.NotEmpty(t, c.versions, "Дано: каталог миграций пуст — судить нечего")
	return c
}

// serRequireSubject — испытуемый обязан быть в каталоге; его отсутствие —
// честный красный, и отказ называет, что осмотрено.
func serRequireSubject(t *testing.T, c serCatalog) {
	t.Helper()
	if !c.found() {
		t.Fatalf("ИСПЫТУЕМОГО НЕТ: в каталоге из %d миграций (голова %d) нет миграции, чей накат вводит '%s' "+
			"в %s — новое значение словаря не заведено", len(c.versions), c.preceding(), serForcedExit, serEndedReasonCheck)
	}
}

func serOpenAt(t *testing.T, version int64) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpTo(db, ".", version), "Дано: цепь доходит до версии %d", version)
	got, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, version, got, "Дано: база стоит на версии %d", version)
	return db
}

// serSeedPerson — личность и её аккаунт одной транзакцией.
func serSeedPerson(t *testing.T, db *sql.DB, tag string) string {
	t.Helper()
	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SET CONSTRAINTS ALL DEFERRED`)
	require.NoError(t, err)
	id := "usr" + strings.Repeat("0", 17-len(tag)) + tag
	acc := "acc" + strings.Repeat("0", 17-len(tag)) + tag
	_, err = tx.Exec(`INSERT INTO kaname.users (id, external_id, email, display_name, account_id, invite_status)
		VALUES ($1, $2, $3, 'p', $4, 'ACTIVE')`, id, "own:"+tag, tag+"@example.invalid", acc)
	require.NoError(t, err, "Дано: личность")
	_, err = tx.Exec(`INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`, acc, "acc-"+tag, id)
	require.NoError(t, err, "Дано: аккаунт")
	require.NoError(t, tx.Commit())
	return id
}

// serLiveRow — живая запись сессии с отличимой свёрткой носителя.
func serLiveRow(t *testing.T, db *sql.DB, person, id string, n int) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO kaname.human_sessions
		(id, user_id, bearer_digest, authenticated_at, last_presented_at, expires_at, assurance_level, presented_methods)
		VALUES ($1, $2, $3, now(), now(), now() + interval '1 day', '1', '{password}')`,
		id, person, fmt.Sprintf("%064x", 0xfe0000+n))
	require.NoError(t, err, "Дано: живая запись %s", id)
}

// serEnd — ОДИН оператор снятия той же формы, что у продукта: условие
// «ещё не снята», один момент на всех.
func serEnd(db *sql.DB, id string, at time.Time, reason string) error {
	res, err := db.Exec(`UPDATE kaname.human_sessions SET ended_at = $2, ended_reason = $3
		WHERE id = $1 AND ended_at IS NULL`, id, at, reason)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("снятие %s задело %d строк вместо одной", id, n)
	}
	return nil
}

// serConstraintOf — имя ограничения, отвергшего оператор; "" — не отказ базы.
func serConstraintOf(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName
	}
	return ""
}

type serRowState struct {
	endedAt *time.Time
	reason  *string
}

func (s serRowState) String() string {
	at, reason := "<NULL>", "<NULL>"
	if s.endedAt != nil {
		at = s.endedAt.UTC().Format(time.RFC3339Nano)
	}
	if s.reason != nil {
		reason = *s.reason
	}
	return fmt.Sprintf("ended_at=%s ended_reason=%s", at, reason)
}

func serReadRow(t *testing.T, db *sql.DB, id string) serRowState {
	t.Helper()
	var s serRowState
	require.NoError(t, db.QueryRow(`SELECT ended_at, ended_reason FROM kaname.human_sessions WHERE id = $1`, id).
		Scan(&s.endedAt, &s.reason), "чтение записи %s", id)
	return s
}

// serMoment — один момент снятия на пробу, в разрешении хранилища.
func serMoment() time.Time { return time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond) }

// TestHumanSessionSchema_KN_SER_06_TheBaseAcceptsTheForcedExitAndStillRefusesForeignWords
// — база принимает новое значение и по-прежнему отвергает чужое.
func TestHumanSessionSchema_KN_SER_06_TheBaseAcceptsTheForcedExitAndStillRefusesForeignWords(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	t.Cleanup(func() { _ = db.Close() })
	person := serSeedPerson(t, db, "ser6")
	rows := []string{"hss-ser6-1", "hss-ser6-2", "hss-ser6-3", "hss-ser6-4", "hss-ser6-5"}
	for i, id := range rows {
		serLiveRow(t, db, person, id, i)
	}
	at := serMoment()

	// Близнецы — до испытуемого: отказ чужому слову и приём трёх прежних.
	err := serEnd(db, rows[1], at, "sneeze")
	require.Error(t, err, "вторая запись с `sneeze` обязана быть отвергнута")
	require.Equal(t, serEndedReasonCheck, serConstraintOf(err), "отказ даёт ограничение словаря: %v", err)
	for i, reason := range []string{"logout", "password-change", "second-factor-removed"} {
		require.NoError(t, serEnd(db, rows[2+i], at, reason), "база принимает прежнее значение %q", reason)
	}

	// Испытуемый: первая запись с новым значением.
	err = serEnd(db, rows[0], at, serForcedExit)
	assert.NoError(t, err, "база обязана принять снятие с причиной %q; отвергло ограничение %q",
		serForcedExit, serConstraintOf(err))
}

// serQuotedLiterals — ВСЕ литералы в кавычках из определения ограничения, в
// порядке появления; удвоенная кавычка — экранированная.
func serQuotedLiterals(def string) []string {
	var out []string
	for i := 0; i < len(def); i++ {
		if def[i] != '\'' {
			continue
		}
		var b strings.Builder
		j := i + 1
		for j < len(def) {
			if def[j] == '\'' {
				if j+1 < len(def) && def[j+1] == '\'' {
					b.WriteByte('\'')
					j += 2
					continue
				}
				break
			}
			b.WriteByte(def[j])
			j++
		}
		out = append(out, b.String())
		i = j
	}
	return out
}

// serVocabularyDiff — сверка перечня домена с определением ограничения в обе
// стороны; чистая функция над текстом.
func serVocabularyDiff(domain []string, constraintDef string) (onlyDomain, onlyBase []string, err error) {
	base := serQuotedLiterals(constraintDef)
	if len(base) == 0 {
		return nil, nil, fmt.Errorf("в определении ограничения нет ни одного литерала в кавычках: %q", constraintDef)
	}
	inBase := map[string]bool{}
	for _, v := range base {
		inBase[v] = true
	}
	inDomain := map[string]bool{}
	for _, v := range domain {
		inDomain[v] = true
		if !inBase[v] {
			onlyDomain = append(onlyDomain, v)
		}
	}
	for _, v := range base {
		if !inDomain[v] {
			onlyBase = append(onlyBase, v)
		}
	}
	sort.Strings(onlyDomain)
	sort.Strings(onlyBase)
	return onlyDomain, onlyBase, nil
}

// serDomainList — перечень словаря снятия, прочитанный разбором домена.
type serDomainList struct {
	found    bool
	at       string
	values   []string
	problems []string
	files    int
}

// serReadDomainList разбирает не-тестовые файлы пакета домена.
func serReadDomainList(dir string) (serDomainList, error) {
	var l serDomainList
	entries, err := os.ReadDir(dir)
	if err != nil {
		return l, err
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			return l, err
		}
		files = append(files, f)
	}
	l.files = len(files)
	if l.files == 0 {
		return l, fmt.Errorf("в %s не разобрано ни одного файла Go", dir)
	}

	consts := map[string]string{}
	for _, f := range files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if gd.Tok == token.VAR && name.Name == serDomainListFunc {
						l.problems = append(l.problems, fmt.Sprintf("%s: %s объявлен переменной, а не функцией со свежим срезом",
							fset.Position(name.Pos()), serDomainListFunc))
					}
					if gd.Tok != token.CONST || i >= len(vs.Values) {
						continue
					}
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if s, err := strconv.Unquote(lit.Value); err == nil {
							consts[name.Name] = s
						}
					}
				}
			}
		}
	}

	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name.Name != serDomainListFunc {
				continue
			}
			l.found = true
			l.at = fset.Position(fd.Pos()).String()
			if fd.Type.Params.NumFields() != 0 || fd.Type.Results.NumFields() != 1 || !isStringSlice(fd.Type.Results.List[0].Type) {
				l.problems = append(l.problems, l.at+": сигнатура обязана быть `func "+serDomainListFunc+"() []string`")
			}
			var returns []*ast.ReturnStmt
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if r, ok := n.(*ast.ReturnStmt); ok {
					returns = append(returns, r)
				}
				return true
			})
			if len(returns) != 1 || len(returns[0].Results) != 1 {
				l.problems = append(l.problems, l.at+": тело обязано быть одним `return []string{…}`")
				continue
			}
			cl, ok := returns[0].Results[0].(*ast.CompositeLit)
			if !ok || !isStringSlice(cl.Type) {
				l.problems = append(l.problems, l.at+": возвращается не составной литерал []string — свежий срез не гарантирован")
				continue
			}
			for _, el := range cl.Elts {
				id, ok := el.(*ast.Ident)
				if !ok {
					l.problems = append(l.problems, fmt.Sprintf("%s: элемент перечня — не константа по имени", fset.Position(el.Pos())))
					continue
				}
				v, ok := consts[id.Name]
				if !ok {
					l.problems = append(l.problems, fmt.Sprintf("%s: %s — не строковая константа пакета домена", fset.Position(el.Pos()), id.Name))
					continue
				}
				l.values = append(l.values, v)
			}
		}
	}
	return l, nil
}

func isStringSlice(e ast.Expr) bool {
	at, ok := e.(*ast.ArrayType)
	if !ok || at.Len != nil {
		return false
	}
	id, ok := at.Elt.(*ast.Ident)
	return ok && id.Name == "string"
}

// TestHumanSessionSchema_KN_SER_07_DomainListAndTheBaseAgreeBothWays — словарь
// объявлен в домене одним перечнем, и база совпадает с ним в обе стороны.
func TestHumanSessionSchema_KN_SER_07_DomainListAndTheBaseAgreeBothWays(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	t.Cleanup(func() { _ = db.Close() })
	var def string
	require.NoError(t, db.QueryRow(`SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = $1`,
		serEndedReasonCheck).Scan(&def), "Дано: определение ограничения на голове")
	base := serQuotedLiterals(def)
	require.NotEmpty(t, base, "Дано: в определении ограничения нет значений — сверять не с чем: %s", def)

	list, err := serReadDomainList(serDomainDir)
	require.NoError(t, err, "Дано: разбор пакета домена")
	t.Logf("перепись: файлов домена разобрано %d; значений у домена N = %d, в ограничении M = %d (%s)",
		list.files, len(list.values), len(base), strings.Join(base, ", "))
	if !list.found {
		t.Fatalf("ИСПЫТУЕМОГО НЕТ: домен не объявляет перечень словаря снятия сессии — функции `%s() []string` "+
			"в %s нет (файлов разобрано %d); ограничение знает %d значений: %s",
			serDomainListFunc, serDomainDir, list.files, len(base), strings.Join(base, ", "))
	}
	assert.Empty(t, list.problems, "перечень домена записан не той формой:\n  %s", strings.Join(list.problems, "\n  "))

	onlyDomain, onlyBase, err := serVocabularyDiff(list.values, def)
	require.NoError(t, err)
	assert.Empty(t, onlyDomain, "значения перечня домена, которых нет в %s: %v", serEndedReasonCheck, onlyDomain)
	assert.Empty(t, onlyBase, "значения %s, которых нет в перечне домена: %v", serEndedReasonCheck, onlyBase)
	assert.NotContains(t, list.values, serCutoffOnlyReason,
		"%q — причина отсечки, а не снятия сессии (§0.2): в перечне словаря снятия её быть не должно", serCutoffOnlyReason)
	assert.Len(t, list.values, 4, "на голове N = 4")
	assert.Len(t, base, 4, "на голове M = 4")
}

// TestHumanSessionMigration_KN_SER_08_UpDoesNotRewriteLyingRows — накат не
// переписывает лежащие строки, и версия после наката — новая.
func TestHumanSessionMigration_KN_SER_08_UpDoesNotRewriteLyingRows(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	cat := serReadCatalog(t)
	before := cat.preceding()
	db := serOpenAt(t, before)
	person := serSeedPerson(t, db, "ser8")
	at := serMoment()
	ended := map[string]string{
		"hss-ser8-logout": "logout",
		"hss-ser8-pwchg":  "password-change",
		"hss-ser8-sfrem":  "second-factor-removed",
	}
	ids := []string{"hss-ser8-logout", "hss-ser8-pwchg", "hss-ser8-sfrem", "hss-ser8-live"}
	for i, id := range ids {
		serLiveRow(t, db, person, id, i)
	}
	for id, reason := range ended {
		require.NoError(t, serEnd(db, id, at, reason), "Дано: %s снята с %q на версии %d", id, reason, before)
	}
	snapshot := map[string]serRowState{}
	for _, id := range ids {
		snapshot[id] = serReadRow(t, db, id)
	}
	require.Nil(t, snapshot["hss-ser8-live"].endedAt, "Дано: живая запись жива")

	// Когда: накат до новой версии. Пока испытуемого нет — накат до головы.
	if cat.found() {
		require.NoError(t, goose.UpTo(db, ".", cat.forced), "накат до новой версии")
	} else {
		require.NoError(t, goose.Up(db, "."), "накат до головы каталога")
	}
	after, err := goose.GetDBVersion(db)
	require.NoError(t, err)

	for _, id := range ids {
		assert.Equal(t, snapshot[id].String(), serReadRow(t, db, id).String(),
			"накат переписал лежащую строку %s", id)
	}
	if !cat.found() {
		t.Fatalf("версия после наката %d — та же, что до наката (%d): ИСПЫТУЕМОГО НЕТ, в каталоге из %d миграций "+
			"нет миграции, чей накат вводит '%s' в %s", after, before, len(cat.versions), serForcedExit, serEndedReasonCheck)
	}
	assert.Equal(t, cat.forced, after, "версия базы после наката обязана быть новой (%s)", cat.file)
}

// TestHumanSessionMigration_KN_SER_09_DownTurnsForcedExitIntoLogoutAndReapplyConverges
// — откат возвращает словарь из трёх, снятые распорядителем становятся
// `logout`, повторный накат сходится.
func TestHumanSessionMigration_KN_SER_09_DownTurnsForcedExitIntoLogoutAndReapplyConverges(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	cat := serReadCatalog(t)
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	t.Cleanup(func() { _ = db.Close() })
	person := serSeedPerson(t, db, "ser9")
	const a, b, c, d = "hss-ser9-a", "hss-ser9-b", "hss-ser9-c", "hss-ser9-d"
	for i, id := range []string{a, b, c, d} {
		serLiveRow(t, db, person, id, i)
	}
	at := serMoment()
	require.NoError(t, serEnd(db, b, at, "password-change"), "Дано: B снята с `password-change`")

	serRequireSubject(t, cat)
	require.NoError(t, serEnd(db, a, at, serForcedExit), "Дано: на голове A снимается с %q", serForcedExit)
	aBefore, bBefore := serReadRow(t, db, a), serReadRow(t, db, b)

	// Когда: откат до версии, предшествующей новой, — до своей, а не «на шаг».
	preceding := cat.preceding()
	require.NoError(t, goose.DownTo(db, ".", preceding), "откат до %d обязан проходить", preceding)
	v, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, preceding, v, "база после отката стоит на версии, предшествующей новой")

	aAfter := serReadRow(t, db, a)
	if assert.NotNil(t, aAfter.reason, "у A причина есть") {
		assert.Equal(t, "logout", *aAfter.reason, "снятая распорядителем A после отката — `logout`")
	}
	if assert.NotNil(t, aAfter.endedAt, "A остаётся снятой") && assert.NotNil(t, aBefore.endedAt) {
		assert.True(t, aAfter.endedAt.Equal(*aBefore.endedAt), "ended_at у A прежний: %s против %s", aAfter, aBefore)
	}
	assert.Equal(t, bBefore.String(), serReadRow(t, db, b).String(), "B не тронута откатом")
	assert.Nil(t, serReadRow(t, db, c).endedAt, "C жива: откат переводит снятые, а не снимает живые")
	err = serEnd(db, c, at, serForcedExit)
	assert.Equal(t, serEndedReasonCheck, serConstraintOf(err),
		"после отката снятие с %q обязано отвергаться ограничением словаря, получено %v", serForcedExit, err)

	// Когда: повторный накат.
	require.NoError(t, goose.Up(db, "."), "повторный накат")
	assert.NoError(t, serEnd(db, d, at, serForcedExit), "после повторного наката снятие с %q снова принимается", serForcedExit)
}
