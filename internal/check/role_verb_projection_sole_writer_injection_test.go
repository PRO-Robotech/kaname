// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// role_verb_projection_sole_writer_injection_test.go — доказательство
// падучести гейта IAM-RV-1-12 «у проекции роли один АВТОР» — В ОБЕ СТОРОНЫ
// (порт одноимённой пробы репозитория платформы, снят там вынесением службы
// доступа — `kacho#2597`).
//
// Гейт обходит дерево, поэтому его признак воспроизводится здесь над
// СИНТЕТИЧЕСКИМ входом: доказывается, что он различает АВТОРСТВО, СНЯТИЕ и
// ЧТЕНИЕ, приписывает находку функции и молчит на законных формах. Инъекция
// правкой настоящего дерева не ставится намеренно — она рвала бы чужие
// прогоны в общей рабочей копии.
//
// Прогонов по каждой оси ТРИ, а не два: контроль · инъекция проверяемого ·
// законный близнец. Без третьего молчание проверки неотличимо от её смерти.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// roleVerbOpsOf — плоский перечень найденных операторов (для утверждений).
func roleVerbOpsOf(t *testing.T, src string) []string {
	t.Helper()
	return roleVerbOpsOfTable(t, src, check.RoleVerbTable)
}

// roleVerbOpsOfTable — то же для ЛЮБОЙ из таблиц проекции.
func roleVerbOpsOfTable(t *testing.T, src, table string) []string {
	t.Helper()
	ops, _, err := check.RoleProjectionWritesIn("zz_injection.go", src, table)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	out := make([]string, 0, len(ops))
	for _, op := range ops {
		role := "снимает"
		if op.Authors {
			role = "АВТОРУЕТ"
		}
		if op.Relocates {
			role += "+переселяет"
		}
		out = append(out, op.Func+" → "+op.Verb+" ["+role+"]")
	}
	return out
}

// roleVerbAuthorsOf — только вносящие строку: единица ОСИ 1.
func roleVerbAuthorsOf(t *testing.T, src, table string) []string {
	t.Helper()
	ops, _, err := check.RoleProjectionWritesIn("zz_injection.go", src, table)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	var out []string
	for _, op := range ops {
		if op.Authors {
			out = append(out, op.Func)
		}
	}
	return out
}

// roleVerbStrandedOf — снимающие, чей оператор НЕ переселяет снятое: единица
// ОСИ 2.
func roleVerbStrandedOf(t *testing.T, src, table string) []string {
	t.Helper()
	ops, _, err := check.RoleProjectionWritesIn("zz_injection.go", src, table)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	var out []string
	for _, op := range ops {
		if !op.Authors && !op.Relocates {
			out = append(out, op.Func+" → "+op.Verb)
		}
	}
	return out
}

// ── ОБРАЗЦЫ, из которых собираются прогоны ──────────────────────────────────
//
// Каждый — форма, ДЕЙСТВИТЕЛЬНО стоящая в дереве kaname, а не выдуманная:
// гейт судит их, и инъекция обязана подавать ему то же, что подаёт прод-код.

// roleVerbSrcAuthor — путь роли: снимает СВОЮ проекцию и вносит её заново
// (форма `internal/repo/kaname/pg/role_repo.go`).
const roleVerbSrcAuthor = `package pg

func (w *roleWriter) ReplaceRoleVerbs(ctx context.Context, roleID string) error {
	if _, err := w.tx.Exec(ctx, ` + "`DELETE FROM kaname.role_verb WHERE role_id = $1`" + `, roleID); err != nil {
		return err
	}
	_, err := w.tx.Exec(ctx, ` + "`INSERT INTO kaname.role_verb (role_id, object_type, verb) VALUES ($1,$2,$3)`" + `)
	return err
}`

// roleVerbSrcResettler — применитель каталога: снимает по чужому референту и
// ПЕРЕСЕЛЯЕТ снятое ТЕМ ЖЕ оператором (форма
// `internal/repo/kaname/pg/catalog_consequence_sql.go`). Законная форма —
// гейт обязан молчать на обеих осях.
const roleVerbSrcResettler = `package pg

func (w catalogWriter) ResettleTenantProjections(ctx context.Context) error {
	return w.tx.QueryRow(ctx, ` + "`" + `
		WITH doomed AS (
		  SELECT rv.role_id, rv.object_type, rv.verb FROM kaname.role_verb rv
		), moved AS (
		  INSERT INTO kaname.role_grant_orphan (role_id, object_type, verb, source, reason)
		  SELECT d.role_id, d.object_type, d.verb, 'role_verb', $1 FROM doomed d
		), dropped AS (
		  DELETE FROM kaname.role_verb rv USING doomed d
		   WHERE rv.role_id = d.role_id AND rv.object_type = d.object_type AND rv.verb = d.verb
		  RETURNING 1
		)
		SELECT (SELECT count(*) FROM doomed), (SELECT count(*) FROM dropped)` + "`" + `).Scan()
}`

// ── ОСЬ 1: АВТОР ОДИН ───────────────────────────────────────────────────────

// TestIAMRV112_AxisAuthor_ControlSeesExactlyOneAuthor — КОНТРОЛЬ.
func TestIAMRV112_AxisAuthor_ControlSeesExactlyOneAuthor(t *testing.T) {
	t.Parallel()
	if got := roleVerbAuthorsOf(t, roleVerbSrcAuthor, check.RoleVerbTable); len(got) != 1 {
		t.Fatalf("на пути роли авторов %d, а он ровно один: %v", len(got), got)
	}
	if got := roleVerbAuthorsOf(t, roleVerbSrcResettler, check.RoleVerbTable); len(got) != 0 {
		t.Fatalf("применитель признан АВТОРОМ: %v — он строку не вносит, а снимает, и "+
			"считать его автором значило бы вернуть прежнюю единицу счёта", got)
	}
}

// TestIAMRV112_AxisAuthor_RedOnASecondAuthor — ИНЪЕКЦИЯ ПРОВЕРЯЕМОГО.
func TestIAMRV112_AxisAuthor_RedOnASecondAuthor(t *testing.T) {
	t.Parallel()
	src := `package seed

func replaceRoleVerbsTx(ctx context.Context, tx pgxExecer, roleID string) error {
	if _, err := tx.Exec(ctx, ` + "`DELETE FROM kaname.role_verb WHERE role_id = $1`" + `, roleID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, ` + "`INSERT INTO kaname.role_verb (role_id, object_type, verb) VALUES ($1,$2,$3)`" + `)
	return err
}`
	got := roleVerbAuthorsOf(t, src, check.RoleVerbTable)
	if len(got) == 0 {
		t.Fatal("ось авторства МОЛЧИТ на втором вносящем — гейт не способен покраснеть, " +
			"и его зелёный на дереве ничего не значит")
	}
	if got[0] != "replaceRoleVerbsTx" {
		t.Errorf("находка не приписана функции: %q — читатель пойдёт искать координату "+
			"и не найдёт её", got[0])
	}
	if stranded := roleVerbStrandedOf(t, src, check.RoleVerbTable); len(stranded) != 1 {
		t.Errorf("инъекция авторства задела ось переселения: %v", stranded)
	}
}

// TestIAMRV112_AxisAuthor_SilentOnAPureRemover — ЗАКОННЫЙ БЛИЗНЕЦ.
func TestIAMRV112_AxisAuthor_SilentOnAPureRemover(t *testing.T) {
	t.Parallel()
	if got := roleVerbAuthorsOf(t, roleVerbSrcResettler, check.RoleVerbTable); len(got) != 0 {
		t.Errorf("ось авторства краснеет на СНИМАЮЩЕМ: %v — под таким предикатом снятие "+
			"модуля не прошло бы ни разу", got)
	}
}

// ── ОСЬ 2: СНИМАЮЩИЙ НЕ-АВТОР ПЕРЕСЕЛЯЕТ ────────────────────────────────────

// TestIAMRV112_AxisRelocation_ControlSeesTheResettlerAsRelocating — КОНТРОЛЬ.
func TestIAMRV112_AxisRelocation_ControlSeesTheResettlerAsRelocating(t *testing.T) {
	t.Parallel()
	if got := roleVerbStrandedOf(t, roleVerbSrcResettler, check.RoleVerbTable); len(got) != 0 {
		t.Fatalf("настоящая форма применителя признана НЕ переселяющей: %v — признак "+
			"переселения не видит `INSERT INTO %s` в том же операторе, и всё, что ниже, "+
			"судит сломанный предикат", got, check.RoleGrantOrphanTable)
	}
}

// TestIAMRV112_AxisRelocation_RedWhenRemovalStrandsTheRow — ИНЪЕКЦИЯ ПРОВЕРЯЕМОГО.
func TestIAMRV112_AxisRelocation_RedWhenRemovalStrandsTheRow(t *testing.T) {
	t.Parallel()
	src := `package pg

func (w catalogWriter) ResettleTenantProjections(ctx context.Context) error {
	return w.tx.QueryRow(ctx, ` + "`" + `
		WITH doomed AS (
		  SELECT rv.role_id, rv.object_type, rv.verb FROM kaname.role_verb rv
		), dropped AS (
		  DELETE FROM kaname.role_verb rv USING doomed d
		   WHERE rv.role_id = d.role_id AND rv.object_type = d.object_type AND rv.verb = d.verb
		  RETURNING 1
		)
		SELECT count(*) FROM dropped` + "`" + `).Scan()
}`
	got := roleVerbStrandedOf(t, src, check.RoleVerbTable)
	if len(got) == 0 {
		t.Fatal("ось переселения МОЛЧИТ на снятии БЕЗ переселения — то есть на том самом " +
			"исходе, ради которого таблица сирот и заведена: право отобрано, записи нет")
	}
	if !strings.Contains(got[0], "catalogWriter.ResettleTenantProjections") {
		t.Errorf("находка не приписана функции: %q", got[0])
	}
	if authors := roleVerbAuthorsOf(t, src, check.RoleVerbTable); len(authors) != 0 {
		t.Errorf("инъекция переселения задела ось авторства: %v", authors)
	}
}

// TestIAMRV112_AxisRelocation_SilentOnTheAuthorsOwnDelete — ЗАКОННЫЙ БЛИЗНЕЦ.
func TestIAMRV112_AxisRelocation_SilentOnTheAuthorsOwnDelete(t *testing.T) {
	t.Parallel()
	stranded := roleVerbStrandedOf(t, roleVerbSrcAuthor, check.RoleVerbTable)
	if len(stranded) != 1 {
		t.Fatalf("признак не увидел снятия у автора: %v", stranded)
	}
	if authors := roleVerbAuthorsOf(t, roleVerbSrcAuthor, check.RoleVerbTable); len(authors) != 1 ||
		!strings.Contains(stranded[0], authors[0]) {
		t.Errorf("снятие и авторство приписаны РАЗНЫМ функциям (%v против %v) — тогда "+
			"освобождение автора по ключу не сработает, и путь роли покраснеет на каждой "+
			"правке роли", stranded, authors)
	}
}

// ── ЗАКОННЫЕ БЛИЗНЕЦЫ, ОБЩИЕ ДЛЯ ОБЕИХ ОСЕЙ ─────────────────────────────────

// TestIAMRV112_InjectionSilentOnBothReaders — читателей проекции в дереве
// несколько, и обе формы чтения обязаны молчать: одни считают строки, другие
// соединяют.
func TestIAMRV112_InjectionSilentOnBothReaders(t *testing.T) {
	t.Parallel()
	whole := `package scalegrid

func (c *census) read() error {
	return scalar(&c.RoleVerbs, ` + "`SELECT count(*)::bigint FROM kaname.role_verb`" + `)
}`
	perRole := `package scalegrid

func strengthOf(ctx context.Context, roleID string) error {
	return q.QueryRow(ctx,
		` + "`SELECT count(*)::bigint FROM kaname.role_verb WHERE role_id = $1`" + `, roleID).Scan(&n)
}`
	joined := `package relverdict

func expand(ctx context.Context) error {
	return q.Query(ctx, ` + "`SELECT 1 FROM roles r JOIN kaname.role_verb rv ON rv.role_id = r.id`" + `)
}`
	for name, src := range map[string]string{
		"чтение таблицы целиком": whole,
		"чтение по одной роли":   perRole,
		"соединение с ролями":    joined,
	} {
		if got := roleVerbOpsOf(t, src); len(got) != 0 {
			t.Errorf("признак краснеет на ЧТЕНИИ проекции (%s): %v — то есть на том, ради чего "+
				"таблица и заведена", name, got)
		}
	}
}

// TestIAMRV112_InjectionSilentOnItsOwnExplanation — ЗАКОННЫЙ БЛИЗНЕЦ второго
// рода: имя таблицы и слово INSERT в КОММЕНТАРИИ, объясняющем эту самую
// проверку.
func TestIAMRV112_InjectionSilentOnItsOwnExplanation(t *testing.T) {
	t.Parallel()
	src := `package check

// Предмет: INSERT INTO kaname.role_verb из второго места — находка.
// Проверяется оператор DELETE FROM kaname.role_verb тоже, и переселение
// INSERT INTO kaname.role_grant_orphan — тоже.
func explain() {}
`
	if got := roleVerbOpsOf(t, src); len(got) != 0 {
		t.Errorf("признак краснеет на КОММЕНТАРИИ, объясняющем проверку: %v — гейт, красный "+
			"на собственном объяснении, снимут первым", got)
	}
}

// TestIAMRV112_InjectionSilentOnAnotherTable — запись в чужую таблицу не находка.
func TestIAMRV112_InjectionSilentOnAnotherTable(t *testing.T) {
	t.Parallel()
	src := `package pg

func put(ctx context.Context) error {
	_, err := tx.Exec(ctx, ` + "`INSERT INTO kaname.role_rule_selectors (role_id) VALUES ($1)`" + `)
	return err
}`
	if got := roleVerbOpsOf(t, src); len(got) != 0 {
		t.Errorf("признак краснеет на записи в ЧУЖУЮ таблицу: %v", got)
	}
}

// TestIAMRV112_LayerPredicateSeparatesRepoFromSeed — третья ось гейта: слой.
func TestIAMRV112_LayerPredicateSeparatesRepoFromSeed(t *testing.T) {
	t.Parallel()
	inRepo := "internal/repo/kaname/pg/role_repo.go"
	inSeed := "internal/apps/kaname/seed/migrate_backfill.go"

	if !strings.Contains("/"+inRepo, check.RoleVerbWriterLayer) {
		t.Errorf("предикат слоя не признаёт законного места писателя (%s) — гейт краснел бы "+
			"на единственно верной раскладке", inRepo)
	}
	if strings.Contains("/"+inSeed, check.RoleVerbWriterLayer) {
		t.Errorf("предикат слоя признаёт своим SQL в слое use-case (%s) — третья ось гейта "+
			"вакуумна", inSeed)
	}
}

// ── ВТОРАЯ таблица проекции (kacho#1030) ────────────────────────────────────

func TestIAMCT105_InjectionRedOnASecondRuleRefAuthor(t *testing.T) {
	t.Parallel()
	src := `package seed

func reseedRuleRefsTx(ctx context.Context, tx pgxExecer, roleID string) error {
	if _, err := tx.Exec(ctx, ` + "`DELETE FROM kaname.role_rule_ref WHERE role_id = $1`" + `, roleID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, ` + "`INSERT INTO kaname.role_rule_ref (role_id, module, resource) VALUES ($1,$2,$3)`" + `)
	return err
}`
	got := roleVerbAuthorsOf(t, src, check.RoleRuleRefTable)
	if len(got) != 1 || got[0] != "reseedRuleRefsTx" {
		t.Fatalf("второй АВТОР ВТОРОЙ проекции обязан находиться и называться функцией; "+
			"найдено: %v", got)
	}
}

func TestIAMCT105_InjectionRedWhenRuleRefRemovalStrandsTheRow(t *testing.T) {
	t.Parallel()
	src := `package pg

func (w catalogWriter) resettle(ctx context.Context) error {
	return w.tx.QueryRow(ctx, ` + "`DELETE FROM kaname.role_rule_ref rr USING doomed d WHERE rr.role_id = d.role_id`" + `).Scan()
}`
	if got := roleVerbStrandedOf(t, src, check.RoleRuleRefTable); len(got) != 1 {
		t.Fatalf("снятие сегментов БЕЗ переселения обязано находиться: %v", got)
	}
}

func TestIAMCT105_InjectionSilentOnARuleRefReader(t *testing.T) {
	t.Parallel()
	src := `package relverdict

func rulesRefsOfRole(ctx context.Context, q pgxQuerier, roleID string) (int, error) {
	var n int
	err := q.QueryRow(ctx, ` + "`SELECT count(*) FROM kaname.role_rule_ref WHERE role_id = $1`" + `, roleID).Scan(&n)
	return n, err
}`
	if got := roleVerbOpsOfTable(t, src, check.RoleRuleRefTable); len(got) != 0 {
		t.Fatalf("ЧТЕНИЕ второй проекции законно и обязано молчать — читателей у неё будет "+
			"несколько; найдено: %v", got)
	}
}

func TestIAMCT105_InjectionSilentOnTheOtherProjection(t *testing.T) {
	t.Parallel()
	if got := roleVerbOpsOfTable(t, roleVerbSrcAuthor, check.RoleRuleRefTable); len(got) != 0 {
		t.Fatalf("признак второй таблицы обязан судить ТОЛЬКО её: иначе расширение охвата "+
			"смешало бы две популяции и находка называла бы не тот предмет; найдено: %v", got)
	}
}
