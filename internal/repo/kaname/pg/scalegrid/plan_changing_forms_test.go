// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ПЛАН ЧТЕНИЯ МЕНЯЕТ НЕ ТОЛЬКО ТО, ЧЬИМ СУБЪЕКТОМ СТОИТ ТАБЛИЦА
//
// Сужение до субъекта закрыло перебор и открыло СЛЕПОТУ: три вида объектов
// меняют план чтения измеряемой таблицы, стоя субъектом САМИ, а таблицу называя
// в своём хвосте.
//
//	расширенная статистика   менять план — её ЕДИНСТВЕННОЕ назначение
//	политика построчной      подставляет условие в КАЖДЫЙ запрос к таблице
//	наследование             чтение родителя становится обходом потомка
//
// Слепота была МОЛЧАЛИВОЙ и потому опаснее перебора: настоящая миграция с
// первыми двумя формами над `kaname.users` оставила отпечаток неподвижным (7
// миграций), перепись форм прошла зелёной — она считала эти виды знакомыми, —
// и гейт свежести промолчал.
//
// Нагляднее всего дефект показывает АСИММЕТРИЯ ОДНОЙ ПАРЫ: включение
// построчной безопасности ловилось (`ALTER TABLE <измеряемая> ENABLE ROW LEVEL
// SECURITY` — субъектом стоит таблица), а политика, несущая само условие, —
// нет. Половина пары ловилась, половина молчала.
func TestPlanChangingFormsWithAForeignSubject(t *testing.T) {
	tables := []string{"access_bindings", "users"}

	// declarations — объявления именованных объектов, из которых ВЫВОДИТСЯ
	// словарь «имя → его таблица». Снятие по имени судится по нему: имя объекта
	// таблицы не содержит, и без словаря исход осторожный.
	declarations := map[string]string{"declarations.sql": "" +
		"CREATE STATISTICS kaname.ab_scope_stx (dependencies) ON scope, role_id FROM kaname.access_bindings;\n" +
		"CREATE STATISTICS kaname.lim_kind_stx (dependencies) ON kind, tier FROM kaname.limits;\n"}
	corpus := buildCorpusIndex(declarations)

	cases := []struct {
		name string
		sql  string
		want bool
		// withCorpus — судить со словарём каталога. Без него имя объекта не
		// связано с таблицей, и осторожный исход законен.
		withCorpus bool
	}{
		// ── РАСШИРЕННАЯ СТАТИСТИКА ─────────────────────────────────────────
		{
			name: "расширенная статистика НАД измеряемой — влияет",
			sql: "CREATE STATISTICS kaname.ab_scope_stx (dependencies)\n" +
				"  ON scope, role_id FROM kaname.access_bindings;",
			want: true,
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: та же статистика над ЧУЖОЙ таблицей — не влияет",
			sql: "CREATE STATISTICS kaname.lim_kind_stx (dependencies)\n" +
				"  ON kind, tier FROM kaname.limits;",
			want: false,
		},
		{
			name: "снятие расширенной статистики измеряемой — влияет",
			// Имя объекта таблицы не содержит, как и у индекса: связывается
			// словарём, выведенным обходом каталога.
			sql:        "DROP STATISTICS kaname.ab_scope_stx;",
			want:       true,
			withCorpus: true,
		},
		{
			name:       "ЗАКОННЫЙ БЛИЗНЕЦ: снятие статистики ЧУЖОЙ таблицы — не влияет",
			sql:        "DROP STATISTICS kaname.lim_kind_stx;",
			want:       false,
			withCorpus: true,
		},
		{
			name: "снятие статистики, НЕ ОБЪЯВЛЕННОЙ каталогом — влияет (осторожно)",
			// Половина пары к двум случаям выше: связать имя с таблицей нечем,
			// и молчание здесь было бы слепотой, а не сужением.
			sql:        "DROP STATISTICS kaname.unknown_stx;",
			want:       true,
			withCorpus: true,
		},

		// ── ПОСТРОЧНАЯ БЕЗОПАСНОСТЬ ────────────────────────────────────────
		{
			name: "политика построчной безопасности НА измеряемой — влияет",
			sql: "CREATE POLICY users_same_account ON kaname.users\n" +
				"  USING (account_id = current_setting('kaname.account_id'));",
			want: true,
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: та же политика на ЧУЖОЙ таблице — не влияет",
			sql: "CREATE POLICY limits_same_account ON kaname.limits\n" +
				"  USING (account_id = current_setting('kaname.account_id'));",
			want: false,
		},
		{
			name: "снятие политики с измеряемой — влияет",
			sql:  "DROP POLICY users_same_account ON kaname.users;",
			want: true,
		},
		{
			name: "правка политики на измеряемой — влияет",
			sql:  "ALTER POLICY users_same_account ON kaname.users USING (true);",
			want: true,
		},
		{
			name: "ВТОРАЯ ПОЛОВИНА ПАРЫ: включение построчной безопасности — влияет",
			// Ловилось и прежде: субъектом стоит сама таблица. Случай оставлен
			// рядом НАМЕРЕННО — именно расхождение этих двух исходов и было
			// признаком дефекта.
			sql:  "ALTER TABLE kaname.users ENABLE ROW LEVEL SECURITY;",
			want: true,
		},

		// ── НАСЛЕДОВАНИЕ ───────────────────────────────────────────────────
		{
			name: "потомок объявляет измеряемую РОДИТЕЛЕМ — влияет",
			// Чтение родителя после этого обходит и потомка.
			sql:  "CREATE TABLE kaname.ab_2026 (note text) INHERITS (kaname.access_bindings);",
			want: true,
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: тот же потомок у ЧУЖОГО родителя — не влияет",
			sql:  "CREATE TABLE kaname.lim_2026 (note text) INHERITS (kaname.limits);",
			want: false,
		},
		{
			name: "потомок подшивается к измеряемой отдельным оператором — влияет",
			sql:  "ALTER TABLE kaname.ab_2026 INHERIT kaname.access_bindings;",
			want: true,
		},
		{
			name: "потомок ОТШИВАЕТСЯ от измеряемой — влияет",
			// Обратное действие меняет план родителя ровно так же.
			sql:  "ALTER TABLE kaname.ab_2026 NO INHERIT kaname.access_bindings;",
			want: true,
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: подшивка к ЧУЖОМУ родителю — не влияет",
			sql:  "ALTER TABLE kaname.lim_2026 INHERIT kaname.limits;",
			want: false,
		},
		{
			name: "КОПИЯ ФОРМЫ, а не наследование: LIKE измеряемой — не влияет",
			// Одно-фактное отличие от случая выше: `LIKE` копирует описание
			// столбцов один раз и связи не заводит, `INHERITS` заводит.
			sql:  "CREATE TABLE kaname.ab_copy (LIKE kaname.access_bindings INCLUDING ALL);",
			want: false,
		},
	}

	var influencing, ignored int
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			idx := corpusIndex{}
			if c.withCorpus {
				idx = corpus
			}
			if got := migrationTouches(c.sql, tables, scopeReadPlan, idx); got != c.want {
				t.Fatalf("вердикт %v, ожидался %v", got, c.want)
			} else if got {
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

// TestFingerprintSeesPlanChangingFormsInATree — ПРЕДИКАТ ПРИЁМКИ, целиком через
// настоящий прибор: миграция с расширенной статистикой над измеряемой таблицей
// обязана двинуть отпечаток, а близнец над неизмеряемой — не двинуть.
//
// Проба над `ComputeFingerprint`, а не над предикатом: молчание наступало у
// ПРИБОРА, и доказывать его снятие надо там же. Дерево синтетическое, поэтому
// проба ничего не утверждает о сегодняшнем составе миграций.
func TestFingerprintSeesPlanChangingFormsInATree(t *testing.T) {
	root := syntheticRoot(t)

	base, err := ComputeFingerprint(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: отпечаток синтетического дерева: %v", err)
	}
	if len(base.Files) == 0 || len(base.Tables) == 0 {
		t.Fatalf("синтетическое дерево пусто: файлов %d, таблиц %d — судить было бы нечего",
			len(base.Files), len(base.Tables))
	}
	t.Logf("контроль: файлов под отпечатком %d, таблиц выведено %d (%s)",
		len(base.Files), len(base.Tables), strings.Join(base.Tables, ", "))

	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, migrateDir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("запись %s: %v", name, err)
		}
	}
	countMigrations := func(fp Fingerprint) int {
		n := 0
		for _, f := range fp.Files {
			if strings.HasSuffix(f, ".sql") {
				n++
			}
		}
		return n
	}
	remeasure := func(what string) Fingerprint {
		t.Helper()
		fp, ferr := ComputeFingerprint(root)
		if ferr != nil {
			t.Fatalf("отпечаток после %s: %v", what, ferr)
		}
		return fp
	}

	// ЗАКОННЫЙ БЛИЗНЕЦ ПЕРВЫМ: те же формы над НЕИЗМЕРЯЕМОЙ таблицей.
	// Порядок намеренный — если бы двигал он, красное следующего шага пришло бы
	// от соседа, а не от предмета.
	write("20990101000000_forms_over_an_unmeasured_table.sql",
		"-- +goose Up\n"+
			"CREATE STATISTICS kaname.limits_stx (dependencies) ON kind, tier FROM kaname.limits;\n"+
			"CREATE POLICY limits_scope ON kaname.limits USING (true);\n")
	twin := remeasure("близнеца над неизмеряемой")
	if twin.Composition != base.Composition {
		t.Fatalf("отпечаток двинулся от форм над НЕИЗМЕРЯЕМОЙ таблицей: было %s, стало %s — "+
			"тогда красное следующего шага пришло бы не от предмета",
			base.Composition, twin.Composition)
	}
	t.Logf("близнец над неизмеряемой: отпечаток неподвижен, миграций под ним %d",
		countMigrations(twin))

	// ДЕФЕКТ: те же формы над ИЗМЕРЯЕМОЙ таблицей. Отличие РОВНО ОДНО — имя.
	write("20990101000001_forms_over_the_measured_table.sql",
		"-- +goose Up\n"+
			"CREATE STATISTICS kaname.ab_stx (dependencies) ON scope_type, scope_id FROM kaname.access_bindings;\n"+
			"CREATE POLICY ab_scope ON kaname.access_bindings USING (true);\n")
	hit := remeasure("форм над измеряемой")
	if hit.Composition == twin.Composition {
		t.Fatalf("отпечаток НЕ ДВИНУЛСЯ от расширенной статистики и политики над измеряемой "+
			"таблицей (%s): отчёт о стоимости вердикта остался бы «свежим», когда план "+
			"чтения уже другой. Менять план — единственное назначение расширенной "+
			"статистики, а политика подставляет условие в каждый запрос к таблице",
			hit.Composition)
	}
	t.Logf("формы над измеряемой: отпечаток сдвинулся %s -> %s, миграций под ним %d",
		twin.Composition, hit.Composition, countMigrations(hit))
}

// TestHarmlessObjectKindsAreProvenNotDeclared — КАЖДЫЙ вид, объявленный
// безвредным, несёт свою инъекционную пару, и она прогоняется.
//
// # Почему проба обязана существовать
//
// Вид, лежащий в словаре безвредных, переписью форм НЕ ищется по построению:
// он знаком, значит про него не спрашивают. Молчание по нему поэтому
// неотличимо от слепоты — ровно так `statistics` и `policy` прожили в словаре,
// не имея на то ни одного довода, и гейт молчал на миграции, менявшей план.
//
// Эта проба — единственное место, где безвредность проверяется. Запись без
// полного доказательства безвредности НЕ покупает: `proven` возвращает ложь, и
// вид уходит в осторожный исход. Проба это утверждение тоже проверяет.
func TestHarmlessObjectKindsAreProvenNotDeclared(t *testing.T) {
	measured := []string{"access_bindings"}

	if len(objectsWithoutTableSubject) == 0 {
		t.Log("безвредным не объявлен НИ ОДИН вид — это законный исход: осторожно " +
			"судится всё, чего разбор не знает")
	}

	kinds := make([]string, 0, len(objectsWithoutTableSubject))
	for word := range objectsWithoutTableSubject {
		kinds = append(kinds, word)
	}
	sort.Strings(kinds)

	for _, word := range kinds {
		h := objectsWithoutTableSubject[word]
		t.Run(word, func(t *testing.T) {
			if !h.proven() {
				t.Fatalf("вид %q объявлен безвредным БЕЗ доказательства: нет одного из трёх "+
					"операторов пары. Объявление молчания не покупает — заполни naming, "+
					"foreign и control либо сними запись, и вид уйдёт в осторожный исход", word)
			}
			if strings.TrimSpace(h.why) == "" {
				t.Fatalf("вид %q объявлен безвредным без причины: читатель не узнает, ПОЧЕМУ "+
					"план чтения не меняется", word)
			}
			if migrationTouches(h.naming, measured, scopeReadPlan, corpusIndex{}) {
				t.Errorf("оператор вида %q, называющий измеряемую таблицу, признан влияющим — "+
					"значит вид безвредным не является:\n  %s", word, h.naming)
			}
			if migrationTouches(h.foreign, measured, scopeReadPlan, corpusIndex{}) {
				t.Errorf("оператор вида %q над НЕИЗМЕРЯЕМОЙ таблицей признан влияющим:\n  %s",
					word, h.foreign)
			}
			// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ. Без него «молчит» неотличимо от «не видит
			// имени»: предикат, ослепший на измеряемую таблицу целиком, прошёл
			// бы обе половины выше.
			if !migrationTouches(h.control, measured, scopeReadPlan, corpusIndex{}) {
				t.Errorf("положительный контроль вида %q НЕ покраснел: распознаватель не видит "+
					"имени измеряемой таблицы вовсе, и молчание выше ничего не доказывает:"+
					"\n  %s", word, h.control)
			}
			t.Logf("безвредность доказана: %s", h.why)
		})
	}

	// ИНЪЕКЦИЯ В ОБРАТНУЮ СТОРОНУ: запись БЕЗ доказательства молчания не даёт.
	// Проверяется на синтетике, а не правкой живого словаря: живой словарь
	// делят все пробы пакета.
	declaredOnly := harmlessObject{why: "объявлено словом, не доказано"}
	if declaredOnly.proven() {
		t.Fatal("запись без операторов пары считается доказанной: словарь снова покупает " +
			"молчание объявлением, и класс возвращается тем же путём, каким пришёл")
	}

	// И ВТОРАЯ ПОЛОВИНА ЭТОЙ ПАРЫ: заполненная запись доказанной считается.
	if !(harmlessObject{why: "x", naming: "a", foreign: "b", control: "c"}).proven() {
		t.Fatal("заполненная запись не признана доказанной: тогда словарь не работает вовсе")
	}

	// КАЖДОЙ ЗАПИСИ ЕСТЬ ЧТО ИСКЛЮЧАТЬ. Запись, чьего вида в каталоге миграций
	// нет, переживает свой предмет и молча покрывает пустоту.
	corpus := migrationCorpus(t)
	seen := map[string]int{}
	for _, body := range corpus {
		for _, stmt := range sqlStatements(body) {
			toks := sqlTokens(stmt)
			if len(toks) == 0 {
				continue
			}
			switch toks[0].word {
			case "create", "alter", "drop":
				for _, tk := range toks[1:4] {
					if seenKind := tk.word; objectsWithoutTableSubject[seenKind].why != "" {
						seen[seenKind]++
					}
				}
			}
		}
	}
	t.Logf("ПЕРЕПИСЬ: видов объявлено безвредными %d; файлов корпуса осмотрено %d", len(kinds), len(corpus))
	for _, word := range kinds {
		t.Logf("  вид %-10s — операторов в каталоге %d", word, seen[word])
		if seen[word] == 0 {
			t.Errorf("вид %q объявлен безвредным, но в каталоге миграций его НЕТ: запись "+
				"пережила свой предмет и молча покрывает пустоту — сними её, и вид вернётся "+
				"в осторожный исход сам", word)
		}
	}
}
