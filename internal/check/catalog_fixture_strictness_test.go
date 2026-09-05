// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// catalog_fixture_strictness_test.go — требования Т8 и Т12 приёмки
// `rule-segments-have-a-referent.md`.
//
// Т8 — колонки СЛОВАРЯ КАТАЛОГА несут проверку «точки не содержит». У колонок
// словаря МОДЕЛИ таких проверок пять (миграции 0091, 0098); у колонок словаря
// каталога до #1030 было ноль, и третье написание — прямой путь к классу 513001,
// где двенадцать доменных ролей не давали НИ ОДНОГО пообъектного права.
//
// Т12 — фикстура пробы НЕ отменяет немедленность новых ключей. Оператор
// `SET CONSTRAINTS ALL DEFERRED` накрывает и ключ, объявленный
// `INITIALLY IMMEDIATE` (измерено пробой
// `TestIAMCT112_InjectionFixtureThatDefersEverythingHidesTheSegment`): отказ
// переезжает с оператора на коммит, подсказка писателя не ставится, и проба
// наблюдает общий текст вместо названного сегмента. Проба остаётся синтаксически
// верной и проверяет ДРУГУЮ форму ключа, чем та, что работает у арендатора, —
// класс «фикстура снисходительнее продукта».
//
// Гейт судит ПЕРЕСЕЧЕНИЕ, а не сам оператор: в дереве шесть фикстур открывают им
// транзакцию, и все шесть законны для своего предмета.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// catalogProbeFile — файл проб ссылочной целостности каталога.
const catalogProbeFile = "services/iam/internal/repo/kacho/pg/catalog_referent_integration_test.go"

// catalogMigrationRel — та же миграция, что сверяет гейт паритета.
const catalogMigrationRel = catalogMigrationPath

// deferEverything — оператор, отменяющий немедленность ДЛЯ ВСЕЙ транзакции.
const deferEverything = "SET CONSTRAINTS ALL DEFERRED"

// auditFixtureStrictness — ЯДРО гейта Т12, отделённое от пути в дереве
// НАМЕРЕННО: инъекция обязана прогнать его на синтетическом исходнике, а не на
// файле проб, который она иначе была бы вынуждена портить.
//
// Возвращает: сколько функций осмотрено, сколько вхождений оператора найдено в
// ИСПОЛНЯЕМОМ коде, и находки.
func auditFixtureStrictness(filename, src string) (funcs, occurrences int, findings []string, err error) {
	fset := token.NewFileSet()
	file, perr := parser.ParseFile(fset, filename, src, 0)
	if perr != nil {
		return 0, 0, nil, perr
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		funcs++
		found := false
		// Судится УЗЕЛ-ЛИТЕРАЛ, а не текст файла: имя оператора стоит и в шапке
		// файла проб, и в объяснении самой пробы, — гейт по подстроке краснел бы
		// на собственном разборе.
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			lit, isLit := n.(*ast.BasicLit)
			if !isLit || lit.Kind != token.STRING {
				return true
			}
			if strings.Contains(lit.Value, deferEverything) {
				found = true
				occurrences++
			}
			return true
		})
		if !found {
			continue
		}
		// Законный близнец ровно один: проба, которая ИЗМЕРЯЕТ цену оператора.
		// Она обязана называться так, чтобы это было видно из имени, — иначе
		// послабление растворяется в перечне обычных проб.
		if !strings.Contains(fn.Name.Name, "Injection") {
			findings = append(findings, fn.Name.Name+" — фикстура пробы каталога открывает "+
				deferEverything+", а он накрывает и ключ, объявленный INITIALLY IMMEDIATE. "+
				"Отказ переедет с оператора на коммит, подсказка писателя не поставится, и "+
				"проба будет наблюдать общий текст вместо названного сегмента — то есть "+
				"проверять ДРУГУЮ форму ключа, чем та, что работает у арендатора")
		}
	}
	return funcs, occurrences, findings, nil
}

// TestIAMCT112_CatalogProbesDoNotDeferEverything — Т12.
func TestIAMCT112_CatalogProbesDoNotDeferEverything(t *testing.T) {
	root := catalogRepoRoot(t)
	path := filepath.Join(root, catalogProbeFile)
	src, err := os.ReadFile(path) // #nosec G304 -- путь-константа своего дерева
	if err != nil {
		t.Fatalf("прочитать пробы каталога: %v — предмета у гейта нет", err)
	}

	funcs, occurrences, findings, perr := auditFixtureStrictness(catalogProbeFile, string(src))
	if perr != nil {
		t.Fatalf("разобрать пробы каталога: %v — молчание неразобранного файла ничего не значит", perr)
	}

	t.Logf("осмотрено функций пробного файла: %d; вхождений %q в исполняемом коде: %d",
		funcs, deferEverything, occurrences)
	if funcs == 0 {
		t.Fatal("функций не прочитано ни одной — обход пуст, вердикт беспредметен")
	}
	if occurrences == 0 {
		t.Fatalf("оператор %q не встречается НИ РАЗУ: либо пробу цены сняли вместе с "+
			"предметом, либо файл переехал. И то и другое обязано быть замечено здесь, "+
			"а не принято за «нарушений нет»", deferEverything)
	}
	for _, f := range findings {
		t.Error(f)
	}
}

// ── инъекция Т12: гейт обязан краснеть и молчать по делу ──────────────────────

func TestIAMCT112_InjectionFixtureGateRedOnAnOrdinaryProbe(t *testing.T) {
	src := "package pg_test\n\nfunc TestSomethingOrdinary(t *testing.T) {\n" +
		"\t_, _ = tx.Exec(ctx, \"SET CONSTRAINTS ALL DEFERRED\")\n}\n"
	_, occ, findings, err := auditFixtureStrictness("zz.go", src)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if occ != 1 || len(findings) != 1 {
		t.Fatalf("обычная проба, отменяющая немедленность, обязана быть находкой; "+
			"вхождений %d, находок %v", occ, findings)
	}
	if !strings.Contains(findings[0], "TestSomethingOrdinary") {
		t.Fatalf("находка обязана называть функцию: %q", findings[0])
	}
}

func TestIAMCT112_InjectionFixtureGateSilentOnTheCostProbe(t *testing.T) {
	src := "package pg_test\n\nfunc TestSomethingInjectionMeasuresTheCost(t *testing.T) {\n" +
		"\t_, _ = tx.Exec(ctx, \"SET CONSTRAINTS ALL DEFERRED\")\n}\n"
	_, occ, findings, err := auditFixtureStrictness("zz.go", src)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if occ != 1 {
		t.Fatalf("вхождение обязано быть прочитано, иначе молчание ничего не значит: %d", occ)
	}
	if len(findings) != 0 {
		t.Fatalf("проба, ИЗМЕРЯЮЩАЯ цену оператора, законна и обязана молчать: %v", findings)
	}
}

func TestIAMCT112_InjectionFixtureGateSilentOnItsOwnExplanation(t *testing.T) {
	src := "package pg_test\n\n// Оператор SET CONSTRAINTS ALL DEFERRED накрывает и\n" +
		"// INITIALLY IMMEDIATE — потому его здесь и нет.\nfunc TestSomethingOrdinary(t *testing.T) {\n" +
		"\t_, _ = tx.Exec(ctx, \"SELECT 1\")\n}\n"
	_, occ, findings, err := auditFixtureStrictness("zz.go", src)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if occ != 0 || len(findings) != 0 {
		t.Fatalf("КОММЕНТАРИЙ об операторе оператором не является: гейт по подстроке "+
			"краснел бы на собственном объяснении; вхождений %d, находок %v", occ, findings)
	}
}

// TestIAMCT108_CatalogDictionaryColumnsRejectTheThirdSpelling — Т8.
func TestIAMCT108_CatalogDictionaryColumnsRejectTheThirdSpelling(t *testing.T) {
	root := catalogRepoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, catalogMigrationRel)) // #nosec G304
	if err != nil {
		t.Fatalf("прочитать миграцию каталога: %v", err)
	}
	exec := stripSQLComments(string(body))

	// Колонки, называющие ИМЯ сегмента, — каждая обязана нести свою проверку.
	// Перечень выписан, а не выведен: он и есть утверждение о том, какие колонки
	// словарём являются. Колонка, добавленная без записи здесь, останется вне
	// наблюдения — и это названо, а не умолчано.
	want := []string{
		"catalog_module_undotted",
		"catalog_resource_module_undotted",
		"catalog_resource_resource_undotted",
		"catalog_verb_undotted",
		"role_rule_ref_module_undotted",
		"role_rule_ref_resource_undotted",
		"role_rule_ref_verb_undotted",
	}
	var missing []string
	for _, name := range want {
		if !strings.Contains(exec, "CONSTRAINT "+name+" CHECK") {
			missing = append(missing, name)
		}
	}
	t.Logf("осмотрено колонок словаря каталога: %d; проверок «точки не содержит» найдено: %d",
		len(want), len(want)-len(missing))
	if len(missing) > 0 {
		t.Errorf("колонки словаря каталога без проверки «точки не содержит»: %v.\n"+
			"У колонок словаря МОДЕЛИ таких проверок пять (0091, 0098); третье написание "+
			"того же имени — прямой путь к классу 513001, где соединение не совпадало "+
			"НИКОГДА и молча", missing)
	}
	// Обратная сторона: сама формулировка проверки. Точку отвергает `NOT LIKE
	// '%.%'`; проверка с другим предикатом под тем же именем прошла бы перечень
	// выше и не отвергала бы ничего.
	if n := countUndottedPredicate(exec); n < len(want) {
		t.Errorf("предикат «точки не содержит» встречается %d раз при %d объявленных проверках — "+
			"проверка под нужным именем, но с другим предикатом не отвергает ничего.\n"+
			"Формы предиката ДВЕ (см. countUndottedPredicate); недобор одной из них "+
			"выглядит как исчезновение проверки", n, len(want))
	}
}

// reUndottedPredicate — предикат «точки не содержит», в ОБЕИХ формах записи.
//
// Рука пишет `NOT LIKE '%.%'`. `pg_dump` печатает то же самое ВНУТРЕННИМ
// оператором — `!~~ '%.%'::text`: `NOT LIKE` и `!~~` суть один оператор, и вывод
// дампа нормализован до второй формы. Распознаватель, знающий только первую, на
// своде считает НОЛЬ при семи ЖИВЫХ проверках — то есть объявляет исчезнувшим
// то, что стоит на месте.
//
// `!~~*` (регистронезависимая форма) сюда НЕ попадает намеренно: после `!~~`
// требуется пробел, а не звёздочка. Точка в образце экранирована — иначе
// предикат совпал бы с любым однобуквенным шаблоном.
var reUndottedPredicate = regexp.MustCompile(`NOT\s+LIKE\s+'%\.%'|!~~\s+'%\.%'`)

// countUndottedPredicate — сколько раз предикат «точки не содержит» встречается
// в ИСПОЛНЯЕМОЙ части (комментарии сняты вызывающим).
func countUndottedPredicate(exec string) int {
	return len(reUndottedPredicate.FindAllString(exec, -1))
}

// ── инъекция Т8: распознаватель предиката знает ОБЕ формы ─────────────────────
//
// Форм записи «точки не содержит» две, и по каждой прогон в обе стороны. Форма,
// о которой распознаватель не знает, не даёт ни красного, ни зелёного — она
// молчит: свод, записанный дампом, обнулил счёт при семи ЖИВЫХ проверках, и
// гейт объявил исчезнувшим то, что стоит на месте.

func TestIAMCT108_InjectionPredicateCounterKnowsBothForms(t *testing.T) {
	handwritten := "CONSTRAINT c_undotted CHECK (module NOT LIKE '%.%')"
	dumped := "CONSTRAINT c_undotted CHECK ((module !~~ '%.%'::text))"

	if n := countUndottedPredicate(handwritten); n != 1 {
		t.Errorf("рукописная форма `NOT LIKE '%%.%%'` обязана считаться: получено %d", n)
	}
	if n := countUndottedPredicate(dumped); n != 1 {
		t.Errorf("форма дампа `!~~ '%%.%%'::text` обязана считаться: получено %d.\n"+
			"Это тот же оператор — дамп нормализует NOT LIKE до внутреннего имени; "+
			"распознаватель, знающий одну форму, объявляет живую проверку исчезнувшей", n)
	}
	if n := countUndottedPredicate(handwritten + "\n" + dumped); n != 2 {
		t.Errorf("обе формы вместе обязаны дать 2: получено %d", n)
	}
}

// TestIAMCT108_InjectionPredicateCounterRejectsLookalikes — ЗАКОННЫЕ БЛИЗНЕЦЫ,
// которые считаться НЕ должны.
//
// Без этой стороны распознаватель ловил бы форму, а не существо: он объявил бы
// найденным предикат там, где стоит другой оператор или другой шаблон, — и
// перечень имён выше проходил бы при проверках, ничего не отвергающих.
func TestIAMCT108_InjectionPredicateCounterRejectsLookalikes(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{"регистронезависимая форма", "CHECK ((module !~~* '%.%'::text))"},
		{"другой шаблон", "CHECK ((module !~~ '%_%'::text))"},
		{"положительная форма", "CHECK ((module ~~ '%.%'::text))"},
		{"LIKE без отрицания", "CHECK (module LIKE '%.%')"},
	} {
		if n := countUndottedPredicate(c.src); n != 0 {
			t.Errorf("%s не является предикатом «точки не содержит», а сосчитана %d раз: %s",
				c.name, n, c.src)
		}
	}
}
