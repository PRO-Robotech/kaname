// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// seed_identity_census_injection_test.go — доказательство, что сверка чисел §0
// СПОСОБНА упасть и СПОСОБНА смолчать.
//
// Инъекция меняет РОВНО ОДИН факт против положительного близнеца: иначе
// неизвестно, который из двух дал красное, и вердикт недействителен, оставаясь
// на вид обычным зелёным.
//
// Последняя проба — не синтетика: она берёт вывод НАСТОЯЩЕГО предиката и
// настоящий текст приёмки, портит в объявлении одну цифру и требует находки
// именно по тому ведру. Без неё доказано было бы, что разбор различает
// подставленные строки, но не то, что он различает НАШИ.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/treeroot"
)

// seedCensusSyntheticOutput — вывод предиката в его дословной форме.
const seedCensusSyntheticOutput = "ревизия: рабочее дерево\n" +
	"осмотрено: в индексе 2848 · прочитано 2848 · двоичных 0\n" +
	"\n" +
	"ПРЕДМЕТ: живой          130 ·  56 ф.\n" +
	"ПРЕДМЕТ: свод и миграции   28 ·   6 ф.\n" +
	"ПРЕДМЕТ: манифесты        0 ·   0 ф.\n" +
	"остаётся: ns             13 ·   2 ф.\n" +
	"\n"

// seedCensusOutputWithFrozen — тот же вывод, но замёрзшее ведро принимает
// поданное значение. Инъекция меняет РОВНО ЕГО.
func seedCensusOutputWithFrozen(frozen string) string {
	return strings.Replace(seedCensusSyntheticOutput,
		"ПРЕДМЕТ: свод и миграции   28 ·   6 ф.\n", frozen, 1)
}

// seedCensusSyntheticDoc собирает приёмку-синтетику: шапка с ревизией и один
// объявляющий блок в двух столбцах, как в настоящей.
func seedCensusSyntheticDoc(rev, subject string) string {
	return "# Приёмка-синтетика\n\n" +
		"- **Ревизия измерения: `" + rev + "`** (пояснение)\n\n" +
		"> ```\n" +
		">                        7cd4cc8355 (монорепо)    " + rev + " (это дерево)\n" +
		"> ПРЕДМЕТ: живой          159 · 63 ф.              " + subject + "\n" +
		"> ПРЕДМЕТ: свод и миграции 12 ·  4 ф.               28 ·  6 ф.\n" +
		"> ПРЕДМЕТ: манифесты      25 ·  5 ф.                0 ·  0 ф.\n" +
		"> остаётся: ns            39 · 15 ф.               13 ·  2 ф.\n" +
		"> ```\n"
}

func seedCensusParseSynthetic(t *testing.T) check.SeedCensusReport {
	t.Helper()
	rep, err := check.ParseSeedCensusOutput(seedCensusSyntheticOutput)
	if err != nil {
		t.Fatalf("синтетический вывод предиката не разобран: %v", err)
	}
	return rep
}

// TestSeedCensusInjection_LegitimateTwinIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ.
// Объявление совпадает с выводом — находок ноль. Без этой пробы красное
// соседних означало бы «гейт краснеет всегда».
func TestSeedCensusInjection_LegitimateTwinIsSilent(t *testing.T) {
	t.Parallel()
	rep := seedCensusParseSynthetic(t)
	decl := check.ParseSeedCensusDeclaration(seedCensusSyntheticDoc("abc1234", "130 · 56 ф."), rep.Order)
	if decl.BlockLines == 0 {
		t.Fatalf("объявляющий блок не найден — предпосылка пробы не выполнена")
	}
	if f := check.AdjudicateSeedCensus(decl, rep); len(f) != 0 {
		t.Fatalf("законный близнец обязан молчать, получено: %v", f)
	}
}

// TestSeedCensusInjection_OneDigitApart — ОДИН ФАКТ: в объявлении другое число
// файлов при том же числе вхождений. Ровно та форма, в которой расхождение уже
// наступало и не было замечено.
func TestSeedCensusInjection_OneDigitApart(t *testing.T) {
	t.Parallel()
	rep := seedCensusParseSynthetic(t)
	decl := check.ParseSeedCensusDeclaration(seedCensusSyntheticDoc("abc1234", "130 · 54 ф."), rep.Order)
	f := check.AdjudicateSeedCensus(decl, rep)
	if len(f) != 1 {
		t.Fatalf("ожидалась одна находка, получено %d: %v", len(f), f)
	}
	if !strings.Contains(f[0], "ПРЕДМЕТ") || !strings.Contains(f[0], "130 · 54 ф.") ||
		!strings.Contains(f[0], "130 · 56 ф.") {
		t.Fatalf("находка обязана назвать ведро и ОБЕ величины, получено: %q", f[0])
	}
}

// TestSeedCensusInjection_BucketPrintedButNotDeclared — ведро, которое предикат
// печатает, а объявление не называет. Иначе новое ведро уехало бы из-под
// наблюдения молча.
func TestSeedCensusInjection_BucketPrintedButNotDeclared(t *testing.T) {
	t.Parallel()
	rep := seedCensusParseSynthetic(t)
	doc := strings.ReplaceAll(seedCensusSyntheticDoc("abc1234", "130 · 56 ф."),
		"> остаётся: ns            39 · 15 ф.               13 ·  2 ф.\n", "")
	decl := check.ParseSeedCensusDeclaration(doc, rep.Order)
	f := check.AdjudicateSeedCensus(decl, rep)
	if len(f) != 1 || !strings.Contains(f[0], "остаётся: ns") {
		t.Fatalf("ожидалась одна находка про непоименованное ведро, получено %d: %v", len(f), f)
	}
}

// TestSeedCensusInjection_BlockIsFoundByRevisionNotByOrder — НЕСУЩАЯ проба.
// В документе два блока тех же вёдер: чужого дерева и своего. Разбор «первый
// попавшийся» сверял бы величины монорепо и был бы зелёным до первой правки
// здешних чисел.
func TestSeedCensusInjection_BlockIsFoundByRevisionNotByOrder(t *testing.T) {
	t.Parallel()
	rep := seedCensusParseSynthetic(t)
	foreign := "```\n" +
		"                       7cd4cc8355\n" +
		"ПРЕДМЕТ: живой         159 · 63 ф.\n" +
		"ПРЕДМЕТ: свод и миграции 12 ·  4 ф.\n" +
		"ПРЕДМЕТ: манифесты      25 ·  5 ф.\n" +
		"остаётся: ns            39 · 15 ф.\n" +
		"```\n\n"
	doc := "# Приёмка-синтетика\n\n" +
		"- **Ревизия измерения: `abc1234`** (пояснение)\n\n" +
		foreign +
		strings.SplitN(seedCensusSyntheticDoc("abc1234", "130 · 56 ф."), "\n\n", 3)[2]
	decl := check.ParseSeedCensusDeclaration(doc, rep.Order)
	if got, ok := decl.Buckets["ПРЕДМЕТ: живой"]; !ok || got.Hits != 130 || got.Files != 56 {
		t.Fatalf("взят блок ЧУЖОГО дерева: по ведру «ПРЕДМЕТ: живой» получено %v (ok=%v), "+
			"ожидалось 130 · 56 ф.", got, ok)
	}
	if f := check.AdjudicateSeedCensus(decl, rep); len(f) != 0 {
		t.Fatalf("блок своего дерева совпадает с выводом — находок быть не должно: %v", f)
	}
}

// TestSeedCensusInjection_RefusalIsNotZeroFindings — «не выполнилось» отличимо
// от «ноль находок» ПО КАЖДОЙ оси: пустой обход и вывод без вёдер.
func TestSeedCensusInjection_RefusalIsNotZeroFindings(t *testing.T) {
	t.Parallel()
	for name, out := range map[string]string{
		"обход пуст": "ревизия: рабочее дерево\n" +
			"осмотрено: в индексе 0 · прочитано 0 · двоичных 0\n\nПРЕДМЕТ  0 ·  0 ф.\n",
		"ни одного ведра": "ревизия: рабочее дерево\n" +
			"осмотрено: в индексе 2848 · прочитано 2848 · двоичных 0\n",
	} {
		if _, err := check.ParseSeedCensusOutput(out); err == nil {
			t.Fatalf("%s: разбор обязан ОТКАЗАТЬ, а не вернуть пустой отчёт", name)
		}
	}
	// Законный близнец той же оси: полный вывод разбирается без отказа.
	if _, err := check.ParseSeedCensusOutput(seedCensusSyntheticOutput); err != nil {
		t.Fatalf("годный вывод обязан разбираться, получено: %v", err)
	}
}

// TestSeedCensusInjection_UnnamedRevisionIsNotAVerdict — приёмка без строки
// ревизии не даёт объявления вовсе: числа не привязаны ни к чему.
func TestSeedCensusInjection_UnnamedRevisionIsNotAVerdict(t *testing.T) {
	t.Parallel()
	rep := seedCensusParseSynthetic(t)
	doc := strings.ReplaceAll(seedCensusSyntheticDoc("abc1234", "130 · 56 ф."),
		"Ревизия измерения", "Замер сделан")
	decl := check.ParseSeedCensusDeclaration(doc, rep.Order)
	if decl.Revision != "" || decl.BlockLines != 0 {
		t.Fatalf("без строки ревизии объявления быть не может, получено rev=%q строк=%d",
			decl.Revision, decl.BlockLines)
	}
}

// TestSeedCensusInjection_RealDocumentOneDigitApart — инъекция НАСТОЯЩИМ входом.
//
// Берётся вывод настоящего предиката и настоящий текст приёмки; в объявлении
// портится ОДНА цифра. Красное обязано прийти по тому ведру, которое испорчено,
// и ни по какому другому — иначе доказано лишь то, что разбор различает
// подставленные строки.
func TestSeedCensusInjection_RealDocumentOneDigitApart(t *testing.T) {
	root, err := treeroot.ModuleRootFrom(".")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не назван: %v", err)
	}
	// Координата константна, от корня модуля.
	raw, err := os.ReadFile(filepath.Join(root, seedCensusDoc))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: приёмка не прочитана: %v", err)
	}
	rep := runSeedCensusPredicate(t, root)

	clean := check.ParseSeedCensusDeclaration(string(raw), rep.Order)
	if len(check.AdjudicateSeedCensus(clean, rep)) != 0 {
		t.Fatalf("предпосылка инъекции не выполнена: дерево уже расходится с §0 — " +
			"инъекция не докажет ничего, пока настоящий вход не сойдётся")
	}

	subject, ok := clean.Buckets["ПРЕДМЕТ"]
	if !ok {
		t.Fatalf("предпосылка инъекции не выполнена: ведро ПРЕДМЕТ не объявлено")
	}
	at, known := clean.LineOf["ПРЕДМЕТ"]
	if !known {
		t.Fatalf("предпосылка инъекции не выполнена: разбор не назвал строку объявления")
	}

	// Портится ИМЕННО объявляющая строка, найденная разбором, а не первое
	// вхождение величины в файле. Разница не стилистическая: та же величина
	// упоминается прозой выше по документу, и порча «первого вхождения»
	// красила бы текст, которого гейт не судит, — инъекция проходила бы,
	// ничего не доказав. Так и случилось при первой редакции этой пробы.
	was := subject.String()
	now := check.SeedCensusCell{Hits: subject.Hits, Files: subject.Files + 1}.String()
	lines := strings.Split(string(raw), "\n")
	if at >= len(lines) || !strings.Contains(lines[at], was) {
		t.Fatalf("предпосылка инъекции не выполнена: в строке %d нет величины %q", at, was)
	}
	lines[at] = strings.Replace(lines[at], was, now, 1)
	spoiled := strings.Join(lines, "\n")

	f := check.AdjudicateSeedCensus(check.ParseSeedCensusDeclaration(spoiled, rep.Order), rep)
	if len(f) != 1 || !strings.Contains(f[0], "ПРЕДМЕТ") {
		t.Fatalf("одна испорченная цифра обязана дать РОВНО одну находку по ведру "+
			"ПРЕДМЕТ, получено %d: %v", len(f), f)
	}
}

// TestSeedCensusInjection_EmptyFrozenBucketIsAFinding — АНТИМАСКА: замёрзшее
// ведро, давшее ноль, есть находка, а не достигнутая цель.
//
// Ноль в нём недостижим by construction: свод посеял написание и правке не
// подлежит (ban #5). Значит ноль там означает ослепший обход — и без этой
// проверки он выглядел бы как «переход завершён вообще везде».
func TestSeedCensusInjection_EmptyFrozenBucketIsAFinding(t *testing.T) {
	rep, err := check.ParseSeedCensusOutput(
		seedCensusOutputWithFrozen("ПРЕДМЕТ: свод и миграции    0 ·   0 ф.\n"))
	if err != nil {
		t.Fatalf("синтетический вывод не разобран: %v", err)
	}
	decl := check.ParseSeedCensusDeclaration(
		seedCensusSyntheticDoc("abc1234", "130 · 56 ф."), rep.Order)

	findings := check.AdjudicateSeedCensus(decl, rep)
	if !seedCensusMentions(findings, check.SeedCensusFrozenBucket) {
		t.Fatalf("пустое замёрзшее ведро не названо находкой: %v", findings)
	}
}

// TestSeedCensusInjection_MissingFrozenBucketIsAFinding — второй способ ослепнуть:
// ведро вовсе перестало печататься.
//
// Отличается от предыдущего РОВНО одним фактом — строки нет, а не ноль в ней, —
// и без отдельного случая переименование ведра у предиката отключило бы
// антимаску молча.
func TestSeedCensusInjection_MissingFrozenBucketIsAFinding(t *testing.T) {
	rep, err := check.ParseSeedCensusOutput(seedCensusOutputWithFrozen(""))
	if err != nil {
		t.Fatalf("синтетический вывод не разобран: %v", err)
	}
	decl := check.ParseSeedCensusDeclaration(
		seedCensusSyntheticDoc("abc1234", "130 · 56 ф."), rep.Order)

	findings := check.AdjudicateSeedCensus(decl, rep)
	if !seedCensusMentions(findings, check.SeedCensusFrozenBucket) {
		t.Fatalf("отсутствие замёрзшего ведра не названо находкой: %v", findings)
	}
}

// TestSeedCensusInjection_ZeroLiveBucketIsNotAFinding — ЗАКОННЫЙ БЛИЗНЕЦ к
// антимаске: ноль в ЖИВОМ ведре при непустом замёрзшем — это достигнутая цель
// (§7-П2), и краснеть на ней нельзя.
//
// Без этой пробы антимаска могла бы оказаться запретом на успех: проверка,
// краснеющая на идеале, толкает держать остаток ради зелёного.
func TestSeedCensusInjection_ZeroLiveBucketIsNotAFinding(t *testing.T) {
	out := strings.Replace(seedCensusSyntheticOutput,
		"ПРЕДМЕТ: живой          130 ·  56 ф.\n",
		"ПРЕДМЕТ: живой            0 ·   0 ф.\n", 1)
	rep, err := check.ParseSeedCensusOutput(out)
	if err != nil {
		t.Fatalf("синтетический вывод не разобран: %v", err)
	}
	decl := check.ParseSeedCensusDeclaration(
		seedCensusSyntheticDoc("abc1234", "0 ·  0 ф."), rep.Order)

	if findings := check.AdjudicateSeedCensus(decl, rep); len(findings) != 0 {
		t.Fatalf("достигнутая цель объявлена находкой — проверка запрещает успех: %v", findings)
	}
}

// seedCensusMentions — находка, называющая предмет. Поиск по существу, а не по
// точной фразе: текст отказа — диагностика, и привязка к нему сделала бы
// инъекцию хрупкой по чужой причине.
func seedCensusMentions(findings []string, what string) bool {
	for _, f := range findings {
		if strings.Contains(f, what) {
			return true
		}
	}
	return false
}
