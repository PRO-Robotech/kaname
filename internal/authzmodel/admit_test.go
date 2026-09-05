// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmodel

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/authzplan"
)

// admit_test.go — пробы допуска собранной модели (предмет A приёмки
// services/iam/docs/engineering/acceptance/composed-model-admits-only-what-it-owns.md,
// сценарии ADM-A-01…ADM-A-27).
//
// # Законный близнец берётся ИЗ КАНОНА, а не сочиняется
//
// Отрицание, у которого нет положительного близнеца, зеленеет на всём сломанном
// (`testing.md` §«Гейт на класс», п. 2б). Близнец здесь — блок `storage_volume`
// канона, вынутый ПРОГРАММНО и переименованный: сочинённый близнец доказывал бы,
// что молчит допуск на тексте, которого платформа не пишет.

// canonBlockOf вынимает тело блока `type <name>` канона — от строки `type` до
// первой пустой строки (единица A, как у modelrender.SplitCanon: комментарии
// канона стоят МЕЖДУ блоками, и единица «до следующего type» приписала бы блоку
// чужой баннер).
func canonBlockOf(t *testing.T, name string) string {
	t.Helper()
	lines := strings.Split(DSL, "\n")
	start := -1
	for i, l := range lines {
		if l == "type "+name {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("блок %q в каноне не найден — близнец обязан браться из канона, а не сочиняться", name)
	}
	end := start
	for end < len(lines) && strings.TrimSpace(lines[end]) != "" {
		end++
	}
	return strings.Join(lines[start:end], "\n") + "\n"
}

// twin — законный близнец: блок `storage_volume` под именем `acme_widget`.
func twin(t *testing.T) string {
	t.Helper()
	return strings.Replace(canonBlockOf(t, "storage_volume"), "type storage_volume", "type acme_widget", 1)
}

// compose складывает собранный текст ровно так, как этого требует §11 приёмки от
// полосы композиции: канон ДОСЛОВНО, перевод строки, блоки.
func compose(blocks ...string) string {
	return DSL + "\n" + strings.Join(blocks, "\n")
}

// swapDecl заменяет одно объявление близнеца на другое.
func swapDecl(block, from, to string) string {
	out := strings.Replace(block, from, to, 1)
	if out == block {
		panic("swapDecl: подстрока не найдена — проба утверждала бы о входе, которого не построила: " + from)
	}
	return out
}

func rules(rep AdmissionReport) []string {
	out := make([]string, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		out = append(out, string(f.Rule))
	}
	sort.Strings(out)
	return out
}

func findingsOf(rep AdmissionReport, rule Rule) []Finding {
	var out []Finding
	for _, f := range rep.Findings {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

func mustAdmit(t *testing.T, composed string) AdmissionReport {
	t.Helper()
	rep, err := Admit(composed)
	if err != nil {
		t.Fatalf("допуск вернул ошибку, а ожидался отчёт: %v", err)
	}
	return rep
}

// ── ADM-A-01 · счастливый путь ────────────────────────────────────────────────

func TestAdmitLegalTwinFromCanonIsAdmitted(t *testing.T) {
	rep := mustAdmit(t, compose(twin(t)))
	if !rep.Admitted() {
		t.Fatalf("законный близнец из канона обязан быть допущен; находки: %v; перепись: %s", rep.Findings, rep.Census())
	}
	if rep.TypesSeen != 33 || rep.TypesNew != 1 {
		t.Fatalf("перепись: типов осмотрено %d (ждали 33), новых %d (ждали 1)", rep.TypesSeen, rep.TypesNew)
	}
	if !strings.Contains(rep.Census(), "типов осмотрено 33, новых 1, находок 0") {
		t.Fatalf("перепись обязана печататься в форме нормы §5 п. 3, получено: %s", rep.Census())
	}
}

// ── ADM-A-02 · Д1: имя, которое канон уже несёт ───────────────────────────────

func TestAdmitTypeNameAlreadyCarriedByCanon(t *testing.T) {
	block := strings.Replace(twin(t), "type acme_widget", "type storage_volume", 1)
	rep := mustAdmit(t, compose(block))
	got := findingsOf(rep, RuleD1)
	if len(got) != 1 {
		t.Fatalf("ждали ровно одну находку Д1, получено %v (все находки: %v)", len(got), rules(rep))
	}
	if got[0].Type != "storage_volume" {
		t.Fatalf("находка обязана называть имя типа, получено %q", got[0].Type)
	}
	if !strings.Contains(got[0].Text, "2") {
		t.Fatalf("находка обязана называть ЧИСЛО вхождений, получено %q", got[0].Text)
	}
	// Переопределение канонического имени новым типом НЕ считается новым типом:
	// формулировка через множество здесь молчит (различных имён по-прежнему 32).
	if rep.TypesNew != 0 {
		t.Fatalf("новых типов обязано быть 0, получено %d", rep.TypesNew)
	}
	if rep.Admitted() {
		t.Fatal("допуск обязан отказать")
	}
	// Перепись НЕ вправе говорить «судить нечего» рядом с находкой: предикат
	// третьего исхода остаётся один (TypesNew == 0) и живёт полем, но фраза
	// читается оператором как «всё в порядке» — а исход здесь ОТКАЗ.
	if strings.Contains(rep.Census(), "судить нечего") {
		t.Fatalf("перепись с находкой не вправе объявлять третий исход, получено: %s", rep.Census())
	}
	if !strings.Contains(rep.Census(), "находок 1") {
		t.Fatalf("перепись обязана называть число находок, получено: %s", rep.Census())
	}
}

// ── ADM-A-03 · Д1: два доставленных блока под одним именем ────────────────────

func TestAdmitTwoDeliveredBlocksShareAName(t *testing.T) {
	rep := mustAdmit(t, compose(twin(t), twin(t)))
	got := findingsOf(rep, RuleD1)
	if len(got) != 1 || got[0].Type != "acme_widget" {
		t.Fatalf("ждали одну находку Д1 про acme_widget, получено %d: %v", len(got), got)
	}
	if !strings.Contains(got[0].Text, "2") {
		t.Fatalf("находка обязана называть число вхождений, получено %q", got[0].Text)
	}
}

// ── ADM-A-04 · Д7(а): канон усечён ────────────────────────────────────────────

func TestAdmitCanonTruncated(t *testing.T) {
	cut := strings.Replace(DSL, canonBlockOf(t, "vpc_subnet"), "", 1)
	if cut == DSL {
		t.Fatal("вход не построен: блок vpc_subnet не изъят")
	}
	rep := mustAdmit(t, cut+"\n"+twin(t))
	if !rep.TerminatedAtD7 {
		t.Fatal("правила после Д7 обязаны не исполняться, и отчёт обязан это говорить")
	}
	got := findingsOf(rep, RuleD7Prefix)
	if len(got) != 1 {
		t.Fatalf("ждали находку Д7(а), получено %v", rules(rep))
	}
	if !strings.Contains(got[0].Text, "не найден дословно") {
		t.Fatalf("находка обязана называть СТОРОНУ, получено %q", got[0].Text)
	}
	if !strings.Contains(got[0].Text, "байт") {
		t.Fatalf("находка обязана называть смещение первого расхождения, получено %q", got[0].Text)
	}
	if !strings.Contains(rep.Census(), "правила после Д7 не исполнялись") {
		t.Fatalf("перепись обязана говорить об остановке, получено: %s", rep.Census())
	}
}

// ── ADM-A-05 · Д7(а): блок канона изменён ─────────────────────────────────────
//
// Второе «И» круга 3 («находки Д3 нет») здесь НЕ утверждается: Д7 терминальна,
// до Д3 этот вход не доходит, и проба на такое «И» зелена при любом устройстве
// Д3 (§17.3 ревизии круга 4). Свойство «подстановка канона не судится» покрыто
// ADM-A-08 — на входе, который Д7 проходит.
func TestAdmitCanonBlockModified(t *testing.T) {
	changed := strings.Replace(DSL,
		"    define v_get: [user, service_account, group#member] or super_admin\n    define v_list: [user, service_account, group#member] or super_admin\n    define v_update: [user, service_account, group#member] or super_admin\n    define v_delete: [user, service_account, group#member] or super_admin\n\ntype storage_snapshot",
		"    define v_get: [user, service_account, group#member, user:*] or super_admin\n    define v_list: [user, service_account, group#member] or super_admin\n    define v_update: [user, service_account, group#member] or super_admin\n    define v_delete: [user, service_account, group#member] or super_admin\n\ntype storage_snapshot", 1)
	if changed == DSL {
		t.Fatal("вход не построен: блок storage_volume не изменён")
	}
	rep := mustAdmit(t, changed+"\n"+twin(t))
	if len(findingsOf(rep, RuleD7Prefix)) != 1 {
		t.Fatalf("ждали находку Д7(а), получено %v", rules(rep))
	}
	if !rep.TerminatedAtD7 {
		t.Fatal("правила после Д7 обязаны не исполняться")
	}
}

// ── ADM-A-06 · Д7(а): различие ТОЛЬКО в пробелах ──────────────────────────────

func TestAdmitWhitespaceOnlyDifferenceIsAFinding(t *testing.T) {
	block := canonBlockOf(t, "storage_volume")
	respaced := strings.ReplaceAll(block, " or ", "  or  ")
	if respaced == block {
		t.Fatal("вход не построен: пробелы не переставлены")
	}
	rep := mustAdmit(t, strings.Replace(DSL, block, respaced, 1)+"\n"+twin(t))
	if len(findingsOf(rep, RuleD7Prefix)) != 1 {
		t.Fatalf("иная расстановка пробелов в блоке канона обязана быть находкой Д7(а), получено %v", rules(rep))
	}
}

// ── ADM-A-07 · Д3: подстановочный субъект у нового типа ───────────────────────

func TestAdmitDirectWildcardOnNewType(t *testing.T) {
	block := swapDecl(twin(t),
		"define v_get: [user, service_account, group#member] or super_admin",
		"define v_get: [user, service_account, user:*] or super_admin")
	rep := mustAdmit(t, compose(block))
	got := findingsOf(rep, RuleD3)
	if len(got) != 1 {
		t.Fatalf("ждали находку Д3, получено %v", rules(rep))
	}
	if got[0].Type != "acme_widget" || got[0].Relation != "v_get" {
		t.Fatalf("находка обязана называть тип и отношение, получено %+v", got[0])
	}
	if !strings.Contains(got[0].Term, "user:*") {
		t.Fatalf("находка обязана называть ЗАПИСЬ субъекта, получено %q", got[0].Term)
	}
}

// ── ADM-A-08 · Д3, положительный близнец: подстановка КАНОНА не судится ───────

func TestAdmitCanonWildcardIsNotJudged(t *testing.T) {
	rep := mustAdmit(t, compose(twin(t)))
	if n := len(findingsOf(rep, RuleD3)); n != 0 {
		t.Fatalf("канон несёт подстановку в двух местах (cluster.viewer, registry_repository.v_get); "+
			"допуск, судящий Д3 по всей модели, покраснел бы на самом каноне. Находок Д3: %d", n)
	}
}

// ── ADM-A-09 · Д4, положительный близнец: новый тип ссылается на другой новый ─

func TestAdmitNewTypeMayReferenceAnotherNewType(t *testing.T) {
	widget := swapDecl(twin(t),
		"define v_get: [user, service_account, group#member] or super_admin",
		"define v_get: [user, service_account, group#member] or super_admin\n    define viewer_of_widget: [user, service_account]")
	gadget := "type acme_gadget\n  relations\n    define project: [project]\n" +
		"    define super_admin: super_admin from project\n" +
		"    define v_get: [user, acme_widget#viewer_of_widget] or super_admin\n"
	rep := mustAdmit(t, compose(widget, gadget))
	if !rep.Admitted() {
		t.Fatalf("модуль с внутренней иерархией обязан проходить (§2.6): %v; перепись: %s", rep.Findings, rep.Census())
	}
	if rep.TypesNew != 2 {
		t.Fatalf("перепись обязана говорить «новых 2», получено %d", rep.TypesNew)
	}
}

// ── ADM-A-10 · Д4(а): Userset, которого тип-носитель не объявляет ─────────────

func TestAdmitUsersetNotDeclaredByItsCarrier(t *testing.T) {
	block := swapDecl(twin(t),
		"define v_get: [user, service_account, group#member] or super_admin",
		"define v_get: [user, service_account, group#nosuchrelation] or super_admin")
	rep := mustAdmit(t, compose(block))
	got := findingsOf(rep, RuleD4Userset)
	if len(got) != 1 {
		t.Fatalf("ждали находку Д4(а), получено %v", rules(rep))
	}
	if !strings.Contains(got[0].Text, "group") || !strings.Contains(got[0].Text, "nosuchrelation") {
		t.Fatalf("находка обязана называть тип-носитель и имя отношения, получено %q", got[0].Text)
	}
}

// ── ADM-A-11 · Д4, положительный близнец: словарь и условия канона ────────────

func TestAdmitCanonVocabularyAndConditionsPass(t *testing.T) {
	block := swapDecl(twin(t),
		"define v_get: [user, service_account, group#member] or super_admin",
		"define v_get: [user with mfa_fresh, service_account, group#member] or super_admin")
	rep := mustAdmit(t, compose(block))
	if n := len(findingsOf(rep, RuleD4Userset)) + len(findingsOf(rep, RuleD4Condition)); n != 0 {
		t.Fatalf("субъекты словаря канона и объявленное каноном условие обязаны проходить, находок Д4: %d (%v)", n, rep.Findings)
	}
}

// ── ADM-A-12 · Д5′: план глагола нового типа невыразим ────────────────────────

func TestAdmitPlanOfNewTypeVerbIsInexpressible(t *testing.T) {
	block := swapDecl(twin(t),
		"define v_get: [user, service_account, group#member] or super_admin",
		"define v_get: [user, service_account] or v_get from project")
	rep := mustAdmit(t, compose(block))
	got := findingsOf(rep, RuleD5)
	if len(got) != 1 {
		t.Fatalf("ждали находку Д5′, получено %v", rules(rep))
	}
	if got[0].Type != "acme_widget" || got[0].Relation != "v_get" {
		t.Fatalf("находка обязана называть тип и глагол, получено %+v", got[0])
	}
	const unclassified = "project.v_get: глагол выводится от глагола предка (project) — форма E такого не выражает"
	if !strings.Contains(got[0].Text, unclassified) {
		t.Fatalf("находка обязана называть НЕОТНЕСЁННЫЙ терм; ждали %q, получено %q", unclassified, got[0].Text)
	}
}

// ── ADM-A-13 · Д5′, положительный близнец ─────────────────────────────────────

func TestAdmitLawfulDerivationIsExpressible(t *testing.T) {
	rep := mustAdmit(t, compose(twin(t)))
	if n := len(findingsOf(rep, RuleD5)); n != 0 {
		t.Fatalf("законная форма вывода обязана проходить, находок Д5′: %d", n)
	}
	// Тот же ответ даёт канон целиком: невыразимых пар 0 из 272.
	// Число перемерено после снятия `cluster#console` (#1820): было 273.
	m, err := authzplan.ParseModel(DSL)
	if err != nil {
		t.Fatalf("разбор канона: %v", err)
	}
	pairs, bad := 0, 0
	for _, ty := range m.Types {
		for _, r := range ty.Relations {
			pairs++
			p, err := m.Compile(ty.Name, r.Name)
			if err != nil || !p.Expressible() {
				bad++
			}
		}
	}
	if pairs != 272 || bad != 0 {
		t.Fatalf("канон: невыразимых пар %d из %d (ждали 0 из 272)", bad, pairs)
	}
}

// ── ADM-A-14 · третий исход: судить нечего ────────────────────────────────────

func TestAdmitNothingToJudgeIsNotSuccess(t *testing.T) {
	// Предикат третьего исхода ОДИН — TypesNew == 0, — и он одинаково отвечает на
	// обоих текстах, на которых два прежних признака расходились (§5 п. 1).
	for name, in := range map[string]string{
		"канон побайтово":        DSL,
		"канон + перевод строки": DSL + "\n",
	} {
		rep := mustAdmit(t, in)
		if !rep.NothingToJudge {
			t.Fatalf("%s: ждали третий исход, перепись: %s", name, rep.Census())
		}
		if rep.Admitted() {
			t.Fatalf("%s: третий исход НЕ засчитывается в успех", name)
		}
		if len(rep.Findings) != 0 {
			t.Fatalf("%s: третий исход не есть находка, получено %v", name, rep.Findings)
		}
		if !strings.Contains(rep.Census(), "новых 0") {
			t.Fatalf("%s: перепись обязана говорить «новых 0», получено %s", name, rep.Census())
		}
	}
}

// ── ADM-A-15 · непонятое до допуска НЕ ДОХОДИТ (утверждение о П-01) ───────────
//
// Отрицание здесь утверждает о ПРОИЗВОДИТЕЛЕ (`authzplan.ParseModel`), а не о
// допуске: ветвей «вывод не выходит за пределы блока» и «тип субъекта объявлен» в
// допуске НЕТ, потому что нарушающего значения `*authzplan.Model` не существует.
func TestParserRejectsWhatNeverReachesAdmission(t *testing.T) {
	base := twin(t)
	inputs := map[string]string{
		"or nosuchrelation":         swapDecl(base, "or super_admin\n    define v_list", "or nosuchrelation\n    define v_list"),
		"or admin from nosuchptr":   swapDecl(base, "or super_admin\n    define v_list", "or admin from nosuchpointer\n    define v_list"),
		"or nosuchrel from project": swapDecl(base, "or super_admin\n    define v_list", "or nosuchrel from project\n    define v_list"),
		"[user, nosuchtype]":        swapDecl(base, "define v_get: [user, service_account, group#member] or super_admin", "define v_get: [user, nosuchtype]"),
	}
	for name, block := range inputs {
		if _, err := authzplan.ParseModel(compose(block)); err == nil {
			t.Fatalf("%s: разбор обязан был отвергнуть вход — иначе у снятых ветвей допуска есть предмет", name)
		}
	}
	// Положительный контроль: те же формы с существующими именами разбираются.
	if _, err := authzplan.ParseModel(compose(base)); err != nil {
		t.Fatalf("положительный контроль: законный близнец обязан разбираться, получено %v", err)
	}
}

// ── ADM-A-16 · Д7(б): строка суффикса вне пяти форм ───────────────────────────

func TestAdmitSuffixLineOutsideTheFiveForms(t *testing.T) {
	cases := map[string]struct {
		composed string
		line     string
	}{
		"условие с телом":   {DSL + "\ncondition mfa_fresh(x: int) {\n  x > 1\n}\n" + twin(t), "condition mfa_fresh(x: int) {"},
		"мусор перед типом": {DSL + "\nмусор перед строкой type\n" + twin(t), "мусор перед строкой type"},
		"мусор в хвосте":    {DSL + "\n" + twin(t) + "\nмусор в самом хвосте\n", "мусор в самом хвосте"},
	}
	for name, c := range cases {
		rep := mustAdmit(t, c.composed)
		got := findingsOf(rep, RuleD7Suffix)
		if len(got) == 0 {
			t.Fatalf("%s: ждали находку Д7(б), получено %v", name, rules(rep))
		}
		var named bool
		for _, f := range got {
			if strings.Contains(f.Text, c.line) && regexp.MustCompile(`строка \d+`).MatchString(f.Text) {
				named = true
			}
		}
		if !named {
			t.Fatalf("%s: находка обязана называть НОМЕР строки и САМУ строку %q, получено %v", name, c.line, got)
		}
		if !rep.TerminatedAtD7 {
			t.Fatalf("%s: правила после Д7 обязаны не исполняться", name)
		}
	}
}

// ── ADM-A-17 · Д7(б), положительный близнец ───────────────────────────────────

func TestAdmitLawfulSuffixShapeIsSilent(t *testing.T) {
	withComment := strings.Replace(twin(t), "  relations\n", "  relations\n    # внутриблочный комментарий, какие даёт рендер\n", 1)
	rep := mustAdmit(t, compose(withComment, twin2(t)))
	if n := len(findingsOf(rep, RuleD7Suffix)); n != 0 {
		t.Fatalf("суффикс законной композиции (пустые строки между блоками + внутриблочные комментарии) "+
			"обязан молчать; белый список без ПУСТОЙ строки покраснел бы на первой же композиции. Находок Д7(б): %d (%v)", n, rep.Findings)
	}
}

// twin2 — второй законный блок, чтобы у суффикса была пустая строка МЕЖДУ блоками.
func twin2(t *testing.T) string {
	t.Helper()
	return strings.Replace(canonBlockOf(t, "storage_snapshot"), "type storage_snapshot", "type acme_gadget", 1)
}

// ── ADM-A-18 · Д7(б): имя типа вне формы идентификатора ───────────────────────

func TestAdmitTypeNameOutsideIdentifierForm(t *testing.T) {
	block := strings.Replace(twin(t), "type acme_widget", "type acme widget", 1)
	rep := mustAdmit(t, compose(block))
	got := findingsOf(rep, RuleD7Suffix)
	if len(got) != 1 {
		t.Fatalf("ждали находку Д7(б), получено %v", rules(rep))
	}
	if !strings.Contains(got[0].Text, "acme widget") {
		t.Fatalf("находка обязана называть ПРЕДЪЯВЛЕННОЕ имя, получено %q", got[0].Text)
	}
	// Положительный близнец: все 32 имени типов канона форме удовлетворяют.
	re := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	m, err := authzplan.ParseModel(DSL)
	if err != nil {
		t.Fatalf("разбор канона: %v", err)
	}
	bad := 0
	for _, ty := range m.Types {
		if !re.MatchString(ty.Name) {
			bad++
		}
	}
	if len(m.Types) != 32 || bad != 0 {
		t.Fatalf("канон: имён вне формы %d из %d (ждали 0 из 32)", bad, len(m.Types))
	}
}

// ── ADM-A-19 · Д1: одно отношение объявлено в типе дважды ─────────────────────

func TestAdmitRelationDeclaredTwiceInOneType(t *testing.T) {
	// Дубль намеренно БЕЗ подстановки: образец §2.3 приёмки несёт `[user, user:*]`
	// и потому поднял бы ЕЩЁ и Д3 — то есть диагональным входом матрицы он быть
	// не может. Здесь проверяется Д1, поэтому дубль безобиден по существу.
	block := swapDecl(twin(t),
		"define v_list: [user, service_account, group#member] or super_admin",
		"define v_list: [user, service_account, group#member] or super_admin\n    define v_list: [user, service_account] or super_admin")
	rep := mustAdmit(t, compose(block))
	got := findingsOf(rep, RuleD1)
	if len(got) != 1 {
		t.Fatalf("ждали находку Д1, получено %v", rules(rep))
	}
	if got[0].Type != "acme_widget" || got[0].Relation != "v_list" {
		t.Fatalf("находка обязана называть тип и имя отношения, получено %+v", got[0])
	}
	if !strings.Contains(got[0].Text, "2") {
		t.Fatalf("находка обязана называть число объявлений, получено %q", got[0].Text)
	}
	// Положительный близнец: в каноне 272 объявления и 0 имён, объявленных дважды
	// (было 273 — перемерено после снятия `cluster#console`, #1820).
	m, err := authzplan.ParseModel(DSL)
	if err != nil {
		t.Fatalf("разбор канона: %v", err)
	}
	decls, dups := 0, 0
	for _, ty := range m.Types {
		byName := map[string]int{}
		for _, r := range ty.Relations {
			decls++
			byName[r.Name]++
		}
		for _, n := range byName {
			if n > 1 {
				dups++
			}
		}
	}
	if decls != 272 || dups != 0 {
		t.Fatalf("канон: объявлений %d (ждали 272), дублей имени %d (ждали 0)", decls, dups)
	}
}

// ── ADM-A-20 · Д3: подстановка достигается ТРАНЗИТИВНО через Userset ──────────

func TestAdmitWildcardReachedTransitivelyViaUserset(t *testing.T) {
	block := swapDecl(twin(t),
		"define v_get: [user, service_account, group#member] or super_admin",
		"define v_get: [user, service_account, cluster#viewer] or super_admin")
	rep := mustAdmit(t, compose(block))
	got := findingsOf(rep, RuleD3)
	if len(got) != 1 {
		t.Fatalf("ждали находку Д3, получено %v", rules(rep))
	}
	if !strings.Contains(got[0].Text, "acme_widget.v_get → cluster.viewer") {
		t.Fatalf("находка обязана называть ПУТЬ достижимости, получено %q", got[0].Text)
	}
	// Производителя у этой полосы, кроме допуска, нет: план её не показывает.
	m, err := authzplan.ParseModel(compose(block))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	p, err := m.Compile("acme_widget", "v_get")
	if err != nil || !p.Expressible() {
		t.Fatalf("вход обязан приниматься и компилироваться выразимым: err=%v expressible=%v", err, p.Expressible())
	}
	for _, a := range p.Atoms {
		if a.ParentType == "cluster" && a.Relation == "viewer" {
			t.Fatal("пара cluster.viewer оказалась среди атомов — значит замыкание можно было бы взять у плана; " +
				"проба закрепляла ЛОЖНОЕ основание Д3")
		}
	}
}

// ── ADM-A-21 · Д3: подстановка достигается ТРАНЗИТИВНО через указатель ────────

func TestAdmitWildcardReachedTransitivelyViaPointer(t *testing.T) {
	block := swapDecl(twin(t), "    define project: [project]\n", "    define project: [project]\n    define cluster: [cluster]\n")
	block = swapDecl(block,
		"define v_get: [user, service_account, group#member] or super_admin",
		"define v_get: [user, service_account] or viewer from cluster")
	rep := mustAdmit(t, compose(block))
	got := findingsOf(rep, RuleD3)
	if len(got) != 1 {
		t.Fatalf("ждали находку Д3, получено %v", rules(rep))
	}
	if !strings.Contains(got[0].Text, "acme_widget.v_get → cluster.viewer") {
		t.Fatalf("находка обязана называть путь достижимости, получено %q", got[0].Text)
	}
	// Второй свидетель: у этой полосы план называет пару прямо.
	m, err := authzplan.ParseModel(compose(block))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	p, _ := m.Compile("acme_widget", "v_get")
	var witnessed bool
	for _, a := range p.Atoms {
		if a.ParentType == "cluster" && a.Relation == "viewer" &&
			a.Origin == "cluster.viewer → [user, user:*, service_account]" {
			witnessed = true
		}
	}
	if !witnessed {
		t.Fatal("второй свидетель (Plan.Atoms) обязан называть пару cluster.viewer с её источником")
	}
}

// ── ADM-A-22 · Д3, положительный близнец: законные источники вывода ───────────

func TestAdmitLawfulDerivationSourcesAreSilent(t *testing.T) {
	rep := mustAdmit(t, compose(twin(t)))
	if n := len(findingsOf(rep, RuleD3)); n != 0 {
		t.Fatalf("законные источники вывода обязаны молчать, находок Д3: %d", n)
	}
	// Близнец несущий, и его непустоту надо утверждать: атомы планов его
	// объявлений (единица П-07, названная §17.2 ревизии) называют три пары канона.
	m, err := authzplan.ParseModel(compose(twin(t)))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	reached := map[string]bool{}
	ty := m.Type("acme_widget")
	for _, r := range ty.Relations {
		p, err := m.Compile("acme_widget", r.Name)
		if err != nil {
			t.Fatalf("Compile(acme_widget,%s): %v", r.Name, err)
		}
		for _, a := range p.Atoms {
			if a.ParentType != "" {
				reached[a.ParentType+"."+a.Relation] = true
			}
		}
	}
	for _, want := range []string{"account.owner", "account.admin", "cluster.system_admin"} {
		if !reached[want] {
			t.Fatalf("близнец обязан быть непустым: атомы его объявлений не достигают %s (достигнуто %v)", want, reached)
		}
	}
}

// ── §2.1 · запретное множество канона: 2 из 272, транзитивных сверх прямых 0 ──
//
// Это ПРОИЗВОДИТЕЛЬ премиссы, которой ревизия круга 4 (§17.5) не нашла ни одного:
// «два ребра и три дают на каноне один ответ» названо там числом-ориентиром, а
// перемерить его на завтрашнем каноне было нечему. Здесь оно перемеряется на
// каждом прогоне, и ЕДИНИЦА названа: пара (тип, отношение) канона, достигаемая
// замыканием от ЛЮБОГО объявления канона.
func TestCanonWildcardSetIsTwoOfTwoHundredSeventyTwo(t *testing.T) {
	m, err := authzplan.ParseModel(DSL)
	if err != nil {
		t.Fatalf("разбор канона: %v", err)
	}
	pairs := 0
	direct := map[string]bool{}
	for _, ty := range m.Types {
		for _, r := range ty.Relations {
			pairs++
			for _, term := range r.Terms {
				for _, d := range term.Direct {
					if d.Wildcard {
						direct[ty.Name+"."+r.Name] = true
					}
				}
			}
		}
	}
	if pairs != 272 {
		t.Fatalf("пар (тип, отношение) в каноне %d, ждали 272 — числа приёмки перемеряются, а не помнятся", pairs)
	}
	if len(direct) != 2 || !direct["cluster.viewer"] || !direct["registry_repository.v_get"] {
		t.Fatalf("прямых подстановок канона %d, ждали 2 (cluster.viewer, registry_repository.v_get): %v", len(direct), direct)
	}
	for _, useComputed := range []bool{false, true} {
		reached := map[string]bool{}
		for _, ty := range m.Types {
			for _, r := range ty.Relations {
				if probeReachesWildcardFrom(t, m, ty.Name, r.Name, useComputed, reached) {
					continue
				}
			}
		}
		if len(reached) != 2 {
			t.Fatalf("замыкание канона (Computed=%v): достигаемых подстановкой пар %d, ждали 2 — "+
				"транзитивных СВЕРХ прямых обязано быть 0: %v", useComputed, len(reached), reached)
		}
	}

	// Положительный контроль: «транзитивных сверх прямых 0» обязано быть замером,
	// а не свойством самого обхода. На модели, где подстановка достижима ТОЛЬКО
	// транзитивно, тот же обход её находит.
	synthetic, err := authzplan.ParseModel(
		"model\n  schema 1.1\n\ntype user\n\ntype org\n  relations\n    define open: [user, user:*]\n\n" +
			"type widget\n  relations\n    define org: [org]\n    define v_get: [user] or open from org\n")
	if err != nil {
		t.Fatalf("синтетический контроль не построен: %v", err)
	}
	control := map[string]bool{}
	probeReachesWildcardFrom(t, synthetic, "widget", "v_get", false, control)
	if !control["org.open"] {
		t.Fatalf("обход не находит транзитивную подстановку — тогда «сверх прямых 0» на каноне "+
			"означает не замер, а слепоту обхода: %v", control)
	}
}

// ── ADM-A-23 · Д4(б): условие, которого канон не объявляет ────────────────────

// Условие внесено на отношение-НЕ-глагол НАМЕРЕННО, и это перенос, а не
// послабление (#2004).
//
// Предмет сценария — «условие, которого канон не объявляет», то есть Д4(б). На
// ГЛАГОЛЕ тот же вход меняет два факта сразу: имя условия вне канона (Д4(б)) и
// условие на прямом списке глагола, который формой E не выражается (Д5′). Пока
// проба считала находки одного правила, второе было невидимо — приёмка
// утверждала «план выразим», план стал невыразим, и не покраснело ничто.
//
// Условие на глаголе есть САМОСТОЯТЕЛЬНЫЙ предмет, и он проверяется своей пробой
// (`TestDeliveredVerbWithConditionIsRefused`), а не здесь. Тот же перенос по тому
// же доводу уже сделан в матрице независимости ниже.
func TestAdmitConditionNotDeclaredByCanon(t *testing.T) {
	block := swapDecl(twin(t),
		"define viewer: [user, service_account, group#member] or editor",
		"define viewer: [user with nosuch_condition, service_account, group#member] or editor")
	rep := mustAdmit(t, compose(block))
	got := findingsOf(rep, RuleD4Condition)
	if len(got) != 1 {
		t.Fatalf("ждали находку Д4(б), получено %v", rules(rep))
	}
	if got[0].Type != "acme_widget" || got[0].Relation != "viewer" ||
		!strings.Contains(got[0].Text, "nosuch_condition") {
		t.Fatalf("находка обязана называть тип, отношение и имя условия, получено %+v", got[0])
	}
	// ИСКЛЮЧИТЕЛЬНОСТЬ — несущее утверждение сценария, а не украшение (#2004).
	//
	// Счёт находок ОДНОГО правила говорит лишь «Д4(б) сработало». Он молчит о
	// том, что вход поднял ЕЩЁ ОДНО правило, — а вход, поднимающий два, меняет
	// два факта сразу и сценарием о своём предмете быть перестаёт. Ровно этим
	// молчанием приёмка разошлась с деревом: она утверждала «план выразим», план
	// стал невыразим, и не покраснело ничто.
	if len(rep.Findings) != 1 {
		t.Fatalf("сценарий обязан поднимать РОВНО Д4(б); поднято %v.\n"+
			"Второе правило означает, что вход изменил два факта, и утверждение о "+
			"первом больше не изолировано", rules(rep))
	}
}

// ── ADM-A-24 · Д8: два указателя нового типа в один тип-предок ────────────────

func TestAdmitTwoPointersIntoOneParentType(t *testing.T) {
	block := swapDecl(twin(t), "    define project: [project]\n",
		"    define project: [project]\n    define owner_project: [project]\n")
	block = swapDecl(block, "define super_admin: super_admin from project",
		"define super_admin: super_admin from project or super_admin from owner_project")
	composed := compose(block)

	rep := mustAdmit(t, composed)
	got := findingsOf(rep, RuleD8)
	if len(got) != 1 {
		t.Fatalf("ждали находку Д8, получено %v", rules(rep))
	}
	if got[0].Type != "acme_widget" {
		t.Fatalf("находка обязана называть тип, получено %+v", got[0])
	}
	const want = `тип "acme_widget" ведёт в "project" более чем одним указателем: owner_project, project`
	if got[0].Text != want {
		t.Fatalf("текст находки обязан производить САМ допуск, с перечнем, приведённым к порядку.\nждали: %s\nполучено: %s", want, got[0].Text)
	}

	// Текст обязан быть детерминирован при ЛЮБОМ обходе: у чужого метода берётся
	// ФАКТ отказа, а не его текст (§2.12 — 400 прогонов дают у метода ДВА текста).
	texts := map[string]int{}
	foreign := map[string]int{}
	for i := 0; i < 400; i++ {
		r, err := Admit(composed)
		if err != nil {
			t.Fatalf("прогон %d: %v", i, err)
		}
		f := findingsOf(r, RuleD8)
		if len(f) != 1 {
			t.Fatalf("прогон %d: находок Д8 %d", i, len(f))
		}
		texts[f[0].Text]++
		m, _ := authzplan.ParseModel(composed)
		foreign[fmt.Sprint(m.AssertOnePointerPerParentType())]++
	}
	if len(texts) != 1 {
		t.Fatalf("текст находки допуска обязан быть ОДИН, получено %d: %v", len(texts), texts)
	}
	if len(foreign) < 2 {
		t.Fatalf("предпосылка правила: текст чужого метода недетерминирован. "+
			"Получено различных текстов %d — премисса §2.12 перестала быть верной, и правило «не цитировать» "+
			"потеряло бы своё основание: %v", len(foreign), foreign)
	}
}

// ── Д8: задвоенное имя типа НЕ роняет процесс ─────────────────────────────────
//
// Сценария на это в приёмке нет, и правильно: она не могла знать, что у метода
// `П-08` есть вход, на котором он РАЗЫМЕНОВЫВАЕТ nil. Замер: карту указателей он
// собирал ПО ИМЕНИ типа, а отношения спрашивал у отдельного блока, — на двух
// блоках одного имени с РАЗНЫМИ именами указателей `t.Rel(rel)` давал nil и
// `PointerTargets` падал. Допуск — первый прод-вызывающий этого метода, и текст
// ему приносит доставленный манифест, поэтому паника означала бы не отказ, а
// падение службы на чужом вводе.
//
// ПРЕДПОСЫЛКА ПЕРЕВЕДЕНА (#1987). Паники больше нет: метод отвечает ОТКАЗОМ,
// потому что на задвоенном имени его утверждение не определено — какой блок
// действует, решал бы порядок сборки. Прежняя редакция требовала здесь паники и
// сама себя сняла, как и было задумано; вместо неё проба утверждает то, что
// дерево производит СЕЙЧАС, и по-прежнему держит свою предпосылку.
//
// ЗАЩИТА В ДОПУСКЕ ПЕРЕПРОВЕРЕНА, А НЕ СОХРАНЕНА ПО ИНЕРЦИИ. Клауза `!dupTypeName`
// остаётся, но её предмет ДРУГОЙ: она больше не спасает от паники, она не даёт
// приписать правилу Д8 отказ, вынесенный по иной причине. Без неё отчёт назвал бы
// Д8 сработавшим там, где метод отказал из-за неопределённости утверждения, а не
// из-за двух указателей в один тип-предок.
func TestAdmitSurvivesSplitPointerNamesAcrossDuplicateBlocks(t *testing.T) {
	blockA := "type acme_widget\n  relations\n    define project: [project]\n" +
		"    define super_admin: super_admin from project\n"
	blockB := "type acme_widget\n  relations\n    define owner_project: [project]\n" +
		"    define owner_super_admin: super_admin from owner_project\n"

	// Предпосылка пробы, названная ЧИСЛОМ: вход разбирается, имя типа задвоено, и
	// карта указателей несёт имена ОБОИХ блоков — то есть вход по-прежнему кормит
	// тот самый разрыв «карта по имени / отношение по блоку». Без этой проверки
	// проба зеленела бы на входе, который защищать уже не от чего.
	m, err := authzplan.ParseModel(compose(blockA, blockB))
	if err != nil {
		t.Fatalf("вход обязан разбираться: %v", err)
	}
	if n := len(m.Pointers["acme_widget"]); n != 2 {
		t.Fatalf("предпосылка пробы отпала: карта указателей обязана нести оба имени, получено %d", n)
	}

	// Метод обязан ОТВЕТИТЬ, а не упасть: текст ему приносит доставленный манифест.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("метод обязан отвечать отказом, а не паникой: %v", r)
			}
		}()
		if err := m.AssertOnePointerPerParentType(); err == nil {
			t.Fatal("на задвоенном имени типа утверждение не определено — ждали отказ, получено nil")
		}
	}()

	rep, err := Admit(compose(blockA, blockB))
	if err != nil {
		t.Fatalf("допуск обязан вернуть отчёт, а не ошибку: %v", err)
	}
	if len(findingsOf(rep, RuleD1)) != 1 {
		t.Fatalf("задвоенное имя типа обязано быть находкой Д1, получено %v", rules(rep))
	}
	// Отказ метода вынесен по неопределённости, а не по неоднозначности указателя,
	// — приписать его Д8 нельзя. Клауза `!dupTypeName` ровно это и не даёт сделать.
	if n := len(findingsOf(rep, RuleD8)); n != 0 {
		t.Fatalf("Д8 не вправе срабатывать на отказе, вынесенном по другой причине, получено %d", n)
	}
	if rep.Admitted() {
		t.Fatal("допуск обязан отказать")
	}
}

// ── ADM-A-25 · Д8, положительный близнец: канон ───────────────────────────────

func TestAdmitCanonPassesPointerUniqueness(t *testing.T) {
	rep := mustAdmit(t, compose(twin(t)))
	if n := len(findingsOf(rep, RuleD8)); n != 0 {
		t.Fatalf("на каноне с законным близнецом находок Д8 обязано быть 0, получено %d", n)
	}
	m, err := authzplan.ParseModel(DSL)
	if err != nil {
		t.Fatalf("разбор канона: %v", err)
	}
	if err := m.AssertOnePointerPerParentType(); err != nil {
		t.Fatalf("канон обязан проходить Д8: %v", err)
	}
}

// ── ADM-A-26 · разбор не состоялся: это ОТКАЗ, а не «ноль находок» ────────────

func TestAdmitParseFailureIsAnError(t *testing.T) {
	cases := map[string]struct{ composed, cause string }{
		"define без relations": {
			compose("type acme_widget\n    define v_get: [user, service_account]\n"),
			"`define` вне блока relations",
		},
		"пересечение": {
			compose(swapDecl(twin(t),
				"define v_get: [user, service_account, group#member] or super_admin",
				"define v_get: [user] and super_admin")),
			"использует пересечение либо вычитание",
		},
	}
	for name, c := range cases {
		rep, err := Admit(c.composed)
		if err == nil {
			t.Fatalf("%s: ждали ОШИБКУ, получен отчёт: %s", name, rep.Census())
		}
		if !strings.Contains(err.Error(), "разбор не состоялся") {
			t.Fatalf("%s: ошибка обязана называть СТАДИЮ, получено %q", name, err)
		}
		if !strings.Contains(err.Error(), c.cause) {
			t.Fatalf("%s: причиной обязан ехать текст разборщика (он детерминирован), получено %q", name, err)
		}
		if len(rep.Findings) != 0 {
			t.Fatalf("%s: отказ разбора не есть находка, получено %v", name, rep.Findings)
		}
	}
}

// ── ADM-A-27 · Д3: правило ПОСЕВА ─────────────────────────────────────────────

func TestAdmitSeedingRuleWildcardReachableOnlyViaDeadRelation(t *testing.T) {
	block := swapDecl(twin(t), "    define project: [project]\n",
		"    define project: [project]\n    define cluster: [cluster]\n    define hidden: viewer from cluster\n")
	block = swapDecl(block,
		"define v_get: [user, service_account, group#member] or super_admin",
		"define v_get: [user, service_account] or hidden")
	composed := compose(block)

	// Вход обязан ДОХОДИТЬ до Д3: разбор принимает, план выразим, соседи молчат.
	m, err := authzplan.ParseModel(composed)
	if err != nil {
		t.Fatalf("вход обязан разбираться: %v", err)
	}
	if p, err := m.Compile("acme_widget", "v_get"); err != nil || !p.Expressible() {
		t.Fatalf("план обязан быть выразим: err=%v expressible=%v", err, p.Expressible())
	}

	rep := mustAdmit(t, composed)
	if r := rules(rep); len(r) != 1 || r[0] != string(RuleD3) {
		t.Fatalf("вход правила посева обязан поднимать РОВНО Д3, получено %v", r)
	}
	got := findingsOf(rep, RuleD3)[0]
	if !strings.Contains(got.Text, "acme_widget.hidden → cluster.viewer") {
		t.Fatalf("находка обязана называть путь через МЁРТВОЕ отношение, получено %q", got.Text)
	}
}

// ── §2.9 · четыре комбинации: различает ПОСЕВ, а не ребро ─────────────────────
//
// Проба закрепляет основание правила, а не его исход: узкий посев (только
// действия) при двух рёбрах не находит НИЧЕГО на том же входе. Без неё
// реализация с узким посевом прошла бы все остальные сценарии.
func TestSeedingRuleDiscriminatesTheImplementation(t *testing.T) {
	block := swapDecl(twin(t), "    define project: [project]\n",
		"    define project: [project]\n    define cluster: [cluster]\n    define hidden: viewer from cluster\n")
	block = swapDecl(block,
		"define v_get: [user, service_account, group#member] or super_admin",
		"define v_get: [user, service_account] or hidden")
	m, err := authzplan.ParseModel(compose(block))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	want := map[string]bool{
		"посев=ВСЕ рёбра=2":      true,
		"посев=ВСЕ рёбра=3":      true,
		"посев=действия рёбра=3": true,
		"посев=действия рёбра=2": false,
	}
	for label, expect := range want {
		seedAll := strings.HasPrefix(label, "посев=ВСЕ")
		useComputed := strings.HasSuffix(label, "рёбра=3")
		got := probeReachesWildcard(t, m, "acme_widget", seedAll, useComputed)
		if got != expect {
			t.Fatalf("%s: находка=%v, ждали %v — правило посева перестало различать реализацию", label, got, expect)
		}
	}
}

// probeReachesWildcardFrom — то же независимое замыкание из ОДНОГО семени;
// достигнутые подстановочные пары складываются в переданное множество.
func probeReachesWildcardFrom(t *testing.T, m *authzplan.Model, typeName, relation string, useComputed bool, out map[string]bool) bool {
	t.Helper()
	seen := map[string]bool{}
	var visit func(tn, rn string)
	visit = func(tn, rn string) {
		key := tn + "." + rn
		if seen[key] {
			return
		}
		seen[key] = true
		cur := m.Type(tn)
		if cur == nil {
			return
		}
		r := cur.Rel(rn)
		if r == nil {
			return
		}
		for _, term := range r.Terms {
			for _, d := range term.Direct {
				if d.Wildcard {
					out[key] = true
				}
			}
			switch term.Kind {
			case authzplan.TermComputed:
				if useComputed {
					visit(tn, term.Computed)
				}
			case authzplan.TermTTU:
				if ptr := cur.Rel(term.TTUPointer); ptr != nil {
					for _, target := range m.PointerTargets(ptr) {
						visit(target, term.TTURelation)
					}
				}
			case authzplan.TermDirect:
				for _, d := range term.Direct {
					if d.Userset != "" {
						visit(d.Type, d.Userset)
					}
				}
			}
		}
	}
	visit(typeName, relation)
	return len(out) > 0
}

// probeReachesWildcard — независимое от допуска замыкание, чтобы утверждение о
// ПОСЕВЕ не опиралось на ту же реализацию, которую оно обосновывает.
func probeReachesWildcard(t *testing.T, m *authzplan.Model, newType string, seedAll, useComputed bool) bool {
	t.Helper()
	ty := m.Type(newType)
	if ty == nil {
		t.Fatalf("тип %q не разобран", newType)
	}
	seen := map[string]bool{}
	hit := false
	var visit func(tn, rn string)
	visit = func(tn, rn string) {
		key := tn + "." + rn
		if seen[key] {
			return
		}
		seen[key] = true
		cur := m.Type(tn)
		if cur == nil {
			return
		}
		r := cur.Rel(rn)
		if r == nil {
			return
		}
		for _, term := range r.Terms {
			for _, d := range term.Direct {
				if d.Wildcard {
					hit = true
				}
			}
			switch term.Kind {
			case authzplan.TermComputed:
				if useComputed {
					visit(tn, term.Computed)
				}
			case authzplan.TermTTU:
				if ptr := cur.Rel(term.TTUPointer); ptr != nil {
					for _, target := range m.PointerTargets(ptr) {
						visit(target, term.TTURelation)
					}
				}
			case authzplan.TermDirect:
				for _, d := range term.Direct {
					if d.Userset != "" {
						visit(d.Type, d.Userset)
					}
				}
			}
		}
	}
	for _, r := range ty.Relations {
		if seedAll || authzplan.IsVerb(r.Name) {
			visit(newType, r.Name)
		}
	}
	return hit
}

// ── §2.10 · матрица независимости: тринадцать входов, восемь клауз ────────────

func TestAdmitIndependenceMatrix(t *testing.T) {
	base := twin(t)
	type row struct {
		composed string
		raises   []Rule // пусто = законный близнец
	}
	rows := []struct {
		name string
		row  row
	}{
		{"законный близнец из канона", row{compose(base), nil}},
		{"блок канона переписан с иными пробелами", row{
			strings.Replace(DSL, canonBlockOf(t, "storage_volume"),
				strings.ReplaceAll(canonBlockOf(t, "storage_volume"), " or ", "  or  "), 1) + "\n" + base,
			[]Rule{RuleD7Prefix}}},
		{"посторонняя строка в суффиксе", row{DSL + "\nмусор перед строкой type\n" + base, []Rule{RuleD7Suffix}}},
		{"type acme widget", row{compose(strings.Replace(base, "type acme_widget", "type acme widget", 1)), []Rule{RuleD7Suffix}}},
		{"дубль имени типа", row{compose(base, base), []Rule{RuleD1}}},
		{"дубль имени отношения в типе", row{compose(swapDecl(base,
			"define v_list: [user, service_account, group#member] or super_admin",
			"define v_list: [user, service_account, group#member] or super_admin\n    define v_list: [user, service_account] or super_admin")), []Rule{RuleD1}}},
		{"[user, cluster#viewer]", row{compose(swapDecl(base,
			"define v_get: [user, service_account, group#member] or super_admin",
			"define v_get: [user, service_account, cluster#viewer] or super_admin")), []Rule{RuleD3}}},
		{"viewer from cluster", row{compose(swapDecl(swapDecl(base,
			"    define project: [project]\n", "    define project: [project]\n    define cluster: [cluster]\n"),
			"define v_get: [user, service_account, group#member] or super_admin",
			"define v_get: [user, service_account] or viewer from cluster")), []Rule{RuleD3}}},
		{"мёртвое отношение hidden (правило посева)", row{compose(swapDecl(swapDecl(base,
			"    define project: [project]\n",
			"    define project: [project]\n    define cluster: [cluster]\n    define hidden: viewer from cluster\n"),
			"define v_get: [user, service_account, group#member] or super_admin",
			"define v_get: [user, service_account] or hidden")), []Rule{RuleD3}}},
		{"[user, group#nosuchrelation]", row{compose(swapDecl(base,
			"define v_get: [user, service_account, group#member] or super_admin",
			"define v_get: [user, service_account, group#nosuchrelation] or super_admin")), []Rule{RuleD4Userset}}},
		// Условие внесено на отношение-НЕ-глагол намеренно: на глаголе оно меняло бы
		// ДВА факта сразу — имя условия вне канона (Д4(б)) и условие на прямом
		// списке глагола, который формой E не выражается (Д5′), — и строка матрицы
		// перестала бы утверждать независимость клауз. Условие на глаголе есть
		// самостоятельный предмет, и он проверяется своей пробой
		// (`TestDeliveredVerbWithConditionIsRefused`), а не здесь.
		{"[user with nosuch_condition]", row{compose(swapDecl(base,
			"define viewer: [user, service_account, group#member] or editor",
			"define viewer: [user with nosuch_condition, service_account, group#member] or editor")), []Rule{RuleD4Condition}}},
		{"or v_get from project", row{compose(swapDecl(base,
			"define v_get: [user, service_account, group#member] or super_admin",
			"define v_get: [user, service_account] or v_get from project")), []Rule{RuleD5}}},
		{"два указателя в project", row{compose(swapDecl(swapDecl(base,
			"    define project: [project]\n", "    define project: [project]\n    define owner_project: [project]\n"),
			"define super_admin: super_admin from project",
			"define super_admin: super_admin from project or super_admin from owner_project")), []Rule{RuleD8}}},
	}

	allRules := []Rule{RuleD7Prefix, RuleD7Suffix, RuleD1, RuleD3, RuleD4Userset, RuleD4Condition, RuleD5, RuleD8}
	raised := map[Rule]int{}
	for _, r := range rows {
		rep, err := Admit(r.row.composed)
		if err != nil {
			t.Fatalf("%s: вход обязан ДОХОДИТЬ до допуска, получена ошибка: %v", r.name, err)
		}
		got := map[Rule]bool{}
		for _, f := range rep.Findings {
			got[f.Rule] = true
		}
		want := map[Rule]bool{}
		for _, x := range r.row.raises {
			want[x] = true
			raised[x]++
		}
		for _, rule := range allRules {
			if got[rule] != want[rule] {
				t.Fatalf("%s: клауза %s — поднята=%v, ждали=%v; все находки: %v",
					r.name, rule, got[rule], want[rule], rep.Findings)
			}
		}
	}
	if len(rows) != 13 {
		t.Fatalf("входов в матрице %d, ждали 13", len(rows))
	}
	for _, rule := range allRules {
		if raised[rule] == 0 {
			t.Fatalf("клауза %s не поднята НИ ОДНИМ входом — она есть ветвь без предмета", rule)
		}
	}
	t.Logf("матрица диагональна: входов %d, клауз %d, поднятий по клаузам %v", len(rows), len(allRules), raised)
}

// ── §17.5 · премисса сокращения рёбер утверждается САМИМ допуском ─────────────
//
// Довод §11 решения («Term.Computed ведёт в отношение ТОГО ЖЕ типа, а посев уже
// включает каждое объявление нового типа») верен для шага внутри НОВОГО типа и не
// покрывает шаг внутри типа КАНОНИЧЕСКОГО, куда замыкание входит по TTU/Userset.
// Решение (§14) закрывает это аддитивно: войдя в канонический тип, замыкание идёт
// по Computed ВНУТРИ него. Здесь проверяется, что оно и вправду идёт.
func TestAdmitAssertsItsOwnPremiseOnComputedInsideCanon(t *testing.T) {
	// Синтетический канон: подстановка достижима из нового типа ТОЛЬКО шагом
	// Computed внутри канонического типа. На настоящем каноне такой пары нет
	// (замер ниже), поэтому вход обязан быть синтетическим.
	canon := "model\n  schema 1.1\n\ntype user\n\ntype org\n  relations\n" +
		"    define open: [user, user:*]\n    define gate: open\n\n" +
		"type project\n  relations\n    define admin: [user]\n"
	block := "type acme_widget\n  relations\n    define org: [org]\n" +
		"    define v_get: [user] or gate from org\n"
	rep, err := admit(canon, canon+"\n"+block)
	if err != nil {
		t.Fatalf("синтетический вход обязан разбираться: %v", err)
	}
	if rep.ComputedOnlyWildcards != 1 {
		t.Fatalf("премисса обязана утверждаться числом: пар, достигающих подстановки ТОЛЬКО через "+
			"Term.Computed внутри канонического типа, получено %d, ждали 1; перепись: %s",
			rep.ComputedOnlyWildcards, rep.Census())
	}
	if n := len(findingsOf(rep, RuleD3)); n != 1 {
		t.Fatalf("нарушенная премисса означает, что подстановка ДОСТИЖИМА, — это находка Д3, получено %d (%v)", n, rep.Findings)
	}
	if !strings.Contains(rep.Census(), "только через Term.Computed") {
		t.Fatalf("перепись обязана печатать величину премиссы всегда, получено: %s", rep.Census())
	}

	// Положительный близнец: на настоящем каноне величина премиссы — ноль, и это
	// не молчание, а напечатанный ноль.
	real := mustAdmit(t, compose(twin(t)))
	if real.ComputedOnlyWildcards != 0 {
		t.Fatalf("на каноне величина премиссы обязана быть 0, получено %d", real.ComputedOnlyWildcards)
	}
	if !strings.Contains(real.Census(), "только через Term.Computed: 0") {
		t.Fatalf("ноль обязан быть напечатан, получено: %s", real.Census())
	}
}

// ── пустой обход роняет ───────────────────────────────────────────────────────

func TestAdmitEmptyTraversalIsRefused(t *testing.T) {
	// Канон, который не разбирается, — не «ноль находок», а отказ: иначе допуск
	// объявил бы чистым текст, о котором не прочитал ничего.
	if _, err := admit("", "что угодно"); err == nil {
		t.Fatal("пустой канон обязан ронять допуск, а не давать чистый отчёт")
	}
	if _, err := admit("не модель", "не модель"); err == nil {
		t.Fatal("неразбираемый канон обязан ронять допуск")
	}
}

// ── канон берётся у образа, а не у вызывающего ────────────────────────────────
//
// Параметризованный канон делает допуск САМОУДОВЛЕТВОРИМЫМ: вызывающий, подавший
// вместо канона собранный текст, обнуляет Д7(а), Д1 и Д4 разом. Поэтому
// экспортированная точка входа принимает ОДИН аргумент.
func TestAdmitTakesCanonFromTheImage(t *testing.T) {
	block := swapDecl(twin(t),
		"define v_get: [user, service_account, group#member] or super_admin",
		"define v_get: [user, service_account, user:*] or super_admin")
	composed := compose(block)

	viaImage := mustAdmit(t, composed)
	if len(findingsOf(viaImage, RuleD3)) != 1 {
		t.Fatalf("подстановка нового типа обязана быть находкой, получено %v", rules(viaImage))
	}
	// Самоудовлетворимость: тот же текст, поданный КАК КАНОН, находок не даёт —
	// именно поэтому параметризованная форма не экспортирована.
	selfServed, err := admit(composed, composed)
	if err != nil {
		t.Fatalf("самоудовлетворимая подача: %v", err)
	}
	if len(selfServed.Findings) != 0 || !selfServed.NothingToJudge {
		t.Fatalf("подача собранного текста вместо канона обязана обнулять правила — иначе довод §1 "+
			"приёмки об одном аргументе неверен; получено находок %d, судить нечего=%v",
			len(selfServed.Findings), selfServed.NothingToJudge)
	}
}
