// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// r74trace_gate_test.go — ТРАССИРОВКА: у каждого сценария приёмки R7-4 есть проба,
// названная его идентификатором (сценарий R7-4-18).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЭТОТ ГЕЙТ СТОРОЖИТ, А ЧТО НЕТ
//
// Он сторожит СОГЛАШЕНИЕ ЭТОГО ДОКУМЕНТА, а не свойство дерева. Соглашение
// «идентификатор сценария трассируется в имя пробы» соблюдено не всюду: у одной
// из соседних под-фаз проб такой формы нет вовсе, и находкой это здесь НЕ
// является — поэтому гейт сужен до приставки R7_4_ и за её пределы не смотрит.
//
// Перечень идентификаторов поэтому ОБЪЯВЛЕН здесь, а не выведен из дерева:
// вывести его неоткуда — приёмка живёт в другом репозитории, и во время прогона
// её здесь нет. Цена названа: перечень придётся править вместе с приёмкой, и
// именно поэтому он стоит одним местом, а не рассыпан по условиям.
//
// ─────────────────────────────────────────────────────────────────────────────
// СООТВЕТСТВИЕ НЕ ОДИН-К-ОДНОМУ, И ЭТО НЕ ПОСЛАБЛЕНИЕ
//
// Требование — «ХОТЯ БЫ ОДНА проба на идентификатор». Прочтение «ровно одна»
// сделало бы находкой законное дробление: у соседней под-фазы под одним
// идентификатором живут пять проб — перепись, две инъекции, проверка предпосылки
// и прогон в конвейере, — и каждая утверждает свою половину одного сценария.
// Гейт, требующий единственности, вынудил бы слить их в одну пробу, у которой
// падение перестало бы называть виновника.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВЕ СТОРОНЫ, И ВТОРАЯ ТИШЕ ПЕРВОЙ
//
//	(а) идентификатор БЕЗ пробы — сценарий приёмки не проверяется ничем;
//	(б) проба, называющая НЕСУЩЕСТВУЮЩИЙ идентификатор, — она выглядит как
//	    покрытие и им не является: сценария, на который она ссылается, нет, и
//	    исправить по её имени нечего.
//
// Требование пробы стоит на `01…17` (так его формулирует сам сценарий 18), а
// СУЩЕСТВУЮТ идентификаторы `01…18`: восемнадцатый — это сценарий, который данный
// гейт и есть, и его собственное имя обязано быть законным, иначе гейт объявил бы
// находкой сам себя.
//
// ─────────────────────────────────────────────────────────────────────────────
// КОРПУС — ИНДЕКС GIT, А НЕ ОБХОД ДИСКА
//
// Вердикт обязан быть свойством КОММИТА: обход диска читал бы рабочие копии
// соседних сессий и игнорируемые каталоги. Следствие названо прямо: проба,
// написанная, но ещё не добавленная в индекс, читается этим гейтом как
// ОТСУТСТВУЮЩАЯ — и это правильно, потому что в свежем клоне её тоже нет.

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

const (
	// r74First / r74LastRequired — идентификаторы, у которых проба ОБЯЗАНА быть.
	r74First        = 1
	r74LastRequired = 17
	// r74LastDeclared — сколько идентификаторов вообще объявлено §6 приёмки.
	// Больше требуемого ровно на один: восемнадцатый описывает сам этот гейт.
	r74LastDeclared = 18
)

// r74RetiredScenarios — сценарии, чей ПРЕДМЕТ снят, а идентификатор остался.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ ЭТОТ ПЕРЕЧЕНЬ ВООБЩЕ ЕСТЬ
//
// Требовать пробу для сценария, у которого больше нет предмета, — значит требовать
// проверку несуществующего механизма. Исходов было бы два, и оба плохие: написать
// пробу, которая не может упасть, либо держать гейт красным, пока его не отключат.
//
// Поэтому третий: назвать идентификатор ЗДЕСЬ вместе с фактом, которым его предмет
// истёк. Тогда трассировка остаётся полной по построению — у каждого требуемого
// идентификатора либо проба, либо запись с причиной, — а «нечего проверять» не
// путается с «забыли проверить».
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАПИСЬ САМА ИСТЕКАЕТ
//
// Появилась проба с этим номером — запись становится находкой: она бы молча
// прикрыла сценарий, у которого предмет ВЕРНУЛСЯ. Это проверяет судья ниже, а не
// чья-то память.
var r74RetiredScenarios = map[int]string{
	4: "предмет — решение ПРИБОРА подачи по составу нагрузки: он отказывался выдавать " +
		"вердикт, получив состав без пяти собственных типов iam. Прибор мерил долю " +
		"расхождений ДВУХ форм и снят вместе со второй формой (стадия S6 эпика #747, " +
		"внешний движок прав). Предикат снятия записи: появится прибор, у которого " +
		"есть, с чем сравнивать",
	12: "предмет — разложение расхождения по НАПРАВЛЕНИЮ и по типу: «форма шире» " +
		"против «форма уже». Направления не существует, когда форма одна, — сравнивать " +
		"не с чем (стадия S6). Предикат снятия записи: вернулась вторая форма решения",
}

// r74ProbeName — имя пробы, называющей идентификатор под-фазы. Число ловится как
// `\d+`, а не как `\d{2}`, намеренно: запись одной цифрой — тоже находка, и
// поймать её лучше, чем не заметить (по `R7_4_05` она не ищется).
var r74ProbeName = regexp.MustCompile(`func\s+(TestR7_4_(\d+)_\w*)`)

// r74Corpus — что прочитано; печатается, чтобы «ноль находок» было отличимо от
// «ноль прочитанного».
type r74Corpus struct {
	Files      int
	Probes     int
	ByID       map[int][]string
	Malformed  []string
	FilesNamed []string
}

// r74Scan — перепись проб по корпусу тестовых файлов дерева.
func r74Scan(files []string) (r74Corpus, error) {
	c := r74Corpus{ByID: map[int][]string{}}
	for _, path := range files {
		body, err := os.ReadFile(path) // #nosec G304 -- path получен из индекса СОБСТВЕННОГО репозитория (treecorpus → git ls-files), не из запроса и не от пользователя
		if err != nil {
			return c, fmt.Errorf("чтение %s: %w", path, err)
		}
		c.Files++
		for _, m := range r74ProbeName.FindAllStringSubmatch(string(body), -1) {
			c.Probes++
			name, digits := m[1], m[2]
			if len(digits) != 2 {
				c.Malformed = append(c.Malformed, fmt.Sprintf("%s (в %s)", name, path))
				continue
			}
			n, err := strconv.Atoi(digits)
			if err != nil {
				return c, fmt.Errorf("идентификатор %q в %s не число: %w", digits, path, err)
			}
			c.ByID[n] = append(c.ByID[n], name)
		}
	}
	return c, nil
}

// ── ВЕРДИКТ ЧИСТОЙ ФУНКЦИЕЙ ─────────────────────────────────────────────────

// judgeR74Traceability — находки. Пустой срез означает «трассировка полна».
//
// Границы перечня — параметры, а не константы внутри: иначе предпосылку («перечень
// пуст») нельзя было бы предъявить, и она осталась бы заявленной.
func judgeR74Traceability(c r74Corpus, first, lastRequired, lastDeclared int, retired map[int]string) []string {
	if lastRequired < first || lastDeclared < lastRequired {
		return []string{fmt.Sprintf("ПРЕДПОСЫЛКА: перечень идентификаторов вырожден "+
			"(первый %d, последний требуемый %d, последний объявленный %d) — сторожить нечего, "+
			"и «находок нет» означало бы «нечего было искать»", first, lastRequired, lastDeclared)}
	}
	if c.Files == 0 {
		return []string{"ПРЕДПОСЫЛКА: прочитано НОЛЬ тестовых файлов дерева — корпус пуст, " +
			"и молчание гейта не означало бы полноты трассировки"}
	}

	var findings []string

	// (а) идентификатор без пробы. Снятые предметом — не находка, но и не тишина:
	// они называются отдельной строкой, чтобы «нечего проверять» было видно.
	var missing []string
	for id := first; id <= lastRequired; id++ {
		if len(c.ByID[id]) != 0 {
			continue
		}
		if _, gone := retired[id]; gone {
			continue
		}
		missing = append(missing, fmt.Sprintf("R7-4-%02d", id))
	}

	// (а2) запись о снятом предмете, у которой предмет ВЕРНУЛСЯ. Послабление,
	// которому больше нечего прикрывать, прикроет следующее.
	var revived []string
	for id, why := range retired {
		if len(c.ByID[id]) == 0 {
			continue
		}
		revived = append(revived, fmt.Sprintf("R7-4-%02d ← %s", id, strings.Join(c.ByID[id], ", ")))
		_ = why
	}
	sort.Strings(revived)
	if len(revived) != 0 {
		findings = append(findings, fmt.Sprintf(
			"СЦЕНАРИЙ ОБЪЯВЛЕН СНЯТЫМ, А ПРОБА С ЕГО НОМЕРОМ ЕСТЬ (%d): %s\n"+
				"  Значит предмет вернулся, а запись в r74RetiredScenarios осталась и "+
				"прикрывает его молча. Снимите запись",
			len(revived), strings.Join(revived, " · ")))
	}
	if len(missing) != 0 {
		findings = append(findings, fmt.Sprintf(
			"СЦЕНАРИИ БЕЗ ПРОБЫ (%d из %d): %s\n"+
				"  У каждого из них есть Given-When-Then в приёмке и нет ничего, что его "+
				"проверяет: сценарий покрытым не считается, пока в дереве нет пробы "+
				"TestR7_4_<NN>_… с его номером",
			len(missing), lastRequired-first+1, strings.Join(missing, ", ")))
	}

	// (б) проба, называющая несуществующий идентификатор.
	var phantom []string
	for id := range c.ByID {
		if id < first || id > lastDeclared {
			phantom = append(phantom, fmt.Sprintf("R7-4-%02d ← %s",
				id, strings.Join(c.ByID[id], ", ")))
		}
	}
	sort.Strings(phantom)
	if len(phantom) != 0 {
		findings = append(findings, fmt.Sprintf(
			"ПРОБЫ, НАЗЫВАЮЩИЕ НЕСУЩЕСТВУЮЩИЙ СЦЕНАРИЙ (%d): %s\n"+
				"  Такая проба выглядит как покрытие и им не является: сценария с этим "+
				"номером в приёмке нет, и по её имени нечего открыть. Объявлено "+
				"идентификаторов %d",
			len(phantom), strings.Join(phantom, " · "), lastDeclared-first+1))
	}

	// (в) запись номера не двумя цифрами — трассировка ломается на поиске.
	if len(c.Malformed) != 0 {
		sort.Strings(c.Malformed)
		findings = append(findings, fmt.Sprintf(
			"НОМЕР ЗАПИСАН НЕ ДВУМЯ ЦИФРАМИ (%d): %s\n"+
				"  Идентификатор приёмки пишется как R7-4-05, и проба обязана называться "+
				"так же: по TestR7_4_05_ такая проба не находится, то есть трассировка "+
				"есть на вид и отсутствует на деле",
			len(c.Malformed), strings.Join(c.Malformed, " · ")))
	}
	return findings
}

// ── ГЕЙТ НАД НАСТОЯЩИМ ДЕРЕВОМ ──────────────────────────────────────────────

// TestR7_4_18_EveryScenarioIdentifierHasAProbeNamedAfterIt — гейт трассировки.
func TestR7_4_18_EveryScenarioIdentifierHasAProbeNamedAfterIt(t *testing.T) {
	root := matrixRepoRoot(t)
	files, err := treecorpus.UnderWithSuffix(root, "_test.go")
	if err != nil {
		t.Fatalf("корпус тестовых файлов не взят: %v", err)
	}
	c, err := r74Scan(files)
	if err != nil {
		t.Fatalf("перепись проб: %v", err)
	}

	var covered []string
	for id := r74First; id <= r74LastDeclared; id++ {
		if n := len(c.ByID[id]); n != 0 {
			covered = append(covered, fmt.Sprintf("R7-4-%02d×%d", id, n))
		}
	}
	// Объём осмотренного — ВСЕГДА, независимо от исхода.
	t.Logf("осмотрено: тестовых файлов дерева %d, проб формы TestR7_4_<NN>_ распознано %d; "+
		"идентификаторов объявлено %d, требуют пробы %d, покрыто %d\n  покрытие: %s",
		c.Files, c.Probes, r74LastDeclared-r74First+1, r74LastRequired-r74First+1,
		len(covered), strings.Join(covered, " · "))

	for _, f := range judgeR74Traceability(c, r74First, r74LastRequired, r74LastDeclared, r74RetiredScenarios) {
		t.Errorf("%s\n  Корпус — ИНДЕКС git: проба, написанная и не добавленная в индекс, "+
			"читается как отсутствующая, потому что в свежем клоне её тоже нет", f)
	}
}

// TestR7_4_18_TheTraceGateFallsOnAGapAndOnAPhantomAndStaysSilentOnASplit —
// ИНЪЕКЦИЯ В ОБЕ СТОРОНЫ.
func TestR7_4_18_TheTraceGateFallsOnAGapAndOnAPhantomAndStaysSilentOnASplit(t *testing.T) {
	full := func() r74Corpus {
		c := r74Corpus{Files: 1, ByID: map[int][]string{}}
		for id := r74First; id <= r74LastDeclared; id++ {
			c.ByID[id] = []string{fmt.Sprintf("TestR7_4_%02d_Probe", id)}
			c.Probes++
		}
		return c
	}

	// (б) ЗАКОННЫЙ БЛИЗНЕЦ №1 — полная трассировка: молчание. Без положительного
	// контроля красное на дефекте неотличимо от красного на чём угодно.
	if got := judgeR74Traceability(full(), r74First, r74LastRequired, r74LastDeclared, nil); got != nil {
		t.Fatalf("полная трассировка покраснела: %v", got)
	}

	// (б) ЗАКОННЫЙ БЛИЗНЕЦ №2 — ДРОБЛЕНИЕ: несколько проб под одним
	// идентификатором. Находкой это НЕ является, иначе гейт запретил бы разносить
	// перепись, инъекцию и предпосылку по отдельным пробам.
	split := full()
	split.ByID[r74First] = append(split.ByID[r74First],
		"TestR7_4_01_Injection", "TestR7_4_01_Premise", "TestR7_4_01_InCI")
	split.Probes += 3
	if got := judgeR74Traceability(split, r74First, r74LastRequired, r74LastDeclared, nil); got != nil {
		t.Errorf("дробление одного сценария на несколько проб объявлено находкой: %v.\n"+
			"  Требование — «хотя бы одна проба на идентификатор», а не «ровно одна»", got)
	}

	// (а) КРАСНОЕ С КООРДИНАТОЙ №1 — пропуск, по каждому требуемому отдельно.
	for id := r74First; id <= r74LastRequired; id++ {
		gap := full()
		delete(gap.ByID, id)
		findings := judgeR74Traceability(gap, r74First, r74LastRequired, r74LastDeclared, nil)
		want := fmt.Sprintf("R7-4-%02d", id)
		if len(findings) != 1 || !strings.Contains(findings[0], want) {
			t.Errorf("проба сценария %s снята → ожидалась одна находка с его номером, "+
				"получено %v", want, findings)
		}
	}

	// (а) КРАСНОЕ С КООРДИНАТОЙ №2 — проба называет несуществующий сценарий.
	phantom := full()
	phantom.ByID[99] = []string{"TestR7_4_99_NamesNothing"}
	phantom.Probes++
	findings := judgeR74Traceability(phantom, r74First, r74LastRequired, r74LastDeclared, nil)
	if len(findings) != 1 || !strings.Contains(findings[0], "R7-4-99") {
		t.Errorf("проба несуществующего сценария → ожидалась одна находка с номером 99, "+
			"получено %v", findings)
	}

	// (а) КРАСНОЕ С КООРДИНАТОЙ №3 — номер записан одной цифрой.
	odd := full()
	odd.Malformed = []string{"TestR7_4_5_Probe (в services/…/x_test.go)"}
	findings = judgeR74Traceability(odd, r74First, r74LastRequired, r74LastDeclared, nil)
	if len(findings) != 1 || !strings.Contains(findings[0], "TestR7_4_5_Probe") {
		t.Errorf("однозначная запись номера → ожидалась одна находка с именем пробы, "+
			"получено %v", findings)
	}

	// ВОСЕМНАДЦАТЫЙ ИДЕНТИФИКАТОР ЗАКОНЕН, ХОТЯ ПРОБЫ НЕ ТРЕБУЕТ: гейт не вправе
	// объявить находкой собственное имя.
	selfOnly := full()
	delete(selfOnly.ByID, r74LastDeclared)
	if got := judgeR74Traceability(selfOnly, r74First, r74LastRequired, r74LastDeclared, nil); got != nil {
		t.Errorf("отсутствие пробы у идентификатора %d объявлено находкой: %v.\n"+
			"  Требование пробы стоит на 01…%02d; %d — сам этот сценарий",
			r74LastDeclared, got, r74LastRequired, r74LastDeclared)
	}

	// СНЯТЫЙ ПРЕДМЕТ — обе стороны.
	//
	// (1) идентификатор, объявленный снятым, БЕЗ пробы — молчание: требовать
	// проверку несуществующего механизма значит требовать пробу, которая не может
	// упасть.
	retiredGap := full()
	delete(retiredGap.ByID, 4)
	if got := judgeR74Traceability(retiredGap, r74First, r74LastRequired, r74LastDeclared,
		map[int]string{4: "предмет снят"}); got != nil {
		t.Errorf("сценарий со снятым предметом объявлен находкой: %v", got)
	}
	// (2) он же, но проба С ЕГО НОМЕРОМ появилась — НАХОДКА: предмет вернулся, а
	// запись осталась и прикрывает его молча.
	revived := judgeR74Traceability(full(), r74First, r74LastRequired, r74LastDeclared,
		map[int]string{4: "предмет снят"})
	if len(revived) != 1 || !strings.Contains(revived[0], "ОБЪЯВЛЕН СНЯТЫМ") {
		t.Errorf("вернувшийся предмет не назван находкой: %v.\n"+
			"  Послабление, которому больше нечего прикрывать, прикроет следующее", revived)
	}

	// ПРЕДПОСЫЛКИ: вырожденный перечень и пустой корпус — ОТКАЗ, а не «находок нет».
	if got := judgeR74Traceability(full(), r74First, r74First-1, r74LastDeclared, nil); len(got) != 1 ||
		!strings.Contains(got[0], "ПРЕДПОСЫЛКА") {
		t.Errorf("вырожденный перечень идентификаторов: ожидался отказ, получено %v", got)
	}
	empty := full()
	empty.Files = 0
	if got := judgeR74Traceability(empty, r74First, r74LastRequired, r74LastDeclared, nil); len(got) != 1 ||
		!strings.Contains(got[0], "ПРЕДПОСЫЛКА") {
		t.Errorf("пустой корпус файлов: ожидался отказ, получено %v", got)
	}
}
