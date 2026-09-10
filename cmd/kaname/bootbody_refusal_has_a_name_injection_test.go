// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// bootbody_refusal_has_a_name_injection_test.go — доказательство того, что гейт
// безымянных отказов старта СПОСОБЕН упасть, и падает на своём предмете (#2514).
//
// ─────────────────────────────────────────────────────────────────────────────
// ИНЪЕКЦИЯ РОНЯЕТ ТОЛЬКО ПРОВЕРЯЕМОЕ
//
// Ни один исходник дерева не правится: разбор принимает байты доводом, суждение
// — перечни и ведомость. Настоящая ведомость подменяется синтетической, поэтому
// её самоистечение проверяется, не трогая живых записей.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОСИ
//
//  1. БЕЗЫМЯННЫЙ ОТКАЗ — находка с координатой. Законный близнец — тот же отказ,
//     названный в ведомости: молчание.
//  2. ВЕДОМОСТЬ ИСТЕКАЕТ САМА — запись, которой нечего прощать, находка.
//  3. ДВЕ ФОРМЫ ПОСТРОЕНИЯ на месте (`fmt.Errorf` и `errors.New`): форма, о
//     которой распознаватель не знает, даёт МОЛЧАНИЕ, а не вердикт.
//  4. ОБОРАЧИВАЮЩИЙ ОТКАЗ предметом НЕ является — это решение, а не пропуск:
//     он передаёт чужой вердикт вместе с причиной.
//  5. ОБЛАСТЬ — судится ТЕЛО ПОДЪЁМА: отказ соседней функции сюда не приходит.
//  6. ВЫЗОВ, А НЕ УПОМИНАНИЕ — имя стража в комментарии вызовом не является:
//     гейт по подстроке краснел бы на собственном объяснении.
//  7. ПУСТОЙ ОБХОД — находка, а не тишина.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bootBodySource — тело подъёма с подставленным содержимым.
func bootBodySource(body string) string {
	return "package main\n\nfunc " + bootBodyFunc + "() error {\n" + body + "\n\treturn nil\n}\n"
}

func verdictsOf(t *testing.T, src string) ([]bootRefusal, []string) {
	t.Helper()
	inline, guards, err := bootBodyVerdicts("serve.go", []byte(src))
	if err != nil {
		t.Fatalf("синтетический исходник не разбирается: %v", err)
	}
	return inline, guards
}

// TestBootBodyRefusalInjection_UnnamedRefusalIsCaught — безымянный отказ назван
// находкой с координатой и с началом своего текста.
func TestBootBodyRefusalInjection_UnnamedRefusalIsCaught(t *testing.T) {
	inline, guards := verdictsOf(t, bootBodySource(
		"\tif x {\n\t\treturn fmt.Errorf(\"боевой режим требует ЧЕГО-ТО; refusing to start\")\n\t}"))
	if len(inline) != 1 {
		t.Fatalf("встроенных отказов прочитано %d, ожидался 1", len(inline))
	}
	findings, census := auditBootBodyRefusals(1, inline, guards, map[string]string{})
	if len(findings) != 1 {
		t.Fatalf("безымянный отказ дал находок %d, ожидалась 1: %v", len(findings), findings)
	}
	for _, want := range []string{"serve.go:", "боевой режим требует ЧЕГО-ТО"} {
		if !strings.Contains(findings[0], want) {
			t.Errorf("находка не называет %q: %s", want, findings[0])
		}
	}
	if census.Inline != 1 || census.InLedger != 0 {
		t.Errorf("перепись не сошлась: встроенных %d, в ведомости %d", census.Inline, census.InLedger)
	}
}

// TestBootBodyRefusalInjection_LedgeredRefusalStaysSilent — ЗАКОННЫЙ БЛИЗНЕЦ:
// тот же отказ, названный в ведомости.
//
// Без него красное выше приходило бы от чего угодно — например от суждения,
// объявляющего находкой всякий встроенный отказ.
func TestBootBodyRefusalInjection_LedgeredRefusalStaysSilent(t *testing.T) {
	inline, guards := verdictsOf(t, bootBodySource(
		"\treturn fmt.Errorf(\"отказ ПОСТРОЕНИЯ: часть узла отсутствует\")"))
	findings, census := auditBootBodyRefusals(1, inline, guards,
		map[string]string{"отказ ПОСТРОЕНИЯ": "причина, названная поимённо"})
	if len(findings) != 0 {
		t.Fatalf("названный в ведомости отказ объявлен находкой: %v", findings)
	}
	if census.InLedger != 1 {
		t.Fatalf("в ведомости насчитано %d, ожидалось 1", census.InLedger)
	}
}

// TestBootBodyRefusalInjection_LedgerExpiresByItself — запись, которой нечего
// прощать, есть находка.
//
// Без этой половины снятый отказ оставлял бы за собой прощение, под которое
// уедет следующий, — и уедет молча.
func TestBootBodyRefusalInjection_LedgerExpiresByItself(t *testing.T) {
	inline, guards := verdictsOf(t, bootBodySource("\tif err := requireSomething(); err != nil {\n\t\treturn err\n\t}"))
	findings, _ := auditBootBodyRefusals(1, inline, guards,
		map[string]string{"этого отказа больше нет": "причина"})
	if len(findings) != 1 {
		t.Fatalf("осиротевшая запись ведомости дала находок %d, ожидалась 1: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0], "пережила свой предмет") {
		t.Errorf("находка не называет причины: %s", findings[0])
	}
}

// TestBootBodyRefusalInjection_BothInPlaceFormsAreRead — обе законные формы
// построения отказа на месте.
func TestBootBodyRefusalInjection_BothInPlaceFormsAreRead(t *testing.T) {
	for _, c := range []struct{ name, body string }{
		{"fmt.Errorf", "\treturn fmt.Errorf(\"отказ формой Errorf\")"},
		{"errors.New", "\treturn errors.New(\"отказ формой New\")"},
		{"склейка литералов", "\treturn fmt.Errorf(\"отказ \" + \"склейкой\")"},
	} {
		t.Run(c.name, func(t *testing.T) {
			inline, _ := verdictsOf(t, bootBodySource(c.body))
			if len(inline) != 1 {
				t.Fatalf("форма не прочитана: встроенных отказов %d — распознаватель молчит "+
					"о написанном ею, и это не красное и не зелёное", len(inline))
			}
		})
	}
}

// TestBootBodyRefusalInjection_WrappingRefusalIsNotTheSubject — оборачивающий
// отказ предметом не является.
//
// Это РЕШЕНИЕ, а не пропуск: он не решает о посадке, а передаёт чужой вердикт
// вместе с причиной. Требовать имени от него значило бы требовать свойства, о
// котором никто не решал, — тот исход, из-за которого два прежних предиката этой
// задачи были отвергнуты замером.
func TestBootBodyRefusalInjection_WrappingRefusalIsNotTheSubject(t *testing.T) {
	inline, _ := verdictsOf(t, bootBodySource("\treturn fmt.Errorf(\"загрузка настройки: %w\", err)"))
	if len(inline) != 0 {
		t.Fatalf("оборачивающий отказ зачтён предметом: %v", inline)
	}
}

// TestBootBodyRefusalInjection_OnlyTheBootBodyIsJudged — отказ соседней функции
// сюда не приходит: область названа и обязана держаться разбором, а не памятью.
func TestBootBodyRefusalInjection_OnlyTheBootBodyIsJudged(t *testing.T) {
	src := "package main\n\nfunc somethingElse() error {\n" +
		"\treturn fmt.Errorf(\"отказ ЧУЖОЙ функции\")\n}\n" +
		"\nfunc " + bootBodyFunc + "() error { return nil }\n"
	inline, _ := verdictsOf(t, src)
	if len(inline) != 0 {
		t.Fatalf("отказ вне тела подъёма зачтён предметом: %v", inline)
	}
}

// TestBootBodyRefusalInjection_GuardCallIsRecognisedAndMentionIsNot — вызов
// именованного стража узнаётся, а его имя в КОММЕНТАРИИ вызовом не является.
func TestBootBodyRefusalInjection_GuardCallIsRecognisedAndMentionIsNot(t *testing.T) {
	inline, guards := verdictsOf(t, bootBodySource(
		"\t// requireИзКомментария здесь только назван.\n"+
			"\tif err := requireSomething(a, b); err != nil {\n\t\treturn err\n\t}\n"+
			"\tif err := helperNotAGuard(); err != nil {\n\t\treturn err\n\t}"))
	if len(inline) != 0 {
		t.Fatalf("возврат чужой ошибки зачтён встроенным отказом: %v", inline)
	}
	if len(guards) != 1 || guards[0] != "requireSomething" {
		t.Fatalf("стражи прочитаны неверно: %v — ожидался ровно requireSomething", guards)
	}
}

// TestBootBodyRefusalInjection_EmptyWalkIsAFinding — обход без файлов и тело
// подъёма без единого отказа: оба обязаны быть находкой, а не тишиной.
//
// Вторая половина несущая: тело, переименованное или не найденное разбором,
// даёт «отказов ноль» — и «всё названо» стало бы верным тривиально.
func TestBootBodyRefusalInjection_EmptyWalkIsAFinding(t *testing.T) {
	findings, _ := auditBootBodyRefusals(0, nil, nil, map[string]string{})
	if len(findings) != 1 || !strings.Contains(findings[0], "прочитано 0") {
		t.Fatalf("обход без файлов не назван беспредметным: %v", findings)
	}

	findings, census := auditBootBodyRefusals(41, nil, nil, map[string]string{})
	if len(findings) != 1 || !strings.Contains(findings[0], "НИ ОДНОГО отказа старта") {
		t.Fatalf("тело подъёма без отказов не названо беспредметным: %v", findings)
	}
	if census.Guards != 0 || census.Inline != 0 {
		t.Fatalf("перепись не пуста при пустом входе: стражей %d, встроенных %d",
			census.Guards, census.Inline)
	}
}

// TestBootBodyRefusalInjection_TheLiveLedgerHasASubject — живая ведомость этого
// дерева прощает ровно то, что в дереве есть.
//
// Проба смотрит на НАСТОЯЩИЕ величины и потому истекает вместе с ними: снимут
// прощаемый отказ — она покраснеет здесь, а не только в гейте.
func TestBootBodyRefusalInjection_TheLiveLedgerHasASubject(t *testing.T) {
	if len(bootBodyRefusalsNotGuards) == 0 {
		t.Skip("ведомость пуста — прощать нечего, и это ЦЕЛЬ, а не поломка")
	}
	src, err := readBootBodySource()
	if err != nil {
		t.Fatalf("исходники корня не прочитаны: %v", err)
	}
	inline, _, perr := bootBodyVerdicts("serve.go", src)
	if perr != nil {
		t.Fatalf("исходник тела подъёма не разобран: %v", perr)
	}
	for key := range bootBodyRefusalsNotGuards {
		found := false
		for _, r := range inline {
			if strings.Contains(r.Text, key) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ведомость прощает %q, а отказа с таким текстом в теле подъёма нет", key)
		}
	}
}

// readBootBodySource — исходник, несущий тело подъёма. Ищется ПО СОДЕРЖИМОМУ, а
// не по имени файла: имя файла — координата, которая переживает переезд.
func readBootBodySource() ([]byte, error) {
	entries, err := os.ReadDir(".")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(name)
		if rerr != nil {
			return nil, rerr
		}
		inline, guards, perr := bootBodyVerdicts(name, src)
		if perr == nil && (len(inline) > 0 || len(guards) > 0) {
			return src, nil
		}
	}
	return nil, errNoBootBody
}

var errNoBootBody = errors.New("исходника с телом подъёма не найдено — предпосылка пробы неверна")
