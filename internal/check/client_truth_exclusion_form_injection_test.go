// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_truth_exclusion_form_injection_test.go — доказательство, что гейт формы
// взаимоисключения СПОСОБЕН упасть и СПОСОБЕН смолчать (задача #17, семейство
// `clienttruth_kaname_exclusion_form`).
//
// Гейт зелен на сегодняшнем дереве, и это не доказывает ничего. Инъекция зовёт
// ТУ ЖЕ функцию, что и гейт, а не её копию.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const (
	// injReaderWithoutCoPresence — читатель отказывает, но НИ ОДИН отказ не о
	// сочетании двух форм. Надгробие снятой ветви стоит комментарием: предикат
	// по подстроке объявил бы живым ровно то, что снято.
	injReaderWithoutCoPresence = `package presentedcred

// Прежняя редакция отвергала запрос, несущий и presented, и forwarded формы
// личности разом. Ветвь снята вместе со своим предметом.
func (r *Reader) f() error {
	if bad {
		return r.refuse("token did not verify")
	}
	return r.refuse("credential is " + "revoked")
}
`
	// injReaderWithCoPresence — производитель отказа НА СОЧЕТАНИИ есть, причём
	// сообщение собрано конкатенацией: читатель одиночного литерала его НЕ
	// УВИДЕЛ БЫ и дал бы молчание вместо вердикта.
	injReaderWithCoPresence = `package presentedcred

func (r *Reader) f() error {
	return r.refuse("both presented and " + "forwarded identity in one request")
}
`
	// injWrapAlive — наше построение живо: читатель НАКРЫВАЕТ пару звеньев.
	injWrapAlive = `package main

func publicIdentityUnary(cfg C, presented *R) []I {
	pair := identityUnary(cfg)
	return []I{presented.UnaryOver(pair)}
}
`
	// injWrapDead — читатель стоит В ЦЕПОЧКЕ с парой, а не накрывает её:
	// построения на нашей стороне больше нет.
	injWrapDead = `package main

func publicIdentityUnary(cfg C, presented *R) []I {
	return append([]I{presented.Unary()}, identityUnary(cfg)...)
}
`
)

// injGuide — страница из трёх абзацев: предмет, сосед и хвост. Сосед законно
// говорит об отказе, НЕ будучи о предмете: чтение файла целиком зачло бы его
// обещанием, и вердикт стал бы ложно-красным.
func injGuide(subject string) string {
	return "Вводный абзац страницы установки.\n\n" +
		subject + "\n\n" +
		"Отказ выглядит одинаково при любой причине: служба отвергает запрос с одним и тем\n" +
		"же текстом. Причину ищите в своём журнале.\n"
}

func injInput(subject, reader, wrap string) check.ExclusionFormInput {
	return check.ExclusionFormInput{
		GuideRel:    "INSTALL.md",
		GuideBody:   injGuide(subject),
		ReaderFiles: map[string]string{"internal/presentedcred/reader.go": reader},
		WrapFiles:   map[string]string{"cmd/kaname/serve.go": wrap},
	}
}

// TestExclusionFormAssertionA_InjectionBothWays — УТВЕРЖДЕНИЕ A: обещанный
// отказ обязан иметь производителя.
func TestExclusionFormAssertionA_InjectionBothWays(t *testing.T) {
	t.Parallel()

	// Абзац предмета ОБЕЩАЕТ отказ. Построение он при этом называет, чтобы ось
	// B молчала: инъекция обязана ронять ТОЛЬКО проверяемое, иначе красное
	// приходит от соседа и об оси A не говорит ничего.
	promises := "Приём предъявленного и наш край — **взаимоисключающие** способы назваться:\n" +
		"запрос, несущий обе формы, служба ОТВЕРГАЕТ, хотя край и снимает удостоверение\n" +
		"перед пересылкой."
	// Законный близнец: тот же предмет, отказа не обещает, построение называет.
	names := "Приём предъявленного и наш край — взаимоисключающие способы назваться, и\n" +
		"держится это ПОСТРОЕНИЕМ: край снимает удостоверение перед пересылкой за себя."

	t.Run("страница обещает отказ, производителя нет — находка с координатой", func(t *testing.T) {
		t.Parallel()
		f, census, err := check.AuditExclusionForm(injInput(promises, injReaderWithoutCoPresence, injWrapAlive))
		if err != nil {
			t.Fatalf("фикстура обязана разбираться: %v", err)
		}
		if census.CoPresenceRefusals != 0 {
			t.Fatalf("предпосылка фикстуры: производителя быть не должно, а их %d",
				census.CoPresenceRefusals)
		}
		if len(f) != 1 || f[0].Kind != "refusal-without-producer" {
			t.Fatalf("обещание без производителя обязано краснить, и ТОЛЬКО им: %+v", f)
		}
		if f[0].Line != 3 {
			t.Fatalf("находка обязана называть строку абзаца, а не файл: %d", f[0].Line)
		}
		if !strings.Contains(f[0].String(), "INSTALL.md:3") {
			t.Fatalf("координата не напечатана: %s", f[0].String())
		}
	})

	t.Run("страница обещает отказ, производитель ЕСТЬ — гейт молчит", func(t *testing.T) {
		t.Parallel()
		f, census, err := check.AuditExclusionForm(injInput(promises, injReaderWithCoPresence, injWrapAlive))
		if err != nil {
			t.Fatalf("фикстура обязана разбираться: %v", err)
		}
		if census.CoPresenceRefusals != 1 {
			t.Fatalf("отказ, собранный конкатенацией, обязан читаться: о сочетании %d из %d",
				census.CoPresenceRefusals, census.RefuseCalls)
		}
		if len(f) != 0 {
			t.Fatalf("законный вход объявлен находкой: %+v — гейт судил бы форму, а не существо", f)
		}
	})

	t.Run("страница отказа не обещает — гейт молчит", func(t *testing.T) {
		t.Parallel()
		f, census, err := check.AuditExclusionForm(injInput(names, injReaderWithoutCoPresence, injWrapAlive))
		if err != nil {
			t.Fatalf("фикстура обязана разбираться: %v", err)
		}
		if census.ExplainByRefusal != 0 {
			t.Fatalf("абзац отказа не обещает, а распознаватель насчитал %d", census.ExplainByRefusal)
		}
		if len(f) != 0 {
			t.Fatalf("законный вход объявлен находкой: %+v", f)
		}
	})

	t.Run("сосед законно говорит об отказе, НЕ будучи о предмете — гейт молчит", func(t *testing.T) {
		t.Parallel()
		_, census, err := check.AuditExclusionForm(injInput(names, injReaderWithoutCoPresence, injWrapAlive))
		if err != nil {
			t.Fatalf("фикстура обязана разбираться: %v", err)
		}
		// Абзацев три, о предмете ровно один: вердикт выносится ПОАБЗАЦНО, и
		// соседний абзац об отказе в него не попадает.
		if census.GuideParagraphs != 3 || census.SubjectParagraphs != 1 {
			t.Fatalf("абзацев прочитано %d, о предмете %d — ожидались 3 и 1; чтение файла "+
				"целиком зачло бы отказ соседа обещанием предмета",
				census.GuideParagraphs, census.SubjectParagraphs)
		}
	})

	t.Run("отказ, назвавший ОДНУ форму, сочетанием не считается", func(t *testing.T) {
		t.Parallel()
		one := `package presentedcred

func (r *Reader) f() error { return r.refuse("presented credential is not accepted") }
`
		_, census, err := check.AuditExclusionForm(injInput(promises, one, injWrapAlive))
		if err != nil {
			t.Fatalf("фикстура обязана разбираться: %v", err)
		}
		if census.RefuseCalls != 1 {
			t.Fatalf("отказов встречено %d, а он один", census.RefuseCalls)
		}
		if census.CoPresenceRefusals != 0 {
			t.Fatal("отказ, назвавший одну форму, — про неё одну; зачесть его сочетанием " +
				"значило бы объявить производителя там, где его нет")
		}
	})
}

// TestExclusionFormAssertionB_InjectionBothWays — УТВЕРЖДЕНИЕ B: пока построение
// живо, страница обязана его называть.
func TestExclusionFormAssertionB_InjectionBothWays(t *testing.T) {
	t.Parallel()

	// Абзац предмета построения НЕ называет и отказа НЕ обещает: ось A при этом
	// молчит, и красное приходит ровно от оси B.
	silent := "Приём предъявленного и наш край — взаимоисключающие способы назваться.\n" +
		"Подробности см. в разделе о посадках."
	names := "Приём предъявленного и наш край — взаимоисключающие способы назваться:\n" +
		"читатель накрывает пару звеньев переданной личности и решает по её вердикту."

	t.Run("построение живо, страница им не объясняет — находка", func(t *testing.T) {
		t.Parallel()
		f, census, err := check.AuditExclusionForm(injInput(silent, injReaderWithoutCoPresence, injWrapAlive))
		if err != nil {
			t.Fatalf("фикстура обязана разбираться: %v", err)
		}
		if census.WrapCalls != 1 {
			t.Fatalf("обращений-обёрток %d, а оно одно — премиса оси B не выполнена", census.WrapCalls)
		}
		if len(f) != 1 || f[0].Kind != "construction-unnamed" {
			t.Fatalf("необъяснённое построение обязано краснить, и ТОЛЬКО им: %+v", f)
		}
		if f[0].Line != 3 {
			t.Fatalf("находка обязана называть строку абзаца предмета: %d", f[0].Line)
		}
	})

	t.Run("построение живо, страница его называет — гейт молчит", func(t *testing.T) {
		t.Parallel()
		f, census, err := check.AuditExclusionForm(injInput(names, injReaderWithoutCoPresence, injWrapAlive))
		if err != nil {
			t.Fatalf("фикстура обязана разбираться: %v", err)
		}
		if census.ExplainByBuild != 1 {
			t.Fatalf("абзац называет построение, а распознаватель насчитал %d", census.ExplainByBuild)
		}
		if len(f) != 0 {
			t.Fatalf("законный вход объявлен находкой: %+v", f)
		}
	})

	t.Run("абзаца предмета нет ВОВСЕ при живом построении — находка", func(t *testing.T) {
		t.Parallel()
		f, census, err := check.AuditExclusionForm(injInput(
			"Абзац, предмета не называющий.", injReaderWithoutCoPresence, injWrapAlive))
		if err != nil {
			t.Fatalf("фикстура обязана разбираться: %v", err)
		}
		if census.SubjectParagraphs != 0 {
			t.Fatalf("абзацев о предмете %d, а их нет", census.SubjectParagraphs)
		}
		if len(f) != 1 || f[0].Kind != "construction-unnamed" {
			t.Fatalf("исчезнувшее объяснение обязано краснить: %+v", f)
		}
		if f[0].Line != 0 || !strings.Contains(f[0].Excerpt, "нет вовсе") {
			t.Fatalf("находка обязана называть, что абзаца нет: %+v", f[0])
		}
	})

	t.Run("построение РАЗОМКНУТО — гейт объяснения не требует: обратное решение не запрещено",
		func(t *testing.T) {
			t.Parallel()
			// САМОИСТЕЧЕНИЕ: форма взаимоисключения — решение владельца, а не
			// константа. Уйдёт обёртка — утверждение B умолкнет само, а премиса
			// гейта скажет об этом вслух, вместо того чтобы отдать зелёный на
			// мёртвом механизме.
			f, census, err := check.AuditExclusionForm(injInput(silent, injReaderWithoutCoPresence, injWrapDead))
			if err != nil {
				t.Fatalf("фикстура обязана разбираться: %v", err)
			}
			if census.WrapCalls != 0 {
				t.Fatalf("обращений-обёрток %d, а построение разомкнуто", census.WrapCalls)
			}
			if len(f) != 0 {
				t.Fatalf("гейт судит СОГЛАСИЕ страницы с построением, а не выбор формы: %+v", f)
			}
		})

	t.Run("ОБЪЯВЛЕНИЕ обёртки вызывающим не является", func(t *testing.T) {
		t.Parallel()
		decl := `package presentedcred

func (r *Reader) UnaryOver(pair []I) I { return nil }
func (r *Reader) StreamOver(pair []I) I { return nil }
`
		in := injInput(names, injReaderWithoutCoPresence, injWrapDead)
		in.WrapFiles[check.ExclusionReaderDeclFileRel] = decl
		_, census, err := check.AuditExclusionForm(in)
		if err != nil {
			t.Fatalf("фикстура обязана разбираться: %v", err)
		}
		if census.WrapCalls != 0 {
			t.Fatalf("обращений насчитано %d — объявление зачтено вызовом, и «построение живо» "+
				"означало бы «функция объявлена»: механизма объявление без вызывающего не даёт",
				census.WrapCalls)
		}
		if census.WrapGoFiles != 2 {
			t.Fatalf("осмотрено файлов %d — объявляющий файл обязан ЧИТАТЬСЯ и попадать в "+
				"перепись, а не пропускаться до счёта", census.WrapGoFiles)
		}
	})

	t.Run("регистр страницы снимается", func(t *testing.T) {
		t.Parallel()
		upper := "Приём предъявленного и наш край — ВЗАИМОИСКЛЮЧАЮЩИЕ способы назваться:\n" +
			"край СНИМАЕТ удостоверение перед пересылкой."
		f, census, err := check.AuditExclusionForm(injInput(upper, injReaderWithoutCoPresence, injWrapAlive))
		if err != nil {
			t.Fatalf("фикстура обязана разбираться: %v", err)
		}
		if census.SubjectParagraphs != 1 || census.ExplainByBuild != 1 {
			t.Fatalf("предмет %d, построение %d — предикат, читающий написанное, промолчал бы "+
				"на живом производителе", census.SubjectParagraphs, census.ExplainByBuild)
		}
		if len(f) != 0 {
			t.Fatalf("законный вход объявлен находкой: %+v", f)
		}
	})
}
