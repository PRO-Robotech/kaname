// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// letters_test.go — модульная проба конструкторов Letter по 24 шаблонам
// (замысел issue-2917 З1, З27; УК48).
//
// Что утверждается и чем отличается красное от зелёного:
//
//   - нуль каждого required атрибута и пустой адресат — ошибка ErrLetterInvalid с
//     именем атрибута; письма нет;
//   - optional: mail.Present("") и нулевой литерал mail.Optional{} — ошибка с
//     именем атрибута; mail.Absent() и mail.Present(v) — письмо есть;
//   - близнец каждого отказа — все значения по форме: письмо есть, и Enqueue
//     доводит его до постановки ленты. Постановка без привязанного источника
//     отвечает feed.ErrSourceUnbound — этот текст производит только
//     feed.PutID, то есть порождённый Send* шаблона был вызван;
//   - полнота: рядов столько, сколько функций Send* в каталоге feedgen, и у
//     каждого конструктора поля — ровно атрибуты типа feedgen (без To).
package mail_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/PRO-Robotech/corelib/notify/address"
	"github.com/PRO-Robotech/corelib/notify/feed"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/mail"
)

// subjectUserID — id пользователя-адресата шаблонов формы subject.
const subjectUserID = "usr-0a1b2c3d4e5f6a7b"

// letterCase — ряд шаблона (ряды — letters_cases_test.go).
type letterCase struct {
	template string
	subject  bool
	// feedgen — нулевое значение типа атрибутов порождённого Send*: проба
	// полноты сверяет с ним поля конструктора.
	feedgen any
	// valid — атрибуты конструктора, все по форме.
	valid any
	// build зовёт конструктор с законным адресатом либо, при zeroTo, с нулевым.
	build func(attrs any, zeroTo bool) (mail.Letter, error)
}

func fixtureCases(t *testing.T) []letterCase {
	t.Helper()
	to, err := address.Normalize("Recipient@example.org")
	if err != nil {
		t.Fatalf("фикстура: Normalize: %v", err)
	}
	return letterCases(to, time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC))
}

// snake — имя атрибута ленты из имени поля Go: AccessKeyID → access_key_id.
func snake(field string) string {
	if strings.HasSuffix(field, "ID") {
		field = strings.TrimSuffix(field, "ID") + "Id"
	}
	var b strings.Builder
	for i, r := range field {
		if unicode.IsUpper(r) {
			if i > 0 {
				b.WriteByte('_')
			}
			r = unicode.ToLower(r)
		}
		b.WriteRune(r)
	}
	return b.String()
}

var optionalType = reflect.TypeFor[mail.Optional]()

func enabledEnqueuer(t *testing.T) mail.Enqueuer {
	t.Helper()
	on := true
	e, err := mail.EnabledFrom(&on)
	if err != nil {
		t.Fatalf("фикстура: EnabledFrom(true): %v", err)
	}
	q, err := mail.NewEnqueuer(e)
	if err != nil {
		t.Fatalf("фикстура: NewEnqueuer: %v", err)
	}
	return q
}

// reachesSend — письмо доведено Enqueue до порождённого Send*: без источника в
// контексте постановка отвечает ErrSourceUnbound, а его производит только
// feed.PutID.
func reachesSend(t *testing.T, q mail.Enqueuer, l mail.Letter) {
	t.Helper()
	_, err := q.Enqueue(context.Background(), nil, l)
	if !errors.Is(err, feed.ErrSourceUnbound) {
		t.Fatalf("шаблон %s: Enqueue отдал %v — ожидалась feed.ErrSourceUnbound (Send* вызван, источника нет)",
			l.Template(), err)
	}
}

// TestLetterCasesCoverTheCatalog — рядов столько, сколько шаблонов в каталоге
// feedgen, имена совпадают, и поля каждого конструктора — ровно атрибуты типа
// feedgen. Перепись печатается всегда.
func TestLetterCasesCoverTheCatalog(t *testing.T) {
	sends, err := feedgenSends(filepath.Join("feedgen"))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	dirs, err := catalogTemplates(filepath.Join("feedgen", "notifications"))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	cases := fixtureCases(t)
	t.Logf("перепись: функций Send* в feedgen %d · каталогов шаблонов %d · рядов пробы %d",
		len(sends), len(dirs), len(cases))
	if len(sends) == 0 || len(dirs) == 0 {
		t.Fatalf("пустой обход каталога feedgen — не вердикт")
	}
	if len(cases) != len(sends) || len(cases) != len(dirs) {
		t.Fatalf("рядов %d, функций Send* %d, каталогов %d — у каждого шаблона ровно один ряд и один конструктор",
			len(cases), len(sends), len(dirs))
	}
	var names []string
	for _, c := range cases {
		names = append(names, c.template)
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, dirs) {
		t.Fatalf("имена рядов %v не совпадают с каталогом %v", names, dirs)
	}
	for _, c := range cases {
		ours := reflect.TypeOf(c.valid)
		theirs := reflect.TypeOf(c.feedgen)
		var want, got []string
		for i := range theirs.NumField() {
			if f := theirs.Field(i).Name; f != "To" {
				want = append(want, snake(f))
			}
		}
		for i := range ours.NumField() {
			got = append(got, snake(ours.Field(i).Name))
		}
		sort.Strings(want)
		sort.Strings(got)
		if !reflect.DeepEqual(want, got) {
			t.Errorf("шаблон %s: атрибуты конструктора %v, у Send* — %v: конструктор обязан принимать каждый объявленный атрибут",
				c.template, got, want)
		}
	}
}

// TestLetterWithValuesReachesSend — близнец каждого отказа: все значения по
// форме — письмо есть, и Enqueue доводит его до Send*.
func TestLetterWithValuesReachesSend(t *testing.T) {
	q := enabledEnqueuer(t)
	for _, c := range fixtureCases(t) {
		t.Run(c.template, func(t *testing.T) {
			l, err := c.build(c.valid, false)
			if err != nil {
				t.Fatalf("законные значения отвергнуты: %v", err)
			}
			if l.Template() != c.template {
				t.Fatalf("Template() = %q, ожидалось %q", l.Template(), c.template)
			}
			reachesSend(t, q, l)
		})
	}
}

// TestLetterRefusesZeroRequiredByName — нуль каждого required атрибута —
// ошибка с его именем; письма нет. Ряд меняет ровно одно поле против близнеца.
func TestLetterRefusesZeroRequiredByName(t *testing.T) {
	refused := 0
	for _, c := range fixtureCases(t) {
		v := reflect.ValueOf(c.valid)
		for i := range v.NumField() {
			f := v.Type().Field(i)
			if f.Type == optionalType {
				continue
			}
			attr := snake(f.Name)
			t.Run(c.template+"/"+attr, func(t *testing.T) {
				mut := reflect.New(v.Type()).Elem()
				mut.Set(v)
				mut.Field(i).Set(reflect.Zero(f.Type))
				l, err := c.build(mut.Interface(), false)
				assertRefused(t, c.template, attr, l, err)
			})
			refused++
		}
	}
	t.Logf("перепись: отказов по нулю required проверено %d", refused)
	if refused == 0 {
		t.Fatalf("ни одного required атрибута не осмотрено — не вердикт")
	}
}

// TestLetterRefusesZeroRecipient — нулевой адресат: address.Normalized{} у формы
// address (причина — address.ErrUnset), пустой id у формы subject.
func TestLetterRefusesZeroRecipient(t *testing.T) {
	var byAddress, bySubject int
	for _, c := range fixtureCases(t) {
		t.Run(c.template, func(t *testing.T) {
			l, err := c.build(c.valid, true)
			assertRefused(t, c.template, "to", l, err)
			if !c.subject && !errors.Is(err, address.ErrUnset) {
				t.Fatalf("адресат формы address: причина %v — ожидалась address.ErrUnset", err)
			}
		})
		if c.subject {
			bySubject++
		} else {
			byAddress++
		}
	}
	t.Logf("перепись: шаблонов формы address %d · формы subject %d", byAddress, bySubject)
	if byAddress == 0 || bySubject == 0 {
		t.Fatalf("одна из форм адресата не осмотрена — не вердикт")
	}
}

// TestLetterOptionalForms — optional атрибут (З27: у kaname один —
// invite.inviter_address): Present("") и нулевой литерал Optional{} — ошибка с
// именем атрибута (УК48); Absent() и Present(v) — письмо доходит до Send*.
func TestLetterOptionalForms(t *testing.T) {
	q := enabledEnqueuer(t)
	optionals := 0
	for _, c := range fixtureCases(t) {
		v := reflect.ValueOf(c.valid)
		for i := range v.NumField() {
			f := v.Type().Field(i)
			if f.Type != optionalType {
				continue
			}
			optionals++
			attr := snake(f.Name)
			with := func(o mail.Optional) (mail.Letter, error) {
				mut := reflect.New(v.Type()).Elem()
				mut.Set(v)
				mut.Field(i).Set(reflect.ValueOf(o))
				return c.build(mut.Interface(), false)
			}
			t.Run(c.template+"/"+attr+"/Present(пусто)", func(t *testing.T) {
				l, err := with(mail.Present(""))
				assertRefused(t, c.template, attr, l, err)
			})
			t.Run(c.template+"/"+attr+"/нулевой литерал", func(t *testing.T) {
				l, err := with(mail.Optional{})
				assertRefused(t, c.template, attr, l, err)
			})
			t.Run(c.template+"/"+attr+"/Absent", func(t *testing.T) {
				l, err := with(mail.Absent())
				if err != nil {
					t.Fatalf("Absent() отвергнут: %v", err)
				}
				reachesSend(t, q, l)
			})
			t.Run(c.template+"/"+attr+"/Present(значение)", func(t *testing.T) {
				l, err := with(mail.Present("inviter@example.org"))
				if err != nil {
					t.Fatalf("Present(значение) отвергнут: %v", err)
				}
				reachesSend(t, q, l)
			})
		}
	}
	t.Logf("перепись: optional атрибутов %d", optionals)
	if optionals != 1 {
		t.Fatalf("optional атрибутов %d — перечень З27 называет ровно один (invite.inviter_address)", optionals)
	}
}

// assertRefused — отказ конструктора: ErrLetterInvalid, текст называет шаблон
// и атрибут, письма нет (Enqueue его не принимает).
func assertRefused(t *testing.T, template, attr string, l mail.Letter, err error) {
	t.Helper()
	if !errors.Is(err, mail.ErrLetterInvalid) {
		t.Fatalf("ожидалась mail.ErrLetterInvalid, получено %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "шаблон "+template) || !strings.Contains(msg, "атрибут "+attr+":") {
		t.Fatalf("текст отказа %q не называет шаблон %s и атрибут %s", msg, template, attr)
	}
	if l.Template() != "" {
		t.Fatalf("при отказе отдано письмо шаблона %q", l.Template())
	}
	if _, qerr := enabledEnqueuer(t).Enqueue(context.Background(), nil, l); !errors.Is(qerr, mail.ErrLetterUnbuilt) {
		t.Fatalf("письмо отказа принято Enqueue: %v", qerr)
	}
}

// feedgenSends — имена функций Send* без получателя в не-тестовых файлах
// каталога feedgen.
func feedgenSends(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	fset := token.NewFileSet()
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && strings.HasPrefix(fd.Name.Name, "Send") {
				out = append(out, fd.Name.Name)
			}
		}
	}
	return out, nil
}

// catalogTemplates — имена каталогов шаблонов (у каждого notification.yaml).
func catalogTemplates(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, e.Name(), "notification.yaml")); err != nil {
			return nil, err
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out, nil
}
