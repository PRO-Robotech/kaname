// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

// speaker_classes_test.go — набор глаголов фильтра класса в SQL равен правилу
// домена (kaname#829, Р4, SC-23). Два написания одного правила разошлись бы
// молча: одна сторона дала бы классу глагол, которого другая не даёт.

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestSystemClass_VerbFilterMatchesTheDomainRule(t *testing.T) {
	m := regexp.MustCompile(`'\{([a-z,]+)\}'`).FindStringSubmatch(classVerbFilterSQL)
	if m == nil {
		t.Fatalf("набор глаголов в фильтре класса не найден: %s", classVerbFilterSQL)
	}
	verbs := strings.Split(m[1], ",")
	for _, v := range verbs {
		if !domain.IsClassReadVerb(v) {
			t.Errorf("фильтр SQL даёт классу %q, домен — нет", v)
		}
	}
	for _, v := range []string{"get", "list", "create", "update", "delete", "*"} {
		if domain.IsClassReadVerb(v) != slices.Contains(verbs, v) {
			t.Errorf("глагол %q: домен %v, фильтр SQL %v", v, domain.IsClassReadVerb(v), slices.Contains(verbs, v))
		}
	}
	// Каждая ветвь выдач несёт фильтр: четыре соединения с проекцией глаголов.
	forms := map[string]string{}
	for _, nesting := range []bool{false, true} {
		forms["вопрос, "+nestingName(nesting)] = mustAssemble(withNesting(verdictQuerySQL, nesting))("")
		forms["страница, "+nestingName(nesting)] = mustAssemble(withNesting(verdictManyQuerySQL, nesting))("")
		forms["перечень, "+nestingName(nesting)] = mustAssemble(withNesting(listQuerySQL, nesting))("")
	}
	for name, sql := range forms {
		if !strings.Contains(sql, classVerbFilterSQL) {
			t.Errorf("форма «%s»: ветвь выдач без фильтра класса", name)
		}
		if !strings.Contains(sql, "'system_class', $10::text") || !strings.Contains(sql, "'system_class', $11::text") {
			t.Errorf("форма «%s»: классы говорящего не приходят параметрами", name)
		}
		if strings.Contains(sql, "'user:*'") || strings.Contains(sql, "'wildcard'") {
			t.Errorf("форма «%s»: безусловная подстановка не снята", name)
		}
	}
}

// TestSystemClass_ClassSlotsCarryEveryClass — двух слотов хватает на всё, что
// отдаёт производитель классов: слот, которого нет, потерял бы класс молча.
func TestSystemClass_ClassSlotsCarryEveryClass(t *testing.T) {
	for _, sp := range []string{"user:usr-1", "service_account:sva-1", "system_class:anonymous", "user:*", "group:g#member"} {
		classes := domain.SpeakerClasses(sp)
		if len(classes) > 2 {
			t.Fatalf("классов у %q %d, слотов 2", sp, len(classes))
		}
		var got []string
		for i := 0; i < 2; i++ {
			if c := classSlot(sp, i); c != "" {
				got = append(got, string(domain.SubjectTypeSystemClass)+":"+c)
			}
		}
		if !slices.Equal(got, classes) && !(len(got) == 0 && len(classes) == 0) {
			t.Errorf("слоты %q = %v, классы %v", sp, got, classes)
		}
	}
}

// TestSpeakerClass_EachFormDerivesItOnlyForAnExistingPrincipal — класс
// говорящего выводится лишь при живой строке учётки, на каждой из трёх форм
// (kaname#909): классы положены говорящему с личностью (Р2), а личность —
// строка учётки, а не вид записи.
//
// Предмет судится текстом СОБРАННОЙ формы: обе строки класса в паре колонок
// несут предикат существования, а текстовая форма берёт классы из пары, а не
// вторым написанием параметров. Виды, которым производитель классов
// (`domain.SpeakerClasses`) их отдаёт, названы предикатом поимённо со своей
// таблицей: вид, получивший классы без таблицы, — находка.
func TestSpeakerClass_EachFormDerivesItOnlyForAnExistingPrincipal(t *testing.T) {
	tableOf := map[domain.SubjectType]string{
		domain.SubjectTypeUser:           "kaname.users",
		domain.SubjectTypeServiceAccount: "kaname.service_accounts",
	}
	kinds := []domain.SubjectType{
		domain.SubjectTypeUser, domain.SubjectTypeServiceAccount,
		domain.SubjectTypeGroup, domain.SubjectTypeSystemClass,
	}
	guardedRow := regexp.MustCompile(`'system_class', \$1[01]::text, 'class'\s+WHERE\s`)
	bareTextRow := regexp.MustCompile(`'system_class:' \|\| \$1[01]::text`)

	forms := map[string]string{}
	for _, nesting := range []bool{false, true} {
		forms["вопрос, "+nestingName(nesting)] = mustAssemble(withNesting(verdictQuerySQL, nesting))("")
		forms["страница, "+nestingName(nesting)] = mustAssemble(withNesting(verdictManyQuerySQL, nesting))("")
		forms["перечень, "+nestingName(nesting)] = mustAssemble(withNesting(listQuerySQL, nesting))("")
	}
	if len(forms) != 6 {
		t.Fatalf("форм осмотрено %d, ждали 6", len(forms))
	}
	for name, sql := range forms {
		if n := len(guardedRow.FindAllString(sql, -1)); n != 2 {
			t.Errorf("форма «%s»: строк класса под предикатом существования %d, ждали 2", name, n)
		}
		if bareTextRow.MatchString(sql) {
			t.Errorf("форма «%s»: текстовая форма выводит класс из параметра, минуя предикат существования", name)
		}
		for _, kind := range kinds {
			if len(domain.SpeakerClasses(string(kind)+":x")) == 0 {
				continue
			}
			table, ok := tableOf[kind]
			if !ok {
				t.Errorf("форма «%s»: вид %s получает классы, а таблицы существования у предиката нет", name, kind)
				continue
			}
			if !strings.Contains(sql, "= '"+string(kind)+"'") || !strings.Contains(sql, "FROM "+table) {
				t.Errorf("форма «%s»: вид %s получает классы без проверки строки в %s", name, kind, table)
			}
		}
	}
}
