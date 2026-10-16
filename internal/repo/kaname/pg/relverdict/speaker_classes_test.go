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
	for name, sql := range map[string]string{
		"вопрос": verdictQuerySQL(""), "страница": verdictManyQuerySQL(""), "перечень": listQuerySQL(""),
	} {
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
