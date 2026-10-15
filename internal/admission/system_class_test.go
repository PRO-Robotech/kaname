// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package admission

// system_class_test.go — допуск не судит системный класс (kaname#829, разбор
// CE-05): класс человеком не является ПО ВИДУ, и вопроса к хранилищу о нём нет.

import (
	"context"
	"testing"
)

// scMarks — хранилище отметок, считающее вопросы: класс не должен спрашивать.
type scMarks struct{ asked int }

func (m *scMarks) PersonMarks(_ context.Context, ids []string) (map[string]bool, error) {
	m.asked++
	out := map[string]bool{}
	for _, id := range ids {
		out[id] = false // всякий названный — человек с неподтверждённым адресом
	}
	return out, nil
}

func TestSystemClass_AdmissionDoesNotJudgeAClass(t *testing.T) {
	for _, s := range []string{"system_class:anonymous", "system_class:authenticated"} {
		if _, ok := SubjectID(s); ok {
			t.Errorf("SubjectID(%q): класс назван человеком", s)
		}
		m := &scMarks{}
		ok, err := Subject(context.Background(), m, s)
		if err != nil || !ok || m.asked != 0 {
			t.Errorf("Subject(%q) = %v, %v, вопросов к хранилищу %d — класс допуском не судится", s, ok, err, m.asked)
		}
	}
	// Близнец: человек с неподтверждённым адресом — отказ, как сегодня.
	m := &scMarks{}
	ok, err := Subject(context.Background(), m, "user:usr-1")
	if err != nil || ok || m.asked != 1 {
		t.Errorf("Subject(user:usr-1) = %v, %v, вопросов %d — ждали отказ одним вопросом", ok, err, m.asked)
	}
}
