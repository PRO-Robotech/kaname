// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

import (
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// Отказ FK по роли называет РОЛЬ, а не всю подсказку (issue #105).
//
// Подсказку составляет access_binding.Insert — единственное место, где под рукой
// сразу субъект, область и роль. Прежде ветвь FK печатала её целиком, и вызывающий
// получал «Role <субъект>|project:<область> not found»: сообщение называло сущности,
// о которых он не спрашивал, и НЕ называло ту, из-за которой отказ. Тексты отказов —
// часть контракта (api-conventions.md §Error-format), поэтому проверяется ТЕКСТ,
// а не код: на одном коде дефект остаётся невидимым.
func TestFKRoleTextNamesTheRoleNotTheWholeHint(t *testing.T) {
	const (
		subject = "usr7h3n9k2m5p8q1r5"
		scope   = "project:prj7h3n9k2m5p8q1"
		role    = "rol9x2k4m8p0q1r5t7"
	)
	hint := subject + "|" + scope + "|" + role

	got, _ := fkText(&pgconn.PgError{ConstraintName: "access_bindings_role_fk"}, "", hint)

	want := "Role " + role + " not found"
	if got != want {
		t.Fatalf("текст отказа называет не роль:\n  получено: %q\n  ожидалось: %q", got, want)
	}
	// Отрицание в паре с положительным: сообщение не вправе называть то, о чём
	// вызывающий не спрашивал, — иначе он уйдёт искать причину не там.
	for _, foreign := range []string{subject, scope} {
		if containsSub(got, foreign) {
			t.Errorf("в тексте отказа осталась чужая сущность %q: %q", foreign, got)
		}
	}
}

// Обратное направление той же связи не затронуто: удаление роли, на которую ещё
// ссылаются выдачи, говорит про использование, а не про «не найдена».
func TestFKRoleDeleteDirectionUnchanged(t *testing.T) {
	got, _ := fkText(&pgconn.PgError{ConstraintName: "access_bindings_role_fk"}, "Role.Delete", "anything")
	if got != "role is in use by access bindings" {
		t.Fatalf("направление DELETE изменилось: %q", got)
	}
}

// Короткая форма подсказки (без роли) и форма без разделителей вовсе не ломают
// потребителей: mapErr зовут из 190 мест, и не все они про выдачу.
func TestBindingHintSplitTolerantToShortForms(t *testing.T) {
	cases := []struct{ in, subj, scope, role string }{
		{"", "", "", ""},
		{"usr1", "usr1", "", ""},
		{"usr1|project:prj1", "usr1", "project:prj1", ""},
		{"usr1|project:prj1|rol1", "usr1", "project:prj1", "rol1"},
	}
	for _, c := range cases {
		s, sc, r := splitBindingHint(c.in)
		if s != c.subj || sc != c.scope || r != c.role {
			t.Errorf("splitBindingHint(%q) = (%q,%q,%q), ожидалось (%q,%q,%q)",
				c.in, s, sc, r, c.subj, c.scope, c.role)
		}
	}

	// Текст UNIQUE продолжает называть субъекта и область — то есть добавление
	// третьего слота не сломало первого потребителя.
	// Имя ключа — живое (`access_bindings_active_grant_uniq`, миграция 0003).
	// Прежде здесь стояло снятое ею `access_bindings_unique`: проба закрепляла
	// текст на имени, которого сервер не назовёт, и оставалась зелёной.
	got := uniqueText(&pgconn.PgError{ConstraintName: "access_bindings_active_grant_uniq"}, "", "usr1|project:prj1|rol1")
	want := "these permissions are already granted to usr1 on project:prj1"
	if got != want {
		t.Fatalf("текст UNIQUE сломан третьим слотом:\n  получено: %q\n  ожидалось: %q", got, want)
	}
}

func containsSub(s, sub string) bool {
	if sub == "" {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
