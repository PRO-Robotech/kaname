// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// delete_hint_injection_test.go — доказательство, что гейт подсказок СПОСОБЕН
// упасть и способен смолчать. Вход синтетический (проба на живом дефекте
// исчезает вместе с ним); оси проверяются по одной.

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func auditSource(t *testing.T, src string) (int, int, []string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("синтетика не разобрана: %v", err)
	}
	return auditDeleteHints(fset, f)
}

func TestDeleteHintGateInjection(t *testing.T) {
	t.Run("инъекция: снимающий метод с пустой подсказкой — находка", func(t *testing.T) {
		_, deleting, found := auditSource(t, `package p
func mapErr(err error, kind, id string) error { return err }
func (r *Repo) Delete(id string) error { return mapErr(nil, "", id) }
`)
		if deleting != 1 {
			t.Fatalf("снимающих вызовов насчитано %d, ожидался 1", deleting)
		}
		if len(found) != 1 || !strings.Contains(found[0], "Delete") {
			t.Fatalf("гейт не назвал метод без подсказки: %v", found)
		}
	})

	t.Run("контроль: тот же метод С подсказкой — молчание", func(t *testing.T) {
		_, deleting, found := auditSource(t, `package p
func mapErr(err error, kind, id string) error { return err }
func (r *Repo) Delete(id string) error { return mapErr(nil, "Project.Delete", id) }
`)
		if deleting != 1 {
			t.Fatalf("снимающих вызовов насчитано %d, ожидался 1", deleting)
		}
		if len(found) != 0 {
			t.Fatalf("гейт краснеет на верной подсказке: %v", found)
		}
	})

	t.Run("контроль: уточнённый глагол снятия принимается", func(t *testing.T) {
		// `DeleteOwnedByID`, `DeleteExpired`, `RemoveMember` — законные формы.
		// Точное равенство глаголу объявляло бы их не снимающими и отдавало бы
		// клиенту текст чужой стороны там, где подсказка передана верно.
		_, _, found := auditSource(t, `package p
func mapErr(err error, kind, id string) error { return err }
func (r *Repo) DeleteExpired() error { return mapErr(nil, "SessionRevocation.DeleteExpired", "") }
func (r *Repo) RemoveMember(id string) error { return mapErr(nil, "Group.RemoveMember", id) }
`)
		if len(found) != 0 {
			t.Fatalf("уточнённый глагол отвергнут: %v", found)
		}
	})

	t.Run("контроль: НЕснимающий метод с пустой подсказкой — молчание", func(t *testing.T) {
		_, deleting, found := auditSource(t, `package p
func mapErr(err error, kind, id string) error { return err }
func (r *Repo) Get(id string) error { return mapErr(nil, "", id) }
func (r *Repo) Insert(id string) error { return mapErr(nil, "", id) }
`)
		if deleting != 0 {
			t.Fatalf("чтение и вставка зачтены снимающими: %d", deleting)
		}
		if len(found) != 0 {
			t.Fatalf("гейт краснеет на чтении и вставке: %v", found)
		}
	})

	t.Run("инъекция: подсказка без глагола вовсе — находка", func(t *testing.T) {
		_, _, found := auditSource(t, `package p
func mapErr(err error, kind, id string) error { return err }
func (r *Repo) Delete(id string) error { return mapErr(nil, "Project", id) }
`)
		if len(found) != 1 {
			t.Fatalf("подсказка без глагола прошла: %v", found)
		}
	})

	t.Run("инъекция: подсказка с ЧУЖИМ глаголом — находка", func(t *testing.T) {
		// Скопированная у соседа подсказка «по аналогии» — самый частый способ
		// получить верный на вид вызов с неверной стороной.
		_, _, found := auditSource(t, `package p
func mapErr(err error, kind, id string) error { return err }
func (r *Repo) Delete(id string) error { return mapErr(nil, "Project.Update", id) }
`)
		if len(found) != 1 {
			t.Fatalf("чужой глагол прошёл: %v", found)
		}
	})

	t.Run("контроль: вычисляемая подсказка не судится", func(t *testing.T) {
		// Автор передаёт её осознанно; литерала нет, судить нечего — и молчание
		// здесь названо ГРАНИЦЕЙ, а не покрытием.
		_, _, found := auditSource(t, `package p
func mapErr(err error, kind, id string) error { return err }
func (r *Repo) Delete(kind, id string) error { return mapErr(nil, kind, id) }
`)
		if len(found) != 0 {
			t.Fatalf("вычисляемая подсказка объявлена находкой: %v", found)
		}
	})
}
