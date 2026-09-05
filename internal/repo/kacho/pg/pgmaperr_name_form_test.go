// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// pgmaperr_name_form_test.go — полоса ФОРМЫ ИМЕНИ отделена от прочих проверок
// таблицы (задача #1279; тот же разбор, что #718 в vpc/storage/nlb).
//
// Предмет. Ограничение таблицы на форму имени — защита ПОСЛЕДНЕГО РУБЕЖА: форму
// проверяет сам сервис, до вставки, на каждом из шести именуемых типов. Значит
// срабатывание ограничения означает не «вызывающий прислал негодное имя», а
// «сервис пропустил негодное значение» — НАШ дефект. `INVALID_ARGUMENT` здесь
// обвинял бы вызывающего в чужой ошибке и не давал бы ему ничего, что можно
// исправить.
//
// Отдельная и не менее важная половина: прежний текст отказа ВЫПИСЫВАЛ форму
// (`^[a-z][-a-z0-9]{2,62}$`). Такой текст переживает смену формы молча — он и
// пережил бы её здесь, посылая арендатора чинить имя по правилу, которого в
// дереве нет.

import (
	stderrors "errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

// nameFormTables — таблицы, которым миграция 715001 поставила форму имени.
// Выписаны, а не выведены: предикат назван в самой миграции, и перепись ниже
// печатает, сколько их осмотрено.
var nameFormTables = []string{
	"accounts", "projects", "groups", "service_accounts", "interactive_clients",
}

// TestWrapPgErr_NameForm_IsOurDefectNotCallerInput — полоса формы имени.
func TestWrapPgErr_NameForm_IsOurDefectNotCallerInput(t *testing.T) {
	for _, tbl := range nameFormTables {
		t.Run(tbl, func(t *testing.T) {
			pgErr := &pgconn.PgError{
				Code:           "23514",
				ConstraintName: tbl + "_name_check",
				TableName:      tbl,
				Message:        secretMessage,
				Detail:         secretDetail,
			}
			err := wrapPgErr(pgErr, "", "")

			if stderrors.Is(err, iamerr.ErrInvalidArg) {
				t.Fatalf("отказ формы имени объявлен ошибкой ВВОДА — вызывающий обвинён "+
					"в нашем дефекте: %v", err)
			}
			if !stderrors.Is(err, iamerr.ErrInternal) {
				t.Fatalf("want ErrInternal, got %v", err)
			}
			out := iamerr.StripSentinel(err)
			if strings.Contains(out, "[-a-z0-9]") || strings.Contains(out, "a-z0-9]") {
				t.Errorf("текст отказа ВЫПИСЫВАЕТ форму (%q) — он переживёт её смену молча", out)
			}
			assertNoLeak(t, out)
		})
	}
	t.Logf("осмотрено таблиц с формой имени: %d — %s",
		len(nameFormTables), strings.Join(nameFormTables, ", "))
}

// TestWrapPgErr_OtherCheck_StaysCallerInput — положительный контроль.
//
// Без него утверждение выше зеленело бы и на отображении, объявляющем НАШИМ
// дефектом всякую проверку таблицы: тогда арендатор перестал бы узнавать, что
// именно во вводе неверно, а полоса «ввод» исчезла бы целиком.
func TestWrapPgErr_OtherCheck_StaysCallerInput(t *testing.T) {
	cases := []struct{ constraint, wantIn string }{
		{"accounts_description_check", "description"},
		{"users_email_check", "email"},
		{"users_display_name_check", "display_name"},
	}
	for _, c := range cases {
		t.Run(c.constraint, func(t *testing.T) {
			pgErr := &pgconn.PgError{
				Code:           "23514",
				ConstraintName: c.constraint,
				TableName:      "accounts",
				Message:        secretMessage,
				Detail:         secretDetail,
			}
			err := wrapPgErr(pgErr, "", "")
			if !stderrors.Is(err, iamerr.ErrInvalidArg) {
				t.Fatalf("проверка НЕ формы имени обязана остаться отказом по вводу, got %v", err)
			}
			out := iamerr.StripSentinel(err)
			if !strings.Contains(out, c.wantIn) {
				t.Errorf("отказ обязан называть поле %q, got %q", c.wantIn, out)
			}
			assertNoLeak(t, out)
		})
	}
	t.Logf("осмотрено проверок НЕ формы имени: %d", len(cases))
}

// TestWrapPgErr_NameFormLaneIsNamedByConstraint_NotBySuffix — предпосылка
// разбора полос.
//
// Полоса опознаётся ТОЧНЫМ сравнением `<таблица>_name_check`, а не суффиксом:
// `users_display_name_check` кончается ровно так же, но сторожит длину другого
// поля. Проверка по суффиксу объявила бы его нашим дефектом и лишила бы
// арендатора внятного отказа — молча.
func TestWrapPgErr_NameFormLaneIsNamedByConstraint_NotBySuffix(t *testing.T) {
	pgErr := &pgconn.PgError{
		Code:           "23514",
		ConstraintName: "users_display_name_check",
		TableName:      "users",
		Message:        secretMessage,
	}
	err := wrapPgErr(pgErr, "", "")
	if !stderrors.Is(err, iamerr.ErrInvalidArg) {
		t.Fatalf("ловушка суффиксного предиката: `users_display_name_check` "+
			"опознан как форма имени, got %v", err)
	}
}
