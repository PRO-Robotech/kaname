// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// pgmaperr_login_method_test.go — перевод отказов хранилища способа входа
// (фаза Ф2, `kacho#1268`; F4d-14: «ALREADY_EXISTS … с контрактным тоном отказа»).
//
// Предмет — ТЕКСТ и ПОЛОСА каждого из четырёх ограничений новой таблицы, и одна
// гарантия сверх них: материал не уезжает в отказ ни в каком виде. Сервер
// кладёт строку целиком в `Detail` нарушения проверки («Failing row contains
// …»), а строка несёт материал. Переводчик `Detail` не читает — здесь это
// утверждается входом, в котором материал лежит именно там.

import (
	stderrors "errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// lmMaterialInDetail — материал так, как его положил бы сервер в `Detail`.
const lmMaterialInDetail = "$2a$12$DETAIL.login.material.must.not.surface"

func lmPgErr(code, constraint string) *pgconn.PgError {
	return &pgconn.PgError{
		Code:           code,
		ConstraintName: constraint,
		TableName:      "user_login_methods",
		Message:        `new row for relation "user_login_methods" violates check constraint "` + constraint + `"`,
		Detail:         "Failing row contains (usr0000000000000lm01, password, " + lmMaterialInDetail + ", 2026-09-15).",
	}
}

func requireNoMaterial(t *testing.T, err error) {
	t.Helper()
	for _, s := range []string{lmMaterialInDetail, "DETAIL.login.material", "Failing row"} {
		if strings.Contains(err.Error(), s) {
			t.Fatalf("отказ несёт материал либо строку целиком (%q): %v", s, err)
		}
	}
}

func TestWrapPgErr_LoginMethodDuplicateIsAlreadyExistsInContractTone(t *testing.T) {
	hint := loginMethodHint("usr0000000000000lm01", domain.LoginMethodPassword)
	err := wrapPgErr(lmPgErr("23505", "user_login_methods_pkey"), "LoginMethod.Create", hint)
	if !stderrors.Is(err, iamerr.ErrAlreadyExists) {
		t.Fatalf("F4d-14: второй способ того же вида обязан отвечать ALREADY_EXISTS, получено %v", err)
	}
	if got := iamerr.StripSentinel(err); got != "Login method password of user usr0000000000000lm01 already exists" {
		t.Fatalf("контрактный тон отказа не тот: %q", got)
	}
	requireNoMaterial(t, err)
}

func TestWrapPgErr_LoginMethodOfAMissingPersonIsReferenceMissing(t *testing.T) {
	hint := loginMethodHint("usr0000000000000nobody", domain.LoginMethodPassword)
	err := wrapPgErr(lmPgErr("23503", "user_login_methods_user_fk"), "LoginMethod.Create", hint)
	if !stderrors.Is(err, iamerr.ErrReferenceMissing) || !stderrors.Is(err, iamerr.ErrFailedPrecondition) {
		t.Fatalf("способ несуществующего человека обязан отвечать полосой ссылки (FAILED_PRECONDITION), получено %v", err)
	}
	if got := iamerr.StripSentinel(err); got != "User usr0000000000000nobody not found" {
		t.Fatalf("текст обязан называть человека, а не подсказку целиком: %q", got)
	}
	requireNoMaterial(t, err)
}

// TestWrapPgErr_LoginMethodBackstopIsOurDefect — вид и непустоту материала
// судит ТИП до вставки. Значит срабатывание ограничения таблицы означает «сервис
// пропустил негодное значение», а не «вызывающий прислал негодное»: материал
// вызывающий не присылает вовсе — его производит служба.
func TestWrapPgErr_LoginMethodBackstopIsOurDefect(t *testing.T) {
	for _, c := range []string{"user_login_methods_kind_check", "user_login_methods_verifier_check"} {
		t.Run(c, func(t *testing.T) {
			err := wrapPgErr(lmPgErr("23514", c), "LoginMethod.Create", "")
			if stderrors.Is(err, iamerr.ErrInvalidArg) {
				t.Fatalf("последний рубеж объявлен ошибкой ввода — вызывающий обвинён в нашем дефекте: %v", err)
			}
			if !stderrors.Is(err, iamerr.ErrInternal) {
				t.Fatalf("want ErrInternal, got %v", err)
			}
			requireNoMaterial(t, err)
		})
	}

	// Положительный контроль: чужая проверка той же формы остаётся полосой
	// ВВОДА — иначе утверждение выше зеленело бы на переводчике, объявляющем
	// нашим дефектом всякую проверку.
	err := wrapPgErr(&pgconn.PgError{Code: "23514", ConstraintName: "users_email_check", TableName: "users"}, "", "")
	if !stderrors.Is(err, iamerr.ErrInvalidArg) {
		t.Fatalf("положительный контроль: проверка адреса обязана остаться ошибкой ввода, получено %v", err)
	}
}

func TestLoginMethodHintCarriesNoMaterialAndSplitsBack(t *testing.T) {
	h := loginMethodHint("usr0000000000000lm01", domain.LoginMethodPassword)
	user, kind := splitLoginMethodHint(h)
	if user != "usr0000000000000lm01" || kind != "password" {
		t.Fatalf("подсказка не разбирается обратно: %q → (%q, %q)", h, user, kind)
	}
	// Короткая форма (подсказка от чужого места вызова) не ломает разбор.
	user, kind = splitLoginMethodHint("usr0000000000000lm02")
	if user != "usr0000000000000lm02" || kind != "" {
		t.Fatalf("короткая форма: (%q, %q)", user, kind)
	}
}
