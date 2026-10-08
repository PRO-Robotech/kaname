// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

// address_in_refusal_text_injection_test.go — гейт адреса СПОСОБЕН упасть и
// способен смолчать (задача kaname#641).
//
// Инъекция подаётся НАСТОЯЩЕЙ формой из дерева: `status.Errorf(codes.NotFound,
// "subject not found by email=%s", email)` и `iamerr.Wrapf(…, "User with email
// %s not found", email)` — ровно то, что стояло до задачи. Каждая подача
// меняет ОДИН факт против своего законного близнеца: тот же приёмник с
// идентификатором вместо адреса, тот же адрес в неприёмнике, имя константы
// с «Email» в имени, маскирующий построитель.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const addressFixtureHeader = `package fixture

import (
	"context"
	"fmt"
	"log/slog"

	c "google.golang.org/grpc/codes"
	st "google.golang.org/grpc/status"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

var _ = fmt.Sprint
var _ = slog.Info
var _ = c.OK
var _ = st.Error
var _ = iamerr.Wrapf
var _ = context.Background

type Email string
type User struct{ ID, Email string }
type Event struct{ To string }
type Req struct{}

func (Req) GetEmail() string { return "" }

const TextEmailInUse = "address already in use"

func mapErr(err error, kind, hint string) error { return err }
func maskAddress(s string) slog.Attr { return slog.String("address", "set") }
`

func scanAddressFixture(t *testing.T, body string) (check.AddressCensus, []check.AddressFinding) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "fixture.go")
	if err := os.WriteFile(p, []byte(addressFixtureHeader+body), 0o600); err != nil {
		t.Fatalf("подача НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	census, findings, err := check.ScanAddressInRefusalText(dir, []string{p})
	if err != nil {
		t.Fatalf("подача НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	if census.Files != 1 {
		t.Fatalf("подача НЕ ИСПОЛНЯЛАСЬ: разобрано файлов %d, ожидался 1", census.Files)
	}
	return census, findings
}

func TestAddressGateInjection_DefectIsFoundTwinIsSilent(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		body   string
		found  bool
		form   string
		expect string // подстрока находки — ЧТО именно названо
	}{
		{
			name: "дефект: статус с адресом (псевдоним импорта)", found: true, form: check.FormAddressIdent,
			body:   `func f(email string) error { return st.Errorf(c.NotFound, "subject not found by email=%s", email) }`,
			expect: "Errorf (отказ)",
		},
		{
			name: "близнец: тот же статус с идентификатором", found: false,
			body: `func f(id string) error { return st.Errorf(c.NotFound, "subject %s not found", id) }`,
		},
		{
			name: "дефект: Wrapf репозитория с адресом", found: true, form: check.FormAddressIdent,
			body:   `func f(email Email) error { return iamerr.Wrapf(nil, "User with email %s not found", email) }`,
			expect: "Wrapf (отказ)",
		},
		{
			name: "дефект: поле адреса в приведении", found: true, form: check.FormAddressField,
			body:   `func f(u User) error { return fmt.Errorf("user %s", string(u.Email)) }`,
			expect: "u.Email",
		},
		{
			name: "близнец: поле идентификатора той же структуры", found: false,
			body: `func f(u User) error { return fmt.Errorf("user %s", string(u.ID)) }`,
		},
		{
			name: "дефект: геттер адреса в журнале", found: true, form: check.FormAddressField,
			body:   `func f(ctx context.Context, l *slog.Logger, r Req) { l.InfoContext(ctx, "lookup", "email", r.GetEmail()) }`,
			expect: "журнал",
		},
		{
			name: "дефект: получатель письма в журнале пакета", found: true, form: check.FormAddressField,
			body:   `func f(ev Event) { slog.Warn("send failed", "to", ev.To) }`,
			expect: "ev.To",
		},
		{
			name: "дефект: адрес подсказкой переводчика", found: true, form: check.FormAddressIdent,
			body:   `func f(err error, email string) error { return mapErr(err, "", email) }`,
			expect: "подсказка",
		},
		{
			name: "близнец: переводчик с идентификатором", found: false,
			body: `func f(err error, id string) error { return mapErr(err, "", id) }`,
		},
		{
			name: "дефект: адрес сквозь прозрачную функцию", found: true, form: check.FormAddressIdent,
			body:   `func f(newEmail string) error { return fmt.Errorf("x %s", fmt.Sprintf("<%s>", newEmail)) }`,
			expect: "newEmail",
		},
		{
			name: "близнец: константа с Email в имени", found: false,
			body: `func f() error { return fmt.Errorf("%s", TextEmailInUse) }`,
		},
		{
			name: "близнец: адрес вне приёмника", found: false,
			body: `func f(email string) string { return fmt.Sprintf("%s", email) }`,
		},
		{
			name: "близнец: маскирующий построитель (непрозрачен)", found: false,
			body: `func f(email string) { slog.Info("starting", maskAddress(email)) }`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			census, findings := scanAddressFixture(t, tc.body)
			if census.Sinks["отказ"]+census.Sinks["журнал"]+census.Sinks["подсказка"] == 0 {
				t.Fatalf("подача НЕ ИСПОЛНЯЛАСЬ: ни одного приёмника в подаче")
			}
			if !tc.found {
				if len(findings) != 0 {
					t.Fatalf("законный близнец дал находку: %v", findings)
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("дефект не найден ровно один раз: %v", findings)
			}
			f := findings[0]
			if f.Form != tc.form {
				t.Fatalf("форма названа %q, ожидалась %q: %s", f.Form, tc.form, f)
			}
			if !strings.Contains(f.String(), tc.expect) || f.Line == 0 || f.File != "fixture.go" {
				t.Fatalf("находка не называет %q с координатой: %s", tc.expect, f)
			}
		})
	}
}

func TestAddressGateInjection_OpaqueCallIsCountedNotSilent(t *testing.T) {
	t.Parallel()
	census, findings := scanAddressFixture(t,
		`func f(email string) { slog.Info("starting", maskAddress(email)) }`)
	if len(findings) != 0 {
		t.Fatalf("маскирующий построитель объявлен находкой: %v", findings)
	}
	if len(census.Opaque) != 1 || !strings.Contains(census.Opaque[0], "maskAddress") {
		t.Fatalf("непрозрачный вызов с адресом не напечатан переписью: %v", census.Opaque)
	}
}
