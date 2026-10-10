// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package mailkey_test

import (
	"errors"
	"testing"

	"github.com/PRO-Robotech/corelib/notify/address"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/mailkey"
)

// normalized — значение из Normalize, единственного производителя непустого
// address.Normalized; отказ разбора — несозданное условие пробы, а не красное.
func normalized(t *testing.T, raw string) address.Normalized {
	t.Helper()
	n, err := address.Normalize(raw)
	if err != nil {
		t.Fatalf("фикстура: Normalize(%q): %v", raw, err)
	}
	return n
}

// TestZeroNormalizedGivesNoKey — нулевое address.Normalized ключом не
// становится ни у одной производной (замысел З11, §0.2 О1; И28): ошибка —
// mailkey.ErrUnset, и errors.Is находит в ней address.ErrUnset. Близнец —
// значение из Normalize даёт ключ у обеих производных.
func TestZeroNormalizedGivesNoKey(t *testing.T) {
	var zero address.Normalized

	acc, err := mailkey.Account(zero)
	if !errors.Is(err, mailkey.ErrUnset) || !errors.Is(err, address.ErrUnset) {
		t.Fatalf("Account(нуль): ошибка %v — ожидалась mailkey.ErrUnset с причиной address.ErrUnset", err)
	}
	if v, verr := acc.Value(); verr == nil || v != "" {
		t.Fatalf("Account(нуль) отдал ключ %q (ошибка чтения %v) — ключа «пустого адреса» быть не должно", v, verr)
	}
	abuse, err := mailkey.Abuse(zero)
	if !errors.Is(err, mailkey.ErrUnset) || !errors.Is(err, address.ErrUnset) {
		t.Fatalf("Abuse(нуль): ошибка %v — ожидалась mailkey.ErrUnset с причиной address.ErrUnset", err)
	}
	if v, verr := abuse.Value(); verr == nil || v != "" {
		t.Fatalf("Abuse(нуль) отдал ключ %q (ошибка чтения %v)", v, verr)
	}

	// Близнец: тот же вызов на значении из Normalize — ключ есть у обеих.
	n := normalized(t, "Owner@example.org")
	acc, err = mailkey.Account(n)
	if err != nil {
		t.Fatalf("близнец Account: %v", err)
	}
	if v, verr := acc.Value(); verr != nil || v != "owner@example.org" {
		t.Fatalf("близнец Account: ключ %q, ошибка %v", v, verr)
	}
	abuse, err = mailkey.Abuse(n)
	if err != nil {
		t.Fatalf("близнец Abuse: %v", err)
	}
	if v, verr := abuse.Value(); verr != nil || v != "owner@example.org" {
		t.Fatalf("близнец Abuse: ключ %q, ошибка %v", v, verr)
	}
}

// TestZeroKeyLiteralIsNotAKey — ключ, построенный литералом мимо производных,
// значения не отдаёт: нулевой ключ читается ошибкой, а не пустой строкой.
func TestZeroKeyLiteralIsNotAKey(t *testing.T) {
	if v, err := (mailkey.AccountKey{}).Value(); !errors.Is(err, mailkey.ErrUnset) || v != "" {
		t.Fatalf("AccountKey{}: %q, %v — ожидалась ErrUnset", v, err)
	}
	if v, err := (mailkey.AbuseKey{}).Value(); !errors.Is(err, mailkey.ErrUnset) || v != "" {
		t.Fatalf("AbuseKey{}: %q, %v — ожидалась ErrUnset", v, err)
	}
}

// TestDerivations — правила двух производных (З11, CX2-20): Account — локальная
// часть в нижнем регистре, домен как есть (A-label из Normalize), «+метка»
// сохраняется; Abuse — то же без «+метки». Строка таблицы меняет один факт.
func TestDerivations(t *testing.T) {
	cases := []struct {
		name, raw, account, abuse string
	}{
		{"нижний регистр как есть", "owner@example.org", "owner@example.org", "owner@example.org"},
		{"регистр локальной части", "OwNeR@example.org", "owner@example.org", "owner@example.org"},
		{"регистр домена сведён Normalize", "owner@EXAMPLE.org", "owner@example.org", "owner@example.org"},
		{"+метка: Account хранит, Abuse снимает", "Owner+news@example.org", "owner+news@example.org", "owner@example.org"},
		{"две «+» — снимается от первой", "a+b+c@example.org", "a+b+c@example.org", "a@example.org"},
		{"«+» первым знаком — ящик сам по себе", "+tag@example.org", "+tag@example.org", "+tag@example.org"},
		{"IDN-домен — A-label", "user@пример.рф", "user@xn--e1afmkfd.xn--p1ai", "user@xn--e1afmkfd.xn--p1ai"},
		{"«@» в локальной части — разделитель последний", `"a@b"@example.org`, `"a@b"@example.org`, `"a@b"@example.org`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := normalized(t, c.raw)
			acc, err := mailkey.Account(n)
			if err != nil {
				t.Fatalf("Account: %v", err)
			}
			if v, err := acc.Value(); err != nil || v != c.account {
				t.Fatalf("Account(%q) = %q (%v), ожидалось %q", c.raw, v, err, c.account)
			}
			abuse, err := mailkey.Abuse(n)
			if err != nil {
				t.Fatalf("Abuse: %v", err)
			}
			if v, err := abuse.Value(); err != nil || v != c.abuse {
				t.Fatalf("Abuse(%q) = %q (%v), ожидалось %q", c.raw, v, err, c.abuse)
			}
		})
	}
}
