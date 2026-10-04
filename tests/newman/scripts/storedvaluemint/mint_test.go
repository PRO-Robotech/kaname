// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mint_test.go — значение, которое строит посев, ЧИТАЕТСЯ проверяющим продукта.
//
// # Предмет
//
// Посев хранимых значений (`tests/authz-fixtures/seed_stored_value.py`) кладёт в
// хранилище стенда значение, построенное библиотекой. Сквозной кейс по нему
// утверждает «вход проходит на формате A (B)». Если форма значения разошлась с
// той, что читает проверяющий, кейс краснел бы находкой о продукте, которого
// никто не ломал, — либо, хуже, зеленел бы на значении, которое продукт читает
// не тем форматом. Поэтому форма сверяется ЗДЕСЬ, без стенда, тем же
// проверяющим, что стоит на полосе входа (`passwordverify.Verifier.Verify`).
//
// # Пара на каждой оси
//
// «Верный пароль совпал» без близнеца прошёл бы у проверяющего, отвечающего
// «совпал» на всё. Поэтому у каждого формата — неверный пароль, и он обязан дать
// «не совпал»; и признак формата, по которому читали, назван перечнем продукта.
// Отказ построить пустой пароль и неизвестный формат — тоже исход, а не значение.
package main

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

type silentObserver struct{}

func (silentObserver) VerificationObserved(passwordverify.Outcome) {}

func verifierForTest(t *testing.T) *passwordverify.Verifier {
	t.Helper()
	v, err := passwordverify.New(1, silentObserver{})
	if err != nil {
		t.Fatalf("проверяющий не собран: %v", err)
	}
	return v
}

func TestMintedStoredValueIsReadByTheProductVerifier(t *testing.T) {
	const password = "stand-seeded-Q9-password"
	cases := []struct {
		name   string
		p      params
		prefix string
		format domain.PasswordHashFormat
	}{
		// Формат A — стоимость прежнего поставщика (ID-PW-1 §1.6).
		{"A bcrypt 12", params{format: "2a", cost: 12}, "$2a$12$", domain.PasswordHashFormatBcrypt},
		// Формат B — параметры ВЫШЕ ручки по проходам: проверяющий обязан читать
		// параметры значения, а не ручки (Р1).
		{"B argon2id t=4", params{format: "argon2id", memory: 65536, iterations: 4, parallelism: 4},
			"$argon2id$v=19$m=65536,t=4,p=4$", domain.PasswordHashFormatArgon2id},
	}
	v := verifierForTest(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mint(tc.p, []byte(password), rand.Reader)
			if err != nil {
				t.Fatalf("значение не построено: %v", err)
			}
			if !strings.HasPrefix(got, tc.prefix) {
				t.Fatalf("признак и параметры значения %q не начинаются с %q", got[:len(tc.prefix)], tc.prefix)
			}
			stored, err := domain.NewLoginVerifier(got)
			if err != nil {
				t.Fatalf("материал не принят доменом: %v", err)
			}
			res := v.Verify(stored, password)
			if res.Outcome != passwordverify.OutcomeMatched {
				t.Fatalf("верный пароль: исход %s, ждали %s", res.Outcome, passwordverify.OutcomeMatched)
			}
			if res.Format != tc.format {
				t.Fatalf("прочитано форматом %q, ждали %q", res.Format, tc.format)
			}
			// Близнец меняет ОДИН факт — пароль.
			res = v.Verify(stored, password+"x")
			if res.Outcome != passwordverify.OutcomeMismatched {
				t.Fatalf("неверный пароль: исход %s, ждали %s", res.Outcome, passwordverify.OutcomeMismatched)
			}
		})
	}
}

func TestMintRefusesWhatIsNotTheGivenOfThePosition(t *testing.T) {
	refusals := []struct {
		name string
		p    params
		pw   string
	}{
		{"пустой пароль", params{format: "2a", cost: 12}, ""},
		{"неизвестный формат", params{format: "2b", cost: 12}, "pw"},
		{"стоимость bcrypt вне диапазона", params{format: "2a", cost: 40}, "pw"},
		{"нулевая память argon2id", params{format: "argon2id", memory: 0, iterations: 3, parallelism: 4}, "pw"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := mint(tc.p, []byte(tc.pw), rand.Reader); err == nil {
				t.Fatalf("построено %q, ждали отказ", got)
			}
		})
	}
	// Положительный контроль той же функции: законный вход строится.
	if _, err := mint(params{format: "2a", cost: 4}, []byte("pw"), rand.Reader); err != nil {
		t.Fatalf("законный вход отвергнут: %v", err)
	}
}
