// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_antioracle_red_test.go — Группа D приёмки LINE-A-1: единый
// анти-оракульный тон обмена (24) и запрет «неисполнимой возможности» (27).
// Свежие утверждения против нашей поверхности; единый код invalid_grant — из
// `ceremony_fosite_vectors_test.go` (fosite errors.go).
//
// Общий честный красный: полосы обмена authorization_code на dd66b5be нет —
// валидный обмен не даёт 200, и единый тон/перенос из кода невыразимы.

package main

import (
	"net/http"
	"net/url"
	"testing"
)

// TestLINEA1_24_UnifiedInvalidGrantAfterCodeNamed — LINE-A-1-24 (E): все шесть
// причин отказа, наступивших ПОСЛЕ того, как назван код, отдают ПОБАЙТОВО одно и
// то же (invalid_grant/400) — обмен не служит оракулом состояния кода. invalid_client
// (12) остаётся различимым (решается ДО кода). Положительный контроль: валидный
// обмен (10) возвращает предъявитель — без него единый тон зеленел бы на
// реализации, отвергающей всё.
//
// RED на dd66b5be: положительный контроль (валидный обмен → 200) не достижим —
// вид выдачи authorization_code не принят.
func TestLINEA1_24_UnifiedInvalidGrantAfterCodeNamed(t *testing.T) {
	mux := buildCeremonyIssuanceSurface(t)

	// Положительный контроль предмета.
	ok := ceremonyTokenPOST(mux, exchangeForm("code-from-02", fositePKCEVerifier, fositeRedirectRegistered, "ic-first-party"))
	assertExchangeGrantWired(t, ok, "LINE-A-1-24")
	if ok.Code != http.StatusOK {
		t.Fatalf("LINE-A-1-24: положительный контроль ожидал 200, получил %d — единый тон нечем контролировать", ok.Code)
	}

	// Шесть причин ПОСЛЕ того, как назван код: неизвестный · истёкший · уже
	// использованный · неверный verifier · чужой клиент · несовпадающий
	// redirect_uri. (Истёкший/использованный держит база; здесь — коды-маркеры.)
	after := []url.Values{
		exchangeForm("code-unknown", fositePKCEVerifier, fositeRedirectRegistered, "ic-first-party"),
		exchangeForm("code-expired", fositePKCEVerifier, fositeRedirectRegistered, "ic-first-party"),
		exchangeForm("code-used", fositePKCEVerifier, fositeRedirectRegistered, "ic-first-party"),
		exchangeForm("code-from-02", fositePKCEVerifierWrong, fositeRedirectRegistered, "ic-first-party"),
		exchangeForm("code-for-ic-1", fositePKCEVerifier, fositeRedirectRegistered, "ic-2"),
		exchangeForm("code-from-02", fositePKCEVerifier, fositeRedirectTrailing, "ic-first-party"),
	}
	var first string
	for i, form := range after {
		rec := ceremonyTokenPOST(mux, form)
		if rec.Code != http.StatusBadRequest || decodeOAuthErr(rec) != oauthErrInvalidGrant {
			t.Errorf("LINE-A-1-24: причина #%d ожидала 400/%s, получила %d/%s", i, oauthErrInvalidGrant, rec.Code, decodeOAuthErr(rec))
		}
		body := rec.Body.String()
		if i == 0 {
			first = body
		} else if body != first {
			t.Errorf("LINE-A-1-24: причина #%d отдала иное тело, чем #0 — обмен служит оракулом состояния кода:\n#0=%q\n#%d=%q", i, first, i, body)
		}
	}

	// invalid_client (12) остаётся различимым — решается ДО кода.
	noAuth := exchangeForm("code-from-02", fositePKCEVerifier, fositeRedirectRegistered, "ic-first-party")
	noAuth.Del("client_secret")
	if rec := ceremonyTokenPOST(mux, noAuth); decodeOAuthErr(rec) == oauthErrInvalidGrant {
		t.Error("LINE-A-1-24: отказ аутентификации клиента слился с invalid_grant — чужая библиотека прочтёт «неверный клиент» как «неверный код»")
	}
}

// TestLINEA1_27_ExchangeIgnoresCallerSuppliedBinding — LINE-A-1-27 (I): связку
// назначает выдача; обмен её НЕ переопределяет (неисполнимая возможность, Р5).
// Обмен, приславший subject/acr/auth_time, получает предъявитель со значениями
// из КОДА (usr-X, "1", T); присланные — игнорируются. Положительный контроль:
// обмен без этих полей даёт тот же предъявитель — поля не были обязательным
// входом, «который нельзя прислать правильно».
//
// RED на dd66b5be: обмен не даёт предъявителя — вид выдачи не принят.
func TestLINEA1_27_ExchangeIgnoresCallerSuppliedBinding(t *testing.T) {
	mux := buildCeremonyIssuanceSurface(t)

	spoofed := exchangeForm("code-from-02", fositePKCEVerifier, fositeRedirectRegistered, "ic-first-party")
	spoofed.Set("subject", "usr-attacker")
	spoofed.Set("acr", "2")
	spoofed.Set("auth_time", "0")

	rec := ceremonyTokenPOST(mux, spoofed)
	assertExchangeGrantWired(t, rec, "LINE-A-1-27")
	if rec.Code != http.StatusOK {
		t.Fatalf("LINE-A-1-27: обмен ожидал 200 (с игнорированием присланной связки), получил %d — предмет отсутствует", rec.Code)
	}
	// Целевое (исполнится по реализации): предъявитель несёт usr-X/"1"/T из кода,
	// а не присланные usr-attacker/"2"/0. Разбор клеймов предъявителя добавляет
	// GREEN-полоса вместе с подписантом реального кода.
}
