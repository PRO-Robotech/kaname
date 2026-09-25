// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TestOAuthStateFloorCountsVSCHARAndIsInclusive — пол 22 «не ниже»; «не
// прислан» — та же проверка; знак вне VSCHAR отвергается до сравнения с полом,
// поэтому на не-ASCII входе байт и знак не расходятся.
func TestOAuthStateFloorCountsVSCHARAndIsInclusive(t *testing.T) {
	cases := map[string]bool{
		"":                               false,
		strings.Repeat("a", 21):          false,
		strings.Repeat("a", 22):          true,
		strings.Repeat("a", 43):          true,
		strings.Repeat("a", 21) + " ":    true,  // пробел — VSCHAR
		strings.Repeat("ж", 11):          false, // 22 байта, 11 знаков вне алфавита
		strings.Repeat("a", 21) + "\x7f": false,
		strings.Repeat("a", 21) + "\t":   false,
	}
	for in, want := range cases {
		if got := domain.ValidOAuthState(in); got != want {
			t.Errorf("ValidOAuthState(%q) = %v, ожидалось %v", in, got, want)
		}
	}
	if domain.AuthorizationStateFloor != 22 {
		t.Fatalf("пол state %d, приёмка Р13 называет 22", domain.AuthorizationStateFloor)
	}
}

// TestPKCEFormsAndS256 — вектор RFC 7636 прил. B; границы длины verifier;
// форма вызова.
func TestPKCEFormsAndS256(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := domain.PKCEChallengeS256(verifier); got != challenge {
		t.Fatalf("S256(%q) = %q, RFC 7636 прил. B даёт %q", verifier, got, challenge)
	}
	if !domain.ValidPKCEChallengeS256(challenge) || domain.ValidPKCEChallengeS256(challenge[1:]) ||
		domain.ValidPKCEChallengeS256(strings.Repeat("+", 43)) {
		t.Fatal("форма вызова S256 судится не так")
	}
	for in, want := range map[string]bool{
		verifier:                      true,
		strings.Repeat("a", 42):       false,
		strings.Repeat("a", 128):      true,
		strings.Repeat("a", 129):      false,
		strings.Repeat("a", 42) + "=": false,
	} {
		if got := domain.ValidPKCEVerifier(in); got != want {
			t.Errorf("ValidPKCEVerifier(len %d) = %v, ожидалось %v", len(in), got, want)
		}
	}
}

// TestOAuthScopeForm — токены через одиночный пробел из алфавита NQCHAR.
func TestOAuthScopeForm(t *testing.T) {
	for in, want := range map[string]bool{
		"": true, "openid": true, "openid email": true,
		" openid": false, "openid ": false, "a  b": false, `a"b`: false, `a\b`: false, "ж": false,
	} {
		if got := domain.ValidOAuthScope(in); got != want {
			t.Errorf("ValidOAuthScope(%q) = %v, ожидалось %v", in, got, want)
		}
	}
}

// TestCeremonySecretNeverPrints — значение не выходит ни одним общим путём
// вывода; свёртка детерминирована и не равна значению.
func TestCeremonySecretNeverPrints(t *testing.T) {
	s, err := domain.NewCeremonySecret()
	if err != nil {
		t.Fatalf("значение: %v", err)
	}
	v := s.Deliver()
	if len(v) != 43 {
		t.Fatalf("длина значения %d, ожидалось 43 (32 байта в BASE64URL)", len(v))
	}
	var logged strings.Builder
	slog.New(slog.NewTextHandler(&logged, nil)).Info("x", slog.Any("secret", s))
	for what, out := range map[string]string{
		"%v": fmt.Sprintf("%v", s), "%s": fmt.Sprintf("%s", s), "%#v": fmt.Sprintf("%#v", s), "журнал": logged.String(),
	} {
		if strings.Contains(out, v) {
			t.Errorf("%s печатает значение", what)
		}
	}
	if _, err := json.Marshal(s); err == nil {
		t.Error("значение сериализуется в JSON")
	}
	if s.Digest() != domain.PresentedCeremonySecret(v).Digest() || string(s.Digest()) == v || len(s.Digest()) != 64 {
		t.Fatal("свёртка значения не та")
	}
	if !domain.PresentedCeremonySecret("").IsZero() || domain.PresentedCeremonySecret("").Digest() != "" {
		t.Fatal("пустое значение — не отсутствие")
	}
}
