// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// assurance_method_vocabulary_injection_test.go — доказательство способности
// гейта «словарь один» упасть И смолчать.
//
// Инъекция герметична: синтетический исходник подаётся прямо в разбор, поэтому
// роняет ТОЛЬКО проверяемое. Оси — по одной на каждую названную форму объявления
// перечня плюс границы, на которых гейт обязан молчать: одиночный литерал (имя
// поля, область токена), слова в комментарии, одно имя словаря рядом с чужими.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

var injectionVocabulary = []string{"password", "totp", "lookup_secret", "webauthn", "recovery_code"}

func vocabularyScan(t *testing.T, rel, src string) ([]check.VocabularyListSite, check.VocabularyScanCensus) {
	t.Helper()
	sites, census, err := check.ScanMethodVocabularyLists(rel, []byte(src), injectionVocabulary)
	if err != nil {
		t.Fatalf("разбор инъекции %s: %v", rel, err)
	}
	if census.Strings == 0 {
		t.Fatalf("перепись инъекции пуста — разбор не прочитал ни одного литерала: %+v", census)
	}
	return sites, census
}

// TestMethodVocabularyGateRedsOnEveryListForm — КРАСНОЕ по каждой форме перечня.
func TestMethodVocabularyGateRedsOnEveryListForm(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, src string }{
		{"составной литерал среза", `package store
var kinds = []string{"password", "totp", "lookup_secret"}
`},
		{"ключи карты", `package store
var column = map[string]string{"password": "pw", "webauthn": "key"}
`},
		{"группа const", `package store
const (
	kindPassword = "password"
	kindTOTP     = "totp"
)
`},
		{"группа var со структурами (форма дома)", `package store
type kind struct{ name string }
var (
	password = kind{"password"}
	totp     = kind{"totp"}
)
`},
		{"перечень ветви case", `package store
func level(kind string) int {
	switch kind {
	case "password", "recovery_code":
		return 1
	}
	return 0
}
`},
		{"локальная группа var в теле функции", `package store
func kinds() []string {
	var (
		a = "webauthn"
		b = "lookup_secret"
	)
	return []string{a, b}
}
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const rel = "internal/repo/kaname/pg/sign_in_methods.go"
			sites, census := vocabularyScan(t, rel, tc.src)
			if census.VocabularyStrings < 2 {
				t.Fatalf("форма ВНЕ наблюдения: слов словаря прочитано %d (%+v)", census.VocabularyStrings, census)
			}
			if len(sites) != 1 {
				t.Fatalf("форма %q НЕ стала находкой: перечней %d при переписи %+v", tc.name, len(sites), census)
			}
			if !strings.Contains(sites[0].String(), rel) {
				t.Errorf("находка не называет координату: %s", sites[0])
			}
		})
	}
}

// TestMethodVocabularyGateStaysSilentOnLegalTwins — законные близнецы.
func TestMethodVocabularyGateStaysSilentOnLegalTwins(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, src string }{
		{"одиночный литерал — область токена", `package svc
const mfaFreshMethod = "webauthn"
func ok(sc string) bool { return sc == "webauthn" || sc == "passkey" }
`},
		{"имена словаря в комментарии", `package svc
// Способы: password, totp, lookup_secret, webauthn, recovery_code — см. assurance.
var x = 1
`},
		{"одно имя словаря среди чужих строк", `package svc
var markers = []string{"password", "client_secret", "token"}
`},
		{"поле с именем способа — идентификатор, а не литерал", `package svc
type row struct {
	password string
	totp     string
}
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sites, _, err := check.ScanMethodVocabularyLists("internal/service/x.go", []byte(tc.src), injectionVocabulary)
			if err != nil {
				t.Fatalf("разбор: %v", err)
			}
			if len(sites) != 0 {
				t.Fatalf("гейт краснеет на законном близнеце %q: %v", tc.name, sites)
			}
		})
	}
}

// TestMethodVocabularySchemaHalf — ограничение схемы: подмножество словаря молчит,
// имя вне словаря — находка; перечень без слов словаря — не предмет.
func TestMethodVocabularySchemaHalf(t *testing.T) {
	t.Parallel()
	up := `
CREATE TABLE kaname.sign_in_methods (
  kind text NOT NULL CONSTRAINT sign_in_methods_kind_ck CHECK (kind IN ('password', 'totp', 'webauthn')),
  state text NOT NULL CHECK (state IN ('ACTIVE', 'REVOKED'))
);
ALTER TABLE kaname.other ADD CONSTRAINT other_kind_ck CHECK (kind = ANY (ARRAY['lookup_secret'::text, 'sms'::text]));
`
	// Накат подаётся ЗАБЕЛЁННЫМ тем же средством, что у гейта.
	cs := check.ScanSchemaValueLists("internal/migrations/1_x.sql", migrations.SQLBlankComments(up), injectionVocabulary)
	if len(cs) != 2 {
		t.Fatalf("ограничений, касающихся словаря, найдено %d при ожидаемых 2 (перечень состояний — не предмет): %v", len(cs), cs)
	}
	if extra := setDifferenceOf(cs[0].Values, injectionVocabulary); len(extra) != 0 {
		t.Errorf("подмножество словаря объявлено находкой: %v", extra)
	}
	if extra := setDifferenceOf(cs[1].Values, injectionVocabulary); len(extra) != 1 || extra[0] != "sms" {
		t.Errorf("имя вне словаря не найдено: %v", extra)
	}
	if !strings.Contains(cs[1].String(), "other_kind_ck") {
		t.Errorf("находка не называет ограничение: %s", cs[1])
	}
	// Слово словаря в комментарии — не ограничение: комментарии забелены до разбора.
	if got := check.ScanSchemaValueLists("internal/migrations/2_x.sql",
		migrations.SQLBlankComments("-- kind IN ('password', 'totp')\nSELECT 1;\n"), injectionVocabulary); len(got) != 0 {
		t.Errorf("комментарий прочитан как ограничение: %v", got)
	}
}
