// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// human_session_forced_exit_reason_injection_test.go — способность пробы
// KN-SER-07 упасть в обе стороны и смолчать на законном входе (приёмка §6
// п.12: «определение ограничения с лишним значением: красная, значение
// названо»). Входы синтетические и герметичные: база не нужна, поэтому
// роняется только проверяемое.
package migrations_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// serHeadDef — определение ограничения той формы, какую отдаёт
// `pg_get_constraintdef` на голове ДО изменения.
const serHeadDef = `CHECK (((ended_reason IS NULL) OR (ended_reason = ANY (ARRAY['logout'::text, 'password-change'::text, 'second-factor-removed'::text]))))`

func TestSessionEndVocabularyDiff_NamesTheExtraAndTheMissingValue(t *testing.T) {
	t.Parallel()
	four := []string{"logout", "password-change", "second-factor-removed", "admin-force-logout"}
	withForced := strings.Replace(serHeadDef, "]", ", 'admin-force-logout'::text]", 1)
	cases := []struct {
		name                 string
		domain               []string
		def                  string
		onlyDomain, onlyBase []string
	}{
		{"равенство — молчание", four, withForced, nil, nil},
		{"домен шире базы (естественный красный до миграции)", four, serHeadDef, []string{"admin-force-logout"}, nil},
		{"база шире домена: лишнее значение названо", four,
			strings.Replace(withForced, "]", ", 'sneeze'::text]", 1), nil, []string{"sneeze"}},
		{"экранированная кавычка — одно значение", []string{"it's"}, `CHECK ((x = 'it''s'::text))`, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			onlyDomain, onlyBase, err := serVocabularyDiff(tc.domain, tc.def)
			if err != nil {
				t.Fatalf("сверка отказала: %v", err)
			}
			if !reflect.DeepEqual(onlyDomain, tc.onlyDomain) || !reflect.DeepEqual(onlyBase, tc.onlyBase) {
				t.Fatalf("только в домене %v (ждали %v), только в базе %v (ждали %v)",
					onlyDomain, tc.onlyDomain, onlyBase, tc.onlyBase)
			}
		})
	}
	if _, _, err := serVocabularyDiff(four, `CHECK ((ended_reason IS NULL))`); err == nil {
		t.Fatal("определение без единого литерала обязано давать отказ, а не «расхождений нет»")
	}
}

// serDomainFixture — пакет домена во временном каталоге.
func serDomainFixture(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "human_session.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "human_session_test.go"),
		[]byte("package domain\n\nfunc HumanSessionEndReasons() []string { return nil }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

const serLegalDomain = `package domain

const (
	RevokeReasonLogout              = "logout"
	RevokeReasonPasswordChange      = "password-change"
	RevokeReasonSecondFactorRemoved = "second-factor-removed"
	RevokeReasonSecondFactorReset   = "second-factor-reset"
	RevokeReasonAdminForceLogout    = "admin-force-logout"
)

func HumanSessionEndReasons() []string {
	return []string{RevokeReasonLogout, RevokeReasonPasswordChange, RevokeReasonSecondFactorRemoved, RevokeReasonAdminForceLogout}
}
`

func TestSessionEndDomainList_ReadsTheLegalFormAndNamesEveryOtherForm(t *testing.T) {
	t.Parallel()
	t.Run("законная форма: функция, свежий срез, константы по имени", func(t *testing.T) {
		t.Parallel()
		l, err := serReadDomainList(serDomainFixture(t, serLegalDomain))
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"logout", "password-change", "second-factor-removed", "admin-force-logout"}
		if !l.found || len(l.problems) != 0 || !reflect.DeepEqual(l.values, want) || l.files != 1 {
			t.Fatalf("законная форма прочитана не так: found=%t files=%d values=%v problems=%v", l.found, l.files, l.values, l.problems)
		}
	})
	cases := []struct {
		name, src, want string
		found           bool
	}{
		{"перечня нет", "package domain\n\nconst RevokeReasonLogout = \"logout\"\n", "", false},
		{"литерал вместо константы", strings.Replace(serLegalDomain, "RevokeReasonAdminForceLogout}", `"admin-force-logout"}`, 1),
			"не константа по имени", true},
		{"переменная вместо функции", "package domain\n\nconst RevokeReasonLogout = \"logout\"\n\nvar HumanSessionEndReasons = []string{RevokeReasonLogout}\n",
			"объявлен переменной", false},
		{"срез пакета вместо свежего", strings.Replace(serLegalDomain,
			"return []string{RevokeReasonLogout, RevokeReasonPasswordChange, RevokeReasonSecondFactorRemoved, RevokeReasonAdminForceLogout}",
			"return sessionEndReasons", 1) + "\nvar sessionEndReasons = []string{RevokeReasonLogout}\n",
			"не составной литерал", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, err := serReadDomainList(serDomainFixture(t, tc.src))
			if err != nil {
				t.Fatal(err)
			}
			if l.found != tc.found {
				t.Fatalf("found=%t, ждали %t", l.found, tc.found)
			}
			if tc.want == "" {
				if len(l.problems) != 0 {
					t.Fatalf("находок быть не должно: %v", l.problems)
				}
				return
			}
			if !strings.Contains(strings.Join(l.problems, "\n"), tc.want) {
				t.Fatalf("находка не называет форму %q: %v", tc.want, l.problems)
			}
		})
	}
	if _, err := serReadDomainList(t.TempDir()); err == nil {
		t.Fatal("пустой каталог обязан давать отказ разбора, а не «перечня нет»")
	}
}
