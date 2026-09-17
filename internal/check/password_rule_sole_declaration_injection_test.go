// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
)

func ruleScan(t *testing.T, rel, src string) check.PasswordRuleCensus {
	t.Helper()
	c, err := check.ScanPasswordRule(rel, []byte(src))
	require.NoError(t, err, "разбор инъекции %s", rel)
	require.Equal(t, 1, c.Files)
	return c
}

// TestPasswordRuleGate_RedsOnEverySecondDeclarationForm — инъекция: второе
// объявление в каждой из трёх форм краснеет с координатой.
func TestPasswordRuleGate_RedsOnEverySecondDeclarationForm(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		src  string
		form check.PasswordRuleForm
	}{
		{"конструктор по имени", `package other
type PasswordRule struct{}
func NewPasswordRule(n int) *PasswordRule { return &PasswordRule{} }
`, check.PasswordRuleFormName},
		{"метод Judge над паролем в чужом типе", `package other
import "context"
type policy struct{}
func (p policy) Judge(ctx context.Context, email, password string) error { return nil }
`, check.PasswordRuleFormVerb},
		{"длина в рунах через []rune", `package other
import "errors"
func accept(password string) error {
	if len([]rune(password)) < 8 { return errors.New("short") }
	return nil
}
`, check.PasswordRuleFormLength},
		{"длина в рунах через utf8", `package other
import ("errors"; "unicode/utf8")
func accept(password string) error {
	if 10 > utf8.RuneCountInString(password) { return errors.New("short") }
	return nil
}
`, check.PasswordRuleFormLength},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := ruleScan(t, "internal/other/rule.go", tc.src)
			foreign := c.Foreign(check.PasswordRuleHomeRel)
			require.NotEmpty(t, foreign, "второе объявление не найдено")
			found := false
			for _, f := range foreign {
				if f.Form == tc.form {
					found = true
					require.Equal(t, "internal/other/rule.go", f.Rel)
					require.Greater(t, f.Line, 1, "координата обязана называть строку")
				}
			}
			require.True(t, found, "ожидалась форма %q, найдено %v", tc.form, foreign)
		})
	}
}

// TestPasswordRuleGate_StaysSilentOnLegitimateTwins — законные близнецы: второй
// ВЫЗЫВАЮЩИЙ (регистрация Ф4), байтовая длина материала у проверяющего
// (PWV-19), `Judge` с другой сигнатурой и объявления в доме.
func TestPasswordRuleGate_StaysSilentOnLegitimateTwins(t *testing.T) {
	t.Parallel()

	caller := ruleScan(t, "internal/apps/kaname/api/registration/register.go", `package registration
import "context"
type rule interface{ Judge(ctx context.Context, email, password string) error }
type uc struct{ rule rule }
func (u uc) run(ctx context.Context, email, pw string) error { return u.rule.Judge(ctx, email, pw) }
`)
	require.Empty(t, caller.Foreign(check.PasswordRuleHomeRel), "второй вызывающий — не второе объявление")
	require.Len(t, caller.Callers, 1, "вызов обязан попасть в перепись вызывающих")

	bytes := ruleScan(t, "internal/passwordverify/verifier.go", `package passwordverify
func rewritable(password string) bool { return len(password) < 72 }
`)
	require.Empty(t, bytes.Foreign(check.PasswordRuleHomeRel), "байтовая длина судит материал, а не пароль")

	otherJudge := ruleScan(t, "internal/apps/kaname/api/other/judge.go", `package other
import "context"
type gate struct{}
func (g gate) Judge(ctx context.Context, subject string) error { return nil }
func use(ctx context.Context) error { return gate{}.Judge(ctx, "x") }
`)
	require.Empty(t, otherJudge.Foreign(check.PasswordRuleHomeRel), "Judge без параметра password — другой предмет")
	require.Empty(t, otherJudge.Callers, "вызов Judge с двумя доводами — не вызов правила пароля")

	home := ruleScan(t, check.PasswordRuleHomeRel, `package humansession
import "context"
type PasswordRule struct{ MinLength int }
func NewPasswordRule(n int) *PasswordRule { return &PasswordRule{MinLength: n} }
func (r *PasswordRule) Judge(ctx context.Context, email, password string) error {
	if len([]rune(password)) < r.MinLength { return nil }
	return nil
}
`)
	require.Empty(t, home.Foreign(check.PasswordRuleHomeRel), "дом правила — не находка")
	require.Len(t, home.Declarations, 4, "дом несёт все формы: тип, конструктор, метод, длину")
	require.Equal(t, []string{check.PasswordRuleHomeRel}, home.HomeFiles())
}
