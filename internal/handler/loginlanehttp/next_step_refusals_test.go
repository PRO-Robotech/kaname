// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// next_step_refusals_test.go — отказ полосы называет СЛЕДУЮЩИЙ ШАГ, не называя
// причины (PRO-Robotech/kaname#211, #520, #258; одобренные редакции Ф4 ред. 8,
// Ф5 ред. 10–11, Ф12 ред. 17–18).
//
// # Почему тексты здесь ЛИТЕРАЛАМИ, а не константами полосы
//
// Предмет — контракт на проводе: клиент читает строку, а не имя константы.
// Утверждение «тело равно константе» зеленело бы при любом значении константы,
// в том числе при прежнем, шага не называвшем; литерал из приёмки краснеет на
// нём (TDD-красный каждой задачи). Что константа полосы и страница клиента
// несут ТОТ ЖЕ текст, держит гейт страницы (`internal/check`).
//
// # Отрицательный контроль текста
//
// Шаг обязан не называть класс причины: перечни запрещённых слов — из «Тогда»
// приёмок дословно (Ф4-11, Ф5-04, Ф12-35). Проверка — по подстроке без учёта
// регистра, как и записано там.
package loginlanehttp_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

// stepLoginWithCode — Ф12 Р4, редакция 17 (kaname#520): вход С полем
// `secondFactor`; дословно.
const stepLoginWithCode = "authentication failed; check the email, the password and the code, and send secondFactor only if a second factor is enrolled"

// refusalWire — тело отказа полосы побайтово (без деталей): порядок ключей и
// отсутствие пробелов — те, что печатает производитель тела.
func refusalWire(code int, message string) string {
	b, _ := json.Marshal(struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Details []any  `json:"details"`
	}{code, message, []any{}})
	return string(b)
}

// requireNamesNoCause — отрицательный контроль текста: ни одного запрещённого
// слова (без учёта регистра).
func requireNamesNoCause(t *testing.T, text string, forbidden ...string) {
	t.Helper()
	low := strings.ToLower(text)
	for _, f := range forbidden {
		require.NotContains(t, low, f, "текст отказа называет класс причины: %q", text)
	}
}

// TestLane_F12_13_LoginWithSecondFactorRefusalNamesTheStep — Ф12-13 (а)…(ж) на
// транспорте: отказ входа С полем `secondFactor` отвечает текстом формы с кодом,
// ОДНИМ на оба способа; близнец формы — тот же отказ БЕЗ поля — прежний текст
// Ф3-02. Отличающий факт — один: прислано ли поле. `null` — поля нет (как его
// читает слушатель формы).
func TestLane_F12_13_LoginWithSecondFactorRefusalNamesTheStep(t *testing.T) {
	stub := &stubLane{loginErr: humansession.ErrAuthenticationFailed}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "login", nil)
	form := func(sf any) map[string]any {
		m := map[string]any{"email": "a@example.invalid", "password": "pw", "csrfToken": tok}
		if sf != nil {
			m["secondFactor"] = sf
		}
		return m
	}

	totp := l.do(t, c, http.MethodPost, loginlanehttp.PathLogin, form(map[string]string{"method": "totp", "code": "123456"}), fwd(), ctxCk)
	require.Equal(t, http.StatusUnauthorized, totp.status, totp.body)
	require.Equal(t, refusalWire(16, stepLoginWithCode), totp.body, "Ф12-13: текст формы с кодом дословно")
	require.Empty(t, totp.cookies, "без Set-Cookie")
	require.NotNil(t, stub.loginIn[0].SecondFactor, "поле дошло до глагола: отказ — исход глагола, а не формы")

	backup := l.do(t, c, http.MethodPost, loginlanehttp.PathLogin, form(map[string]string{"method": "lookup_secret", "code": "ABCDEFGH12"}), fwd(), ctxCk)
	require.Equal(t, totp.status, backup.status)
	require.Equal(t, totp.body, backup.body, "текст один на оба способа")

	// Близнец формы: тот же отказ глагола без поля — Ф3-02 дословно.
	twin := l.do(t, c, http.MethodPost, loginlanehttp.PathLogin, form(nil), fwd(), ctxCk)
	require.Equal(t, http.StatusUnauthorized, twin.status)
	require.Equal(t, refusalWire(16, "authentication failed"), twin.body, "вход без поля — прежний текст Ф3-02")
	require.Empty(t, twin.cookies)

	// `null` — поля нет: тот же близнец.
	null := l.do(t, c, http.MethodPost, loginlanehttp.PathLogin, `{"email":"a@example.invalid","password":"pw","csrfToken":"`+tok+`","secondFactor":null}`, fwd(), ctxCk)
	require.Equal(t, twin.body, null.body, "secondFactor: null читается как отсутствие поля")

	// Прочие исходы входа с полем не меняются: отказ по частоте — свой текст.
	stub.loginErr = &humansession.TooManyAttemptsError{Scope: humansession.FailureByAddress}
	tma := l.do(t, c, http.MethodPost, loginlanehttp.PathLogin, form(map[string]string{"method": "totp", "code": "123456"}), fwd(), ctxCk)
	require.Equal(t, http.StatusTooManyRequests, tma.status)
	require.Contains(t, tma.body, `"too many attempts; try again later"`)
}

// TestLane_F12_16_SessionVerbRefusalKeepsTheCommonText — глаголы под сессией
// Р4 не трогает (Ф12 §14 DoD п. 4): отказ step-up — прежний общий текст, даже
// когда способ — код.
func TestLane_F12_16_SessionVerbRefusalKeepsTheCommonText(t *testing.T) {
	stub := &stubLane{stepUpErr: humansession.ErrAuthenticationFailed}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "step-up", nil)
	sess := &http.Cookie{Name: "kaname_session", Value: "bearer-1"}

	r := l.do(t, c, http.MethodPost, "/iam/v1/auth/step-up", map[string]string{"method": "totp", "code": "123456", "csrfToken": tok}, fwd(), ctxCk, sess)
	require.Equal(t, http.StatusUnauthorized, r.status)
	require.Equal(t, refusalWire(16, "authentication failed"), r.body)
}
