// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// recovery_without_a_way_in_integration_test.go — личность `ACTIVE` без способа
// входа возвращается восстановлением по почте: Ф5-29, Ф5-30, Ф5-31 на слушателе
// службы и настоящей базе после миграции пары (задача PRO-Robotech/kaname#608;
// приёмки `recovery-of-access.md` Р9 и `active-identity-has-a-way-in.md` AWI-12).
//
// «Дано» — строка в форме «после переноса» (Ф5 §5.5 (6), AWI-11): личность
// заведена регистрацией полосы пробы, затем ОДНОЙ транзакцией прямой записи
// сняты строка пароля и отметка подтверждения и поставлена отметка открытого
// пути — иначе отложенный ключ пары отверг бы фиксацию посева. Продукт такую
// строку не производит (Ф5 §5.6 (8)); её производил прежний путь, и перенос
// пары привёл лежащие строки ровно к этой форме.
//
// Близнецы: Ф5-31 — личность с паролем и неподтверждённым адресом (отличие —
// строка пароля); адрес `Z`, не принадлежащий никому, — ответ Ф5-02.
//
// Run: `go test ./internal/handler/loginlanehttp/ -run F5_29 -count=1` (Docker).
// Skipped under -short.
package loginlanehttp_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

// seedWithoutAWayIn приводит личность стенда к форме «после переноса».
func (h *sessionLane) seedWithoutAWayIn(t *testing.T) {
	t.Helper()
	tx, err := h.pool.Begin(h.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(h.ctx) }()
	_, err = tx.Exec(h.ctx, `DELETE FROM user_login_methods WHERE user_id = $1`, string(h.user.ID))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): снятие строки пароля")
	_, err = tx.Exec(h.ctx, `UPDATE users SET email_verified_at = NULL, recovery_path_opened_at = now() WHERE id = $1`, string(h.user.ID))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): снятие подтверждения и отметка пути")
	require.NoError(t, tx.Commit(h.ctx), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев формы «после переноса» отвергнут")
}

type wayInState struct {
	passwords int
	verified  bool
	open      bool
	status    string
}

func (h *sessionLane) wayInState(t *testing.T) wayInState {
	t.Helper()
	var s wayInState
	require.NoError(t, h.pool.QueryRow(h.ctx, `
		SELECT (SELECT count(*) FROM user_login_methods WHERE user_id = u.id AND kind = 'password'),
		       u.email_verified_at IS NOT NULL, u.recovery_path_opened_at IS NOT NULL, u.invite_status
		  FROM users u WHERE u.id = $1`, string(h.user.ID)).Scan(&s.passwords, &s.verified, &s.open, &s.status))
	return s
}

func TestLaneIntegration_F5_29_IdentityWithoutAWayInRecoversByMail(t *testing.T) {
	h := newSessionLane(t)
	h.seedWithoutAWayIn(t)
	require.Equal(t, wayInState{passwords: 0, verified: false, open: true, status: "ACTIVE"}, h.wayInState(t),
		"Дано: ACTIVE без пароля, адрес не подтверждён, путь открыт")

	// Ф5-29: код выдаётся и на неподтверждённый адрес; ответ равен ответу для Z.
	const src = "203.0.113.129"
	ra, ctxA := h.requestCodeFrom(t, h.email, src)
	rz, _ := h.requestCodeFrom(t, "z-"+ids.NewID("tst")[3:11]+"@example.invalid", src)
	require.Equal(t, http.StatusOK, ra.status, "Ф5-29: %s", ra.body)
	require.Equal(t, rz.status, ra.status, "Ф5-29: код ответа для A равен ответу для Z")
	require.Equal(t, rz.body, ra.body, "Ф5-29: тело ответа для A побайтово равно ответу для Z")
	require.Equal(t, 1, h.recoveryLetters(t, h.user.ID), "Ф5-29: письмо вида восстановления для A в очереди")
	code := h.lastRecoveryCode(t, h.user.ID)

	// Ф5-31 близнец строкой пароля: личность с паролем и неподтверждённым
	// адресом кода не получает, как прежде.
	emailB := "b-" + ids.NewID("tst")[3:11] + "@example.invalid"
	regB, err := h.register.Execute(h.ctx, registration.Input{Email: emailB, Password: integrationPassword, Source: "192.0.2.251"})
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): регистрация B")
	rb, _ := h.requestCodeFrom(t, emailB, src)
	require.Equal(t, rz.body, rb.body, "Ф5-31: ответ для B равен ответу для Z")
	require.Zero(t, h.recoveryLetters(t, regB.View.User.ID), "Ф5-31: письма для B нет")

	// Ф5-30 / AWI-12: предъявление кода заводит первый пароль, подтверждает
	// адрес и снимает отметку — одним исходом; выдана сессия.
	const fresh = "first-password-after-transfer-608"
	done := h.completeRecovery(t, code, fresh, map[string]string{loginlanehttp.HeaderForwardedFor: src}, ctxA)
	require.Equal(t, http.StatusOK, done.status, "Ф5-30: сессия выдана, а не 503: %s", done.body)
	require.NotNil(t, cookieNamed(done.cookies, loginlanehttp.CookieSession), "Ф5-30: носитель выдан")
	var body struct {
		Session struct {
			EmailVerified *bool `json:"emailVerified"`
		} `json:"session"`
	}
	require.NoError(t, json.Unmarshal([]byte(done.body), &body))
	require.NotNil(t, body.Session.EmailVerified, "Ф5-30: поле emailVerified сессии в ответе есть: %s", done.body)
	require.True(t, *body.Session.EmailVerified, "Ф5-30: emailVerified в ответе — после записи")
	require.Equal(t, wayInState{passwords: 1, verified: true, open: false, status: "ACTIVE"}, h.wayInState(t),
		"Ф5-30: первый пароль заведён, адрес подтверждён, пути нет, статус прежний")

	h.login(t, fresh)
	again := h.completeRecovery(t, code, "another-password-after-608", map[string]string{loginlanehttp.HeaderForwardedFor: src}, ctxA)
	require.Equal(t, http.StatusUnauthorized, again.status, "Ф5-30: второе предъявление того же кода — отказ Ф5-05: %s", again.body)
	require.Equal(t, refusalWire(16, stepRecoveryRefused), again.body, "Ф5-05: текст Р10 п. 2 (редакция 10)")
}
