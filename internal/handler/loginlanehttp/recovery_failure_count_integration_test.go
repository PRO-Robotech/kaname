// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// recovery_failure_count_integration_test.go — ЗАВЕРШЕНИЕ ВОССТАНОВЛЕНИЯ
// РЕШАЕТ СЧЁТ ПО АДРЕСУ МЕСТОМ РЕШЕНИЯ ВХОДА: Ф5-25 на слушателе службы (задача
// PRO-Robotech/kaname#305; приёмка `docs/engineering/acceptance/recovery-of-access.md`
// ред. 4, Р5, Д13, §9 строка «Ф5-25»; правило — Ф3 Р10 ред. 13 и Ф12 Р7).
//
// # Что утверждается
//
// Счёт по адресу обнуляет вход, завершённый до уровня всех заведённых у
// личности факторов. Сессия восстановления — «1» (`recovery_code`, Ф11 Р8),
// кода второго фактора восстановление не требует — поэтому исходов три, и
// каждый наблюдается ответами входа ПОСЛЕ завершения, а не строкой базы:
//
//	(а) [замок]   A — второй фактор заведён: завершение выдаёт сессию, счёт НЕ
//	              обнулён — первый неверный пароль 401, второй 429 (форма Ф3-28);
//	              это и бюджет подбора кода второго фактора (счёт общий, Ф12 Р7);
//	(б) [близнец] B — без второго фактора: завершение выдаёт сессию, счёт
//	              обнулён — оба неверных пароля 401;
//	(в) [замок]   C — заблокирована: сессии нет, ответ завершения — отказ входа
//	              заблокированной, он сосчитан попыткой, счёт НЕ обнулён — первый
//	              же неверный пароль 429.
//
// Отличающий факт каждого замка против (б) — один: заведён ли второй фактор
// либо заблокирована ли личность. Каждой личности — своя база и свой источник:
// ось источника не вмешивается в замер оси адреса, и профиль это требует
// явно (`N_источник > N_адрес + 1`).
//
// # Способность упасть — в обе стороны
//
// Обнуление, не связанное с достигнутым уровнем, краснеет на (а) и (в);
// отсутствие обнуления — на (б). Поэтому зелёный здесь значит «решение принято
// местом решения входа», а не «счёт как-то обнулился».
//
// Run: `go test ./internal/handler/loginlanehttp/ -run F5_25 -count=1`
// (Docker). Skipped under -short.
package loginlanehttp_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

// refusedLogin — тело отказа входа: одно на все причины (Ф3-02).
const refusedLogin = `{"code":16,"message":"authentication failed","details":[]}`

// TestLaneIntegration_F5_25_RecoveryCompletionDecidesTheAddressCountLikeALogin — Ф5-25.
func TestLaneIntegration_F5_25_RecoveryCompletionDecidesTheAddressCountLikeALogin(t *testing.T) {
	const newPassword = "recovered-and-counted-5-25"
	type person struct {
		label          string
		source         string
		factor, locked bool
		lane           *sessionLane
	}
	people := []*person{
		{label: "(а) A — второй фактор заведён", source: "203.0.113.61", factor: true},
		{label: "(б) B — без второго фактора", source: "203.0.113.62"},
		{label: "(в) C — заблокирована", source: "203.0.113.63", locked: true},
	}
	for _, p := range people {
		p.lane = newSessionLane(t)
		h := p.lane
		// Дано: адрес подтверждён — посевом писателем продукта (как Ф5-24).
		require.NoError(t, kanamepg.NewLoginMethodRepo(h.pool).MarkEmailVerified(h.ctx, h.user.ID, h.user.Email, time.Now().UTC()))
		if p.factor {
			h.seedEnrolledSecondFactor(t)
		}
		if p.locked {
			// Дано: блокировка — писателем продукта, как Ф5-17.
			h.setInviteStatus(t, domain.InviteStatusBlocked)
		}
	}
	lim := people[0].lane.limits
	require.GreaterOrEqual(t, lim.AddressAttempts, 2, "Дано: N_адрес ≥ 2")
	require.Greater(t, lim.SourceAttempts, lim.AddressAttempts+1, "Дано: N_источник > N_адрес + 1")
	t.Logf("профиль: N_адрес %d за %v · N_источник %d за %v", lim.AddressAttempts, lim.AddressWindow,
		lim.SourceAttempts, lim.SourceWindow)

	type outcome struct {
		before     reply // последний отказ входа до завершения
		completion reply
		after      [2]reply
		byAddress  int
	}
	got := map[*person]outcome{}
	for _, p := range people {
		h := p.lane
		from := map[string]string{loginlanehttp.HeaderForwardedFor: p.source}
		code, ctxCk := h.requestRecoveryCode(t, from) // Дано: код, выданный Ф5-01
		var o outcome
		// Когда: N_адрес − 1 неверных паролей на входе в одном окне.
		for i := 0; i < lim.AddressAttempts-1; i++ {
			o.before = h.loginAttempt(t, laneWrongPassword, from)
			require.Equal(t, http.StatusUnauthorized, o.before.status, "%s: Дано — неверный пароль есть отказ входа: %s", p.label, o.before.body)
			require.JSONEq(t, refusedLogin, o.before.body, "%s: Дано — отказ входа одним текстом", p.label)
		}
		o.completion = h.completeRecovery(t, code, newPassword, from, ctxCk)
		o.byAddress, _ = h.failureCounts(t, p.source)
		o.after[0] = h.loginAttempt(t, laneWrongPassword, from)
		o.after[1] = h.loginAttempt(t, laneWrongPassword, from)
		got[p] = o
		t.Logf("%s: завершение %d · счёт по адресу после завершения %d · неверные после: %d, %d",
			p.label, o.completion.status, o.byAddress, o.after[0].status, o.after[1].status)
	}
	a, b, c := got[people[0]], got[people[1]], got[people[2]]

	// (б) близнец — первым: без него замки ниже краснели бы и на полосе, не
	// выдающей ничего.
	require.Equal(t, http.StatusOK, b.completion.status, "(б): завершение — исход Ф5-03: %s", b.completion.body)
	require.NotNil(t, cookieNamed(b.completion.cookies, loginlanehttp.CookieSession), "(б): сессия выдана")
	for i, r := range b.after {
		if assert.Equal(t, http.StatusUnauthorized, r.status,
			"(б): счёт по адресу обнулён — неверный пароль %d после завершения есть отказ входа: %s", i+1, r.body) {
			assert.JSONEq(t, refusedLogin, r.body)
		}
	}

	// (а) замок: второй фактор заведён — «1» не уровень всех её факторов.
	require.Equal(t, http.StatusOK, a.completion.status, "(а): завершение — исход Ф5-03: %s", a.completion.body)
	require.NotNil(t, cookieNamed(a.completion.cookies, loginlanehttp.CookieSession), "(а): сессия выдана")
	if assert.Equal(t, http.StatusUnauthorized, a.after[0].status, "(а): первый неверный пароль после завершения — 401: %s", a.after[0].body) {
		assert.JSONEq(t, refusedLogin, a.after[0].body)
	}
	assertAddressRateRefusal(t, a.after[1], "(а): второй неверный пароль обязан упереться в частоту — счёт по адресу "+
		"НЕ обнулён завершением, бюджет подбора кода второго фактора не обновлён", a.byAddress)

	// (в) замок: заблокирована — сессии нет, вход не завершён, отказ — попытка.
	assert.Equal(t, http.StatusUnauthorized, c.completion.status, "(в): отказ завершения: %s", c.completion.body)
	assert.Equal(t, c.before.body, c.completion.body, "(в): тот же отказ, что на входе заблокированной (Ф1-59, Ф3-02)")
	assert.Nil(t, cookieNamed(c.completion.cookies, loginlanehttp.CookieSession), "(в): сессии нет")
	_, live := people[2].lane.sessionsOfPerson(t)
	assert.Zero(t, live, "(в): живых сессий нет — прежние сняты, новая не выдана (Ф5-17)")
	assertAddressRateRefusal(t, c.after[0], "(в): первый неверный пароль обязан упереться в частоту — отказ завершения "+
		"сосчитан N_адрес-й попыткой, счёт по адресу НЕ обнулён", c.byAddress)
}

// assertAddressRateRefusal — отказ по частоте формы Ф3-28.
func assertAddressRateRefusal(t *testing.T, r reply, why string, countAfterCompletion int) {
	t.Helper()
	if !assert.Equal(t, http.StatusTooManyRequests, r.status, "%s; получено %d %s (счёт по адресу после завершения %d)",
		why, r.status, r.body, countAfterCompletion) {
		return
	}
	assert.Contains(t, r.body, `"reason":"TOO_MANY_ATTEMPTS"`, why)
	assert.Contains(t, r.body, `"too many attempts; try again later"`, why)
	assert.NotEmpty(t, r.header.Get("Retry-After"), "%s: Retry-After", why)
}

// loginAttempt — вход паролем через слушатель с источником из headers; исход
// судит проба.
func (h *sessionLane) loginAttempt(t *testing.T, password string, headers map[string]string) reply {
	t.Helper()
	tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
	return h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathLogin,
		map[string]any{"email": h.email, "password": password, "csrfToken": tok}, headers, ctxCk)
}

// seedEnrolledSecondFactor — «Дано: второй фактор заведён» строкой способа
// входа в состоянии «заведён», посевом операторами хранилища продукта — без
// церемонии заведения (приёмка §7, строка Ф5-25): церемония зовёт место
// решения о счёте сама, а «Дано» не вправе трогать предмет пробы.
func (h *sessionLane) seedEnrolledSecondFactor(t *testing.T) {
	t.Helper()
	secret, err := totpverify.NewSecret()
	require.NoError(t, err)
	material, err := h.secondFactor.TOTP.Wrap(secret)
	require.NoError(t, err)
	at := time.Now().UTC().Truncate(time.Microsecond)
	w, err := h.sessions.Writer(h.ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(h.ctx) }()
	accepted, err := w.UpsertPendingTOTP(h.ctx, domain.LoginMethod{
		UserID: h.user.ID, Kind: domain.LoginMethodTOTP, Verifier: material, State: domain.LoginMethodStatePending, CreatedAt: at,
	})
	require.NoError(t, err)
	require.True(t, accepted, "Дано: строка второго фактора заведена")
	activated, err := w.ActivateTOTP(h.ctx, h.user.ID, at, totpverify.StepAt(at), at)
	require.NoError(t, err)
	require.True(t, activated, "Дано: строка второго фактора в состоянии «заведён»")
	require.NoError(t, w.Commit(h.ctx))
	row, err := kanamepg.NewLoginMethodRepo(h.pool).Get(h.ctx, h.user.ID, domain.LoginMethodTOTP)
	require.NoError(t, err)
	require.True(t, row.Enrolled(), "Дано: хранилище способов читает второй фактор заведённым")
}
