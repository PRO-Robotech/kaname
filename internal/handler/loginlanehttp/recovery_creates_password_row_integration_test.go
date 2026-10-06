// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// recovery_creates_password_row_integration_test.go — Ф5-34 на настоящем
// хранилище (задача PRO-Robotech/kacho#2698, исход 1; приёмка Ф5, редакция с
// отпечатком be4dfb5a…, одобренная в PRO-Robotech/kaname#612): у личности без
// строки «пароль» завершение восстановления строку ЗАВОДИТ; под конкуренцией
// `K` предъявлений одного кода с разными паролями проходит ровно одно, строка
// «пароль» одна, и входит личность паролем победителя (ban #10 — решает
// оператор применения кода и ключ строки хранилища, а не проверка перед
// вставкой).
//
// «Дано» — личность стенда со снятой ЗАПИСЬЮ строкой «пароль» (§5.6 (8):
// производителя такого состояния в проде нет).
package loginlanehttp_test

import (
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func (h *sessionLane) passwordRows(t *testing.T) int {
	t.Helper()
	var n int
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT count(*) FROM user_login_methods WHERE user_id = $1 AND kind = 'password'`, string(h.user.ID)).Scan(&n))
	return n
}

func (h *sessionLane) dropPasswordRow(t *testing.T) {
	t.Helper()
	// Дано: адрес подтверждён — писателем продукта (Ф6), как у Ф5-24.
	require.NoError(t, kanamepg.NewLoginMethodRepo(h.pool).MarkEmailVerified(h.ctx, h.user.ID, h.user.Email, time.Now().UTC()))
	seedPasswordless(t, h.ctx, h.pool, h.user.ID)
}

func TestLaneIntegration_F5_34_RecoveryCreatesTheMissingPasswordRow(t *testing.T) {
	h := newSessionLane(t)
	h.dropPasswordRow(t)
	code, ctxCk := h.requestRecoveryCode(t, fwd())

	done := h.completeRecovery(t, code, "recovered-password-f5-34", fwd(), ctxCk)
	require.Equalf(t, http.StatusOK, done.status, "Ф5-34 (а): завершение у личности без строки — исход Ф5-03, не 503: %s", done.body)
	require.NotNil(t, cookieNamed(done.cookies, loginlanehttp.CookieSession), "сессия выдана")
	require.Equal(t, 1, h.passwordRows(t), "Ф5-34 (г): строка «пароль» ровно одна")

	again := h.completeRecovery(t, code, "another-password-f5-34", fwd(), ctxCk)
	require.Equal(t, http.StatusUnauthorized, again.status, "повтор — отказ Ф5-05")

	tok, ck := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
	in := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathLogin,
		map[string]any{"email": h.email, "password": "recovered-password-f5-34", "csrfToken": tok}, fwd(), ck)
	require.Equalf(t, http.StatusOK, in.status, "вход новым паролем: %s", in.body)
}

func TestLaneIntegration_F5_34_ConcurrentPresentationsCreateOneRow(t *testing.T) {
	h := newSessionLane(t)
	h.dropPasswordRow(t)
	code, ctxCk := h.requestRecoveryCode(t, fwd())

	const racers = 3
	forms := make([]map[string]any, racers)
	for i := range forms {
		forms[i] = map[string]any{
			"email": h.email, "code": code, "newPassword": fmt.Sprintf("racing-password-f5-34-%d", i),
			"csrfToken": h.csrfFor(t, domain.FormRecoveryComplete, ctxCk),
		}
	}
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		statuses = map[int]int{}
	)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st := postStatus(h, loginlanehttp.PathRecoveryComplete, forms[i], ctxCk)
			mu.Lock()
			statuses[i] = st
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	winner := -1
	for i, st := range statuses {
		if st == http.StatusOK {
			require.Equal(t, -1, winner, "Ф5-34 (г): проходит ровно одно предъявление")
			winner = i
		} else {
			require.Equalf(t, http.StatusUnauthorized, st, "проигравший — отказ Ф5-05, а не %d", st)
		}
	}
	require.NotEqual(t, -1, winner, "одно предъявление прошло")
	require.Equal(t, 1, h.passwordRows(t), "строка «пароль» одна")

	tok, ck := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
	in := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathLogin,
		map[string]any{"email": h.email, "password": forms[winner]["newPassword"], "csrfToken": tok}, fwd(), ck)
	require.Equalf(t, http.StatusOK, in.status, "входит паролем победителя: %s", in.body)
}
