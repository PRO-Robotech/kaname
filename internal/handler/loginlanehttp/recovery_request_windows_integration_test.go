// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// recovery_request_windows_integration_test.go — полоса «частота запроса кода»
// приёмки `docs/engineering/acceptance/recovery-of-access.md` ред. 5 (Р8;
// задачи PRO-Robotech/kaname#246, PRO-Robotech/kacho#2700): держатели Ф5-26
// (окно писем адресата) и Ф5-27 (окно обращений источника) на слушателе
// полосы над настоящими глаголами и настоящей базой.
//
// # Что утверждается
//
// Сверхнормативный запрос кода отвечает ТЕМ ЖЕ, что запрос о адресе, не
// принадлежащем никому (MAIL-25, Р8 п. 3), письма и кода не даёт, прежний код
// не вытесняет (Р8 п. 4); исход различим только клеткой счётчика исходов
// запроса — `recipient-paced` у оси адресата, `source-paced` у оси источника.
// Окно адресата — у пары «вид письма · адрес» (Р8 п. 2), окно источника — у
// пары «полоса · источник».
//
// # Способность упасть
//
// Красного до кода у этих сценариев нет — оба окна посажены `kaname#456`
// (приёмка §9). Способность упасть доказана инъекциями в продукт, по одному
// различию на опыт (§9): снятое списание окна адресата краснеет на (а);
// списание окна, общего для видов письма, — на (в); вытеснение прежнего кода
// своей транзакцией раньше списания — на (а) «прежний код жив»; снятое
// списание окна источника — на Ф5-27 (а); списание окна источника только на
// полосе «адрес есть» — на Ф5-27 (а) «окно исчерпали запросы о
// несуществующем адресе». Сырой вывод инъекций приложен к отчёту полосы.
//
// Run: `go test ./internal/handler/loginlanehttp/ -run 'F5_2[67]' -count=1`
// (Docker). Skipped under -short.
package loginlanehttp_test

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// recoveryCells — счётчик исходов запроса кода (клетки `observer.go`).
type recoveryCells struct {
	humansession.NopObserver
	mu    sync.Mutex
	cells map[humansession.RecoveryRequestOutcome]int
}

func newRecoveryCells() *recoveryCells {
	return &recoveryCells{cells: map[humansession.RecoveryRequestOutcome]int{}}
}

func (o *recoveryCells) RecoveryRequestObserved(outcome humansession.RecoveryRequestOutcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cells[outcome]++
}

func (o *recoveryCells) get(outcome humansession.RecoveryRequestOutcome) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.cells[outcome]
}

// verifiedPerson — свежая личность с подтверждённым адресом: регистрация
// полосой Ф4 и отметка подтверждённости писателем продукта (как Ф5-01).
func (h *sessionLane) verifiedPerson(t *testing.T, tag string) (domain.UserID, string) {
	t.Helper()
	email := tag + "-" + ids.NewID("tst")[3:11] + "@example.invalid"
	reg, err := h.register.Execute(h.ctx, registration.Input{Email: email, Password: integrationPassword,
		Source: "192.0.2.250"})
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): регистрация личности %s", tag)
	require.NoError(t, kanamepg.NewLoginMethodRepo(h.pool).MarkEmailVerified(h.ctx, reg.View.User.ID,
		domain.Email(email), time.Now().UTC()), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): отметка подтверждённости %s", tag)
	return reg.View.User.ID, email
}

// requestCodeFrom — запрос кода для адреса с источника; ответ и контекст формы.
func (h *sessionLane) requestCodeFrom(t *testing.T, email, source string) (reply, *http.Cookie) {
	t.Helper()
	tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormRecovery), nil)
	r := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRecovery,
		map[string]any{"email": email, "csrfToken": tok},
		map[string]string{loginlanehttp.HeaderForwardedFor: source}, ctxCk)
	return r, ctxCk
}

// recoveryLetters — строки очереди писем восстановления личности.
func (h *sessionLane) recoveryLetters(t *testing.T, user domain.UserID) int {
	t.Helper()
	var n int
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT count(*) FROM invite_mail_outbox WHERE resource_id = $1 AND event_type = 'mail.recovery.send'`,
		string(user)).Scan(&n))
	return n
}

// recoveryCodes — строки кодов восстановления личности (любого состояния).
func (h *sessionLane) recoveryCodes(t *testing.T, user domain.UserID) int {
	t.Helper()
	var n int
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM recovery_codes WHERE user_id = $1`,
		string(user)).Scan(&n))
	return n
}

// liveRecoveryCodes — идентификаторы живых (не применённых) кодов личности:
// вытеснение снимает прежние строки, поэтому «код выдан» читается сменой
// множества, а не числом строк.
func (h *sessionLane) liveRecoveryCodes(t *testing.T, user domain.UserID) []string {
	t.Helper()
	rows, err := h.pool.Query(h.ctx, `SELECT id FROM recovery_codes WHERE user_id = $1 AND consumed_at IS NULL ORDER BY id`,
		string(user))
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		out = append(out, id)
	}
	require.NoError(t, rows.Err())
	return out
}

// lastRecoveryCode — код из последнего поставленного письма личности.
func (h *sessionLane) lastRecoveryCode(t *testing.T, user domain.UserID) string {
	t.Helper()
	var code string
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT payload->>'code' FROM invite_mail_outbox WHERE resource_id = $1 AND event_type = 'mail.recovery.send'
		  ORDER BY id DESC LIMIT 1`, string(user)).Scan(&code))
	require.NotEmpty(t, code, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): письмо несёт код")
	return code
}

// Величины пробы: окна малы, чтобы исчерпаться за несколько обращений; окно,
// которое проба НЕ мерит, больше числа её обращений.
const (
	f526LettersPerRecipient = 3
	f527RequestsPerSource   = 3
	recoveryProbeWindow     = time.Hour
	f526Source              = "198.51.100.61"
	f527Source              = "198.51.100.71"
	f527OtherSource         = "198.51.100.72"
)

// TestLaneIntegration_F5_26_RecipientLetterWindow — Ф5-26.
func TestLaneIntegration_F5_26_RecipientLetterWindow(t *testing.T) {
	const newPassword = "recovered-within-the-window-26"
	cells := newRecoveryCells()
	mail := outboxtypes.InviteMailRateLimit{MaxPerWindow: f526LettersPerRecipient, Window: recoveryProbeWindow}
	h := newSessionLaneWith(t, sessionLaneOptions{recoveryMailLimit: mail, recoveryObserver: cells})
	n := mail.MaxPerWindow
	t.Logf("Дано: окно писем адресата N=%d за T=%s; окно источника %d за %s (больше %d обращений пробы)",
		n, mail.Window, laneSourcePace.Limit, laneSourcePace.Window, 2*n+3)

	p, pEmail := h.verifiedPerson(t, "f526p")
	q, qEmail := h.verifiedPerson(t, "f526q")
	pp, ppEmail := h.verifiedPerson(t, "f526pp")
	z := "f526z-" + ids.NewID("tst")[3:11] + "@example.invalid"

	// (а) N + 1 запросов для P в одном окне.
	queued0, paced0 := cells.get(humansession.RecoveryRequestQueued), cells.get(humansession.RecoveryRequestRecipientPaced)
	var (
		last     reply
		nthCtxCk *http.Cookie
		nthLive  []string
	)
	for i := 1; i <= n+1; i++ {
		r, ctxCk := h.requestCodeFrom(t, pEmail, f526Source)
		require.Equal(t, http.StatusOK, r.status, "запрос %d для P: %s", i, r.body)
		if i == n {
			nthCtxCk = ctxCk
			nthLive = h.liveRecoveryCodes(t, p)
			require.Len(t, nthLive, 1, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): после N-го запроса живой код один")
		}
		last = r
	}
	nobody, _ := h.requestCodeFrom(t, z, f526Source)

	require.Equal(t, n, h.recoveryLetters(t, p),
		"Ф5-26 (а): в очереди писем восстановления P ровно N строк — N+1-й запрос письма не поставил")
	require.Equal(t, nthLive, h.liveRecoveryCodes(t, p),
		"Ф5-26 (а): N+1-й запрос кода не выдал и прежнего не вытеснил — живой код тот же, что после N-го")
	require.Equal(t, nobody.status, last.status, "Ф5-26 (а): код ответа N+1-го запроса = ответу о несуществующем адресе")
	require.Equal(t, nobody.body, last.body, "Ф5-26 (а): тело ответа N+1-го запроса = ответу о несуществующем адресе")
	require.Equal(t, 1, cells.get(humansession.RecoveryRequestRecipientPaced)-paced0,
		"Ф5-26 (а): клетка recipient-paced выросла ровно на 1")
	require.Equal(t, n, cells.get(humansession.RecoveryRequestQueued)-queued0,
		"Ф5-26 (а): клетка queued выросла ровно на N")

	// (а) прежний код — из N-го письма — жив: сверхнормативный запрос его не
	// вытеснил (Р8 п. 4).
	code := h.lastRecoveryCode(t, p)
	done := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRecoveryComplete, map[string]any{
		"email": pEmail, "code": code, "newPassword": newPassword,
		"csrfToken": h.csrfFor(t, domain.FormRecoveryComplete, nthCtxCk),
	}, map[string]string{loginlanehttp.HeaderForwardedFor: f526Source}, nthCtxCk)
	require.Equal(t, http.StatusOK, done.status,
		"Ф5-26 (а): код из N-го письма предъявляется и проходит (Ф5-03) — прежний код не вытеснен: %s", done.body)

	// (б) [близнец (а)] — один факт, адрес: запрос для Q в том же окне.
	r, _ := h.requestCodeFrom(t, qEmail, f526Source)
	require.Equal(t, http.StatusOK, r.status)
	require.Equal(t, 1, h.recoveryLetters(t, q), "Ф5-26 (б): окно принадлежит адресу — письмо Q поставлено")

	// (в) [близнец (а)] — один факт, вид заполненного окна: окно писем
	// ПРИГЛАШЕНИЯ P′ заполнено посевом до N.
	_, err := h.pool.Exec(h.ctx, `
		INSERT INTO kaname.invite_mail_windows (kind, recipient, window_started_at, sent, updated_at)
		VALUES ('invite', lower($1), now(), $2, now())`, ppEmail, n)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): окно приглашений P′ посевом")
	for i := 1; i <= n; i++ {
		r, _ := h.requestCodeFrom(t, ppEmail, f526Source)
		require.Equal(t, http.StatusOK, r.status)
	}
	require.Equal(t, n, h.recoveryLetters(t, pp),
		"Ф5-26 (в): окно у пары «вид письма · адрес» — полное окно приглашений не выедает окна восстановления")
}

// TestLaneIntegration_F5_27_SourceRequestWindow — Ф5-27.
func TestLaneIntegration_F5_27_SourceRequestWindow(t *testing.T) {
	cells := newRecoveryCells()
	src := humansession.SourcePace{Limit: f527RequestsPerSource, Window: recoveryProbeWindow}
	h := newSessionLaneWith(t, sessionLaneOptions{recoverySourcePace: src, recoveryObserver: cells})
	m := src.Limit
	t.Logf("Дано: окно обращений источника M=%d за %s; окно писем адресата %d за %s (больше %d обращений пробы)",
		m, src.Window, laneMailLimit.MaxPerWindow, laneMailLimit.Window, m+2)

	p, pEmail := h.verifiedPerson(t, "f527p")
	z := "f527z-" + ids.NewID("tst")[3:11] + "@example.invalid"

	var nobody reply
	for i := 1; i <= m; i++ {
		nobody, _ = h.requestCodeFrom(t, z, f527Source)
		require.Equal(t, http.StatusOK, nobody.status, "запрос %d для Z: %s", i, nobody.body)
	}
	paced0 := cells.get(humansession.RecoveryRequestSourcePaced)

	// (а) окно источника S исчерпали запросы о НЕСУЩЕСТВУЮЩЕМ адресе.
	r, _ := h.requestCodeFrom(t, pEmail, f527Source)
	require.Equal(t, nobody.status, r.status, "Ф5-27 (а): код ответа для P = ответу о несуществующем адресе")
	require.Equal(t, nobody.body, r.body, "Ф5-27 (а): тело ответа для P = ответу о несуществующем адресе")
	require.Zero(t, h.recoveryLetters(t, p),
		"Ф5-27 (а): письма для P нет — окно источника исчерпали запросы о несуществующем адресе")
	require.Zero(t, h.recoveryCodes(t, p), "Ф5-27 (а): кода для P не выдано")
	require.Equal(t, 1, cells.get(humansession.RecoveryRequestSourcePaced)-paced0,
		"Ф5-27 (а): клетка source-paced выросла ровно на 1")

	// (б) [близнец (а)] — один факт, источник: тот же запрос с S′.
	queued0 := cells.get(humansession.RecoveryRequestQueued)
	r, _ = h.requestCodeFrom(t, pEmail, f527OtherSource)
	require.Equal(t, http.StatusOK, r.status)
	require.Equal(t, 1, h.recoveryLetters(t, p), "Ф5-27 (б): с другого источника письмо P поставлено (Ф5-01)")
	require.Equal(t, 1, cells.get(humansession.RecoveryRequestQueued)-queued0, "Ф5-27 (б): клетка queued выросла на 1")
}
