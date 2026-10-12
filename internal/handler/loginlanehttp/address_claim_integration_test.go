// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// address_claim_integration_test.go — АДРЕС, ЗАНЯТЫЙ НЕПОДТВЕРЖДЁННОЙ ЗАПИСЬЮ,
// ПЕРЕХОДИТ К ВЛАДЕЛЬЦУ ЯЩИКА (задача PRO-Robotech/kaname#458; приёмка
// `docs/engineering/acceptance/unverified-address-passes-to-the-mailbox-owner.md`,
// редакция 4, сценарии A458-01…A458-09 и A458-11…A458-13, DoD п. 2 (в) и п. 3).
//
// # Стенд
//
// Пробы идут на ПРОВОДЕ полосы формы: слушатель над настоящими глаголами и
// настоящими адаптерами базы (`sessionLane`, `avLane`). Код восстановления
// берётся ИЗ СТРОКИ ОЧЕРЕДИ письма этого человека до её дренажа (§5 приёмки):
// проба судит производителя письма, а не выдумывает код. Удостоверения записи
// (второй фактор, ключ доступа, личные токены) и начатые заведения кладутся
// посевом писателями хранилища продукта: после посадки kaname#456
// неподтверждённая запись завести их сама не может, а записи до посадки могли.
//
// # Ступени и их слова
//
//  1. МИР — база, человек, сессия прежнего держателя заведены и прочитаны
//     обратно. Отказ — «НЕ-ВЫПОЛНИЛОСЬ(фикстура)»: сломан вопрос, а не ответ.
//  2. ПРЕДМЕТ — утверждения сценария; отказ несёт номер сценария. Код на
//     неподтверждённый адрес записи с паролем (П1) — предмет A458-01 и общее
//     «Дано» остальных: его отсутствие называется «ПРЕДМЕТ A458-01 (П1)», а не
//     поломкой фикстуры, потому что мир к этому шагу уже проверен.
//
// Слова клеток, причины конца сессии и поля события (`address-claimed`,
// `address-verified`, `invite-not-valid`, `address_claimed`) проба называет
// ЛИТЕРАЛАМИ из приёмки,
// а не константами продукта: её предмет и есть то, что продукт их завёл, и
// ссылка на несуществующую константу не собралась бы — «не выполнилось», а не
// красный.
//
// Run: `go test ./internal/handler/loginlanehttp/ -run 'A458' -count=1`
// (Docker). Skipped under -short.
package loginlanehttp_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user_tokens"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/signingkeygen"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Слова приёмки, дословно (Р2, Р3 п. 6, Р6, Р7).
const (
	a458ReasonClaimed    = "address-claimed"
	a458CellClaimed      = "address-claimed"
	a458CellVerified     = "address-verified"
	a458CellInviteNot    = "invite-not-valid"
	a458EventField       = "address_claimed"
	a458NewPassword      = "a-mailbox-owner-password-458"
	a458InviteNotValidTx = "invite is no longer valid; ask an account administrator to invite again"
	a458Source           = "198.51.100.158"
)

// a458AuthFailedBody — отказ входа на проводе полосы формы побайтово: та же
// форма тела, что у всякого отказа полосы (`refusalWire`: код, текст,
// `details`), — «401 / 16 authentication failed» приёмки.
var a458AuthFailedBody = refusalWire(16, "authentication failed")

// a458Cells — счётчик исходов запроса кода и завершения восстановления
// (клетки `observer.go`), ключом — слово клетки.
type a458Cells struct {
	humansession.NopObserver
	mu       sync.Mutex
	request  map[string]int
	complete map[string]int
}

func newA458Cells() *a458Cells {
	return &a458Cells{request: map[string]int{}, complete: map[string]int{}}
}

func (o *a458Cells) RecoveryRequestObserved(outcome humansession.RecoveryRequestOutcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.request[string(outcome)]++
}

func (o *a458Cells) RecoveryCompletionObserved(outcome humansession.RecoveryCompletionOutcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.complete[string(outcome)]++
}

func (o *a458Cells) req(outcome string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.request[outcome]
}

func (o *a458Cells) done(outcome string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.complete[outcome]
}

// ─────────────────────────────────────────────────────────────────────────────
// Помощники стенда `sessionLane` для человека, названного адресом.
// ─────────────────────────────────────────────────────────────────────────────

// a458Person — запись человека стенда: идентификатор и адрес.
type a458Person struct {
	id    domain.UserID
	email string
}

// holder — запись стенда (прежний держатель зарегистрировался полосой Ф4
// паролем `integrationPassword`; адрес не подтверждён).
func (h *sessionLane) holder(t *testing.T) a458Person {
	t.Helper()
	_, verified, err := kanamepg.NewLoginMethodRepo(h.pool).EmailVerification(h.ctx, h.user.ID)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): подтверждённость записи стенда не читается")
	require.False(t, verified, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): адрес записи стенда обязан быть не подтверждён")
	return a458Person{id: h.user.ID, email: h.email}
}

// registerAnother — ещё одна запись регистрацией полосы Ф4; адрес не подтверждён.
func (h *sessionLane) registerAnother(t *testing.T, tag string) a458Person {
	t.Helper()
	email := tag + "-" + ids.NewID("tst")[3:11] + "@example.invalid"
	reg, err := h.register.Execute(h.ctx, registration.Input{Email: email, Password: integrationPassword, Source: "192.0.2.251"})
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): регистрация %s", tag)
	return a458Person{id: reg.View.User.ID, email: email}
}

// loginAs — вход паролем через слушатель; ответ как есть.
func (h *sessionLane) loginAs(t *testing.T, email, password string) reply {
	t.Helper()
	tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
	return h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathLogin,
		map[string]any{"email": email, "password": password, "csrfToken": tok},
		map[string]string{loginlanehttp.HeaderForwardedFor: a458Source}, ctxCk)
}

// sessionOf — вход, выдавший сессию прежнему держателю: «Дано: S-old».
func (h *sessionLane) sessionOf(t *testing.T, p a458Person) *http.Cookie {
	t.Helper()
	r := h.loginAs(t, p.email, integrationPassword)
	require.Equal(t, http.StatusOK, r.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): вход прежнего держателя: %s", r.body)
	b := cookieNamed(r.cookies, loginlanehttp.CookieSession)
	require.NotNil(t, b, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): вход прежнего держателя не выдал носитель")
	require.True(t, h.resolve(t, b.Value).GetFound(), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): S-old жива до события")
	return b
}

// letterCodes — коды писем восстановления человека по порядку постановки.
func (h *sessionLane) letterCodes(t *testing.T, user domain.UserID) []string {
	t.Helper()
	rows, err := h.pool.Query(h.ctx,
		`SELECT coalesce(payload->>'code', '') FROM invite_mail_outbox
		  WHERE resource_id = $1 AND event_type = 'mail.recovery.send' ORDER BY id`, string(user))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): чтение очереди писем")
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		require.NoError(t, rows.Scan(&c))
		out = append(out, c)
	}
	require.NoError(t, rows.Err())
	return out
}

// claimCode — владелец ящика запрашивает код и читает его из строки очереди.
// Письма нет — ПРЕДМЕТ A458-01 (П1) отсутствует: мир к этому шагу проверен.
func (h *sessionLane) claimCode(t *testing.T, id string, p a458Person) (string, *http.Cookie) {
	t.Helper()
	before := len(h.letterCodes(t, p.id))
	r, ctxCk := h.requestCodeFrom(t, p.email, a458Source)
	require.Equal(t, http.StatusOK, r.status, "%s: запрос кода отвечает 200: %s", id, r.body)
	codes := h.letterCodes(t, p.id)
	if len(codes) <= before {
		t.Fatalf("%s ПРЕДМЕТ A458-01 (П1): код на неподтверждённый адрес записи с паролем не выдан — "+
			"в очереди нет новой строки mail.recovery.send для %s (было %d, стало %d)", id, p.id, before, len(codes))
	}
	code := codes[len(codes)-1]
	require.NotEmpty(t, code, "%s: письмо несёт код", id)
	return code, ctxCk
}

// completeAs — предъявление кода с новым паролем через слушатель.
func (h *sessionLane) completeAs(t *testing.T, email, code, newPassword string, ctxCk *http.Cookie) reply {
	t.Helper()
	return h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRecoveryComplete, map[string]any{
		"email": email, "code": code, "newPassword": newPassword,
		"csrfToken": h.csrfFor(t, domain.FormRecoveryComplete, ctxCk),
	}, map[string]string{loginlanehttp.HeaderForwardedFor: a458Source}, ctxCk)
}

// claim — запрос кода и завершение им; ответ завершения как есть.
func (h *sessionLane) claim(t *testing.T, id string, p a458Person) reply {
	t.Helper()
	code, ctxCk := h.claimCode(t, id, p)
	return h.completeAs(t, p.email, code, a458NewPassword, ctxCk)
}

// markVerified — отметка подтверждения посевом, писателем продукта.
func (h *sessionLane) markVerified(t *testing.T, p a458Person) {
	t.Helper()
	require.NoError(t, kanamepg.NewLoginMethodRepo(h.pool).MarkEmailVerified(h.ctx, p.id, domain.Email(p.email), time.Now().UTC()),
		"НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев отметки подтверждения")
}

// verifiedNow — стоит ли отметка подтверждения у записи.
func (h *sessionLane) verifiedNow(t *testing.T, p a458Person) bool {
	t.Helper()
	var at *time.Time
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT email_verified_at FROM kaname.users WHERE id = $1`, string(p.id)).Scan(&at))
	return at != nil
}

// recoveryAudit — события завершения восстановления о человеке.
func (h *sessionLane) recoveryAudit(t *testing.T, p a458Person) []map[string]any {
	t.Helper()
	rows, err := h.pool.Query(h.ctx, `
		SELECT event_payload FROM kaname.audit_outbox
		 WHERE event_type = $1 AND event_payload->>'user_id' = $2 ORDER BY created_at, id`,
		humansession.AuditRecoveryCompleted, string(p.id))
	require.NoError(t, err)
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var raw []byte
		require.NoError(t, rows.Scan(&raw))
		var m map[string]any
		require.NoError(t, json.Unmarshal(raw, &m))
		out = append(out, m)
	}
	require.NoError(t, rows.Err())
	return out
}

// liveCodes — живые коды восстановления человека.
func (h *sessionLane) liveCodes(t *testing.T, p a458Person) int {
	t.Helper()
	return len(h.liveRecoveryCodes(t, p.id))
}

// liveSessionsOf — живые записи сессий человека.
func (h *sessionLane) liveSessionsOf(t *testing.T, p a458Person) int {
	t.Helper()
	var n int
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT count(*) FROM human_sessions WHERE user_id = $1 AND ended_at IS NULL`, string(p.id)).Scan(&n))
	return n
}

// claimedSession — тело успеха завершения: идентификатор человека и подтверждённость.
func claimedSession(t *testing.T, body string) (userID string, emailVerified bool) {
	t.Helper()
	var out struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Session struct {
			EmailVerified bool `json:"emailVerified"`
		} `json:"session"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &out), body)
	return out.User.ID, out.Session.EmailVerified
}

// ─────────────────────────────────────────────────────────────────────────────
// A458-01: код выдаётся на неподтверждённый адрес записи с паролем.
// ─────────────────────────────────────────────────────────────────────────────

// TestA458_01_CodeIsIssuedToTheUnverifiedAddressOfARecordWithAPassword —
// A458-01 и близнецы (а) `BLOCKED` с паролем, (б) `PENDING` без пароля.
func TestA458_01_CodeIsIssuedToTheUnverifiedAddressOfARecordWithAPassword(t *testing.T) {
	cells := newA458Cells()
	h := newSessionLaneWith(t, sessionLaneOptions{recoveryObserver: cells})
	holder := h.holder(t)

	// Эталон ответа — адрес, которого нет ни у кого (Ф5-02).
	nobody, _ := h.requestCodeFrom(t, "nobody-"+ids.NewID("tst")[3:11]+"@example.invalid", a458Source)
	require.Equal(t, http.StatusOK, nobody.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): ответ о несуществующем адресе: %s", nobody.body)

	// Близнецы — строки, у которых неподтверждённый адрес кода не даёт.
	blocked := h.registerAnother(t, "a458-blocked")
	{
		w, err := h.users.Writer(h.ctx)
		require.NoError(t, err)
		_, err = w.UsersW().SetInviteStatus(h.ctx, blocked.id, domain.InviteStatusBlocked)
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): блокировка писателем продукта")
		require.NoError(t, w.Commit(h.ctx))
	}
	invited := a458Person{email: "a458-invited-" + ids.NewID("tst")[3:11] + "@example.invalid"}
	{
		w, err := h.users.Writer(h.ctx)
		require.NoError(t, err)
		row, _, err := w.UsersW().InsertPending(h.ctx, domain.User{
			ID: domain.UserID(ids.NewID(domain.PrefixUser)), AccountID: h.user.AccountID, Email: domain.Email(invited.email),
			DisplayName: "invitee-458", InviteStatus: domain.InviteStatusPending, InvitedBy: h.user.ID,
		}, time.Now().UTC().Add(24*time.Hour))
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): строка приглашения без пароля")
		require.NoError(t, w.Commit(h.ctx))
		invited.id = row.ID
	}

	for _, twin := range []struct {
		name string
		p    a458Person
	}{{"(а) BLOCKED с паролем", blocked}, {"(б) PENDING без пароля", invited}} {
		unverifiedBefore := cells.req(string(humansession.RecoveryRequestUnverified))
		r, _ := h.requestCodeFrom(t, twin.p.email, a458Source)
		require.Equal(t, http.StatusOK, r.status, "A458-01 %s: %s", twin.name, r.body)
		require.Equal(t, nobody.body, r.body, "A458-01 %s: ответ побайтово тот же", twin.name)
		require.Zero(t, h.recoveryLetters(t, twin.p.id), "A458-01 %s: письма нет", twin.name)
		require.Zero(t, h.recoveryCodes(t, twin.p.id), "A458-01 %s: кода нет", twin.name)
		require.Equal(t, unverifiedBefore+1, cells.req(string(humansession.RecoveryRequestUnverified)),
			"A458-01 %s: клетка unverified прибавила 1", twin.name)
	}

	// Предмет: запись ACTIVE с паролем и неподтверждённым адресом.
	queuedBefore := cells.req(string(humansession.RecoveryRequestQueued))
	unverifiedBefore := cells.req(string(humansession.RecoveryRequestUnverified))
	r, _ := h.requestCodeFrom(t, holder.email, a458Source)
	require.Equal(t, http.StatusOK, r.status, "A458-01: %s", r.body)
	require.Equal(t, nobody.body, r.body, "A458-01: ответ побайтово равен ответу на адрес, которого нет ни у кого")
	require.Equal(t, 1, h.recoveryLetters(t, holder.id), "A458-01: в очереди ровно одна строка mail.recovery.send на адрес записи")
	require.Equal(t, 1, h.liveCodes(t, holder), "A458-01: у записи ровно один живой код восстановления")
	require.Equal(t, queuedBefore+1, cells.req(string(humansession.RecoveryRequestQueued)), "A458-01: клетка queued прибавила 1")
	require.Equal(t, unverifiedBefore, cells.req(string(humansession.RecoveryRequestUnverified)), "A458-01: клетка unverified — 0")
}

// ─────────────────────────────────────────────────────────────────────────────
// A458-02: предъявление кода переводит запись к владельцу ящика.
// ─────────────────────────────────────────────────────────────────────────────

// TestA458_02_PresentingTheCodePassesTheRecordToTheMailboxOwner — A458-02.
func TestA458_02_PresentingTheCodePassesTheRecordToTheMailboxOwner(t *testing.T) {
	cells := newA458Cells()
	h := newSessionLaneWith(t, sessionLaneOptions{completionObserver: cells})
	holder := h.holder(t)
	sOld := h.sessionOf(t, holder)
	claimedBefore, issuedBefore := cells.done(a458CellClaimed), cells.done(string(humansession.RecoveryCompletionIssued))

	done := h.claim(t, "A458-02", holder)

	require.Equal(t, http.StatusOK, done.status, "A458-02: завершение — 200: %s", done.body)
	require.NotNil(t, cookieNamed(done.cookies, loginlanehttp.CookieSession), "A458-02: Set-Cookie несёт новый носитель")
	uid, verified := claimedSession(t, done.body)
	require.Equal(t, string(holder.id), uid, "A458-02: user.id — та же запись, что заводил прежний держатель")
	require.True(t, verified, "A458-02: session.emailVerified = true")
	require.True(t, h.verifiedNow(t, holder), "A458-02: у записи стоит отметка подтверждения")

	old := h.loginAs(t, holder.email, integrationPassword)
	require.Equal(t, http.StatusUnauthorized, old.status, "A458-02: вход прежним паролем — 401: %s", old.body)
	require.Equal(t, a458AuthFailedBody, old.body, "A458-02: вход прежним паролем — 16 authentication failed")
	require.Equal(t, http.StatusOK, h.loginAs(t, holder.email, a458NewPassword).status, "A458-02: вход новым паролем — 200")

	require.False(t, h.resolve(t, sOld.Value).GetFound(), "A458-02: «кто я» по S-old — сессии нет")
	require.Equal(t, a458ReasonClaimed, h.endedReason(t, sOld.Value), "A458-02: S-old закрыта причиной address-claimed")
	require.Equal(t, a458ReasonClaimed, h.cutoffReason(t, holder.id), "A458-02: отсечка записи — причиной address-claimed")

	events := h.recoveryAudit(t, holder)
	require.Len(t, events, 1, "A458-02: одно событие iam.user.recovery_completed")
	require.Equal(t, true, events[0][a458EventField], "A458-02: событие несёт address_claimed: true: %v", events[0])
	for k, v := range events[0] {
		require.NotContains(t, toString(v), holder.email, "A458-02: адреса в событии нет (поле %s)", k)
	}
	require.Equal(t, claimedBefore+1, cells.done(a458CellClaimed), "A458-02: клетка address-claimed прибавила 1")
	require.Equal(t, issuedBefore, cells.done(string(humansession.RecoveryCompletionIssued)), "A458-02: клетка issued — 0")
}

// TestA458_02_Twin_VerifiedRecordIsOrdinaryRecovery — близнец A458-02 (адрес
// подтверждён до выдачи кода): обычное восстановление.
func TestA458_02_Twin_VerifiedRecordIsOrdinaryRecovery(t *testing.T) {
	cells := newA458Cells()
	h := newSessionLaneWith(t, sessionLaneOptions{completionObserver: cells})
	holder := h.holder(t)
	h.markVerified(t, holder)
	sOld := h.sessionOf(t, holder)
	claimedBefore, issuedBefore := cells.done(a458CellClaimed), cells.done(string(humansession.RecoveryCompletionIssued))

	done := h.claim(t, "A458-02 близнец", holder)

	require.Equal(t, http.StatusOK, done.status, "A458-02 близнец: 200: %s", done.body)
	_, verified := claimedSession(t, done.body)
	require.True(t, verified, "A458-02 близнец: emailVerified = true")
	require.Equal(t, string(domain.RevokeReasonPasswordChange), h.endedReason(t, sOld.Value), "A458-02 близнец: S-old — password-change")
	events := h.recoveryAudit(t, holder)
	require.Len(t, events, 1, "A458-02 близнец: одно событие")
	require.Equal(t, false, events[0][a458EventField], "A458-02 близнец: событие несёт address_claimed: false: %v", events[0])
	require.Equal(t, issuedBefore+1, cells.done(string(humansession.RecoveryCompletionIssued)), "A458-02 близнец: issued +1")
	require.Equal(t, claimedBefore, cells.done(a458CellClaimed), "A458-02 близнец: address-claimed — 0")
}

// a458VerifyBetween — хранилище завершения, которое ставит отметку
// подтверждения МЕЖДУ чтением адреса и транзакцией исхода (DoD п. 2 (в)):
// подтвердить запись в полёте мог только владелец ящика.
type a458VerifyBetween struct {
	*kanamepg.HumanSessionRepo
	armed atomic.Bool
	mark  func()
}

func (s *a458VerifyBetween) RecoveryTarget(ctx context.Context, email domain.Email) (humansession.RecoveryTarget, bool, error) {
	target, found, err := s.HumanSessionRepo.RecoveryTarget(ctx, email)
	if err == nil && found && s.armed.CompareAndSwap(true, false) {
		s.mark()
	}
	return target, found, err
}

// TestA458_02_Race_VerifiedInFlightIsOrdinaryRecovery — проба гонки DoD п. 2
// (в), близнец A458-02 при подтверждении в полёте: запись подтверждена между
// выдачей кода и предъявлением, ПОСЛЕ чтения адреса завершением — ветвь
// решает отметка под замком, и исход — обычное восстановление: у записи без
// удостоверений переход снял бы начатые заведения, здесь они на месте.
func TestA458_02_Race_VerifiedInFlightIsOrdinaryRecovery(t *testing.T) {
	cells := newA458Cells()
	var seam *a458VerifyBetween
	h := newSessionLaneWith(t, sessionLaneOptions{completionObserver: cells,
		completeStore: func(r *kanamepg.HumanSessionRepo) humansession.Store {
			seam = &a458VerifyBetween{HumanSessionRepo: r}
			return seam
		}})
	holder := h.holder(t)
	seam.mark = func() { h.markVerified(t, holder) }
	h.seedStartedEnrolments(t, holder)
	sOld := h.sessionOf(t, holder)
	code, ctxCk := h.claimCode(t, "A458-02 гонка", holder)

	seam.armed.Store(true)
	done := h.completeAs(t, holder.email, code, a458NewPassword, ctxCk)

	require.False(t, seam.armed.Load(), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): шов подтверждения в полёте не сработал")
	require.Equal(t, http.StatusOK, done.status, "A458-02 гонка: 200: %s", done.body)
	require.Equal(t, string(domain.RevokeReasonPasswordChange), h.endedReason(t, sOld.Value),
		"A458-02 гонка: подтверждённая в полёте запись — обычное восстановление: S-old — password-change")
	require.Equal(t, a458Rows{started: 1, challenges: 1}, h.credentialRows(t, holder),
		"A458-02 гонка: начатые заведения владельца ящика на месте")
	events := h.recoveryAudit(t, holder)
	require.Len(t, events, 1)
	require.Equal(t, false, events[0][a458EventField], "A458-02 гонка: address_claimed: false: %v", events[0])
	require.Zero(t, cells.done(a458CellClaimed), "A458-02 гонка: клетка address-claimed — 0")
}

// ─────────────────────────────────────────────────────────────────────────────
// Посев удостоверений «Дано» (§5 приёмки): писатели хранилища продукта, посев
// читается обратно до «Когда»; не лёг — «НЕ-ВЫПОЛНИЛОСЬ(фикстура)».
// ─────────────────────────────────────────────────────────────────────────────

// a458Rows — строки удостоверений и начатых заведений человека: factor —
// заведённый второй фактор (генератор не в состоянии «начато» и набор
// резервных кодов), started — начатое заведение генератора, keys — ключи
// доступа, challenges — неиспользованные испытания регистрации ключа, tokens —
// личные токены.
type a458Rows struct{ factor, started, keys, challenges, tokens int }

func (h *sessionLane) credentialRows(t *testing.T, p a458Person) a458Rows {
	t.Helper()
	var r a458Rows
	require.NoError(t, h.pool.QueryRow(h.ctx, `
		SELECT (SELECT count(*) FROM user_login_methods
		         WHERE user_id = $1 AND ((kind = $2 AND state <> $4) OR kind = $3)),
		       (SELECT count(*) FROM user_login_methods WHERE user_id = $1 AND kind = $2 AND state = $4),
		       (SELECT count(*) FROM user_access_keys WHERE user_id = $1),
		       (SELECT count(*) FROM access_key_challenges WHERE user_id = $1 AND purpose = 'registration' AND consumed_at IS NULL),
		       (SELECT count(*) FROM user_oauth_clients WHERE user_id = $1)`,
		string(p.id), string(domain.LoginMethodTOTP), string(domain.LoginMethodLookupSecret), string(domain.LoginMethodStatePending)).
		Scan(&r.factor, &r.started, &r.keys, &r.challenges, &r.tokens))
	return r
}

// seedStartedEnrolments — начатое заведение генератора (строка в состоянии
// «начато») и начатое испытание регистрации ключа доступа.
func (h *sessionLane) seedStartedEnrolments(t *testing.T, p a458Person) {
	t.Helper()
	secret, err := totpverify.NewSecret()
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): секрет генератора")
	material, err := h.secondFactor.TOTP.Wrap(secret)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): материал генератора")
	{
		w, err := h.sessions.Writer(h.ctx)
		require.NoError(t, err)
		defer func() { _ = w.Rollback(h.ctx) }()
		accepted, err := w.UpsertPendingTOTP(h.ctx, domain.LoginMethod{UserID: p.id, Kind: domain.LoginMethodTOTP,
			Verifier: material, State: domain.LoginMethodStatePending, CreatedAt: time.Now().UTC().Truncate(time.Microsecond)})
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): начатое заведение генератора")
		require.True(t, accepted, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): начатое заведение генератора легло")
		require.NoError(t, w.Commit(h.ctx))
	}
	{
		w, err := kanamepg.NewAccessKeyRepo(h.pool).Writer(h.ctx)
		require.NoError(t, err)
		defer func() { _ = w.Rollback(h.ctx) }()
		challenge := make([]byte, 32)
		_, err = rand.Read(challenge)
		require.NoError(t, err)
		now := time.Now().UTC().Truncate(time.Microsecond)
		require.NoError(t, w.InsertChallenge(h.ctx, domain.AccessKeyChallenge{Challenge: challenge, UserID: p.id,
			Purpose: domain.ChallengeForRegistration, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}),
			"НЕ-ВЫПОЛНИЛОСЬ(фикстура): начатое испытание регистрации ключа")
		require.NoError(t, w.Commit(h.ctx))
	}
	require.Equal(t, a458Rows{started: 1, challenges: 1}, h.credentialRows(t, p), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев прочитан обратно")
}

// seedEnrolledFactor — заведённый второй фактор: генератор в состоянии
// «заведён» и набор резервных кодов. Пробе достаются секрет генератора и
// ступень, принятая заведением.
func (h *sessionLane) seedEnrolledFactor(t *testing.T, p a458Person) (totpverify.Secret, int64) {
	t.Helper()
	secret, err := totpverify.NewSecret()
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): секрет генератора")
	material, err := h.secondFactor.TOTP.Wrap(secret)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): материал генератора")
	backup, err := passwordverify.NewBackupCodes()
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): чеканка резервных кодов")
	set, err := h.secondFactor.SetHasher.HashSet(backup)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): набор резервных кодов")
	at := time.Now().UTC().Truncate(time.Microsecond)
	step := totpverify.StepAt(at)
	w, err := h.sessions.Writer(h.ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(h.ctx) }()
	accepted, err := w.UpsertPendingTOTP(h.ctx, domain.LoginMethod{UserID: p.id, Kind: domain.LoginMethodTOTP,
		Verifier: material, State: domain.LoginMethodStatePending, CreatedAt: at})
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): заведение генератора")
	require.True(t, accepted, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): заведение генератора легло")
	activated, err := w.ActivateTOTP(h.ctx, p.id, at, step, at)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): подтверждение генератора")
	require.True(t, activated, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): генератор в состоянии «заведён»")
	require.NoError(t, w.ReplaceLookupSet(h.ctx, domain.LoginMethod{UserID: p.id, Kind: domain.LoginMethodLookupSecret,
		Verifier: set, State: domain.LoginMethodStateActive, CreatedAt: at}), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев набора резервных кодов")
	require.NoError(t, w.Commit(h.ctx))
	require.Equal(t, a458Rows{factor: 2}, h.credentialRows(t, p), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев прочитан обратно")
	return secret, step
}

// a458Tokens — посеянные личные токены: ключ утверждения клиента и базовый секрет.
type a458Tokens struct {
	keypairID domain.UserOAuthClientID
	secretID  string
	secret    string
}

// seedUserTokens — личный токен с ключом утверждения клиента (писатель
// реестра) и личный токен с базовым секретом (глагол выдачи).
func (h *sessionLane) seedUserTokens(t *testing.T, p a458Person) a458Tokens {
	t.Helper()
	var c a458Tokens
	{
		m, err := signingkeygen.Generate(domain.SigningAlgES256)
		require.NoError(t, err)
		tx, err := h.pool.Begin(h.ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(h.ctx) }()
		row, err := kanamepg.NewUserOAuthClientRepo(h.pool).Insert(h.ctx, tx, domain.UserOAuthClient{
			ID: domain.UserOAuthClientID(ids.NewID(domain.PrefixUserOAuthClient)), UserID: p.id, CreatedByUserID: p.id,
			CreatedAt: time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond), PublicKeyPEM: m.PublicKeyPEM,
			KeyAlgorithm: string(domain.SigningAlgES256), CredentialKind: domain.CredentialKindKeypair,
		})
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): личный токен с ключом утверждения")
		require.NoError(t, tx.Commit(h.ctx))
		c.keypairID = row.ID
	}
	{
		uc := user_tokens.NewIssueUserTokenUseCase(kanamepg.NewUserOAuthClientRepo(h.pool), kanamepg.NewPoolTxBeginner(h.pool),
			shared.NewTerminalRefusalRepo(operations.NewRepo(h.pool, "kaname"))).WithIssuanceClock(momentclock.Func(time.Now))
		ctx := operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: string(p.id)})
		op, err := uc.Execute(ctx, user_tokens.IssueInput{UserID: p.id, CreatedByUserID: string(p.id),
			CredentialKind: domain.CredentialKindSecret, TTLSeconds: int64((24 * time.Hour).Seconds())})
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): выдача личного токена с базовым секретом")
		require.NotNil(t, op)
		require.Nil(t, op.Error, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): выдача личного токена с базовым секретом состоялась")
		var resp iamv1.IssueUserTokenResponse
		require.NoError(t, op.Response.UnmarshalTo(&resp))
		c.secretID, c.secret = resp.GetToken().GetId(), resp.GetSecret()
		require.NotEmpty(t, c.secret, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): базовый секрет выдан")
	}
	require.Equal(t, a458Rows{tokens: 2}, h.credentialRows(t, p), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев прочитан обратно")
	return c
}

// tokenIDs — идентификаторы личных токенов человека по порядку.
func (h *sessionLane) tokenIDs(t *testing.T, p a458Person) []string {
	t.Helper()
	rows, err := h.pool.Query(h.ctx, `SELECT id FROM user_oauth_clients WHERE user_id = $1 ORDER BY id`, string(p.id))
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

// a458TokenVerdict — исход полос личных токенов: правило выдачи токен-эндпоинта
// (`revocationpolicy.AtIssuance` с якорем выдачи ключа, как его ставит объявление
// состава) и полоса базового секрета (`ResolveBasic`: `accepted` либо причина отказа).
type a458TokenVerdict struct {
	assertion revocationpolicy.Verdict
	basic     string
}

func (h *sessionLane) tokenVerdict(t *testing.T, p a458Person, c a458Tokens) a458TokenVerdict {
	t.Helper()
	row, err := kanamepg.NewUserOAuthClientRepo(h.pool).Get(h.ctx, c.keypairID)
	require.NoError(t, err, "строка личного токена с ключом утверждения читается")
	issued := row.CreatedAt
	verdict, _, err := revocationpolicy.AtIssuance(h.ctx, kanamepg.NewSessionRevocationsAdapter(h.pool),
		service.ResolvedPrincipal{Kind: service.PrincipalUser, UserID: string(p.id), StandingCredentialIssuedAt: &issued}, time.Time{})
	require.NoError(t, err, "правило выдачи ответило")
	basic, err := kanamepg.NewBasicCredentialRepo(h.pool, 5*time.Second)
	require.NoError(t, err)
	out := a458TokenVerdict{assertion: verdict, basic: "accepted"}
	if _, err := basic.ResolveBasic(h.ctx, c.secret); err != nil {
		reason, ok := domain.BasicCredentialRefusalReasonOf(err)
		require.True(t, ok, "полоса базового секрета ответила отказом полосы, а не сбоем: %v", err)
		out.basic = string(reason)
	}
	return out
}

// keyLogin — вход ключом доступа k; ответ как есть.
func (h *sessionLane) keyLogin(t *testing.T, k akKey) reply {
	t.Helper()
	f := givenAKForm(t, h)
	return akLoginWith(t, h, f, k, givenChallenge(t, h, f), webauthntest.AssertionOptions{})
}

// completedSession — сессия, выданная завершением: носитель и контекст формы.
func completedSession(t *testing.T, r reply) laneSession {
	t.Helper()
	s := laneSession{bearer: cookieNamed(r.cookies, loginlanehttp.CookieSession), form: cookieNamed(r.cookies, loginlanehttp.CookieForm)}
	require.NotNil(t, s.bearer, "завершение пишет носитель")
	require.NotNil(t, s.form, "завершение сменяет контекст формы")
	return s
}

// assuranceLevelOf — `session.assuranceLevel` тела ответа.
func assuranceLevelOf(t *testing.T, body string) string {
	t.Helper()
	var out struct {
		Session struct {
			AssuranceLevel string `json:"assuranceLevel"`
		} `json:"session"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &out), body)
	return out.Session.AssuranceLevel
}

// secondFactorEnrolled — `GET /iam/v1/auth/second-factor` под сессией s:
// заведён ли генератор и начато ли заведение (`pendingUntil`).
func (h *sessionLane) secondFactorEnrolled(t *testing.T, s laneSession) (enrolled, pending bool) {
	t.Helper()
	r := h.lane.do(t, h.c, http.MethodGet, loginlanehttp.PathSecondFactor, nil, fwd(), s.bearer, s.form)
	require.Equal(t, http.StatusOK, r.status, "чтение состояния второго фактора — 200: %s", r.body)
	var out struct {
		TOTP struct {
			Enrolled     bool   `json:"enrolled"`
			PendingUntil string `json:"pendingUntil"`
		} `json:"totp"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &out), r.body)
	return out.TOTP.Enrolled, out.TOTP.PendingUntil != ""
}

// a458StepAhead — часы церемонии повышения впереди часов процесса на две
// ступени генератора: код повышения берётся на ступени строго позже ступени,
// принятой заведением при посеве (часы глаголов управляемые, A458-11).
const a458StepAhead = 2 * totpverify.Period

func a458CeremonyNow() time.Time { return time.Now().Add(a458StepAhead) }

// stepUpWithSeededFactor — повышение под сессией s кодом генератора посева на
// ступени часов церемонии; уровень после повышения.
func (h *sessionLane) stepUpWithSeededFactor(t *testing.T, id string, s laneSession, secret totpverify.Secret, accepted int64) string {
	t.Helper()
	step := totpverify.StepAt(a458CeremonyNow())
	require.Greater(t, step, accepted, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): ступень повышения позже ступени заведения")
	r := h.stepUpCode(t, s, "totp", laneTOTP(t, secret, step), h.csrfFor(t, domain.FormStepUp, s.form))
	require.Equal(t, http.StatusOK, r.status, "%s: повышение генератором посева проходит: %s", id, r.body)
	return assuranceLevelOf(t, r.body)
}

// ─────────────────────────────────────────────────────────────────────────────
// A458-03: переход записи без удостоверений снимает начатые заведения.
// ─────────────────────────────────────────────────────────────────────────────

// TestA458_03_TheClaimRemovesStartedEnrolments — A458-03.
func TestA458_03_TheClaimRemovesStartedEnrolments(t *testing.T) {
	cells := newA458Cells()
	h := newSessionLaneWith(t, sessionLaneOptions{completionObserver: cells})
	holder := h.holder(t)
	h.seedStartedEnrolments(t, holder)
	sOld := h.sessionOf(t, holder)
	claimedBefore := cells.done(a458CellClaimed)

	done := h.claim(t, "A458-03", holder)
	require.Equal(t, http.StatusOK, done.status, "A458-03: завершение — 200: %s", done.body)

	require.Equal(t, a458ReasonClaimed, h.endedReason(t, sOld.Value), "A458-03: исход — переход: S-old закрыта причиной address-claimed")
	events := h.recoveryAudit(t, holder)
	require.Len(t, events, 1, "A458-03: одно событие")
	require.Equal(t, true, events[0][a458EventField], "A458-03: address_claimed: true: %v", events[0])
	require.Equal(t, claimedBefore+1, cells.done(a458CellClaimed), "A458-03: клетка address-claimed прибавила 1")
	require.Equal(t, a458Rows{}, h.credentialRows(t, holder),
		"A458-03: ноль строк второго фактора и ноль неиспользованных испытаний регистрации ключа")
	enrolled, pending := h.secondFactorEnrolled(t, completedSession(t, done))
	require.False(t, enrolled, "A458-03: второй фактор под новой сессией — «не заведён»")
	require.False(t, pending, "A458-03: начатого заведения под новой сессией нет")
	require.Equal(t, "1", assuranceLevelOf(t, done.body), "A458-03: session.assuranceLevel — \"1\"")
}

// TestA458_03_Twin_EnrolledFactorIsTheOutcomeOfA458_11 — близнец A458-03
// (заведение второго фактора завершено): исход A458-11 — ничего не снято,
// причина password-change, address_claimed: false.
func TestA458_03_Twin_EnrolledFactorIsTheOutcomeOfA458_11(t *testing.T) {
	h := newSessionLane(t)
	holder := h.holder(t)
	h.seedEnrolledFactor(t, holder)
	sOld := h.sessionOf(t, holder)

	done := h.claim(t, "A458-03 близнец (фактор заведён)", holder)
	require.Equal(t, http.StatusOK, done.status, "A458-03 близнец: 200: %s", done.body)
	require.Equal(t, a458Rows{factor: 2}, h.credentialRows(t, holder), "A458-03 близнец: заведённый второй фактор на месте")
	require.Equal(t, string(domain.RevokeReasonPasswordChange), h.endedReason(t, sOld.Value), "A458-03 близнец: S-old — password-change")
	events := h.recoveryAudit(t, holder)
	require.Len(t, events, 1)
	require.Equal(t, false, events[0][a458EventField], "A458-03 близнец: address_claimed: false: %v", events[0])
}

// TestA458_03_Twin_VerifiedRecordKeepsItsStartedEnrolments — близнец A458-03
// (адрес подтверждён до выдачи кода): начатое на месте, причина password-change.
func TestA458_03_Twin_VerifiedRecordKeepsItsStartedEnrolments(t *testing.T) {
	h := newSessionLane(t)
	holder := h.holder(t)
	h.markVerified(t, holder)
	h.seedStartedEnrolments(t, holder)
	sOld := h.sessionOf(t, holder)

	done := h.claim(t, "A458-03 близнец (подтверждён)", holder)
	require.Equal(t, http.StatusOK, done.status, "A458-03 близнец: 200: %s", done.body)
	require.Equal(t, a458Rows{started: 1, challenges: 1}, h.credentialRows(t, holder),
		"A458-03 близнец: начатые строка второго фактора и испытание на месте")
	require.Equal(t, string(domain.RevokeReasonPasswordChange), h.endedReason(t, sOld.Value), "A458-03 близнец: S-old — password-change")
}

// ─────────────────────────────────────────────────────────────────────────────
// A458-11…A458-13: удостоверения, заведённые на записи, переходом не снимаются.
// ─────────────────────────────────────────────────────────────────────────────

// a458KeptOutcome — общее «Тогда» восстановления записи с удостоверениями:
// ответ, отметка, уровень, вход прежним паролем, причина S-old и отсечки,
// событие и клетки. cell — клетка, которая обязана прибавить 1.
func (h *sessionLane) a458KeptOutcome(t *testing.T, id string, cells *a458Cells, holder a458Person, sOld *http.Cookie, done reply, before map[string]int, cell string) {
	t.Helper()
	require.Equal(t, http.StatusOK, done.status, "%s: завершение — 200: %s", id, done.body)
	_, verified := claimedSession(t, done.body)
	require.True(t, verified, "%s: session.emailVerified = true", id)
	require.True(t, h.verifiedNow(t, holder), "%s: у записи стоит отметка подтверждения", id)
	require.Equal(t, "1", assuranceLevelOf(t, done.body), "%s: session.assuranceLevel — \"1\"", id)
	old := h.loginAs(t, holder.email, integrationPassword)
	require.Equal(t, http.StatusUnauthorized, old.status, "%s: вход прежним паролем — 401: %s", id, old.body)
	require.Equal(t, a458AuthFailedBody, old.body, "%s: 16 authentication failed", id)
	require.Equal(t, string(domain.RevokeReasonPasswordChange), h.endedReason(t, sOld.Value), "%s: S-old закрыта причиной password-change", id)
	require.Equal(t, string(domain.RevokeReasonPasswordChange), h.cutoffReason(t, holder.id), "%s: отсечка — причиной password-change", id)
	events := h.recoveryAudit(t, holder)
	require.Len(t, events, 1, "%s: одно событие iam.user.recovery_completed", id)
	require.Equal(t, false, events[0][a458EventField], "%s: событие несёт address_claimed: false: %v", id, events[0])
	for k, v := range events[0] {
		require.NotContains(t, toString(v), holder.email, "%s: адреса в событии нет (поле %s)", id, k)
	}
	for _, c := range []string{a458CellClaimed, a458CellVerified, string(humansession.RecoveryCompletionIssued)} {
		want := before[c]
		if c == cell {
			want++
		}
		require.Equal(t, want, cells.done(c), "%s: клетка %s", id, c)
	}
}

func a458CellsNow(cells *a458Cells) map[string]int {
	out := map[string]int{}
	for _, c := range []string{a458CellClaimed, a458CellVerified, string(humansession.RecoveryCompletionIssued)} {
		out[c] = cells.done(c)
	}
	return out
}

// a458FactorRun — один прогон A458-11 на своём стенде: verified — адрес
// подтверждён до выдачи кода (близнец). Уровень после повышения — наружу.
func a458FactorRun(t *testing.T, id string, verified bool) string {
	cells := newA458Cells()
	h := newSessionLaneWith(t, sessionLaneOptions{completionObserver: cells, ceremonyNow: a458CeremonyNow})
	holder := h.holder(t)
	if verified {
		h.markVerified(t, holder)
	}
	secret, accepted := h.seedEnrolledFactor(t, holder)
	sOld := h.sessionOf(t, holder)
	before := a458CellsNow(cells)

	done := h.claim(t, id, holder)

	cell := a458CellVerified
	if verified {
		cell = string(humansession.RecoveryCompletionIssued)
	}
	h.a458KeptOutcome(t, id, cells, holder, sOld, done, before, cell)
	require.Equal(t, a458Rows{factor: 2}, h.credentialRows(t, holder), "%s: строки второго фактора те же (генератор и набор резервных кодов)", id)
	s := completedSession(t, done)
	enrolled, _ := h.secondFactorEnrolled(t, s)
	require.True(t, enrolled, "%s: второй фактор под новой сессией — «заведён»", id)
	return h.stepUpWithSeededFactor(t, id, s, secret, accepted)
}

// TestA458_11_RecordWithASecondFactorKeepsIt — A458-11 и близнец «адрес
// подтверждён до выдачи кода»: тот же исход, то же повышение, клетка `issued`.
// Близнец «второго фактора нет» — A458-02.
func TestA458_11_RecordWithASecondFactorKeepsIt(t *testing.T) {
	level := a458FactorRun(t, "A458-11", false)
	twin := a458FactorRun(t, "A458-11 близнец (подтверждён)", true)
	require.Equal(t, twin, level, "A458-11: уровень после повышения равен уровню на восстановлении подтверждённой записи")
}

// TestA458_12_RecordWithAnAccessKeyKeepsIt — A458-12. Близнец «ключа нет» — A458-02.
func TestA458_12_RecordWithAnAccessKeyKeepsIt(t *testing.T) {
	cells := newA458Cells()
	h := newSessionLaneWith(t, sessionLaneOptions{completionObserver: cells})
	holder := h.holder(t)
	key := givenAcceptedKey(t, h, holder.id)
	require.Equal(t, a458Rows{keys: 1}, h.credentialRows(t, holder), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев прочитан обратно")
	require.Equal(t, http.StatusOK, h.keyLogin(t, key).status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): вход ключом до исхода — посев годен")
	sOld := h.sessionOf(t, holder)
	before := a458CellsNow(cells)

	done := h.claim(t, "A458-12", holder)

	h.a458KeptOutcome(t, "A458-12", cells, holder, sOld, done, before, a458CellVerified)
	require.Equal(t, a458Rows{keys: 1}, h.credentialRows(t, holder), "A458-12: строка ключа доступа на месте")
	_, same, err := kanamepg.NewAccessKeyRepo(h.pool).KeyOwnedByID(h.ctx, holder.id, key.id)
	require.NoError(t, err)
	require.True(t, same, "A458-12: строка ключа доступа та же")
	r := h.keyLogin(t, key)
	require.Equal(t, http.StatusOK, r.status, "A458-12: вход ключом после исхода — 200: %s", r.body)
	require.NotNil(t, cookieNamed(r.cookies, loginlanehttp.CookieSession), "A458-12: сессия выдана")
}

// a458TokenRun — один прогон A458-13 на своём стенде: verified — адрес
// подтверждён до выдачи кода (восстановление подтверждённой записи, Ф5).
func a458TokenRun(t *testing.T, id string, verified bool) a458TokenVerdict {
	cells := newA458Cells()
	h := newSessionLaneWith(t, sessionLaneOptions{completionObserver: cells})
	holder := h.holder(t)
	if verified {
		h.markVerified(t, holder)
	}
	tokens := h.seedUserTokens(t, holder)
	ids := h.tokenIDs(t, holder)
	sOld := h.sessionOf(t, holder)
	before := a458CellsNow(cells)

	done := h.claim(t, id, holder)

	cell := a458CellVerified
	if verified {
		cell = string(humansession.RecoveryCompletionIssued)
	}
	h.a458KeptOutcome(t, id, cells, holder, sOld, done, before, cell)
	require.Equal(t, ids, h.tokenIDs(t, holder), "%s: у записи те же две строки личных токенов", id)
	_, err := kanamepg.NewAssertionClientRepo(h.pool).ResolveAssertionClient(h.ctx, string(tokens.keypairID))
	require.NoError(t, err, "%s: токен-эндпоинт находит ключ утверждения первого токена", id)
	return h.tokenVerdict(t, holder, tokens)
}

// TestA458_13_RecordWithPersonalTokensKeepsThem — A458-13. Строки личных
// токенов те же; полосы личных токенов (правило выдачи токен-эндпоинта и полоса
// базового секрета) отвечают тем же исходом, что после восстановления
// подтверждённой записи с тем же посевом (Р3 п. 2: исход тот же, что у Ф5).
// Близнец «личных токенов нет» — A458-02.
func TestA458_13_RecordWithPersonalTokensKeepsThem(t *testing.T) {
	got := a458TokenRun(t, "A458-13", false)
	twin := a458TokenRun(t, "A458-13 близнец (подтверждён)", true)
	t.Logf("A458-13: полосы личных токенов после исхода — %+v; после восстановления подтверждённой записи — %+v", got, twin)
	require.Equal(t, twin, got, "A458-13: полосы личных токенов отвечают так же, как после восстановления подтверждённой записи")
}

// ─────────────────────────────────────────────────────────────────────────────
// A458-07: без ящика пути нет.
// ─────────────────────────────────────────────────────────────────────────────

// TestA458_07_WithoutTheMailboxThereIsNoWay — A458-07.
func TestA458_07_WithoutTheMailboxThereIsNoWay(t *testing.T) {
	h := newSessionLane(t)
	holder := h.holder(t)
	sOld := h.sessionOf(t, holder)
	code, ctxCk := h.claimCode(t, "A458-07", holder)

	r := h.completeAs(t, holder.email, wrongCodeLike(code), a458NewPassword, ctxCk)

	require.Equal(t, http.StatusUnauthorized, r.status, "A458-07: 401: %s", r.body)
	require.Equal(t, refusalWire(16, stepRecoveryRefused), r.body, "A458-07: единый отказ завершения побайтово")
	require.Nil(t, cookieNamed(r.cookies, loginlanehttp.CookieSession), "A458-07: носителя нет")
	require.Equal(t, http.StatusOK, h.loginAs(t, holder.email, integrationPassword).status, "A458-07: пароль записи — P-old")
	require.True(t, h.resolve(t, sOld.Value).GetFound(), "A458-07: S-old жива")
	require.False(t, h.verifiedNow(t, holder), "A458-07: отметки нет")
	require.Equal(t, 1, h.liveCodes(t, holder), "A458-07: код из письма годен")
}

// ─────────────────────────────────────────────────────────────────────────────
// A458-09 и DoD п. 3: вход прежнего держателя в полёте переход не переживает.
// ─────────────────────────────────────────────────────────────────────────────

// a458Barrier — барьер пробы: n вызовов шва, взведённых `arm`, отмечаются в
// `arrived` и ждут `release`; прочие вызовы проходят насквозь.
type a458Barrier struct {
	armed   atomic.Int32
	arrived chan struct{}
	release chan struct{}
}

func newA458Barrier() *a458Barrier {
	return &a458Barrier{arrived: make(chan struct{}, 64), release: make(chan struct{})}
}

func (b *a458Barrier) arm(n int) { b.armed.Store(int32(n)) }

// pass — точка шва: взведённый вызов ждёт снятия барьера.
func (b *a458Barrier) pass() {
	for {
		n := b.armed.Load()
		if n <= 0 {
			return
		}
		if b.armed.CompareAndSwap(n, n-1) {
			b.arrived <- struct{}{}
			<-b.release
			return
		}
	}
}

// waitArrived — все n взведённых вызовов дошли до барьера; предел — 30 с.
func (b *a458Barrier) waitArrived(t *testing.T, n int) {
	t.Helper()
	deadline := time.After(30 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case <-b.arrived:
		case <-deadline:
			t.Fatalf("НЕ-ВЫПОЛНИЛОСЬ(фикстура): до барьера дошло %d входов из %d", i, n)
		}
	}
}

// a458VerifyBarrier — обёртка над портом проверяющего пароля: отвечает
// настоящим исходом и ждёт барьер — шов МЕЖДУ проверкой пароля и чтением
// момента выдачи.
type a458VerifyBarrier struct {
	humansession.Verifier
	b *a458Barrier
}

func (v a458VerifyBarrier) Verify(stored domain.LoginVerifier, presented string) passwordverify.Result {
	res := v.Verifier.Verify(stored, presented)
	v.b.pass()
	return res
}

// a458MomentBarrier — обёртка над источником моментов выдачи: отдаёт момент и
// ждёт барьер — шов ПОСЛЕ чтения момента (положительный контроль отсечки).
type a458MomentBarrier struct {
	inner revocationpolicy.Clock
	b     *a458Barrier
}

func (m a458MomentBarrier) Now(ctx context.Context) (time.Time, error) {
	at, err := m.inner.Now(ctx)
	m.b.pass()
	return at, err
}

// a458Clock — часы входа: идут с часами процесса, пока их не сдвинули;
// сдвинутые стоят на названном моменте.
type a458Clock struct {
	mu     sync.Mutex
	pinned *time.Time
}

func (c *a458Clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pinned != nil {
		return *c.pinned
	}
	return time.Now()
}

func (c *a458Clock) pin(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pinned = &at
}

// a458InFlight — стенд A458-09: барьер на выбранном шве, управляемые часы входа.
type a458InFlight struct {
	h     *sessionLane
	b     *a458Barrier
	clock *a458Clock
}

// newA458InFlight — barrierAfterMoment=false: барьер на шве «проверка пароля →
// чтение момента» (постановка «Дано»); true — после чтения момента
// (положительный контроль отсечки).
func newA458InFlight(t *testing.T, barrierAfterMoment bool) *a458InFlight {
	t.Helper()
	w := &a458InFlight{b: newA458Barrier(), clock: &a458Clock{}}
	opts := sessionLaneOptions{loginNow: w.clock.now}
	if barrierAfterMoment {
		opts.loginMoments = func(c revocationpolicy.Clock) revocationpolicy.Clock { return a458MomentBarrier{inner: c, b: w.b} }
	} else {
		opts.loginVerifier = func(v humansession.Verifier) humansession.Verifier { return a458VerifyBarrier{Verifier: v, b: w.b} }
	}
	w.h = newSessionLaneWith(t, opts)
	return w
}

// loginsInFlight — n входов прежнего держателя с P-old, остановленных барьером.
func (w *a458InFlight) loginsInFlight(t *testing.T, p a458Person, n int) <-chan reply {
	t.Helper()
	w.b.arm(n)
	out := make(chan reply, n)
	for i := 0; i < n; i++ {
		tok, ctxCk := w.h.lane.csrf(t, w.h.c, string(domain.FormLogin), nil)
		go func() {
			out <- w.h.lane.do(t, w.h.c, http.MethodPost, loginlanehttp.PathLogin,
				map[string]any{"email": p.email, "password": integrationPassword, "csrfToken": tok},
				map[string]string{loginlanehttp.HeaderForwardedFor: a458Source}, ctxCk)
		}()
	}
	w.b.waitArrived(t, n)
	return out
}

// shiftPastCutoff — источник моментов выдачи сдвинут строго позже отсечки
// записи (≥ 1 мкс): отсечка вход не накрывает.
func (w *a458InFlight) shiftPastCutoff(t *testing.T, p a458Person) time.Time {
	t.Helper()
	var cutoff time.Time
	require.NoError(t, w.h.pool.QueryRow(w.h.ctx,
		`SELECT revoke_before FROM user_token_revocations WHERE user_id = $1`, string(p.id)).Scan(&cutoff),
		"A458-09: отсечка записи прочитана после перехода")
	w.clock.pin(cutoff.Add(time.Millisecond))
	return cutoff
}

// collect — ответы n отпущенных входов; предел — 30 с.
func collectReplies(t *testing.T, ch <-chan reply, n int) []reply {
	t.Helper()
	out := make([]reply, 0, n)
	deadline := time.After(30 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case r := <-ch:
			out = append(out, r)
		case <-deadline:
			t.Fatalf("НЕ-ВЫПОЛНИЛОСЬ: отпущенный вход не ответил (%d из %d)", i, n)
		}
	}
	return out
}

// TestA458_09_LoginInFlightDoesNotSurviveTheClaim — A458-09, постановка «Дано»:
// барьер между проверкой пароля и чтением момента, часы сдвинуты за отсечку.
func TestA458_09_LoginInFlightDoesNotSurviveTheClaim(t *testing.T) {
	w := newA458InFlight(t, false)
	holder := w.h.holder(t)
	w.h.sessionOf(t, holder)
	code, ctxCk := w.h.claimCode(t, "A458-09", holder)
	inFlight := w.loginsInFlight(t, holder, 1)

	done := w.h.completeAs(t, holder.email, code, a458NewPassword, ctxCk)
	require.Equal(t, http.StatusOK, done.status, "A458-09: переход зафиксирован: %s", done.body)
	w.shiftPastCutoff(t, holder)
	close(w.b.release)

	r := collectReplies(t, inFlight, 1)[0]
	require.Equal(t, http.StatusUnauthorized, r.status, "A458-09: вход прежнего держателя — 401: %s", r.body)
	require.Equal(t, a458AuthFailedBody, r.body, "A458-09: 16 authentication failed")
	require.Nil(t, cookieNamed(r.cookies, loginlanehttp.CookieSession), "A458-09: Set-Cookie нет")
	require.Equal(t, 1, w.h.liveSessionsOf(t, holder), "A458-09: живая — только сессия, выданная завершением восстановления")
}

// TestA458_09_Twin_WithoutTheClaimTheLoginIsIssued — близнец A458-09 (перехода
// не было): тот же вход после снятия барьера — 200, сессия выдана.
func TestA458_09_Twin_WithoutTheClaimTheLoginIsIssued(t *testing.T) {
	w := newA458InFlight(t, false)
	holder := w.h.holder(t)
	inFlight := w.loginsInFlight(t, holder, 1)
	close(w.b.release)
	r := collectReplies(t, inFlight, 1)[0]
	require.Equal(t, http.StatusOK, r.status, "A458-09 близнец: 200: %s", r.body)
	require.NotNil(t, cookieNamed(r.cookies, loginlanehttp.CookieSession), "A458-09 близнец: сессия выдана")
}

// TestA458_09_PositiveControl_BarrierAfterTheMomentIsRefusedByTheCutoff —
// положительный контроль отсечки: барьер ПОСЛЕ чтения момента; этот исход даёт
// отсечка выданного (Р3 п. 3), а не Р5.
func TestA458_09_PositiveControl_BarrierAfterTheMomentIsRefusedByTheCutoff(t *testing.T) {
	w := newA458InFlight(t, true)
	holder := w.h.holder(t)
	code, ctxCk := w.h.claimCode(t, "A458-09 контроль", holder)
	inFlight := w.loginsInFlight(t, holder, 1)

	done := w.h.completeAs(t, holder.email, code, a458NewPassword, ctxCk)
	require.Equal(t, http.StatusOK, done.status, "A458-09 контроль: переход зафиксирован: %s", done.body)
	w.shiftPastCutoff(t, holder)
	close(w.b.release)

	r := collectReplies(t, inFlight, 1)[0]
	require.Equal(t, http.StatusUnauthorized, r.status, "A458-09 контроль: 401: %s", r.body)
	require.Equal(t, 1, w.h.liveSessionsOf(t, holder), "A458-09 контроль: сессии на P-old нет")
}

// a458Parallel — число параллельных входов конкурентной пробы (DoD п. 3);
// меньше окна адреса стенда (5), чтобы отказы входов не упёрлись в частоту.
const a458Parallel = 4

// TestA458_09_Concurrent_NoSessionOnTheOldPasswordSurvivesTheClaim — DoD п. 3:
// N параллельных входов с P-old в той же постановке, что «Дано» A458-09, и одно
// завершение перехода — после фиксации у записи нет живой сессии на P-old.
// Прогон трижды: `-run A458_09_Concurrent -count=3`.
func TestA458_09_Concurrent_NoSessionOnTheOldPasswordSurvivesTheClaim(t *testing.T) {
	w := newA458InFlight(t, false)
	holder := w.h.holder(t)
	code, ctxCk := w.h.claimCode(t, "DoD п. 3", holder)
	inFlight := w.loginsInFlight(t, holder, a458Parallel)

	done := w.h.completeAs(t, holder.email, code, a458NewPassword, ctxCk)
	require.Equal(t, http.StatusOK, done.status, "DoD п. 3: переход зафиксирован: %s", done.body)
	w.shiftPastCutoff(t, holder)
	close(w.b.release)

	issued := 0
	for _, r := range collectReplies(t, inFlight, a458Parallel) {
		if r.status == http.StatusOK {
			issued++
		}
	}
	require.Zero(t, issued, "DoD п. 3: ни один из %d входов с P-old не получил сессию после перехода", a458Parallel)
	require.Equal(t, 1, w.h.liveSessionsOf(t, holder), "DoD п. 3: живая — только сессия завершения восстановления")
}

// ─────────────────────────────────────────────────────────────────────────────
// Помощники стенда `avLane` (дверь решения, приглашения, регистрация на проводе).
// ─────────────────────────────────────────────────────────────────────────────

// recoveryCode — владелец ящика запрашивает код и читает его из строки очереди.
func (h *avLane) recoveryCode(t *testing.T, id string, user domain.UserID, email string) (string, *http.Cookie) {
	t.Helper()
	count := func() []string {
		rows, err := h.pool.Query(h.ctx, `SELECT coalesce(payload->>'code', '') FROM kaname.invite_mail_outbox
			 WHERE resource_id = $1 AND event_type = 'mail.recovery.send' ORDER BY id`, string(user))
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): чтение очереди писем")
		defer rows.Close()
		var out []string
		for rows.Next() {
			var c string
			require.NoError(t, rows.Scan(&c))
			out = append(out, c)
		}
		return out
	}
	before := len(count())
	tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormRecovery), nil)
	r := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRecovery, map[string]any{"email": email, "csrfToken": tok}, fwd(), ctxCk)
	require.Equal(t, http.StatusOK, r.status, "%s: запрос кода: %s", id, r.body)
	codes := count()
	if len(codes) <= before {
		t.Fatalf("%s ПРЕДМЕТ A458-01 (П1): код на неподтверждённый адрес записи с паролем не выдан — "+
			"в очереди нет новой строки mail.recovery.send для %s (было %d, стало %d)", id, user, before, len(codes))
	}
	return codes[len(codes)-1], ctxCk
}

// complete — предъявление кода через слушатель.
func (h *avLane) complete(t *testing.T, email, code string, ctxCk *http.Cookie) reply {
	t.Helper()
	tok, _ := h.lane.csrf(t, h.c, string(domain.FormRecoveryComplete), ctxCk)
	return h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRecoveryComplete, map[string]any{
		"email": email, "code": code, "newPassword": a458NewPassword, "csrfToken": tok,
	}, fwd(), ctxCk)
}

// grantProject — распорядитель выдаёт записи привязку с ролью на проект, как
// пишет её `invite` (строка выдачи, состав субъектов, факт журнала).
func (h *avLane) grantProject(t *testing.T, user domain.UserID, prj domain.ProjectID) domain.AccessBindingID {
	t.Helper()
	w, err := h.users.Writer(h.ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(h.ctx) }()
	ab, err := w.AccessBindingsW().Insert(h.ctx, domain.AccessBinding{
		ID: domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)), SubjectType: domain.SubjectTypeUser,
		SubjectID: domain.SubjectID(user), RoleID: domain.RoleID(domain.ClusterAdminRoleID),
		ResourceType: domain.ResourceType("project"), ResourceID: string(prj), Target: domain.AccessTarget{AllInScope: true},
	})
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): выдача роли на проект")
	require.NoError(t, w.AccessBindingsW().InsertSubjects(h.ctx, ab.ID, []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(user)}}))
	require.NoError(t, w.EmitFGARelationWrite(h.ctx, []outboxtypes.RelationTuple{{
		User: "project:" + string(prj), Relation: "project", Object: "iam_access_binding:" + string(ab.ID),
	}, {
		User: "user:" + string(user), Relation: "admin", Object: "project:" + string(prj),
	}}))
	require.NoError(t, w.Commit(h.ctx))
	return ab.ID
}

// allowed — вопрос двери решения о записи на проекте.
func (h *avLane) allowed(t *testing.T, user domain.UserID, prj domain.ProjectID) bool {
	t.Helper()
	ok, err := h.door.Check(h.ctx, "user:"+string(user), "admin", "project:"+string(prj))
	require.NoError(t, err)
	return ok
}

// ─────────────────────────────────────────────────────────────────────────────
// A458-04: права записи переходят вместе с ней и начинают действовать.
// ─────────────────────────────────────────────────────────────────────────────

// TestA458_04_TheRightsOfTheRecordPassWithItAndStartToWork — A458-04 и его
// близнец (завершения не было — дверь отказывает неподтверждённому).
func TestA458_04_TheRightsOfTheRecordPassWithItAndStartToWork(t *testing.T) {
	h := newAVLane(t)
	_, _, prj := h.inviter(t)
	holder := h.register(t, freshAddress("a458-04"))
	binding := h.grantProject(t, holder.user, prj)
	before := h.liveBindingsOf(t, holder.user)
	require.Contains(t, before, string(binding), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): выдача на проект прочитана обратно")

	// Близнец: под S-old право не действует (`#456` Р3).
	require.False(t, h.allowed(t, holder.user, prj), "A458-04 близнец: до перехода дверь отказывает неподтверждённой записи")

	code, ctxCk := h.recoveryCode(t, "A458-04", holder.user, holder.email)
	done := h.complete(t, holder.email, code, ctxCk)
	require.Equal(t, http.StatusOK, done.status, "A458-04: завершение — 200: %s", done.body)

	require.True(t, h.allowed(t, holder.user, prj), "A458-04: после перехода право на проект действует")
	require.Equal(t, before, h.liveBindingsOf(t, holder.user),
		"A458-04: привязки записи те же (в том числе выдача на проект), повторной выдачи не было")
}

// liveBindingsOf — живые выдачи, где запись — субъект, по идентификатору. У
// записи, заведённой регистрацией, кроме выдачи пробы есть выдачи её личного
// аккаунта: судится равенство множества до и после перехода.
func (h *avLane) liveBindingsOf(t *testing.T, user domain.UserID) []string {
	t.Helper()
	rows, err := h.pool.Query(h.ctx, `SELECT id FROM kaname.access_bindings WHERE subject_id = $1 AND revoked_at IS NULL ORDER BY id`, string(user))
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

// extendInvite — повторное приглашение того же адреса в тот же аккаунт, когда
// выдача роли под приглашением жива (ветвь «истекло»): срок строки продлён
// тем же оператором, что пишет `invite` (A198 Р5), выдача не дублируется.
func (h *avLane) extendInvite(t *testing.T, iv avInvite, ttl time.Duration) avInvite {
	t.Helper()
	w, err := h.users.Writer(h.ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(h.ctx) }()
	row, _, err := w.UsersW().InsertPending(h.ctx, domain.User{
		ID: domain.UserID(ids.NewID(domain.PrefixUser)), AccountID: iv.account, Email: domain.Email(iv.email),
		DisplayName: "invitee", InviteStatus: domain.InviteStatusPending, InvitedBy: iv.inviter.user,
	}, time.Now().UTC().Add(ttl))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): повторное приглашение")
	require.NoError(t, w.Commit(h.ctx))
	iv.user = row.ID
	return iv
}

// ─────────────────────────────────────────────────────────────────────────────
// A458-05 и A458-06: строка `PENDING`, на которую зарегистрировался прежний держатель.
// ─────────────────────────────────────────────────────────────────────────────

// TestA458_05_InvitationRegisteredByThePreviousHolderPassesAndActivates — A458-05.
func TestA458_05_InvitationRegisteredByThePreviousHolderPassesAndActivates(t *testing.T) {
	h := newAVLane(t)
	inv, acc, prj := h.inviter(t)
	iv := h.invite(t, inv, acc, prj, freshAddress("a458-05"), 24*time.Hour)
	sOld := h.registerInvitee(t, iv)

	code, ctxCk := h.recoveryCode(t, "A458-05", iv.user, iv.email)
	done := h.complete(t, iv.email, code, ctxCk)

	require.Equal(t, http.StatusOK, done.status, "A458-05: 200: %s", done.body)
	v, _ := sessionEmailVerified(t, done.body)
	require.True(t, v, "A458-05: emailVerified: true")
	st, mem, ext := h.inviteState(t, iv)
	require.Equal(t, "ACTIVE", st, "A458-05: запись — та же строка приглашения, inviteStatus = ACTIVE")
	require.Equal(t, "ACTIVE", mem, "A458-05: членство ACTIVE")
	require.NotEmpty(t, ext, "A458-05: у записи есть личность (тот же исход, что активация подтверждением)")
	require.Equal(t, a458ReasonClaimed, h.endReason(t, sOld.bearer), "A458-05: S-old закрыта причиной address-claimed")
	require.Equal(t, http.StatusUnauthorized, h.loginReply(t, iv.email, integrationPassword).status, "A458-05: вход с P-old — 401")
}

// TestA458_05_Twin_InvitationWithoutRegistrationGetsNoCode — близнец A458-05:
// на приглашение не регистрировались — письма нет; регистрация ложится на строку.
func TestA458_05_Twin_InvitationWithoutRegistrationGetsNoCode(t *testing.T) {
	h := newAVLane(t)
	inv, acc, prj := h.inviter(t)
	iv := h.invite(t, inv, acc, prj, freshAddress("a458-05t"), 24*time.Hour)
	tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormRecovery), nil)
	r := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRecovery, map[string]any{"email": iv.email, "csrfToken": tok}, fwd(), ctxCk)
	require.Equal(t, http.StatusOK, r.status, "A458-05 близнец: %s", r.body)
	var n int
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM kaname.invite_mail_outbox
		 WHERE resource_id = $1 AND event_type = 'mail.recovery.send'`, string(iv.user)).Scan(&n))
	require.Zero(t, n, "A458-05 близнец: письма восстановления нет")
	h.registerInvitee(t, iv)
}

// TestA458_06_InvalidInvitationRefusesTheOutcomeAndChangesNothing — A458-06,
// ветви (а) снято и (б) истекло, и продолжение — повторное приглашение.
func TestA458_06_InvalidInvitationRefusesTheOutcomeAndChangesNothing(t *testing.T) {
	for _, branch := range []string{"(а) снято", "(б) истекло"} {
		t.Run(branch, func(t *testing.T) {
			cells := newA458Cells()
			h := newAVLaneWith(t, avOptions{completionObserver: cells})
			inv, acc, prj := h.inviter(t)
			iv := h.invite(t, inv, acc, prj, freshAddress("a458-06"), 24*time.Hour)
			sOld := h.registerInvitee(t, iv)
			code, ctxCk := h.recoveryCode(t, "A458-06 "+branch, iv.user, iv.email)
			if branch == "(а) снято" {
				h.removeInvite(t, iv)
			} else {
				_, err := h.pool.Exec(h.ctx, `UPDATE kaname.users SET invite_expires_at = now() - interval '1 second' WHERE id = $1`, string(iv.user))
				require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): срок приглашения в прошлом")
			}
			notValidBefore := cells.done(a458CellInviteNot)

			r := h.complete(t, iv.email, code, ctxCk)

			require.Equal(t, http.StatusBadRequest, r.status, "A458-06 %s: 400: %s", branch, r.body)
			ref := parseRefusal(t, r.body)
			require.Equal(t, 9, ref.Code, "A458-06 %s: code 9", branch)
			require.Equal(t, a458InviteNotValidTx, ref.Message, "A458-06 %s: текст побайтово", branch)
			require.Equal(t, "INVITE_NOT_VALID", ref.reason(), "A458-06 %s: ErrorInfo.reason", branch)
			require.Nil(t, cookieNamed(r.cookies, loginlanehttp.CookieSession), "A458-06 %s: Set-Cookie нет", branch)
			var live int
			require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM kaname.recovery_codes WHERE user_id = $1 AND consumed_at IS NULL`,
				string(iv.user)).Scan(&live))
			require.Equal(t, 1, live, "A458-06 %s: код остаётся годным", branch)
			require.Equal(t, "", h.endReason(t, sOld.bearer), "A458-06 %s: S-old жива", branch)
			_, marked := h.markedAt(t, iv.user)
			require.False(t, marked, "A458-06 %s: отметки нет", branch)
			st, _, _ := h.inviteState(t, iv)
			require.Equal(t, "PENDING", st, "A458-06 %s: строка PENDING", branch)
			require.Equal(t, notValidBefore+1, cells.done(a458CellInviteNot), "A458-06 %s: клетка invite-not-valid +1", branch)
			require.Equal(t, http.StatusOK, h.loginReply(t, iv.email, integrationPassword).status, "A458-06 %s: пароль записи — P-old", branch)

			// Продолжение: повторное приглашение — тот же код переводит запись.
			// (а): выдача под приглашением снята исключением — повторное
			// приглашение пишет её заново; (б): выдача жива — продлевается срок.
			var again avInvite
			if branch == "(а) снято" {
				again = h.invite(t, inv, acc, prj, iv.email, 24*time.Hour)
			} else {
				again = h.extendInvite(t, iv, 24*time.Hour)
			}
			require.Equal(t, iv.user, again.user, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): повторное приглашение — та же строка")
			r2 := h.complete(t, iv.email, code, ctxCk)
			require.Equal(t, http.StatusOK, r2.status, "A458-06 %s продолжение: исход A458-05: %s", branch, r2.body)
			st, _, _ = h.inviteState(t, iv)
			require.Equal(t, "ACTIVE", st, "A458-06 %s продолжение: ACTIVE", branch)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// A458-08: регистрация не отличает подтверждённую занятость от неподтверждённой.
// ─────────────────────────────────────────────────────────────────────────────

// TestA458_08_RegistrationDoesNotTellVerifiedFromUnverifiedOccupancy — A458-08
// с положительным контролем (адрес свободен — регистрация проходит).
func TestA458_08_RegistrationDoesNotTellVerifiedFromUnverifiedOccupancy(t *testing.T) {
	h := newAVLane(t)
	unverified := h.register(t, freshAddress("a458-08u"))
	verified := h.register(t, freshAddress("a458-08v"))
	h.mark(t, verified)
	letters := func() int {
		var n int
		require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM kaname.invite_mail_outbox`).Scan(&n))
		return n
	}
	lettersBefore := letters()
	register := func(email string) reply {
		tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormRegister), nil)
		return h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRegister,
			map[string]any{"email": email, "password": "another-password-of-a-stranger-458", "csrfToken": tok}, fwd(), ctxCk)
	}

	ru, rv := register(unverified.email), register(verified.email)

	require.Equal(t, http.StatusBadRequest, ru.status, "A458-08: неподтверждённая занятость — 400: %s", ru.body)
	require.Equal(t, rv.status, ru.status, "A458-08: статусы равны")
	require.Equal(t, rv.body, ru.body, "A458-08: тела побайтово равны")
	ref := parseRefusal(t, ru.body)
	require.Equal(t, 9, ref.Code)
	require.Equal(t, "REGISTRATION_REFUSED", ref.reason())
	require.Nil(t, cookieNamed(ru.cookies, loginlanehttp.CookieSession), "A458-08: Set-Cookie нет")
	require.Equal(t, "", h.endReason(t, unverified.bearer), "A458-08: S-old жива")
	require.Equal(t, lettersBefore, letters(), "A458-08: писем не поставлено")

	free := register(freshAddress("a458-08f"))
	require.Equal(t, http.StatusOK, free.status, "A458-08 положительный контроль: адрес свободен — 200: %s", free.body)
}
