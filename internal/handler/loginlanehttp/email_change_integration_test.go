// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// email_change_integration_test.go — пробы уровня I приёмки
// `docs/engineering/acceptance/email-change-is-confirmed-from-the-new-address.md`
// (задача PRO-Robotech/kaname#635), сценарии EC-01…EC-23, на ПРОВОДЕ полосы
// формы: стенд `avLane` (настоящие глаголы, настоящие адаптеры базы, часы
// глаголов управляемые, только вперёд).
//
// Ступени — те же, что у проб подтверждения адреса: МИР (посев глаголами
// продукта; отказ — «НЕ-ВЫПОЛНИЛОСЬ(фикстура)»), ВОЗМОЖНОСТЬ (оба пути смены
// смонтированы; 404 — «ЧЕСТНЫЙ-КРАСНЫЙ: глагола нет»), ПРЕДМЕТ (утверждения
// сценария с его номером).
//
// Каждый сценарий строится на СВОЁМ посеве (§4.0 приёмки): свой человек, свои
// сессии; шаг, двигающий часы, стоит последним либо получает свой посев.
package loginlanehttp_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// Пути, виды формы, виды письма, событие и причина конца — ДОСЛОВНО из приёмки
// (Р1, Р7, Р8): проба называет их литералами, потому что её предмет и есть то,
// что слушатель и хранилище их объявили.
const (
	ecPathRequest   = "/iam/v1/auth/email-change"
	ecPathConfirm   = "/iam/v1/auth/email-change/confirm"
	ecFormRequest   = "email-change"
	ecFormConfirm   = "email-change-confirm"
	ecMailCode      = "mail.email-change.send"
	ecMailNotice    = "mail.email-changed.send"
	ecAudit         = "iam.user.email_changed"
	ecEndReason     = "email-changed"
	ecSubjectOp     = "user_email_change"
	ecRetryInterval = "60" // Retry-After интервала профиля Р6 в секундах
)

// ecSeed — посев П (§4.0): регистрация глаголом, отметка писателем продукта,
// вход глаголом. Сессия свежая: момент последнего предъявления — момент входа.
func (h *avLane) ecSeed(t *testing.T, tag string) avSession {
	t.Helper()
	s := h.register(t, freshAddress(tag))
	h.mark(t, s)
	return h.login(t, s)
}

// requireEmailChangeVerbs — ступень ВОЗМОЖНОСТИ: оба пути смены смонтированы.
func (h *avLane) requireEmailChangeVerbs(t *testing.T, id string) {
	t.Helper()
	probe := avSession{bearer: ghostBearer(t), form: &http.Cookie{Name: loginlanehttp.CookieForm, Value: "probe-context"}}
	for _, p := range []string{ecPathRequest, ecPathConfirm} {
		r := h.post(t, probe, p, map[string]any{})
		if r.status == http.StatusNotFound {
			t.Fatalf("%s ЧЕСТНЫЙ-КРАСНЫЙ: глагола смены адреса нет — %s отвечает 404: %s", id, p, r.body)
		}
	}
}

// requestChange — запрос смены (Р1): новый адрес и признак вида `email-change`.
func (h *avLane) requestChange(t *testing.T, s avSession, newEmail string) reply {
	t.Helper()
	return h.post(t, s, ecPathRequest, map[string]any{"newEmail": newEmail, "csrfToken": h.token(s, ecFormRequest)})
}

// confirmChange — предъявление кода смены (Р1).
func (h *avLane) confirmChange(t *testing.T, s avSession, code string) reply {
	t.Helper()
	return h.post(t, s, ecPathConfirm, map[string]any{"code": code, "csrfToken": h.token(s, ecFormConfirm)})
}

// mailOf — строки очереди писем вида kind о человеке, по порядку постановки
// (чтение рядом с `letters`, та же форма).
func (h *avLane) mailOf(t *testing.T, kind string, user domain.UserID) []avLetter {
	t.Helper()
	rows, err := h.pool.Query(h.ctx, `
		SELECT id, coalesce(payload->>'code', ''), coalesce((payload->>'code_valid_minutes')::int, 0), coalesce(payload->>'to', '')
		  FROM kaname.invite_mail_outbox
		 WHERE event_type = $1 AND payload->>'user_id' = $2
		 ORDER BY id`, kind, string(user))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): чтение очереди писем")
	defer rows.Close()
	var out []avLetter
	for rows.Next() {
		var l avLetter
		require.NoError(t, rows.Scan(&l.id, &l.code, &l.minutes, &l.to))
		out = append(out, l)
	}
	require.NoError(t, rows.Err())
	return out
}

// mailPayloads — нагрузки строк очереди вида kind о человеке целиком, текстом.
func (h *avLane) mailPayloads(t *testing.T, kind string, user domain.UserID) []string {
	t.Helper()
	rows, err := h.pool.Query(h.ctx, `
		SELECT payload::text FROM kaname.invite_mail_outbox
		 WHERE event_type = $1 AND payload->>'user_id' = $2 ORDER BY id`, kind, string(user))
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		require.NoError(t, rows.Scan(&p))
		out = append(out, p)
	}
	require.NoError(t, rows.Err())
	return out
}

// changeCode — код последнего письма смены человека; письма нет — красное
// сценария id.
func (h *avLane) changeCode(t *testing.T, id string, user domain.UserID) string {
	t.Helper()
	ls := h.mailOf(t, ecMailCode, user)
	if len(ls) == 0 {
		t.Fatalf("%s ЧЕСТНЫЙ-КРАСНЫЙ: в очереди нет ни одной строки вида %s для %s", id, ecMailCode, user)
	}
	return ls[len(ls)-1].code
}

// ecSubjectChange — строка очереди смены субъекта.
type ecSubjectChange struct {
	op, eventType string
	payload       map[string]any
	raw           string
}

// subjectChanges — строки `kaname.subject_change_outbox` с subject_id = user
// (§4.0 «Чтение исходов»), по порядку записи.
func (h *avLane) subjectChanges(t *testing.T, user domain.UserID) []ecSubjectChange {
	t.Helper()
	rows, err := h.pool.Query(h.ctx, `
		SELECT op, coalesce(event_type, ''), payload::text FROM kaname.subject_change_outbox
		 WHERE subject_id = $1 ORDER BY id`, string(user))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): чтение очереди смены субъекта")
	defer rows.Close()
	var out []ecSubjectChange
	for rows.Next() {
		var c ecSubjectChange
		require.NoError(t, rows.Scan(&c.op, &c.eventType, &c.raw))
		require.NoError(t, json.Unmarshal([]byte(c.raw), &c.payload))
		out = append(out, c)
	}
	require.NoError(t, rows.Err())
	return out
}

// identityOf — адрес, внешний идентификатор и отметка строки человека.
func (h *avLane) identityOf(t *testing.T, user domain.UserID) (email, externalID string) {
	t.Helper()
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT email, external_id FROM kaname.users WHERE id = $1`, string(user)).
		Scan(&email, &externalID), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): строка человека")
	return email, externalID
}

// withBearer — та же сессия с носителем из ответа (перевыпуск Р8 п. 3).
func withBearer(t *testing.T, s avSession, r reply) avSession {
	t.Helper()
	ck := cookieNamed(r.cookies, loginlanehttp.CookieSession)
	require.NotNil(t, ck, "ответ не несёт нового носителя")
	out := s
	out.bearer = ck
	return out
}

// mixedCase — адрес с заглавными буквами в локальной части и домене.
func mixedCase(email string) string {
	at := strings.LastIndex(email, "@")
	return strings.ToUpper(email[:3]) + email[3:at] + "@" + strings.ToUpper(email[at+1:at+2]) + email[at+2:]
}

// requireRefusal — статус, код и признак причины отказа; text непуст — и текст.
func requireRefusal(t *testing.T, r reply, status, code int, reason, text, id string) {
	t.Helper()
	require.Equal(t, status, r.status, "%s: статус: %s", id, r.body)
	ref := parseRefusal(t, r.body)
	require.Equal(t, code, ref.Code, "%s: code: %s", id, r.body)
	require.Equal(t, reason, ref.reason(), "%s: reason: %s", id, r.body)
	if text != "" {
		require.Equal(t, text, ref.Message, "%s: текст отказа", id)
	}
}

// TestEC01_RequestQueuesACodeToTheNewAddressAndChangesNothingElse — EC-01.
func TestEC01_RequestQueuesACodeToTheNewAddressAndChangesNothingElse(t *testing.T) {
	h := newAVLane(t)
	s := h.ecSeed(t, "ec01")
	h.requireEmailChangeVerbs(t, "EC-01")
	n := freshAddress("ec01n")

	r := h.requestChange(t, s, mixedCase(n))
	require.Equal(t, http.StatusOK, r.status, "EC-01: запрос смены: %s", r.body)
	require.JSONEq(t, `{}`, r.body, "EC-01: тело {}")
	require.Equal(t, ecRetryInterval, r.header.Get("Retry-After"), "EC-01: Retry-After = интервал Р6")
	require.Nil(t, cookieNamed(r.cookies, loginlanehttp.CookieSession), "EC-01: запрос носителя не выдаёт")

	letters := h.mailOf(t, ecMailCode, s.user)
	require.Len(t, letters, 1, "EC-01: одна строка %s", ecMailCode)
	require.Equal(t, n, letters[0].to, "EC-01: адресат — новый адрес в приведённом виде")
	require.Len(t, strings.ReplaceAll(letters[0].code, "-", ""), 10, "EC-01: 10-значный код (форма письма делит его дефисом)")
	require.Equal(t, int(avCodeTTLProfile/time.Minute), letters[0].minutes, "EC-01: срок в минутах")
	for _, p := range h.mailPayloads(t, ecMailCode, s.user) {
		var payload map[string]any
		require.NoError(t, json.Unmarshal([]byte(p), &payload))
		for k, v := range payload {
			if k == "code" {
				continue
			}
			require.NotContains(t, toString(v), letters[0].code, "EC-01: кода нет вне поля кода (%s)", k)
		}
	}
	require.Empty(t, h.mailOf(t, ecMailNotice, s.user), "EC-01: строк %s ноль", ecMailNotice)

	email, _ := h.identityOf(t, s.user)
	require.Equal(t, s.email, email, "EC-01: адрес прежний")
	_, marked := h.markedAt(t, s.user)
	require.True(t, marked, "EC-01: отметка на месте")
	require.Equal(t, http.StatusOK, h.loginReply(t, s.email, integrationPassword).status, "EC-01: вход прежним адресом")
}

// TestEC02_PresentingTheCodeChangesTheAddressInOneOutcome — EC-02.
func TestEC02_PresentingTheCodeChangesTheAddressInOneOutcome(t *testing.T) {
	h := newAVLane(t)
	s := h.ecSeed(t, "ec02")
	s2 := h.login(t, s)
	h.requireEmailChangeVerbs(t, "EC-02")
	n := freshAddress("ec02n")
	_, extBefore := h.identityOf(t, s.user)
	require.Equal(t, http.StatusOK, h.requestChange(t, s, n).status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): EC-01 в посеве")
	code := h.changeCode(t, "EC-02", s.user)
	at := h.clock.Now()

	r := h.confirmChange(t, s, code)
	require.Equal(t, http.StatusOK, r.status, "EC-02: предъявление: %s", r.body)
	verified, ok := sessionEmailVerified(t, r.body)
	require.True(t, ok && verified, "EC-02: тело {\"session\": {…}} с emailVerified: %s", r.body)
	fresh := withBearer(t, s, r)
	require.NotEqual(t, s.bearer.Value, fresh.bearer.Value, "EC-02: новый носитель")
	require.Equal(t, http.StatusUnauthorized, h.requestChange(t, s, freshAddress("ec02x")).status,
		"EC-02: прежний носитель S отвечает 401 на глаголе под сессией")

	email, ext := h.identityOf(t, s.user)
	require.Equal(t, n, email, "EC-02: адрес — новый в приведённом виде")
	require.Equal(t, extBefore, ext, "EC-02: external_id не изменился")
	markedAt, marked := h.markedAt(t, s.user)
	require.True(t, marked, "EC-02: отметка стоит")
	require.True(t, markedAt.Equal(at), "EC-02: отметка — момент предъявления (%s против %s)", markedAt, at)
	require.Equal(t, ecEndReason, h.endReason(t, s2.bearer), "EC-02: S′ снята причиной email-changed")
	require.Equal(t, "", h.endReason(t, fresh.bearer), "EC-02: текущая сессия жива")

	notices := h.mailPayloads(t, ecMailNotice, s.user)
	require.Len(t, notices, 1, "EC-02: одна строка %s", ecMailNotice)
	require.Equal(t, s.email, h.mailOf(t, ecMailNotice, s.user)[0].to, "EC-02: уведомление — на прежний адрес")
	require.NotContains(t, strings.ToLower(notices[0]), n, "EC-02: нагрузка уведомления не несёт нового адреса")

	events := h.auditEvents(t, ecAudit, s.user)
	require.Len(t, events, 1, "EC-02: одно событие %s", ecAudit)
	keys := make([]string, 0, len(events[0]))
	for k := range events[0] {
		keys = append(keys, k)
	}
	sortStrings(keys)
	require.Equal(t, []string{"session_id", "user_id"}, keys, "EC-02: нагрузка ровно {user_id, session_id}")

	changes := h.subjectChanges(t, s.user)
	require.Len(t, changes, 1, "EC-02: одна строка очереди смены субъекта")
	require.Equal(t, ecSubjectOp, changes[0].op, "EC-02: op")
	require.Equal(t, ecSubjectOp, changes[0].eventType, "EC-02: event_type")
	require.Equal(t, "user", changes[0].payload["subject_type"], "EC-02: subject_type = user")
	require.NotContains(t, strings.ToLower(changes[0].raw), strings.ToLower(s.email), "EC-02: прежнего адреса в нагрузке нет")
	require.NotContains(t, strings.ToLower(changes[0].raw), n, "EC-02: нового адреса в нагрузке нет")
}

// TestEC03_AfterTheChangeTheNewAddressSignsInAndTheOldDoesNot — EC-03.
func TestEC03_AfterTheChangeTheNewAddressSignsInAndTheOldDoesNot(t *testing.T) {
	h := newAVLane(t)
	s := h.ecSeed(t, "ec03")
	h.requireEmailChangeVerbs(t, "EC-03")
	n := freshAddress("ec03n")
	require.Equal(t, http.StatusOK, h.requestChange(t, s, n).status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): EC-01")
	require.Equal(t, http.StatusOK, h.confirmChange(t, s, h.changeCode(t, "EC-03", s.user)).status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): EC-02")

	a := h.loginReply(t, n, integrationPassword)
	b := h.loginReply(t, s.email, integrationPassword)
	require.Equal(t, http.StatusOK, a.status, "EC-03 (а): вход новым адресом: %s", a.body)
	require.NotNil(t, cookieNamed(a.cookies, loginlanehttp.CookieSession), "EC-03 (а): сессия выдана")
	requireRefusal(t, b, http.StatusUnauthorized, 16, "", "authentication failed", "EC-03 (б)")
}

// TestEC04_StaleSessionIsRefusedAndStepUpOpensTheSameRequest — EC-04.
func TestEC04_StaleSessionIsRefusedAndStepUpOpensTheSameRequest(t *testing.T) {
	h := newAVLane(t)
	s := h.ecSeed(t, "ec04")
	h.requireEmailChangeVerbs(t, "EC-04")
	n := freshAddress("ec04n")
	h.clock.Advance(laneFreshness + time.Second)

	a := h.requestChange(t, s, n)
	requireRefusal(t, a, http.StatusForbidden, 7, "SESSION_NOT_FRESH", "re-authentication required: present a credential again", "EC-04 (а)")
	require.Empty(t, h.mailOf(t, ecMailCode, s.user), "EC-04 (а): писем ноль")

	up := h.post(t, s, loginlanehttp.PathStepUp, map[string]any{
		"method": "password", "password": integrationPassword, "csrfToken": h.token(s, string(domain.FormStepUp)),
	})
	require.Equal(t, http.StatusOK, up.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): повышение паролем (б): %s", up.body)
	s = withBearer(t, s, up)

	c := h.requestChange(t, s, n)
	require.Equal(t, http.StatusOK, c.status, "EC-04 (в): после повышения: %s", c.body)
	require.Len(t, h.mailOf(t, ecMailCode, s.user), 1, "EC-04 (в): письмо одно")
}

// TestEC05_InTheVerificationPositionBothPathsAreRefused — EC-05.
func TestEC05_InTheVerificationPositionBothPathsAreRefused(t *testing.T) {
	h := newAVLane(t)
	reg := h.register(t, freshAddress("ec05"))
	s := h.login(t, reg)
	h.requireEmailChangeVerbs(t, "EC-05")
	n := freshAddress("ec05n")

	a := h.requestChange(t, s, n)
	require.Equal(t, http.StatusForbidden, a.status, "EC-05 (а): %s", a.body)
	require.Equal(t, avRefusalBody, a.body, "EC-05 (а): значение отказа положения F6b Р3 побайтово")
	confirm := h.confirmChange(t, s, "0000000000")
	require.Equal(t, http.StatusForbidden, confirm.status, "EC-05: confirm без отметки: %s", confirm.body)
	require.Equal(t, avRefusalBody, confirm.body, "EC-05: confirm без отметки — тот же отказ (а)")
	require.Empty(t, h.mailOf(t, ecMailCode, s.user), "EC-05 (а): писем ноль")

	h.mark(t, s)
	b := h.requestChange(t, s, n)
	require.Equal(t, http.StatusOK, b.status, "EC-05 (б): после отметки: %s", b.body)
	require.Len(t, h.mailOf(t, ecMailCode, s.user), 1, "EC-05 (б): письмо одно")
}

// TestEC06_WithoutASessionTheRequestIsRefused — EC-06; близнец — EC-01.
func TestEC06_WithoutASessionTheRequestIsRefused(t *testing.T) {
	h := newAVLane(t)
	s := h.ecSeed(t, "ec06")
	h.requireEmailChangeVerbs(t, "EC-06")
	n := freshAddress("ec06n")
	noBearer := s
	noBearer.bearer = nil

	r := h.requestChange(t, noBearer, n)
	requireRefusal(t, r, http.StatusUnauthorized, 16, "", "authentication failed", "EC-06")
	require.Empty(t, h.mailOf(t, ecMailCode, s.user), "EC-06: писем ноль")
	require.Equal(t, http.StatusOK, h.requestChange(t, s, n).status, "EC-06 близнец (EC-01): тот же запрос с носителем")
}

// TestEC07_AddressFormRefusalsNameTheFieldAndSpendNoPace — EC-07.
func TestEC07_AddressFormRefusalsNameTheFieldAndSpendNoPace(t *testing.T) {
	h := newAVLane(t)
	s := h.ecSeed(t, "ec07")
	h.requireEmailChangeVerbs(t, "EC-07")

	a := h.post(t, s, ecPathRequest, map[string]any{"csrfToken": h.token(s, ecFormRequest)})
	requireRefusal(t, a, http.StatusBadRequest, 3, "", "Illegal argument newEmail: required", "EC-07 (а)")
	b := h.requestChange(t, s, "not-an-address")
	requireRefusal(t, b, http.StatusBadRequest, 3, "", "Illegal argument newEmail: invalid format", "EC-07 (б)")
	c := h.post(t, s, ecPathRequest, map[string]any{"newEmail": freshAddress("ec07x"), "email": "x@example.invalid", "csrfToken": h.token(s, ecFormRequest)})
	requireRefusal(t, c, http.StatusBadRequest, 3, "", "Illegal argument email: unknown field", "EC-07 (в)")
	require.Empty(t, h.mailOf(t, ecMailCode, s.user), "EC-07: после (а)–(в) писем ноль")

	d := h.requestChange(t, s, freshAddress("ec07n"))
	require.Equal(t, http.StatusOK, d.status, "EC-07 (г): без сдвига часов — темп не расходован: %s", d.body)
}

// TestEC08_TheSameAddressIsRefusedAsAField — EC-08; близнец — EC-01.
func TestEC08_TheSameAddressIsRefusedAsAField(t *testing.T) {
	h := newAVLane(t)
	s := h.ecSeed(t, "ec08")
	h.requireEmailChangeVerbs(t, "EC-08")

	r := h.requestChange(t, s, mixedCase(s.email))
	requireRefusal(t, r, http.StatusBadRequest, 3, "", "Illegal argument newEmail: must differ from the current address", "EC-08")
	require.Empty(t, h.mailOf(t, ecMailCode, s.user), "EC-08: писем ноль")
	require.Equal(t, http.StatusOK, h.requestChange(t, s, freshAddress("ec08n")).status, "EC-08 близнец: другой адрес")
}

// TestEC09_ATakenAddressIsIndistinguishableOnTheRequest — EC-09.
func TestEC09_ATakenAddressIsIndistinguishableOnTheRequest(t *testing.T) {
	taken := newAVLane(t)
	free := newAVLane(t)
	taken.requireEmailChangeVerbs(t, "EC-09")
	u := taken.ecSeed(t, "ec09u")
	n := freshAddress("ec09n")
	v := taken.register(t, n)
	vEmail, vExt := taken.identityOf(t, v.user)
	w := free.ecSeed(t, "ec09w")
	n2 := freshAddress("ec09n2")

	a := taken.requestChange(t, u, n)
	b := free.requestChange(t, w, n2)
	require.Equal(t, http.StatusOK, a.status, "EC-09: занятый: %s", a.body)
	require.Equal(t, b.status, a.status, "EC-09: статусы равны")
	require.Equal(t, b.body, a.body, "EC-09: тела равны побайтово")
	require.Equal(t, b.header.Get("Retry-After"), a.header.Get("Retry-After"), "EC-09: Retry-After равны")
	require.Empty(t, taken.mailOf(t, ecMailCode, u.user), "EC-09: на занятый адрес письма с кодом нет")
	require.Len(t, free.mailOf(t, ecMailCode, w.user), 1, "EC-09: на свободный — одно")

	ra := taken.requestChange(t, u, n)
	rb := free.requestChange(t, w, n2)
	requireRefusal(t, ra, http.StatusTooManyRequests, 8, "TOO_MANY_ATTEMPTS", "", "EC-09 повтор (занятый)")
	requireRefusal(t, rb, http.StatusTooManyRequests, 8, "TOO_MANY_ATTEMPTS", "", "EC-09 повтор (свободный)")
	require.Equal(t, rb.header.Get("Retry-After"), ra.header.Get("Retry-After"),
		"EC-09: Retry-After повторов равны — оба первых запроса расходовали темп одинаково")
	vEmailAfter, vExtAfter := taken.identityOf(t, v.user)
	require.Equal(t, vEmail, vEmailAfter, "EC-09: строка V не изменилась")
	require.Equal(t, vExt, vExtAfter, "EC-09: строка V не изменилась")
	require.Equal(t, "", taken.endReason(t, v.bearer), "EC-09: сессия V жива")
}

// TestEC10_AWrongCodeKeepsTheAddress — EC-10.
func TestEC10_AWrongCodeKeepsTheAddress(t *testing.T) {
	h := newAVLane(t)
	s := h.ecSeed(t, "ec10")
	h.requireEmailChangeVerbs(t, "EC-10")
	n := freshAddress("ec10n")
	require.Equal(t, http.StatusOK, h.requestChange(t, s, n).status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): EC-01")
	code := h.changeCode(t, "EC-10", s.user)

	a := h.confirmChange(t, s, otherCode(code))
	requireRefusal(t, a, http.StatusUnauthorized, 16, "", "authentication failed", "EC-10 (а)")
	email, _ := h.identityOf(t, s.user)
	require.Equal(t, s.email, email, "EC-10 (а): адрес прежний")
	require.Empty(t, h.mailOf(t, ecMailNotice, s.user), "EC-10 (а): писем email-changed ноль")
	require.Empty(t, h.subjectChanges(t, s.user), "EC-10 (а): строк очереди смены субъекта ноль")

	b := h.confirmChange(t, s, code)
	require.Equal(t, http.StatusOK, b.status, "EC-10 (б): %s", b.body)
	email, _ = h.identityOf(t, s.user)
	require.Equal(t, n, email, "EC-10 (б): адрес N")
	changes := h.subjectChanges(t, s.user)
	require.Len(t, changes, 1, "EC-10 (б): одна строка")
	require.Equal(t, ecSubjectOp, changes[0].op, "EC-10 (б): user_email_change")
}

// otherCode — код той же формы, отличный от code.
func otherCode(code string) string {
	if strings.HasPrefix(code, "0") {
		return "1" + code[1:]
	}
	return "0" + code[1:]
}

// TestEC11_AnExpiredCodeKeepsTheAddress — EC-11; близнец — EC-10 (б).
func TestEC11_AnExpiredCodeKeepsTheAddress(t *testing.T) {
	h := newAVLane(t)
	s := h.ecSeed(t, "ec11")
	h.requireEmailChangeVerbs(t, "EC-11")
	require.Equal(t, http.StatusOK, h.requestChange(t, s, freshAddress("ec11n")).status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): EC-01")
	code := h.changeCode(t, "EC-11", s.user)
	h.clock.Advance(avCodeTTLProfile + time.Second)

	r := h.confirmChange(t, s, code)
	requireRefusal(t, r, http.StatusUnauthorized, 16, "", "authentication failed", "EC-11")
	email, _ := h.identityOf(t, s.user)
	require.Equal(t, s.email, email, "EC-11: адрес прежний")
}

// TestEC12_TheFifthFailureSpendsTheCode — EC-12: пятая неудача тратит код,
// после четырёх верный код проходит.
func TestEC12_TheFifthFailureSpendsTheCode(t *testing.T) {
	for _, tc := range []struct {
		name  string
		wrong int
		want  int
	}{
		{"пять неверных — код истрачен", avAttemptsProfile, http.StatusUnauthorized},
		{"близнец: четыре неверных — верный проходит", avAttemptsProfile - 1, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newAVLane(t)
			s := h.ecSeed(t, "ec12")
			h.requireEmailChangeVerbs(t, "EC-12")
			n := freshAddress("ec12n")
			require.Equal(t, http.StatusOK, h.requestChange(t, s, n).status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): EC-01")
			code := h.changeCode(t, "EC-12", s.user)
			for i := 0; i < tc.wrong; i++ {
				require.Equal(t, http.StatusUnauthorized, h.confirmChange(t, s, otherCode(code)).status, "EC-12: неверное %d", i+1)
			}
			r := h.confirmChange(t, s, code)
			require.Equal(t, tc.want, r.status, "EC-12: верный код после %d неверных: %s", tc.wrong, r.body)
			email, _ := h.identityOf(t, s.user)
			if tc.want == http.StatusOK {
				require.Equal(t, n, email, "EC-12: адрес N")
			} else {
				require.Equal(t, s.email, email, "EC-12: адрес прежний")
			}
		})
	}
}

// TestEC13_ANewRequestSupersedesTheEarlierCodeAndAddress — EC-13: второй
// запрос вытесняет первый код одинаково, свободен второй адрес или занят.
func TestEC13_ANewRequestSupersedesTheEarlierCodeAndAddress(t *testing.T) {
	for _, tc := range []struct {
		name  string
		taken bool
	}{
		{"второй адрес свободен", false},
		{"второй адрес занят", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newAVLane(t)
			s := h.ecSeed(t, "ec13")
			h.requireEmailChangeVerbs(t, "EC-13")
			n, n2 := freshAddress("ec13n"), freshAddress("ec13n2")
			if tc.taken {
				h.register(t, n2)
			}
			require.Equal(t, http.StatusOK, h.requestChange(t, s, n).status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): запрос на N")
			c1 := h.changeCode(t, "EC-13", s.user)
			h.clock.Advance(avIntervalProfile)
			second := h.requestChange(t, s, n2)
			require.Equal(t, http.StatusOK, second.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): запрос на N₂: %s", second.body)

			a := h.confirmChange(t, s, c1)
			require.Equal(t, http.StatusUnauthorized, a.status, "EC-13 (а): C₁ вытеснен (%s): %s", tc.name, a.body)
			email, _ := h.identityOf(t, s.user)
			require.Equal(t, s.email, email, "EC-13 (а): адрес прежний")
			if tc.taken {
				require.Len(t, h.mailOf(t, ecMailCode, s.user), 1, "EC-13: на занятый N₂ кода нет")
				return
			}
			c2 := h.changeCode(t, "EC-13", s.user)
			require.NotEqual(t, c1, c2)
			b := h.confirmChange(t, s, c2)
			require.Equal(t, http.StatusOK, b.status, "EC-13 (б): %s", b.body)
			email, _ = h.identityOf(t, s.user)
			require.Equal(t, n2, email, "EC-13 (б): адрес N₂, а не N")
		})
	}
}

// TestEC14_TheCodeIsSingleUseUnderConcurrency — EC-14: из двух одновременных
// предъявлений проходит одно; 16 повторов с новыми посевами.
func TestEC14_TheCodeIsSingleUseUnderConcurrency(t *testing.T) {
	h := newAVLane(t)
	h.requireEmailChangeVerbs(t, "EC-14")
	const repeats = 16
	dist := map[string]int{}
	for i := 0; i < repeats; i++ {
		s := h.ecSeed(t, "ec14")
		require.Equal(t, http.StatusOK, h.requestChange(t, s, freshAddress("ec14n")).status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): EC-01")
		code := h.changeCode(t, "EC-14", s.user)
		statuses := make([]int, 2)
		var wg sync.WaitGroup
		for j := 0; j < 2; j++ {
			wg.Add(1)
			go func(j int) {
				defer wg.Done()
				statuses[j] = h.confirmChange(t, s, code).status
			}(j)
		}
		wg.Wait()
		ok, refused := 0, 0
		for _, st := range statuses {
			switch st {
			case http.StatusOK:
				ok++
			case http.StatusUnauthorized:
				refused++
			default:
				t.Fatalf("EC-14 повтор %d: исход, которого у предъявления нет: %d", i, st)
			}
		}
		require.Equal(t, 1, ok, "EC-14 повтор %d: ровно один 200 (%v)", i, statuses)
		require.Equal(t, 1, refused, "EC-14 повтор %d: ровно один 401", i)
		require.Len(t, h.mailOf(t, ecMailNotice, s.user), 1, "EC-14 повтор %d: строка email-changed одна", i)
		require.Len(t, h.auditEvents(t, ecAudit, s.user), 1, "EC-14 повтор %d: событие одно", i)
		require.Len(t, h.subjectChanges(t, s.user), 1, "EC-14 повтор %d: строка очереди смены субъекта одна", i)
		dist[strconv.Itoa(ok)+"/"+strconv.Itoa(refused)]++
	}
	t.Logf("EC-14: повторов %d · распределение (200/401): %v", repeats, dist)
}

// TestEC15_AnAddressTakenBetweenRequestAndPresentationIsANamedRefusal — EC-15;
// близнец — EC-02 (тот же порядок без приглашения).
func TestEC15_AnAddressTakenBetweenRequestAndPresentationIsANamedRefusal(t *testing.T) {
	h := newAVLane(t)
	s := h.ecSeed(t, "ec15")
	other := h.login(t, s)
	h.requireEmailChangeVerbs(t, "EC-15")
	n := freshAddress("ec15n")
	require.Equal(t, http.StatusOK, h.requestChange(t, s, n).status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): EC-01")
	code := h.changeCode(t, "EC-15", s.user)
	inv, acc, prj := h.inviter(t)
	h.invite(t, inv, acc, prj, n, 7*24*time.Hour)

	r := h.confirmChange(t, s, code)
	requireRefusal(t, r, http.StatusConflict, 6, "EMAIL_IN_USE", "email address is already in use", "EC-15")
	email, _ := h.identityOf(t, s.user)
	require.Equal(t, s.email, email, "EC-15: адрес прежний")
	require.Equal(t, "", h.endReason(t, other.bearer), "EC-15: прочие сессии живы")
	require.Empty(t, h.mailOf(t, ecMailNotice, s.user), "EC-15: писем email-changed ноль")
	require.Empty(t, h.subjectChanges(t, s.user), "EC-15: строк очереди смены субъекта ноль")
	var consumed int
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM kaname.email_change_codes WHERE user_id = $1 AND consumed_at IS NOT NULL`,
		string(s.user)).Scan(&consumed))
	require.Zero(t, consumed, "EC-15: код не применён")
}

// TestEC16_TwoPeopleOneFreeAddressOnlyOneWins — EC-16: 16 повторов с новыми
// посевами.
func TestEC16_TwoPeopleOneFreeAddressOnlyOneWins(t *testing.T) {
	h := newAVLane(t)
	h.requireEmailChangeVerbs(t, "EC-16")
	const repeats = 16
	dist := map[string]int{}
	for i := 0; i < repeats; i++ {
		u, w := h.ecSeed(t, "ec16u"), h.ecSeed(t, "ec16w")
		n := freshAddress("ec16n")
		require.Equal(t, http.StatusOK, h.requestChange(t, u, n).status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): U запросил N")
		require.Equal(t, http.StatusOK, h.requestChange(t, w, n).status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): W запросил N")
		cu, cw := h.changeCode(t, "EC-16", u.user), h.changeCode(t, "EC-16", w.user)
		replies := make([]reply, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); replies[0] = h.confirmChange(t, u, cu) }()
		go func() { defer wg.Done(); replies[1] = h.confirmChange(t, w, cw) }()
		wg.Wait()
		ok, conflict := 0, 0
		for _, r := range replies {
			switch r.status {
			case http.StatusOK:
				ok++
			case http.StatusConflict:
				require.Equal(t, "EMAIL_IN_USE", parseRefusal(t, r.body).reason(), "EC-16 повтор %d", i)
				conflict++
			default:
				t.Fatalf("EC-16 повтор %d: исход %d: %s", i, r.status, r.body)
			}
		}
		require.Equal(t, 1, ok, "EC-16 повтор %d: ровно один 200", i)
		require.Equal(t, 1, conflict, "EC-16 повтор %d: ровно один 409", i)
		var rows int
		require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM kaname.users WHERE lower(email) = $1`, n).Scan(&rows))
		require.Equal(t, 1, rows, "EC-16 повтор %d: строка с адресом N одна", i)
		loser := u
		if replies[0].status == http.StatusOK {
			loser = w
		}
		email, _ := h.identityOf(t, loser.user)
		require.Equal(t, loser.email, email, "EC-16 повтор %d: адрес проигравшего прежний", i)
		dist[strconv.Itoa(ok)+"/"+strconv.Itoa(conflict)]++
	}
	t.Logf("EC-16: повторов %d · распределение (200/409): %v", repeats, dist)
}

// TestEC_DB02_ConcurrentRequestsOfOnePersonAdmitOne — два одновременных
// запроса смены ОДНОГО человека (Р5, Р6; ревью схемы волны 6, критическое 2):
// живая строка у человека одна (частичный уникальный ключ) и темп человека
// судит одним условным оператором, а держит их вместе замок строки человека,
// взятый первым оператором транзакции запроса. Без замка обе транзакции видят
// «живой строки нет, окно пусто» — и либо обе принимаются, либо вторая ловит
// отказ частичного ключа вместо отказа темпа. Исход: ровно один 200 и один 429
// TOO_MANY_ATTEMPTS, живая строка одна, письмо с кодом одно. 16 повторов с
// новыми посевами; адреса двух запросов разные, чтобы окно адресата их не
// сводило.
func TestEC_DB02_ConcurrentRequestsOfOnePersonAdmitOne(t *testing.T) {
	h := newAVLane(t)
	h.requireEmailChangeVerbs(t, "EC-DB-02")
	const repeats = 16
	dist := map[string]int{}
	for i := 0; i < repeats; i++ {
		s := h.ecSeed(t, "ecdb2")
		addrs := []string{freshAddress("ecdb2a"), freshAddress("ecdb2b")}
		replies := make([]reply, 2)
		var wg sync.WaitGroup
		for j := range replies {
			wg.Add(1)
			go func(j int) {
				defer wg.Done()
				replies[j] = h.requestChange(t, s, addrs[j])
			}(j)
		}
		wg.Wait()
		ok, paced := 0, 0
		for _, r := range replies {
			switch r.status {
			case http.StatusOK:
				ok++
			case http.StatusTooManyRequests:
				requireRefusal(t, r, http.StatusTooManyRequests, 8, "TOO_MANY_ATTEMPTS", "too many attempts; try again later",
					fmt.Sprintf("EC-DB-02 повтор %d", i))
				paced++
			default:
				t.Fatalf("EC-DB-02 повтор %d: исход, которого у запроса нет: %d: %s", i, r.status, r.body)
			}
		}
		require.Equal(t, 1, ok, "EC-DB-02 повтор %d: ровно один 200", i)
		require.Equal(t, 1, paced, "EC-DB-02 повтор %d: ровно один 429", i)
		var live, all int
		require.NoError(t, h.pool.QueryRow(h.ctx, `
			SELECT count(*) FILTER (WHERE consumed_at IS NULL AND superseded_at IS NULL), count(*)
			  FROM kaname.email_change_codes WHERE user_id = $1`, string(s.user)).Scan(&live, &all))
		require.Equal(t, 1, live, "EC-DB-02 повтор %d: живая строка одна", i)
		require.Equal(t, 1, all, "EC-DB-02 повтор %d: принятый запрос один — отказ темпа ничего не пишет", i)
		require.Len(t, h.mailOf(t, ecMailCode, s.user), 1, "EC-DB-02 повтор %d: письмо с кодом одно", i)
		dist[strconv.Itoa(ok)+"/"+strconv.Itoa(paced)]++
	}
	t.Logf("EC-DB-02: повторов %d · распределение (200/429): %v", repeats, dist)
}

// TestEC17_TheIntervalBetweenLetters — EC-17.
func TestEC17_TheIntervalBetweenLetters(t *testing.T) {
	h := newAVLane(t)
	s := h.ecSeed(t, "ec17")
	h.requireEmailChangeVerbs(t, "EC-17")
	n := freshAddress("ec17n")
	require.Equal(t, http.StatusOK, h.requestChange(t, s, n).status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): EC-01")

	a := h.requestChange(t, s, n)
	requireRefusal(t, a, http.StatusTooManyRequests, 8, "TOO_MANY_ATTEMPTS", "too many attempts; try again later", "EC-17 (а)")
	retry, err := strconv.Atoi(a.header.Get("Retry-After"))
	require.NoError(t, err, "EC-17 (а): Retry-After — секунды")
	require.LessOrEqual(t, retry, int(avIntervalProfile/time.Second), "EC-17 (а): Retry-After ≤ интервала")
	require.Len(t, h.mailOf(t, ecMailCode, s.user), 1, "EC-17 (а): новой строки кода нет")

	h.clock.Advance(avIntervalProfile)
	b := h.requestChange(t, s, n)
	require.Equal(t, http.StatusOK, b.status, "EC-17 (б): %s", b.body)
	require.Len(t, h.mailOf(t, ecMailCode, s.user), 2, "EC-17 (б): письмо второе")
}

// TestEC18_TheLimitOfLettersPerPersonPerWindow — EC-18.
func TestEC18_TheLimitOfLettersPerPersonPerWindow(t *testing.T) {
	h := newAVLane(t)
	s := h.ecSeed(t, "ec18")
	h.requireEmailChangeVerbs(t, "EC-18")
	for i := 0; i < avLimitProfile; i++ {
		if i > 0 {
			h.clock.Advance(avIntervalProfile)
		}
		require.Equal(t, http.StatusOK, h.requestChange(t, s, freshAddress("ec18n")).status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): запрос %d", i+1)
	}
	h.clock.Advance(avIntervalProfile)
	a := h.requestChange(t, s, freshAddress("ec18n"))
	requireRefusal(t, a, http.StatusTooManyRequests, 8, "TOO_MANY_ATTEMPTS", "", "EC-18 (а)")

	h.clock.Advance(avWindowProfile)
	s2 := h.login(t, s)
	b := h.requestChange(t, s2, freshAddress("ec18n"))
	require.Equal(t, http.StatusOK, b.status, "EC-18 (б): после выхода первого запроса из окна, под S₂: %s", b.body)
}

// TestEC19_TheRecipientWindowAcrossAccounts — EC-19: один адрес не засыпать
// из многих учётных записей; L = 3 на одном стенде.
func TestEC19_TheRecipientWindowAcrossAccounts(t *testing.T) {
	const limit = 3
	h := newAVLaneWith(t, avOptions{recoveryLettersPerRecipient: limit})
	h.requireEmailChangeVerbs(t, "EC-19")
	n := freshAddress("ec19n")
	for i := 0; i < limit; i++ {
		p := h.ecSeed(t, "ec19p")
		require.Equal(t, http.StatusOK, h.requestChange(t, p, n).status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): человек %d запросил N", i+1)
	}
	last := h.ecSeed(t, "ec19last")

	a := h.requestChange(t, last, n)
	requireRefusal(t, a, http.StatusTooManyRequests, 8, "TOO_MANY_ATTEMPTS", "", "EC-19 (а)")
	require.Empty(t, h.mailOf(t, ecMailCode, last.user), "EC-19 (а): строки кода нет")
	b := h.requestChange(t, last, freshAddress("ec19n3"))
	require.Equal(t, http.StatusOK, b.status, "EC-19 (б): другой адресат: %s", b.body)
	require.Len(t, h.mailOf(t, ecMailCode, last.user), 1, "EC-19 (б): письмо одно")
}

// TestEC20_TheCodeBelongsToThePerson — EC-20.
func TestEC20_TheCodeBelongsToThePerson(t *testing.T) {
	h := newAVLane(t)
	u := h.ecSeed(t, "ec20u")
	w := h.ecSeed(t, "ec20w")
	h.requireEmailChangeVerbs(t, "EC-20")
	n := freshAddress("ec20n")
	require.Equal(t, http.StatusOK, h.requestChange(t, u, n).status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): EC-01")
	code := h.changeCode(t, "EC-20", u.user)

	a := h.confirmChange(t, w, code)
	requireRefusal(t, a, http.StatusUnauthorized, 16, "", "authentication failed", "EC-20 (а)")
	ue, _ := h.identityOf(t, u.user)
	we, _ := h.identityOf(t, w.user)
	require.Equal(t, u.email, ue, "EC-20 (а): адрес U прежний")
	require.Equal(t, w.email, we, "EC-20 (а): адрес W прежний")

	b := h.confirmChange(t, u, code)
	require.Equal(t, http.StatusOK, b.status, "EC-20 (б): %s", b.body)
	ue, _ = h.identityOf(t, u.user)
	require.Equal(t, n, ue, "EC-20 (б): адрес U — N")
}

// TestEC21_TheChangeDoesNotOpenTheAdmissionWindow — EC-21: сцена A197-04,
// смена адреса настоящими глаголами EC-01 и EC-02.
func TestEC21_TheChangeDoesNotOpenTheAdmissionWindow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ceiling int64
		admit   bool
	}{
		{"потолок 1 — отказ рубежом темпа", 1, false},
		{"близнец: потолок 2 — заведение проходит, счётчик 2", 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newAVLane(t)
			h.requireEmailChangeVerbs(t, "EC-21")
			inv, acc, prj := h.inviter(t)
			iv := h.invite(t, inv, acc, prj, freshAddress("ec21"), 7*24*time.Hour)
			s := h.registerInvitee(t, iv)
			act := h.confirm(t, s, h.latestCode(t, "EC-21", iv.user))
			require.Equal(t, http.StatusOK, act.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): активация подтверждением: %s", act.body)
			s = withBearer(t, s, act)
			carrier := strings.ToLower(iv.email)
			var admitted int
			require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT admitted FROM kaname.identity_admission_windows WHERE kind = 'iam.account' AND carrier_id = $1`, carrier).Scan(&admitted),
				"НЕ-ВЫПОЛНИЛОСЬ(фикстура): окно носителя после активации")
			require.Equal(t, 1, admitted, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): личный аккаунт активации сосчитан")
			_, err := kanamepg.NewOwnCeilingRepo(h.pool).ApplyAdmissionRate(h.ctx, tc.ceiling, time.Hour)
			require.NoError(t, err)

			n := freshAddress("ec21n")
			require.Equal(t, http.StatusOK, h.requestChange(t, s, n).status, "EC-21: запрос смены глаголом")
			done := h.confirmChange(t, s, h.changeCode(t, "EC-21", iv.user))
			require.Equal(t, http.StatusOK, done.status, "EC-21: предъявление глаголом: %s", done.body)
			email, _ := h.identityOf(t, iv.user)
			require.Equal(t, n, email, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): адрес сменён глаголом")

			_, err = h.pool.Exec(h.ctx, `INSERT INTO kaname.accounts (id, name, owner_user_id, labels) VALUES ($1, $2, $3, '{}'::jsonb)`,
				ids.NewID(domain.PrefixAccount), "ec21-"+strings.ToLower(string(iv.user)[4:12]), string(iv.user))
			var got string
			require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT admission_carrier FROM kaname.users WHERE id = $1`, string(iv.user)).Scan(&got))
			require.Equal(t, carrier, got, "EC-21: носитель до и после смены одинаков — адрес на момент активации")
			require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT admitted FROM kaname.identity_admission_windows WHERE kind = 'iam.account' AND carrier_id = $1`, carrier).Scan(&admitted))
			if tc.admit {
				require.NoError(t, err, "EC-21 близнец: заведение при потолке 2")
				require.Equal(t, 2, admitted, "EC-21 близнец: счётчик окна носителя 2")
				return
			}
			require.Error(t, err, "EC-21: смена адреса открыла окно — второе заведение прошло")
			require.Contains(t, err.Error(), "KQ004", "EC-21: отказ рубежом темпа (тот же, что в A197-04)")
			require.Equal(t, 1, admitted)
		})
	}
}

// TestEC22_TheOldAddressIsFreedForRegistration — EC-22.
func TestEC22_TheOldAddressIsFreedForRegistration(t *testing.T) {
	h := newAVLane(t)
	s := h.ecSeed(t, "ec22")
	h.requireEmailChangeVerbs(t, "EC-22")
	n := freshAddress("ec22n")
	require.Equal(t, http.StatusOK, h.requestChange(t, s, n).status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): EC-01")
	require.Equal(t, http.StatusOK, h.confirmChange(t, s, h.changeCode(t, "EC-22", s.user)).status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): EC-02")

	registerWith := func(email string) reply {
		tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormRegister), nil)
		return h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRegister,
			map[string]any{"email": email, "password": integrationPassword, "csrfToken": tok}, fwd(), ctxCk)
	}
	old := registerWith(s.email)
	require.Equal(t, http.StatusOK, old.status, "EC-22: регистрация прежним адресом: %s", old.body)
	taken := registerWith(n)
	requireRefusal(t, taken, http.StatusBadRequest, 9, "REGISTRATION_REFUSED", "", "EC-22 близнец: адрес N занят — единый отказ Ф4 Р3")
}

// TestEC23_TheChangeWithdrawsALiveRecoveryCode — EC-23.
func TestEC23_TheChangeWithdrawsALiveRecoveryCode(t *testing.T) {
	for _, tc := range []struct {
		name    string
		changed bool
	}{
		{"смена выполнена — код восстановления снят", true},
		{"близнец: смены нет — восстановление проходит", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newAVLane(t)
			s := h.ecSeed(t, "ec23")
			h.requireEmailChangeVerbs(t, "EC-23")
			tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormRecovery), nil)
			rq := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRecovery,
				map[string]any{"email": s.email, "csrfToken": tok}, fwd(), ctxCk)
			require.Equal(t, http.StatusOK, rq.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): запрос восстановления")
			recovery := h.mailOf(t, "mail.recovery.send", s.user)
			require.Len(t, recovery, 1, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): письмо восстановления")
			address := s.email
			if tc.changed {
				address = freshAddress("ec23n")
				require.Equal(t, http.StatusOK, h.requestChange(t, s, address).status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): EC-01")
				require.Equal(t, http.StatusOK, h.confirmChange(t, s, h.changeCode(t, "EC-23", s.user)).status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): EC-02")
			}
			const newPassword = "recovered-after-the-change-23"
			ctok, ctxCk2 := h.lane.csrf(t, h.c, string(domain.FormRecoveryComplete), ctxCk)
			r := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRecoveryComplete, map[string]any{
				"email": address, "code": recovery[0].code, "newPassword": newPassword, "csrfToken": ctok,
			}, fwd(), ctxCk2)
			if tc.changed {
				requireRefusal(t, r, http.StatusUnauthorized, 16, "", stepRecoveryRefused, "EC-23: код, выданный на прежний адрес — отказ завершения Ф5 Р10 п. 2")
				require.Equal(t, http.StatusOK, h.loginReply(t, address, integrationPassword).status, "EC-23: пароль прежний")
				return
			}
			require.Equal(t, http.StatusOK, r.status, "EC-23 близнец: успех Ф5: %s", r.body)
		})
	}
}
