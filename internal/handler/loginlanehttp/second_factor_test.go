// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// second_factor_test.go — HTTP-контракт шести глаголов второго фактора и поля
// `secondFactor` формы входа (фаза Ф12, задача PRO-Robotech/kacho#1281; приёмка
// `docs/engineering/acceptance/second-factor-totp-and-recovery-codes.md`, Р4;
// Ф12-01, 02, 06, 11, 15, 17, 18, 25, 28, 41 в части транспорта). Варианты
// использования подставлены дублёрами: предмет проб — форма запроса, форма
// ответа, печенья, отказы с фиксированными текстами и токенами.
package loginlanehttp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

// --- дублёр глаголов второго фактора ---

func (s *stubLane) EnrollSecondFactor(_ context.Context, in humansession.EnrollInput) (humansession.EnrollOutput, error) {
	s.enrollIn = append(s.enrollIn, in)
	return s.enrollOut, s.enrollErr
}

func (s *stubLane) ConfirmSecondFactor(_ context.Context, in humansession.ConfirmInput) (humansession.ConfirmOutput, error) {
	s.confirmIn = append(s.confirmIn, in)
	return s.confirmOut, s.confirmErr
}

func (s *stubLane) SecondFactorStatus(_ context.Context, in humansession.StatusInput) (humansession.StatusOutput, error) {
	s.statusIn = append(s.statusIn, in)
	return s.statusOut, s.statusErr
}

func (s *stubLane) RemoveSecondFactor(_ context.Context, in humansession.RemoveSecondFactorInput) (humansession.RemoveSecondFactorOutput, error) {
	s.removeIn = append(s.removeIn, in)
	return s.removeOut, s.removeErr
}

func (s *stubLane) RegenerateBackupCodes(_ context.Context, in humansession.RegenerateBackupCodesInput) (humansession.RegenerateBackupCodesOutput, error) {
	s.regenIn = append(s.regenIn, in)
	return s.regenOut, s.regenErr
}

func (s *stubLane) StepUp(_ context.Context, in humansession.StepUpInput) (humansession.StepUpOutput, error) {
	s.stepUpIn = append(s.stepUpIn, in)
	return s.stepUpOut, s.stepUpErr
}

func levelTwoView() humansession.SessionView {
	v := sessionView()
	v.Session.AssuranceLevel = "2"
	v.Session.PresentedMethods = []string{"password", "totp"}
	v.Session.LastPresentedAt = base.Add(5 * time.Minute)
	return v
}

func assuranceTwo() humansession.AssuranceView {
	return humansession.AssuranceView{Level: "2", Level2Reachable: true, MissingForLevel2: []string{}}
}

func fwd() map[string]string { return map[string]string{"X-Forwarded-For": "203.0.113.7"} }

// TestLane_F12_01_EnrollShowsTheSecretOnce — `enroll`: форма из одного
// признака, ответ — секрет base32, адрес `otpauth` и срок до секунды; носитель и
// только он уходит глаголу.
func TestLane_F12_01_EnrollShowsTheSecretOnce(t *testing.T) {
	secret, err := totpverify.NewSecret()
	require.NoError(t, err)
	stub := &stubLane{enrollOut: humansession.EnrollOutput{
		Secret: secret, OtpauthURI: totpverify.OtpauthURI("kacho.example", "a@example.invalid", secret),
		ExpiresAt: base.Add(15 * time.Minute),
	}}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "second-factor", nil)
	sess := &http.Cookie{Name: "kaname_session", Value: "bearer-1"}

	r := l.do(t, c, http.MethodPost, "/iam/v1/auth/second-factor/enroll", map[string]string{"csrfToken": tok}, fwd(), ctxCk, sess)
	require.Equal(t, http.StatusOK, r.status, r.body)
	var body struct {
		Secret     string `json:"secret"`
		OtpauthURI string `json:"otpauthUri"`
		ExpiresAt  string `json:"expiresAt"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &body))
	require.Equal(t, secret.Base32(), body.Secret)
	require.Len(t, body.Secret, 32)
	require.Equal(t, "otpauth://totp/kacho.example:a@example.invalid?secret="+secret.Base32()+"&issuer=kacho.example&algorithm=SHA1&digits=6&period=30", body.OtpauthURI)
	require.Equal(t, "2026-09-16T12:15:00Z", body.ExpiresAt)
	require.Empty(t, r.cookies, "заведение печений не пишет: сессия и контекст прежние")
	require.Len(t, stub.enrollIn, 1)
	require.Equal(t, "bearer-1", stub.enrollIn[0].Bearer.CookieValue())
	var keys map[string]any
	require.NoError(t, json.Unmarshal([]byte(r.body), &keys))
	require.Len(t, keys, 3, "ровно три поля: secret, otpauthUri, expiresAt")
}

// TestLane_F12_02_ConfirmShowsTheCodesAndRotatesTheBearer — `confirm`: коды,
// сессия «2», объект `assurance`, новый носитель печеньем; код и адрес
// источника уходят глаголу.
func TestLane_F12_02_ConfirmShowsTheCodesAndRotatesTheBearer(t *testing.T) {
	fresh, _ := domain.NewSessionBearer()
	stub := &stubLane{confirmOut: humansession.ConfirmOutput{
		View: levelTwoView(), Bearer: fresh, Assurance: assuranceTwo(),
		BackupCodes: []string{"0123456789", "ABCDEFGHJK", "MNPQRSTVWX", "YZ01234567", "89ABCDEFGH", "JKMNPQRSTV", "WXYZ012345", "6789ABCDEF", "GHJKMNPQRS", "TVWXYZ0123"},
	}}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "second-factor", nil)
	sess := &http.Cookie{Name: "kaname_session", Value: "bearer-1"}

	r := l.do(t, c, http.MethodPost, "/iam/v1/auth/second-factor/confirm", map[string]string{"code": "123456", "csrfToken": tok}, fwd(), ctxCk, sess)
	require.Equal(t, http.StatusOK, r.status, r.body)
	var body struct {
		BackupCodes []string       `json:"backupCodes"`
		Session     map[string]any `json:"session"`
		Assurance   map[string]any `json:"assurance"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &body))
	require.Len(t, body.BackupCodes, 10)
	require.Equal(t, "2", body.Session["assuranceLevel"])
	require.Equal(t, map[string]any{"level": "2", "level2Reachable": true, "missingForLevel2": []any{}}, body.Assurance)
	sc := cookieNamed(r.cookies, "kaname_session")
	require.NotNil(t, sc, "Set-Cookie: kaname_session — предъявление перевыпускает носитель")
	require.Equal(t, fresh.CookieValue(), sc.Value)
	require.Nil(t, cookieNamed(r.cookies, "kaname_form"), "контекст формы не меняется: сессия та же")
	require.Equal(t, "123456", stub.confirmIn[0].Code)
	require.Equal(t, "203.0.113.7", stub.confirmIn[0].Source)
	require.Equal(t, "bearer-1", stub.confirmIn[0].Bearer.CookieValue())
	var keys map[string]any
	require.NoError(t, json.Unmarshal([]byte(r.body), &keys))
	require.NotContains(t, keys, "backupCodesRemaining", "поле остатка — только у предъявления запасного кода")
}

// TestLane_F12_StatusHasTwoShapes — `GET` состояния: без признака; `pending` —
// `enrolled: false` с `pendingUntil` и БЕЗ `backupCodes`; `active` — `enrolled:
// true`, `confirmedAt`, остаток числом (ноль — тоже число, Ф12-26).
func TestLane_F12_StatusHasTwoShapes(t *testing.T) {
	stub := &stubLane{statusOut: humansession.StatusOutput{PendingUntil: base.Add(15 * time.Minute)}}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	sess := &http.Cookie{Name: "kaname_session", Value: "bearer-1"}

	r := l.do(t, c, http.MethodGet, "/iam/v1/auth/second-factor", nil, nil, sess)
	require.Equal(t, http.StatusOK, r.status, r.body)
	require.JSONEq(t, `{"totp":{"enrolled":false,"pendingUntil":"2026-09-16T12:15:00Z"}}`, r.body)
	require.Equal(t, "bearer-1", stub.statusIn[0].Bearer.CookieValue())

	stub.statusOut = humansession.StatusOutput{}
	r = l.do(t, c, http.MethodGet, "/iam/v1/auth/second-factor", nil, nil, sess)
	require.JSONEq(t, `{"totp":{"enrolled":false}}`, r.body, "строки нет — ни срока, ни набора")

	stub.statusOut = humansession.StatusOutput{TOTPEnrolled: true, ConfirmedAt: base, BackupCodes: &humansession.BackupCodesView{Remaining: 0, Total: 10}}
	r = l.do(t, c, http.MethodGet, "/iam/v1/auth/second-factor", nil, nil, sess)
	require.JSONEq(t, `{"totp":{"enrolled":true,"confirmedAt":"2026-09-16T12:00:00Z"},"backupCodes":{"remaining":0,"total":10}}`, r.body)

	post := l.do(t, c, http.MethodPost, "/iam/v1/auth/second-factor", map[string]string{}, nil, sess)
	require.Equal(t, http.StatusMethodNotAllowed, post.status)
	require.Equal(t, http.MethodGet, post.header.Get("Allow"))

	stub.statusErr = humansession.ErrAuthenticationFailed
	r = l.do(t, c, http.MethodGet, "/iam/v1/auth/second-factor", nil, nil)
	require.Equal(t, http.StatusUnauthorized, r.status)
	require.JSONEq(t, `{"code":16,"message":"authentication failed","details":[]}`, r.body)
}

// TestLane_F12_15_18_StepUpNamesTheMethodAndTheRemainder — церемония: способ
// называет клиент; ответ — сессия и `assurance`; `backupCodesRemaining` только
// там, где потреблён запасной код; ветвь пароля несёт `password`, а не `code`.
func TestLane_F12_15_18_StepUpNamesTheMethodAndTheRemainder(t *testing.T) {
	fresh, _ := domain.NewSessionBearer()
	stub := &stubLane{stepUpOut: humansession.StepUpOutput{View: levelTwoView(), Bearer: fresh, Assurance: assuranceTwo()}}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "step-up", nil)
	sess := &http.Cookie{Name: "kaname_session", Value: "bearer-1"}

	r := l.do(t, c, http.MethodPost, "/iam/v1/auth/step-up", map[string]string{"method": "totp", "code": "123456", "csrfToken": tok}, fwd(), ctxCk, sess)
	require.Equal(t, http.StatusOK, r.status, r.body)
	var keys map[string]any
	require.NoError(t, json.Unmarshal([]byte(r.body), &keys))
	require.Len(t, keys, 2)
	require.Contains(t, keys, "session")
	require.Contains(t, keys, "assurance")
	require.Equal(t, fresh.CookieValue(), cookieNamed(r.cookies, "kaname_session").Value)
	require.Equal(t, assurance.MethodTOTP, stub.stepUpIn[0].Method)
	require.Equal(t, "123456", stub.stepUpIn[0].Code)
	require.Equal(t, "203.0.113.7", stub.stepUpIn[0].Source)

	nine := 9
	stub.stepUpOut.BackupCodesRemaining = &nine
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/step-up", map[string]string{"method": "lookup_secret", "code": "ABCDEFGH12", "csrfToken": tok}, fwd(), ctxCk, sess)
	require.Equal(t, http.StatusOK, r.status, r.body)
	keys = nil
	require.NoError(t, json.Unmarshal([]byte(r.body), &keys))
	require.Len(t, keys, 3)
	require.EqualValues(t, 9, keys["backupCodesRemaining"])
	require.Equal(t, assurance.MethodLookupSecret, stub.stepUpIn[1].Method)

	stub.stepUpOut.BackupCodesRemaining = nil
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/step-up", map[string]string{"method": "password", "password": "correct horse battery", "csrfToken": tok}, fwd(), ctxCk, sess)
	require.Equal(t, http.StatusOK, r.status, r.body)
	require.Equal(t, assurance.MethodPassword, stub.stepUpIn[2].Method)
	require.Equal(t, "correct horse battery", stub.stepUpIn[2].Password)
	require.Empty(t, stub.stepUpIn[2].Code)
}

// TestLane_F12_25_28_RemoveAndBackupCodesConfirmWithACode — снятие и
// перечеканка: `{"method","code"}` в теле; снятие отвечает сессией и
// `assurance` (с остатком, когда подтверждали запасным); перечеканка — новым
// набором.
func TestLane_F12_25_28_RemoveAndBackupCodesConfirmWithACode(t *testing.T) {
	fresh, _ := domain.NewSessionBearer()
	three := 3
	stub := &stubLane{
		removeOut: humansession.RemoveSecondFactorOutput{View: levelTwoView(), Bearer: fresh, Assurance: humansession.AssuranceView{Level: "2", MissingForLevel2: []string{}}, BackupCodesRemaining: &three},
		regenOut:  humansession.RegenerateBackupCodesOutput{View: levelTwoView(), Bearer: fresh, Assurance: assuranceTwo(), BackupCodes: []string{"0123456789"}},
	}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "second-factor", nil)
	sess := &http.Cookie{Name: "kaname_session", Value: "bearer-1"}

	r := l.do(t, c, http.MethodPost, "/iam/v1/auth/second-factor/remove", map[string]string{"method": "lookup_secret", "code": "ABCDEFGH12", "csrfToken": tok}, fwd(), ctxCk, sess)
	require.Equal(t, http.StatusOK, r.status, r.body)
	var keys map[string]any
	require.NoError(t, json.Unmarshal([]byte(r.body), &keys))
	require.Len(t, keys, 3)
	require.EqualValues(t, 3, keys["backupCodesRemaining"])
	require.Equal(t, map[string]any{"level": "2", "level2Reachable": false, "missingForLevel2": []any{}}, keys["assurance"])
	require.Equal(t, fresh.CookieValue(), cookieNamed(r.cookies, "kaname_session").Value)
	require.Equal(t, assurance.MethodLookupSecret, stub.removeIn[0].Factor.Method)
	require.Equal(t, "ABCDEFGH12", stub.removeIn[0].Factor.Code)
	require.Equal(t, "203.0.113.7", stub.removeIn[0].Source)

	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/second-factor/backup-codes", map[string]string{"method": "totp", "code": "123456", "csrfToken": tok}, fwd(), ctxCk, sess)
	require.Equal(t, http.StatusOK, r.status, r.body)
	keys = nil // разбор в непустую карту дописывает, а не заменяет
	require.NoError(t, json.Unmarshal([]byte(r.body), &keys))
	require.Len(t, keys, 3)
	require.Equal(t, []any{"0123456789"}, keys["backupCodes"])
	require.Contains(t, keys, "session")
	require.Contains(t, keys, "assurance")
	require.Equal(t, assurance.MethodTOTP, stub.regenIn[0].Factor.Method)
}

// TestLane_F12_06_FormsNameTheField — лишнее поле отвергается, отсутствующее
// называется, способ вне словаря — по имени поля; глагол не вызван.
func TestLane_F12_06_FormsNameTheField(t *testing.T) {
	stub := &stubLane{}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	sfTok, ctxCk := l.csrf(t, c, "second-factor", nil)
	suTok, ctxCk := l.csrf(t, c, "step-up", ctxCk)
	sess := &http.Cookie{Name: "kaname_session", Value: "bearer-1"}

	cases := []struct {
		name, path string
		body       map[string]any
		want       string
	}{
		{"enroll-extra", "/iam/v1/auth/second-factor/enroll", map[string]any{"csrfToken": sfTok, "extra": 1}, `"Illegal argument extra: unknown field"`},
		{"confirm-no-code", "/iam/v1/auth/second-factor/confirm", map[string]any{"csrfToken": sfTok}, `"Illegal argument code: required"`},
		{"step-up-method", "/iam/v1/auth/step-up", map[string]any{"method": "sms", "code": "123456", "csrfToken": suTok}, `"Illegal argument method: must be one of password|totp|lookup_secret"`},
		{"step-up-no-method", "/iam/v1/auth/step-up", map[string]any{"code": "123456", "csrfToken": suTok}, `"Illegal argument method: required"`},
		{"step-up-password-no-password", "/iam/v1/auth/step-up", map[string]any{"method": "password", "csrfToken": suTok}, `"Illegal argument password: required"`},
		{"remove-no-method", "/iam/v1/auth/second-factor/remove", map[string]any{"code": "123456", "csrfToken": sfTok}, `"Illegal argument method: required"`},
		{"backup-codes-bad-method", "/iam/v1/auth/second-factor/backup-codes", map[string]any{"method": "password", "code": "123456", "csrfToken": sfTok}, `"Illegal argument method: must be one of totp|lookup_secret"`},
		{"malformed", "/iam/v1/auth/second-factor/confirm", nil, `"Illegal argument body: malformed JSON"`},
	}
	for _, tc := range cases {
		var body any
		if tc.body != nil {
			body = tc.body
		} else {
			body = "{not json"
		}
		r := l.do(t, c, http.MethodPost, tc.path, body, fwd(), ctxCk, sess)
		require.Equal(t, http.StatusBadRequest, r.status, "%s: %s", tc.name, r.body)
		require.Contains(t, r.body, tc.want, tc.name)
		require.Contains(t, r.body, `"code":3`, tc.name)
	}
	require.Empty(t, stub.enrollIn)
	require.Empty(t, stub.confirmIn)
	require.Empty(t, stub.stepUpIn)
	require.Empty(t, stub.removeIn)
	require.Empty(t, stub.regenIn)
}

// TestLane_F12_41_FormKindsAreOneList — виды `second-factor` и `step-up` в
// том же перечне; чужой вид — 403 `FORM_TOKEN_REJECTED`; без признака — 400
// `csrfToken`; состояние не изменено (глагол не вызван).
func TestLane_F12_41_FormKindsAreOneList(t *testing.T) {
	require.Contains(t, domain.FormKinds(), domain.FormSecondFactor)
	require.Contains(t, domain.FormKinds(), domain.FormStepUp)
	require.Equal(t, domain.FormKind("second-factor"), domain.FormSecondFactor)
	require.Equal(t, domain.FormKind("step-up"), domain.FormStepUp)

	stub := &stubLane{}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	sfTok, ctxCk := l.csrf(t, c, "second-factor", nil)
	suTok, ctxCk := l.csrf(t, c, "step-up", ctxCk)
	pwTok, ctxCk := l.csrf(t, c, "password", ctxCk)
	require.NotEqual(t, sfTok, suTok)
	sess := &http.Cookie{Name: "kaname_session", Value: "bearer-1"}

	r := l.do(t, c, http.MethodPost, "/iam/v1/auth/second-factor/enroll", map[string]string{"csrfToken": suTok}, fwd(), ctxCk, sess)
	require.Equal(t, http.StatusForbidden, r.status, r.body)
	require.Contains(t, r.body, `"FORM_TOKEN_REJECTED"`)
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/step-up", map[string]string{"method": "totp", "code": "123456", "csrfToken": pwTok}, fwd(), ctxCk, sess)
	require.Equal(t, http.StatusForbidden, r.status, r.body)
	require.Contains(t, r.body, `"form token rejected"`)
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/second-factor/confirm", map[string]string{"code": "123456"}, fwd(), ctxCk, sess)
	require.Equal(t, http.StatusBadRequest, r.status, r.body)
	require.Contains(t, r.body, `"Illegal argument csrfToken: required"`)
	require.Empty(t, stub.enrollIn)
	require.Empty(t, stub.stepUpIn)
	require.Empty(t, stub.confirmIn)

	// Перечень путей — одно объявление, и шесть глаголов в нём.
	for _, p := range []string{
		"/iam/v1/auth/second-factor/enroll", "/iam/v1/auth/second-factor/confirm", "/iam/v1/auth/second-factor/remove",
		"/iam/v1/auth/second-factor/backup-codes", "/iam/v1/auth/second-factor", "/iam/v1/auth/step-up",
	} {
		require.Contains(t, loginlanehttp.Paths(), p)
	}
	require.Len(t, loginlanehttp.Paths(), 13)
}

// TestLane_F12_RefusalsCarryTheirTokens — отказы глаголов семейства (Р4):
// состояние — 400 `FAILED_PRECONDITION` с токеном; «уже заведён» — 409
// `ALREADY_EXISTS`; свежесть — 403 `SESSION_NOT_FRESH`; материал не открылся —
// 503 фиксированным текстом; сессии нет — 401 как на смене пароля.
func TestLane_F12_RefusalsCarryTheirTokens(t *testing.T) {
	stub := &stubLane{}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "second-factor", nil)
	sess := &http.Cookie{Name: "kaname_session", Value: "bearer-1"}
	call := func() reply {
		return l.do(t, c, http.MethodPost, "/iam/v1/auth/second-factor/confirm", map[string]string{"code": "123456", "csrfToken": tok}, fwd(), ctxCk, sess)
	}
	info := func(reason string) string {
		return `{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"` + reason + `","domain":"iam.kaname.cloud"}`
	}

	stub.confirmErr = humansession.ErrSecondFactorNotEnrolled
	r := call()
	require.Equal(t, http.StatusBadRequest, r.status)
	require.JSONEq(t, `{"code":9,"message":"second factor is not enrolled","details":[`+info("SECOND_FACTOR_NOT_ENROLLED")+`]}`, r.body)

	stub.confirmErr = humansession.ErrEnrollmentNotPending
	r = call()
	require.Equal(t, http.StatusBadRequest, r.status)
	require.JSONEq(t, `{"code":9,"message":"no pending enrollment: begin with enroll","details":[`+info("ENROLLMENT_NOT_PENDING")+`]}`, r.body)

	stub.confirmErr = humansession.ErrSecondFactorAlreadyEnrolled
	r = call()
	require.Equal(t, http.StatusConflict, r.status)
	require.JSONEq(t, `{"code":6,"message":"second factor is already enrolled","details":[`+info("SECOND_FACTOR_ALREADY_ENROLLED")+`]}`, r.body)

	stub.confirmErr = humansession.ErrSessionNotFresh
	r = call()
	require.Equal(t, http.StatusForbidden, r.status)
	require.JSONEq(t, `{"code":7,"message":"re-authentication required: present a credential again","details":[`+info("SESSION_NOT_FRESH")+`]}`, r.body)

	stub.confirmErr = humansession.ErrSecondFactorUnavailable
	r = call()
	require.Equal(t, http.StatusServiceUnavailable, r.status)
	require.JSONEq(t, `{"code":14,"message":"second factor temporarily unavailable","details":[]}`, r.body)

	stub.confirmErr = humansession.ErrAuthenticationFailed
	r = call()
	require.Equal(t, http.StatusUnauthorized, r.status)
	require.JSONEq(t, `{"code":16,"message":"authentication failed","details":[]}`, r.body)
	require.Empty(t, r.cookies, "отказ печений не пишет")
}

// TestLane_F12_11_LoginCarriesTheSecondFactorField — поле `secondFactor`
// формы входа: необязательно; способ и код уходят глаголу; `password` как
// способ поля и лишнее вложенное поле — 400 с именем поля.
func TestLane_F12_11_LoginCarriesTheSecondFactorField(t *testing.T) {
	stub := &stubLane{loginOut: humansession.LoginOutput{View: levelTwoView()}}
	stub.loginOut.Bearer, _ = domain.NewSessionBearer()
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "login", nil)

	r := l.do(t, c, http.MethodPost, "/iam/v1/auth/login", map[string]any{
		"email": "a@example.invalid", "password": "correct horse battery", "csrfToken": tok,
		"secondFactor": map[string]string{"method": "lookup_secret", "code": "ABCDEFGH12"},
	}, fwd(), ctxCk)
	require.Equal(t, http.StatusOK, r.status, r.body)
	require.NotNil(t, stub.loginIn[0].SecondFactor)
	require.Equal(t, assurance.MethodLookupSecret, stub.loginIn[0].SecondFactor.Method)
	require.Equal(t, "ABCDEFGH12", stub.loginIn[0].SecondFactor.Code)
	require.Contains(t, r.body, `"assuranceLevel":"2"`)

	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/login", map[string]any{"email": "a@example.invalid", "password": "correct horse battery", "csrfToken": tok}, fwd(), ctxCk)
	require.Equal(t, http.StatusOK, r.status, r.body)
	require.Nil(t, stub.loginIn[1].SecondFactor, "без поля — nil, а не пустое предъявление")

	for name, sf := range map[string]map[string]string{
		"password-method": {"method": "password", "code": "123456"},
		"no-method":       {"code": "123456"},
		"no-code":         {"method": "totp"},
		"extra":           {"method": "totp", "code": "123456", "extra": "x"},
	} {
		r = l.do(t, c, http.MethodPost, "/iam/v1/auth/login", map[string]any{"email": "a@example.invalid", "password": "correct horse battery", "csrfToken": tok, "secondFactor": sf}, fwd(), ctxCk)
		require.Equal(t, http.StatusBadRequest, r.status, "%s: %s", name, r.body)
		require.Contains(t, r.body, `"Illegal argument secondFactor.`, name)
	}
	require.Len(t, stub.loginIn, 2, "негодная форма до глагола не доходит")
}
