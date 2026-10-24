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

// TestLane_F12_02_ConfirmShowsTheCodesAndRotatesTheBearer — `confirm`: коды
// массивом `backupCodes`, сводка нового набора `backupCodeSet` (kaname#297
// BCS-03), сессия «2», объект `assurance`, новый носитель печеньем; код и
// адрес источника уходят глаголу.
func TestLane_F12_02_ConfirmShowsTheCodesAndRotatesTheBearer(t *testing.T) {
	fresh, _ := domain.NewSessionBearer()
	stub := &stubLane{confirmOut: humansession.ConfirmOutput{
		View: levelTwoView(), Bearer: fresh, Assurance: assuranceTwo(),
		BackupCodes:   []string{"0123456789", "ABCDEFGHJK", "MNPQRSTVWX", "YZ01234567", "89ABCDEFGH", "JKMNPQRSTV", "WXYZ012345", "6789ABCDEF", "GHJKMNPQRS", "TVWXYZ0123"},
		BackupCodeSet: humansession.BackupCodeSetView{Remaining: 10, Total: 10, IssuedAt: base.Add(time.Second / 2)},
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
	require.NotContains(t, keys, "backupCodesRemaining", "плоского остатка нет ни в одном ответе (kaname#297 Р3)")
	require.Equal(t, map[string]any{"remaining": float64(10), "total": float64(10), "issuedAt": "2026-09-16T12:00:00Z"}, keys["backupCodeSet"],
		"BCS-03: сводка нового набора, без lastUsedAt")
}

// TestLane_F12_StatusHasTwoShapes — `GET` состояния: без признака; `pending` —
// `enrolled: false` с `pendingUntil` и БЕЗ `backupCodeSet`; `active` — `enrolled:
// true`, `confirmedAt`, сводка `backupCodeSet` (kaname#297 Р2), остаток числом
// (ноль — тоже число, Ф12-26); набора не прочитано — ключа нет (BCS-50).
func TestLane_F12_StatusHasTwoShapes(t *testing.T) {
	stub := &stubLane{statusOut: humansession.StatusOutput{PendingUntil: base.Add(15 * time.Minute)}}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	sess := &http.Cookie{Name: "kaname_session", Value: "bearer-1"}

	r := l.do(t, c, http.MethodGet, "/iam/v1/auth/second-factor", nil, nil, sess)
	require.Equal(t, http.StatusOK, r.status, r.body)
	require.JSONEq(t, `{"totp":{"enrolled":false,"pendingUntil":"2026-09-16T12:15:00Z"},"accessKeys":{"available":false},"stepUpMethods":[]}`, r.body)
	require.Equal(t, "bearer-1", stub.statusIn[0].Bearer.CookieValue())

	stub.statusOut = humansession.StatusOutput{}
	r = l.do(t, c, http.MethodGet, "/iam/v1/auth/second-factor", nil, nil, sess)
	require.JSONEq(t, `{"totp":{"enrolled":false},"accessKeys":{"available":false},"stepUpMethods":[]}`, r.body, "строки нет — ни срока, ни набора")

	// `active`: моменты — до секунды; момента, которого не было, нет ключом
	// (kaname#827, SUA Р6).
	stub.statusOut = humansession.StatusOutput{TOTPEnrolled: true, ConfirmedAt: base,
		BackupCodeSet:       &humansession.BackupCodeSetView{Remaining: 0, Total: 10, IssuedAt: base.Add(time.Second / 2)},
		AccessKeysAvailable: true, StepUpMethods: []string{"totp"}}
	r = l.do(t, c, http.MethodGet, "/iam/v1/auth/second-factor", nil, nil, sess)
	require.JSONEq(t, `{"totp":{"enrolled":true,"confirmedAt":"2026-09-16T12:00:00Z"},"backupCodeSet":{"remaining":0,"total":10,"issuedAt":"2026-09-16T12:00:00Z"},"accessKeys":{"available":true},"stepUpMethods":["totp"]}`, r.body)
	stub.statusOut.TOTPLastUsed, stub.statusOut.TOTPLastUsedAt = true, base.Add(90*time.Second+time.Millisecond)
	stub.statusOut.BackupCodeSet.LastUsed, stub.statusOut.BackupCodeSet.LastUsedAt = true, base.Add(time.Minute)
	r = l.do(t, c, http.MethodGet, "/iam/v1/auth/second-factor", nil, nil, sess)
	require.JSONEq(t, `{"totp":{"enrolled":true,"confirmedAt":"2026-09-16T12:00:00Z","lastUsedAt":"2026-09-16T12:01:30Z"},"backupCodeSet":{"remaining":0,"total":10,"issuedAt":"2026-09-16T12:00:00Z","lastUsedAt":"2026-09-16T12:01:00Z"},"accessKeys":{"available":true},"stepUpMethods":["totp"]}`, r.body)

	// Фактор заведён, сводки набора нет (BCS-50, BCS-51): ключа нет, а не нули.
	stub.statusOut.BackupCodeSet = nil
	r = l.do(t, c, http.MethodGet, "/iam/v1/auth/second-factor", nil, nil, sess)
	require.JSONEq(t, `{"totp":{"enrolled":true,"confirmedAt":"2026-09-16T12:00:00Z","lastUsedAt":"2026-09-16T12:01:30Z"},"accessKeys":{"available":true},"stepUpMethods":["totp"]}`, r.body)

	post := l.do(t, c, http.MethodPost, "/iam/v1/auth/second-factor", map[string]string{}, nil, sess)
	require.Equal(t, http.StatusMethodNotAllowed, post.status)
	require.Equal(t, http.MethodGet, post.header.Get("Allow"))

	stub.statusErr = humansession.ErrAuthenticationFailed
	r = l.do(t, c, http.MethodGet, "/iam/v1/auth/second-factor", nil, nil)
	require.Equal(t, http.StatusUnauthorized, r.status)
	require.JSONEq(t, `{"code":16,"message":"authentication failed","details":[]}`, r.body)
}

// TestLane_F12_15_18_StepUpNamesTheMethodAndTheRemainder — церемония: способ
// называет клиент; ответ — сессия и `assurance`; сводка `backupCodeSet` только
// там, где потреблён запасной код (kaname#297 BCS-06, BCS-07), плоского
// `backupCodesRemaining` нет; ветвь пароля несёт `password`, а не `code`.
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

	stub.stepUpOut.BackupCodeSet = &humansession.BackupCodeSetView{Remaining: 9, Total: 10, IssuedAt: base, LastUsedAt: base.Add(time.Minute + time.Millisecond), LastUsed: true}
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/step-up", map[string]string{"method": "lookup_secret", "code": "ABCDEFGH12", "csrfToken": tok}, fwd(), ctxCk, sess)
	require.Equal(t, http.StatusOK, r.status, r.body)
	keys = nil
	require.NoError(t, json.Unmarshal([]byte(r.body), &keys))
	require.Len(t, keys, 3)
	require.NotContains(t, keys, "backupCodesRemaining", "BCS-31: плоского остатка нет")
	require.Equal(t, map[string]any{"remaining": float64(9), "total": float64(10), "issuedAt": "2026-09-16T12:00:00Z", "lastUsedAt": "2026-09-16T12:01:00Z"}, keys["backupCodeSet"],
		"BCS-06: сводка набора после траты")
	require.Equal(t, assurance.MethodLookupSecret, stub.stepUpIn[1].Method)

	stub.stepUpOut.BackupCodeSet = nil
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/step-up", map[string]string{"method": "password", "password": "correct horse battery", "csrfToken": tok}, fwd(), ctxCk, sess)
	require.Equal(t, http.StatusOK, r.status, r.body)
	require.Equal(t, assurance.MethodPassword, stub.stepUpIn[2].Method)
	require.Equal(t, "correct horse battery", stub.stepUpIn[2].Password)
	require.Empty(t, stub.stepUpIn[2].Code)
}

// TestLane_F12_25_28_RemoveAndBackupCodesConfirmWithACode — снятие и
// перечеканка: `{"method","code"}` в теле; снятие отвечает ровно сессией и
// `assurance` — набора после снятия нет, и это отсутствие ключа (kaname#297
// BCS-10, BCS-11; инвариант kaname#275 сохранён); перечеканка — новым набором
// массивом и его сводкой (BCS-04).
func TestLane_F12_25_28_RemoveAndBackupCodesConfirmWithACode(t *testing.T) {
	fresh, _ := domain.NewSessionBearer()
	stub := &stubLane{
		removeOut: humansession.RemoveSecondFactorOutput{View: levelTwoView(), Bearer: fresh, Assurance: humansession.AssuranceView{Level: "2", MissingForLevel2: []string{}}},
		regenOut: humansession.RegenerateBackupCodesOutput{View: levelTwoView(), Bearer: fresh, Assurance: assuranceTwo(), BackupCodes: []string{"0123456789"},
			BackupCodeSet: humansession.BackupCodeSetView{Remaining: 10, Total: 10, IssuedAt: base}},
	}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "second-factor", nil)
	sess := &http.Cookie{Name: "kaname_session", Value: "bearer-1"}

	r := l.do(t, c, http.MethodPost, "/iam/v1/auth/second-factor/remove", map[string]string{"method": "lookup_secret", "code": "ABCDEFGH12", "csrfToken": tok}, fwd(), ctxCk, sess)
	require.Equal(t, http.StatusOK, r.status, r.body)
	var keys map[string]any
	require.NoError(t, json.Unmarshal([]byte(r.body), &keys))
	require.Len(t, keys, 2, "BCS-10, BCS-11: ключи тела ровно session и assurance")
	require.Contains(t, keys, "session")
	require.Equal(t, map[string]any{"level": "2", "level2Reachable": false, "missingForLevel2": []any{}}, keys["assurance"])
	require.Equal(t, fresh.CookieValue(), cookieNamed(r.cookies, "kaname_session").Value)
	require.Equal(t, assurance.MethodLookupSecret, stub.removeIn[0].Factor.Method)
	require.Equal(t, "ABCDEFGH12", stub.removeIn[0].Factor.Code)
	require.Equal(t, "203.0.113.7", stub.removeIn[0].Source)

	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/second-factor/backup-codes", map[string]string{"method": "totp", "code": "123456", "csrfToken": tok}, fwd(), ctxCk, sess)
	require.Equal(t, http.StatusOK, r.status, r.body)
	keys = nil // разбор в непустую карту дописывает, а не заменяет
	require.NoError(t, json.Unmarshal([]byte(r.body), &keys))
	require.Len(t, keys, 4)
	require.Equal(t, []any{"0123456789"}, keys["backupCodes"])
	require.Equal(t, map[string]any{"remaining": float64(10), "total": float64(10), "issuedAt": "2026-09-16T12:00:00Z"}, keys["backupCodeSet"],
		"BCS-04: сводка нового набора, без lastUsedAt")
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
		{"step-up-method", "/iam/v1/auth/step-up", map[string]any{"method": "sms", "code": "123456", "csrfToken": suTok}, `"Illegal argument method: must be one of password|totp|lookup_secret|webauthn"`},
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
	// Свои сессии (kaname#634, Р1): один вид на оба снимающих глагола — в том же
	// закрытом перечне.
	require.Contains(t, domain.FormKinds(), domain.FormSessionEnd)
	require.Equal(t, domain.FormKind("session-end"), domain.FormSessionEnd)
	// Видов признака 17: тринадцать базы, два смены адреса (kaname#635, Р1),
	// один своих сессий (kaname#634, Р1) и один выдачи испытания повышения
	// ключом (kaname#827, Р2).
	require.Contains(t, domain.FormKinds(), domain.FormStepUpAccessKeyBegin)
	require.Equal(t, domain.FormKind("step-up-access-key-begin"), domain.FormStepUpAccessKeyBegin)
	require.Len(t, domain.FormKinds(), 17, "видов признака — 17 (приёмки kaname#635, kaname#634 и kaname#827)")

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
	// Путей полосы — 24: два глагола подтверждения адреса (kaname#456, Р6),
	// два глагола входа ключом (Ф13, kaname#613), заведение первого пароля
	// (kaname#213), два глагола смены адреса (kaname#635) и три глагола своих
	// сессий (kaname#634), выдача испытания повышения ключом (kaname#827).
	// Число — перепись популяции, двигает его тот, кто популяцию изменил.
	require.Len(t, loginlanehttp.Paths(), 24)
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
	require.JSONEq(t, refusalWire(14, stepSecondFactorUnavailable), r.body)

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
