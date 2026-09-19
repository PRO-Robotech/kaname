// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package loginlanehttp

// access_key_login.go — ТРАНСПОРТ двух глаголов формы входа ключом (Ф13 Р1):
// разбор формы, признак вида, base64url — и ничего больше. Решения принимает
// вариант использования; здесь только перевод байтов браузера в его вход и
// его исхода — в тело ответа.
//
// # Форма закрыта, и лишнее поле отвергается
//
// `secondFactor` у входа ключом НЕТ (Р5): второй фактор этой полосой не
// требуется и не принимается. Поле, которое у входа паролём законно, здесь
// отвергается разбором по имени — это вторая сторона оси, а не оговорка формы:
// принять поле и выбросить значило бы обещать вызывающему проверку, которой
// нет.
//
// # Почему base64url без дополнения — единственная принимаемая форма
//
// Норма сериализует поля браузерного ответа именно так. Принимать вдобавок
// форму с дополнением значило бы, что одно значение выразимо двумя способами:
// два написания одного удостоверения пришли бы в два разных запроса, и
// хранилище различало бы их там, где различия нет.

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// credentialTypePublicKey — единственный принимаемый вид удостоверения: норма
// другого для этой формы не знает.
const credentialTypePublicKey = "public-key"

// accessKeyBeginForm — форма выдачи испытания: ОДНО поле.
type accessKeyBeginForm struct {
	CSRFToken string `json:"csrfToken"`
}

// accessKeyLoginForm — форма предъявления: признак и браузерный ответ
// аутентификатора. Вложенное разбирается отдельно, чтобы отказ формы называл
// поле полным именем.
type accessKeyLoginForm struct {
	CSRFToken  string          `json:"csrfToken"`
	Credential json.RawMessage `json:"credential"`
}

// credentialField — объект `credential` браузера.
type credentialField struct {
	ID       string          `json:"id"`
	RawID    string          `json:"rawId"`
	Type     string          `json:"type"`
	Response json.RawMessage `json:"response"`
}

// credentialResponseField — объект `credential.response`.
type credentialResponseField struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle"`
}

// b64urlField — поле в base64url без дополнения. Пустое значение остаётся
// пустым (его «обязательность» судит вариант использования по своему правилу),
// негодное написание — отказ формы с именем поля.
func b64urlField(name, v string) ([]byte, error) {
	if v == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return nil, &humansession.FieldError{Field: name, Rule: "must be base64url without padding"}
	}
	return raw, nil
}

// accessKeyBegin — выдача испытания (Ф13-01).
func (h *Handler) accessKeyBegin(w http.ResponseWriter, r *http.Request) {
	var form accessKeyBeginForm
	if err := decodeForm(r, &form); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	if !h.judgeForm(w, r, domain.FormAccessKeyLogin, form.CSRFToken) {
		return
	}
	out, err := h.lane.BeginAccessKeyLogin(r.Context(), humansession.BeginAccessKeyLoginInput{
		FormContext: h.formContext(r), Source: h.source(r),
	})
	if err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	// `allowCredentials` — ПУСТОЙ МАССИВ словом, а не отсутствующее поле:
	// «никого не ограничивать» есть факт о запросе, и клиент читает его
	// значением, а не умолчанием (Ф13-01).
	writeJSON(w, http.StatusOK, map[string]any{
		"publicKey": map[string]any{
			"challenge":        base64.RawURLEncoding.EncodeToString(out.Challenge),
			"rpId":             out.RPID,
			"timeout":          out.Timeout.Milliseconds(),
			"userVerification": out.UserVerification,
			"allowCredentials": []any{},
		},
	})
}

// accessKeyLogin — предъявление утверждения (Ф13-05).
func (h *Handler) accessKeyLogin(w http.ResponseWriter, r *http.Request) {
	var form accessKeyLoginForm
	if err := decodeForm(r, &form); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	if !h.judgeForm(w, r, domain.FormAccessKeyLogin, form.CSRFToken) {
		return
	}
	in, err := accessKeyLoginInput(form)
	if err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	in.FormContext = h.formContext(r)
	in.Source = h.source(r)
	out, err := h.lane.AccessKeyLogin(r.Context(), in)
	if err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	// Контекст формы СМЕНЯЕТСЯ выдачей сессии (Р12, Ф3-37) — тем же правилом,
	// что у входа паролём.
	fresh, ferr := humansession.NewFormContext()
	if ferr != nil {
		writeRefusal(w, http.StatusServiceUnavailable, codeUnavailable, humansession.TextRequestNotPerformed, nil)
		return
	}
	http.SetCookie(w, h.sessionCookie(out.Bearer))
	http.SetCookie(w, h.formCookie(fresh))
	writeJSON(w, http.StatusOK, map[string]any{
		"user":    userJSON(out.View),
		"session": sessionJSON(out.View),
	})
}

// accessKeyLoginInput — байты браузера из формы. Отсутствующее поле называется
// полным именем ДО всякой сверки (Ф13-07).
func accessKeyLoginInput(form accessKeyLoginForm) (humansession.AccessKeyLoginInput, error) {
	var in humansession.AccessKeyLoginInput
	if len(form.Credential) == 0 || string(form.Credential) == "null" {
		return in, humansession.FieldRequired("credential")
	}
	var cred credentialField
	if err := decodeNested("credential", form.Credential, &cred); err != nil {
		return in, err
	}
	if len(cred.Response) == 0 || string(cred.Response) == "null" {
		return in, humansession.FieldRequired("credential.response")
	}
	var resp credentialResponseField
	if err := decodeNested("credential.response", cred.Response, &resp); err != nil {
		return in, err
	}
	fields := []struct {
		name  string
		value string
		into  *[]byte
	}{
		{"credential.id", cred.ID, &in.CredentialID},
		{"credential.response.clientDataJSON", resp.ClientDataJSON, &in.ClientDataJSON},
		{"credential.response.authenticatorData", resp.AuthenticatorData, &in.AuthenticatorData},
		{"credential.response.signature", resp.Signature, &in.Signature},
		{"credential.response.userHandle", resp.UserHandle, &in.UserHandle},
	}
	for _, f := range fields {
		raw, err := b64urlField(f.name, f.value)
		if err != nil {
			return humansession.AccessKeyLoginInput{}, err
		}
		*f.into = raw
	}
	// `type` и `rawId` форма ПРИНИМАЕТ — значит обязана их читать: поле,
	// принятое и выброшенное, обещает вызывающему проверку, которой нет.
	// `rawId` — то же удостоверение вторым написанием, и расхождение двух
	// написаний в одном запросе есть отказ формы, а не выбор одного из них.
	if cred.Type != credentialTypePublicKey {
		return humansession.AccessKeyLoginInput{}, &humansession.FieldError{
			Field: "credential.type", Rule: "must be " + credentialTypePublicKey}
	}
	if cred.RawID != "" && cred.RawID != cred.ID {
		return humansession.AccessKeyLoginInput{}, &humansession.FieldError{
			Field: "credential.rawId", Rule: "must equal credential.id"}
	}
	return in, nil
}
