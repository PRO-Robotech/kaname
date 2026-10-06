// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_key_login_harness_integration_test.go — «ДАНО» полосы входа ключом
// доступа без пароля (Ф13, задача PRO-Robotech/kaname#613; приёмка
// `docs/engineering/acceptance/passwordless-login-with-access-key.md`,
// отпечаток 5fe6cca1…, §5 преамбула «Как строится Дано»).
//
// # Почему «Дано» строится ДЕЙСТВИЕМ продукта, а не приготовленным ответом
//
//   - «личность с принятым ключом» — строку ключа кладёт ПИСАТЕЛЬ ПРОДУКТА
//     (`access_keys.Writer.InsertKey`) с НАСТОЯЩИМ открытым ключом подставного
//     аутентификатора; рукоятка — значение человека из его строки рукояток
//     (`EnsureCeremonyHandle`, Р3), то есть то, что положила бы церемония Ф7;
//   - «испытание выдано» — НАСТОЯЩИМ глаголом `begin` под тем же контекстом
//     формы, под которым предъявляется утверждение.
//
// # Почему виды формы и пути — литералами
//
// Проба обязана КОМПИЛИРОВАТЬСЯ на ревизии без полосы: ссылка на не
// заведённую константу сорвала бы сборку, а сорванная сборка — «не
// выполнилось», не красный (`change-graph.md` §5). Литералы наблюдают ровно
// то, что видит клиент полосы: путь и имя вида в запросе.
package loginlanehttp_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

const (
	// Пути двух глаголов формы (Р1).
	akPathBegin = "/iam/v1/auth/access-key/begin"
	akPathLogin = "/iam/v1/auth/access-key/login"
	// Виды признака формы — по одному на глагол (Р1, решение владельца
	// 2026-09-22).
	akKindBegin = "access-key-begin"
	akKindLogin = "access-key-login"
)

// akProbeRPID / akProbeOrigin — доверяющая сторона и происхождение стенда:
// ими собирает утверждение подставной аутентификатор и ими же провязана
// полоса стенда (`laneKeyBinding`). Расхождение читалось бы как отказ
// происхождения вместо отказа подписи.
const (
	akProbeRPID   = laneProbeDomain
	akProbeOrigin = "https://" + laneProbeDomain
)

// laneKeyBinding — привязка ключей стенда (три ручки Ф7 Р2).
func laneKeyBinding() webauthnverify.Binding {
	return webauthnverify.Binding{
		RPID:       akProbeRPID,
		Origins:    []string{akProbeOrigin},
		Algorithms: []webauthnverify.Algorithm{webauthnverify.AlgES256},
	}
}

// akKey — принятый ключ личности: строка, рукоятка и аутентификатор, который
// её подписывает.
type akKey struct {
	id     domain.AccessKeyID
	handle []byte
	auth   *webauthntest.Authenticator
}

// givenAcceptedKey — «Дано: личность с принятым ключом» (Ф7-01) для user.
func givenAcceptedKey(t *testing.T, h *sessionLane, user domain.UserID) akKey {
	t.Helper()
	// Потолок вида объявлен ДО вставки: без него писатель отказывает учётом, и
	// это «условие не создано», а не отказ полосы.
	_, err := h.pool.Exec(h.ctx, `
		INSERT INTO own_ceilings (kind, limit_value) VALUES ('iam.user.accessKey', $1)
		ON CONFLICT (kind) DO UPDATE SET limit_value = EXCLUDED.limit_value`, 8)
	require.NoError(t, err, "Дано: потолок вида ключа объявлен")
	auth := webauthntest.New(t, webauthntest.AlgES256)
	repo := kanamepg.NewAccessKeyRepo(h.pool)
	w, err := repo.Writer(h.ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(h.ctx) }()
	minted, err := domain.NewCeremonyHandle()
	require.NoError(t, err)
	handle, err := w.EnsureCeremonyHandle(h.ctx, user, minted)
	require.NoError(t, err, "Дано: рукоятка человека — из его строки рукояток (Р3)")
	k, err := w.InsertKey(h.ctx, domain.AccessKey{
		ID:           domain.AccessKeyID(ids.NewHyphenID(ids.PrefixAccessKeyHyphen)),
		UserID:       user,
		CredentialID: auth.CredentialID(),
		PublicKey:    auth.COSEPublicKey(t),
		Algorithm:    auth.Algorithm(),
		UserHandle:   handle.Bytes(),
		Name:         "probe-key",
		CreatedAt:    time.Now().UTC(),
	})
	require.NoError(t, err, "Дано: строка ключа кладётся писателем продукта")
	require.NoError(t, w.Commit(h.ctx))
	return akKey{id: k.ID, handle: handle.Bytes(), auth: auth}
}

// revokeKey — снятие строки ключа писателем продукта (Ф7-25, ветвь «к»).
func revokeKey(t *testing.T, h *sessionLane, user domain.UserID, id domain.AccessKeyID) {
	t.Helper()
	w, err := kanamepg.NewAccessKeyRepo(h.pool).Writer(h.ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(h.ctx) }()
	_, ok, err := w.DeleteOwnedByID(h.ctx, user, id)
	require.NoError(t, err)
	require.True(t, ok, "Дано: ключ снят")
	require.NoError(t, w.Commit(h.ctx))
}

// akForm — контекст формы и ДВА признака под ним (Р1).
type akForm struct {
	begin, login string
	cookie       *http.Cookie
}

// givenAKForm — контекст формы полосы ключа: признак запроса, затем признак
// подтверждения под ТЕМ ЖЕ контекстом.
func givenAKForm(t *testing.T, h *sessionLane) akForm {
	t.Helper()
	tb, ck := h.lane.csrf(t, h.c, akKindBegin, nil)
	tl, _ := h.lane.csrf(t, h.c, akKindLogin, ck)
	return akForm{begin: tb, login: tl, cookie: ck}
}

// akBegin — глагол испытания с признаком token.
func akBegin(t *testing.T, h *sessionLane, f akForm, body map[string]any) reply {
	t.Helper()
	return h.lane.do(t, h.c, http.MethodPost, akPathBegin, body, fwd(), f.cookie)
}

// givenChallenge — «Дано: испытание выдано» настоящим `begin`.
func givenChallenge(t *testing.T, h *sessionLane, f akForm) []byte {
	t.Helper()
	r := akBegin(t, h, f, map[string]any{"csrfToken": f.begin})
	require.Equalf(t, http.StatusOK, r.status, "Дано: `begin` выдаёт испытание: %s", r.body)
	return challengeOf(t, r)
}

// challengeOf — байты испытания из ответа `begin`.
func challengeOf(t *testing.T, r reply) []byte {
	t.Helper()
	var out struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &out), r.body)
	raw, err := base64.RawURLEncoding.DecodeString(out.PublicKey.Challenge)
	require.NoError(t, err, "испытание — base64url без дополнения")
	return raw
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// credentialBody — объект `credential` формы входа: браузерный ответ
// аутентификатора; nil-рукоятка — поле не отправляется.
func credentialBody(as webauthntest.Assertion, userHandle []byte) map[string]any {
	resp := map[string]any{
		"clientDataJSON":    b64url(as.ClientDataJSON),
		"authenticatorData": b64url(as.AuthenticatorData),
		"signature":         b64url(as.Signature),
	}
	if userHandle != nil {
		resp["userHandle"] = b64url(userHandle)
	}
	return map[string]any{"id": b64url(as.CredentialID), "rawId": b64url(as.CredentialID), "type": "public-key", "response": resp}
}

// assertOver — утверждение ключа k над испытанием challenge.
func assertOver(t *testing.T, k akKey, challenge []byte, o webauthntest.AssertionOptions) webauthntest.Assertion {
	t.Helper()
	o.Challenge = challenge
	if o.Origin == "" {
		o.Origin = akProbeOrigin
	}
	if o.RPID == "" {
		o.RPID = akProbeRPID
	}
	return k.auth.Assert(t, o)
}

// akLogin — глагол входа.
func akLogin(t *testing.T, h *sessionLane, f akForm, body map[string]any) reply {
	t.Helper()
	return h.lane.do(t, h.c, http.MethodPost, akPathLogin, body, fwd(), f.cookie)
}

// akLoginWith — вход ключом k над challenge в контексте f.
func akLoginWith(t *testing.T, h *sessionLane, f akForm, k akKey, challenge []byte, o webauthntest.AssertionOptions) reply {
	t.Helper()
	as := assertOver(t, k, challenge, o)
	return akLogin(t, h, f, map[string]any{"csrfToken": f.login, "credential": credentialBody(as, k.handle)})
}

// f302 — ЕДИНЫЙ отказ входа паролем (Ф3-02), захваченный живым входом с
// неверным паролем: положительный производитель отказа, не литерал.
func f302(t *testing.T, h *sessionLane) reply {
	t.Helper()
	tok, ck := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
	r := h.lane.do(t, h.c, http.MethodPost, "/iam/v1/auth/login",
		map[string]any{"email": h.email, "password": laneWrongPassword, "csrfToken": tok}, fwd(), ck)
	require.Equalf(t, http.StatusUnauthorized, r.status, "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: единый отказ Ф3-02 существует: %s", r.body)
	require.Contains(t, r.body, "authentication failed")
	return r
}
