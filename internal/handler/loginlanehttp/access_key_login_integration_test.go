// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_key_login_integration_test.go — СЦЕНАРИИ полосы входа ключом доступа
// без пароля на собственном слушателе службы (Ф13, задача
// PRO-Robotech/kaname#613; приёмка
// `docs/engineering/acceptance/passwordless-login-with-access-key.md`,
// отпечаток `5fe6cca1aea606f96b2f24174a8f45411291f69250e6fb268b3274fd17a58af4`,
// запись `docs/specs/reviews/passwordless-login-with-access-key/5fe6cca1….yaml`,
// APPROVED).
//
// Дом пробы — репозиторий предмета (`e2e-flow.md` §7а): слушатель формы над
// НАСТОЯЩИМИ глаголами и настоящей базой, клиент предъявляет сертификат края
// (Ф3 Р16). Ретрансляция краем (Ф13-28) — в доме платформы.
//
// # Порядок проверок в каждой пробе — несущий
//
// Сперва «Дано» строится действием продукта и само утверждает свой исход
// (положительный контроль фикстуры), только потом — проба возможности. Отказ
// «Дано» — сломанная фикстура, а не красный вердикт.
//
// # Что на ревизии без полосы
//
// Видов `access-key-begin`/`access-key-login` в закрытом перечне формы нет —
// `GET /iam/v1/auth/csrf` отвечает 400 с именем поля `form` (Ф3-35), и это
// первый честный красный (Ф13-27, §9 п. 3): адрес признака существует, а
// объявленной возможности в нём нет. Глаголов `begin`/`login` нет — 404.
package loginlanehttp_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

// TestF13_27_TwoFormKindsAreDeclaredAndAThirdIsRefused — Ф13-27: оба вида
// признака выдаются под одним контекстом, третье написание — 400 с полем.
func TestF13_27_TwoFormKindsAreDeclaredAndAThirdIsRefused(t *testing.T) {
	h := newSessionLane(t)
	begin := h.lane.do(t, h.c, http.MethodGet, "/iam/v1/auth/csrf?form="+akKindBegin, nil, nil)
	require.Equalf(t, http.StatusOK, begin.status, "Ф13-27: вид `%s` в закрытом перечне формы: %s", akKindBegin, begin.body)
	ck := cookieNamed(begin.cookies, loginlanehttp.CookieForm)
	require.NotNil(t, ck, "Ф13-27: признак выдан вместе с контекстом")
	login := h.lane.do(t, h.c, http.MethodGet, "/iam/v1/auth/csrf?form="+akKindLogin, nil, nil, ck)
	require.Equalf(t, http.StatusOK, login.status, "Ф13-27: вид `%s` в закрытом перечне формы: %s", akKindLogin, login.body)
	require.Nil(t, cookieNamed(login.cookies, loginlanehttp.CookieForm), "контекст ОДИН на оба вида (Р1)")
	require.NotEqual(t, begin.body, login.body, "два признака — разные")

	third := h.lane.do(t, h.c, http.MethodGet, "/iam/v1/auth/csrf?form=access-key", nil, nil)
	require.Equal(t, http.StatusBadRequest, third.status, "Ф13-27: третье написание вида — отказ формы")
	require.Contains(t, third.body, "form", "Ф3-35: отказ называет поле")
}

// TestF13_01_ChallengeNamesNobody — Ф13-01: испытание без имени, объявленной
// формы, без сессии; два испытания подряд различны.
func TestF13_01_ChallengeNamesNobody(t *testing.T) {
	h := newSessionLane(t)
	f := givenAKForm(t, h)
	r := akBegin(t, h, f, map[string]any{"csrfToken": f.begin})
	require.Equalf(t, http.StatusOK, r.status, "Ф13-01: испытание выдано: %s", r.body)

	var out struct {
		PublicKey map[string]json.RawMessage `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &out))
	require.ElementsMatch(t, []string{"challenge", "rpId", "timeout", "userVerification", "allowCredentials"}, keysOf(out.PublicKey),
		"Ф13-01: форма ответа — ровно пять полей")
	require.JSONEq(t, `[]`, string(out.PublicKey["allowCredentials"]), "Ф13-01: allowCredentials — пустой массив словом")
	require.JSONEq(t, `"preferred"`, string(out.PublicKey["userVerification"]), "Ф13-01: литерал Ф7 Р9")
	require.JSONEq(t, strconv.Quote(akProbeRPID), string(out.PublicKey["rpId"]), "Ф13-01: имя доверяющей стороны Ф7 Р2")
	require.JSONEq(t, strconv.FormatInt(access_keys.ChallengeTTL.Milliseconds(), 10), string(out.PublicKey["timeout"]),
		"Ф13-01: срок — литерал Ф7 в миллисекундах")
	require.Nil(t, cookieNamed(r.cookies, loginlanehttp.CookieSession), "Ф13-01: испытание сессией не является")
	require.Nil(t, cookieNamed(r.cookies, loginlanehttp.CookieForm), "Ф13-01: контекст формы не сменён")

	c1 := challengeOf(t, r)
	c2 := givenChallenge(t, h, f)
	require.Len(t, c1, 32)
	require.NotEqual(t, c1, c2, "Ф13-01: два испытания подряд различны (§7 инв. 5)")
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestF13_02_BeginFormRefusals — Ф13-02: признак обязателен, вид — вид ЭТОЙ
// формы; пара (д)/(е) различается ровно видом признака.
func TestF13_02_BeginFormRefusals(t *testing.T) {
	h := newSessionLane(t)
	f := givenAKForm(t, h)

	// (а) без признака — 400 с полем.
	r := akBegin(t, h, f, map[string]any{})
	require.Equal(t, http.StatusBadRequest, r.status, "Ф13-02 (а): %s", r.body)
	require.Contains(t, r.body, "csrfToken")
	// (б) признак вида `login` — 403.
	loginTok, _ := h.lane.csrf(t, h.c, string(domain.FormLogin), f.cookie)
	r = akBegin(t, h, f, map[string]any{"csrfToken": loginTok})
	require.Equal(t, http.StatusForbidden, r.status, "Ф13-02 (б): %s", r.body)
	require.Contains(t, r.body, "form token rejected")
	// (г) лишнее поле — 400 с его именем.
	r = akBegin(t, h, f, map[string]any{"csrfToken": f.begin, "email": h.email})
	require.Equal(t, http.StatusBadRequest, r.status, "Ф13-02 (г): %s", r.body)
	require.Contains(t, r.body, "email")
	// (д) признак формы ПОДТВЕРЖДЕНИЯ на форме запроса — 403.
	d := akBegin(t, h, f, map[string]any{"csrfToken": f.login})
	require.Equal(t, http.StatusForbidden, d.status, "Ф13-02 (д): признак `%s` форму запроса не закрывает: %s", akKindLogin, d.body)
	require.Contains(t, d.body, "form token rejected")
	// (е) близнец (д): годный признак своего вида — 200.
	e := akBegin(t, h, f, map[string]any{"csrfToken": f.begin})
	require.Equal(t, http.StatusOK, e.status, "Ф13-02 (е): %s", e.body)
}

// TestF13_26_LoginFormIsNotClosedByTheBeginToken — Ф13-26: признак формы
// запроса форму подтверждения не закрывает; после выдачи сессии контекст сменён.
func TestF13_26_LoginFormIsNotClosedByTheBeginToken(t *testing.T) {
	h := newSessionLane(t)
	k := givenAcceptedKey(t, h, h.user.ID)
	f := givenAKForm(t, h)
	c := givenChallenge(t, h, f)
	as := assertOver(t, k, c, webauthntest.AssertionOptions{})
	cred := credentialBody(as, k.handle)

	// (а) без признака — 400.
	r := akLogin(t, h, f, map[string]any{"credential": cred})
	require.Equal(t, http.StatusBadRequest, r.status, "Ф13-26 (а): %s", r.body)
	require.Contains(t, r.body, "csrfToken")
	// (б) признак вида `password` — 403.
	pwTok, _ := h.lane.csrf(t, h.c, string(domain.FormPassword), f.cookie)
	r = akLogin(t, h, f, map[string]any{"csrfToken": pwTok, "credential": cred})
	require.Equal(t, http.StatusForbidden, r.status, "Ф13-26 (б): %s", r.body)
	// (д) признак формы ЗАПРОСА — 403; испытание не сгорело.
	d := akLogin(t, h, f, map[string]any{"csrfToken": f.begin, "credential": cred})
	require.Equal(t, http.StatusForbidden, d.status, "Ф13-26 (д): признак `%s` форму подтверждения не закрывает: %s", akKindBegin, d.body)
	require.Contains(t, d.body, "form token rejected")
	// (г) близнец: годный признак своего вида — 200, и контекст сменён.
	g := akLogin(t, h, f, map[string]any{"csrfToken": f.login, "credential": cred})
	require.Equal(t, http.StatusOK, g.status, "Ф13-26 (г): %s", g.body)
	fresh := cookieNamed(g.cookies, loginlanehttp.CookieForm)
	require.NotNil(t, fresh, "Ф13-26 (г): выдача сменила контекст формы")
	require.NotEqual(t, f.cookie.Value, fresh.Value)
}

// TestF13_05_LoginIssuesASessionWithoutAPassword — Ф13-05, Ф13-29: сессия
// выдана, носитель поставлен, пароль не предъявлен; событие выдачи несёт
// способ и `id` ключа и ничего секретного.
func TestF13_05_LoginIssuesASessionWithoutAPassword(t *testing.T) {
	h := newSessionLane(t)
	k := givenAcceptedKey(t, h, h.user.ID)
	f := givenAKForm(t, h)
	c := givenChallenge(t, h, f)
	before := time.Now().UTC()

	as := assertOver(t, k, c, webauthntest.AssertionOptions{})
	body := map[string]any{"csrfToken": f.login, "credential": credentialBody(as, k.handle)}
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	require.NotContains(t, string(raw), `"password"`, "Ф13-05: ни один запрос полосы не несёт поля password")
	r := akLogin(t, h, f, body)
	require.Equalf(t, http.StatusOK, r.status, "Ф13-05: вход ключом выдаёт сессию: %s", r.body)

	var out struct {
		User struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
		Session struct {
			ExpiresAt              time.Time `json:"expiresAt"`
			AssuranceLevel         string    `json:"assuranceLevel"`
			PasswordChangeRequired bool      `json:"passwordChangeRequired"`
		} `json:"session"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &out), r.body)
	require.Equal(t, string(h.user.ID), out.User.ID)
	require.Equal(t, "2", out.Session.AssuranceLevel, "Ф13-05: «2» — правило над {webauthn} без проверки пользователя")
	require.False(t, out.Session.PasswordChangeRequired)
	require.WithinDuration(t, before.Add(laneSessionTTL), out.Session.ExpiresAt, time.Minute, "срок — выдача плюс 24 ч")

	bearer := cookieNamed(r.cookies, loginlanehttp.CookieSession)
	require.NotNil(t, bearer, "Ф13-05: носитель поставлен")
	require.NotNil(t, cookieNamed(r.cookies, loginlanehttp.CookieForm), "Ф13-05: контекст сменён выдачей")
	row, ok := h.rowByBearer(t, bearer.Value)
	require.True(t, ok)
	require.Equal(t, []string{"webauthn"}, row.methods, "Ф13-05 (I): множество предъявленного — {webauthn}")
	require.Equal(t, "2", row.level)

	var lastUsed *time.Time
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT last_used_at FROM user_access_keys WHERE id = $1`, string(k.id)).Scan(&lastUsed))
	require.NotNil(t, lastUsed, "Ф13-05: момент последнего предъявления ключа сдвинут")

	// Ф13-29: одно событие выдачи с `access_key_id`, без секрета.
	var payloads []string
	rows, err := h.pool.Query(h.ctx, `SELECT event_payload::text FROM audit_outbox
		 WHERE event_type = 'iam.session.issued' AND event_payload->>'access_key_id' IS NOT NULL`)
	require.NoError(t, err)
	for rows.Next() {
		var p string
		require.NoError(t, rows.Scan(&p))
		payloads = append(payloads, p)
	}
	require.NoError(t, rows.Err())
	require.Len(t, payloads, 1, "Ф13-29: ровно одно событие выдачи входом ключом")
	var ev map[string]any
	require.NoError(t, json.Unmarshal([]byte(payloads[0]), &ev))
	require.Equal(t, string(k.id), ev["access_key_id"], "Р10: `id` ключа формы ak-…")
	require.Equal(t, []any{"webauthn"}, ev["methods"])
	require.Equal(t, string(h.user.ID), ev["user_id"])
	require.Equal(t, row.id, ev["session_id"])
	for _, banned := range []string{h.email, b64url(k.auth.CredentialID()), b64url(k.handle), bearer.Value} {
		require.NotContains(t, payloads[0], banned, "Ф13-29: событие без адреса, удостоверения, рукоятки и носителя")
	}
	require.Len(t, ev, 4, "Ф13-29: состав события — user_id, session_id, methods, access_key_id")
}

// TestF13_06_OneRefusalForEveryCause — Ф13-06: каждая ветвь — единый отказ
// входа, побайтово равный Ф3-02; сессии не выдано ни одной.
func TestF13_06_OneRefusalForEveryCause(t *testing.T) {
	h := newSessionLane(t)
	ref := f302(t, h)
	k := givenAcceptedKey(t, h, h.user.ID)
	other := registerPerson(t, h, "f1306")
	kOther := givenAcceptedKey(t, h, other)
	stranger := akKey{auth: webauthntest.New(t, webauthntest.AlgES256), handle: k.handle}
	totalBefore, _ := h.sessionsOfPerson(t)

	refused := func(name string, r reply) {
		t.Helper()
		require.Equalf(t, http.StatusUnauthorized, r.status, "Ф13-06 %s: единый отказ входа — 401: %s", name, r.body)
		require.Equalf(t, ref.body, r.body, "Ф13-06 %s: тело побайтово равно Ф3-02", name)
		require.Nilf(t, cookieNamed(r.cookies, loginlanehttp.CookieSession), "Ф13-06 %s: без Set-Cookie носителя", name)
	}
	fresh := func() (akForm, []byte) {
		f := givenAKForm(t, h)
		return f, givenChallenge(t, h, f)
	}

	f, c := fresh()
	refused("(а) подпись", akLoginWith(t, h, f, k, c, webauthntest.AssertionOptions{ForgeSignature: true}))
	f, c = fresh()
	refused("(б) удостоверения нет", akLoginWith(t, h, f, stranger, c, webauthntest.AssertionOptions{}))
	f, c = fresh()
	refused("(в) происхождение", akLoginWith(t, h, f, k, c, webauthntest.AssertionOptions{Origin: "https://elsewhere.example.invalid"}))
	f, c = fresh()
	refused("(г) хэш имени", akLoginWith(t, h, f, k, c, webauthntest.AssertionOptions{RPID: "elsewhere.example.invalid"}))
	f, c = fresh()
	refused("(д) присутствие", akLoginWith(t, h, f, k, c, webauthntest.AssertionOptions{UserPresentUnset: true}))
	f, _ = fresh()
	refused("(ж) не выдавалось", akLoginWith(t, h, f, k, []byte("challenge-never-issued-by-the-lane"), webauthntest.AssertionOptions{}))
	_, cK1 := fresh()
	f2 := givenAKForm(t, h)
	refused("(ж) чужой контекст", akLoginWith(t, h, f2, k, cK1, webauthntest.AssertionOptions{}))
	f, c = fresh()
	refused("(з) рукоятка другого человека", akLogin(t, h, f, map[string]any{"csrfToken": f.login,
		"credential": credentialBody(assertOver(t, k, c, webauthntest.AssertionOptions{}), kOther.handle)}))

	f, c = fresh()
	h.setInviteStatus(t, domain.InviteStatusBlocked)
	refused("(и) владелец заблокирован", akLoginWith(t, h, f, k, c, webauthntest.AssertionOptions{}))
	h.setInviteStatus(t, domain.InviteStatusActive)

	revokeKey(t, h, other, kOther.id)
	f, c = fresh()
	refused("(к) ключ снят", akLoginWith(t, h, f, kOther, c, webauthntest.AssertionOptions{}))

	totalAfter, _ := h.sessionsOfPerson(t)
	require.Equal(t, totalBefore, totalAfter, "Ф13-06: ни одна ветвь сессии не выдала")

	// Положительный контроль (и): разблокированный входит.
	f, c = fresh()
	ok := akLoginWith(t, h, f, k, c, webauthntest.AssertionOptions{})
	require.Equalf(t, http.StatusOK, ok.status, "Ф13-06 положительный контроль: %s", ok.body)
}

// registerPerson — вторая личность стенда регистрацией полосой пароля.
func registerPerson(t *testing.T, h *sessionLane, tag string) domain.UserID {
	t.Helper()
	out, err := h.register.Execute(h.ctx, registration.Input{
		Email:    tag + "-" + ids.NewID("tst")[3:9] + "@example.invalid",
		Password: integrationPassword, Source: fwd()[loginlanehttp.HeaderForwardedFor],
	})
	require.NoError(t, err, "Дано: вторая личность зарегистрирована")
	return out.View.User.ID
}

// TestF13_07_LoginFormRefusals — Ф13-07, Ф13-16: отсутствующее поле
// называется, лишнее отвергается, испытание не сгорает.
func TestF13_07_LoginFormRefusals(t *testing.T) {
	h := newSessionLane(t)
	k := givenAcceptedKey(t, h, h.user.ID)
	f := givenAKForm(t, h)
	c := givenChallenge(t, h, f)
	as := assertOver(t, k, c, webauthntest.AssertionOptions{})
	full := func() map[string]any {
		return map[string]any{"csrfToken": f.login, "credential": credentialBody(as, k.handle)}
	}

	missing := []struct {
		field string
		mut   func(map[string]any)
	}{
		{"credential", func(b map[string]any) { delete(b, "credential") }},
		{"userHandle", func(b map[string]any) {
			delete(b["credential"].(map[string]any)["response"].(map[string]any), "userHandle")
		}},
		{"signature", func(b map[string]any) {
			delete(b["credential"].(map[string]any)["response"].(map[string]any), "signature")
		}},
		{"csrfToken", func(b map[string]any) { delete(b, "csrfToken") }},
	}
	for _, m := range missing {
		b := full()
		m.mut(b)
		r := akLogin(t, h, f, b)
		require.Equalf(t, http.StatusBadRequest, r.status, "Ф13-07: без %s — 400: %s", m.field, r.body)
		require.Containsf(t, r.body, m.field, "Ф13-07: отказ называет поле %s", m.field)
	}
	for _, extra := range []string{"secondFactor", "email", "password"} {
		b := full()
		b[extra] = map[string]any{"method": "totp", "code": "123456"}
		r := akLogin(t, h, f, b)
		require.Equalf(t, http.StatusBadRequest, r.status, "Ф13-07/Ф13-16: лишнее поле %s — 400: %s", extra, r.body)
		require.Containsf(t, r.body, extra, "Ф13-07: отказ называет поле %s", extra)
	}
	b := full()
	b["credential"].(map[string]any)["clientExtensionResults"] = map[string]any{}
	r := akLogin(t, h, f, b)
	require.Equalf(t, http.StatusBadRequest, r.status, "Ф13-07: clientExtensionResults — 400: %s", r.body)
	require.Contains(t, r.body, "clientExtensionResults")

	// Положительный контроль: полная форма над ТЕМ ЖЕ испытанием проходит —
	// отказы формы испытания не сожгли.
	ok := akLogin(t, h, f, full())
	require.Equalf(t, http.StatusOK, ok.status, "Ф13-07: испытание не сгорело на отказах формы: %s", ok.body)
}

// TestF13_08_ChallengeIsOneTime — Ф13-08: испытание сгорает первым
// предъявлением при любом исходе; под параллелью проходит ровно одно.
func TestF13_08_ChallengeIsOneTime(t *testing.T) {
	h := newSessionLane(t)
	ref := f302(t, h)
	k := givenAcceptedKey(t, h, h.user.ID)

	// (а) годное дважды.
	f := givenAKForm(t, h)
	c := givenChallenge(t, h, f)
	first := akLoginWith(t, h, f, k, c, webauthntest.AssertionOptions{})
	require.Equalf(t, http.StatusOK, first.status, "Ф13-08 (а): первое — 200: %s", first.body)
	f.cookie = cookieNamed(first.cookies, loginlanehttp.CookieForm)
	f.login = h.csrfFor(t, akKindLogin, f.cookie)
	second := akLoginWith(t, h, f, k, c, webauthntest.AssertionOptions{})
	require.Equal(t, http.StatusUnauthorized, second.status, "Ф13-08 (а): повтор — единый отказ")
	require.Equal(t, ref.body, second.body)

	// (б) негодное, затем годное над тем же.
	f = givenAKForm(t, h)
	c = givenChallenge(t, h, f)
	bad := akLoginWith(t, h, f, k, c, webauthntest.AssertionOptions{ForgeSignature: true})
	require.Equal(t, http.StatusUnauthorized, bad.status)
	good := akLoginWith(t, h, f, k, c, webauthntest.AssertionOptions{})
	require.Equal(t, http.StatusUnauthorized, good.status, "Ф13-08 (б): испытание сгорело на отказе")
	require.Equal(t, ref.body, good.body)

	// (в) новое испытание — 200.
	c = givenChallenge(t, h, f)
	again := akLoginWith(t, h, f, k, c, webauthntest.AssertionOptions{})
	require.Equalf(t, http.StatusOK, again.status, "Ф13-08 (в): %s", again.body)

	// Параллель над одним испытанием — ровно одно проходит (ban #10).
	f = givenAKForm(t, h)
	c = givenChallenge(t, h, f)
	const racers = 4
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		statuses []int
	)
	bodies := make([]map[string]any, racers)
	for i := range bodies {
		bodies[i] = map[string]any{"csrfToken": f.login, "credential": credentialBody(assertOver(t, k, c, webauthntest.AssertionOptions{}), k.handle)}
	}
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(b map[string]any) {
			defer wg.Done()
			st := postStatus(h, akPathLogin, b, f.cookie)
			mu.Lock()
			statuses = append(statuses, st)
			mu.Unlock()
		}(bodies[i])
	}
	wg.Wait()
	ok := 0
	for _, s := range statuses {
		if s == http.StatusOK {
			ok++
		} else {
			require.Equal(t, http.StatusUnauthorized, s)
		}
	}
	require.Equal(t, 1, ok, "Ф13-08: ровно одно предъявление над живым испытанием проходит")
}

// postStatus — POST без require: безопасен из горутины.
func postStatus(h *sessionLane, path string, body any, cookies ...*http.Cookie) int {
	return postStatusVia(h.lane, h.c, path, body, cookies...)
}

// postStatusVia — POST слушателю без require: код ответа либо 0 при отказе
// транспорта; безопасен из горутины (require.FailNow из неё запрещён).
func postStatusVia(l *lane, c *http.Client, path string, body any, cookies ...*http.Cookie) int {
	raw, err := json.Marshal(body)
	if err != nil {
		return 0
	}
	req, err := http.NewRequest(http.MethodPost, l.srv.URL+path, strings.NewReader(string(raw)))
	if err != nil {
		return 0
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range fwd() {
		req.Header.Set(k, v)
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestF13_03_SecondChallengeReplacesTheFirst — Ф13-03.
func TestF13_03_SecondChallengeReplacesTheFirst(t *testing.T) {
	h := newSessionLane(t)
	ref := f302(t, h)
	k := givenAcceptedKey(t, h, h.user.ID)
	f := givenAKForm(t, h)
	c1 := givenChallenge(t, h, f)
	c2 := givenChallenge(t, h, f)
	r1 := akLoginWith(t, h, f, k, c1, webauthntest.AssertionOptions{})
	require.Equal(t, http.StatusUnauthorized, r1.status, "Ф13-03: замещённое испытание — единый отказ")
	require.Equal(t, ref.body, r1.body)
	r2 := akLoginWith(t, h, f, k, c2, webauthntest.AssertionOptions{})
	require.Equalf(t, http.StatusOK, r2.status, "Ф13-03: живое испытание не тронуто: %s", r2.body)
}

// TestF13_10_11_12_LevelComesFromThisAssertionsFlags — Ф13-10…12 (Ф11-03…05):
// один и тот же ключ даёт «2», «3», «2» по флагам утверждения.
func TestF13_10_11_12_LevelComesFromThisAssertionsFlags(t *testing.T) {
	h := newSessionLane(t)
	k := givenAcceptedKey(t, h, h.user.ID)
	cases := []struct {
		name string
		o    webauthntest.AssertionOptions
		want string
	}{
		{"Ф13-10 без проверки", webauthntest.AssertionOptions{}, "2"},
		{"Ф13-11 проверка, без резерва", webauthntest.AssertionOptions{UserVerified: true}, "3"},
		{"Ф13-12 проверка, резерв допускается", webauthntest.AssertionOptions{UserVerified: true, BackupEligible: true}, "2"},
	}
	for _, tc := range cases {
		f := givenAKForm(t, h)
		c := givenChallenge(t, h, f)
		r := akLoginWith(t, h, f, k, c, tc.o)
		require.Equalf(t, http.StatusOK, r.status, "%s: %s", tc.name, r.body)
		var out struct {
			Session struct {
				AssuranceLevel string `json:"assuranceLevel"`
			} `json:"session"`
		}
		require.NoError(t, json.Unmarshal([]byte(r.body), &out))
		require.Equal(t, tc.want, out.Session.AssuranceLevel, tc.name)
		bearer := cookieNamed(r.cookies, loginlanehttp.CookieSession)
		require.Equal(t, tc.want, h.resolve(t, bearer.Value).GetSession().GetAssuranceLevel(), "%s: ответ службы краю о сессии", tc.name)
	}
}

// TestF13_13_17_CopiesReadTheRecordInAKeySession — Ф13-13, Ф13-17 (б): из
// сессии «3», выданной ключом, смена пароля и предъявление пароля называют «3»,
// запись остаётся «3».
func TestF13_13_17_CopiesReadTheRecordInAKeySession(t *testing.T) {
	h := newSessionLane(t)
	k := givenAcceptedKey(t, h, h.user.ID)
	f := givenAKForm(t, h)
	c := givenChallenge(t, h, f)
	r := akLoginWith(t, h, f, k, c, webauthntest.AssertionOptions{UserVerified: true})
	require.Equalf(t, http.StatusOK, r.status, "Дано: сессия «3» выдана ключом: %s", r.body)
	s := laneSession{bearer: cookieNamed(r.cookies, loginlanehttp.CookieSession), form: cookieNamed(r.cookies, loginlanehttp.CookieForm)}

	// (б) предъявление пароля внутри сессии ключа.
	su := h.stepUpPassword(t, s, integrationPassword, h.csrfFor(t, domain.FormStepUp, s.form))
	require.Equalf(t, http.StatusOK, su.status, "Ф13-17 (б): %s", su.body)
	assuranceLevel, sessionLevel := ceremonyLevels(t, su.body)
	require.Equal(t, "3", assuranceLevel, "Ф13-13 (б): церемония называет «3»")
	require.Equal(t, "3", sessionLevel)
	s.bearer = cookieNamed(su.cookies, loginlanehttp.CookieSession)
	row, ok := h.rowByBearer(t, s.bearer.Value)
	require.True(t, ok)
	require.Equal(t, "3", row.level, "Ф13-17 (I): запись не понижена")

	// (а) смена пароля.
	cp := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathPassword, map[string]any{
		"currentPassword": integrationPassword, "newPassword": "a-brand-new-passphrase-13",
		"csrfToken": h.csrfFor(t, domain.FormPassword, s.form),
	}, fwd(), s.bearer, s.form)
	require.Equalf(t, http.StatusOK, cp.status, "Ф13-13 (а): %s", cp.body)
	_, sessionLevel = ceremonyLevels(t, cp.body)
	require.Equal(t, "3", sessionLevel, "Ф13-13 (а): ответ смены пароля — «3»")
}

// TestF13_19_PasswordlessPersonSignsInWithAKey — Ф13-19: личность без пароля
// входит ключом; полоса пароля — единый отказ, побайтово Ф3-02.
func TestF13_19_PasswordlessPersonSignsInWithAKey(t *testing.T) {
	h := newSessionLane(t)
	ref := f302(t, h)
	k := givenAcceptedKey(t, h, h.user.ID)
	tag, err := h.pool.Exec(h.ctx, `DELETE FROM user_login_methods WHERE user_id = $1 AND kind = 'password'`, string(h.user.ID))
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(), "Дано: строка способа «пароль» снята записью (§5 преамбула)")

	f := givenAKForm(t, h)
	c := givenChallenge(t, h, f)
	r := akLoginWith(t, h, f, k, c, webauthntest.AssertionOptions{})
	require.Equalf(t, http.StatusOK, r.status, "Ф13-19 (а): личность без пароля входит ключом: %s", r.body)

	pw := f302(t, h)
	require.Equal(t, ref.body, pw.body, "Ф13-19 (б): отказ полосы пароля побайтово Ф3-02")
}

// TestF13_20_PersonWithoutAKeyRowGetsNoSession — Ф13-20.
func TestF13_20_PersonWithoutAKeyRowGetsNoSession(t *testing.T) {
	h := newSessionLane(t)
	ref := f302(t, h)
	nobody := akKey{auth: webauthntest.New(t, webauthntest.AlgES256), handle: make([]byte, domain.CeremonyHandleBytes)}
	totalBefore, _ := h.sessionsOfPerson(t)
	f := givenAKForm(t, h)
	c := givenChallenge(t, h, f)
	r := akLoginWith(t, h, f, nobody, c, webauthntest.AssertionOptions{})
	require.Equal(t, http.StatusUnauthorized, r.status)
	require.Equal(t, ref.body, r.body, "Ф13-20: единый отказ, побайтово Ф3-02")
	totalAfter, _ := h.sessionsOfPerson(t)
	require.Equal(t, totalBefore, totalAfter, "Ф13-20 (I): новых записей сессии ноль")
}

// TestF13_04_BeginIsAnAttemptBySourceAndAFormRefusalIsNot — Ф13-04.
func TestF13_04_BeginIsAnAttemptBySourceAndAFormRefusalIsNot(t *testing.T) {
	h := newSessionLane(t)
	n := h.limits.SourceAttempts
	require.GreaterOrEqual(t, n, 2, "Дано: профиль даёт границу по источнику")
	f := givenAKForm(t, h)
	// Положительный контроль: n отказов ФОРМЫ окна не исчерпывают.
	for i := 0; i < n; i++ {
		r := akBegin(t, h, f, map[string]any{})
		require.Equal(t, http.StatusBadRequest, r.status)
	}
	for i := 0; i < n; i++ {
		r := akBegin(t, h, f, map[string]any{"csrfToken": f.begin})
		require.Equalf(t, http.StatusOK, r.status, "Ф13-04: begin %d из %d — граница включена: %s", i+1, n, r.body)
	}
	over := akBegin(t, h, f, map[string]any{"csrfToken": f.begin})
	require.Equal(t, http.StatusTooManyRequests, over.status, "Ф13-04: begin сверх границы — 429")
	require.Contains(t, over.body, "TOO_MANY_ATTEMPTS")
	retry, err := strconv.Atoi(over.header.Get("Retry-After"))
	require.NoError(t, err, "Retry-After — секунды")
	require.Positive(t, retry)
}

// TestF13_32_KeyLoginResetsTheAddressCount — Ф13-32: вход ключом обнуляет
// счёт по адресу; близнец без входа — 429 на первой же неверной.
func TestF13_32_KeyLoginResetsTheAddressCount(t *testing.T) {
	series := func(t *testing.T, withKeyLogin bool) []int {
		h := newSessionLane(t)
		nAddr := h.limits.AddressAttempts
		require.GreaterOrEqual(t, nAddr, 2)
		require.GreaterOrEqual(t, h.limits.SourceAttempts, 2*nAddr, "Дано: N_источник ≥ 2·N_адрес")
		k := givenAcceptedKey(t, h, h.user.ID)
		for i := 0; i < nAddr; i++ {
			f302(t, h)
		}
		if withKeyLogin {
			f := givenAKForm(t, h)
			c := givenChallenge(t, h, f)
			r := akLoginWith(t, h, f, k, c, webauthntest.AssertionOptions{})
			require.Equalf(t, http.StatusOK, r.status, "Ф13-32 (а): вход ключом: %s", r.body)
		}
		var got []int
		for i := 0; i < nAddr-1; i++ {
			tok, ck := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
			r := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathLogin,
				map[string]any{"email": h.email, "password": laneWrongPassword, "csrfToken": tok}, fwd(), ck)
			got = append(got, r.status)
		}
		return got
	}
	for _, st := range series(t, true) {
		require.Equal(t, http.StatusUnauthorized, st, "Ф13-32 (а): после входа ключом ни одного 429")
	}
	twin := series(t, false)
	require.Equal(t, http.StatusTooManyRequests, twin[0], "Ф13-32 (б): без входа первая же неверная — 429")
}
