// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// f13_passwordless_login_red_integration_test.go — ПОЛОСА RED фазы Ф13 (вход
// без пароля ключом доступа).
//
// # Опора: отпечатки и их ДОМА — координата без дома не резолвится
//
// ПРИЁМКА (APPROVED, ред.4) — `docs/engineering/acceptance/passwordless-login-with-access-key.md`,
// отпечаток `3f4ee3b1bc845e0ae6af3e6e8fc35b90fc93c544b40d65530f08865f2964599d`.
// Дом: `PRO-Robotech/kaname`, ветка `issue-1282-f13-f7-without-transfer`,
// ЗАКОММИЧЕНА в `ae1338ba` (перемерено: отпечаток блоба `HEAD:<путь>` совпал с
// файлом). В `main` ещё НЕ влита — там `833470…`, ред.3, где жив снятый
// владельцем Ф13-24; опора взята на ред.4, а не на то, что лежит в стволе.
// САНКЦИЯ на ред.4 опубликована СОБЫТИЕМ: `PRO-Robotech/kacho#1282`,
// комментарий `issuecomment-5738095798`, актор `pointpu`, 2026-09-19.
// Запись ревью о событии ещё не знает (блок `event:` допишет `git-operator`):
// действующее одобрение выводится из внешнего события, а не из слова в шапке
// документа (`change-graph.md` §2 «вердикт привязан к отпечатку», §3 «роль без
// события полномочия не даёт»).
//
// ЗАМЫСЕЛ — отпечаток `934b8752ae96900a53f742c3f8d87a8fdff659a3acc78dcda02dba2dad2046a9`,
// путь `docs/engineering/acceptance/passwordless-login-with-access-key-design.md`,
// та же ветка `issue-1282-f13-f7-without-transfer`, но РАБОЧЕЕ ДЕРЕВО и ещё НЕ
// ЗАКОММИЧЕН (`git status` → `??`). До его посадки координата не резолвится
// ничем, кроме рабочей копии, — это названо здесь, а не подразумевается.
//
// # Почему транспорт, а не слой репозитория
//
// use-case входа Ф13 на базе `kaname@dd66b5be` ОТСУТСТВУЕТ (перемерено:
// `grep -rn 'func VerifyAssertion' → verify.go:409` есть, `IssueSession` есть,
// use-case входа — нет). Ссылка на любой ещё не заведённый символ Go (глагол
// входа, поле `IssueInput.AccessKeyID`, вид формы `access-key-login`) сорвала
// бы КОМПИЛЯЦИЮ — а сорванная компиляция это «не выполнилось», не честный
// красный (`change-graph.md` §5). Поэтому пробы бьют в ЕДИНСТВЕННУЮ стабильную
// поверхность, где предмет наблюдаем без ссылки на отсутствующее, — слушатель
// формы Ф3 (`loginlanehttp`): два глагола формы `POST /iam/v1/auth/access-key/
// {begin,login}` (замысел D1, §5 L1) на `dd66b5be` НЕ смонтированы, и мультиплексор
// отвечает на них 404. Каждая проба ниже утверждает НАБЛЮДАЕМОЕ приёмки и красна
// потому, что глагол не смонтирован (use-case входа не существует), а не из-за
// компиляции или сломанной фикстуры.
//
// # Порядок проверок несущий (change-graph.md §5)
//
// Сперва ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ ФИКСТУРЫ — существующий глагол формы отвечает
// как положено (слушатель, mTLS края, база, миграции — исправны). Только ПОСЛЕ
// него — проба возможности (глагол Ф13). Сломанная фикстура так выдаёт себя за
// отсутствующую возможность и не открывает реализацию собственной поломкой.
//
// # Свежие assertions против НАШЕЙ поверхности — без Apache-атрибуции
//
// Кода и векторов ory/kratos эта полоса НЕ переносит: утверждения собраны
// нашим `webauthntest` (аутентификатор Ф7 §8) и бьют в наш HTTP-слушатель.
// Атрибуция Apache относится к ссылочной адаптации ФОРМЫ оркестрации kratos в
// сам use-case входа — это работа полосы реализации (go-implementer, §5 L3),
// не полосы RED.
package loginlanehttp_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

// Адреса двух глаголов формы Ф13 (замысел D1) — ЛИТЕРАЛАМИ: на `dd66b5be`
// констант этих путей в дереве нет by construction, и проба не вправе на них
// ссылаться (иначе не скомпилируется). При посадке L1 пути станут константами
// `loginlanehttp.Path…`, и литералы здесь заменит их импорт.
const (
	pathAccessKeyBegin = "/iam/v1/auth/access-key/begin"
	pathAccessKeyLogin = "/iam/v1/auth/access-key/login"
)

// akProbeRPID / akProbeOrigin — доверяющая сторона и происхождение, которыми
// фикстура собирает утверждение. На `dd66b5be` глагол 404-ит до любой сверки,
// поэтому точные величины на красный не влияют; для зелёного (по посадке L3)
// они обязаны совпасть с профилем Ф7.
const (
	akProbeRPID   = "console.example.invalid"
	akProbeOrigin = "https://console.example.invalid"
)

// b64url — URL-безопасный base64 без дополнения: канон полей WebAuthn в теле
// браузера (форма `credential`).
func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// credentialBody — форма `credential` тела `login` (Ф13-05): браузерный ответ
// аутентификатора, поля base64url.
func credentialBody(as webauthntest.Assertion, userHandle []byte) map[string]any {
	resp := map[string]any{
		"clientDataJSON":    b64url(as.ClientDataJSON),
		"authenticatorData": b64url(as.AuthenticatorData),
		"signature":         b64url(as.Signature),
	}
	if userHandle != nil {
		resp["userHandle"] = b64url(userHandle)
	}
	return map[string]any{
		"id":       b64url(as.CredentialID),
		"rawId":    b64url(as.CredentialID),
		"type":     "public-key",
		"response": resp,
	}
}

// fixtureIsSound — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: существующий глагол формы Ф3
// отвечает как положено. Провал здесь — сломанная фикстура (третья категория,
// «не выполнилось»), а не красный вердикт: об отсутствии use-case Ф13 он не
// говорит ничего.
func fixtureIsSound(t *testing.T, h *sessionLane) {
	t.Helper()
	r := h.lane.do(t, h.c, http.MethodGet, "/iam/v1/auth/csrf?form="+string(domain.FormLogin), nil, nil)
	require.Equalf(t, http.StatusOK, r.status,
		"ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ ФИКСТУРЫ: существующий глагол формы отвечает 200 — если нет, это НЕ красный, а сломанная фикстура: %s", r.body)
}

// akPostRaw — POST без require: безопасен из горутины (require.FailNow из
// не-тестовой горутины запрещён). Возвращает статус, тело и ошибку транспорта.
func akPostRaw(h *sessionLane, path string, body any, cookies ...*http.Cookie) (int, string, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, "", err
	}
	req, err := http.NewRequest(http.MethodPost, h.lane.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range fwd() {
		req.Header.Set(k, v)
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	resp, err := h.c.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b := make([]byte, 0, 512)
	buf := bytes.NewBuffer(b)
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.String(), nil
}

// TestAccessKeyLogin_F1308_D2_ChallengeIsOneTimeAndAtomic — D2 (анти-replay):
// испытание входа однократно; предъявление сжигает его атомарно, каким бы ни
// был исход (Ф13-08); две ГОРУТИНЫ над одним живым испытанием — ровно одна
// проходит, вторая получает единый отказ (модель cross-replica: два соединения
// над одной строкой). Приёмка: Ф13-01/03/08.
//
// КРАСНЫЙ на `dd66b5be`: глагол `begin` не смонтирован (404) — живого испытания
// нет, потому что use-case входа Ф13 отсутствует.
func TestAccessKeyLogin_F1308_D2_ChallengeIsOneTimeAndAtomic(t *testing.T) {
	h := newSessionLane(t)
	fixtureIsSound(t, h)

	// Контекст формы — существующим глаголом (на `dd66b5be` вида
	// `access-key-login` ещё нет; при посадке L1 контекст берётся под ним).
	token, formCk := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)

	// (1) begin выдаёт испытание — Ф13-01. КРАСНЫЙ: глагол не смонтирован.
	begin := h.lane.do(t, h.c, http.MethodPost, pathAccessKeyBegin,
		map[string]any{"csrfToken": token}, fwd(), formCk)
	require.Equalf(t, http.StatusOK, begin.status,
		"D2/Ф13-01: `POST %s` обязан выдать испытание (200) — красный, пока use-case входа Ф13 не смонтирован: %s",
		pathAccessKeyBegin, begin.body)

	// Ниже — контракт, исполняемый по посадке L2/L3; на `dd66b5be` недостижим,
	// проба уже красна выше.
	var out struct {
		PublicKey struct {
			Challenge        string `json:"challenge"`
			UserVerification string `json:"userVerification"`
			AllowCredentials []any  `json:"allowCredentials"`
			RPID             string `json:"rpId"`
			Timeout          int    `json:"timeout"`
		} `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal([]byte(begin.body), &out))
	require.Equal(t, "preferred", out.PublicKey.UserVerification, "D2/Ф13-01: userVerification — литерал Ф7")
	require.NotNil(t, out.PublicKey.AllowCredentials, "D2/Ф13-01: allowCredentials — пустой массив словом, не отсутствие поля")
	require.Empty(t, out.PublicKey.AllowCredentials, "D2/Ф13-01: allowCredentials пуст — обнаружение без имени")
	require.Nil(t, cookieNamed(begin.cookies, loginlanehttp.CookieSession), "D2/Ф13-01: begin не выдаёт сессию")
	challenge, err := base64.RawURLEncoding.DecodeString(out.PublicKey.Challenge)
	require.NoError(t, err)

	// (2) Одно живое на контекст, атомарное сгорание под параллелью: две
	// горутины над ОДНИМ испытанием — ровно одна проходит (Ф13-08, cross-replica).
	auth := webauthntest.New(t, webauthntest.AlgES256)
	userHandle := []byte("uh-" + string(h.user.ID))
	const racers = 2
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		ok, ref int
	)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			as := auth.Assert(t, webauthntest.AssertionOptions{Challenge: challenge, Origin: akProbeOrigin, RPID: akProbeRPID})
			status, _, perr := akPostRaw(h, pathAccessKeyLogin,
				map[string]any{"csrfToken": token, "credential": credentialBody(as, userHandle)}, formCk)
			if perr != nil {
				return
			}
			mu.Lock()
			switch status {
			case http.StatusOK:
				ok++
			case http.StatusUnauthorized:
				ref++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	require.Equal(t, 1, ok, "D2/Ф13-08: ровно одна горутина над живым испытанием проходит")
	require.Equal(t, racers-1, ref, "D2/Ф13-08: остальные — единый отказ (испытание сгорело атомарно, ban #10)")
}

// TestAccessKeyLogin_F1320_D3_UserHandleRequiredAndUnconditional — D3
// (рукоятка): `userHandle` — ОБЯЗАТЕЛЬНОЕ поле формы (нет → 400 ДО сверки, отказ
// формы Ф3-05, а не единый отказ входа); сравнение с рукояткой строки —
// БЕЗУСЛОВНОЕ (охрана присутствия Ф7 не наследуется); несовпавшая рукоятка →
// единый отказ входа. Приёмка: Ф13-07, Ф13-20, Ф13-06 «з».
//
// КРАСНЫЙ на `dd66b5be`: глагол `login` не смонтирован (404) — ни отказа формы,
// ни единого отказа входа: use-case входа Ф13 отсутствует.
func TestAccessKeyLogin_F1320_D3_UserHandleRequiredAndUnconditional(t *testing.T) {
	h := newSessionLane(t)
	fixtureIsSound(t, h)
	token, formCk := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
	auth := webauthntest.New(t, webauthntest.AlgES256)
	as := auth.Assert(t, webauthntest.AssertionOptions{Challenge: []byte("challenge-of-the-probe-0001"), Origin: akProbeOrigin, RPID: akProbeRPID})

	// (а) userHandle ОТСУТСТВУЕТ → 400 отказ формы, ДО сверки байтов (Ф3-05).
	noHandle := h.lane.do(t, h.c, http.MethodPost, pathAccessKeyLogin,
		map[string]any{"csrfToken": token, "credential": credentialBody(as, nil)}, fwd(), formCk)
	require.Equalf(t, http.StatusBadRequest, noHandle.status,
		"D3/Ф13-07: отсутствующий userHandle — отказ формы 400 ДО сверки — красный, пока глагол login не смонтирован: %s", noHandle.body)
	require.Contains(t, noHandle.body, "userHandle", "D3/Ф13-07: отказ формы называет поле")

	// (б) userHandle несовпавший → ЕДИНЫЙ отказ входа 401 (безусловная сверка,
	// Ф13-20/Ф13-06 «з»), а не «пропуск».
	mismatch := h.lane.do(t, h.c, http.MethodPost, pathAccessKeyLogin,
		map[string]any{"csrfToken": token, "credential": credentialBody(as, []byte("some-other-persons-handle"))}, fwd(), formCk)
	require.Equalf(t, http.StatusUnauthorized, mismatch.status,
		"D3/Ф13-20: несовпавшая рукоятка — единый отказ входа 401 (безусловная сверка): %s", mismatch.body)
}

// TestAccessKeyLogin_F1306_D7_UnifiedRefusalIsBytewiseEqualToF302 — D7 (единый
// отказ): отказ входа ключом ПОБАЙТОВО равен единому отказу входа паролём
// Ф3-02 — `UNAUTHENTICATED`/401, тело `{"code":16,"message":"authentication
// failed","details":[]}` (детали — пустой массив), без `Set-Cookie`. Приёмка:
// Ф13-06 (одиннадцать ветвей), Р7.
//
// Опорное значение Ф3-02 захвачено ЖИВЫМ входом паролём с неверным паролем —
// это положительный производитель отказа (не литерал): сравнивать надо с тем,
// что край действительно отдаёт.
//
// КРАСНЫЙ на `dd66b5be`: глагол `login` не смонтирован (404) — отказ ключом
// не равен Ф3-02.
func TestAccessKeyLogin_F1306_D7_UnifiedRefusalIsBytewiseEqualToF302(t *testing.T) {
	h := newSessionLane(t)
	fixtureIsSound(t, h)

	// Опорный отказ Ф3-02: вход паролём с неверным паролем.
	token, formCk := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
	f302 := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathLogin,
		map[string]any{"email": h.email, "password": laneWrongPassword, "csrfToken": token}, fwd(), formCk)
	require.Equalf(t, http.StatusUnauthorized, f302.status,
		"ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: единый отказ Ф3-02 (401) существует и захвачен: %s", f302.body)
	require.Contains(t, f302.body, "authentication failed", "опорный отказ Ф3-02 несёт текст семейства")
	require.Nil(t, cookieNamed(f302.cookies, loginlanehttp.CookieSession), "опорный отказ Ф3-02 без Set-Cookie")

	// Отказ входа КЛЮЧОМ — ветвь (а) Ф13-06: подпись не сверяется (форсированная).
	tok2, form2 := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
	auth := webauthntest.New(t, webauthntest.AlgES256)
	forged := auth.Assert(t, webauthntest.AssertionOptions{Challenge: []byte("challenge-of-the-probe-0002"), Origin: akProbeOrigin, RPID: akProbeRPID, ForgeSignature: true})
	keyRefusal := h.lane.do(t, h.c, http.MethodPost, pathAccessKeyLogin,
		map[string]any{"csrfToken": tok2, "credential": credentialBody(forged, []byte("uh-"+string(h.user.ID)))}, fwd(), form2)

	require.Equalf(t, http.StatusUnauthorized, keyRefusal.status,
		"D7/Ф13-06 «а»: отказ входа ключом — 401 — красный, пока глагол login не смонтирован: %s", keyRefusal.body)
	require.Equal(t, f302.body, keyRefusal.body,
		"D7/Р7: тело отказа входа ключом ПОБАЙТОВО равно Ф3-02 — один текст на семейство")
	require.Nil(t, cookieNamed(keyRefusal.cookies, loginlanehttp.CookieSession),
		"D7/Ф13-06: единый отказ без Set-Cookie")
}

// TestAccessKeyLogin_F1305_D10_SessionIssuedEventCarriesAccessKeyID — D10
// (событие): успешный вход ключом порождает событие `iam.session.issued` с
// `methods:["webauthn"]` и `access_key_id` формы `ak-…` в PAYLOAD; запись сессии
// (`domain.HumanSession`) при этом НЕ расширяется (§7 инв.11); пустой
// `AccessKeyID` → ключа в payload нет. Приёмка: Ф13-05, Р10.
//
// Наблюдаемое — строка `kaname.audit_outbox` с `event_payload->>'access_key_id'`.
// Положительный производитель события (вход паролём) доказывает, что запрос к
// выборке событий работает и что событие БЕЗ ключа существует — иначе
// отрицание «ключа в событии нет» зеленело бы на пустой выборке (gate-authoring §6).
//
// КРАСНЫЙ на `dd66b5be`: глагол `login` не смонтирован (404) — события входа
// ключом с `access_key_id` не возникает.
func TestAccessKeyLogin_F1305_D10_SessionIssuedEventCarriesAccessKeyID(t *testing.T) {
	h := newSessionLane(t)
	fixtureIsSound(t, h)

	// Положительный производитель: вход паролём эмитит iam.session.issued БЕЗ
	// access_key_id (методы — ["password"]).
	_ = h.login(t, integrationPassword)
	var pwEvents int
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT count(*) FROM audit_outbox
		   WHERE event_type = 'iam.session.issued'
		     AND jsonb_exists(event_payload, 'methods')`).Scan(&pwEvents))
	require.GreaterOrEqualf(t, pwEvents, 1,
		"ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: вход паролём эмитит iam.session.issued (выборка событий работает); нашлось %d", pwEvents)
	var pwWithKey int
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT count(*) FROM audit_outbox
		   WHERE event_type = 'iam.session.issued'
		     AND jsonb_exists(event_payload, 'access_key_id')`).Scan(&pwWithKey))
	require.Equal(t, 0, pwWithKey, "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: событие входа паролём НЕ несёт access_key_id (sentinel чист)")

	// Проба возможности: вход КЛЮЧОМ. Красный: 404 (глагол не смонтирован).
	token, formCk := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
	auth := webauthntest.New(t, webauthntest.AlgES256)
	as := auth.Assert(t, webauthntest.AssertionOptions{Challenge: []byte("challenge-of-the-probe-0003"), Origin: akProbeOrigin, RPID: akProbeRPID, UserVerified: true})
	login := h.lane.do(t, h.c, http.MethodPost, pathAccessKeyLogin,
		map[string]any{"csrfToken": token, "credential": credentialBody(as, []byte("uh-"+string(h.user.ID)))}, fwd(), formCk)
	require.Equalf(t, http.StatusOK, login.status,
		"D10/Ф13-05: вход ключом выдаёт сессию (200) — красный, пока глагол login не смонтирован: %s", login.body)

	// По посадке L3 наблюдаемо: событие iam.session.issued с webauthn + ak-…,
	// а запись сессии колонки под ключ не завела.
	var akEvents int
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT count(*) FROM audit_outbox
		   WHERE event_type = 'iam.session.issued'
		     AND event_payload->'methods' @> '"webauthn"'
		     AND event_payload->>'access_key_id' LIKE 'ak-%'`).Scan(&akEvents))
	require.Equal(t, 1, akEvents, "D10/Р10: событие входа ключом несёт methods:[webauthn] и access_key_id формы ak-…")

	// §7 инв.11: запись сессии НЕ расширена — в таблице сессий нет колонки под ключ.
	var sessionKeyCols int
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT count(*) FROM information_schema.columns
		   WHERE table_schema = 'kaname' AND table_name = 'human_sessions'
		     AND column_name IN ('access_key_id','access_key')`).Scan(&sessionKeyCols))
	require.Equal(t, 0, sessionKeyCols, "D10/§7 инв.11: состав записи сессии не расширяется (ключ — только в событии)")
}

// TestAccessKeyLogin_F1305_D12_LoginVerifiesAssertionThroughF7 — D12 (сверка):
// вход сверяет утверждение ТЕМ ЖЕ существом Ф7 (`webauthnverify.VerifyAssertion`)
// — форсированная подпись → единый отказ входа; годное утверждение над верным
// испытанием → сессия. Это поведенческое лицо инварианта «вход — второй
// ВЫЗЫВАЮЩИЙ проверяющего»; статический гейт единственности (1 объявление, 2
// вызывающих, Ф13-31) — предмет автора кода, не этой полосы. Приёмка: Ф13-05,
// Ф13-06 «а», Р13.
//
// КРАСНЫЙ на `dd66b5be`: глагол `login` не смонтирован (404) — ни отказа на
// негодной подписи, ни сессии на годной: сверки во входе нет, use-case отсутствует.
func TestAccessKeyLogin_F1305_D12_LoginVerifiesAssertionThroughF7(t *testing.T) {
	h := newSessionLane(t)
	fixtureIsSound(t, h)
	auth := webauthntest.New(t, webauthntest.AlgES256)
	userHandle := []byte("uh-" + string(h.user.ID))

	// Негодная подпись → единый отказ входа (проверяющий отверг). Красный: 404.
	tokBad, formBad := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
	forged := auth.Assert(t, webauthntest.AssertionOptions{Challenge: []byte("challenge-of-the-probe-0004"), Origin: akProbeOrigin, RPID: akProbeRPID, ForgeSignature: true})
	bad := h.lane.do(t, h.c, http.MethodPost, pathAccessKeyLogin,
		map[string]any{"csrfToken": tokBad, "credential": credentialBody(forged, userHandle)}, fwd(), formBad)
	require.Equalf(t, http.StatusUnauthorized, bad.status,
		"D12/Ф13-06 «а»: негодная подпись — единый отказ входа (сверка Ф7 отвергла) — красный, пока глагол login не смонтирован: %s", bad.body)

	// Годное утверждение → сессия (проверяющий принял, выдача Ф1).
	tokOK, formOK := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
	good := auth.Assert(t, webauthntest.AssertionOptions{Challenge: []byte("challenge-of-the-probe-0005"), Origin: akProbeOrigin, RPID: akProbeRPID, UserVerified: true})
	ok := h.lane.do(t, h.c, http.MethodPost, pathAccessKeyLogin,
		map[string]any{"csrfToken": tokOK, "credential": credentialBody(good, userHandle)}, fwd(), formOK)
	require.Equalf(t, http.StatusOK, ok.status,
		"D12/Ф13-05: годное утверждение над верным испытанием — сессия (сверка Ф7 приняла): %s", ok.body)
	require.NotNil(t, cookieNamed(ok.cookies, loginlanehttp.CookieSession), "D12: сессия выдана носителем")
}

// TestAccessKeyLogin_F1310_F1311_AAL_LevelFromAssertionFlagsNotConstant — AAL:
// уровень сессии вычисляет правило Ф11 над `{webauthn}` по флагам ИМЕННО ЭТОГО
// утверждения, а не константой полосы. Ф11-03: проверка пользователя НЕ
// выполнена, резерв не допускается → «2» (Ф13-10); Ф11-04: проверка выполнена →
// «3» (Ф13-11). Различие ровно в одном флаге — уровень обязан различаться.
// Приёмка: Ф13-05, Ф13-10, Ф13-11.
//
// КРАСНЫЙ на `dd66b5be`: глагол `login` не смонтирован (404) — уровня сессии
// ключом нет вовсе.
func TestAccessKeyLogin_F1310_F1311_AAL_LevelFromAssertionFlagsNotConstant(t *testing.T) {
	h := newSessionLane(t)
	fixtureIsSound(t, h)
	auth := webauthntest.New(t, webauthntest.AlgES256)
	userHandle := []byte("uh-" + string(h.user.ID))

	level := func(userVerified bool, challenge string) (int, string) {
		token, formCk := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
		as := auth.Assert(t, webauthntest.AssertionOptions{Challenge: []byte(challenge), Origin: akProbeOrigin, RPID: akProbeRPID, UserVerified: userVerified})
		r := h.lane.do(t, h.c, http.MethodPost, pathAccessKeyLogin,
			map[string]any{"csrfToken": token, "credential": credentialBody(as, userHandle)}, fwd(), formCk)
		var out struct {
			Session struct {
				AssuranceLevel string `json:"assuranceLevel"`
			} `json:"session"`
		}
		_ = json.Unmarshal([]byte(r.body), &out)
		return r.status, out.Session.AssuranceLevel
	}

	// Ф11-03: userVerified=false → «2». Красный: 404.
	st2, lvl2 := level(false, "challenge-of-the-probe-0006")
	require.Equalf(t, http.StatusOK, st2,
		"AAL/Ф13-10: вход ключом без проверки пользователя выдаёт сессию — красный, пока глагол login не смонтирован (уровень получен: %q)", lvl2)
	require.Equal(t, "2", lvl2, "AAL/Ф11-03: проверка не выполнена, резерв не допускается → уровень «2»")

	// Ф11-04: userVerified=true → «3». Пара — положительный контроль: без неё
	// «2» было бы неотличимо от «полоса всегда отвечает константой».
	st3, lvl3 := level(true, "challenge-of-the-probe-0007")
	require.Equal(t, http.StatusOK, st3, "AAL/Ф13-11: вход ключом с проверкой пользователя выдаёт сессию")
	require.Equal(t, "3", lvl3, "AAL/Ф11-04: проверка выполнена → уровень «3»")
	require.NotEqual(t, lvl2, lvl3, "AAL: уровень — по флагам ЭТОГО утверждения, не константа полосы")
}
