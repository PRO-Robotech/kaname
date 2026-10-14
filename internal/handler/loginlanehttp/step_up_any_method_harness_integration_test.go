// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// step_up_any_method_harness_integration_test.go — СТЕНД проб приёмки
// `docs/engineering/acceptance/step-up-with-any-enrolled-method.md` (задача
// PRO-Robotech/kaname#827, редакция 3, отпечаток 35224856…; сценарии SUA-01…80)
// на ПРОВОДЕ полосы формы: слушатель над настоящими глаголами и настоящими
// адаптерами базы (стенд `newSessionLaneWith`), часы глаголов управляемые.
//
// # Ступени пробы и их слова
//
//  1. МИР — посев (§3 приёмки, таблица посевов) заведён глаголами продукта и
//     прочитан обратно. Отказ — «НЕ-ВЫПОЛНИЛОСЬ(фикстура)»: сломан вопрос, а не
//     ответ.
//  2. ВОЗМОЖНОСТЬ — предмет приёмки существует на проводе: путь выдачи
//     испытания повышения смонтирован, способ `webauthn` разбирается, ключ
//     ответа состояния объявлен. Отсутствие — «ЧЕСТНЫЙ-КРАСНЫЙ»: предмета нет.
//     Ступень стоит ПОСЛЕ мира: сломанная фикстура не выдаёт себя за отсутствие
//     предмета.
//  3. ПРЕДМЕТ — утверждения сценария; отказ несёт ID сценария.
//
// # Почему пути, виды формы, тексты и ключи — литералами
//
// Проба обязана КОМПИЛИРОВАТЬСЯ на ревизии без предмета: ссылка на не заведённую
// константу, тип или поле сорвала бы сборку пакета, а сорванная сборка — «не
// выполнилось», не красный (`change-graph.md` §5). Литералы наблюдают ровно то,
// что видит клиент полосы. Признак формы нового вида считается той же
// свёрткой, которой его судит слушатель (`humansession.FormToken`), а не
// глаголом выдачи признака: вид, которого нет в перечне, глагол выдачи не
// выдаёт, и проба спросила бы не то.
//
// # Что стенд задаёт сверх `newSessionLaneWith`
//
//   - настоящие `enroll`, `confirm`, `remove`, `backup-codes` и снятие своих
//     сессий (`end-others`) над теми же зависимостями второго фактора;
//   - одни управляемые часы на вход, вход ключом, церемонию и снятие сессий
//     (`suaClock`): ступень кода по времени, срок испытания и окно свежести
//     двигает проба, ожидания нет (§3 приёмки: «ось времени — управляемые часы»);
//   - привязку ключей стенда с перечнем происхождений «никого» (посев «выкл»).
//
// # Провязка реализации — шаг полосы реализации
//
// Новый глагол выдачи испытания и ветвь `webauthn` церемонии реализация
// провязывает в ЭТОТ стенд тем же составом, что корень композиции: хранилище
// ключей и привязка — те же, что у полосы входа ключом (`akDeps` стенда,
// привязка — `sessionLaneOptions.keyBinding`). До провязки глагол стенда —
// дублёр (`stubLane`), и проба краснеет: дублёр отвечает нулевым исходом.
package loginlanehttp_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 задаёт HMAC-SHA1; оракул кода, не защита
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

// Пути, вид формы, тексты отказов и причины — ДОСЛОВНО из приёмки (Р1, Р2, Р3,
// Р5, Р7).
const (
	suaPathBegin  = "/iam/v1/auth/step-up/access-key/begin"
	suaKindBegin  = "step-up-access-key-begin"
	suaPathStepUp = "/iam/v1/auth/step-up"
	suaPathStatus = "/iam/v1/auth/second-factor"

	suaTextAuthFailed      = "authentication failed"
	suaBodyAuthFailed      = `{"code":16,"message":"authentication failed","details":[]}`
	suaReasonNotIssued     = "CHALLENGE_NOT_ISSUED"
	suaTextNotIssued       = "step-up challenge was not issued: begin step-up again"
	suaReasonPresented     = "CHALLENGE_ALREADY_PRESENTED"
	suaTextPresented       = "step-up challenge was already presented: begin step-up again"
	suaReasonExpired       = "CHALLENGE_EXPIRED"
	suaTextExpired         = "step-up challenge expired: begin step-up again"
	suaReasonNoKey         = "ACCESS_KEY_NOT_REGISTERED"
	suaTextNoKey           = "no access key is registered: register an access key first"
	suaReasonKeysOff       = "ACCESS_KEYS_DISABLED"
	suaTextKeysOff         = "access keys are turned off on this installation"
	suaReasonNotEnrolled   = "SECOND_FACTOR_NOT_ENROLLED"
	suaTextNotEnrolled     = "second factor is not enrolled"
	suaReasonTooMany       = "TOO_MANY_ATTEMPTS"
	suaTextTooMany         = "too many attempts; try again later"
	suaTextMethodVocabular = "Illegal argument method: must be one of password|totp|lookup_secret|webauthn"
)

// suaClock — управляемые часы стенда (только вперёд).
type suaClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *suaClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *suaClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// nextStep — часы на одну ступень кода вперёд; ступень после сдвига. Каждый код
// пробы — на своей ступени: повтор ступени суждён как повтор (Ф12 Р7), и проба
// судила бы его, а не предмет.
func (c *suaClock) nextStep() int64 {
	c.Advance(totpverify.Period)
	return totpverify.StepAt(c.Now())
}

// suaVerbs — глаголы стенда плюс настоящие глаголы второго фактора и снятия
// своих сессий над теми же зависимостями.
type suaVerbs struct {
	sessionVerbs
	enroll    *humansession.EnrollSecondFactorUseCase
	confirm   *humansession.ConfirmSecondFactorUseCase
	remove    *humansession.RemoveSecondFactorUseCase
	regen     *humansession.RegenerateBackupCodesUseCase
	endOthers *humansession.EndOtherOwnSessionsUseCase
}

func (v suaVerbs) EnrollSecondFactor(ctx context.Context, in humansession.EnrollInput) (humansession.EnrollOutput, error) {
	return v.enroll.Execute(ctx, in)
}

func (v suaVerbs) ConfirmSecondFactor(ctx context.Context, in humansession.ConfirmInput) (humansession.ConfirmOutput, error) {
	return v.confirm.Execute(ctx, in)
}

func (v suaVerbs) RemoveSecondFactor(ctx context.Context, in humansession.RemoveSecondFactorInput) (humansession.RemoveSecondFactorOutput, error) {
	return v.remove.Execute(ctx, in)
}

func (v suaVerbs) RegenerateBackupCodes(ctx context.Context, in humansession.RegenerateBackupCodesInput) (humansession.RegenerateBackupCodesOutput, error) {
	return v.regen.Execute(ctx, in)
}

func (v suaVerbs) EndOtherOwnSessions(ctx context.Context, in humansession.EndOtherOwnSessionsInput) (humansession.EndOtherOwnSessionsOutput, error) {
	return v.endOthers.Execute(ctx, in)
}

// suaOptions — величины стенда SUA.
type suaOptions struct {
	// keysOff — посев «выкл»: перечень происхождений «никого» (Ф7 Р2).
	keysOff bool
	// observer — приёмник исходов церемонии; nil — молчащий.
	observer humansession.Observer
	// stepUpKeys — шов хранилища ветви ключа (замысел §2.3); nil — адаптер.
	stepUpKeys func(humansession.StepUpChallengeStore) humansession.StepUpChallengeStore
}

// suaStand — стенд проб SUA.
type suaStand struct {
	*sessionLane
	clock *suaClock
}

func newSUAStand(t *testing.T) *suaStand { return newSUAStandWith(t, suaOptions{}) }

func newSUAStandWith(t *testing.T, o suaOptions) *suaStand {
	t.Helper()
	clock := &suaClock{now: time.Now().UTC().Truncate(time.Microsecond)}
	opts := sessionLaneOptions{
		loginNow:         clock.Now,
		ceremonyNow:      clock.Now,
		ceremonyObserver: o.observer,
		stepUpKeys:       o.stepUpKeys,
		verbs: func(v sessionVerbs, d humansession.SecondFactorDeps) loginlanehttp.Lane {
			enroll, err := humansession.NewEnrollSecondFactorUseCase(d)
			require.NoError(t, err)
			confirm, err := humansession.NewConfirmSecondFactorUseCase(d)
			require.NoError(t, err)
			remove, err := humansession.NewRemoveSecondFactorUseCase(d)
			require.NoError(t, err)
			regen, err := humansession.NewRegenerateBackupCodesUseCase(d)
			require.NoError(t, err)
			endOthers, err := humansession.NewEndOtherOwnSessionsUseCase(humansession.OwnSessionsDeps{
				Store: d.Store, Freshness: laneFreshness, Observer: humansession.NopObserver{}, Now: clock.Now, Logger: d.Logger,
			})
			require.NoError(t, err)
			return suaVerbs{sessionVerbs: v, enroll: enroll, confirm: confirm, remove: remove, regen: regen, endOthers: endOthers}
		},
	}
	if o.keysOff {
		b := laneKeyBinding()
		b.Origins = []string{}
		opts.keyBinding = &b
	}
	return &suaStand{sessionLane: newSessionLaneWith(t, opts), clock: clock}
}

// suaPerson — человек посева: личность, адрес, и что у него заведено.
type suaPerson struct {
	user  domain.UserID
	email string
	// код по времени и набор (П-к): секрет base32 из ответа `enroll` и коды
	// набора из ответа `confirm`.
	secret string
	codes  []string
	// ключи (П-кл, П-ккл, П-ккл2, П-л).
	keys []akKey
}

// person — человек с паролем (П-п) регистрацией полосы Ф4; адрес — свой у
// каждого человека пробы.
func (h *suaStand) person(t *testing.T, tag string) *suaPerson {
	t.Helper()
	email := "sua-" + tag + "-" + strings.ToLower(ids.NewID("tst")[3:11]) + "@example.invalid"
	out, err := h.register.Execute(h.ctx, registration.Input{Email: email, Password: integrationPassword, Source: fwd()[loginlanehttp.HeaderForwardedFor]})
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): регистрация %s", email)
	require.NotEmpty(t, out.View.User.ID, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): регистрация назвала личность")
	return &suaPerson{user: out.View.User.ID, email: email}
}

// login — вход паролем человека p; сессия «1» проверена до предмета.
func (h *suaStand) login(t *testing.T, p *suaPerson) laneSession {
	t.Helper()
	tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
	r := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathLogin,
		map[string]any{"email": p.email, "password": integrationPassword, "csrfToken": tok}, fwd(), ctxCk)
	require.Equalf(t, http.StatusOK, r.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): вход паролем %s: %s", p.email, r.body)
	s := laneSession{bearer: cookieNamed(r.cookies, loginlanehttp.CookieSession), form: cookieNamed(r.cookies, loginlanehttp.CookieForm)}
	require.NotNil(t, s.bearer, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): вход пишет носитель")
	require.NotNil(t, s.form, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): выдача сменяет контекст формы")
	require.Equal(t, "1", h.levelOf(t, s), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): вход паролем — сессия «1»")
	return s
}

// keyLogin — НАСТОЯЩИЙ вход ключом k (Ф13); сессия «2» проверена до предмета.
func (h *suaStand) keyLogin(t *testing.T, k akKey, o webauthntest.AssertionOptions) laneSession {
	t.Helper()
	f := givenAKForm(t, h.sessionLane)
	c := givenChallenge(t, h.sessionLane, f)
	r := akLoginWith(t, h.sessionLane, f, k, c, o)
	require.Equalf(t, http.StatusOK, r.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): вход ключом: %s", r.body)
	s := laneSession{bearer: cookieNamed(r.cookies, loginlanehttp.CookieSession), form: cookieNamed(r.cookies, loginlanehttp.CookieForm)}
	require.NotNil(t, s.bearer, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): вход ключом пишет носитель")
	return s
}

// levelOf — уровень записи сессии по носителю, из базы.
func (h *suaStand) levelOf(t *testing.T, s laneSession) string {
	t.Helper()
	row, ok := h.rowByBearer(t, s.bearer.Value)
	require.True(t, ok, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): запись сессии найдена по носителю")
	return row.level
}

// rowEnded — запись сессии s снята (по носителю, которым её держит браузер).
func (h *suaStand) rowEnded(t *testing.T, s laneSession) bool {
	t.Helper()
	row, ok := h.rowByBearer(t, s.bearer.Value)
	require.True(t, ok, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): запись сессии найдена по носителю")
	return row.ended
}

// withCode — П-к: заведение и подтверждение кода НАСТОЯЩИМИ глаголами в
// свежей сессии человека; секрет и набор — в окружении пробы.
func (h *suaStand) withCode(t *testing.T, p *suaPerson) {
	t.Helper()
	s := h.login(t, p)
	r := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathSecondFactorEnroll,
		map[string]any{"csrfToken": h.csrfFor(t, domain.FormSecondFactor, s.form)}, fwd(), s.bearer, s.form)
	require.Equalf(t, http.StatusOK, r.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): enroll: %s", r.body)
	var en struct {
		Secret string `json:"secret"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &en), r.body)
	require.NotEmpty(t, en.Secret, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): ответ enroll несёт секрет")
	secret := en.Secret
	step := h.clock.nextStep()
	r = h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathSecondFactorConfirm,
		map[string]any{"code": suaCodeAt(t, secret, step), "csrfToken": h.csrfFor(t, domain.FormSecondFactor, s.form)}, fwd(), s.bearer, s.form)
	require.Equalf(t, http.StatusOK, r.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): confirm первым кодом: %s", r.body)
	var cf struct {
		BackupCodes []string `json:"backupCodes"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &cf), r.body)
	require.Len(t, cf.BackupCodes, passwordverify.BackupCodeCount, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): confirm выдал набор")
	p.secret, p.codes = secret, cf.BackupCodes
}

// withKey — ключ человека p писателем продукта (Ф7-01, `givenAcceptedKey`).
// Счётчик подписи аутентификатора — положительный: утверждение несёт
// растущий счётчик, и записанный после предъявления больше нуля (SUA-80).
func (h *suaStand) withKey(t *testing.T, p *suaPerson) akKey {
	t.Helper()
	k := givenAcceptedKey(t, h.sessionLane, p.user)
	k.auth.SetCounter(7)
	p.keys = append(p.keys, k)
	return k
}

// keyOnly — П-л: строка пароля снята посевом формы «после переноса».
func (h *suaStand) keyOnly(t *testing.T, p *suaPerson) {
	t.Helper()
	seedPasswordless(t, h.ctx, h.pool, p.user)
}

// totpNow — код текущей (новой) ступени часов стенда.
func (h *suaStand) totpNow(t *testing.T, p *suaPerson) string {
	t.Helper()
	require.NotEmpty(t, p.secret, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): у человека заведён код")
	return suaCodeAt(t, p.secret, h.clock.nextStep())
}

// suaCodeAt — код ступени step от секрета base32, посчитанный пробой по
// RFC 6238 независимо от проверяющего: оракул, а не вызов прод-функции.
func suaCodeAt(t *testing.T, secret string, step int64) string {
	t.Helper()
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): секрет — base32 без дополнения")
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) // #nosec G115 -- ступень неотрицательна
	mac := hmac.New(sha1.New, raw)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", bin%1000000)
}

// suaWrongCode — код формы `totp`, не совпадающий ни с одной ступенью вокруг
// текущей ступени часов стенда (окно ±Skew плюс запас).
func (h *suaStand) suaWrongCode(t *testing.T, p *suaPerson) string {
	t.Helper()
	at := totpverify.StepAt(h.clock.Now())
	near := map[string]bool{}
	for d := int64(-4); d <= 64; d++ {
		near[suaCodeAt(t, p.secret, at+d)] = true
	}
	for n := 0; n < 1000000; n += 7919 {
		if c := fmt.Sprintf("%06d", n); !near[c] {
			return c
		}
	}
	t.Fatal("НЕ-ВЫПОЛНИЛОСЬ(фикстура): не найден код вне окна")
	return ""
}

// stepUpCode — церемония кодом (`totp` либо `lookup_secret`).
func (h *suaStand) stepUpCode(t *testing.T, s laneSession, method, code string) reply {
	t.Helper()
	return h.lane.do(t, h.c, http.MethodPost, suaPathStepUp,
		map[string]any{"method": method, "code": code, "csrfToken": h.csrfFor(t, domain.FormStepUp, s.form)}, fwd(), s.bearer, s.form)
}

// raiseByCode — сессия «2» повышением кодом; новый носитель.
func (h *suaStand) raiseByCode(t *testing.T, p *suaPerson, s laneSession) laneSession {
	t.Helper()
	r := h.stepUpCode(t, s, "totp", h.totpNow(t, p))
	require.Equalf(t, http.StatusOK, r.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): повышение кодом: %s", r.body)
	out := laneSession{bearer: cookieNamed(r.cookies, loginlanehttp.CookieSession), form: s.form}
	require.NotNil(t, out.bearer, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): повышение перевыпускает носитель")
	require.Equal(t, "2", h.levelOf(t, out), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): после повышения кодом — «2»")
	return out
}

// begin — выдача испытания повышения ключом (Р2) под сессией s.
func (h *suaStand) begin(t *testing.T, s laneSession) reply {
	t.Helper()
	return h.lane.do(t, h.c, http.MethodPost, suaPathBegin,
		map[string]any{"csrfToken": humansession.FormToken(s.form.Value, domain.FormKind(suaKindBegin))}, fwd(), s.bearer, s.form)
}

// requireBeginMounted — ступень ВОЗМОЖНОСТИ: путь выдачи смонтирован.
func requireBeginMounted(t *testing.T, id string, r reply) {
	t.Helper()
	if r.status == http.StatusNotFound || r.status == http.StatusMethodNotAllowed {
		t.Fatalf("ЧЕСТНЫЙ-КРАСНЫЙ %s: выдачи испытания повышения ключом нет — POST %s отвечает %d: %q",
			id, suaPathBegin, r.status, r.body)
	}
}

// suaChallenge — выданное испытание: байты и перечень удостоверений.
type suaChallenge struct {
	raw   []byte
	allow []string
}

// issued — разбор ответа выдачи (Р2): 200, испытание, перечень удостоверений.
func issued(t *testing.T, id string, r reply) suaChallenge {
	t.Helper()
	requireBeginMounted(t, id, r)
	require.Equalf(t, http.StatusOK, r.status, "%s: выдача испытания повышения — 200: %s", id, r.body)
	var out struct {
		PublicKey struct {
			Challenge        string `json:"challenge"`
			RPID             string `json:"rpId"`
			AllowCredentials []struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &out), "%s: тело выдачи разбирается: %s", id, r.body)
	require.NotEmpty(t, out.PublicKey.Challenge, "%s: испытание выдано: %s", id, r.body)
	raw, err := b64urlDecode(out.PublicKey.Challenge)
	require.NoError(t, err, "%s: испытание — base64url без дополнения", id)
	c := suaChallenge{raw: raw}
	for _, a := range out.PublicKey.AllowCredentials {
		require.Equal(t, "public-key", a.Type, "%s: тип удостоверения перечня", id)
		c.allow = append(c.allow, a.ID)
	}
	return c
}

// challenge — выдача, утверждённая как 200, для шага «Дано»/«Когда».
func (h *suaStand) challenge(t *testing.T, id string, s laneSession) suaChallenge {
	t.Helper()
	return issued(t, id, h.begin(t, s))
}

// stepUpKey — церемония ключом над испытанием c: утверждение ключа k.
func (h *suaStand) stepUpKey(t *testing.T, s laneSession, k akKey, c []byte, o webauthntest.AssertionOptions) reply {
	t.Helper()
	as := assertOver(t, k, c, o)
	return h.lane.do(t, h.c, http.MethodPost, suaPathStepUp,
		map[string]any{"method": "webauthn", "credential": credentialBody(as, k.handle), "csrfToken": h.csrfFor(t, domain.FormStepUp, s.form)},
		fwd(), s.bearer, s.form)
}

// strong — флаги «2» по умолчанию сценариев: UP|UV|BE.
func strong() webauthntest.AssertionOptions {
	return webauthntest.AssertionOptions{UserVerified: true, BackupEligible: true}
}

// rotated — носитель ответа (после успешного предъявления).
func rotated(t *testing.T, id string, r reply, s laneSession) laneSession {
	t.Helper()
	b := cookieNamed(r.cookies, loginlanehttp.CookieSession)
	require.NotNil(t, b, "%s: успешное предъявление перевыпускает носитель (Ф11 Р5)", id)
	return laneSession{bearer: b, form: s.form}
}

// status — чтение состояния второго фактора (Р6) телом ответа.
func (h *suaStand) status(t *testing.T, s laneSession) map[string]any {
	t.Helper()
	r := h.lane.do(t, h.c, http.MethodGet, suaPathStatus, nil, fwd(), s.bearer, s.form)
	require.Equalf(t, http.StatusOK, r.status, "чтение состояния второго фактора — 200: %s", r.body)
	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(r.body), &out), r.body)
	return out
}

// field — значение по пути `a.b` в ответе состояния; ok=false — ключа нет.
func field(m map[string]any, path string) (any, bool) {
	var cur any = m
	for _, part := range strings.Split(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = obj[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// requireDeclared — ступень ВОЗМОЖНОСТИ для ключа ответа состояния (Р6),
// который при этом «Дано» обязан быть.
func requireDeclared(t *testing.T, id string, m map[string]any, path string) any {
	t.Helper()
	v, ok := field(m, path)
	if !ok {
		raw, _ := json.Marshal(m)
		t.Fatalf("ЧЕСТНЫЙ-КРАСНЫЙ %s: ключа `%s` в ответе состояния второго фактора нет: %s", id, path, raw)
	}
	return v
}

// methodsOf — `stepUpMethods` как набор строк (ступень ВОЗМОЖНОСТИ внутри).
func methodsOf(t *testing.T, id string, m map[string]any) []string {
	t.Helper()
	v := requireDeclared(t, id, m, "stepUpMethods")
	arr, ok := v.([]any)
	require.Truef(t, ok, "%s: `stepUpMethods` — массив: %v", id, v)
	out := []string{}
	for _, x := range arr {
		s, ok := x.(string)
		require.Truef(t, ok, "%s: элемент `stepUpMethods` — строка: %v", id, x)
		out = append(out, s)
	}
	return out
}

// momentOf — момент RFC 3339 по ключу ответа.
func momentOf(t *testing.T, id string, m map[string]any, path string) time.Time {
	t.Helper()
	v := requireDeclared(t, id, m, path)
	s, ok := v.(string)
	require.Truef(t, ok, "%s: `%s` — строка момента: %v", id, path, v)
	at, err := time.Parse(time.RFC3339, s)
	require.NoErrorf(t, err, "%s: `%s` — RFC 3339: %q", id, path, s)
	require.Equalf(t, at.Truncate(time.Second), at, "%s: `%s` усечён до секунды", id, path)
	return at
}

// requireRefusalOf — отказ полосы: статус, `code`, `reason` и текст дословно.
func requireRefusalOf(t *testing.T, id string, r reply, status, code int, reason, text string) {
	t.Helper()
	requireRefusal(t, r, status, code, reason, text, id)
}

// requireAuthFailed — суждённый отказ церемонии (Р3): 401, побайтово тот же,
// что у неверного кода.
func requireAuthFailed(t *testing.T, id string, r reply) {
	t.Helper()
	require.Equalf(t, http.StatusUnauthorized, r.status, "%s: суждённый отказ — 401: %s", id, r.body)
	require.JSONEq(t, suaBodyAuthFailed, r.body, "%s: тело суждённого отказа — `authentication failed`", id)
	require.Nil(t, cookieNamed(r.cookies, loginlanehttp.CookieSession), "%s: отказ носителя не перевыпускает", id)
}

// keyRow — счётчик подписи и момент последнего предъявления строки ключа.
func (h *suaStand) keyRow(t *testing.T, id domain.AccessKeyID) (signCount int64, lastUsed *time.Time) {
	t.Helper()
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT sign_count, last_used_at FROM kaname.user_access_keys WHERE id = $1`, string(id)).Scan(&signCount, &lastUsed),
		"НЕ-ВЫПОЛНИЛОСЬ(фикстура): строка ключа %s читается", id)
	return signCount, lastUsed
}

// failures — следов неверных предъявлений по адресу p и по источнику стенда.
func (h *suaStand) failures(t *testing.T, p *suaPerson) (byAddress, bySource int) {
	t.Helper()
	require.NoError(t, h.pool.QueryRow(h.ctx, `
		SELECT count(*) FILTER (WHERE scope = $1 AND key = $2),
		       count(*) FILTER (WHERE scope = $3 AND key = $4)
		  FROM login_failures`,
		string(humansession.FailureByAddress), humansession.AddressKey(p.email),
		string(humansession.FailureBySource), fwd()[loginlanehttp.HeaderForwardedFor]).Scan(&byAddress, &bySource))
	return byAddress, bySource
}

// journalOf — записи журнала повышения сессии s (вид `iam.session.step_up`).
func (h *suaStand) journalOf(t *testing.T, s laneSession) []journalRecord {
	t.Helper()
	row, ok := h.rowByBearer(t, s.bearer.Value)
	require.True(t, ok, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): запись сессии найдена по носителю")
	return h.journalOfID(t, row.id)
}

func (h *suaStand) journalOfID(t *testing.T, sessionID string) []journalRecord {
	t.Helper()
	var out []journalRecord
	for _, r := range h.presentationRecords(t, sessionID) {
		if r.eventType == "iam.session.step_up" {
			out = append(out, r)
		}
	}
	return out
}

// requireLastJournal — последняя запись журнала повышения: способ и исход.
func requireLastJournal(t *testing.T, id string, recs []journalRecord, method, outcome string) {
	t.Helper()
	require.NotEmptyf(t, recs, "%s: журнал повышения несёт запись", id)
	last := recs[len(recs)-1]
	require.Equalf(t, method, toString(last.payload["method"]), "%s: способ записи журнала: %s", id, last)
	require.Equalf(t, outcome, toString(last.payload["outcome"]), "%s: исход записи журнала: %s", id, last)
}

// credentialIDOf — удостоверение ключа k так, как его называет перечень.
func credentialIDOf(k akKey) string { return b64url(k.auth.CredentialID()) }

func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// suaRecorder — приёмник исходов церемонии (Р10): клетки способ × исход и
// сигнал клонирования. Сигнал — метод `SignCountRegressionObserved`, тот же,
// что у наблюдателя Ф7 (`access_keys.Observer`): реализация, у которой
// наблюдатель церемонии его не зовёт, оставит счёт нулём.
type suaRecorder struct {
	humansession.NopObserver
	mu          sync.Mutex
	cells       map[string]int
	regressions int
}

func newSUARecorder() *suaRecorder { return &suaRecorder{cells: map[string]int{}} }

func (r *suaRecorder) SecondFactorPresentationObserved(m assurance.Method, o humansession.PresentationOutcome) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cells[m.String()+"×"+string(o)]++
}

func (r *suaRecorder) SignCountRegressionObserved() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.regressions++
}

func (r *suaRecorder) cell(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cells[name]
}

func (r *suaRecorder) clones() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.regressions
}
