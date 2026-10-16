// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// level_two_enrollment_integration_test.go — заведение второго фактора у
// личности с ключом доступа идёт сессией «2» (задача PRO-Robotech/kaname#747;
// приёмка `docs/engineering/acceptance/level-two-is-enrolled-at-level-two.md`,
// отпечаток 711609ce…, Р4, §7 инварианты 3, 4, 6; сценарии KN747-05…08, -12,
// -17, -18).
//
// # Что доказывается — на ПРОВОДЕ, над настоящими глаголами и базой
//
// Слушатель полосы формы собран стендом `newSessionLaneWith` над настоящими
// `enroll`, `confirm` и чтением состояния с адаптерами `pg`; сессия «2» без
// кода получается НАСТОЯЩИМ входом ключом (Ф13), ключ кладёт писатель продукта
// (`givenAcceptedKey`), сброс ключей — глагол администратора (`ResetAccessKeys`).
// Отказ по уровню утверждается формой Р4 дословно: `401`, тело с `code` 16 и
// текстом шага (одно объявление текста с публичным слушателем — §7 п. 3),
// вызов с `error="insufficient_user_authentication"` и `acr_values="2"`.
//
// # Нечитаемый перечень ключей (§3.7)
//
// Шов — обёртка хранилища способов (`loginmethod.Store`), у которой отказывает
// ровно `AccessKeyEnrolled`, остальное — настоящий адаптер. Переключатель
// включается ПОСЛЕ «Дано», и его действие проверяется до предмета.
//
// # Чем краснеет ДО кода
//
// Полоса до kaname#747 условия Р4 не несёт: KN747-06, -07 отвечают `200` там,
// где ждётся указание повысить уровень; KN747-17, -18 — `200` там, где ждётся
// `503`/14. Положительные близнецы (KN747-05, -08, -12) зелены и до кода —
// они держат проходимость, которую правка не вправе отнять.
//
// Run: `go test ./internal/handler/loginlanehttp/ -run 'TestKN747' -count=1`
// (Docker). Skipped under -short.
package loginlanehttp_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238: SHA-1 — контракт приложений-аутентификаторов
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/loginmethod"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerrs "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

var errKN747KeyListUnreadable = errors.New("kn747 probe: access key list unreadable")

// kn747Methods — шов хранилища способов: отказывает ровно чтение перечня
// ключей и только при поднятом переключателе.
type kn747Methods struct {
	loginmethod.Store
	fail *atomic.Bool
}

func (m kn747Methods) AccessKeyEnrolled(ctx context.Context, userID domain.UserID) (bool, error) {
	if m.fail.Load() {
		return false, errKN747KeyListUnreadable
	}
	return m.Store.AccessKeyEnrolled(ctx, userID)
}

// kn747Verbs — глаголы стенда плюс настоящие `enroll` и `confirm` над швом.
type kn747Verbs struct {
	sessionVerbs
	enroll  *humansession.EnrollSecondFactorUseCase
	confirm *humansession.ConfirmSecondFactorUseCase
}

func (v kn747Verbs) EnrollSecondFactor(ctx context.Context, in humansession.EnrollInput) (humansession.EnrollOutput, error) {
	return v.enroll.Execute(ctx, in)
}

func (v kn747Verbs) ConfirmSecondFactor(ctx context.Context, in humansession.ConfirmInput) (humansession.ConfirmOutput, error) {
	return v.confirm.Execute(ctx, in)
}

type kn747Stand struct {
	*sessionLane
	fail    *atomic.Bool
	methods kn747Methods
}

func newKN747Stand(t *testing.T) *kn747Stand {
	t.Helper()
	fail := &atomic.Bool{}
	st := &kn747Stand{fail: fail}
	st.sessionLane = newSessionLaneWith(t, sessionLaneOptions{
		verbs: func(v sessionVerbs, d humansession.SecondFactorDeps) loginlanehttp.Lane {
			st.methods = kn747Methods{Store: d.Methods, fail: fail}
			d.Methods = st.methods
			enroll, err := humansession.NewEnrollSecondFactorUseCase(d)
			require.NoError(t, err)
			confirm, err := humansession.NewConfirmSecondFactorUseCase(d)
			require.NoError(t, err)
			return kn747Verbs{sessionVerbs: v, enroll: enroll, confirm: confirm}
		},
	})
	return st
}

// levelOf — уровень записи сессии по носителю, из базы.
func (h *kn747Stand) levelOf(t *testing.T, s laneSession) string {
	t.Helper()
	row, ok := h.rowByBearer(t, s.bearer.Value)
	require.True(t, ok, "Дано: запись сессии найдена по носителю")
	return row.level
}

// passwordSession — вход одним паролем; уровень «1» проверен ДО предмета.
func (h *kn747Stand) passwordSession(t *testing.T) laneSession {
	t.Helper()
	s := h.login(t, integrationPassword)
	require.Equal(t, "1", h.levelOf(t, s), "Дано: вход паролем — сессия «1»")
	return s
}

// keySession — НАСТОЯЩИЙ вход ключом k (Ф13); уровень «2» проверен ДО предмета.
func (h *kn747Stand) keySession(t *testing.T, k akKey) laneSession {
	t.Helper()
	f := givenAKForm(t, h.sessionLane)
	c := givenChallenge(t, h.sessionLane, f)
	r := akLoginWith(t, h.sessionLane, f, k, c, webauthntest.AssertionOptions{})
	require.Equalf(t, http.StatusOK, r.status, "Дано: вход ключом выдаёт сессию: %s", r.body)
	s := laneSession{bearer: cookieNamed(r.cookies, loginlanehttp.CookieSession), form: cookieNamed(r.cookies, loginlanehttp.CookieForm)}
	require.NotNil(t, s.bearer, "Дано: вход ключом пишет носитель")
	require.NotNil(t, s.form, "Дано: вход ключом сменяет контекст формы")
	require.Equal(t, "2", h.levelOf(t, s), "Дано: вход ключом — сессия «2» (Ф11 Р2)")
	return s
}

func (h *kn747Stand) enrollIn(t *testing.T, s laneSession) reply {
	t.Helper()
	return h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathSecondFactorEnroll,
		map[string]any{"csrfToken": h.csrfFor(t, domain.FormSecondFactor, s.form)}, fwd(), s.bearer, s.form)
}

func (h *kn747Stand) confirmIn(t *testing.T, s laneSession, code string) reply {
	t.Helper()
	return h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathSecondFactorConfirm,
		map[string]any{"code": code, "csrfToken": h.csrfFor(t, domain.FormSecondFactor, s.form)}, fwd(), s.bearer, s.form)
}

// statusIn — состояние второго фактора телом ответа.
func (h *kn747Stand) statusIn(t *testing.T, s laneSession) string {
	t.Helper()
	r := h.lane.do(t, h.c, http.MethodGet, loginlanehttp.PathSecondFactor, nil, fwd(), s.bearer, s.form)
	require.Equalf(t, http.StatusOK, r.status, "чтение состояния второго фактора: %s", r.body)
	return r.body
}

// secretOf — секрет из ответа `enroll` (base32 без дополнения, Ф12-27).
func secretOf(t *testing.T, r reply) string {
	t.Helper()
	var out struct {
		Secret string `json:"secret"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &out), r.body)
	require.NotEmpty(t, out.Secret, "ответ `enroll` несёт секрет")
	return out.Secret
}

// kn747Code — код текущей ступени от секрета ответа, посчитанный пробой по
// RFC 6238 независимо от проверяющего: оракул, а не вызов прод-функции.
func kn747Code(t *testing.T, secret string) string {
	t.Helper()
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	require.NoError(t, err)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(totpverify.StepAt(time.Now()))) // #nosec G115 -- ступень неотрицательна
	mac := hmac.New(sha1.New, raw)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", bin%1000000)
}

// reChallengeParamKN747 — параметр вызова RFC 7235: имя="значение";
// утверждается РАЗБОР вызова, а не сравнение строки.
var reChallengeParamKN747 = regexp.MustCompile(`([a-z_]+)="([^"]*)"`)

// requireStepUpIndication — указание повысить уровень формой Р4 дословно.
func requireStepUpIndication(t *testing.T, r reply, what string) {
	t.Helper()
	require.Equalf(t, http.StatusUnauthorized, r.status, "%s: ждалось указание повысить уровень (401), ответ: %s", what, r.body)
	require.Equalf(t, refusalWire(16, iamerrs.TextStepUpRequired), r.body, "%s: тело указания (Ф11 Р11, одно объявление текста)", what)
	ch := r.header.Get("WWW-Authenticate")
	params := map[string]string{}
	for _, m := range reChallengeParamKN747.FindAllStringSubmatch(ch, -1) {
		params[m[1]] = m[2]
	}
	require.Equalf(t, "insufficient_user_authentication", params["error"], "%s: вызов: %q", what, ch)
	require.Equalf(t, "2", params["acr_values"], "%s: вызов: %q", what, ch)
}

// requireStoreRefusal — отказ хранилища полосы формы: `503`, тело `code` 14.
func requireStoreRefusal(t *testing.T, r reply, what string) {
	t.Helper()
	require.Equalf(t, http.StatusServiceUnavailable, r.status, "%s: ждался отказ хранилища (503), ответ: %s", what, r.body)
	require.Equalf(t, refusalWire(14, humansession.TextRequestNotPerformed), r.body, "%s: тело отказа хранилища", what)
}

// kn747NotEnrolled — состояние личности с ключом и без заведённого кода: с
// kaname#827 (SUA Р6) тело несёт доступность ключей и способы повышения, и у
// такой личности способ один — ключ.
const kn747NotEnrolled = `{"accessKeys":{"available":true},"stepUpMethods":["webauthn"],"totp":{"enrolled":false}}`

// TestKN747_05_PasswordOnlyPersonEnrollsFromLevelOne — положительный близнец
// KN747-06: у личности без ключа свежая «1» заводит код (Ф12 Р8 без правки).
func TestKN747_05_PasswordOnlyPersonEnrollsFromLevelOne(t *testing.T) {
	h := newKN747Stand(t)
	require.Zero(t, h.keysOf(t, h.user.ID), "Дано: ключей ноль")
	s := h.passwordSession(t)

	en := h.enrollIn(t, s)
	require.Equalf(t, http.StatusOK, en.status, "KN747-05: заведение начато: %s", en.body)
	conf := h.confirmIn(t, s, kn747Code(t, secretOf(t, en)))
	require.Equalf(t, http.StatusOK, conf.status, "KN747-05: подтверждение: %s", conf.body)
	next := laneSession{bearer: cookieNamed(conf.cookies, loginlanehttp.CookieSession), form: s.form}
	require.NotNil(t, next.bearer, "KN747-05: подтверждение выдаёт новый носитель")
	require.Equal(t, "2", h.levelOf(t, next), "KN747-05: пароль и код в одной сессии — «2»")
}

// TestKN747_06_PersonWithAKeyCannotEnrollFromLevelOne — KN747-06; близнец —
// KN747-05, отличается одним фактом: у личности заведён ключ.
func TestKN747_06_PersonWithAKeyCannotEnrollFromLevelOne(t *testing.T) {
	h := newKN747Stand(t)
	givenAcceptedKey(t, h.sessionLane, h.user.ID)
	require.Equal(t, 1, h.keysOf(t, h.user.ID), "Дано: один ключ")
	s := h.passwordSession(t)
	require.Equal(t, kn747NotEnrolled, h.statusIn(t, s), "Дано: фактор не заведён")

	r := h.enrollIn(t, s)
	requireStepUpIndication(t, r, "KN747-06")
	require.Equal(t, kn747NotEnrolled, h.statusIn(t, s), "KN747-06: заведение не начато, `pendingUntil` нет")
}

// kn747PendingFromKeySession — «Дано» KN747-07, -08, -18: личность с ключом,
// вошедшая ключом («2») и начавшая в этой сессии заведение; вторая живая
// сессия — паролем («1»).
func kn747PendingFromKeySession(t *testing.T, h *kn747Stand) (two, one laneSession, secret string, pending string) {
	t.Helper()
	k := givenAcceptedKey(t, h.sessionLane, h.user.ID)
	two = h.keySession(t, k)
	en := h.enrollIn(t, two)
	require.Equalf(t, http.StatusOK, en.status, "Дано: заведение начато в сессии «2»: %s", en.body)
	secret = secretOf(t, en)
	one = h.passwordSession(t)
	pending = h.statusIn(t, two)
	require.Contains(t, pending, `"pendingUntil"`, "Дано: заведение ожидает подтверждения")
	require.Contains(t, pending, `"enrolled":false`, "Дано: фактор не заведён")
	return two, one, secret, pending
}

// TestKN747_07_ConfirmFromLevelOneIsAStepUpIndication — KN747-07; близнец —
// KN747-08, отличается одним фактом: подтверждение из сессии «1».
func TestKN747_07_ConfirmFromLevelOneIsAStepUpIndication(t *testing.T) {
	h := newKN747Stand(t)
	two, one, secret, pending := kn747PendingFromKeySession(t, h)

	r := h.confirmIn(t, one, kn747Code(t, secret))
	requireStepUpIndication(t, r, "KN747-07")
	require.Equal(t, pending, h.statusIn(t, two), "KN747-07: фактор не заведён, `pendingUntil` прежний (§7 п. 4)")
}

// TestKN747_08_ConfirmFromLevelTwoEnrolls — положительный близнец KN747-07.
func TestKN747_08_ConfirmFromLevelTwoEnrolls(t *testing.T) {
	h := newKN747Stand(t)
	two, _, secret, _ := kn747PendingFromKeySession(t, h)

	r := h.confirmIn(t, two, kn747Code(t, secret))
	require.Equalf(t, http.StatusOK, r.status, "KN747-08: подтверждение из «2»: %s", r.body)
	require.Contains(t, r.body, `"backupCodes":[`, "KN747-08: набор показан")
	next := laneSession{bearer: cookieNamed(r.cookies, loginlanehttp.CookieSession), form: two.form}
	require.NotNil(t, next.bearer)
	require.Contains(t, h.statusIn(t, next), `"enrolled":true`, "KN747-08: фактор заведён")
}

// TestKN747_12_AfterAdminResetPersonEnrollsFromLevelOne — KN747-12;
// положительный близнец KN747-06, отличается одним фактом: ключей ноль после
// сброса администратором.
func TestKN747_12_AfterAdminResetPersonEnrollsFromLevelOne(t *testing.T) {
	h := newKN747Stand(t)
	admin := registerPerson(t, h.sessionLane, "kn747-admin")
	givenAcceptedKey(t, h.sessionLane, h.user.ID)
	require.Equal(t, 1, h.keysOf(t, h.user.ID), "Дано: один ключ")
	h.requireResetDone(t, admin, h.user.ID, "Дано KN747-12")
	require.Zero(t, h.keysOf(t, h.user.ID), "Дано: ключей ноль после сброса")
	s := h.passwordSession(t)

	r := h.enrollIn(t, s)
	require.Equalf(t, http.StatusOK, r.status, "KN747-12: заведение начато: %s", r.body)
}

// TestKN747_17_EnrollWithUnreadableKeyListIsAStoreRefusal — KN747-17; близнец
// — KN747-06, отличается одним фактом: чтение перечня ключей не удалось.
func TestKN747_17_EnrollWithUnreadableKeyListIsAStoreRefusal(t *testing.T) {
	h := newKN747Stand(t)
	givenAcceptedKey(t, h.sessionLane, h.user.ID)
	s := h.passwordSession(t)
	require.Equal(t, kn747NotEnrolled, h.statusIn(t, s), "Дано: фактор не заведён")

	h.fail.Store(true)
	_, err := h.methods.AccessKeyEnrolled(h.ctx, h.user.ID)
	require.ErrorIs(t, err, errKN747KeyListUnreadable, "Дано: чтение перечня ключей отвечает ошибкой")
	r := h.enrollIn(t, s)
	h.fail.Store(false)

	requireStoreRefusal(t, r, "KN747-17")
	require.Equal(t, kn747NotEnrolled, h.statusIn(t, s), "KN747-17: заведение не начато")
}

// TestKN747_18_ConfirmWithUnreadableKeyListIsAStoreRefusal — KN747-18; близнец
// — KN747-07, отличается одним фактом: чтение перечня ключей не удалось.
func TestKN747_18_ConfirmWithUnreadableKeyListIsAStoreRefusal(t *testing.T) {
	h := newKN747Stand(t)
	two, one, secret, pending := kn747PendingFromKeySession(t, h)

	h.fail.Store(true)
	_, err := h.methods.AccessKeyEnrolled(h.ctx, h.user.ID)
	require.ErrorIs(t, err, errKN747KeyListUnreadable, "Дано: чтение перечня ключей отвечает ошибкой")
	r := h.confirmIn(t, one, kn747Code(t, secret))
	h.fail.Store(false)

	requireStoreRefusal(t, r, "KN747-18")
	require.Equal(t, pending, h.statusIn(t, two), "KN747-18: фактор не заведён, `pendingUntil` прежний")
}
