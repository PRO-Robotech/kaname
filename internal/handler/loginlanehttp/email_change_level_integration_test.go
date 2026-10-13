// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// email_change_level_integration_test.go — пробы уровня I редакции 3 приёмки
// `docs/engineering/acceptance/email-change-is-confirmed-from-the-new-address.md`
// (задача PRO-Robotech/kaname#770, решение Р2 «уровень — по заведённому»),
// сценарии EC-28…EC-31 и EC-34, на ПРОВОДЕ полосы формы: стенд `avLane`
// (настоящие глаголы, настоящие адаптеры базы, часы глаголов управляемые,
// только вперёд).
//
// # Ступени
//
// МИР — посев П2Ф (§4.0) глаголами продукта: регистрация, отметка писателем
// продукта, заведение кода по времени глаголами Ф12 в отдельной сессии, вход
// одним паролем; уровень сессии прочитан и ответом службы краю, и записью
// сессии. Отказ — «НЕ-ВЫПОЛНИЛОСЬ(фикстура)». ВОЗМОЖНОСТЬ — оба пути смены
// смонтированы. ПРЕДМЕТ — утверждения сценария с его номером.
//
// # Ступень кода повышения (редакция 4)
//
// Подтверждение заведения принимает код ступени `StepAt(avClock.Now())`, а
// сверка отвергает как повтор всякий код ступени не новее принятой; часы стенда
// без `Advance` стоят. Повышение предъявляет код СЛЕДУЮЩЕЙ ступени — в окне
// расхождения ±1 и новее ступени заведения; в каждом посеве — не больше одного
// повышения кодом. Код считает оракул пробы по RFC 6238 (`ecTOTP`), а не
// прод-функция.
package loginlanehttp_test

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 задаёт HMAC-SHA1; оракул кода пробы
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

// ecFormSecondFactor, ecFormStepUp — виды признака формы глаголов Ф12 и
// повышения, дословно.
const (
	ecFormSecondFactor = "second-factor"
	ecFormStepUp       = "step-up"
)

// ec2FSeed — посев П2Ф: человек с заведённым кодом по времени и его свежая
// сессия `S` уровня «1» (вход одним паролем).
type ec2FSeed struct {
	u      avSession
	s      avSession
	secret string
}

// ecTOTP — код ступени step от секрета (base32 без дополнения) по RFC 6238,
// посчитанный пробой независимо от проверяющего.
func ecTOTP(t *testing.T, secretB32 string, step int64) string {
	t.Helper()
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): секрет ответа `enroll` не разбирается")
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) // #nosec G115 -- ступень неотрицательна
	mac := hmac.New(sha1.New, raw)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", bin%1000000)
}

// ecLevelOf — уровень сессии по носителю: ответ службы краю о сессии (Ф11
// §3.0) и запись сессии; расхождение двух чтений — поломка мира.
func (h *avLane) ecLevelOf(t *testing.T, s avSession) string {
	t.Helper()
	got := h.resolve(t, s.bearer)
	require.True(t, got.GetFound(), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): сессия жива")
	var row string
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT assurance_level FROM kaname.human_sessions WHERE bearer_digest = $1`,
		string(domain.PresentedSessionBearer(s.bearer.Value).Digest())).Scan(&row),
		"НЕ-ВЫПОЛНИЛОСЬ(фикстура): запись сессии по носителю")
	require.Equal(t, row, got.GetSession().GetAssuranceLevel(), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): уровень в записи и в ответе краю один")
	return row
}

// ecSeedSF — посев П2Ф (§4.0): П, где после отметки человек заводит код по
// времени глаголами Ф12 в отдельной сессии `S₀`, а сессия `S` — вход одним
// паролем ПОСЛЕ этого («1», свежая).
func (h *avLane) ecSeedSF(t *testing.T, tag string) ec2FSeed {
	t.Helper()
	u := h.register(t, freshAddress(tag))
	h.mark(t, u)
	s0 := h.login(t, u)
	en := h.post(t, s0, loginlanehttp.PathSecondFactorEnroll, map[string]any{"csrfToken": h.token(s0, ecFormSecondFactor)})
	require.Equal(t, http.StatusOK, en.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): заведение кода начато: %s", en.body)
	var out struct {
		Secret string `json:"secret"`
	}
	require.NoError(t, json.Unmarshal([]byte(en.body), &out), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): ответ `enroll`")
	require.NotEmpty(t, out.Secret, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): ответ `enroll` несёт секрет")
	conf := h.post(t, s0, loginlanehttp.PathSecondFactorConfirm, map[string]any{
		"code": ecTOTP(t, out.Secret, totpverify.StepAt(h.clock.Now())), "csrfToken": h.token(s0, ecFormSecondFactor),
	})
	require.Equal(t, http.StatusOK, conf.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): заведение кода подтверждено: %s", conf.body)
	row, err := h.methods.Get(h.ctx, u.user, domain.LoginMethodTOTP)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): строка кода по времени")
	require.True(t, row.Enrolled(), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): код по времени заведён (подтверждён)")
	keys, err := h.methods.AccessKeyEnrolled(h.ctx, u.user)
	require.NoError(t, err)
	require.False(t, keys, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): ключа доступа у личности посева нет")

	s := h.login(t, u)
	require.Equal(t, "1", h.ecLevelOf(t, s), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): вход одним паролем — сессия «1»")
	return ec2FSeed{u: u, s: s, secret: out.Secret}
}

// ecStepUpTOTP — повышение кодом ступени, следующей за ступенью заведения
// (редакция 4): носитель перевыпущен, уровень «2».
func (h *avLane) ecStepUpTOTP(t *testing.T, seed ec2FSeed, s avSession) avSession {
	t.Helper()
	up := h.post(t, s, loginlanehttp.PathStepUp, map[string]any{
		"method": "totp", "code": ecTOTP(t, seed.secret, totpverify.StepAt(h.clock.Now())+1),
		"csrfToken": h.token(s, ecFormStepUp),
	})
	require.Equal(t, http.StatusOK, up.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): повышение кодом следующей ступени: %s", up.body)
	out := withBearer(t, s, up)
	require.Equal(t, "2", h.ecLevelOf(t, out), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): после повышения кодом — «2»")
	return out
}

// reEcChallengeParam — параметр вызова RFC 7235: имя="значение"; утверждается
// разбор вызова, а не сравнение строки.
var reEcChallengeParam = regexp.MustCompile(`([a-z_]+)="([^"]*)"`)

// ecRequireStepUp — указание повысить уровень формой Ф11 Р11 на полосе формы
// дословно: `401`, тело `code 16` с текстом одного объявления, вызов с
// `insufficient_user_authentication` и `acr_values="2"`.
func ecRequireStepUp(t *testing.T, r reply, what string) {
	t.Helper()
	if r.status != http.StatusUnauthorized {
		t.Fatalf("%s ЧЕСТНЫЙ-КРАСНЫЙ: ждалось указание повысить уровень (401) — ответ %d: %s", what, r.status, r.body)
	}
	require.Equalf(t, refusalWire(16, iamerr.TextStepUpRequired), r.body, "%s: тело указания (Ф11 Р11)", what)
	ch := r.header.Get("WWW-Authenticate")
	params := map[string]string{}
	for _, m := range reEcChallengeParam.FindAllStringSubmatch(ch, -1) {
		params[m[1]] = m[2]
	}
	require.Equalf(t, "insufficient_user_authentication", params["error"], "%s: вызов: %q", what, ch)
	require.Equalf(t, "2", params["acr_values"], "%s: вызов: %q", what, ch)
	require.Nilf(t, cookieNamed(r.cookies, loginlanehttp.CookieSession), "%s: указание носителя не пишет", what)
}

// TestEC28_CodeHolderAtLevelOneIsToldToStepUpAndTheSameRequestPassesAfter —
// EC-28: отрицание (а) и близнец (в) отличаются одним фактом — уровнем сессии.
func TestEC28_CodeHolderAtLevelOneIsToldToStepUpAndTheSameRequestPassesAfter(t *testing.T) {
	h := newAVLane(t)
	seed := h.ecSeedSF(t, "ec28")
	h.requireEmailChangeVerbs(t, "EC-28")
	n := freshAddress("ec28n")

	a := h.requestChange(t, seed.s, n)
	ecRequireStepUp(t, a, "EC-28 (а)")
	require.Empty(t, h.mailOf(t, ecMailCode, seed.u.user), "EC-28 (а): строк %s ноль", ecMailCode)
	email, _ := h.identityOf(t, seed.u.user)
	require.Equal(t, seed.u.email, email, "EC-28 (а): адрес прежний")

	star := h.ecStepUpTOTP(t, seed, seed.s)

	c := h.requestChange(t, star, n)
	require.Equal(t, http.StatusOK, c.status, "EC-28 (в): тот же запрос из «2»: %s", c.body)
	require.Equal(t, "{}", c.body, "EC-28 (в): тело")
	require.Equal(t, ecRetryInterval, c.header.Get("Retry-After"),
		"EC-28 (в): Retry-After — интервал Р6; (а) темпа не расходовал (иначе 429 по интервалу без сдвига часов)")
	require.Len(t, h.mailOf(t, ecMailCode, seed.u.user), 1, "EC-28 (в): строка %s одна", ecMailCode)
}

// TestEC29_ConfirmFromLevelOneIsToldToStepUpAndTheCodeIsUntouched — EC-29:
// отрицание (а) и близнец (б) отличаются одним фактом — уровнем сессии, из
// которой предъявлен тот же код.
func TestEC29_ConfirmFromLevelOneIsToldToStepUpAndTheCodeIsUntouched(t *testing.T) {
	h := newAVLane(t)
	seed := h.ecSeedSF(t, "ec29")
	h.requireEmailChangeVerbs(t, "EC-29")
	n := freshAddress("ec29n")
	star := h.ecStepUpTOTP(t, seed, seed.s)
	req := h.requestChange(t, star, n)
	require.Equal(t, http.StatusOK, req.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): запрос смены из «2»: %s", req.body)
	code := h.changeCode(t, "EC-29", seed.u.user)
	other := h.login(t, seed.u)
	require.Equal(t, "1", h.ecLevelOf(t, other), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): вторая сессия S′ — вход одним паролем, «1»")

	for i := 1; i <= avAttemptsProfile; i++ {
		ecRequireStepUp(t, h.confirmChange(t, other, code), fmt.Sprintf("EC-29 (а) предъявление %d из %d", i, avAttemptsProfile))
	}
	email, _ := h.identityOf(t, seed.u.user)
	require.Equal(t, seed.u.email, email, "EC-29 (а): адрес прежний")
	require.Empty(t, h.mailOf(t, ecMailNotice, seed.u.user), "EC-29 (а): строк %s ноль", ecMailNotice)
	require.Empty(t, h.subjectChanges(t, seed.u.user), "EC-29 (а): строк очереди смены субъекта ноль")
	require.Equal(t, "", h.endReason(t, other.bearer), "EC-29 (а): S′ жива")
	require.Equal(t, "", h.endReason(t, star.bearer), "EC-29 (а): S* жива")

	b := h.confirmChange(t, star, code)
	require.Equal(t, http.StatusOK, b.status,
		"EC-29 (б): тот же код из «2» — отказы (а) попыток не засчитали (иначе пятый тратил бы код): %s", b.body)
	email, _ = h.identityOf(t, seed.u.user)
	require.Equal(t, n, email, "EC-29 (б): адрес новый")
	require.Equal(t, ecEndReason, h.endReason(t, other.bearer), "EC-29 (б): S′ снята с причиной %s", ecEndReason)
}

// TestEC30_StaleLevelOneOfACodeHolderIsToldToStepUpNotRefusedForFreshness —
// EC-30; близнец — EC-31, отличается одним фактом: уровень «1», а не «2».
func TestEC30_StaleLevelOneOfACodeHolderIsToldToStepUpNotRefusedForFreshness(t *testing.T) {
	h := newAVLane(t)
	seed := h.ecSeedSF(t, "ec30")
	h.requireEmailChangeVerbs(t, "EC-30")
	n := freshAddress("ec30n")
	h.clock.Advance(laneFreshness + time.Second)

	r := h.requestChange(t, seed.s, n)
	ecRequireStepUp(t, r, "EC-30 (уровень судится раньше свежести)")
	require.Empty(t, h.mailOf(t, ecMailCode, seed.u.user), "EC-30: строк %s ноль", ecMailCode)
}

// TestEC31_StaleLevelTwoIsRefusedForFreshness — EC-31; близнец — EC-30.
func TestEC31_StaleLevelTwoIsRefusedForFreshness(t *testing.T) {
	h := newAVLane(t)
	seed := h.ecSeedSF(t, "ec31")
	h.requireEmailChangeVerbs(t, "EC-31")
	n := freshAddress("ec31n")
	star := h.ecStepUpTOTP(t, seed, seed.s)
	h.clock.Advance(laneFreshness + time.Second)

	r := h.requestChange(t, star, n)
	requireRefusal(t, r, http.StatusForbidden, 7, "SESSION_NOT_FRESH", humansession.TextSessionNotFresh, "EC-31")
	require.Empty(t, h.mailOf(t, ecMailCode, seed.u.user), "EC-31: строк %s ноль", ecMailCode)
}

// ecRecoverySession — завершение восстановления кодом из письма и новым
// паролем: сессия восстановления `Q` («1», Ф11 Р2).
func (h *avLane) ecRecoverySession(t *testing.T, id string, seed ec2FSeed) avSession {
	t.Helper()
	code, ctxCk := h.recoveryCode(t, id, seed.u.user, seed.u.email)
	r := h.complete(t, seed.u.email, code, ctxCk)
	require.Equal(t, http.StatusOK, r.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): %s: завершение восстановления: %s", id, r.body)
	q := seed.u
	q.bearer = cookieNamed(r.cookies, loginlanehttp.CookieSession)
	require.NotNil(t, q.bearer, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): %s: завершение выдало носитель", id)
	q.form = ctxCk
	if f := cookieNamed(r.cookies, loginlanehttp.CookieForm); f != nil {
		q.form = f
	}
	require.Equal(t, "1", h.ecLevelOf(t, q), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): %s: сессия восстановления — «1»", id)
	return q
}

// TestEC34_RecoverySessionAtLevelOneIsToldToStepUpAndAtLevelTwoPasses — EC-34:
// отрицание (а); близнец (б) отличается одним фактом — уровнем сессии
// восстановления («2» после повышения паролем и кодом, Ф11-29).
func TestEC34_RecoverySessionAtLevelOneIsToldToStepUpAndAtLevelTwoPasses(t *testing.T) {
	t.Run("(а) сессия восстановления «1»", func(t *testing.T) {
		h := newAVLane(t)
		seed := h.ecSeedSF(t, "ec34a")
		h.requireEmailChangeVerbs(t, "EC-34 (а)")
		q := h.ecRecoverySession(t, "EC-34 (а)", seed)

		r := h.requestChange(t, q, freshAddress("ec34an"))
		ecRequireStepUp(t, r, "EC-34 (а)")
		require.Empty(t, h.mailOf(t, ecMailCode, seed.u.user), "EC-34 (а): строк %s ноль", ecMailCode)
	})
	t.Run("(б) сессия восстановления, повышенная паролем и кодом, — «2»", func(t *testing.T) {
		h := newAVLane(t)
		seed := h.ecSeedSF(t, "ec34b")
		h.requireEmailChangeVerbs(t, "EC-34 (б)")
		q := h.ecRecoverySession(t, "EC-34 (б)", seed)
		// Сессия восстановления аутентифицирована на единицу разрешения ПОЗЖЕ
		// момента завершения (`recovery_complete.go`, отсечка Ф5-19), а часы
		// стенда стоят: предъявление в тот же момент легло бы раньше
		// аутентификации и отвергнуто ключом записи сессии. Часы — только вперёд,
		// на секунду: свежесть `Q` не тронута, ступень кода повышения остаётся
		// новее ступени заведения и в окне расхождения.
		h.clock.Advance(time.Second)
		pw := h.post(t, q, loginlanehttp.PathStepUp, map[string]any{
			"method": "password", "password": a458NewPassword, "csrfToken": h.token(q, ecFormStepUp),
		})
		require.Equal(t, http.StatusOK, pw.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): повышение паролем восстановления: %s", pw.body)
		q = withBearer(t, q, pw)
		qStar := h.ecStepUpTOTP(t, seed, q)

		r := h.requestChange(t, qStar, freshAddress("ec34bn"))
		require.Equal(t, http.StatusOK, r.status, "EC-34 (б): запрос из «2»: %s", r.body)
		require.Len(t, h.mailOf(t, ecMailCode, seed.u.user), 1, "EC-34 (б): строка %s одна", ecMailCode)
	})
}
