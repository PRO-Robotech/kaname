// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// step_up_any_method_ceremony_integration_test.go — церемония повышения каждым
// заведённым способом и её отказы (задача PRO-Robotech/kaname#827; приёмка
// `docs/engineering/acceptance/step-up-with-any-enrolled-method.md`, редакция 3,
// отпечаток 35224856…, §3.1 SUA-01…05, §3.2 SUA-10…19, SUA-80; решения Р1…Р4,
// Р10). Стенд и слова ступеней — `step_up_any_method_harness_integration_test.go`.
//
// # Близнецы
//
// Каждое отрицание — в паре с положительным близнецом, отличающимся ОДНИМ
// фактом, и близнец исполняется в той же пробе: отказ, зеленеющий на полосе,
// которая отвергает всё, близнец ловит.
//
// # Чем краснеет ДО кода
//
// Путь выдачи испытания повышения не смонтирован (404), способа `webauthn` у
// церемонии нет (отказ формы), моменты способов ответ состояния не несёт —
// «ЧЕСТНЫЙ-КРАСНЫЙ» с ID сценария. SUA-11 и SUA-12 утверждают поведение,
// которое уже есть (Ф12 Р7): они держат проходимость, которую правка не вправе
// отнять, и зелены до кода.
//
// Run: `go test ./internal/handler/loginlanehttp/ -run 'TestSUA' -count=1`
// (Docker). Skipped under -short.
package loginlanehttp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

// assuranceOf — объект `assurance` ответа церемонии как есть.
func assuranceOf(t *testing.T, body string) string {
	t.Helper()
	var out struct {
		Assurance json.RawMessage `json:"assurance"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &out), body)
	return string(out.Assurance)
}

// requireKeyAccepted — ступень ВОЗМОЖНОСТИ для способа `webauthn`: отказ формы
// «поле неизвестно» либо прежний словарь способов — предмета нет.
func requireKeyAccepted(t *testing.T, id string, r reply) {
	t.Helper()
	if r.status != http.StatusBadRequest {
		return
	}
	ref := parseRefusal(t, r.body)
	switch ref.Message {
	case "Illegal argument credential: unknown field",
		"Illegal argument method: must be one of password|totp|lookup_secret":
		t.Fatalf("ЧЕСТНЫЙ-КРАСНЫЙ %s: способа `webauthn` у церемонии повышения нет — %s отвечает %q", id, suaPathStepUp, ref.Message)
	}
}

// keyStepUp — предъявление ключа с проверкой ступени ВОЗМОЖНОСТИ.
func (h *suaStand) keyStepUp(t *testing.T, id string, s laneSession, k akKey, c []byte, o webauthntest.AssertionOptions) reply {
	t.Helper()
	r := h.stepUpKey(t, s, k, c, o)
	requireKeyAccepted(t, id, r)
	return r
}

// TestSUA01_CodeRaisesTheSessionAndStampsItsMoment — SUA-01.
func TestSUA01_CodeRaisesTheSessionAndStampsItsMoment(t *testing.T) {
	const id = "SUA-01"
	h := newSUAStand(t)
	p := h.person(t, "01")
	h.withCode(t, p)
	s := h.login(t, p)

	r := h.stepUpCode(t, s, "totp", h.totpNow(t, p))
	at := h.clock.Now().UTC().Truncate(time.Second)
	require.Equalf(t, http.StatusOK, r.status, "%s: повышение кодом — 200: %s", id, r.body)
	assuranceLevel, sessionLevel := ceremonyLevels(t, r.body)
	require.Equal(t, "2", sessionLevel, "%s: session.assuranceLevel", id)
	require.Equal(t, "2", assuranceLevel, "%s: assurance.level", id)
	require.JSONEq(t, `{"level":"2","level2Reachable":true,"missingForLevel2":[]}`, assuranceOf(t, r.body), "%s: assurance", id)
	fresh := rotated(t, id, r, s)

	old := h.lane.do(t, h.c, http.MethodGet, suaPathStatus, nil, fwd(), s.bearer, s.form)
	require.Equalf(t, http.StatusUnauthorized, old.status, "%s: прежний носитель — 401: %s", id, old.body)
	require.JSONEq(t, suaBodyAuthFailed, old.body, "%s: прежний носитель — отказ несуществующей сессии", id)

	got := momentOf(t, id, h.status(t, fresh), "totp.lastUsedAt")
	require.Equal(t, at, got, "%s: totp.lastUsedAt — момент предъявления до секунды", id)
}

// TestSUA02_BackupCodeRaisesTheSessionAndStampsItsMoment — SUA-02.
func TestSUA02_BackupCodeRaisesTheSessionAndStampsItsMoment(t *testing.T) {
	const id = "SUA-02"
	h := newSUAStand(t)
	p := h.person(t, "02")
	h.withCode(t, p)
	s := h.login(t, p)

	r := h.stepUpCode(t, s, "lookup_secret", p.codes[0])
	require.Equalf(t, http.StatusOK, r.status, "%s: повышение запасным кодом — 200: %s", id, r.body)
	assuranceLevel, _ := ceremonyLevels(t, r.body)
	require.Equal(t, "2", assuranceLevel, "%s: assurance.level", id)
	var body map[string]any
	require.NoError(t, json.Unmarshal([]byte(r.body), &body))
	require.EqualValues(t, 9, requireDeclared(t, id, body, "backupCodeSet.remaining"), "%s: backupCodeSet.remaining ответа (kaname#297 Р3)", id)
	require.NotContains(t, body, "backupCodesRemaining", "%s: плоского остатка нет (kaname#297 BCS-31)", id)

	st := h.status(t, rotated(t, id, r, s))
	require.EqualValues(t, 9, requireDeclared(t, id, st, "backupCodeSet.remaining"), "%s: backupCodeSet.remaining", id)
	require.EqualValues(t, 10, requireDeclared(t, id, st, "backupCodeSet.total"), "%s: backupCodeSet.total", id)
	momentOf(t, id, st, "backupCodeSet.lastUsedAt")
}

// TestSUA03_KeyRaisesTheSessionToLevelTwo — SUA-03.
func TestSUA03_KeyRaisesTheSessionToLevelTwo(t *testing.T) {
	const id = "SUA-03"
	h := newSUAStand(t)
	p := h.person(t, "03")
	k := h.withKey(t, p)
	s := h.login(t, p)

	c := issued(t, id, h.begin(t, s))
	require.Equal(t, []string{credentialIDOf(k)}, c.allow, "%s: allowCredentials — ровно ключ П-кл", id)
	r := h.keyStepUp(t, id, s, k, c.raw, strong())
	at := h.clock.Now().UTC()
	require.Equalf(t, http.StatusOK, r.status, "%s: повышение ключом — 200: %s", id, r.body)
	_, sessionLevel := ceremonyLevels(t, r.body)
	require.Equal(t, "2", sessionLevel, "%s: session.assuranceLevel", id)
	var out struct {
		Assurance struct {
			MissingForLevel2 []string `json:"missingForLevel2"`
		} `json:"assurance"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &out))
	require.Equal(t, []string{}, out.Assurance.MissingForLevel2, "%s: assurance.missingForLevel2 = []", id)
	fresh := rotated(t, id, r, s)

	_, lastUsed := h.keyRow(t, k.id)
	require.NotNil(t, lastUsed, "%s: AccessKey.lastUsedAt записан", id)
	require.WithinDuration(t, at, *lastUsed, time.Second, "%s: AccessKey.lastUsedAt — момент предъявления", id)
	requireLastJournal(t, id, h.journalOf(t, fresh), "webauthn", "accepted")
}

// TestSUA04_KeyWithoutBackupEligibilityRaisesToLevelThree — SUA-04; отличие от
// SUA-03 одно — флаги `UP|UV` без `BE`.
func TestSUA04_KeyWithoutBackupEligibilityRaisesToLevelThree(t *testing.T) {
	const id = "SUA-04"
	h := newSUAStand(t)
	p := h.person(t, "04")
	k := h.withKey(t, p)
	s := h.login(t, p)

	c := h.challenge(t, id, s)
	r := h.keyStepUp(t, id, s, k, c.raw, webauthntest.AssertionOptions{UserVerified: true})
	require.Equalf(t, http.StatusOK, r.status, "%s: повышение ключом — 200: %s", id, r.body)
	assuranceLevel, sessionLevel := ceremonyLevels(t, r.body)
	require.Equal(t, "3", sessionLevel, "%s: session.assuranceLevel", id)
	require.Equal(t, "3", assuranceLevel, "%s: assurance.level", id)
}

// TestSUA05_KeyRefreshesAKeyOnlyPersonsSession — SUA-05 (kaname#729).
func TestSUA05_KeyRefreshesAKeyOnlyPersonsSession(t *testing.T) {
	const id = "SUA-05"
	h := newSUAStand(t)
	p := h.person(t, "05")
	k := h.withKey(t, p)
	h.keyOnly(t, p)
	s := h.keyLogin(t, k, strong())
	require.Equal(t, "2", h.levelOf(t, s), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): вход ключом UP|UV|BE — «2»")
	other := h.keyLogin(t, k, strong())
	require.NotNil(t, other.bearer)
	h.clock.Advance(laneFreshness + time.Minute)

	endOthers := func(s laneSession) reply {
		return h.lane.do(t, h.c, http.MethodPost, osPathEndOthers,
			map[string]any{"csrfToken": h.csrfFor(t, domain.FormSessionEnd, s.form)}, fwd(), s.bearer, s.form)
	}
	stale := endOthers(s)
	require.Equalf(t, http.StatusForbidden, stale.status, "%s: несвежая сессия — 403: %s", id, stale.body)
	require.JSONEq(t, osBodyNotFresh, stale.body, "%s: SESSION_NOT_FRESH дословно", id)

	c := h.challenge(t, id, s)
	r := h.keyStepUp(t, id, s, k, c.raw, strong())
	require.Equalf(t, http.StatusOK, r.status, "%s: повышение ключом — 200: %s", id, r.body)
	_, sessionLevel := ceremonyLevels(t, r.body)
	require.Equal(t, "2", sessionLevel, "%s: уровень прежний — «2»", id)
	fresh := rotated(t, id, r, s)

	// Другие живые сессии человека — перепись до снятия: кроме сессии
	// `other` посева живёт и сессия, выданная регистрацией П-л (Ф4 выдаёт её
	// сразу), и снимаются ВСЕ другие (kaname#634).
	var others int
	require.NoError(t, h.pool.QueryRow(h.ctx, `
		SELECT count(*) FROM kaname.human_sessions
		 WHERE user_id = $1 AND ended_at IS NULL AND bearer_digest <> $2`,
		string(p.user), string(domain.PresentedSessionBearer(fresh.bearer.Value).Digest())).Scan(&others))
	require.GreaterOrEqual(t, others, 1, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): другая сессия посева жива")
	done := endOthers(fresh)
	require.Equalf(t, http.StatusOK, done.status, "%s: end-others после повышения — 200: %s", id, done.body)
	var out struct {
		Ended *int `json:"ended"`
	}
	require.NoError(t, json.Unmarshal([]byte(done.body), &out), done.body)
	require.NotNil(t, out.Ended, "%s: тело {ended: <число>}", id)
	require.Equal(t, others, *out.Ended, "%s: сняты все другие живые сессии", id)
	_, otherLive := h.rowByBearer(t, other.bearer.Value)
	require.True(t, otherLive, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): запись сессии other найдена")
	require.True(t, h.rowEnded(t, other), "%s: сессия other снята", id)
}

// TestSUA10_WrongCodeIsRefusedAndStampsNothing — SUA-10; близнец SUA-01 (верный
// код в той же сессии).
func TestSUA10_WrongCodeIsRefusedAndStampsNothing(t *testing.T) {
	const id = "SUA-10"
	h := newSUAStand(t)
	p := h.person(t, "10")
	h.withCode(t, p)
	s := h.login(t, p)
	_, beforeHas := field(h.status(t, s), "totp.lastUsedAt")

	r := h.stepUpCode(t, s, "totp", h.suaWrongCode(t, p))
	requireAuthFailed(t, id, r)
	require.Equal(t, "1", h.levelOf(t, s), "%s: уровень «1»", id)
	_, afterHas := field(h.status(t, s), "totp.lastUsedAt")
	require.Equal(t, beforeHas, afterHas, "%s: totp.lastUsedAt не изменился", id)
	requireLastJournal(t, id, h.journalOf(t, s), "totp", "refused")

	twin := h.stepUpCode(t, s, "totp", h.totpNow(t, p))
	require.Equalf(t, http.StatusOK, twin.status, "%s близнец: верный код — 200: %s", id, twin.body)
	momentOf(t, id, h.status(t, rotated(t, id, twin, s)), "totp.lastUsedAt")
}

// TestSUA11_ReplayedCodeIsRefused — SUA-11; близнец — первое предъявление.
func TestSUA11_ReplayedCodeIsRefused(t *testing.T) {
	const id = "SUA-11"
	h := newSUAStand(t)
	p := h.person(t, "11")
	h.withCode(t, p)
	s1 := h.login(t, p)
	s2 := h.login(t, p)
	code := h.totpNow(t, p)
	first := h.stepUpCode(t, s1, "totp", code)
	require.Equalf(t, http.StatusOK, first.status, "%s близнец: первое предъявление — 200: %s", id, first.body)

	again := h.stepUpCode(t, s2, "totp", code)
	requireAuthFailed(t, id, again)
	require.Equal(t, "1", h.levelOf(t, s2), "%s: S2 остаётся «1»", id)

	next := h.stepUpCode(t, s2, "totp", h.totpNow(t, p))
	require.Equalf(t, http.StatusOK, next.status, "%s: код следующей ступени в S2 — 200: %s", id, next.body)
}

// TestSUA12_SpentBackupCodeIsRefused — SUA-12; близнец SUA-02.
func TestSUA12_SpentBackupCodeIsRefused(t *testing.T) {
	const id = "SUA-12"
	h := newSUAStand(t)
	p := h.person(t, "12")
	h.withCode(t, p)
	s0 := h.login(t, p)
	spend := h.stepUpCode(t, s0, "lookup_secret", p.codes[0])
	require.Equalf(t, http.StatusOK, spend.status, "%s близнец SUA-02: — 200: %s", id, spend.body)

	s := h.login(t, p)
	r := h.stepUpCode(t, s, "lookup_secret", p.codes[0])
	requireAuthFailed(t, id, r)
	require.EqualValues(t, 9, requireDeclared(t, id, h.status(t, s), "backupCodeSet.remaining"), "%s: остаток не изменился", id)
}

// TestSUA13_KeyFromAForeignOriginIsRefused — SUA-13; близнец SUA-03, отличие —
// `origin` данных клиента.
func TestSUA13_KeyFromAForeignOriginIsRefused(t *testing.T) {
	const id = "SUA-13"
	h := newSUAStand(t)
	p := h.person(t, "13")
	k := h.withKey(t, p)
	s := h.login(t, p)

	c := h.challenge(t, id, s)
	r := h.keyStepUp(t, id, s, k, c.raw, webauthntest.AssertionOptions{UserVerified: true, BackupEligible: true, Origin: "https://elsewhere.example.invalid"})
	requireAuthFailed(t, id, r)
	require.Equal(t, "1", h.levelOf(t, s), "%s: уровень «1»", id)
	_, lastUsed := h.keyRow(t, k.id)
	require.Nil(t, lastUsed, "%s: AccessKey.lastUsedAt не изменился", id)

	again := h.stepUpKey(t, s, k, c.raw, strong())
	requireRefusalOf(t, id, again, http.StatusBadRequest, 9, suaReasonPresented, suaTextPresented)

	twin := h.keyStepUp(t, id, s, k, h.challenge(t, id, s).raw, strong())
	require.Equalf(t, http.StatusOK, twin.status, "%s близнец SUA-03: — 200: %s", id, twin.body)
}

// TestSUA14_AnotherPersonsKeyIsRefused — SUA-14; близнец SUA-03, отличие — чьё
// удостоверение.
func TestSUA14_AnotherPersonsKeyIsRefused(t *testing.T) {
	const id = "SUA-14"
	h := newSUAStand(t)
	a := h.person(t, "14a")
	ka := h.withKey(t, a)
	b := h.person(t, "14b")
	kb := h.withKey(t, b)
	s := h.login(t, a)

	c := h.challenge(t, id, s)
	r := h.keyStepUp(t, id, s, kb, c.raw, strong())
	requireAuthFailed(t, id, r)
	_, lastUsed := h.keyRow(t, kb.id)
	require.Nil(t, lastUsed, "%s: lastUsedAt ключа Б не изменился", id)

	twin := h.keyStepUp(t, id, s, ka, h.challenge(t, id, s).raw, strong())
	require.Equalf(t, http.StatusOK, twin.status, "%s близнец SUA-03: — 200: %s", id, twin.body)
}

// TestSUA15_RevokedKeyIsNotOfferedAndIsRefused — SUA-15; близнец — годный K2
// над тем же испытанием.
//
// «Дано: K1 снят» — писателем продукта, которым снимает `Revoke`
// (`revokeKey`, Ф7-25 ветвь «к»): предмет сценария — выдача и церемония, а не
// снятие.
func TestSUA15_RevokedKeyIsNotOfferedAndIsRefused(t *testing.T) {
	const id = "SUA-15"
	h := newSUAStand(t)
	p := h.person(t, "15")
	h.withCode(t, p)
	k1 := h.withKey(t, p)
	k2 := h.withKey(t, p)
	revokeKey(t, h.sessionLane, p.user, k1.id)
	s := h.login(t, p)

	c := h.challenge(t, id, s)
	require.Equal(t, []string{credentialIDOf(k2)}, c.allow, "%s: allowCredentials — ровно K2", id)
	r := h.keyStepUp(t, id, s, k1, c.raw, strong())
	requireAuthFailed(t, id, r)
	require.Equal(t, "1", h.levelOf(t, s), "%s: уровень «1»", id)
	requireLastJournal(t, id, h.journalOf(t, s), "webauthn", "refused")

	again := h.stepUpKey(t, s, k2, c.raw, strong())
	requireRefusalOf(t, id, again, http.StatusBadRequest, 9, suaReasonPresented, suaTextPresented)
	twin := h.keyStepUp(t, id, s, k2, h.challenge(t, id, s).raw, strong())
	require.Equalf(t, http.StatusOK, twin.status, "%s близнец: K2 — 200: %s", id, twin.body)
	_, lvl := ceremonyLevels(t, twin.body)
	require.Equal(t, "2", lvl, "%s близнец: уровень «2»", id)
}

// TestSUA16_ChallengeOfAnotherSessionIsNotFound — SUA-16; близнец по сессии.
func TestSUA16_ChallengeOfAnotherSessionIsNotFound(t *testing.T) {
	const id = "SUA-16"
	h := newSUAStand(t)
	p := h.person(t, "16")
	k := h.withKey(t, p)
	s1 := h.login(t, p)
	s2 := h.login(t, p)

	c := h.challenge(t, id, s1)
	addrBefore, srcBefore := h.failures(t, p)
	r := h.keyStepUp(t, id, s2, k, c.raw, strong())
	requireRefusalOf(t, id, r, http.StatusBadRequest, 9, suaReasonNotIssued, suaTextNotIssued)
	addrAfter, srcAfter := h.failures(t, p)
	require.Equal(t, addrBefore, addrAfter, "%s: попытки нет (адрес)", id)
	require.Equal(t, srcBefore, srcAfter, "%s: попытки нет (источник)", id)

	twin := h.keyStepUp(t, id, s1, k, c.raw, strong())
	require.Equalf(t, http.StatusOK, twin.status, "%s близнец: испытание S1 в S1 — 200: %s", id, twin.body)
	_, lvl := ceremonyLevels(t, twin.body)
	require.Equal(t, "2", lvl, "%s близнец: уровень «2»", id)
}

// TestSUA17_ReissuedChallengeSupersedesThePreviousOne — SUA-17.
func TestSUA17_ReissuedChallengeSupersedesThePreviousOne(t *testing.T) {
	const id = "SUA-17"
	h := newSUAStand(t)
	p := h.person(t, "17")
	k := h.withKey(t, p)
	s := h.login(t, p)

	e1 := h.challenge(t, id, s)
	e2 := h.challenge(t, id, s)
	require.NotEqual(t, e1.raw, e2.raw, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): две выдачи — два испытания")
	r1 := h.keyStepUp(t, id, s, k, e1.raw, strong())
	requireRefusalOf(t, id, r1, http.StatusBadRequest, 9, suaReasonNotIssued, suaTextNotIssued)
	r2 := h.keyStepUp(t, id, s, k, e2.raw, strong())
	require.Equalf(t, http.StatusOK, r2.status, "%s: утверждение над E2 — 200: %s", id, r2.body)
	_, lvl := ceremonyLevels(t, r2.body)
	require.Equal(t, "2", lvl, "%s: уровень «2»", id)
}

// TestSUA18_ExpiredChallengeIsRefused — SUA-18; близнец — свежее испытание.
func TestSUA18_ExpiredChallengeIsRefused(t *testing.T) {
	const id = "SUA-18"
	h := newSUAStand(t)
	p := h.person(t, "18")
	k := h.withKey(t, p)
	s := h.login(t, p)

	c := h.challenge(t, id, s)
	h.clock.Advance(access_keys.ChallengeTTL + time.Second)
	r := h.keyStepUp(t, id, s, k, c.raw, strong())
	requireRefusalOf(t, id, r, http.StatusBadRequest, 9, suaReasonExpired, suaTextExpired)

	twin := h.keyStepUp(t, id, s, k, h.challenge(t, id, s).raw, strong())
	require.Equalf(t, http.StatusOK, twin.status, "%s близнец: свежее испытание — 200: %s", id, twin.body)
}

// TestSUA19_FormRefusalsNameTheFieldAndCountNoAttempt — SUA-19; близнецы
// SUA-01 и SUA-03.
func TestSUA19_FormRefusalsNameTheFieldAndCountNoAttempt(t *testing.T) {
	const id = "SUA-19"
	h := newSUAStand(t)
	p := h.person(t, "19")
	h.withCode(t, p)
	k := h.withKey(t, p)
	s := h.login(t, p)
	cred := credentialBody(assertOver(t, k, []byte("sua-19-not-a-challenge"), strong()), k.handle)
	addrBefore, _ := h.failures(t, p)

	rows := []struct {
		name string
		body map[string]any
		want string
	}{
		{"без method", map[string]any{"code": "123456"}, "Illegal argument method: required"},
		{"method passkey", map[string]any{"method": "passkey"}, suaTextMethodVocabular},
		{"webauthn без credential", map[string]any{"method": "webauthn"}, "Illegal argument credential: required"},
		{"totp с credential", map[string]any{"method": "totp", "code": "123456", "credential": cred}, "Illegal argument credential: not accepted with method totp"},
		{"webauthn с code", map[string]any{"method": "webauthn", "credential": cred, "code": "123456"}, "Illegal argument code: not accepted with method webauthn"},
	}
	for _, row := range rows {
		body := map[string]any{"csrfToken": h.csrfFor(t, domain.FormStepUp, s.form)}
		for k, v := range row.body {
			body[k] = v
		}
		r := h.lane.do(t, h.c, http.MethodPost, suaPathStepUp, body, fwd(), s.bearer, s.form)
		if assert.Equalf(t, http.StatusBadRequest, r.status, "%s (%s): отказ формы — 400: %s", id, row.name, r.body) {
			ref := parseRefusal(t, r.body)
			assert.Equalf(t, 3, ref.Code, "%s (%s): code 3", id, row.name)
			assert.Equalf(t, row.want, ref.Message, "%s (%s): текст отказа формы", id, row.name)
		}
	}
	addrAfter, _ := h.failures(t, p)
	require.Equal(t, addrBefore, addrAfter, "%s: попыток ноль", id)
}

// TestSUA80_SignCountThatDidNotGrowIsRefusedAndSignalled — SUA-80; близнец
// SUA-03, отличие одно — счётчик утверждения не больше записанного.
func TestSUA80_SignCountThatDidNotGrowIsRefusedAndSignalled(t *testing.T) {
	const id = "SUA-80"
	rec := newSUARecorder()
	h := newSUAStandWith(t, suaOptions{observer: rec})
	p := h.person(t, "80")
	k := h.withKey(t, p)

	// Дано: ключ уже предъявлялся (SUA-03) — записанный счётчик > 0.
	s0 := h.login(t, p)
	first := h.keyStepUp(t, id, s0, k, h.challenge(t, id, s0).raw, strong())
	require.Equalf(t, http.StatusOK, first.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): первое предъявление ключа — 200: %s", first.body)
	stored, lastUsedBefore := h.keyRow(t, k.id)
	require.Positive(t, stored, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): записанный счётчик подписи > 0")
	clonesBefore := rec.clones()

	s := h.login(t, p)
	same := uint32(stored) // #nosec G115 -- счётчик схемы неотрицателен и помещается в uint32
	o := strong()
	o.SignCount = &same
	r := h.keyStepUp(t, id, s, k, h.challenge(t, id, s).raw, o)
	requireAuthFailed(t, id, r)
	require.Equal(t, "1", h.levelOf(t, s), "%s: уровень «1» — не изменился", id)
	storedAfter, lastUsedAfter := h.keyRow(t, k.id)
	require.Equal(t, stored, storedAfter, "%s: записанный счётчик не сдвинут", id)
	require.Equal(t, lastUsedBefore, lastUsedAfter, "%s: AccessKey.lastUsedAt не изменился", id)
	requireLastJournal(t, id, h.journalOf(t, s), "webauthn", "refused")
	require.Equal(t, clonesBefore+1, rec.clones(), "%s: сигнал клонирования SignCountRegressionObserved — один", id)
	require.Positive(t, rec.cell("webauthn×mismatched"), "%s: клетка webauthn × mismatched", id)

	twin := h.keyStepUp(t, id, s, k, h.challenge(t, id, s).raw, strong())
	require.Equalf(t, http.StatusOK, twin.status, "%s близнец SUA-03: счётчик больше записанного — 200: %s", id, twin.body)
	_, lvl := ceremonyLevels(t, twin.body)
	require.Equal(t, "2", lvl, "%s близнец: уровень «2»", id)
}

// TestSUA80_LostCounterRaceIsRefused — SUA-80 (§8 п.1, отдельный случай Р3):
// два утверждения одного ключа с ОДНИМ и тем же выросшим счётчиком в двух
// сессиях параллельно — ровно одно 200, второе — суждённый отказ 401; ровно
// одна сессия поднята.
//
// Граница пробы: какая из двух ветвей отказа (счётчик не вырос — с сигналом
// клонирования; сдвиг проигран — без сигнала) достанется второму, решает
// порядок фиксации, и без шва внутри хранилища ключей повышения детерминированно
// его не построить; шов называет замысел (вопрос к замыслу в возврате полосы).
// Здесь утверждается инвариант, общий обеим ветвям, и потолок сигнала — не
// больше одного.
func TestSUA80_LostCounterRaceIsRefused(t *testing.T) {
	const id = "SUA-80 гонка"
	rec := newSUARecorder()
	h := newSUAStandWith(t, suaOptions{observer: rec})
	p := h.person(t, "80r")
	k := h.withKey(t, p)
	s0 := h.login(t, p)
	first := h.keyStepUp(t, id, s0, k, h.challenge(t, id, s0).raw, strong())
	require.Equalf(t, http.StatusOK, first.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): первое предъявление ключа — 200: %s", first.body)
	stored, _ := h.keyRow(t, k.id)

	s1, s2 := h.login(t, p), h.login(t, p)
	c1, c2 := h.challenge(t, id, s1), h.challenge(t, id, s2)
	next := uint32(stored) + 1 // #nosec G115 -- счётчик схемы помещается в uint32
	o := strong()
	o.SignCount = &next
	bodies := make([]map[string]any, 2)
	for i, c := range [][]byte{c1.raw, c2.raw} {
		as := assertOver(t, k, c, o)
		bodies[i] = map[string]any{"method": "webauthn", "credential": credentialBody(as, k.handle)}
	}
	sessions := []laneSession{s1, s2}
	for i := range bodies {
		bodies[i]["csrfToken"] = h.csrfFor(t, domain.FormStepUp, sessions[i].form)
	}
	clonesBefore := rec.clones()
	replies := make([]reply, 2)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range bodies {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			replies[i] = h.lane.do(t, h.c, http.MethodPost, suaPathStepUp, bodies[i], fwd(), sessions[i].bearer, sessions[i].form)
		}(i)
	}
	close(start)
	wg.Wait()
	for _, r := range replies {
		requireKeyAccepted(t, id, r)
	}

	ok, refused := 0, 0
	for _, r := range replies {
		switch r.status {
		case http.StatusOK:
			ok++
		case http.StatusUnauthorized:
			require.JSONEq(t, suaBodyAuthFailed, r.body, "%s: второе — суждённый отказ", id)
			refused++
		default:
			t.Fatalf("%s: исход вне двух: %d %s", id, r.status, r.body)
		}
	}
	require.Equal(t, 1, ok, "%s: ровно одно 200", id)
	require.Equal(t, 1, refused, "%s: ровно один 401", id)
	// Поднятая сессия перевыпустила носитель (Ф11 Р5): её запись читается по
	// новому носителю из ответа, отказанная — по прежнему.
	raised := 0
	for i, s := range sessions {
		if replies[i].status == http.StatusOK {
			s = rotated(t, id, replies[i], s)
		}
		if h.levelOf(t, s) == "2" {
			raised++
		}
	}
	require.Equal(t, 1, raised, "%s: поднята ровно одна сессия", id)
	got, _ := h.keyRow(t, k.id)
	require.EqualValues(t, next, got, "%s: счётчик сдвинут ровно до присланного", id)
	require.LessOrEqual(t, rec.clones()-clonesBefore, 1, "%s: сигнал клонирования — не больше одного", id)
}

// suaLostAdvance — шов «сдвиг проигран» (замысел §2.3): декоратор порта
// хранилища ветви ключа над НАСТОЯЩИМ адаптером. Взведённый, он отдаёт
// прочитанную строку ключа и перед возвратом фиксирует НАСТОЯЩИМ оператором
// хранилища ключей сдвиг того же ключа на присланное значение — так, как это
// сделало бы утверждение соседней сессии. Ветвь повышения видит «растёт» по
// прочитанному и проигрывает оператору внутри своей транзакции.
type suaLostAdvance struct {
	humansession.StepUpChallengeStore
	keys  *kanamepg.AccessKeyRepo
	now   func() time.Time
	to    uint32
	armed atomic.Bool
	fired atomic.Int32
}

func (d *suaLostAdvance) KeyByCredentialID(ctx context.Context, id []byte) (domain.AccessKey, bool, error) {
	k, ok, err := d.StepUpChallengeStore.KeyByCredentialID(ctx, id)
	if err != nil || !ok || !d.armed.Swap(false) {
		return k, ok, err
	}
	w, err := d.keys.Writer(ctx)
	if err != nil {
		return domain.AccessKey{}, false, err
	}
	defer func() { _ = w.Rollback(ctx) }()
	advanced, err := w.AdvanceSignCount(ctx, k.ID, k.SignCount, d.to, d.now())
	if err != nil {
		return domain.AccessKey{}, false, err
	}
	if !advanced {
		return domain.AccessKey{}, false, fmt.Errorf("шов пробы: сдвиг соседа не лёг")
	}
	if err := w.Commit(ctx); err != nil {
		return domain.AccessKey{}, false, err
	}
	d.fired.Add(1)
	return k, ok, nil
}

// TestSUA80_LostAdvanceIsRefusedWithoutTheCloneSignal — SUA-80, ветвь «сдвиг
// проигран» детерминированно (замысел §2.3): чтение строки ключа показало
// «растёт», а условный оператор сдвига внутри транзакции предъявления дал ноль
// строк. Исход — тот же 401, что у «не вырос», те же следствия, и БЕЗ сигнала
// клонирования. Близнец — тот же человек и тот же присланный рост без
// вмешательства шва: 200 и «2».
func TestSUA80_LostAdvanceIsRefusedWithoutTheCloneSignal(t *testing.T) {
	const id = "SUA-80 проигран"
	rec := newSUARecorder()
	dec := &suaLostAdvance{}
	h := newSUAStandWith(t, suaOptions{observer: rec, stepUpKeys: func(in humansession.StepUpChallengeStore) humansession.StepUpChallengeStore {
		dec.StepUpChallengeStore = in
		return dec
	}})
	dec.keys, dec.now = kanamepg.NewAccessKeyRepo(h.pool), h.clock.Now
	p := h.person(t, "80l")
	k := h.withKey(t, p)
	s0 := h.login(t, p)
	first := h.keyStepUp(t, id, s0, k, h.challenge(t, id, s0).raw, strong())
	require.Equalf(t, http.StatusOK, first.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): первое предъявление ключа — 200: %s", first.body)
	stored, _ := h.keyRow(t, k.id)
	require.Positive(t, stored, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): записанный счётчик подписи > 0")

	s := h.login(t, p)
	c := h.challenge(t, id, s)
	next := uint32(stored) + 1 // #nosec G115 -- счётчик схемы помещается в uint32
	o := strong()
	o.SignCount = &next
	dec.to = next
	dec.armed.Store(true)
	clonesBefore, mismatchedBefore := rec.clones(), rec.cell("webauthn×mismatched")
	addrBefore, _ := h.failures(t, p)
	r := h.keyStepUp(t, id, s, k, c.raw, o)
	require.EqualValues(t, 1, dec.fired.Load(), "НЕ-ВЫПОЛНИЛОСЬ(шов): сосед сдвинул счётчик между чтением и оператором")
	requireAuthFailed(t, id, r)
	require.Equal(t, "1", h.levelOf(t, s), "%s: уровень «1» — транзакция предъявления откачена", id)
	got, _ := h.keyRow(t, k.id)
	require.EqualValues(t, next, got, "%s: счётчик — сдвиг соседа, отказавшее предъявление второго сдвига не сделало", id)
	requireLastJournal(t, id, h.journalOf(t, s), "webauthn", "refused")
	addrAfter, _ := h.failures(t, p)
	require.Equal(t, addrBefore+1, addrAfter, "%s: след попытки +1", id)
	require.Equal(t, clonesBefore, rec.clones(), "%s: сигнала клонирования у проигранного сдвига нет", id)
	require.Greater(t, rec.cell("webauthn×mismatched"), mismatchedBefore, "%s: клетка webauthn × mismatched", id)

	twinCount := next + 1
	ot := strong()
	ot.SignCount = &twinCount
	twin := h.keyStepUp(t, id, s, k, h.challenge(t, id, s).raw, ot)
	require.Equalf(t, http.StatusOK, twin.status, "%s близнец: шов не вмешан — 200: %s", id, twin.body)
	_, lvl := ceremonyLevels(t, twin.body)
	require.Equal(t, "2", lvl, "%s близнец: уровень «2»", id)
	require.Equal(t, clonesBefore, rec.clones(), "%s близнец: сигнала нет", id)
}
