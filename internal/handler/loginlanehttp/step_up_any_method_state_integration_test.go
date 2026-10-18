// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// step_up_any_method_state_integration_test.go — способ не заведён, ключи
// выключены, перечень доступных способов, моменты, заведение и снятие, набор
// запасных кодов, счёт попыток (задача PRO-Robotech/kaname#827; приёмка
// `docs/engineering/acceptance/step-up-with-any-enrolled-method.md`, редакция 3,
// отпечаток 35224856…, §3.3…§3.8: SUA-20…24, 30…33, 40, 41, 50…52, 60, 61,
// 70…73; решения Р5…Р9). Стенд и слова ступеней —
// `step_up_any_method_harness_integration_test.go`.
//
// # Посев «выкл»
//
// Стенд собирается с перечнем происхождений «никого» (Ф7 Р2) над своей базой;
// ключ П-кл кладёт писатель продукта — тот же, что при непустом перечне.
//
// # Где граница пробы
//
// SUA-22, строки `Revoke` из сессии «1» и её близнец: пол «2» глагола `Revoke`
// судит страж уровня на gRPC и край (Ф11 Р11, форма — край
// `gateway/internal/middleware/auth_stepup.go`), а не полоса формы; их держит
// сквозная проба края newman SUA-22 (§8 п.2). Здесь — ответ состояния,
// выдача и перечень.
//
// # Чем краснеет ДО кода
//
// Ключей `stepUpMethods`, `accessKeys.available`, моментов в ответе состояния
// нет, путь выдачи испытания не смонтирован, отказа `ACCESS_KEYS_DISABLED` нет
// ни у одной выдачи — «ЧЕСТНЫЙ-КРАСНЫЙ» либо утверждение предмета. SUA-20,
// SUA-70, SUA-71 утверждают поведение, которое уже есть, и зелены до кода.
//
// Run: `go test ./internal/handler/loginlanehttp/ -run 'TestSUA' -count=1`
// (нужен Docker); под -short пропускается.
package loginlanehttp_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

// keyDepsOf — зависимости глаголов ключа Ф7 стенда; keysOff — перечень
// происхождений «никого».
func (h *suaStand) keyDepsOf(keysOff bool) access_keys.Deps {
	d := h.keyDeps()
	d.Now = h.clock.Now
	if keysOff {
		b := laneKeyBinding()
		b.Origins = []string{}
		d.Binding = b
	}
	return d
}

// requireGRPCRefusal — отказ глагола gRPC: код, причина и текст дословно.
func requireGRPCRefusal(t *testing.T, id string, err error, code codes.Code, reason, text string) {
	t.Helper()
	require.Errorf(t, err, "%s: ждался отказ %s, глагол прошёл", id, reason)
	st, ok := status.FromError(err)
	require.Truef(t, ok, "%s: отказ — статус gRPC: %v", id, err)
	require.Equalf(t, code, st.Code(), "%s: код отказа: %v", id, err)
	require.Equalf(t, text, st.Message(), "%s: текст отказа", id)
	var got string
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			got = info.GetReason()
		}
	}
	require.Equalf(t, reason, got, "%s: причина отказа", id)
}

// TestSUA20_CodeIsNotEnrolled — SUA-20; близнец SUA-01.
func TestSUA20_CodeIsNotEnrolled(t *testing.T) {
	const id = "SUA-20"
	h := newSUAStand(t)
	p := h.person(t, "20")
	h.withKey(t, p)
	s := h.login(t, p)
	addrBefore, _ := h.failures(t, p)

	r := h.stepUpCode(t, s, "totp", "123456")
	requireRefusalOf(t, id, r, http.StatusBadRequest, 9, suaReasonNotEnrolled, suaTextNotEnrolled)
	addrAfter, _ := h.failures(t, p)
	require.Equal(t, addrBefore, addrAfter, "%s: попытки нет", id)

	q := h.person(t, "20twin")
	h.withCode(t, q)
	twin := h.stepUpCode(t, h.login(t, q), "totp", h.totpNow(t, q))
	require.Equalf(t, http.StatusOK, twin.status, "%s близнец SUA-01: — 200: %s", id, twin.body)
}

// TestSUA21_NoKeyIsRegistered — SUA-21; близнец SUA-03 (выдача).
func TestSUA21_NoKeyIsRegistered(t *testing.T) {
	const id = "SUA-21"
	h := newSUAStand(t)
	p := h.person(t, "21")
	h.withCode(t, p)
	s := h.login(t, p)
	addrBefore, _ := h.failures(t, p)

	r := h.begin(t, s)
	requireBeginMounted(t, id, r)
	requireRefusalOf(t, id, r, http.StatusBadRequest, 9, suaReasonNoKey, suaTextNoKey)
	addrAfter, _ := h.failures(t, p)
	require.Equal(t, addrBefore, addrAfter, "%s: попытки нет", id)

	k := h.withKey(t, p)
	c := h.challenge(t, id, s)
	require.Equal(t, []string{credentialIDOf(k)}, c.allow, "%s близнец: ключ заведён — испытание выдано", id)
}

// TestSUA22_KeysTurnedOffOnTheInstallation — SUA-22; близнец — тот же человек
// на установке с непустым перечнем.
func TestSUA22_KeysTurnedOffOnTheInstallation(t *testing.T) {
	const id = "SUA-22"
	off := newSUAStandWith(t, suaOptions{keysOff: true})
	p := off.person(t, "22")
	k := off.withKey(t, p)
	s := off.login(t, p)

	st := off.status(t, s)
	require.Equal(t, false, requireDeclared(t, id, st, "accessKeys.available"), "%s: accessKeys.available", id)
	require.Equal(t, []string{}, methodsOf(t, id, st), "%s: stepUpMethods", id)
	r := off.begin(t, s)
	requireBeginMounted(t, id, r)
	requireRefusalOf(t, id, r, http.StatusBadRequest, 9, suaReasonKeysOff, suaTextKeysOff)

	list, err := access_keys.NewListUseCase(off.keyDepsOf(true))
	require.NoError(t, err)
	keys, _, err := list.Execute(off.ctx, access_keys.ListInput{UserID: p.user})
	require.NoError(t, err, "%s: перечень ключей работает", id)
	require.Len(t, keys, 1, "%s: перечень несёт ключ П-кл", id)
	require.Equal(t, k.id, keys[0].ID, "%s: перечень несёт ключ П-кл", id)

	on := newSUAStand(t)
	q := on.person(t, "22twin")
	on.withKey(t, q)
	sq := on.login(t, q)
	twin := on.status(t, sq)
	require.Equal(t, true, requireDeclared(t, id, twin, "accessKeys.available"), "%s близнец: accessKeys.available", id)
	require.Equal(t, []string{"webauthn"}, methodsOf(t, id, twin), "%s близнец: stepUpMethods", id)
}

// TestSUA23_RegistrationIsRefusedWhenKeysAreOff — SUA-23; близнец Ф7-01.
func TestSUA23_RegistrationIsRefusedWhenKeysAreOff(t *testing.T) {
	const id = "SUA-23"
	off := newSUAStandWith(t, suaOptions{keysOff: true})
	p := off.person(t, "23")
	off.withCode(t, p)
	off.raiseByCode(t, p, off.login(t, p))

	begin, err := access_keys.NewBeginRegistrationUseCase(off.keyDepsOf(true))
	require.NoError(t, err)
	_, err = begin.Execute(off.ctx, access_keys.BeginRegistrationInput{UserID: p.user, Actor: p.user})
	requireGRPCRefusal(t, id, err, codes.FailedPrecondition, suaReasonKeysOff, suaTextKeysOff)

	twin, err := access_keys.NewBeginRegistrationUseCase(off.keyDepsOf(false))
	require.NoError(t, err)
	out, err := twin.Execute(off.ctx, access_keys.BeginRegistrationInput{UserID: p.user, Actor: p.user})
	require.NoError(t, err, "%s близнец Ф7-01: перечень непуст — испытание выдано", id)
	require.NotEmpty(t, out.Challenge, "%s близнец: испытание выдано", id)
}

// TestSUA24_KeyLoginIsRefusedWhenKeysAreOff — SUA-24; близнец Ф13-01.
func TestSUA24_KeyLoginIsRefusedWhenKeysAreOff(t *testing.T) {
	const id = "SUA-24"
	off := newSUAStandWith(t, suaOptions{keysOff: true})
	_, srcBefore := off.failures(t, &suaPerson{email: "nobody@example.invalid"})
	f := givenAKForm(t, off.sessionLane)
	r := akBegin(t, off.sessionLane, f, map[string]any{"csrfToken": f.begin})
	requireRefusalOf(t, id, r, http.StatusBadRequest, 9, suaReasonKeysOff, suaTextKeysOff)
	_, srcAfter := off.failures(t, &suaPerson{email: "nobody@example.invalid"})
	require.Equal(t, srcBefore, srcAfter, "%s: попытка по источнику не записана", id)

	on := newSUAStand(t)
	g := givenAKForm(t, on.sessionLane)
	twin := akBegin(t, on.sessionLane, g, map[string]any{"csrfToken": g.begin})
	require.Equalf(t, http.StatusOK, twin.status, "%s близнец Ф13-01: — 200: %s", id, twin.body)
}

// TestSUA30_StepUpMethodsNameWhatEachPersonCanPresent — SUA-30.
func TestSUA30_StepUpMethodsNameWhatEachPersonCanPresent(t *testing.T) {
	const id = "SUA-30"
	h := newSUAStand(t)
	ckl := h.person(t, "30ckl")
	h.withCode(t, ckl)
	h.withKey(t, ckl)
	ck := h.person(t, "30ck")
	h.withCode(t, ck)
	kl := h.person(t, "30kl")
	h.withKey(t, kl)
	pp := h.person(t, "30p")

	for _, row := range []struct {
		name string
		p    *suaPerson
		want []string
	}{
		{"П-ккл", ckl, []string{"lookup_secret", "totp", "webauthn"}},
		{"П-к", ck, []string{"lookup_secret", "totp"}},
		{"П-кл", kl, []string{"webauthn"}},
		{"П-п", pp, []string{}},
	} {
		require.Equal(t, row.want, methodsOf(t, id+" "+row.name, h.status(t, h.login(t, row.p))), "%s %s: stepUpMethods", id, row.name)
	}
}

// TestSUA31_ExhaustedSetLeavesOnlyTheCode — SUA-31; близнец SUA-30 (П-к).
func TestSUA31_ExhaustedSetLeavesOnlyTheCode(t *testing.T) {
	const id = "SUA-31"
	h := newSUAStand(t)
	p := h.person(t, "31")
	h.withCode(t, p)
	s := h.login(t, p)
	require.Equal(t, []string{"lookup_secret", "totp"}, methodsOf(t, id, h.status(t, s)), "%s близнец SUA-30: до траты", id)
	for i, code := range p.codes {
		r := h.stepUpCode(t, s, "lookup_secret", code)
		require.Equalf(t, http.StatusOK, r.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): трата кода %d: %s", i+1, r.body)
		s = rotated(t, id, r, s)
	}
	st := h.status(t, s)
	require.EqualValues(t, 0, requireDeclared(t, id, st, "backupCodes.remaining"), "%s: остаток — ноль числом", id)
	require.Equal(t, []string{"totp"}, methodsOf(t, id, st), "%s: stepUpMethods", id)
}

// TestSUA32_AnyOfSeveralMethodsPasses — SUA-32.
func TestSUA32_AnyOfSeveralMethodsPasses(t *testing.T) {
	const id = "SUA-32"
	h := newSUAStand(t)
	p := h.person(t, "32")
	h.withCode(t, p)
	k := h.withKey(t, p)

	r1 := h.stepUpCode(t, h.login(t, p), "totp", h.totpNow(t, p))
	r2 := h.stepUpCode(t, h.login(t, p), "lookup_secret", p.codes[0])
	s3 := h.login(t, p)
	r3 := h.keyStepUp(t, id, s3, k, h.challenge(t, id, s3).raw, strong())
	for name, r := range map[string]reply{"totp": r1, "lookup_secret": r2, "webauthn": r3} {
		require.Equalf(t, http.StatusOK, r.status, "%s %s: — 200: %s", id, name, r.body)
		_, lvl := ceremonyLevels(t, r.body)
		require.Equal(t, "2", lvl, "%s %s: уровень «2»", id, name)
	}
}

// TestSUA33_WhatIsMissingNamesTheKey — SUA-33; близнец П-п.
func TestSUA33_WhatIsMissingNamesTheKey(t *testing.T) {
	const id = "SUA-33"
	h := newSUAStand(t)
	kl := h.person(t, "33kl")
	h.withKey(t, kl)
	pp := h.person(t, "33p")

	password := func(s laneSession) reply {
		return h.lane.do(t, h.c, http.MethodPost, suaPathStepUp,
			map[string]any{"method": "password", "password": integrationPassword, "csrfToken": h.csrfFor(t, domain.FormStepUp, s.form)},
			fwd(), s.bearer, s.form)
	}
	twin := password(h.login(t, pp))
	require.Equalf(t, http.StatusOK, twin.status, "%s близнец П-п: — 200: %s", id, twin.body)
	require.JSONEq(t, `{"level":"1","level2Reachable":false,"missingForLevel2":[]}`, assuranceOf(t, twin.body), "%s близнец П-п", id)

	r := password(h.login(t, kl))
	require.Equalf(t, http.StatusOK, r.status, "%s: — 200: %s", id, r.body)
	require.JSONEq(t, `{"level":"1","level2Reachable":true,"missingForLevel2":["webauthn"]}`, assuranceOf(t, r.body), "%s: assurance П-кл", id)
}

// TestSUA40_NoMomentsRightAfterConfirmation — SUA-40; близнецы SUA-01, SUA-02.
func TestSUA40_NoMomentsRightAfterConfirmation(t *testing.T) {
	const id = "SUA-40"
	h := newSUAStand(t)
	p := h.person(t, "40")
	h.withCode(t, p)
	s := h.login(t, p)

	st := h.status(t, s)
	require.Equal(t, true, requireDeclared(t, id, st, "totp.enrolled"), "%s: totp.enrolled", id)
	confirmed := momentOf(t, id, st, "totp.confirmedAt")
	_, has := field(st, "totp.lastUsedAt")
	require.False(t, has, "%s: ключа totp.lastUsedAt нет", id)
	require.EqualValues(t, 10, requireDeclared(t, id, st, "backupCodes.remaining"), "%s: backupCodes.remaining", id)
	require.EqualValues(t, 10, requireDeclared(t, id, st, "backupCodes.total"), "%s: backupCodes.total", id)
	issuedAt := momentOf(t, id, st, "backupCodes.issuedAt")
	require.False(t, issuedAt.After(confirmed), "%s: issuedAt ≤ confirmedAt до секунды", id)
	_, has = field(st, "backupCodes.lastUsedAt")
	require.False(t, has, "%s: ключа backupCodes.lastUsedAt нет", id)

	r := h.stepUpCode(t, s, "totp", h.totpNow(t, p))
	require.Equalf(t, http.StatusOK, r.status, "%s близнец SUA-01: — 200: %s", id, r.body)
	s = rotated(t, id, r, s)
	r = h.stepUpCode(t, s, "lookup_secret", p.codes[0])
	require.Equalf(t, http.StatusOK, r.status, "%s близнец SUA-02: — 200: %s", id, r.body)
	after := h.status(t, rotated(t, id, r, s))
	momentOf(t, id, after, "totp.lastUsedAt")
	momentOf(t, id, after, "backupCodes.lastUsedAt")
}

// TestSUA41_LoginWithTheSecondFactorStampsTheCode — SUA-41.
func TestSUA41_LoginWithTheSecondFactorStampsTheCode(t *testing.T) {
	const id = "SUA-41"
	h := newSUAStand(t)
	p := h.person(t, "41")
	h.withCode(t, p)

	tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
	r := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathLogin, map[string]any{
		"email": p.email, "password": integrationPassword, "csrfToken": tok,
		"secondFactor": map[string]string{"method": "totp", "code": h.totpNow(t, p)},
	}, fwd(), ctxCk)
	at := h.clock.Now().UTC().Truncate(time.Second)
	require.Equalf(t, http.StatusOK, r.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): вход паролем и кодом: %s", r.body)
	s := laneSession{bearer: cookieNamed(r.cookies, loginlanehttp.CookieSession), form: cookieNamed(r.cookies, loginlanehttp.CookieForm)}
	require.Equal(t, at, momentOf(t, id, h.status(t, s), "totp.lastUsedAt"), "%s: totp.lastUsedAt — момент входа", id)
}

// TestSUA50_KeyMakesLevelTwoEnrolmentReachable — SUA-50 (kacho#3196).
func TestSUA50_KeyMakesLevelTwoEnrolmentReachable(t *testing.T) {
	const id = "SUA-50"
	h := newSUAStand(t)
	p := h.person(t, "50")
	k := h.withKey(t, p)
	s := h.login(t, p)

	enroll := func(s laneSession) reply {
		return h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathSecondFactorEnroll,
			map[string]any{"csrfToken": h.csrfFor(t, domain.FormSecondFactor, s.form)}, fwd(), s.bearer, s.form)
	}
	requireStepUpIndication(t, enroll(s), id+": enroll из «1» у личности с ключом")

	r := h.keyStepUp(t, id, s, k, h.challenge(t, id, s).raw, strong())
	require.Equalf(t, http.StatusOK, r.status, "%s: повышение ключом — 200: %s", id, r.body)
	s = rotated(t, id, r, s)
	en := enroll(s)
	require.Equalf(t, http.StatusOK, en.status, "%s: enroll из «2» — 200: %s", id, en.body)
	p.secret = secretOf(t, en)
	conf := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathSecondFactorConfirm,
		map[string]any{"code": h.totpNow(t, p), "csrfToken": h.csrfFor(t, domain.FormSecondFactor, s.form)}, fwd(), s.bearer, s.form)
	require.Equalf(t, http.StatusOK, conf.status, "%s: confirm — 200: %s", id, conf.body)
	st := h.status(t, rotated(t, id, conf, s))
	require.Equal(t, true, requireDeclared(t, id, st, "totp.enrolled"), "%s: totp.enrolled", id)
	require.Equal(t, []string{"lookup_secret", "totp", "webauthn"}, methodsOf(t, id, st), "%s: stepUpMethods", id)
}

// TestSUA51_LastSignInMethodIsNotRevoked — SUA-51; близнец — снятие у П-кл.
func TestSUA51_LastSignInMethodIsNotRevoked(t *testing.T) {
	const id = "SUA-51"
	h := newSUAStand(t)
	revoke := func(p *suaPerson, k akKey) (*operations.Operation, error) {
		uc, err := access_keys.NewRevokeUseCase(h.keyDepsOf(false), operations.NewRepo(h.pool, "kaname"))
		require.NoError(t, err)
		return uc.Execute(h.ctx, access_keys.RevokeInput{UserID: p.user, Actor: p.user, AccessKeyID: string(k.id)})
	}

	l := h.person(t, "51l")
	kl := h.withKey(t, l)
	h.keyOnly(t, l)
	h.keyLogin(t, kl, strong())
	_, err := revoke(l, kl)
	requireGRPCRefusal(t, id, err, codes.FailedPrecondition, "LAST_SIGN_IN_METHOD",
		"last sign-in method cannot be revoked: enrol another sign-in method first")
	require.Equal(t, 1, h.keysOf(t, l.user), "%s: ключ в перечне", id)

	p := h.person(t, "51kl")
	k := h.withKey(t, p)
	h.keyLogin(t, k, strong())
	op, err := revoke(p, k)
	require.NoErrorf(t, err, "%s близнец: Revoke у П-кл принят", id)
	got := h.awaitOp(t, op.ID)
	require.Nilf(t, got.Error, "%s близнец: операция done без ошибки", id)
	s := h.login(t, p)
	require.Equal(t, []string{}, methodsOf(t, id, h.status(t, s)), "%s близнец: stepUpMethods = []", id)
	r := h.lane.do(t, h.c, http.MethodPost, suaPathStepUp,
		map[string]any{"method": "password", "password": integrationPassword, "csrfToken": h.csrfFor(t, domain.FormStepUp, s.form)},
		fwd(), s.bearer, s.form)
	require.Equalf(t, http.StatusOK, r.status, "%s близнец: повышение паролем — 200: %s", id, r.body)
	require.JSONEq(t, `{"level":"1","level2Reachable":false,"missingForLevel2":[]}`, assuranceOf(t, r.body), "%s близнец: level2Reachable — false", id)
}

// TestSUA52_CodeIsRemovedOnlyByTheCode — SUA-52.
func TestSUA52_CodeIsRemovedOnlyByTheCode(t *testing.T) {
	const id = "SUA-52"
	h := newSUAStand(t)
	p := h.person(t, "52")
	h.withCode(t, p)
	k := h.withKey(t, p)
	s := h.login(t, p)
	r := h.keyStepUp(t, id, s, k, h.challenge(t, id, s).raw, strong())
	require.Equalf(t, http.StatusOK, r.status, "%s: Дано — сессия поднята ключом: %s", id, r.body)
	s = rotated(t, id, r, s)

	remove := func(code string) reply {
		return h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathSecondFactorRemove,
			map[string]any{"method": "totp", "code": code, "csrfToken": h.csrfFor(t, domain.FormSecondFactor, s.form)}, fwd(), s.bearer, s.form)
	}
	wrong := remove(h.suaWrongCode(t, p))
	requireAuthFailed(t, id, wrong)
	require.Equal(t, true, requireDeclared(t, id, h.status(t, s), "totp.enrolled"), "%s: фактор на месте", id)

	right := remove(h.totpNow(t, p))
	require.Equalf(t, http.StatusOK, right.status, "%s: remove верным кодом — 200: %s", id, right.body)
	require.Equal(t, []string{"webauthn"}, methodsOf(t, id, h.status(t, rotated(t, id, right, s))), "%s: stepUpMethods", id)
}

// TestSUA60_BackupCodesAreShownOnce — SUA-60.
func TestSUA60_BackupCodesAreShownOnce(t *testing.T) {
	const id = "SUA-60"
	h := newSUAStand(t)
	p := h.person(t, "60")
	h.withCode(t, p)
	require.Len(t, p.codes, 10, "%s: тело confirm несёт 10 кодов", id)
	st := h.status(t, h.login(t, p))
	momentOf(t, id, st, "backupCodes.issuedAt")
	raw, ok := field(st, "backupCodes")
	require.True(t, ok, "%s: объект backupCodes", id)
	obj, ok := raw.(map[string]any)
	require.True(t, ok, "%s: backupCodes — объект", id)
	keys := []string{}
	for k := range obj {
		keys = append(keys, k)
	}
	require.ElementsMatch(t, []string{"remaining", "total", "issuedAt"}, keys, "%s: ровно ключи remaining, total, issuedAt", id)
}

// TestSUA61_RegenerationRetiresThePreviousSet — SUA-61; близнец — новый код.
func TestSUA61_RegenerationRetiresThePreviousSet(t *testing.T) {
	const id = "SUA-61"
	h := newSUAStand(t)
	p := h.person(t, "61")
	h.withCode(t, p)
	old := p.codes[0]
	s := h.raiseByCode(t, p, h.login(t, p))
	before := momentOf(t, id, h.status(t, s), "backupCodes.issuedAt")
	h.clock.Advance(2 * time.Second)

	r := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathSecondFactorBackupCodes,
		map[string]any{"method": "totp", "code": h.totpNow(t, p), "csrfToken": h.csrfFor(t, domain.FormSecondFactor, s.form)}, fwd(), s.bearer, s.form)
	require.Equalf(t, http.StatusOK, r.status, "%s: перевыпуск — 200: %s", id, r.body)
	var out struct {
		BackupCodes []string `json:"backupCodes"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &out))
	require.Len(t, out.BackupCodes, 10, "%s: 10 новых кодов", id)
	s = rotated(t, id, r, s)
	st := h.status(t, s)
	require.True(t, momentOf(t, id, st, "backupCodes.issuedAt").After(before), "%s: issuedAt сдвинут", id)
	_, has := field(st, "backupCodes.lastUsedAt")
	require.False(t, has, "%s: ключа backupCodes.lastUsedAt нет", id)

	requireAuthFailed(t, id, h.stepUpCode(t, h.login(t, p), "lookup_secret", old))
	twin := h.stepUpCode(t, h.login(t, p), "lookup_secret", out.BackupCodes[0])
	require.Equalf(t, http.StatusOK, twin.status, "%s близнец: новый код — 200: %s", id, twin.body)
}

// TestSUA70_SixthPresentationIsRefusedEvenWithTheRightCode — SUA-70.
func TestSUA70_SixthPresentationIsRefusedEvenWithTheRightCode(t *testing.T) {
	const id = "SUA-70"
	h := newSUAStand(t)
	p := h.person(t, "70")
	h.withCode(t, p)
	s := h.login(t, p)
	for i := 0; i < h.limits.AddressAttempts; i++ {
		requireAuthFailed(t, id, h.stepUpCode(t, s, "totp", h.suaWrongCode(t, p)))
	}
	r := h.stepUpCode(t, s, "totp", h.totpNow(t, p))
	requireRefusalOf(t, id, r, http.StatusTooManyRequests, 8, suaReasonTooMany, suaTextTooMany)
	after, err := strconv.Atoi(r.header.Get("Retry-After"))
	require.NoErrorf(t, err, "%s: Retry-After — целое: %q", id, r.header.Get("Retry-After"))
	require.GreaterOrEqual(t, after, 1, "%s: Retry-After ≥ 1", id)
	require.LessOrEqual(t, after, 900, "%s: Retry-After ≤ 900", id)
	require.Equal(t, "1", h.levelOf(t, s), "%s: уровень «1»", id)
}

// TestSUA71_FourWrongCodesLetTheFifthPass — SUA-71; близнец SUA-70.
func TestSUA71_FourWrongCodesLetTheFifthPass(t *testing.T) {
	const id = "SUA-71"
	h := newSUAStand(t)
	p := h.person(t, "71")
	h.withCode(t, p)
	s := h.login(t, p)
	for i := 0; i < h.limits.AddressAttempts-1; i++ {
		requireAuthFailed(t, id, h.stepUpCode(t, s, "totp", h.suaWrongCode(t, p)))
	}
	r := h.stepUpCode(t, s, "totp", h.totpNow(t, p))
	require.Equalf(t, http.StatusOK, r.status, "%s: пятое — 200: %s", id, r.body)
	_, lvl := ceremonyLevels(t, r.body)
	require.Equal(t, "2", lvl, "%s: уровень «2»", id)
}

// TestSUA72_JudgedKeyRefusalsShareTheCount — SUA-72; близнец — четыре отказа.
func TestSUA72_JudgedKeyRefusalsShareTheCount(t *testing.T) {
	const id = "SUA-72"
	foreign := webauthntest.AssertionOptions{UserVerified: true, BackupEligible: true, Origin: "https://elsewhere.example.invalid"}
	run := func(t *testing.T, refusals int) reply {
		h := newSUAStand(t)
		p := h.person(t, "72")
		k := h.withKey(t, p)
		s := h.login(t, p)
		for i := 0; i < refusals; i++ {
			requireAuthFailed(t, id, h.keyStepUp(t, id, s, k, h.challenge(t, id, s).raw, foreign))
		}
		return h.keyStepUp(t, id, s, k, h.challenge(t, id, s).raw, strong())
	}
	sixth := run(t, 5)
	requireRefusalOf(t, id, sixth, http.StatusTooManyRequests, 8, suaReasonTooMany, suaTextTooMany)
	fifth := run(t, 4)
	require.Equalf(t, http.StatusOK, fifth.status, "%s близнец: четыре отказа, затем верное — 200: %s", id, fifth.body)
}

// TestSUA73_ChallengeRefusalsSpendNoAttempt — SUA-73.
func TestSUA73_ChallengeRefusalsSpendNoAttempt(t *testing.T) {
	const id = "SUA-73"
	h := newSUAStand(t)
	p := h.person(t, "73")
	k := h.withKey(t, p)
	s := h.login(t, p)
	for i := 0; i < h.limits.AddressAttempts; i++ {
		r := h.keyStepUp(t, id, s, k, []byte("sua-73-never-issued-"+strconv.Itoa(i)), strong())
		requireRefusalOf(t, id, r, http.StatusBadRequest, 9, suaReasonNotIssued, suaTextNotIssued)
	}
	r := h.keyStepUp(t, id, s, k, h.challenge(t, id, s).raw, strong())
	require.Equalf(t, http.StatusOK, r.status, "%s: новое испытание и верное утверждение — 200: %s", id, r.body)
}
