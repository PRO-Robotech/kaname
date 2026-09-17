// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// second_factor_usecase_test.go — второй фактор на полосе входа: заведение,
// подтверждение, предъявление на входе и внутри сессии, запасные коды, снятие
// (фаза Ф12, задача PRO-Robotech/kacho#1281; приёмка
// `second-factor-totp-and-recovery-codes.md`, §5). Уровень I через дублёры
// портов; проверяющие — настоящие; коды считает проба (RFC 6238 из stdlib).
//
// Часы пробы: после каждого принятого кода они сдвигаются не меньше чем на
// ступень (§5 преамбула, Б2 круга 1) — иначе код той же ступени отвергался бы
// повтором на верном продукте.

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238: SHA-1 — контракт приложений-аутентификаторов
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

const sfWindow = 15 * time.Minute

const sfDomain = "access.example.invalid"

type sfHarness struct {
	*harness
	totp       *totpverify.Verifier
	enroll     *humansession.EnrollSecondFactorUseCase
	confirm    *humansession.ConfirmSecondFactorUseCase
	status     *humansession.SecondFactorStatusUseCase
	remove     *humansession.RemoveSecondFactorUseCase
	regenerate *humansession.RegenerateBackupCodesUseCase
	stepUp     *humansession.StepUpUseCase
}

// sfLimits — предел частоты харнесса второго фактора: выше базового (3),
// потому что сценарии Ф12-13 и Ф12-22 считают по четыре попытки до успеха.
func sfLimits() humansession.Limits {
	return humansession.Limits{AddressAttempts: 6, AddressWindow: 10 * time.Minute, SourceAttempts: 60, SourceWindow: 10 * time.Minute}
}

func newSFHarness(t *testing.T) *sfHarness {
	t.Helper()
	base := newHarness(t, nil)
	totp := base.totp
	h := &sfHarness{harness: base, totp: totp}
	var err error
	now := func() time.Time { return h.clock }
	logger := slog.New(slog.DiscardHandler)
	deps := humansession.SecondFactorDeps{
		Store: h.store, Methods: fakeMethods{h.store}, TOTP: totp, Sets: h.verifier, SetHasher: h.hasher,
		Verifier: h.verifier, Limits: sfLimits(), Freshness: sfWindow, Domain: sfDomain,
		Observer: h.obs, Now: now, Logger: logger,
	}
	h.enroll, err = humansession.NewEnrollSecondFactorUseCase(deps)
	require.NoError(t, err)
	h.confirm, err = humansession.NewConfirmSecondFactorUseCase(deps)
	require.NoError(t, err)
	h.status, err = humansession.NewSecondFactorStatusUseCase(deps)
	require.NoError(t, err)
	h.remove, err = humansession.NewRemoveSecondFactorUseCase(deps)
	require.NoError(t, err)
	h.regenerate, err = humansession.NewRegenerateBackupCodesUseCase(deps)
	require.NoError(t, err)
	h.stepUp, err = humansession.NewStepUpUseCase(deps)
	require.NoError(t, err)
	// Вход читает второй фактор теми же портами.
	h.login, err = humansession.NewLoginUseCase(humansession.LoginDeps{
		Store: h.store, Users: fakeUsers{h.store}, Methods: fakeMethods{h.store}, Verifier: h.verifier,
		Hasher: h.hasher, Limits: sfLimits(), TTL: ucTTL, Observer: h.obs, Now: now, Logger: logger,
		Envelope: h.envelopePort, TOTP: totp, Sets: h.verifier,
	})
	require.NoError(t, err)
	return h
}

// probeTOTP — код ступени step от секрета, посчитанный пробой.
func probeTOTP(t *testing.T, secret totpverify.Secret, step int64) string {
	t.Helper()
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret.Base32())
	require.NoError(t, err)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) // #nosec G115 -- ступень неотрицательна
	mac := hmac.New(sha1.New, raw)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", bin%1000000)
}

func (h *sfHarness) step() int64 { return totpverify.StepAt(h.clock) }

// advanceStep — часы пробы на n ступеней вперёд (§5 преамбула).
func (h *sfHarness) advanceStep(n int64) { h.clock = h.clock.Add(time.Duration(n) * totpverify.Period) }

func (h *sfHarness) freshSession(t *testing.T, email, password string) humansession.LoginOutput {
	t.Helper()
	return h.mustLogin(t, email, password)
}

// enrolled — личность с заведённым фактором: заведение, подтверждение, часы
// сдвинуты на ступень после принятого кода. Возвращает вход, секрет, коды.
func (h *sfHarness) enrolled(t *testing.T, id, email, password string) (humansession.LoginOutput, totpverify.Secret, []string) {
	t.Helper()
	h.person(t, id, email, password, true)
	login := h.freshSession(t, email, password)
	en, err := h.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: login.Bearer})
	require.NoError(t, err)
	out, err := h.confirm.Execute(context.Background(), humansession.ConfirmInput{
		Bearer: login.Bearer, Code: probeTOTP(t, en.Secret, h.step()), Source: "203.0.113.7",
	})
	require.NoError(t, err)
	h.advanceStep(1)
	login.Bearer = out.Bearer
	login.View = out.View
	return login, en.Secret, out.BackupCodes
}

func (h *sfHarness) failures(scope humansession.FailureScope, key string) int {
	n, _ := h.store.CountFailures(context.Background(), scope, key, h.clock.Add(-time.Hour))
	return n
}

func (h *sfHarness) sfRow(userID domain.UserID, kind domain.LoginMethodKind) (domain.LoginMethod, bool) {
	row, ok := h.store.factors[userID][kind]
	if !ok {
		return domain.LoginMethod{}, false
	}
	return *row, true
}

// ───────────────────────────── заведение ────────────────────────────────

// TestF12_01_EnrollMintsAPendingRowAndShowsTheSecretOnce — Ф12-01.
func TestF12_01_EnrollMintsAPendingRowAndShowsTheSecretOnce(t *testing.T) {
	h := newSFHarness(t)
	u := h.person(t, "usr-e1", "e1@example.invalid", "correct horse battery", true)
	login := h.freshSession(t, "e1@example.invalid", "correct horse battery")

	en, err := h.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: login.Bearer})
	require.NoError(t, err)
	require.Len(t, en.Secret.Base32(), 32)
	require.Equal(t, totpverify.OtpauthURI(sfDomain, "e1@example.invalid", en.Secret), en.OtpauthURI)
	require.True(t, en.ExpiresAt.Equal(h.clock.Add(sfWindow)), "срок — момент enroll плюс окно Р8")

	row, ok := h.sfRow(u.ID, domain.LoginMethodTOTP)
	require.True(t, ok)
	require.Equal(t, domain.LoginMethodStatePending, row.State)
	require.NotContains(t, row.Verifier.Reveal(), en.Secret.Base32(), "секрет в строке обёрнут")
	_, ok = h.sfRow(u.ID, domain.LoginMethodLookupSecret)
	require.False(t, ok, "набора у pending нет")

	st, err := h.status.Execute(context.Background(), humansession.StatusInput{Bearer: login.Bearer})
	require.NoError(t, err)
	require.False(t, st.TOTPEnrolled)
	require.True(t, st.PendingUntil.Equal(en.ExpiresAt))
	require.Nil(t, st.BackupCodes, "ключа backupCodes нет: заведён — только active")
	require.Equal(t, 1, h.obs.sfEvents[humansession.SecondFactorEnrollmentStarted])

	// Вход с кодом от pending — «не заведён»; без кода — «1», как до заведения.
	_, err = h.login.Execute(context.Background(), humansession.LoginInput{
		Email: "e1@example.invalid", Password: "correct horse battery", Source: "203.0.113.7",
		SecondFactor: &humansession.SecondFactorPresentation{Method: assurance.MethodTOTP, Code: probeTOTP(t, en.Secret, h.step())},
	})
	require.ErrorIs(t, err, humansession.ErrSecondFactorNotEnrolled)
	plain := h.mustLogin(t, "e1@example.invalid", "correct horse battery")
	require.Equal(t, "1", plain.View.Session.AssuranceLevel)
}

// TestF12_02_ConfirmActivatesMintsCodesAndIsAPresentation — Ф12-02, Ф12-42.
func TestF12_02_ConfirmActivatesMintsCodesAndIsAPresentation(t *testing.T) {
	h := newSFHarness(t)
	u := h.person(t, "usr-c1", "c1@example.invalid", "correct horse battery", true)
	login := h.freshSession(t, "c1@example.invalid", "correct horse battery")
	authAt := login.View.Session.AuthenticatedAt
	en, err := h.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: login.Bearer})
	require.NoError(t, err)
	h.clock = h.clock.Add(time.Minute)
	step := h.step()

	out, err := h.confirm.Execute(context.Background(), humansession.ConfirmInput{
		Bearer: login.Bearer, Code: probeTOTP(t, en.Secret, step), Source: "203.0.113.7",
	})
	require.NoError(t, err)
	require.Len(t, out.BackupCodes, 10)
	for _, c := range out.BackupCodes {
		require.Len(t, c, 10)
	}
	require.Equal(t, "2", out.View.Session.AssuranceLevel)
	require.ElementsMatch(t, []string{"password", "totp"}, out.View.Session.PresentedMethods)
	require.True(t, out.View.Session.AuthenticatedAt.Equal(authAt), "момент аутентификации неподвижен")
	require.True(t, out.View.Session.LastPresentedAt.Equal(h.clock), "момент последнего предъявления — момент сверки")
	require.Equal(t, humansession.AssuranceView{Level: "2", Level2Reachable: true, MissingForLevel2: []string{}}, out.Assurance)
	require.NotEqual(t, login.Bearer.Digest(), out.Bearer.Digest(), "носитель перевыпущен")
	_, reason, err := h.store.Resolve(context.Background(), login.Bearer.Digest(), h.clock)
	require.NoError(t, err)
	require.NotEqual(t, humansession.SessionFound, reason, "прежний носитель даёт «сессии нет»")

	row, _ := h.sfRow(u.ID, domain.LoginMethodTOTP)
	require.Equal(t, domain.LoginMethodStateActive, row.State)
	require.True(t, row.StepAccepted)
	require.Equal(t, step, row.AcceptedStep)
	set, ok := h.sfRow(u.ID, domain.LoginMethodLookupSecret)
	require.True(t, ok)
	for _, c := range out.BackupCodes {
		require.NotContains(t, set.Verifier.Reveal(), c)
	}

	st, err := h.status.Execute(context.Background(), humansession.StatusInput{Bearer: out.Bearer})
	require.NoError(t, err)
	require.True(t, st.TOTPEnrolled)
	require.True(t, st.ConfirmedAt.Equal(h.clock))
	require.NotNil(t, st.BackupCodes)
	require.Equal(t, 10, st.BackupCodes.Remaining)
	require.Equal(t, 10, st.BackupCodes.Total)

	// Событие аудита и журнал повышения — одной транзакцией, без личных данных.
	var enrolledEvents, stepUps int
	for _, ev := range h.store.audit {
		switch ev.EventType {
		case humansession.AuditSecondFactorEnrolled:
			enrolledEvents++
			require.Equal(t, string(u.ID), ev.Payload["user_id"])
			require.Equal(t, string(out.View.Session.ID), ev.Payload["session_id"])
			require.Equal(t, "totp", ev.Payload["method"])
			for _, k := range []string{"email", "display_name", "secret", "code", "codes"} {
				require.NotContains(t, ev.Payload, k)
			}
		case humansession.AuditSessionStepUp:
			stepUps++
			require.Equal(t, "1", ev.Payload["level_before"])
			require.Equal(t, "2", ev.Payload["level_after"])
			require.Equal(t, "totp", ev.Payload["method"])
		}
	}
	require.Equal(t, 1, enrolledEvents)
	require.Equal(t, 1, stepUps)
	require.Equal(t, 1, h.obs.sfEvents[humansession.SecondFactorEnrollmentConfirmed])
	require.Equal(t, 1, h.obs.sfPresent[sfKey(assurance.MethodTOTP, humansession.PresentationMatched)])

	// Близнец Ф12-14: вход паролем без кода после заведения даёт «1».
	plain := h.mustLogin(t, "c1@example.invalid", "correct horse battery")
	require.Equal(t, "1", plain.View.Session.AssuranceLevel)
}

// TestF12_03_ConfirmWithAWrongCodeCountsAndKeepsPending — Ф12-03.
func TestF12_03_ConfirmWithAWrongCodeCountsAndKeepsPending(t *testing.T) {
	h := newSFHarness(t)
	u := h.person(t, "usr-c3", "c3@example.invalid", "correct horse battery", true)
	login := h.freshSession(t, "c3@example.invalid", "correct horse battery")
	en, err := h.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: login.Bearer})
	require.NoError(t, err)
	wrong := probeTOTP(t, en.Secret, h.step()+5)

	_, err = h.confirm.Execute(context.Background(), humansession.ConfirmInput{Bearer: login.Bearer, Code: wrong, Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	row, _ := h.sfRow(u.ID, domain.LoginMethodTOTP)
	require.Equal(t, domain.LoginMethodStatePending, row.State)
	_, ok := h.sfRow(u.ID, domain.LoginMethodLookupSecret)
	require.False(t, ok)
	require.Equal(t, 1, h.failures(humansession.FailureByAddress, "c3@example.invalid"))
	require.Equal(t, 1, h.failures(humansession.FailureBySource, "203.0.113.7"))
	resolved, reason, err := h.store.Resolve(context.Background(), login.Bearer.Digest(), h.clock)
	require.NoError(t, err)
	require.Equal(t, humansession.SessionFound, reason, "носитель не перевыпущен")
	require.Equal(t, "1", resolved.Session.AssuranceLevel)

	// Положительный контроль: тот же секрет, верный код — проходит.
	_, err = h.confirm.Execute(context.Background(), humansession.ConfirmInput{Bearer: login.Bearer, Code: probeTOTP(t, en.Secret, h.step()), Source: "203.0.113.7"})
	require.NoError(t, err)
}

// TestF12_04_ConfirmWithoutAPendingEnrollmentIsOneRefusal — Ф12-04 (а), (в), Н6.
func TestF12_04_ConfirmWithoutAPendingEnrollmentIsOneRefusal(t *testing.T) {
	h := newSFHarness(t)
	h.person(t, "usr-c4", "c4@example.invalid", "correct horse battery", true)
	login := h.freshSession(t, "c4@example.invalid", "correct horse battery")

	// (в) заведение не начато.
	_, err := h.confirm.Execute(context.Background(), humansession.ConfirmInput{Bearer: login.Bearer, Code: "123456", Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrEnrollmentNotPending)
	require.Zero(t, h.failures(humansession.FailureByAddress, "c4@example.invalid"), "отказ по состоянию — не попытка")

	// (а) заведение истекло, сессия свежа (предъявлен пароль).
	en, err := h.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: login.Bearer})
	require.NoError(t, err)
	h.clock = h.clock.Add(sfWindow + time.Second)
	su, err := h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: login.Bearer, Method: assurance.MethodPassword, Password: "correct horse battery", Source: "203.0.113.7"})
	require.NoError(t, err)
	_, err = h.confirm.Execute(context.Background(), humansession.ConfirmInput{Bearer: su.Bearer, Code: probeTOTP(t, en.Secret, h.step()), Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrEnrollmentNotPending, "истёкшее заведение — тот же отказ, код не сверяется")
	require.Zero(t, h.failures(humansession.FailureByAddress, "c4@example.invalid"))

	// Н6: истекли оба окна — первой отвечает свежесть.
	h.clock = h.clock.Add(sfWindow + time.Second)
	_, err = h.confirm.Execute(context.Background(), humansession.ConfirmInput{Bearer: su.Bearer, Code: probeTOTP(t, en.Secret, h.step()), Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrSessionNotFresh)

	// Положительный контроль: новый enroll выдаёт новый секрет, confirm им проходит.
	su2, err := h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: su.Bearer, Method: assurance.MethodPassword, Password: "correct horse battery", Source: "203.0.113.7"})
	require.NoError(t, err)
	en2, err := h.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: su2.Bearer})
	require.NoError(t, err)
	require.NotEqual(t, en.Secret.Base32(), en2.Secret.Base32())
	_, err = h.confirm.Execute(context.Background(), humansession.ConfirmInput{Bearer: su2.Bearer, Code: probeTOTP(t, en2.Secret, h.step()), Source: "203.0.113.7"})
	require.NoError(t, err)
}

// TestF12_05_07_SecondEnrollmentAndSecondConfirm — Ф12-05 (а, б), Ф12-07 (б).
func TestF12_05_07_SecondEnrollmentAndSecondConfirm(t *testing.T) {
	h := newSFHarness(t)
	h.person(t, "usr-c5", "c5@example.invalid", "correct horse battery", true)
	login := h.freshSession(t, "c5@example.invalid", "correct horse battery")

	// (б) при pending — замена: код от прежнего — 401, от нового — проходит.
	en1, err := h.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: login.Bearer})
	require.NoError(t, err)
	en2, err := h.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: login.Bearer})
	require.NoError(t, err)
	require.NotEqual(t, en1.Secret.Base32(), en2.Secret.Base32())
	_, err = h.confirm.Execute(context.Background(), humansession.ConfirmInput{Bearer: login.Bearer, Code: probeTOTP(t, en1.Secret, h.step()), Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	out, err := h.confirm.Execute(context.Background(), humansession.ConfirmInput{Bearer: login.Bearer, Code: probeTOTP(t, en2.Secret, h.step()), Source: "203.0.113.7"})
	require.NoError(t, err)
	h.advanceStep(1)

	// (а) при active — 409, строка не изменена; (Ф12-07 б) второй confirm — 409,
	// код не сверяется, не попытка.
	_, err = h.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: out.Bearer})
	require.ErrorIs(t, err, humansession.ErrSecondFactorAlreadyEnrolled)
	before := h.failures(humansession.FailureByAddress, "c5@example.invalid")
	_, err = h.confirm.Execute(context.Background(), humansession.ConfirmInput{Bearer: out.Bearer, Code: "000000", Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrSecondFactorAlreadyEnrolled)
	require.Equal(t, before, h.failures(humansession.FailureByAddress, "c5@example.invalid"))
	require.Equal(t, 2, h.obs.sfRefusals[humansession.RefusalAlreadyEnrolled], "клетка отказа растёт: заведение и подтверждение при active")
}

// ───────────────────────────── свежесть ─────────────────────────────────

// TestF12_09_10_EnrollRequiresAFreshSessionAndAPresentationRefreshesIt — Ф11-33, Ф11-32.
func TestF12_09_10_EnrollRequiresAFreshSessionAndAPresentationRefreshesIt(t *testing.T) {
	h := newSFHarness(t)
	u := h.person(t, "usr-f1", "f1@example.invalid", "correct horse battery", true)
	login := h.freshSession(t, "f1@example.invalid", "correct horse battery")
	h.clock = h.clock.Add(sfWindow + time.Second)

	_, err := h.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: login.Bearer})
	require.ErrorIs(t, err, humansession.ErrSessionNotFresh)
	_, ok := h.sfRow(u.ID, domain.LoginMethodTOTP)
	require.False(t, ok, "строки pending нет")
	require.Zero(t, h.failures(humansession.FailureByAddress, "f1@example.invalid"))
	_, reason, err := h.store.Resolve(context.Background(), login.Bearer.Digest(), h.clock)
	require.NoError(t, err)
	require.Equal(t, humansession.SessionFound, reason, "носитель цел и годен")
	require.Equal(t, 1, h.obs.sfRefusals[humansession.RefusalSessionNotFresh])

	// Ф12-10: предъявление пароля внутри сессии освежает окно, уровень «1».
	su, err := h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: login.Bearer, Method: assurance.MethodPassword, Password: "correct horse battery", Source: "203.0.113.7"})
	require.NoError(t, err)
	require.Equal(t, "1", su.View.Session.AssuranceLevel)
	require.Equal(t, humansession.AssuranceView{Level: "1", Level2Reachable: false, MissingForLevel2: []string{}}, su.Assurance)
	_, err = h.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: su.Bearer})
	require.NoError(t, err)
}

// ───────────────────────────── вход с кодом ──────────────────────────────

// TestF12_11_14_LoginWithACodeIssuesLevelTwoOnTheFirstBearer — Ф12-11, 12, 14.
func TestF12_11_14_LoginWithACodeIssuesLevelTwoOnTheFirstBearer(t *testing.T) {
	h := newSFHarness(t)
	_, secret, codes := h.enrolled(t, "usr-l1", "l1@example.invalid", "correct horse battery")
	step := h.step()

	out, err := h.login.Execute(context.Background(), humansession.LoginInput{
		Email: "l1@example.invalid", Password: "correct horse battery", Source: "203.0.113.7",
		SecondFactor: &humansession.SecondFactorPresentation{Method: assurance.MethodTOTP, Code: probeTOTP(t, secret, step)},
	})
	require.NoError(t, err)
	require.Equal(t, "2", out.View.Session.AssuranceLevel)
	require.ElementsMatch(t, []string{"password", "totp"}, out.View.Session.PresentedMethods)
	row, _ := h.sfRow(out.View.User.ID, domain.LoginMethodTOTP)
	require.Equal(t, step, row.AcceptedStep, "последний принятый шаг — ступень входа")
	var issued int
	for _, ev := range h.store.audit {
		if ev.EventType == humansession.AuditSessionIssued && ev.Payload["session_id"] == string(out.View.Session.ID) {
			issued++
			require.ElementsMatch(t, []string{"password", "totp"}, ev.Payload["methods"])
		}
	}
	require.Equal(t, 1, issued)
	h.advanceStep(1)

	// Ф12-12: запасным кодом — «2», код потреблён, остаток 9.
	out2, err := h.login.Execute(context.Background(), humansession.LoginInput{
		Email: "l1@example.invalid", Password: "correct horse battery", Source: "203.0.113.7",
		SecondFactor: &humansession.SecondFactorPresentation{Method: assurance.MethodLookupSecret, Code: codes[0]},
	})
	require.NoError(t, err)
	require.Equal(t, "2", out2.View.Session.AssuranceLevel)
	require.ElementsMatch(t, []string{"password", "lookup_secret"}, out2.View.Session.PresentedMethods)
	st, err := h.status.Execute(context.Background(), humansession.StatusInput{Bearer: out2.Bearer})
	require.NoError(t, err)
	require.Equal(t, 9, st.BackupCodes.Remaining)
	_, err = h.login.Execute(context.Background(), humansession.LoginInput{
		Email: "l1@example.invalid", Password: "correct horse battery", Source: "203.0.113.7",
		SecondFactor: &humansession.SecondFactorPresentation{Method: assurance.MethodLookupSecret, Code: codes[0]},
	})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "тот же код на следующем входе — 401")

	// Ф12-14: без поля — «1», а не отказ.
	plain := h.mustLogin(t, "l1@example.invalid", "correct horse battery")
	require.Equal(t, "1", plain.View.Session.AssuranceLevel)
	st, err = h.status.Execute(context.Background(), humansession.StatusInput{Bearer: plain.Bearer})
	require.NoError(t, err)
	require.True(t, st.TOTPEnrolled)
}

// TestF12_13_LoginRefusalsWithASecondFactor — Ф12-13 (а…ж): один отказ 401 на
// все семь, включая (е) — состояние фактора на входе наружу не выходит
// (редакция 8, kaname#257); строка после неполного успеха не изменена.
func TestF12_13_LoginRefusalsWithASecondFactor(t *testing.T) {
	h := newSFHarness(t)
	loginA, secret, codes := h.enrolled(t, "usr-a13", "a13@example.invalid", "correct horse battery")
	h.person(t, "usr-b13", "b13@example.invalid", "correct horse battery", true)
	h.person(t, "usr-c13", "c13@example.invalid", "correct horse battery", true)
	loginC := h.freshSession(t, "c13@example.invalid", "correct horse battery")
	_, err := h.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: loginC.Bearer})
	require.NoError(t, err)
	uA := loginA.View.User.ID
	step := h.step()
	attempt := func(email, password string, f *humansession.SecondFactorPresentation) error {
		_, err := h.login.Execute(context.Background(), humansession.LoginInput{Email: email, Password: password, Source: "203.0.113.7", SecondFactor: f})
		return err
	}
	totp := func(code string) *humansession.SecondFactorPresentation {
		return &humansession.SecondFactorPresentation{Method: assurance.MethodTOTP, Code: code}
	}
	lookup := func(code string) *humansession.SecondFactorPresentation {
		return &humansession.SecondFactorPresentation{Method: assurance.MethodLookupSecret, Code: code}
	}
	rowBefore, _ := h.sfRow(uA, domain.LoginMethodTOTP)
	setBefore, _ := h.sfRow(uA, domain.LoginMethodLookupSecret)

	// (а) верный пароль, неверный код.
	require.ErrorIs(t, attempt("a13@example.invalid", "correct horse battery", totp(probeTOTP(t, secret, step+7))), humansession.ErrAuthenticationFailed)
	// (б) неверный пароль, верный код — строка не изменена.
	require.ErrorIs(t, attempt("a13@example.invalid", "wrong", totp(probeTOTP(t, secret, step))), humansession.ErrAuthenticationFailed)
	rowAfter, _ := h.sfRow(uA, domain.LoginMethodTOTP)
	require.Equal(t, rowBefore.AcceptedStep, rowAfter.AcceptedStep, "сверка на неверном пароле ничего не записывает")
	// (в) оба неверны.
	require.ErrorIs(t, attempt("a13@example.invalid", "wrong", totp("000000")), humansession.ErrAuthenticationFailed)
	// (ж) неверный пароль, годный запасной код — не потреблён.
	require.ErrorIs(t, attempt("a13@example.invalid", "wrong", lookup(codes[1])), humansession.ErrAuthenticationFailed)
	setAfter, _ := h.sfRow(uA, domain.LoginMethodLookupSecret)
	require.Equal(t, setBefore.Verifier.Reveal(), setAfter.Verifier.Reveal(), "набор после (ж) прежний")
	// (е) B без фактора и C со строкой pending — тот же отказ входа и попытка
	// (Р4, Р7 редакции 8): состояние наружу не выходит; различимость — только
	// внутрь, в клетку исходов входа, а клетка отказов под сессией не растёт.
	require.ErrorIs(t, attempt("b13@example.invalid", "correct horse battery", totp("123456")), humansession.ErrAuthenticationFailed)
	require.ErrorIs(t, attempt("c13@example.invalid", "correct horse battery", totp("123456")), humansession.ErrAuthenticationFailed)
	require.ErrorIs(t, attempt("b13@example.invalid", "correct horse battery", lookup("ABCDEFGH12")), humansession.ErrAuthenticationFailed)
	require.Equal(t, 2, h.failures(humansession.FailureByAddress, "b13@example.invalid"), "(е) у B — две попытки")
	require.Equal(t, 1, h.failures(humansession.FailureByAddress, "c13@example.invalid"), "(е) у C — попытка")
	require.Equal(t, 3, h.obs.login[humansession.LoginOutcomeSecondFactorNotEnrolled], "различимость внутрь: клетка исходов входа")
	require.Zero(t, h.obs.sfRefusals[humansession.RefusalNotEnrolled], "клетка отказов под сессией на входе не растёт")
	// (е) c неверным паролем — тот же 401, что и (в), и та же попытка.
	require.ErrorIs(t, attempt("b13@example.invalid", "wrong", totp("123456")), humansession.ErrAuthenticationFailed)
	require.Equal(t, 3, h.failures(humansession.FailureByAddress, "b13@example.invalid"))
	// Положительный близнец (е): та же личность B без поля — сессия «1».
	plainB := h.mustLogin(t, "b13@example.invalid", "correct horse battery")
	require.Equal(t, "1", plainB.View.Session.AssuranceLevel)
	require.Zero(t, h.failures(humansession.FailureByAddress, "b13@example.invalid"), "успех обнуляет счёт (Ф3 Р10)")

	require.Equal(t, 4, h.failures(humansession.FailureByAddress, "a13@example.invalid"), "(а), (б), (в), (ж) сосчитаны")

	// Положительные контроли после отказов: (б) → Ф12-11 тем же кодом той же
	// ступени; (ж) → Ф12-12 тем же кодом.
	out, err := h.login.Execute(context.Background(), humansession.LoginInput{
		Email: "a13@example.invalid", Password: "correct horse battery", Source: "203.0.113.7", SecondFactor: totp(probeTOTP(t, secret, step)),
	})
	require.NoError(t, err)
	require.Equal(t, "2", out.View.Session.AssuranceLevel)
	// (г) тот же шаг снова — повтор → 401, сосчитан.
	require.ErrorIs(t, attempt("a13@example.invalid", "correct horse battery", totp(probeTOTP(t, secret, step))), humansession.ErrAuthenticationFailed)
	require.Equal(t, 1, h.obs.sfPresent[sfKey(assurance.MethodTOTP, humansession.PresentationReplayed)])
	out, err = h.login.Execute(context.Background(), humansession.LoginInput{
		Email: "a13@example.invalid", Password: "correct horse battery", Source: "203.0.113.7", SecondFactor: lookup(codes[1]),
	})
	require.NoError(t, err)
	require.Equal(t, "2", out.View.Session.AssuranceLevel)
	// (д) потреблённый запасной код — 401.
	require.ErrorIs(t, attempt("a13@example.invalid", "correct horse battery", lookup(codes[1])), humansession.ErrAuthenticationFailed)
}

// TestF12_13e_NotEnrolledOnLoginIsTheSameRefusalAsAWrongPassword — Ф12-13 «е»
// редакции 8 (kaname#257): у личности без фактора «неверный пароль + код» и
// «верный пароль + код» дают ОДИН И ТОТ ЖЕ сентинел с тем же текстом, обе —
// попытки в окне частоты; положительный близнец — верный пароль без поля даёт
// сессию «1». Отрицательный контроль: реализация, отдающая на второе обращение
// сентинел состояния, тело, отличное от первого, либо не считающая его попыткой,
// краснеет здесь.
func TestF12_13e_NotEnrolledOnLoginIsTheSameRefusalAsAWrongPassword(t *testing.T) {
	h := newSFHarness(t)
	h.person(t, "usr-ne1", "ne1@example.invalid", "correct horse battery", true)
	attempt := func(password string, f *humansession.SecondFactorPresentation) error {
		_, err := h.login.Execute(context.Background(), humansession.LoginInput{Email: "ne1@example.invalid", Password: password, Source: "203.0.113.7", SecondFactor: f})
		return err
	}
	code := &humansession.SecondFactorPresentation{Method: assurance.MethodTOTP, Code: "000000"}

	wrong := attempt("wrong", code)
	require.ErrorIs(t, wrong, humansession.ErrAuthenticationFailed)
	require.Equal(t, 1, h.failures(humansession.FailureByAddress, "ne1@example.invalid"))

	right := attempt("correct horse battery", code)
	require.ErrorIs(t, right, humansession.ErrAuthenticationFailed, "совпавший пароль не назван кодом отказа")
	require.Equal(t, wrong.Error(), right.Error(), "совпавший пароль не назван текстом отказа")
	require.Equal(t, 2, h.failures(humansession.FailureByAddress, "ne1@example.invalid"), "совпавший пароль не назван темпом окна")
	require.Equal(t, 1, h.obs.login[humansession.LoginOutcomeSecondFactorNotEnrolled], "различимость — внутрь")
	require.Zero(t, h.obs.sfRefusals[humansession.RefusalNotEnrolled])

	out := h.mustLogin(t, "ne1@example.invalid", "correct horse battery")
	require.Equal(t, "1", out.View.Session.AssuranceLevel, "положительный близнец: без поля — сессия «1»")
}

// ───────────────────────────── церемония ─────────────────────────────────

// TestF12_15_18_StepUpWithACodeRaisesTheSession — Ф11-08, Ф11-30, Ф12-16…18.
func TestF12_15_18_StepUpWithACodeRaisesTheSession(t *testing.T) {
	h := newSFHarness(t)
	_, secret, codes := h.enrolled(t, "usr-s1", "s1@example.invalid", "correct horse battery")
	login := h.mustLogin(t, "s1@example.invalid", "correct horse battery")
	require.Equal(t, "1", login.View.Session.AssuranceLevel)
	authAt := login.View.Session.AuthenticatedAt

	// Ф12-16: неверный код — 401, уровень и носитель прежние, попытка.
	_, err := h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: login.Bearer, Method: assurance.MethodTOTP, Code: probeTOTP(t, secret, h.step()+9), Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	resolved, reason, err := h.store.Resolve(context.Background(), login.Bearer.Digest(), h.clock)
	require.NoError(t, err)
	require.Equal(t, humansession.SessionFound, reason)
	require.Equal(t, "1", resolved.Session.AssuranceLevel)
	require.Equal(t, 1, h.failures(humansession.FailureByAddress, "s1@example.invalid"))

	// Ф12-15: верный код — «2», носитель перевыпущен, прежний — «сессии нет».
	out, err := h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: login.Bearer, Method: assurance.MethodTOTP, Code: probeTOTP(t, secret, h.step()), Source: "203.0.113.7"})
	require.NoError(t, err)
	require.Equal(t, "2", out.View.Session.AssuranceLevel)
	require.Equal(t, humansession.AssuranceView{Level: "2", Level2Reachable: true, MissingForLevel2: []string{}}, out.Assurance)
	require.Nil(t, out.BackupCodesRemaining, "поле только у ответа, потребившего код")
	require.True(t, out.View.Session.AuthenticatedAt.Equal(authAt))
	_, reason, err = h.store.Resolve(context.Background(), login.Bearer.Digest(), h.clock)
	require.NoError(t, err)
	require.Equal(t, humansession.NoSessionUnknown, reason, "прежний носитель — как несуществующая сессия")
	require.Zero(t, h.failures(humansession.FailureByAddress, "s1@example.invalid"), "успешное предъявление обнуляет счёт по адресу")
	h.advanceStep(1)

	// Ф12-18: запасной код — «2» и остаток.
	other := h.mustLogin(t, "s1@example.invalid", "correct horse battery")
	out, err = h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: other.Bearer, Method: assurance.MethodLookupSecret, Code: codes[3], Source: "203.0.113.7"})
	require.NoError(t, err)
	require.Equal(t, "2", out.Assurance.Level)
	require.NotNil(t, out.BackupCodesRemaining)
	require.Equal(t, 9, *out.BackupCodesRemaining)
	_, err = h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: out.Bearer, Method: assurance.MethodLookupSecret, Code: codes[3], Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "тот же код второй раз")
	require.Equal(t, 1, h.obs.sfEvents[humansession.SecondFactorBackupCodeConsumed])

	// Ф12-17: личность без фактора и со строкой pending.
	h.person(t, "usr-s2", "s2@example.invalid", "correct horse battery", true)
	nb := h.mustLogin(t, "s2@example.invalid", "correct horse battery")
	_, err = h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: nb.Bearer, Method: assurance.MethodTOTP, Code: "123456", Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrSecondFactorNotEnrolled)
	_, err = h.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: nb.Bearer})
	require.NoError(t, err)
	_, err = h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: nb.Bearer, Method: assurance.MethodLookupSecret, Code: "ABCDEFGH12", Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrSecondFactorNotEnrolled)
	require.Zero(t, h.failures(humansession.FailureByAddress, "s2@example.invalid"))
}

// TestF12_19_AssuranceViewOnThreeSessions — Ф11-11, Ф11-29, Ф12-19.
func TestF12_19_AssuranceViewOnThreeSessions(t *testing.T) {
	h := newSFHarness(t)
	loginA, secret, _ := h.enrolled(t, "usr-r1", "r1@example.invalid", "correct horse battery")
	u := loginA.View.User

	// (а) сессия восстановления: множество {recovery_code}, пароль задан.
	rb, err := domain.NewSessionBearer()
	require.NoError(t, err)
	r := domain.HumanSession{ID: "hss-recovery", UserID: u.ID, AuthenticatedAt: h.clock, LastPresentedAt: h.clock,
		ExpiresAt: h.clock.Add(ucTTL), AssuranceLevel: "1", PresentedMethods: []string{"recovery_code"}}
	h.store.rows[r.ID] = &fakeRow{s: r, digest: rb.Digest()}
	out, err := h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: rb, Method: assurance.MethodTOTP, Code: probeTOTP(t, secret, h.step()), Source: "203.0.113.7"})
	require.NoError(t, err)
	require.Equal(t, humansession.AssuranceView{Level: "1", Level2Reachable: true, MissingForLevel2: []string{"password"}}, out.Assurance)
	h.advanceStep(1)
	// Ф11-29: затем заданный пароль — «2».
	out, err = h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: out.Bearer, Method: assurance.MethodPassword, Password: "correct horse battery", Source: "203.0.113.7"})
	require.NoError(t, err)
	require.Equal(t, "2", out.Assurance.Level)
	require.Equal(t, []string{}, out.Assurance.MissingForLevel2)

	// (б) сессия «1» входом паролем — код даёт «2».
	b := h.mustLogin(t, "r1@example.invalid", "correct horse battery")
	out, err = h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: b.Bearer, Method: assurance.MethodTOTP, Code: probeTOTP(t, secret, h.step()), Source: "203.0.113.7"})
	require.NoError(t, err)
	require.Equal(t, humansession.AssuranceView{Level: "2", Level2Reachable: true, MissingForLevel2: []string{}}, out.Assurance)

	// (в) личность без фактора — пароль: путь к «2» не в предъявлении.
	h.person(t, "usr-r2", "r2@example.invalid", "correct horse battery", true)
	c := h.mustLogin(t, "r2@example.invalid", "correct horse battery")
	out, err = h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: c.Bearer, Method: assurance.MethodPassword, Password: "correct horse battery", Source: "203.0.113.7"})
	require.NoError(t, err)
	require.Equal(t, humansession.AssuranceView{Level: "1", Level2Reachable: false, MissingForLevel2: []string{}}, out.Assurance)
}

// TestF12_22_ReplayIsAPropertyOfTheRowNotTheSession — Ф12-22 (в).
func TestF12_22_ReplayIsAPropertyOfTheRowNotTheSession(t *testing.T) {
	h := newSFHarness(t)
	_, secret, _ := h.enrolled(t, "usr-rp", "rp@example.invalid", "correct horse battery")
	s1 := h.mustLogin(t, "rp@example.invalid", "correct horse battery")
	s2 := h.mustLogin(t, "rp@example.invalid", "correct horse battery")
	code := probeTOTP(t, secret, h.step())
	out, err := h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: s1.Bearer, Method: assurance.MethodTOTP, Code: code, Source: "203.0.113.7"})
	require.NoError(t, err)
	// (а) тот же код по новому носителю S1 и код t−1 — 401.
	_, err = h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: out.Bearer, Method: assurance.MethodTOTP, Code: code, Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	_, err = h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: out.Bearer, Method: assurance.MethodTOTP, Code: probeTOTP(t, secret, h.step()-1), Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	// (в) тот же код из S2 — 401: шаг принадлежит строке; уровень S2 — «1».
	_, err = h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: s2.Bearer, Method: assurance.MethodTOTP, Code: code, Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	resolved, reason, err := h.store.Resolve(context.Background(), s2.Bearer.Digest(), h.clock)
	require.NoError(t, err)
	require.Equal(t, humansession.SessionFound, reason)
	require.Equal(t, "1", resolved.Session.AssuranceLevel)
	// (б) t+1 — 200.
	_, err = h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: out.Bearer, Method: assurance.MethodTOTP, Code: probeTOTP(t, secret, h.step()+1), Source: "203.0.113.7"})
	require.NoError(t, err)
}

// ───────────────────────────── запасные коды ────────────────────────────

// TestF12_23_26_BackupCodesOnceEachDownToZero — Ф12-23, Ф12-26.
func TestF12_23_26_BackupCodesOnceEachDownToZero(t *testing.T) {
	h := newSFHarness(t)
	_, secret, codes := h.enrolled(t, "usr-bc", "bc@example.invalid", "correct horse battery")
	login := h.mustLogin(t, "bc@example.invalid", "correct horse battery")
	bearer := login.Bearer
	present := func(code string) (*humansession.StepUpOutput, error) {
		out, err := h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: bearer, Method: assurance.MethodLookupSecret, Code: code, Source: "203.0.113.7"})
		if err == nil {
			bearer = out.Bearer
			return &out, nil
		}
		return nil, err
	}
	out, err := present(codes[2])
	require.NoError(t, err)
	require.Equal(t, 9, *out.BackupCodesRemaining)
	_, err = present(codes[2])
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	out, err = present(codes[6])
	require.NoError(t, err)
	require.Equal(t, 8, *out.BackupCodesRemaining)
	for _, i := range []int{0, 1, 3, 4, 5, 7, 8} {
		out, err = present(codes[i])
		require.NoError(t, err, "код №%d годен", i)
	}
	require.Equal(t, 1, *out.BackupCodesRemaining)
	out, err = present(codes[9])
	require.NoError(t, err)
	require.Equal(t, 0, *out.BackupCodesRemaining, "остаток ноль назван числом")
	st, err := h.status.Execute(context.Background(), humansession.StatusInput{Bearer: bearer})
	require.NoError(t, err)
	require.Equal(t, 0, st.BackupCodes.Remaining)
	require.Equal(t, 10, st.BackupCodes.Total)
	_, err = present(codes[4])
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "одиннадцатый — 401")
	// Код по времени по-прежнему работает.
	_, err = h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: bearer, Method: assurance.MethodTOTP, Code: probeTOTP(t, secret, h.step()), Source: "203.0.113.7"})
	require.NoError(t, err)
}

// TestF12_25_RegenerateReplacesTheSetWhole — Ф12-25.
func TestF12_25_RegenerateReplacesTheSetWhole(t *testing.T) {
	h := newSFHarness(t)
	login, secret, old := h.enrolled(t, "usr-rg", "rg@example.invalid", "correct horse battery")
	// Сессия несвежа — перечеканке свежесть не нужна: код в теле и есть предъявление.
	h.clock = h.clock.Add(sfWindow + time.Minute)

	out, err := h.regenerate.Execute(context.Background(), humansession.RegenerateBackupCodesInput{
		Bearer: login.Bearer, Factor: humansession.SecondFactorPresentation{Method: assurance.MethodTOTP, Code: probeTOTP(t, secret, h.step())}, Source: "203.0.113.7",
	})
	require.NoError(t, err)
	require.Len(t, out.BackupCodes, 10)
	require.Equal(t, "2", out.Assurance.Level)
	require.NotEqual(t, login.Bearer.Digest(), out.Bearer.Digest())
	for _, o := range old {
		require.NotContains(t, out.BackupCodes, o)
	}
	var events int
	for _, ev := range h.store.audit {
		if ev.EventType == humansession.AuditBackupCodesRegenerated {
			events++
		}
	}
	require.Equal(t, 1, events)
	// Старый код непригоден — 401 и попытка.
	_, err = h.regenerate.Execute(context.Background(), humansession.RegenerateBackupCodesInput{
		Bearer: out.Bearer, Factor: humansession.SecondFactorPresentation{Method: assurance.MethodLookupSecret, Code: old[0]}, Source: "203.0.113.7",
	})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	require.Equal(t, 1, h.failures(humansession.FailureByAddress, "rg@example.invalid"))
	// (в) без фактора / pending — не заведён, код не сверяется.
	h.person(t, "usr-rg2", "rg2@example.invalid", "correct horse battery", true)
	nb := h.mustLogin(t, "rg2@example.invalid", "correct horse battery")
	_, err = h.regenerate.Execute(context.Background(), humansession.RegenerateBackupCodesInput{
		Bearer: nb.Bearer, Factor: humansession.SecondFactorPresentation{Method: assurance.MethodTOTP, Code: "123456"}, Source: "203.0.113.7",
	})
	require.ErrorIs(t, err, humansession.ErrSecondFactorNotEnrolled)
	require.Zero(t, h.failures(humansession.FailureByAddress, "rg2@example.invalid"))
}

// ───────────────────────────── снятие ─────────────────────────────────────

// TestF12_28_29_RemoveEndsOtherSessionsAndKeepsTheCurrentAtTwo — Ф12-28, Ф12-29.
func TestF12_28_29_RemoveEndsOtherSessionsAndKeepsTheCurrentAtTwo(t *testing.T) {
	h := newSFHarness(t)
	_, secret, codes := h.enrolled(t, "usr-rm", "rm@example.invalid", "correct horse battery")
	s1 := h.mustLogin(t, "rm@example.invalid", "correct horse battery")
	s2 := h.mustLogin(t, "rm@example.invalid", "correct horse battery")
	s3 := h.mustLogin(t, "rm@example.invalid", "correct horse battery")
	s3up, err := h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: s3.Bearer, Method: assurance.MethodTOTP, Code: probeTOTP(t, secret, h.step()), Source: "203.0.113.7"})
	require.NoError(t, err)
	h.advanceStep(1)
	u := s1.View.User.ID

	// Ф12-29 (а…в): отказы, ничего не снято.
	_, err = h.remove.Execute(context.Background(), humansession.RemoveSecondFactorInput{Bearer: s1.Bearer, Factor: humansession.SecondFactorPresentation{Method: assurance.MethodTOTP}, Source: "203.0.113.7"})
	var fe *humansession.FieldError
	require.ErrorAs(t, err, &fe)
	require.Equal(t, "code", fe.Field)
	_, err = h.remove.Execute(context.Background(), humansession.RemoveSecondFactorInput{Bearer: s1.Bearer, Factor: humansession.SecondFactorPresentation{Method: assurance.MethodTOTP, Code: probeTOTP(t, secret, h.step()+8)}, Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	require.Equal(t, 1, h.failures(humansession.FailureByAddress, "rm@example.invalid"))
	_, ok := h.sfRow(u, domain.LoginMethodTOTP)
	require.True(t, ok, "ничего не снято")

	// Ф12-28: снятие кодом.
	out, err := h.remove.Execute(context.Background(), humansession.RemoveSecondFactorInput{Bearer: s1.Bearer, Factor: humansession.SecondFactorPresentation{Method: assurance.MethodLookupSecret, Code: codes[0]}, Source: "203.0.113.7"})
	require.NoError(t, err)
	require.Equal(t, "2", out.View.Session.AssuranceLevel, "сверка кода — предъявление")
	require.NotEqual(t, s1.Bearer.Digest(), out.Bearer.Digest())
	_, ok = h.sfRow(u, domain.LoginMethodTOTP)
	require.False(t, ok)
	_, ok = h.sfRow(u, domain.LoginMethodLookupSecret)
	require.False(t, ok)
	for _, b := range []domain.SessionBearer{s2.Bearer, s3up.Bearer} {
		_, reason, err := h.store.Resolve(context.Background(), b.Digest(), h.clock)
		require.NoError(t, err)
		require.Equal(t, humansession.NoSessionEnded, reason, "прочие сессии сняты")
	}
	resolved, reason, err := h.store.Resolve(context.Background(), out.Bearer.Digest(), h.clock)
	require.NoError(t, err)
	require.Equal(t, humansession.SessionFound, reason, "текущая жива")
	require.Equal(t, "2", resolved.Session.AssuranceLevel, "уровня не теряет")
	require.Equal(t, humansession.AssuranceView{Level: "2", Level2Reachable: false, MissingForLevel2: []string{}}, out.Assurance)
	var removed int
	for _, ev := range h.store.audit {
		if ev.EventType == humansession.AuditSecondFactorRemoved {
			removed++
			require.Equal(t, "lookup_secret", ev.Payload["method"])
		}
	}
	require.Equal(t, 1, removed)
	st, err := h.status.Execute(context.Background(), humansession.StatusInput{Bearer: out.Bearer})
	require.NoError(t, err)
	require.False(t, st.TOTPEnrolled)
	require.Nil(t, st.BackupCodes)
	require.Equal(t, 1, h.obs.sfEvents[humansession.SecondFactorRemoved])

	// (г) без фактора — не заведён, не попытка; новое заведение проходит.
	before := h.failures(humansession.FailureByAddress, "rm@example.invalid")
	_, err = h.remove.Execute(context.Background(), humansession.RemoveSecondFactorInput{Bearer: out.Bearer, Factor: humansession.SecondFactorPresentation{Method: assurance.MethodTOTP, Code: "123456"}, Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrSecondFactorNotEnrolled)
	require.Equal(t, before, h.failures(humansession.FailureByAddress, "rm@example.invalid"))
	su, err := h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: out.Bearer, Method: assurance.MethodPassword, Password: "correct horse battery", Source: "203.0.113.7"})
	require.NoError(t, err)
	en, err := h.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: su.Bearer})
	require.NoError(t, err)
	// (д) при pending — не заведён, pending не тронута.
	_, err = h.remove.Execute(context.Background(), humansession.RemoveSecondFactorInput{Bearer: su.Bearer, Factor: humansession.SecondFactorPresentation{Method: assurance.MethodTOTP, Code: probeTOTP(t, en.Secret, h.step())}, Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrSecondFactorNotEnrolled)
	row, ok := h.sfRow(u, domain.LoginMethodTOTP)
	require.True(t, ok)
	require.Equal(t, domain.LoginMethodStatePending, row.State)

	// Транзакция одним исходом: подставной отказ события — ничего не снято.
	cf, err := h.confirm.Execute(context.Background(), humansession.ConfirmInput{Bearer: su.Bearer, Code: probeTOTP(t, en.Secret, h.step()), Source: "203.0.113.7"})
	require.NoError(t, err)
	h.advanceStep(1)
	h.store.failOn = "audit"
	_, err = h.remove.Execute(context.Background(), humansession.RemoveSecondFactorInput{Bearer: cf.Bearer, Factor: humansession.SecondFactorPresentation{Method: assurance.MethodTOTP, Code: probeTOTP(t, en.Secret, h.step())}, Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrStoreUnavailable)
	h.store.failOn = ""
	_, ok = h.sfRow(u, domain.LoginMethodTOTP)
	require.True(t, ok, "при отказе записи очереди изменение не зафиксировано")
}

// ───────────────────────────── подбор ─────────────────────────────────────

// TestF12_31_32_WrongCodesShareTheAttemptCountWithThePassword — Ф12-31 (а, б, д), Ф12-32.
func TestF12_31_32_WrongCodesShareTheAttemptCountWithThePassword(t *testing.T) {
	h := newSFHarness(t)
	_, secret, _ := h.enrolled(t, "usr-rt", "rt@example.invalid", "correct horse battery")
	login := h.mustLogin(t, "rt@example.invalid", "correct horse battery")
	n := sfLimits().AddressAttempts
	for i := 0; i < n; i++ {
		_, err := h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: login.Bearer, Method: assurance.MethodTOTP, Code: probeTOTP(t, secret, h.step()+9), Source: "203.0.113.7"})
		require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	}
	// (а) N+1-й верный — 429, не сверяется.
	_, err := h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: login.Bearer, Method: assurance.MethodTOTP, Code: probeTOTP(t, secret, h.step()), Source: "203.0.113.7"})
	var tma *humansession.TooManyAttemptsError
	require.ErrorAs(t, err, &tma)
	require.Equal(t, humansession.FailureByAddress, tma.Scope)
	row, _ := h.sfRow(login.View.User.ID, domain.LoginMethodTOTP)
	require.Less(t, row.AcceptedStep, h.step(), "верный код в этом окне не сверялся: шаг не записан")

	// (г) после окна — верный проходит; (д) успех обнуляет счёт по адресу.
	h.clock = h.clock.Add(sfLimits().AddressWindow + time.Second)
	_, err = h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: login.Bearer, Method: assurance.MethodTOTP, Code: probeTOTP(t, secret, h.step()), Source: "203.0.113.7"})
	require.NoError(t, err)
	require.Zero(t, h.failures(humansession.FailureByAddress, "rt@example.invalid"))

	// (б) неверные ПАРОЛИ на входе и неверный КОД в церемонии — один счёт.
	h.advanceStep(1)
	login = h.mustLogin(t, "rt@example.invalid", "correct horse battery")
	for i := 0; i < n-1; i++ {
		_, err := h.login.Execute(context.Background(), humansession.LoginInput{Email: "rt@example.invalid", Password: "wrong", Source: "203.0.113.7"})
		require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	}
	_, err = h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: login.Bearer, Method: assurance.MethodTOTP, Code: probeTOTP(t, secret, h.step()+9), Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "N-й — 401")
	_, err = h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: login.Bearer, Method: assurance.MethodTOTP, Code: probeTOTP(t, secret, h.step()), Source: "203.0.113.7"})
	require.ErrorAs(t, err, &tma, "N+1-й — 429: пароль и код — один счёт")

	// Ф12-32: что попыткой не считается — состояние, свежесть, ёмкость.
	h.clock = h.clock.Add(sfLimits().AddressWindow + time.Second)
	h.person(t, "usr-rt2", "rt2@example.invalid", "correct horse battery", true)
	other := h.mustLogin(t, "rt2@example.invalid", "correct horse battery")
	bySource := h.failures(humansession.FailureBySource, "203.0.113.7")
	_, err = h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: other.Bearer, Method: assurance.MethodTOTP, Code: "123456", Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrSecondFactorNotEnrolled)
	require.Equal(t, bySource, h.failures(humansession.FailureBySource, "203.0.113.7"), "состояние — не попытка ни по адресу, ни по источнику")
	require.Zero(t, h.failures(humansession.FailureByAddress, "rt2@example.invalid"))
	require.Equal(t, 1, h.obs.sfRefusals[humansession.RefusalNotEnrolled]+0)
}

// TestF12_35_UnreadableMaterialIsUnavailableNotARefusal — Ф12-35 «в».
func TestF12_35_UnreadableMaterialIsUnavailableNotARefusal(t *testing.T) {
	h := newSFHarness(t)
	login, _, _ := h.enrolled(t, "usr-uw", "uw@example.invalid", "correct horse battery")
	// Материал, который не открывается ни одним ключом: подставлен в строку.
	row := h.store.factors[login.View.User.ID][domain.LoginMethodTOTP]
	v, err := domain.NewLoginVerifier("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	require.NoError(t, err)
	row.Verifier = v
	_, err = h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: login.Bearer, Method: assurance.MethodTOTP, Code: "123456", Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrSecondFactorUnavailable)
	require.Zero(t, h.failures(humansession.FailureByAddress, "uw@example.invalid"), "в счёт попыток не идёт")
	require.Equal(t, 1, h.obs.sfPresent[sfKey(assurance.MethodTOTP, humansession.PresentationMaterialUnreadable)])
	require.Equal(t, 1, h.obs.sfRefusals[humansession.RefusalUnavailable])
}

// TestSecondFactorRefusalTextsAreTheContract — тексты и токены (Р4, §7 инв. 14).
func TestSecondFactorRefusalTextsAreTheContract(t *testing.T) {
	require.Equal(t, "second factor is not enrolled", humansession.ErrSecondFactorNotEnrolled.Error())
	require.Equal(t, "SECOND_FACTOR_NOT_ENROLLED", humansession.ReasonSecondFactorNotEnrolled)
	require.Equal(t, "second factor is already enrolled", humansession.ErrSecondFactorAlreadyEnrolled.Error())
	require.Equal(t, "SECOND_FACTOR_ALREADY_ENROLLED", humansession.ReasonSecondFactorAlreadyEnrolled)
	require.Equal(t, "no pending enrollment: begin with enroll", humansession.ErrEnrollmentNotPending.Error())
	require.Equal(t, "ENROLLMENT_NOT_PENDING", humansession.ReasonEnrollmentNotPending)
	require.Equal(t, "re-authentication required: present a credential again", humansession.ErrSessionNotFresh.Error())
	require.Equal(t, "SESSION_NOT_FRESH", humansession.ReasonSessionNotFresh)
	require.Equal(t, "second factor temporarily unavailable", humansession.ErrSecondFactorUnavailable.Error())
	require.True(t, strings.HasPrefix(humansession.AuditSecondFactorEnrolled, "iam.user."))
}

func sfKey(m assurance.Method, o humansession.PresentationOutcome) string {
	return m.String() + "/" + string(o)
}
