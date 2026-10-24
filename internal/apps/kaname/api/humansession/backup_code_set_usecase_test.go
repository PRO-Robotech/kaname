// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// backup_code_set_usecase_test.go — пробы use-case приёмки
// `docs/engineering/acceptance/backup-code-set-has-one-form.md` (kaname#297):
// состояние набора запасных кодов — одна величина `BackupCodeSetView` в
// выходах подтверждения, перечеканки, повышения и чтения состояния; значения
// выхода глагола совпадают со значениями следующего чтения состояния; сводка
// строится только о ПРОЧИТАННОМ наборе (BCS-50, BCS-51).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// requireSameSet — две величины набора равны по всем полям (моменты — до
// секунды, как их видит ответ: `moment` усекает до секунды).
func requireSameSet(t *testing.T, id string, want, got humansession.BackupCodeSetView) {
	t.Helper()
	require.Equalf(t, want.Remaining, got.Remaining, "%s: remaining", id)
	require.Equalf(t, want.Total, got.Total, "%s: total", id)
	require.Truef(t, want.IssuedAt.Truncate(time.Second).Equal(got.IssuedAt.Truncate(time.Second)),
		"%s: issuedAt %s против %s", id, want.IssuedAt, got.IssuedAt)
	require.Equalf(t, want.LastUsed, got.LastUsed, "%s: присутствие lastUsedAt", id)
	if want.LastUsed {
		require.Truef(t, want.LastUsedAt.Truncate(time.Second).Equal(got.LastUsedAt.Truncate(time.Second)),
			"%s: lastUsedAt %s против %s", id, want.LastUsedAt, got.LastUsedAt)
	}
}

// statusSet — сводка набора следующего чтения состояния; nil — ключа нет.
func (h *sfHarness) statusSet(t *testing.T, bearer domain.SessionBearer) (humansession.StatusOutput, *humansession.BackupCodeSetView) {
	t.Helper()
	st, err := h.status.Execute(context.Background(), humansession.StatusInput{Bearer: bearer})
	require.NoError(t, err)
	return st, st.BackupCodeSet
}

// TestBCS03_ConfirmReportsTheMintedSetAsTheNextStatusDoes — BCS-03: выход
// подтверждения несёт сводку только что выпущенного набора `{10, 10, issuedAt}`
// без момента траты, и она равна сводке следующего чтения состояния.
func TestBCS03_ConfirmReportsTheMintedSetAsTheNextStatusDoes(t *testing.T) {
	h := newSFHarness(t)
	h.person(t, "usr-bcs03", "bcs03@example.invalid", "correct horse battery", true)
	login := h.freshSession(t, "bcs03@example.invalid", "correct horse battery")
	en, err := h.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: login.Bearer})
	require.NoError(t, err)
	h.clock = h.clock.Add(time.Minute)
	confirmedAt := h.clock

	out, err := h.confirm.Execute(context.Background(), humansession.ConfirmInput{
		Bearer: login.Bearer, Code: probeTOTP(t, en.Secret, h.step()), Source: "203.0.113.7",
	})
	require.NoError(t, err)
	require.Len(t, out.BackupCodes, passwordverify.BackupCodeCount, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): confirm выдал набор")

	want := humansession.BackupCodeSetView{Remaining: 10, Total: 10, IssuedAt: confirmedAt}
	requireSameSet(t, "BCS-03 выход confirm", want, out.BackupCodeSet)
	_, next := h.statusSet(t, out.Bearer)
	require.NotNil(t, next, "BCS-03: следующее чтение состояния несёт сводку")
	requireSameSet(t, "BCS-03 confirm = следующий GET", *next, out.BackupCodeSet)
}

// TestBCS04_05_RegenerateReportsTheNewSetNotTheOld — BCS-04 (кодом по
// времени) и BCS-05 (запасным кодом): сводка — НОВОГО набора `{10, 10,
// issuedAt}` без момента траты, а не остаток прежнего (8 у BCS-05).
func TestBCS04_05_RegenerateReportsTheNewSetNotTheOld(t *testing.T) {
	for _, tc := range []struct {
		id     string
		method assurance.Method
	}{
		{"BCS-04", assurance.MethodTOTP},
		{"BCS-05", assurance.MethodLookupSecret},
	} {
		t.Run(tc.id, func(t *testing.T) {
			h := newSFHarness(t)
			login, secret, codes := h.enrolled(t, "usr-"+tc.id, tc.id+"@example.invalid", "correct horse battery")
			spent, err := h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: login.Bearer, Method: assurance.MethodLookupSecret, Code: codes[0], Source: "203.0.113.7"})
			require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): трата C1")
			_, before := h.statusSet(t, spent.Bearer)
			require.NotNil(t, before)
			require.Equal(t, 9, before.Remaining, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): после траты C1 остаток 9")
			h.advanceStep(1)
			h.clock = h.clock.Add(time.Second)
			code := probeTOTP(t, secret, h.step())
			if tc.method == assurance.MethodLookupSecret {
				code = codes[1]
			}
			at := h.clock

			out, err := h.regenerate.Execute(context.Background(), humansession.RegenerateBackupCodesInput{
				Bearer: spent.Bearer, Factor: humansession.SecondFactorPresentation{Method: tc.method, Code: code}, Source: "203.0.113.7",
			})
			require.NoError(t, err)
			require.Len(t, out.BackupCodes, passwordverify.BackupCodeCount)

			want := humansession.BackupCodeSetView{Remaining: 10, Total: 10, IssuedAt: at}
			requireSameSet(t, tc.id+" выход перечеканки", want, out.BackupCodeSet)
			require.False(t, out.BackupCodeSet.IssuedAt.Before(before.IssuedAt), "%s: issuedAt не раньше прежнего", tc.id)
			_, next := h.statusSet(t, out.Bearer)
			require.NotNil(t, next)
			requireSameSet(t, tc.id+" перечеканка = следующий GET", *next, out.BackupCodeSet)
		})
	}
}

// TestBCS06_StepUpWithABackupCodeReportsTheSetAfterTheSpend — BCS-06: выход
// повышения запасным кодом — сводка набора ПОСЛЕ траты: остаток 9, выпуск
// прежний, момент траты — момент этого повышения; равна следующему чтению.
func TestBCS06_StepUpWithABackupCodeReportsTheSetAfterTheSpend(t *testing.T) {
	h := newSFHarness(t)
	login, _, codes := h.enrolled(t, "usr-bcs06", "bcs06@example.invalid", "correct horse battery")
	_, given := h.statusSet(t, login.Bearer)
	require.NotNil(t, given, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): сводка до траты")
	require.False(t, given.LastUsed, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): из набора не тратили")
	h.clock = h.clock.Add(time.Minute)
	spentAt := h.clock

	out, err := h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: login.Bearer, Method: assurance.MethodLookupSecret, Code: codes[0], Source: "203.0.113.7"})
	require.NoError(t, err)
	require.NotNil(t, out.BackupCodeSet, "BCS-06: выход повышения запасным кодом несёт сводку")

	want := humansession.BackupCodeSetView{Remaining: 9, Total: 10, IssuedAt: given.IssuedAt, LastUsedAt: spentAt, LastUsed: true}
	requireSameSet(t, "BCS-06 выход повышения", want, *out.BackupCodeSet)
	_, next := h.statusSet(t, out.Bearer)
	require.NotNil(t, next)
	requireSameSet(t, "BCS-06 повышение = следующий GET", *next, *out.BackupCodeSet)
}

// TestBCS07_StepUpWithATimeCodeCarriesNoSet — BCS-07, близнец BCS-06: способ
// иной — набор глаголом не менялся, сводки в выходе нет.
func TestBCS07_StepUpWithATimeCodeCarriesNoSet(t *testing.T) {
	h := newSFHarness(t)
	login, secret, _ := h.enrolled(t, "usr-bcs07", "bcs07@example.invalid", "correct horse battery")

	out, err := h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: login.Bearer, Method: assurance.MethodTOTP, Code: probeTOTP(t, secret, h.step()), Source: "203.0.113.7"})
	require.NoError(t, err)
	require.Nil(t, out.BackupCodeSet, "BCS-07: способ totp набора не меняет — сводки нет")
	_, next := h.statusSet(t, out.Bearer)
	require.NotNil(t, next)
	require.Equal(t, 10, next.Remaining, "BCS-07: остаток не изменился")
}

// TestBCS50_51_StatusWithoutAReadableSetHasNoSummary — BCS-50 (строки набора
// нет) и BCS-51 (материал не открывается) против близнеца BCS-01 (набор на
// месте): сводки нет вовсе — ни нулевого остатка, ни нулевого момента;
// фактор заведён, `lookup_secret` способом повышения не назван.
func TestBCS50_51_StatusWithoutAReadableSetHasNoSummary(t *testing.T) {
	for _, tc := range []struct {
		id    string
		spoil func(t *testing.T, h *sfHarness, user domain.UserID)
	}{
		{"BCS-01", func(*testing.T, *sfHarness, domain.UserID) {}},
		{"BCS-50", func(t *testing.T, h *sfHarness, user domain.UserID) {
			_, ok := h.store.factors[user][domain.LoginMethodLookupSecret]
			require.True(t, ok, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): строка набора есть до удаления")
			delete(h.store.factors[user], domain.LoginMethodLookupSecret)
		}},
		{"BCS-51", func(t *testing.T, h *sfHarness, user domain.UserID) {
			row, ok := h.store.factors[user][domain.LoginMethodLookupSecret]
			require.True(t, ok, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): строка набора есть до порчи")
			row.Verifier = unreadableStored(t)
		}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			h := newSFHarness(t)
			u := h.person(t, "usr-"+tc.id, tc.id+"@example.invalid", "correct horse battery", true)
			login := h.freshSession(t, tc.id+"@example.invalid", "correct horse battery")
			en, err := h.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: login.Bearer})
			require.NoError(t, err)
			cf, err := h.confirm.Execute(context.Background(), humansession.ConfirmInput{
				Bearer: login.Bearer, Code: probeTOTP(t, en.Secret, h.step()), Source: "203.0.113.7",
			})
			require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): заведение подтверждено")
			tc.spoil(t, h, u.ID)

			st, set := h.statusSet(t, cf.Bearer)
			require.True(t, st.TOTPEnrolled, "%s: фактор заведён", tc.id)
			if tc.id == "BCS-01" {
				require.NotNil(t, set, "BCS-01: набор прочитан — сводка есть")
				require.Equal(t, 10, set.Remaining)
				require.False(t, set.IssuedAt.IsZero(), "BCS-01: момент выпуска настоящий")
				require.Contains(t, st.StepUpMethods, assurance.MethodLookupSecret.String())
				return
			}
			require.Nil(t, set, "%s: набора нет либо он не читается — сводки нет, а не нули", tc.id)
			require.NotContains(t, st.StepUpMethods, assurance.MethodLookupSecret.String(), "%s: запасной код способом не назван", tc.id)
		})
	}
}
