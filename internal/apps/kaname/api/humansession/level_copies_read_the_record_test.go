// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// level_copies_read_the_record_test.go — КОПИИ уровня уверенности читают
// запись сессии, а не пересчитывают его от имён способов (задачи
// PRO-Robotech/kaname#208 и #343; приёмки Ф11
// `assurance-level-is-declared-by-our-session.md` Р1, Р2 и Ф13
// `passwordless-login-with-access-key.md` Ф13-13, Ф13-17).
//
// # «Дано» — согласованным состоянием записи
//
// Сессия уровня «3» производится только входом ключом с проверкой
// пользователя (Ф13). Здесь она строится ЗАПИСЬЮ: множество {webauthn} и
// уровень «3» — единственное согласованное состояние для этого множества
// (Ф11 §3.0а: флаги утверждения в записи не хранятся). Близнец — та же запись
// с уровнем «2»: различие пары ровно одно — записанный уровень.
package humansession_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
)

// keySession — сессия, выданная входом ключом на уровне level: запись
// приводится к {webauthn} и уровню; носитель — тот же.
func keySession(t *testing.T, store *fakeStore, out humansession.LoginOutput, level string) {
	t.Helper()
	row, ok := store.rows[out.View.Session.ID]
	require.True(t, ok, "Дано: запись сессии существует")
	row.s.PresentedMethods = []string{assurance.MethodWebAuthn.String()}
	row.s.AssuranceLevel = level
}

// TestChangePassword_208_ResponseLevelReadsTheRecord — Ф13-13 (а): ответ
// смены пароля из сессии «3» называет «3»; близнец «2» — «2». Уровень записи
// смена пароля не трогает (Ф3 Р6), и копия обязана быть его чтением.
func TestChangePassword_208_ResponseLevelReadsTheRecord(t *testing.T) {
	for _, recorded := range []string{"3", "2"} {
		t.Run("recorded-"+recorded, func(t *testing.T) {
			h := newHarness(t, nil)
			h.person(t, "usr-a", "a@example.invalid", "correct horse battery", true)
			login := h.mustLogin(t, "a@example.invalid", "correct horse battery")
			keySession(t, h.store, login, recorded)

			h.clock = ucBase.Add(time.Minute)
			out, err := h.change.Execute(context.Background(), humansession.ChangePasswordInput{
				Bearer: login.Bearer, CurrentPassword: "correct horse battery", NewPassword: "brand new passphrase",
				Source: "203.0.113.7",
			})
			require.NoError(t, err, "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: смена пароля проходит")
			require.Equal(t, recorded, out.View.Session.AssuranceLevel,
				"kaname#208: копия уровня в ответе смены пароля — чтение записи («%s»), а не пересчёт от имён способов", recorded)
			require.Equal(t, recorded, h.store.rows[login.View.Session.ID].s.AssuranceLevel, "уровень записи не тронут")
		})
	}
}

// TestStepUp_343_PresentationInsideAKeySessionKeepsTheLevel — Ф13-17 (б):
// предъявление пароля внутри сессии, выданной ключом, проходит, носитель
// перевыпущен, а уровень — прежний и в записи, и в ответе церемонии. Близнец
// «2» — «2». Близнец с другой стороны оси (сессия «1» поднимается кодом до
// «2») — TestF12_15_18_StepUpWithACodeRaisesTheSession: условие на прежнее
// значение не превращает запись в константу.
func TestStepUp_343_PresentationInsideAKeySessionKeepsTheLevel(t *testing.T) {
	for _, recorded := range []string{"3", "2"} {
		t.Run("recorded-"+recorded, func(t *testing.T) {
			h := newSFHarness(t)
			h.person(t, "usr-a", "a@example.invalid", "correct horse battery", true)
			login := h.mustLogin(t, "a@example.invalid", "correct horse battery")
			keySession(t, h.store, login, recorded)

			h.clock = ucBase.Add(time.Minute)
			out, err := h.stepUp.Execute(context.Background(), humansession.StepUpInput{
				Bearer: login.Bearer, Method: assurance.MethodPassword, Password: "correct horse battery", Source: "203.0.113.7",
			})
			require.NoError(t, err, "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: предъявление пароля внутри сессии проходит")
			require.NotEqual(t, login.Bearer.CookieValue(), out.Bearer.CookieValue(), "носитель перевыпущен")
			require.Equal(t, recorded, h.store.rows[login.View.Session.ID].s.AssuranceLevel,
				"kaname#343: запись уровня «%s» после предъявления с более бедным множеством — прежняя (Ф11 Р2)", recorded)
			require.Equal(t, recorded, out.View.Session.AssuranceLevel, "ответ — чтение записи")
			require.Equal(t, recorded, out.Assurance.Level, "Ф13-17: церемония называет достигнутый уровень равным прежнему")
			require.Empty(t, out.Assurance.MissingForLevel2, "Ф13-17: перечень недостающего пуст")
			require.ElementsMatch(t, []string{"webauthn", "password"}, h.store.rows[login.View.Session.ID].s.PresentedMethods,
				"множество предъявленного накоплено")
		})
	}
}
