// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys_test

// irreversible_facts_test.go — ДВА решения, которые нельзя принять потом, и
// потому принимаются до первой регистрации на посадке `own`.
//
// # Почему «потом» здесь не бывает
//
// Обнаружимость сообщается расширением свойств удостоверения РОВНО ОДИН раз —
// в церемонии регистрации; из последующих утверждений она не выводится, и
// колонка, заведённая позже, у каждого уже заведённого ключа осталась бы пустой
// навсегда. Рукоятка записывается В АУТЕНТИФИКАТОР и в синхронизируемое
// хранилище держателя, возвращается в каждом утверждении обнаруживаемого
// удостоверения и видна в интерфейсе управления удостоверениями операционной
// системы; отозвать её нечем — писать туда мы не можем.
//
// # Что здесь утверждается
//
// Обнаружимость — ХРАНИМЫЙ ФАКТ СТРОКИ с тремя состояниями, и страж последнего
// способа входа читает его ПОСТРОЧНО, а не из умолчания; рукоятка — отдельное
// случайное значение на человека, не равное ни одному его имени. Замок на
// адрес почты — отдельной пробой: в соседней строке церемонии адрес стоит
// законно (`CeremonyUser.Name`), и подстановка его в рукоятку — правка на один
// символ.

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

// registerWithDiscoverability — регистрация, называющая расширение свойств
// удостоверения явно: `nil` — не сообщено, `&true` — сообщено «обнаруживаемое».
func registerWithDiscoverability(t *testing.T, h *harness, user domain.UserID, a *webauthntest.Authenticator, rk *bool) domain.AccessKey {
	t.Helper()
	ch := h.beginRegistration(user)
	cd, att := a.Register(t, webauthntest.RegistrationOptions{Challenge: ch.Challenge, Origin: origin, RPID: rpID})
	op, err := h.finishRegistration(access_keys.FinishRegistrationInput{
		UserID: user, Actor: user, CredentialID: a.CredentialID(), ClientDataJSON: cd,
		AttestationObject: att, Discoverable: rk,
	})
	require.NoError(t, err)
	require.Nil(t, h.ops.await(t, op.ID).Error, "операция заведения упала")
	k, ok, err := h.store.KeyByCredentialID(h.ctx(), a.CredentialID())
	require.NoError(t, err)
	require.True(t, ok)
	return k
}

// ─── предмет 1: обнаружимость — хранимый факт строки ────────────────────────

// TestAccessKey_LastSignInMethodGuardCountsPresentableKeysNotRows — страж
// последнего способа входа считает ГОДНЫЕ К ПРЕДЪЯВЛЕНИЮ способы, а не строки.
//
// Отрицание: у человека без пароля два ключа, и у обоих обнаружимость НЕ
// подтверждена (клиент расширения не прислал). Снятие любого из них оставило бы
// человека с ключом, который в полосе входа без имени не появится, — то есть
// запертым. Положительный близнец отличается РОВНО ОДНИМ фактом: расширение
// сообщило «обнаруживаемое» — снятие проходит.
func TestAccessKey_LastSignInMethodGuardCountsPresentableKeysNotRows(t *testing.T) {
	t.Parallel()
	// Положительный близнец — ПЕРВЫМ, чтобы красное отрицания не читалось как
	// «проба падает на чём угодно»: те же две строки, отличие ОДНО —
	// расширение сообщило «обнаруживаемое».
	g := newHarness(t)
	g.meth.password[alice] = false
	yes := true
	ok1 := registerWithDiscoverability(t, g, alice, webauthntest.New(t, webauthntest.AlgES256), &yes)
	registerWithDiscoverability(t, g, alice, webauthntest.New(t, webauthntest.AlgES256), &yes)
	op, err := g.revoke(alice, string(ok1.ID))
	require.NoError(t, err, "два подтверждённо обнаружимых ключа: снятие одного законно")
	require.Nil(t, op.Error)
	require.Equal(t, 1, g.store.keyCount(alice))

	h := newHarness(t)
	h.meth.password[alice] = false
	first := registerWithDiscoverability(t, h, alice, webauthntest.New(t, webauthntest.AlgES256), nil)
	registerWithDiscoverability(t, h, alice, webauthntest.New(t, webauthntest.AlgES256), nil)
	_, err = h.revoke(alice, string(first.ID))
	requireReason(t, err, codes.FailedPrecondition, access_keys.ReasonLastSignInMethod)
	require.Equal(t, 2, h.store.keyCount(alice), "ни один ключ не снят")
}

// TestAccessKey_DiscoverabilityIsReadFromTheRowNotFromADefault — признак
// читается ПОСТРОЧНО: у одного человека без пароля две строки с РАЗНЫМ
// признаком, и исход снятия у них разный. Продукт, берущий признак из
// умолчания — любого из трёх, — обе ветви разом не проходит: он либо пропустит
// снятие единственного годного, либо откажет в снятии негодного.
func TestAccessKey_DiscoverabilityIsReadFromTheRowNotFromADefault(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.meth.password[alice] = false
	yes := true
	confirmed := registerWithDiscoverability(t, h, alice, webauthntest.New(t, webauthntest.AlgES256), &yes)
	silent := registerWithDiscoverability(t, h, alice, webauthntest.New(t, webauthntest.AlgES256), nil)

	// Снятие ЕДИНСТВЕННОГО годного к предъявлению — отказ: строка, которая
	// останется, в полосе входа без имени не появится.
	_, err := h.revoke(alice, string(confirmed.ID))
	requireReason(t, err, codes.FailedPrecondition, access_keys.ReasonLastSignInMethod)
	require.Equal(t, 2, h.store.keyCount(alice))

	// Снятие НЕГОДНОГО — проходит: годный остаётся.
	op, err := h.revoke(alice, string(silent.ID))
	require.NoError(t, err, "снятие строки, которая способом входа не была, законно")
	require.Nil(t, op.Error)
	require.Equal(t, 1, h.store.keyCount(alice))
}

// ─── предмет 2: рукоятка — не платформенный идентификатор ───────────────────

// TestAccessKey_CeremonyHandleIsNotThePlatformIdentifier — рукоятка церемонии
// и рукоятка, легшая в строку, — отдельное случайное значение: не равны `id`
// человека, длиной с рекомендацию нормы, одна у всех ключей человека и разные
// у разных людей.
func TestAccessKey_CeremonyHandleIsNotThePlatformIdentifier(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	ch := h.beginRegistration(alice)
	require.NotEqual(t, []byte(alice), []byte(ch.UserHandle), "рукоятка церемонии равна платформенному id")
	// 64 — рекомендация нормы §14.6.1 («64 random bytes»); после правки
	// величина переезжает в `domain.CeremonyHandleBytes`, здесь она названа
	// числом, потому что на день красного объявителя у неё нет.
	require.Len(t, []byte(ch.UserHandle), 64, "рукоятка — 64 случайных байта (норма §14.6.1)")

	first := registerWithDiscoverability(t, h, alice, webauthntest.New(t, webauthntest.AlgES256), nil)
	require.NotEqual(t, []byte(alice), first.UserHandle, "рукоятка строки равна платформенному id")
	require.Equal(t, []byte(ch.UserHandle), first.UserHandle,
		"в строку легло не то, что церемония положила в user.id")

	second := registerWithDiscoverability(t, h, alice, webauthntest.New(t, webauthntest.AlgES256), nil)
	require.Equal(t, first.UserHandle, second.UserHandle, "рукоятка ОДНА на человека")

	bobKey := registerWithDiscoverability(t, h, bob, webauthntest.New(t, webauthntest.AlgES256), nil)
	require.NotEqual(t, first.UserHandle, bobKey.UserHandle, "у разных людей рукоятки разные")
}

// TestAccessKey_CeremonyHandleCarriesNoNameOfThePerson — ЗАМОК: в рукоятку не
// попадает ни адрес почты, ни отображаемое имя, ни платформенный `id`. Адрес
// стоит в соседней строке церемонии законно (`CeremonyUser.Name`), поэтому
// утверждение — не о равенстве, а о ВХОЖДЕНИИ: подставленный адрес, дополненный
// до длины рукоятки, проба тоже находит.
func TestAccessKey_CeremonyHandleCarriesNoNameOfThePerson(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	user, err := h.store.UserOf(h.ctx(), alice)
	require.NoError(t, err)
	require.NotEmpty(t, user.Email, "предпосылка пробы: у человека есть адрес")
	require.NotEmpty(t, user.DisplayName, "предпосылка пробы: у человека есть отображаемое имя")

	key := registerWithDiscoverability(t, h, alice, webauthntest.New(t, webauthntest.AlgES256), nil)
	for _, name := range []struct{ what, value string }{
		{"адрес почты", string(user.Email)},
		{"отображаемое имя", string(user.DisplayName)},
		{"платформенный id", string(user.ID)},
	} {
		require.False(t, bytes.Contains(bytes.ToLower(key.UserHandle), bytes.ToLower([]byte(name.value))),
			"рукоятка несёт %s (%q): отозвать её нечем — она уже в чужом аутентификаторе", name.what, name.value)
	}
}
