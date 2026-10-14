// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys_test

// ceremony_handle_test.go — Ф13-33 (I) на уровне сценария: значение рукоятки
// `user.id` церемонии регистрации — ОТДЕЛЬНОЕ СЛУЧАЙНОЕ значение человека
// (приёмка `passwordless-login-with-access-key.md`, Р3, редакция 9; норма
// WebAuthn §14.6.1), а не его платформенный `id`.
//
// Рукоятка уезжает в аутентификатор и в синхронизируемое хранилище держателя,
// отозвать её оттуда нечем. Поэтому значение судится по тому, что ЛЕГЛО: длина
// — верхняя граница нормы, одно на человека у всех его церемоний, разное у
// разных людей, и ни одно не несёт имени своего человека (`id`, адрес;
// отображаемое имя не судится — см. `TestAccessKey_F13_33_ShortDisplayNameDoesNotLockOutRegistration`).
// Отрицательный контроль назван в приёмке: реализация,
// оставившая рукоятку равной `id`, зелена на всех прочих сценариях; различают
// её только эти пробы и гейт по дереву (`ceremony_handle_gate_test.go`).

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// ceremonyHandleBytes — верхняя граница нормы для `user.id` (Р3: значение во
// всю ширину). Литерал, а не константа продукта: проба не берёт ожидаемое у
// того, кого судит.
const ceremonyHandleBytes = 64

// requireCeremonyHandleOf — рукоятка годна для человека `id`: длина нормы, не
// нули и ни одного идентификатора человека (`id`, адрес) внутри (вхождение, без учёта регистра:
// дополненный адрес равенства не дал бы, а уехал бы так же безвозвратно).
func requireCeremonyHandleOf(t *testing.T, h *harness, id domain.UserID, handle []byte) {
	t.Helper()
	require.Len(t, handle, ceremonyHandleBytes, "рукоятка — 64 байта, верхняя граница нормы (Р3)")
	require.NotEqual(t, make([]byte, ceremonyHandleBytes), handle, "рукоятку не чеканили — нули")
	u, err := h.store.UserOf(context.Background(), id)
	require.NoError(t, err)
	for field, name := range map[string]string{"id": string(u.ID), "email": string(u.Email)} {
		require.False(t, bytes.Contains(bytes.ToLower(handle), bytes.ToLower([]byte(name))),
			"рукоятка несёт %s человека — значение в аутентификаторе не отзывается", field)
	}
}

// TestAccessKey_F13_33_CeremonyHandleIsOneRandomValuePerPerson — две церемонии
// одного человека дают одну рукоятку, у другого человека она другая, и строка
// ключа помнит ровно ту, что ушла в `user.id`.
func TestAccessKey_F13_33_CeremonyHandleIsOneRandomValuePerPerson(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	first := h.beginRegistration(alice)
	again := h.beginRegistration(alice)
	other := h.beginRegistration(bob)

	requireCeremonyHandleOf(t, h, alice, first.UserHandle)
	requireCeremonyHandleOf(t, h, bob, other.UserHandle)
	require.Equal(t, first.UserHandle, again.UserHandle, "одна рукоятка на человека у всех его церемоний")
	require.NotEqual(t, first.UserHandle, other.UserHandle, "у разных людей рукоятки разные")

	// Второй приёмник — строка ключа: сверка утверждения идёт с ней (Ф13-06 «з»).
	key := h.mustRegister(alice, webauthntest.New(t, webauthntest.AlgES256))
	require.Equal(t, first.UserHandle, key.UserHandle, "строка ключа несёт ту рукоятку, что ушла в user.id")
}

// TestAccessKeyHandler_F13_33_CeremonyUserIdIsTheHandle — то же на транспорте:
// `user.id` выданного испытания — рукоятка, и `id` человека в нём нет.
func TestAccessKeyHandler_F13_33_CeremonyUserIdIsTheHandle(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	hd := h.handler()
	ch, err := hd.BeginRegistration(asUser(alice), &iamv1.BeginAccessKeyRegistrationRequest{UserId: string(alice)})
	require.NoError(t, err)
	requireCeremonyHandleOf(t, h, alice, ch.GetUser().GetId())
	again, err := hd.BeginRegistration(asUser(alice), &iamv1.BeginAccessKeyRegistrationRequest{UserId: string(alice)})
	require.NoError(t, err)
	require.Equal(t, ch.GetUser().GetId(), again.GetUser().GetId())
}

// TestAccessKey_F13_33_HandleStoreFailureIssuesNoChallenge — рукоятку не
// удалось ни завести, ни прочесть: испытание НЕ выдаётся (fail-closed), отказ —
// недоступность, а не испытание с подставленным значением.
func TestAccessKey_F13_33_HandleStoreFailureIssuesNoChallenge(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.store.failWriter = true
	uc, err := access_keys.NewBeginRegistrationUseCase(h.deps)
	require.NoError(t, err)
	_, err = uc.Execute(h.ctx(), access_keys.BeginRegistrationInput{UserID: alice, Actor: alice})
	requireCode(t, err, codes.Unavailable)
	require.Empty(t, h.store.challenges, "испытание без рукоятки не выдаётся")
}

// TestAccessKey_F13_33_ShortDisplayNameDoesNotLockOutRegistration — рукоятка,
// уже лёгшая за человеком, содержит его однобуквенное отображаемое имя (так
// случается примерно в четырёх чеканках из десяти): регистрация идёт, и
// испытание несёт ту же рукоятку. Рукоятка не меняется после заведения, так что
// отказ здесь был бы вечным. Близнец ниже — та же форма с `id` человека внутри:
// отказ недоступностью и ни одного испытания.
func TestAccessKey_F13_33_ShortDisplayNameDoesNotLockOutRegistration(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	u := h.store.users[alice]
	u.DisplayName = "A"
	h.store.users[alice] = u
	stored := bytes.Repeat([]byte("a"), ceremonyHandleBytes)
	h.store.handles[alice] = stored

	out := h.beginRegistration(alice)
	require.Equal(t, stored, out.UserHandle, "лёгшая рукоятка уходит в user.id как есть")
	require.Len(t, h.store.challenges, 1)
}

// TestAccessKey_F13_33_StoredHandleCarryingTheIdIsRefused — законный близнец
// предыдущей: лёгшая рукоятка несёт платформенный `id` человека — испытание не
// выдаётся, отказ — недоступность.
func TestAccessKey_F13_33_StoredHandleCarryingTheIdIsRefused(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	stored := append([]byte(alice), bytes.Repeat([]byte("a"), ceremonyHandleBytes-len(alice))...)
	h.store.handles[alice] = stored

	uc, err := access_keys.NewBeginRegistrationUseCase(h.deps)
	require.NoError(t, err)
	_, err = uc.Execute(h.ctx(), access_keys.BeginRegistrationInput{UserID: alice, Actor: alice})
	requireCode(t, err, codes.Unavailable)
	require.Empty(t, h.store.challenges, "испытание с рукояткой, несущей id, не выдаётся")
}
