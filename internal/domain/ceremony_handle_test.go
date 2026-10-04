// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

// ceremony_handle_test.go — самопроверка рукоятки церемонии (Ф13 Р3): форма
// нормы, два производителя, выход байтов копией, замок «ни одного имени
// человека» и тот же замок у строки ключа. Каждое отрицание — рядом с
// положительным близнецом, отличающимся одним фактом.

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestCeremonyHandle_NewIsSixtyFourRandomBytes(t *testing.T) {
	t.Parallel()
	a, err := domain.NewCeremonyHandle()
	require.NoError(t, err)
	b, err := domain.NewCeremonyHandle()
	require.NoError(t, err)
	require.NoError(t, a.Validate())
	require.Len(t, a.Bytes(), 64)
	require.NotEqual(t, a.Bytes(), b.Bytes(), "два производства — два значения")
	require.False(t, a.IsZero())
	require.True(t, domain.CeremonyHandle{}.IsZero(), "нулевое значение — «рукоятки нет»")
	require.Error(t, domain.CeremonyHandle{}.Validate())
}

func TestCeremonyHandle_RestoreJudgesTheStoredForm(t *testing.T) {
	t.Parallel()
	good := bytes.Repeat([]byte{0x5a}, 64)
	h, err := domain.RestoreCeremonyHandle(good)
	require.NoError(t, err, "близнец: 64 ненулевых байта")
	require.Equal(t, good, h.Bytes())
	for name, raw := range map[string][]byte{
		"63 байта": bytes.Repeat([]byte{0x5a}, 63),
		"65 байт":  bytes.Repeat([]byte{0x5a}, 65),
		"нули":     make([]byte, 64),
		"пусто":    nil,
	} {
		_, err := domain.RestoreCeremonyHandle(raw)
		require.Error(t, err, name)
		require.Contains(t, err.Error(), "user_handle", name)
	}
}

func TestCeremonyHandle_BytesIsACopy(t *testing.T) {
	t.Parallel()
	stored := bytes.Repeat([]byte{0x11}, 64)
	h, err := domain.RestoreCeremonyHandle(stored)
	require.NoError(t, err)
	stored[0] = 0x22
	out := h.Bytes()
	require.Equal(t, byte(0x11), out[0], "правка входа не меняет рукоятку")
	out[1] = 0x33
	require.Equal(t, byte(0x11), h.Bytes()[1], "правка выхода не меняет рукоятку")
}

func TestCeremonyHandle_CarriesNoNameOfThePerson(t *testing.T) {
	t.Parallel()
	u := domain.User{ID: "usr00000000000000a01", Email: "alice@example.invalid", DisplayName: "Alice Person"}
	pad := func(s string) []byte {
		return []byte(s + strings.Repeat("\x01", 64-len(s)))
	}
	clean, err := domain.NewCeremonyHandle()
	require.NoError(t, err)
	require.NoError(t, clean.CarriesNoNameOf(u), "близнец: случайное значение")
	for field, raw := range map[string][]byte{
		"id":    pad(string(u.ID)),
		"email": pad(strings.ToUpper(string(u.Email))),
	} {
		h, err := domain.RestoreCeremonyHandle(raw)
		require.NoError(t, err, "%s: форма годна — судится только имя", field)
		err = h.CarriesNoNameOf(u)
		require.Error(t, err, field)
		require.Contains(t, err.Error(), field)
	}
}

// TestCeremonyHandle_DisplayNameIsNotJudged — отображаемое имя рукоятку НЕ
// судит. Его длина — от одного символа, и случайные 64 байта несут однобуквенное
// имя примерно в четырёх чеканках из десяти (без учёта регистра); рукоятка
// заводится один раз и не меняется, поэтому такой отказ был бы вечным отказом
// человеку в регистрации ключа. Имя — не идентификатор: им ничего не ищут и не
// ключуют, а `id` (20 знаков) и адрес (не короче пяти, с `@` и точкой)
// случайно в 64 байтах не встречаются.
//
// Отличие от близнеца `TestCeremonyHandle_CarriesNoNameOfThePerson` — ровно
// один факт: вхождение имени, а не `id` либо адреса.
func TestCeremonyHandle_DisplayNameIsNotJudged(t *testing.T) {
	t.Parallel()
	u := domain.User{ID: "usr00000000000000a01", Email: "alice@example.invalid", DisplayName: "A"}
	h, err := domain.RestoreCeremonyHandle(bytes.Repeat([]byte("a"), 64))
	require.NoError(t, err)
	require.NoError(t, h.CarriesNoNameOf(u), "однобуквенное имя внутри случайных байтов — не имя человека в рукоятке")
}

func TestAccessKey_HandleCarryingThePlatformIdIsRefused(t *testing.T) {
	t.Parallel()
	minted, err := domain.NewCeremonyHandle()
	require.NoError(t, err)
	key := domain.AccessKey{
		ID: "ak-00000000000000001", UserID: "usr00000000000000a01", CredentialID: []byte("cred"),
		PublicKey: []byte{0xa5}, Algorithm: -7, UserHandle: minted.Bytes(), Name: "key-1",
		CreatedAt: time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC),
	}
	require.NoError(t, key.Validate(), "близнец: рукоятка носителя")
	key.UserHandle = []byte("usr00000000000000a01")
	err = key.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "user_handle")
}
