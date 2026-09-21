// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

// ceremony_handle_test.go — рукоятка церемонии и обнаружимость ключа как
// САМОПРОВЕРЯЮЩИЕСЯ величины домена. Каждое отрицание стоит рядом с законным
// близнецом, отличающимся РОВНО ОДНИМ фактом.

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TestCeremonyHandle_IsMintedRandomAndOfTheNormsLength — производитель даёт
// значение длины нормы, и два вызова подряд его не повторяют.
func TestCeremonyHandle_IsMintedRandomAndOfTheNormsLength(t *testing.T) {
	t.Parallel()
	first, err := domain.NewCeremonyHandle()
	require.NoError(t, err)
	require.Len(t, []byte(first), domain.CeremonyHandleBytes)
	require.NoError(t, first.Validate())

	second, err := domain.NewCeremonyHandle()
	require.NoError(t, err)
	require.NotEqual(t, []byte(first), []byte(second), "производитель повторился — значение не случайное")
}

// TestCeremonyHandle_ValidateSeparatesTheTwoWaysOfBeingWrong — негодная длина и
// незачеканенное значение различимы: чинятся они разным.
func TestCeremonyHandle_ValidateSeparatesTheTwoWaysOfBeingWrong(t *testing.T) {
	t.Parallel()
	good, err := domain.NewCeremonyHandle()
	require.NoError(t, err)
	require.NoError(t, good.Validate(), "законный близнец молчит")

	short := domain.CeremonyHandle(bytes.Repeat([]byte{0x7f}, domain.CeremonyHandleBytes-1))
	require.ErrorContains(t, short.Validate(), "random bytes")

	forgotten := domain.CeremonyHandle(make([]byte, domain.CeremonyHandleBytes))
	require.ErrorContains(t, forgotten.Validate(), "was not minted",
		"нули длины нормы обязаны читаться как забытая чеканка, а не как годное значение")
}

// TestCeremonyHandle_CarriesNoNameOfInjection — ЗАМОК, доказанный инъекцией в
// обе стороны: каждое имя человека, подставленное в рукоятку — в том числе
// дополненное до длины нормы, — находится и названо полем; чеканенная рукоятка
// молчит.
func TestCeremonyHandle_CarriesNoNameOfInjection(t *testing.T) {
	t.Parallel()
	user := domain.User{
		ID: "usr00000000000000a01", Email: "Person@Example.Invalid", DisplayName: "Person Personovich",
	}
	minted, err := domain.NewCeremonyHandle()
	require.NoError(t, err)
	require.NoError(t, minted.CarriesNoNameOf(user), "законный близнец: чеканенная рукоятка молчит")

	for _, tc := range []struct{ name, value, field string }{
		{"платформенный id", string(user.ID), "id"},
		{"адрес почты", string(user.Email), "email"},
		{"адрес почты в нижнем регистре", "person@example.invalid", "email"},
		{"отображаемое имя", string(user.DisplayName), "display_name"},
	} {
		// Подставленное значение ДОПОЛНЕНО до длины нормы: проверка равенства
		// такую подстановку пропустила бы, а уехала бы она так же безвозвратно.
		padded := domain.CeremonyHandle(append([]byte(tc.value),
			bytes.Repeat([]byte{0x2d}, domain.CeremonyHandleBytes-len(tc.value))...))
		require.Len(t, []byte(padded), domain.CeremonyHandleBytes, "%s: инъекция обязана быть годной по длине", tc.name)
		require.NoError(t, padded.Validate(), "%s: инъекция проходит длину — падает ИМЕННО замок", tc.name)
		err := padded.CarriesNoNameOf(user)
		require.Error(t, err, "%s: замок пропустил подстановку", tc.name)
		require.ErrorContains(t, err, tc.field, "%s: находка обязана называть поле", tc.name)
	}

	// Человек без адреса и без имени: пустые значения замок не судит — иначе
	// любая рукоятка «несла бы» пустую строку.
	bare := domain.User{ID: "usr00000000000000b02"}
	require.NoError(t, minted.CarriesNoNameOf(bare))
}

// TestAccessKeyDiscoverability_VocabularyIsClosedAndOnlyOneIsPresentable —
// словарь из трёх состояний; годным к предъявлению считается ровно одно.
func TestAccessKeyDiscoverability_VocabularyIsClosedAndOnlyOneIsPresentable(t *testing.T) {
	t.Parallel()
	all := domain.AccessKeyDiscoverabilities()
	require.Len(t, all, 3, "словарь закрыт тремя состояниями")

	presentable := 0
	for _, d := range all {
		require.NoError(t, d.Validate(), "состояние словаря %q обязано проходить", d)
		if d.Presentable() {
			presentable++
		}
	}
	require.Equal(t, 1, presentable, "годным к предъявлению обязано быть ровно одно состояние")
	require.True(t, domain.DiscoverabilityConfirmed.Presentable())
	require.False(t, domain.DiscoverabilityRefuted.Presentable(), "«сообщено, что не обнаруживаемое» годным не делает")
	require.False(t, domain.DiscoverabilityNotReported.Presentable(), "«не сообщено» годным не делает")

	require.Error(t, domain.AccessKeyDiscoverability("").Validate(),
		"пустое состояние означало бы, что спросить забыли, а спрашивать уже не у кого")
	require.Error(t, domain.AccessKeyDiscoverability("maybe").Validate())
}

// TestAccessKey_ValidateRefusesAHandleCarryingThePlatformId — строка судит сама
// себя: рукоятка с платформенным `id` не записывается; законный близнец
// отличается ровно рукояткой.
func TestAccessKey_ValidateRefusesAHandleCarryingThePlatformId(t *testing.T) {
	t.Parallel()
	minted, err := domain.NewCeremonyHandle()
	require.NoError(t, err)
	lawful := domain.AccessKey{
		ID: "ak-0000000000000key1", UserID: "usr00000000000000a01",
		CredentialID: []byte("credential-id-of-32-bytes-exact!"), PublicKey: []byte{0xa5, 0x01, 0x02},
		Algorithm: -7, UserHandle: minted, Discoverability: domain.DiscoverabilityNotReported,
		Name: "ak-0000000000000key1", CreatedAt: time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC),
	}
	require.NoError(t, lawful.Validate(), "законный близнец молчит")

	carrying := lawful
	carrying.UserHandle = []byte(lawful.UserID)
	require.ErrorContains(t, carrying.Validate(), "platform user id")

	// Строка ПЕРЕНОСА: рукоятки источник не нёс — пустая законна и не судится.
	transferred := lawful
	transferred.UserHandle = nil
	require.NoError(t, transferred.Validate())

	// Обнаружимость, не названная вовсе, — отказ строки, а не молчаливое
	// умолчание.
	unstated := lawful
	unstated.Discoverability = ""
	require.ErrorContains(t, unstated.Validate(), "discoverability")
}
