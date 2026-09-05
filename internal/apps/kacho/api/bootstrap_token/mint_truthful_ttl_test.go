// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap_token

// mint_truthful_ttl_test.go — срок, СООБЩЁННЫЙ о выпущенном удостоверении,
// обязан быть сроком, который у него есть.
//
// # Что здесь изменилось вместе с переходом на свою чеканку (задача #1119)
//
// Прежде срок был свойством клиента у внешнего издателя, и единственное, что
// служба могла с ним сделать, — сообщить честно. Теперь подпись НАША, значит и
// срок наш; но урок остаётся тем же и потому проба живёт: сообщается то, что
// стоит В ТОКЕНЕ, и берётся оно ИЗ ТОКЕНА, а не считается заново.
//
// Второй расчёт того же предмета разошёлся бы с первым молча — и разошёлся бы в
// ту сторону, где предъявитель считает cluster-admin удостоверение умершим, пока
// край его ещё принимает. Это единственная ошибка, из которой нет возврата:
// токен, который считают истёкшим, никто не ищет и не отзывает.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

// TestMintBootstrapToken_ReportedLifetimeIsTheSignedOne — подписант выпустил
// токен на 900 секунд, значит вызывающему сообщается 900.
func TestMintBootstrapToken_ReportedLifetimeIsTheSignedOne(t *testing.T) {
	issued := fixedNow
	uc := newUseCase(t, &fakeStore{}, &fakeMinter{out: MintOutput{
		AccessToken: "signed.by.us",
		IssuedAt:    issued,
		ExpiresAt:   issued.Add(900 * time.Second),
	}}, Config{})

	res, err := uc.Execute(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(900), res.ExpiresIn,
		"сообщается срок ПОДПИСАННОГО токена, а не число, которое служба предпочла бы")
	assert.Equal(t, int64(900), int64(res.ExpiresAt.Sub(res.IssuedAt)/time.Second),
		"expires_at − issued_at обязано сходиться с expires_in")
}

// TestMintBootstrapToken_LongerSignedLifetimeIsReportedHonestly — если токен
// подписан на дольше, чем контур просил, ответ всё равно правда. Занижение и
// есть то, что прячет живое удостоверение.
func TestMintBootstrapToken_LongerSignedLifetimeIsReportedHonestly(t *testing.T) {
	issued := fixedNow
	uc := newUseCase(t, &fakeStore{}, &fakeMinter{out: MintOutput{
		AccessToken: "signed.by.us",
		IssuedAt:    issued,
		ExpiresAt:   issued.Add(24 * time.Hour),
	}}, Config{})

	res, err := uc.Execute(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(86400), res.ExpiresIn,
		"токен, живущий сутки, не может быть объявлен истекающим раньше")
}

// TestMintBootstrapToken_DefaultLifetimeIsTheContourPolicy — не переопределённый
// срок берётся из политики контура, а не из запроса.
func TestMintBootstrapToken_DefaultLifetimeIsTheContourPolicy(t *testing.T) {
	minter := okMinter()
	uc := newUseCase(t, &fakeStore{}, minter, Config{})

	res, err := uc.Execute(context.Background())
	require.NoError(t, err)
	assert.Equal(t, MaxTTL, minter.last.TTL, "срок просится политикой контура")
	assert.Equal(t, int64(MaxTTL/time.Second), res.ExpiresIn)
}

// TestMintBootstrapTokenRequest_NoUnhonouredTTLField — параметра срока в
// контракте нет, номер и имя зарезервированы.
func TestMintBootstrapTokenRequest_NoUnhonouredTTLField(t *testing.T) {
	d := (&iamv1.MintBootstrapTokenRequest{}).ProtoReflect().Descriptor()

	assert.Nil(t, d.Fields().ByName("ttl_seconds"),
		"срок не выбирает вызывающий: удостоверение выпускается политикой контура")

	reservedTags := map[int32]bool{}
	for i := 0; i < d.ReservedRanges().Len(); i++ {
		r := d.ReservedRanges().Get(i)
		for n := r[0]; n < r[1]; n++ {
			reservedTags[int32(n)] = true
		}
	}
	assert.True(t, reservedTags[1], "tag 1 must stay reserved (never reused)")

	reservedNames := map[string]bool{}
	for i := 0; i < d.ReservedNames().Len(); i++ {
		reservedNames[string(d.ReservedNames().Get(i))] = true
	}
	assert.True(t, reservedNames["ttl_seconds"], "the name ttl_seconds must stay reserved")

	var _ protoreflect.MessageDescriptor = d
}
