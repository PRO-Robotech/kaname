// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// invite_link_field_reserved_test.go — MAIL-34 и MAIL-35 приёмки ID-MAIL-1
// (задача продукта #1774): поле ссылки приглашения снято с контракта с
// резервированием НОМЕРА И ИМЕНИ, а соседние поля метаданных живы.
//
// Гейт читает ДЕСКРИПТОР контракта, а не текст `.proto`: текст несёт то же имя
// в комментариях, объясняющих снятие, и предикат по подстроке краснел бы на
// собственном объяснении. Дескриптор — то, что процесс исполняет.
//
// Отрицание («поля нет») стоит В ПАРЕ с положительным контролем («идентификаторы
// человека и аккаунта в метаданных ЕСТЬ и заполняются»): без пары «поля нет»
// зеленело бы и на метаданных, которые не собираются вовсе.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/PRO-Robotech/corelib/operations"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

const (
	inviteLinkFieldName   = "magic_link_url"
	inviteLinkFieldNumber = 3
)

// TestMAIL34_InviteLinkFieldIsReservedByNumberAndName — само снятие.
func TestMAIL34_InviteLinkFieldIsReservedByNumberAndName(t *testing.T) {
	md := (&iamv1.InviteUserMetadata{}).ProtoReflect().Descriptor()

	require.Nil(t, md.Fields().ByName(inviteLinkFieldName),
		"поле %q ещё объявлено в InviteUserMetadata — продукт обещает ссылку, которой не "+
			"производит никто (решение Р10 приёмки ID-MAIL-1)", inviteLinkFieldName)
	require.Nil(t, md.Fields().ByNumber(inviteLinkFieldNumber),
		"номер %d ещё занят полем в InviteUserMetadata", inviteLinkFieldNumber)

	require.True(t, md.ReservedNames().Has(inviteLinkFieldName),
		"имя %q не зарезервировано: снятое поле может вернуться под тем же именем с другим "+
			"смыслом, и клиент прочтёт его по-старому", inviteLinkFieldName)
	require.True(t, md.ReservedRanges().Has(protoreflect.FieldNumber(inviteLinkFieldNumber)),
		"номер %d не зарезервирован: снятое поле может вернуться под тем же номером с другим "+
			"типом, и проволочная форма разъедется молча", inviteLinkFieldNumber)

	t.Logf("перепись: полей InviteUserMetadata %d · зарезервированных имён %d · диапазонов %d",
		md.Fields().Len(), md.ReservedNames().Len(), md.ReservedRanges().Len())
}

// TestMAIL35_InviteMetadataStillCarriesTheIdentifiers — положительный контроль:
// метаданные операции приглашения по-прежнему собираются и несут человека и
// аккаунт. Предикат различает «поле снято» и «метаданные не собираются вовсе»:
// он спрашивает ЗАПОЛНЕННУЮ операцию, а не форму сообщения.
func TestMAIL35_InviteMetadataStillCarriesTheIdentifiers(t *testing.T) {
	md := (&iamv1.InviteUserMetadata{}).ProtoReflect().Descriptor()
	require.NotNil(t, md.Fields().ByName("user_id"), "user_id снят вместе со ссылкой — это уже не снятие поля, а снятие метаданных")
	require.NotNil(t, md.Fields().ByName("account_id"), "account_id снят вместе со ссылкой")

	repo := &invPrincRepo{}
	ops := newFakeUsrOps()
	uc := NewInviteUserUseCase(repo, ops, invPrincAllowAll{})
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr0000000000000invm"})
	op, err := uc.Execute(ctx, InviteUserInput{
		AccountID: domain.AccountID(invPrincAccount),
		Email:     domain.Email(invPrincEmail),
	})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		got, gerr := ops.Get(context.Background(), op.ID)
		return gerr == nil && got.Done
	}, 5*time.Second, 10*time.Millisecond)

	stored, err := ops.Get(context.Background(), op.ID)
	require.NoError(t, err)
	got := &iamv1.InviteUserMetadata{}
	require.NoError(t, stored.Metadata.UnmarshalTo(got))
	require.NotEmpty(t, got.GetUserId(), "метаданные не несут человека")
	require.Equal(t, invPrincAccount, got.GetAccountId(), "метаданные не несут аккаунт")
}
