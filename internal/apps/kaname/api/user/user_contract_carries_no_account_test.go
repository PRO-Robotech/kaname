// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// user_contract_carries_no_account_test.go — ресурс «пользователь» не несёт
// аккаунта (IAM-ID-1-19, задача kacho#471).
//
// # Предмет
//
// Поле `account_id` объявляло, что у человека РОВНО ОДИН аккаунт: так было,
// пока человек был строкой в аккаунте. После отрыва принадлежность выражается
// членствами, которых у него может быть несколько, — и поле начинает
// возвращать ОДНО из многих, не говоря вызывающему, что их больше.
//
// Это хуже отсутствия: отсутствие видно сразу, а значение, выбранное из
// множества без указания на множество, читается как факт о человеке и уезжает
// в чужое состояние как истина. Поэтому поле снимается, а не переопределяется.
//
// # Почему проба читает ДЕСКРИПТОР, а не сгенерированную структуру
//
// «Метода `GetAccountId` нет» проверяется компилятором и потому не нуждается в
// пробе: дерево просто не соберётся. Проверять надо другое — что номер и имя
// ЗАРЕЗЕРВИРОВАНЫ. Резервирование не порождает ни поля, ни метода, значит
// увидеть его можно только в дескрипторе; без него следующий, кто заведёт поле,
// молча переиспользует номер 6, и старый клиент прочитает новое значение как
// аккаунт (`api-conventions.md` §«Принято-и-проигнорировано» — исход 3 требует
// резервировать И номер, И имя).
//
// # Почему рядом стоит положительный контроль
//
// «Поля нет» истинно и тогда, когда предикат не находит НИ ОДНОГО поля — то
// есть когда сломан он сам. Поэтому проба утверждает и присутствие соседнего
// поля с его номером.

package user_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
)

// accountFieldNumber — номер, который занимал аккаунт в ресурсе пользователя.
const accountFieldNumber protoreflect.FieldNumber = 6

func TestUserContractCarriesNoAccount(t *testing.T) {
	md := (&iamv1.User{}).ProtoReflect().Descriptor()

	// ── перепись: объём осмотренного печатается всегда ───────────────────────
	fields := md.Fields()
	names := make([]string, 0, fields.Len())
	for i := 0; i < fields.Len(); i++ {
		names = append(names, string(fields.Get(i).Name()))
	}
	t.Logf("перепись ресурса %s: полей %d (%v), зарезервированных номеров %d, имён %d",
		md.FullName(), fields.Len(), names,
		md.ReservedRanges().Len(), md.ReservedNames().Len())
	require.Positive(t, fields.Len(),
		"у ресурса обязано остаться хоть одно поле — на пустом дескрипторе "+
			"каждое отрицание ниже истинно тождественно")

	// ── IAM-ID-1-19: поля нет ────────────────────────────────────────────────
	require.Nil(t, fields.ByName("account_id"),
		"ресурс пользователя не вправе нести аккаунт: после отрыва их у человека несколько, "+
			"и одно значение из множества лжёт, не признаваясь в этом")
	require.Nil(t, fields.ByNumber(accountFieldNumber),
		"номер %d обязан остаться незанятым", accountFieldNumber)

	// ── IAM-ID-1-19: номер И имя зарезервированы ─────────────────────────────
	require.True(t, isReservedNumber(md, accountFieldNumber),
		"номер %d обязан быть зарезервирован: без этого следующий заведёт на нём новое поле, "+
			"и клиент прежней версии прочитает его значение как аккаунт", accountFieldNumber)
	require.True(t, isReservedName(md, "account_id"),
		"имя обязано быть зарезервировано отдельно от номера: JSON-имена разбираются по имени, "+
			"а не по номеру, поэтому один резерв номера от воскрешения имени не спасает")

	// ── положительный контроль ───────────────────────────────────────────────
	//
	// Без него «поля нет» неотличимо от «предикат не видит полей вовсе».
	email := fields.ByName("email")
	require.NotNil(t, email, "контроль: соседнее поле обязано находиться тем же предикатом")
	require.False(t, isReservedNumber(md, email.Number()),
		"контроль: номер живого поля зарезервированным быть не может — "+
			"иначе предикат резервирования отвечает «да» на что угодно")
}

func isReservedNumber(md protoreflect.MessageDescriptor, n protoreflect.FieldNumber) bool {
	rr := md.ReservedRanges()
	for i := 0; i < rr.Len(); i++ {
		if rr.Get(i)[0] <= n && n < rr.Get(i)[1] {
			return true
		}
	}
	return false
}

func isReservedName(md protoreflect.MessageDescriptor, name protoreflect.Name) bool {
	rn := md.ReservedNames()
	for i := 0; i < rn.Len(); i++ {
		if rn.Get(i) == name {
			return true
		}
	}
	return false
}
