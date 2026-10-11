// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

import (
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// MembershipPointer — кортеж модели прав «человек принадлежит аккаунту»:
// `iam_user:<u>#account@account:<A>`. От него выводится админ-уровень
// распорядителя аккаунта над личностью участника.
//
// Форма объявлена здесь затем, чтобы СНИМАЮЩИЕ указатель говорили о нём одним
// выражением: исключение из аккаунта, снятие аккаунта (указатели всех его
// участников) и снятие личности (указатели всех её членств, kaname#664, Р6).
// Снятие, построившее кортеж иначе, чем его положили, промахнулось бы мимо
// факта молча — модель прав приняла бы удаление несуществующего кортежа.
func MembershipPointer(userID domain.UserID, accountID domain.AccountID) outboxtypes.RelationTuple {
	return outboxtypes.RelationTuple{
		User:     "account:" + string(accountID),
		Relation: "account",
		Object:   "iam_user:" + string(userID),
	}
}
