// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard_test

// notification_grant_edge_test.go — рычаг оператора над выдачей права на
// письма (`InternalNotificationGrantService/Revoke`, `/Restore`) зовёт человек
// ЧЕРЕЗ ВНУТРЕННИЙ КРАЙ (решение владельца 2026-10-08, п. 1: отзыв и
// восстановление выдачи — личностью администратора кластера через внутренний
// край; новой машинной учётки нет).
//
// Что из этого следует для внутреннего слушателя и что утверждается здесь:
//
//   - оба метода — в круге края (`GatewayFrontedInternalRPCs`): звать их
//     вправе только учётка края, и пол ступени подтверждения (`ACRFloor`)
//     применяет к ним объявленную каталогом ступень «2»;
//   - строка рубежа положения — `GateRefuses`: неподтверждённый человек
//     получает отказ положения до обработчика;
//   - законный близнец той же службы — `ResolveSend`: его зовёт служба notify
//     по сертификату, человека на пути нет, и он остаётся ВНЕ круга. Близнец
//     держит, что перенос не задел службу целиком.

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

func TestNotificationGrantLeversAreFrontedByTheEdge(t *testing.T) {
	circle := map[string]bool{}
	for _, m := range authzguard.GatewayFrontedInternalRPCs() {
		circle[m] = true
	}
	table := authzguard.InternalAddressGateTable()

	for _, m := range []string{
		iamv1.InternalNotificationGrantService_Revoke_FullMethodName,
		iamv1.InternalNotificationGrantService_Restore_FullMethodName,
	} {
		if !circle[m] {
			t.Errorf("%s: вне круга края — звать рычаг вправе любой проверенный модуль, "+
				"а ступень «2» каталога на внутреннем слушателе не исполняется", m)
		}
		row, ok := table[m]
		switch {
		case !ok:
			t.Errorf("%s: строки рубежа положения нет", m)
		case row.Row != authzguard.GateRefuses:
			t.Errorf("%s: строка рубежа %d, ожидалась GateRefuses (%d) — неподтверждённый "+
				"человек дошёл бы до обработчика", m, row.Row, authzguard.GateRefuses)
		case row.Reason == "":
			t.Errorf("%s: строка рубежа без довода", m)
		}
	}

	// Законный близнец: решение о письме зовёт служба, а не человек.
	twin := iamv1.InternalNotificationGrantService_ResolveSend_FullMethodName
	if circle[twin] {
		t.Errorf("%s: в круге края — служба notify по своему сертификату получила бы отказ "+
			"«только край», а решение о письме — ступень человека", twin)
	}
	if row, ok := table[twin]; !ok || row.Row != authzguard.GateOutsideCircle {
		t.Errorf("%s: строка рубежа %+v (объявлена %v), ожидалась GateOutsideCircle", twin, row, ok)
	}
}
