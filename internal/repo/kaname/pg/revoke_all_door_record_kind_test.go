// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// revoke_all_door_record_kind_test.go — дверь отсечки отзыва-всех кладёт
// запись СВОЕГО вида и вида записи из рук вызывающего не берёт (kaname#380).
//
// # Что здесь утверждается
//
// Запись принудительного выхода обязана нести ИСХОД снятия записей сессии —
// число снятых либо «снятие не состоялось» (kaname#340). Кладёт её транзакция
// снятия (`humanSessionWriter`), потому что только она этот исход знает.
// Дверь `SessionRevocationsAdapter.RevokeAllUserTokensTx` снятия не видит: её
// запись — четыре величины (актор · вид субъекта · субъект · причина), и
// исхода в ней нет и быть не может.
//
// Пока дверь брала вид записи параметром, запись принудительного выхода БЕЗ
// исхода стояла в одном аргументе от любого её вызова. Так её и клала ветвь
// посадки `external`: посадка снята (kaname#363), вызов снят вместе с ней, а
// параметр, заведённый ради этого вызова, остался — и с ним сама форма.
// Производитель у двери после снятия ОДИН (отзыв всех токенов субъекта), и
// вид её записи — одно значение, как у двери отзыва одного носителя.
//
// # Почему судится форма, а не вызов
//
// Утверждение — о том, что запись без исхода НЕПРЕДСТАВИМА через эту дверь, а
// не о том, что сегодня её никто так не зовёт: второе держится вниманием
// следующего вызывающего. Представимость — свойство подписи, и проба
// спрашивает подпись: удовлетворяет ли дверь порту, в котором вида записи нет.
//
// # Чем проба защищена от собственной снисходительности
//
// Законный близнец — дверь отзыва одного носителя (`RevokeTx`): у неё вид
// записи свой и параметром не приходит. Тот же вопрос о форме к ней обязан
// давать «да» — иначе отказ основного утверждения был бы свойством способа
// спрашивать, а не двери.
package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// revokeAllDoorOwnKind — дверь отсечки отзыва-всех, вид записи которой свой.
type revokeAllDoorOwnKind interface {
	RevokeAllUserTokensTx(ctx context.Context, userID domain.UserID, revokeBefore time.Time,
		reason string, revokedBy domain.UserID) error
}

// perJTIDoorOwnKind — дверь отзыва одного носителя; вид записи у неё свой
// всегда.
type perJTIDoorOwnKind interface {
	RevokeTx(ctx context.Context, rev domain.SessionRevocation, revokedBy domain.UserID) error
}

func TestRevokeAllDoorLaysItsOwnRecordKindNotTheCallersOne(t *testing.T) {
	// Пул не нужен: спрашивается форма двери, в базу проба не ходит.
	var door any = kanamepg.NewSessionRevocationsAdapter(nil)

	_, twin := door.(perJTIDoorOwnKind)
	require.True(t, twin,
		"близнец: дверь отзыва одного носителя обязана удовлетворять порту без вида записи — "+
			"иначе проба отвечает о способе спрашивать, а не о двери")

	_, own := door.(revokeAllDoorOwnKind)
	require.True(t, own,
		"дверь отсечки отзыва-всех берёт вид записи из рук вызывающего: запись "+
			"принудительного выхода без исхода снятия представима через неё одним "+
			"аргументом (kaname#380)")
}
