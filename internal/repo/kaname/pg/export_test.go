// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"io"

	"github.com/jackc/pgx/v5/pgconn"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// export_test.go — мост для проб пакета, намеренно УЗКИЙ.
//
// Здесь только то, чего проба не вправе написать своей рукой: ТЕКСТ оператора
// состава и ВЕЛИЧИНА его предела. Проба, переписавшая оператор, замеряла бы
// другой запрос — и осталась бы зелёной ровно тогда, когда предел сняли с
// настоящего.

// MembersOfGroupsSQL — оператор, который исполняет MembersOfGroups.
const MembersOfGroupsSQL = membersOfGroupsSQL

// MaxMembersInGrantSurface — предел состава, возвращаемого одним перечислением.
const MaxMembersInGrantSurface = maxMembersInGrantSurface

// SweepUnservableSessionsSQL — оператор, который исполняет SweepUnservableSessions.
const SweepUnservableSessionsSQL = sweepUnservableSessionsSQL

// EndSessionsOfSQL — оператор снятия живых записей личности, который исполняет
// EndOtherSessions.
const EndSessionsOfSQL = endSessionsOfSQL

// Операторы выдачи кода (`IssueAuthorizationCode`) — ТЕ САМЫЕ тексты, из
// которых пробы перекрытия собирают контрольные руки: форму «замок одной лишь
// сессии», «только условие» и «только замок» (kaname#369). Рука, переписавшая
// оператор своей рукой, отличалась бы от продукта не одним фактом, а двумя.
const (
	LockUserForKeySQL            = lockUserForKeySQL
	LockCeremonyClientSQL        = lockCeremonyClientSQL
	LockSessionOfCeremonySQL     = lockSessionOfCeremonySQL
	InsertFamilyOnLiveSessionSQL = insertFamilyOnLiveSessionSQL
	SessionCutOffBySubjectSQL    = sessionCutOffBySubjectSQL
)

// WithClientSecretEntropy — исполнитель заведения с НАЗВАННЫМ источником
// случайности секрета клиента (kaname#405). Проба подаёт им сорванный источник
// (отказ, а не запасная строка) и считающий источник (сколько случайности
// секрет потребил). Прод-путь источник не называет — берёт криптографический.
func (p *OwnInteractiveClientProvider) WithClientSecretEntropy(r io.Reader) *OwnInteractiveClientProvider {
	p.entropy = r
	return p
}

// WriterTx — открытая транзакция писателя репозитория как исполнитель
// оператора фикстуры (kaname#608): посев строки пароля личности, заведённой
// `InsertActive`, обязан лечь ТОЙ ЖЕ транзакцией, иначе отложенный ключ
// инварианта отвергнет фиксацию. Продуктовых путей мимо типа не открывает:
// файл компилируется только с пробами.
func WriterTx(w kaname.Writer) interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
} {
	return w.(*writeTx).tx
}
