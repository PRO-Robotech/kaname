// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// registration_store.go — адаптер хранилища регистрации (фаза Ф4, задача
// PRO-Robotech/kacho#1270). Порт — `internal/apps/kaname/api/registration`;
// адаптер его НЕ импортирует (пробы пакета зеркала зовут этот адаптер, а
// пакет порта зовёт пакет зеркала — импорт замкнул бы круг в пробах) и
// исполняет структурно: соответствие порту закрепляет композиционный корень
// и харнесс проб присваиванием.
//
// # Одна транзакция базы — три следствия
//
// Writer собирается над ОДНОЙ `pgx.Tx`: писатель зеркала (`writeTx` — тот же,
// что у корневого репозитория; порт отдаёт его вызывающему через
// `MirrorWriter`, и композицию зеркала исполняет use-case), писатель сессии
// (`humanSessionWriter`) и вставка строки способа входа. Отказ любой из
// записей откатывает все три (Ф4-02…Ф4-04); фиксация одна, и отложенные
// проверки схемы — в том числе триггер потолка темпа заведения (Р5) —
// срабатывают на ней и переводятся тем же мостом SQLSTATE→sentinel, что у
// корневого писателя.
//
// Таблицу способа входа этот файл НЕ называет: вставка делегируется функции
// файла адаптера способа входа (`insertLoginMethodTx`, гейт
// `TestLoginVerifierStaysInside`).

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// RegistrationStore — хранилище регистрации на пуле.
type RegistrationStore struct {
	pool *pgxpool.Pool
}

// NewRegistrationStore — адаптер поверх пула.
func NewRegistrationStore(pool *pgxpool.Pool) *RegistrationStore {
	return &RegistrationStore{pool: pool}
}

// Writer — одна транзакция трёх следствий.
func (s *RegistrationStore) Writer(ctx context.Context) (*RegistrationWriter, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, mapErr(err, "Registration.Writer", "")
	}
	return &RegistrationWriter{
		humanSessionWriter: &humanSessionWriter{tx: tx},
		mirror:             &writeTx{readTx: readTx{tx: tx}},
		tx:                 tx,
	}, nil
}

// RegistrationWriter — одна транзакция трёх следствий над одной `pgx.Tx`.
type RegistrationWriter struct {
	*humanSessionWriter
	// mirror — писатель зеркала над ТОЙ ЖЕ транзакцией; его Commit несёт мост
	// отложенных отказов схемы (accounts_owner_fk, потолок темпа).
	mirror *writeTx
	tx     pgx.Tx
}

// MirrorWriter — писатель зеркала над той же транзакцией (порт зеркала —
// корневой `kaname.Writer`).
func (w *RegistrationWriter) MirrorWriter() kaname.Writer { return w.mirror }

// Commit — фиксация ОДНОЙ транзакции; отказы, приходящие на фиксации
// (отложенные ограничения и триггеры), переводит мост корневого писателя.
func (w *RegistrationWriter) Commit(ctx context.Context) error { return w.mirror.Commit(ctx) }

// Rollback — откат той же транзакции.
func (w *RegistrationWriter) Rollback(ctx context.Context) error { return w.tx.Rollback(ctx) }
