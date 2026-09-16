// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// registration_store.go — адаптер хранилища регистрации (фаза Ф4, задача
// PRO-Robotech/kacho#1270). Порт — `internal/apps/kaname/api/registration`.
//
// # Одна транзакция базы — три следствия
//
// Writer собирается над ОДНОЙ `pgx.Tx`: писатель зеркала (`writeTx` — тот же,
// что у корневого репозитория), писатель сессии (`humanSessionWriter`) и
// вставка строки способа входа. Отказ любой из записей откатывает все три
// (Ф4-02…Ф4-04); фиксация одна, и отложенные проверки схемы — в том числе
// триггер потолка темпа заведения (Р5) — срабатывают на ней и переводятся тем
// же мостом SQLSTATE→sentinel, что у корневого писателя.
//
// Таблицу способа входа этот файл НЕ называет: вставка делегируется функции
// файла адаптера способа входа (`insertLoginMethodTx`, гейт
// `TestLoginVerifierStaysInside`).

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
)

// RegistrationStore — хранилище регистрации на пуле.
type RegistrationStore struct {
	pool *pgxpool.Pool
}

// NewRegistrationStore — адаптер поверх пула.
func NewRegistrationStore(pool *pgxpool.Pool) *RegistrationStore {
	return &RegistrationStore{pool: pool}
}

// Writer — см. порт.
func (s *RegistrationStore) Writer(ctx context.Context) (registration.Writer, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, mapErr(err, "Registration.Writer", "")
	}
	return &registrationWriter{
		humanSessionWriter: &humanSessionWriter{tx: tx},
		mirror:             &writeTx{readTx: readTx{tx: tx}},
		tx:                 tx,
	}, nil
}

// registrationWriter — одна транзакция трёх следствий.
type registrationWriter struct {
	*humanSessionWriter
	// mirror — писатель зеркала над ТОЙ ЖЕ транзакцией; его Commit несёт мост
	// отложенных отказов схемы (accounts_owner_fk, потолок темпа).
	mirror *writeTx
	tx     pgx.Tx
}

// Mirror — см. порт: композиция Р6 живёт у use-case зеркала, адаптер отдаёт
// ей свой writer.
func (w *registrationWriter) Mirror(ctx context.Context, in registration.MirrorInput) (registration.MirrorResult, error) {
	return user.RegisterMirrorTx(ctx, w.mirror, in)
}

// Commit — фиксация ОДНОЙ транзакции; отказы, приходящие на фиксации
// (отложенные ограничения и триггеры), переводит мост корневого писателя.
func (w *registrationWriter) Commit(ctx context.Context) error { return w.mirror.Commit(ctx) }

// Rollback — откат той же транзакции.
func (w *registrationWriter) Rollback(ctx context.Context) error { return w.tx.Rollback(ctx) }

var _ registration.Store = (*RegistrationStore)(nil)
