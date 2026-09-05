// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// reconcile_outbox_retention.go — уборщик дренированных строк очереди сверки
// прав (задача #2050).
//
// # Предмет
//
// `MarkReconcileEventSent` переводил строку в отправленные, и на этом всё:
// дренированные строки не снимались и не архивировались НИКОГДА, а таблица
// росла неограниченно под штатным потоком регистраций ресурсов. Приём уборки в
// дереве при этом уже был и применён к соседней очереди — у этой его просто не
// было.
//
// # Почему отдельный тип, а не метод адаптера сверки
//
// Тот же довод, что у уборщика журнала смены субъекта: адаптер сверки — это
// поверхность ДРЕНАЖА, и метод, снимающий строки, сделал бы его заголовок
// ложью. Плюс уборщику не нужен каталог, который адаптер требует конструктором:
// собирать его ради пула значило бы просить то, чем не пользуешься.
//
// # Наблюдателя границы устоявшегося здесь НЕТ — и это не пропуск
//
// У соседа он есть, потому что его читатель ходит КУРСОРОМ по позиции и строка
// с меньшим номером вправе стать видимой позже уже снятой. Здесь читатель один
// — дренаж, и он берёт строки по признаку `sent_at IS NULL`, а не по номеру.
// Строка, помеченная отправленной, из его набора выбыла окончательно; дыр в
// нумерации он не замечает by construction.

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/reconcile_outbox"
)

// ReconcileOutboxSweeper — уборщик дренированных строк очереди сверки.
type ReconcileOutboxSweeper struct {
	pool *pgxpool.Pool
}

// NewReconcileOutboxSweeper собирает уборщика над пулом владельца очереди.
func NewReconcileOutboxSweeper(pool *pgxpool.Pool) *ReconcileOutboxSweeper {
	return &ReconcileOutboxSweeper{pool: pool}
}

// SweepDrainedReconcileEvents — один проход партии. Подпись — общая форма
// уборщика реестра (`retention.SweepFunc`): момент времени входом не приходит,
// часы у предиката — базы.
func (s *ReconcileOutboxSweeper) SweepDrainedReconcileEvents(
	ctx context.Context, grace time.Duration, batch int,
) (int64, bool, error) {
	return reconcile_outbox.SweepDrained(ctx, s.pool, grace, batch)
}
