// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// dangling_project_mirror_adapter.go — pgx-адаптер порта
// seed.DanglingProjectMirrorStore (стадия S2 приёмки
// `non-empty-project-is-not-deleted.md`).
//
// Норма, граница и довод «ничего не удаляет и родителя не выдумывает» — в шапке
// `internal/apps/kaname/seed/dangling_project_mirror_sweep.go`; здесь они не
// пересказываются, чтобы два места об одном предмете не разошлись.
//
// Число сирот считается ТЕМ ЖЕ предикатом в ТОМ ЖЕ снимке, что и выборка:
// `count(*) OVER ()` вычисляется до `LIMIT`, поэтому потолок отрезает
// названные строки, а не счёт. Отдельный `SELECT count(*)` брал бы свой снимок и
// мог бы разойтись с выборкой между двумя операторами.

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
)

// danglingProjectMirrorSingletonLockKey — известный ключ общего замка прохода.
// Отличен от ключей обратного заполнения ("P8BF"), прохода по пустому родителю
// ("OMSW") и уборки висячих областей ("OSSW"): два разных прохода не вправе
// исключать друг друга. Мнемоника "OMPN" — orphan mirror, parent named.
// Различность держит `singleton_lock_keys_distinct_test.go`.
const danglingProjectMirrorSingletonLockKey int64 = 0x4F_4D_50_4E // "OMPN"

// DanglingProjectMirrorAdapter — адаптер прохода.
type DanglingProjectMirrorAdapter struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewDanglingProjectMirrorAdapter собирает адаптер над пулом. Логгер nil-безопасен.
func NewDanglingProjectMirrorAdapter(pool *pgxpool.Pool) *DanglingProjectMirrorAdapter {
	return &DanglingProjectMirrorAdapter{pool: pool, logger: slog.Default()}
}

var _ seed.DanglingProjectMirrorStore = (*DanglingProjectMirrorAdapter)(nil)

// TryAcquireSingletonDanglingProjectMirrorLock берёт СЕССИОННЫЙ
// pg_try_advisory_lock по своему ключу на ОДНОМ соединении пула, чтобы замок
// пережил отдельные стейтменты прогона.
func (a *DanglingProjectMirrorAdapter) TryAcquireSingletonDanglingProjectMirrorLock(ctx context.Context) (bool, func(context.Context), error) {
	conn, err := a.pool.Acquire(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("dangling-project-mirror sweep: acquire conn for singleton lock: %w", err)
	}
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, danglingProjectMirrorSingletonLockKey).Scan(&ok); err != nil {
		conn.Release()
		return false, nil, fmt.Errorf("dangling-project-mirror sweep: pg_try_advisory_lock: %w", err)
	}
	if !ok {
		conn.Release()
		return false, nil, nil
	}
	release := func(rctx context.Context) {
		// Отвязываемся от возможно отменённого ctx вызывающего: на отменённом
		// Exec стал бы no-op и сессионный замок протёк бы до утилизации
		// соединения.
		uctx := context.WithoutCancel(rctx)
		if _, err := conn.Exec(uctx, `SELECT pg_advisory_unlock($1)`, danglingProjectMirrorSingletonLockKey); err != nil {
			a.logger.WarnContext(uctx, "dangling-project-mirror sweep: singleton advisory-unlock failed (released on conn recycle)",
				slog.Any("err", err))
		}
		conn.Release()
	}
	return true, release, nil
}

// CountMirrorRows — знаменатель переписи.
func (a *DanglingProjectMirrorAdapter) CountMirrorRows(ctx context.Context) (int, error) {
	var n int
	if err := a.pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.resource_mirror`).Scan(&n); err != nil {
		return 0, fmt.Errorf("dangling-project-mirror sweep: count mirror rows: %w", err)
	}
	return n, nil
}

// ListDanglingProjectMirrorRows — строки, у которых проект НАЗВАН и строки
// `kaname.projects` с таким id нет, плюс их точное число в том же снимке.
//
// Порядок детерминирован (вид, затем идентификатор), чтобы потолок прогона
// отрезал одно и то же место, а не случайное. Строки с пустым родителем сюда не
// попадают by construction — они предмет соседнего прохода.
func (a *DanglingProjectMirrorAdapter) ListDanglingProjectMirrorRows(ctx context.Context, limit int) ([]seed.DanglingProjectMirrorRow, int, error) {
	rows, err := a.pool.Query(ctx,
		`SELECT m.object_type, m.object_id, m.parent_project_id, count(*) OVER () AS total
		   FROM kaname.resource_mirror m
		  WHERE m.parent_project_id <> ''
		    AND NOT EXISTS (SELECT 1 FROM kaname.projects p WHERE p.id = m.parent_project_id)
		  ORDER BY m.object_type ASC, m.object_id ASC
		  LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("dangling-project-mirror sweep: list dangling rows: %w", err)
	}
	defer rows.Close()

	var (
		out   []seed.DanglingProjectMirrorRow
		total int64
	)
	for rows.Next() {
		var r seed.DanglingProjectMirrorRow
		if err := rows.Scan(&r.ObjectType, &r.ObjectID, &r.ParentProjectID, &total); err != nil {
			return nil, 0, fmt.Errorf("dangling-project-mirror sweep: scan dangling row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("dangling-project-mirror sweep: iterate dangling rows: %w", err)
	}
	// Пустая выборка означает ноль сирот: оконный счёт вычисляется по тем же
	// строкам, и без строк ему не с чего быть ненулевым.
	return out, int(total), nil
}
