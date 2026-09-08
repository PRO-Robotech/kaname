// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// orphan_scope_adapter.go — pgx-адаптер порта seed.OrphanScopeStore (задача #810).
//
// Держит РОВНО две вещи: общий на кластер try-lock и перепись областей, чьей
// строки-владельца в базе iam нет. Снятие выдач сюда не попадает by construction:
// оно идёт через `shared.RevokeBindingsInScope` → `Writer.EmitFGARelationDelete`,
// то есть тем же путём, что и `Project.Delete`. Второй экземпляр этой логики —
// хоть на Go, хоть на SQL — разошёлся бы с первым молча.

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// orphanScopeSingletonLockKey — известный ключ общего замка уборки. Отличен от
// backfillSingletonLockKey ("P8BF"): два разных прогона не вправе исключать друг
// друга. Мнемоника "OSSW" (orphan-scope sweep).
const orphanScopeSingletonLockKey int64 = 0x4F_53_53_57 // "OSSW"

// OrphanScopeAdapter — адаптер уборки висячих областей.
type OrphanScopeAdapter struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewOrphanScopeAdapter собирает адаптер над пулом. Логгер nil-безопасен.
func NewOrphanScopeAdapter(pool *pgxpool.Pool) *OrphanScopeAdapter {
	return &OrphanScopeAdapter{pool: pool, logger: slog.Default()}
}

var _ seed.OrphanScopeStore = (*OrphanScopeAdapter)(nil)

// TryAcquireSingletonOrphanScopeLock берёт СЕССИОННЫЙ pg_try_advisory_lock по
// известному ключу (неблокирующий). Выделяет ОДНО соединение пула на весь прогон,
// чтобы сессионный замок пережил отдельные стейтменты; замыкание освобождает
// замок и возвращает соединение.
func (a *OrphanScopeAdapter) TryAcquireSingletonOrphanScopeLock(ctx context.Context) (bool, func(context.Context), error) {
	conn, err := a.pool.Acquire(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("orphan-scope sweep: acquire conn for singleton lock: %w", err)
	}
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, orphanScopeSingletonLockKey).Scan(&ok); err != nil {
		conn.Release()
		return false, nil, fmt.Errorf("orphan-scope sweep: pg_try_advisory_lock: %w", err)
	}
	if !ok {
		conn.Release()
		return false, nil, nil
	}
	release := func(rctx context.Context) {
		// Отвязываемся от возможно отменённого ctx вызывающего: на отменённом
		// Exec стал бы no-op и сессионный замок протёк бы до утилизации
		// соединения. Отказ снятия логируется, а не проглатывается.
		uctx := context.WithoutCancel(rctx)
		if _, err := conn.Exec(uctx, `SELECT pg_advisory_unlock($1)`, orphanScopeSingletonLockKey); err != nil {
			a.logger.WarnContext(uctx, "orphan-scope sweep: singleton advisory-unlock failed (released on conn recycle)",
				slog.Any("err", err))
		}
		conn.Release()
	}
	return true, release, nil
}

// ListOrphanBindingScopes возвращает до `limit` РАЗЛИЧНЫХ областей, на которые
// есть выдачи, но чьей строки-владельца в базе iam нет.
//
// ПОЧЕМУ ТОЛЬКО project И account. Это единственные виды области, чьи строки
// лежат в собственной базе iam, — только про них отсутствие строки ЗНАЧИТ, что
// ресурса нет. `cluster` таблицы-владельца не имеет вовсе, а межсервисный вид
// принадлежит чужому владельцу, и объявить его отсутствующим по своей базе
// нельзя. Перечень закрыт ЗДЕСЬ и продублирован разбором в `seed`
// (`orphanScopeNoun`), который отказывает на неизвестном виде вслух: перепись и
// уборка обязаны сходиться, а расхождение обязано быть слышно.
//
// Порядок детерминирован (тип, затем идентификатор), чтобы потолок прогона
// отрезал одно и то же место, а не случайное.
func (a *OrphanScopeAdapter) ListOrphanBindingScopes(ctx context.Context, limit int) ([]seed.OrphanScope, error) {
	rows, err := a.pool.Query(ctx,
		`SELECT DISTINCT ab.resource_type, ab.resource_id
		   FROM kaname.access_bindings ab
		  WHERE (ab.resource_type = 'project'
		         AND NOT EXISTS (SELECT 1 FROM kaname.projects p WHERE p.id = ab.resource_id))
		     OR (ab.resource_type = 'account'
		         AND NOT EXISTS (SELECT 1 FROM kaname.accounts a WHERE a.id = ab.resource_id))
		  ORDER BY ab.resource_type ASC, ab.resource_id ASC
		  LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("orphan-scope sweep: list orphan binding scopes: %w", err)
	}
	defer rows.Close()
	var out []seed.OrphanScope
	for rows.Next() {
		var rt, rid string
		if err := rows.Scan(&rt, &rid); err != nil {
			return nil, fmt.Errorf("orphan-scope sweep: scan orphan binding scope: %w", err)
		}
		out = append(out, seed.OrphanScope{ResourceType: domain.ResourceType(rt), ResourceID: rid})
	}
	return out, rows.Err()
}
