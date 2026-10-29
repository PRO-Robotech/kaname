// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// backfill_adapter.go — pgx-адаптер портов seed.BackfillStore и seed.VerifyStore
// (чистая архитектура: подмётка и страж сверки зависят только от этих портов, и
// это единственное место, где они касаются pgx).
//
// Подмётка (seed.BackfillRunner) перечисляет активные выдачи порциями и сводит
// каждую СУЩЕСТВУЮЩИМ use-case сведения (своя пишущая транзакция и
// рекомендательная блокировка на выдачу), поэтому SQL сведения здесь нет. Адаптер
// держит блокировку-одиночку, порционный перечень и ЧТЕНИЯ стража сверки; в
// таблицы он ничего не пишет — дымовой посев зеркала снят (#148).

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// backfillSingletonLockKey — общеизвестный ключ рекомендательной блокировки
// одиночки подмётки. Постоянный bigint, отличный от любого ключа hashtext на
// выдачу. Число произвольное, но неизменное (мнемоника «P8BF»), и записано здесь,
// чтобы будущий пользователь рекомендательных блокировок с ним не столкнулся.
const backfillSingletonLockKey int64 = 0x50_38_42_46 // "P8BF"

// BackfillAdapter — адаптер композиционного корня для подмётки и стража сверки.
type BackfillAdapter struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewBackfillAdapter строит адаптер над пулом. Журнал — slog.Default; через него
// сбой снятия блокировки-одиночки выводится наружу, а не проглатывается.
func NewBackfillAdapter(pool *pgxpool.Pool) *BackfillAdapter {
	return &BackfillAdapter{pool: pool, logger: slog.Default()}
}

var (
	_ seed.BackfillStore = (*BackfillAdapter)(nil)
	_ seed.VerifyStore   = (*BackfillAdapter)(nil)
)

// ── seed.BackfillStore ──────────────────────────────────────────────────────────

// TryAcquireSingletonBackfillLock берёт pg_try_advisory_lock уровня СЕАНСА на
// общеизвестном ключе (без ожидания). На всю подмётку выделяется ОДНО соединение
// пула, чтобы блокировка сеанса пережила отдельные операторы; замыкание снятия
// снимает блокировку и возвращает соединение в пул. ok=false ⇒ блокировку держит
// другой процесс ⇒ вызывающий пропускает подмётку.
func (a *BackfillAdapter) TryAcquireSingletonBackfillLock(ctx context.Context) (bool, func(context.Context), error) {
	conn, err := a.pool.Acquire(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("backfill: acquire conn for singleton lock: %w", err)
	}
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, backfillSingletonLockKey).Scan(&ok); err != nil {
		conn.Release()
		return false, nil, fmt.Errorf("backfill: pg_try_advisory_lock: %w", err)
	}
	if !ok {
		conn.Release()
		return false, nil, nil
	}
	release := func(rctx context.Context) {
		// Снять блокировку в ТОМ ЖЕ сеансе, что её взял, затем вернуть соединение.
		// Отвязаться от ctx вызывающего (возможно, отменённого): с отменённым rctx
		// conn.Exec ничего бы не сделал, и блокировка сеанса жила бы до пересоздания
		// соединения. WithoutCancel сохраняет срок и значения, но снимает отмену, так
		// что снятие исполняется всегда. Сбой снятия пишется в журнал (наблюдаемость
		// эшелоном защиты): блокировка сеанса всё равно снимется при закрытии или
		// пересоздании соединения, но молчаливый сбой скрыл бы настоящую беду базы.
		uctx := context.WithoutCancel(rctx)
		if _, err := conn.Exec(uctx, `SELECT pg_advisory_unlock($1)`, backfillSingletonLockKey); err != nil {
			a.logger.WarnContext(uctx, "backfill: singleton advisory-unlock failed (released on conn recycle)",
				slog.Any("err", err))
		}
		conn.Release()
	}
	return true, release, nil
}

// ListActiveBindingIDsChunk возвращает не больше `limit` id АКТИВНЫХ выдач с id >
// afterID (пагинация по ключу, ORDER BY id ASC). Чтение уровня пула ВНЕ
// транзакции сведения выдачи (каждая выдача сводится в своей транзакции).
func (a *BackfillAdapter) ListActiveBindingIDsChunk(ctx context.Context, afterID string, limit int) ([]domain.AccessBindingID, error) {
	rows, err := a.pool.Query(ctx,
		`SELECT id
		   FROM kaname.access_bindings
		  WHERE status = 'ACTIVE' AND id > $1
		  ORDER BY id ASC
		  LIMIT $2`,
		afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("backfill: list active binding ids chunk: %w", err)
	}
	defer rows.Close()
	var out []domain.AccessBindingID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("backfill: scan active binding id: %w", err)
		}
		out = append(out, domain.AccessBindingID(id))
	}
	return out, rows.Err()
}

// ── seed.VerifyStore ────────────────────────────────────────────────────────────

// ListActiveBindingMaterialization возвращает для каждой АКТИВНОЙ выдачи, ОЖИДАЕТ
// ли она явной материализации, и текущее число её кортежей в ведомости. Ожидание —
// СОБСТВЕННЫЙ вердикт сверщика (число АКТИВНЫХ access_binding_target_members,
// оставленных последним проходом сведения), а НЕ эвристика по правилам роли. Это
// точно: у выдачи, которую сверщик решил материализовать (вложенный член селектора
// либо член «сама область» счёта или проекта), АКТИВНЫХ членов ≥1; у выдачи,
// которую сверщик оставляет пустой (суперадминистратор `*.*.*` уровня кластера,
// обслуживаемый коротким замыканием; правило содержимого с подстановочным знаком,
// чьи ObjectTypes пропускаются; селектор, ничего не нашедший в зеркале), АКТИВНЫХ
// членов 0 → она ничего не ожидает, и пустая ведомость верна. Отказ «потеря
// доступа» (Verify) — ровно «АКТИВНЫЕ члены есть, а ведомость пуста»: член,
// активированный сверщиком без выпуска своего кортежа.
func (a *BackfillAdapter) ListActiveBindingMaterialization(ctx context.Context) ([]seed.BindingMaterialization, error) {
	rows, err := a.pool.Query(ctx,
		`SELECT b.id,
		        COALESCE(am.cnt, 0) AS active_members,
		        COALESCE(lt.cnt, 0) AS ledger_count
		   FROM kaname.access_bindings b
		   LEFT JOIN (
		        SELECT binding_id, count(*) AS cnt
		          FROM kaname.access_binding_target_members
		         WHERE verification_status = 'ACTIVE'
		         GROUP BY binding_id
		   ) am ON am.binding_id = b.id
		   LEFT JOIN (
		        SELECT binding_id, count(*) AS cnt
		          FROM kaname.access_binding_emitted_tuples
		         GROUP BY binding_id
		   ) lt ON lt.binding_id = b.id
		  WHERE b.status = 'ACTIVE'`)
	if err != nil {
		return nil, fmt.Errorf("backfill: list active binding materialization: %w", err)
	}
	defer rows.Close()

	var out []seed.BindingMaterialization
	for rows.Next() {
		var (
			id            string
			activeMembers int
			ledgerCount   int
		)
		if err := rows.Scan(&id, &activeMembers, &ledgerCount); err != nil {
			return nil, fmt.Errorf("backfill: scan binding materialization: %w", err)
		}
		out = append(out, seed.BindingMaterialization{
			BindingID:     domain.AccessBindingID(id),
			ExpectsTuples: activeMembers > 0,
			LedgerCount:   ledgerCount,
		})
	}
	return out, rows.Err()
}

// ListOwnerBindingsMissingMembers возвращает id АКТИВНЫХ выдач ВЛАДЕЛЬЦА уровня
// счёта (role_id — системная роль владельца), у которых АКТИВНЫХ целевых членов
// НОЛЬ. Выдача владельца ВСЕГДА материализует ≥1 члена (своего члена «сама область»
// на account:<A>), поэтому выдача владельца с 0 АКТИВНЫХ членов — полный провал
// сведения, который отмечает страж сверки. Сужено до выдач владельца, чтобы
// проверка никогда ложно не отметила законно пустую выдачу (суперадминистратор
// кластера, обслуживаемый коротким замыканием; тонкая роль из одних разрешений;
// селектор, ничего не нашедший).
func (a *BackfillAdapter) ListOwnerBindingsMissingMembers(ctx context.Context) ([]domain.AccessBindingID, error) {
	rows, err := a.pool.Query(ctx,
		`SELECT b.id
		   FROM kaname.access_bindings b
		  WHERE b.status = 'ACTIVE'
		    AND b.role_id = $1
		    AND b.resource_type = 'account'
		    AND NOT EXISTS (
		      SELECT 1
		        FROM kaname.access_binding_target_members m
		       WHERE m.binding_id = b.id
		         AND m.verification_status = 'ACTIVE'
		    )
		  ORDER BY b.id ASC`,
		domain.OwnerRoleID)
	if err != nil {
		return nil, fmt.Errorf("backfill: list owner bindings missing members: %w", err)
	}
	defer rows.Close()
	var out []domain.AccessBindingID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("backfill: scan owner binding missing members: %w", err)
		}
		out = append(out, domain.AccessBindingID(id))
	}
	return out, rows.Err()
}

// ListActiveBindingRelationChecks возвращает для каждой АКТИВНОЙ выдачи кортежи
// исполнения чтения v_* по объектам (v_get / v_list), которые страж «отношение
// удовлетворяет действию» обязан проверить настоящим Check. Это отношения,
// решающие для переключения: при Design-B каталог судит `<domain>.<res>.get`→v_get
// и `…list`→v_list, поэтому страж доказывает, что каждый материализованный кортеж
// чтения действительно СВОДИТСЯ к исполняемому отношению, а не только что ведомость
// непуста. Сужено до v_get/v_list (поверхность чтения, которую переворачивает
// переключение), чтобы веер вызовов Check стража ограничивался отношениями, чья
// ошибочная материализация дала живой дефект «403 владельцу». Чтение уровня пула
// ВНЕ любой транзакции сведения.
func (a *BackfillAdapter) ListActiveBindingRelationChecks(ctx context.Context) ([]seed.BindingRelationCheck, error) {
	rows, err := a.pool.Query(ctx,
		`SELECT DISTINCT t.binding_id, t.fga_user, t.relation, t.object
		   FROM kaname.access_binding_emitted_tuples t
		   JOIN kaname.access_bindings b ON b.id = t.binding_id
		  WHERE b.status = 'ACTIVE'
		    AND t.relation IN ('v_get', 'v_list')
		  ORDER BY t.binding_id ASC, t.object ASC, t.relation ASC`)
	if err != nil {
		return nil, fmt.Errorf("backfill: list active binding relation checks: %w", err)
	}
	defer rows.Close()
	var out []seed.BindingRelationCheck
	for rows.Next() {
		var c seed.BindingRelationCheck
		var bindingID string
		if err := rows.Scan(&bindingID, &c.Subject, &c.Relation, &c.Object); err != nil {
			return nil, fmt.Errorf("backfill: scan binding relation check: %w", err)
		}
		c.BindingID = domain.AccessBindingID(bindingID)
		out = append(out, c)
	}
	return out, rows.Err()
}
