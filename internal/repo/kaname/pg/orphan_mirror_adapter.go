// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// orphan_mirror_adapter.go — pgx-адаптер порта seed.OrphanMirrorStore
// (задача `PRO-Robotech/kacho#2051`).
//
// Норма, граница починимого и довод за три носителя — в шапке
// `internal/apps/kaname/seed/orphan_mirror_sweep.go`; здесь они не
// пересказываются, чтобы два места об одном предмете не разошлись.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЗДЕСЬ НЕТ РЕЗОЛВА АККАУНТА ЧЕРЕЗ ПРОЕКТ — И ЭТО РАЗБОР ОШИБКИ
//
// Читающая сторона зеркала резолвит аккаунт транзитивно —
// `COALESCE(NULLIF(m.parent_account_id, ''), pj.account_id, '')`
// (`resource_mirror/reader.go`). Первая редакция ЭТОГО предиката повторила ту же
// форму дословно, «чтобы два места об одном предмете не разошлись», и над ней
// стоял комментарий, объявлявший резолв действующим.
//
// Комментарий был ЛОЖЕН о собственном коде. Предикат сиротства требует
// `parent_project_id = ''`; при пустом проекте `LEFT JOIN projects ON pj.id = ''`
// не даёт строки, `pj.account_id` равен NULL, и всё выражение сводится к
// `parent_account_id = ''` — то есть к наивной форме. Резолв был НЕДОСТИЖИМ,
// а джойн — мёртвым.
//
// Обнаружено НЕ чтением: инъекция подменила выражение наивной формой, и ни одна
// проба не покраснела. Ноль находок от инъекции означал здесь не «предикат
// верен», а «обе формы дают одно и то же» (`testing.md` §«Гейт на класс», п. 2).
//
// Поэтому джойн снят, а не оставлен «на всякий случай»: мёртвая ветвь,
// объявленная комментарием живой, есть ровно тот класс, который корпус ловит.
// Транзитивность здесь не нужна by construction — при непустом проекте строка
// сиротой не является уже по первому условию.
//
// Обе полосы «не сирота» держат ОТДЕЛЬНЫЕ пробы, и каждая падает на снятии
// СВОЕГО условия: `..._03_RowWithProjectOnlyIsNotAnOrphan` (полоса проекта) и
// `..._04_RowWithAccountOnlyIsNotAnOrphan` (полоса аккаунта). Одна проба на обе
// полосы проходила бы по первому условию и вторую не проверяла бы вовсе.

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
)

// orphanMirrorSingletonLockKey — известный ключ общего замка прохода. Отличен от
// ключа уборки областей ("OSSW") и от ключа обратного заполнения ("P8BF"): два
// разных прохода не вправе исключать друг друга. Мнемоника "OMSW".
const orphanMirrorSingletonLockKey int64 = 0x4F_4D_53_57 // "OMSW"

// OrphanMirrorAdapter — адаптер прохода по зеркалу.
type OrphanMirrorAdapter struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewOrphanMirrorAdapter собирает адаптер над пулом. Логгер nil-безопасен.
func NewOrphanMirrorAdapter(pool *pgxpool.Pool) *OrphanMirrorAdapter {
	return &OrphanMirrorAdapter{pool: pool, logger: slog.Default()}
}

var _ seed.OrphanMirrorStore = (*OrphanMirrorAdapter)(nil)

// TryAcquireSingletonOrphanMirrorLock берёт СЕССИОННЫЙ pg_try_advisory_lock по
// известному ключу. Выделяет ОДНО соединение пула на весь прогон, чтобы
// сессионный замок пережил отдельные стейтменты.
func (a *OrphanMirrorAdapter) TryAcquireSingletonOrphanMirrorLock(ctx context.Context) (bool, func(context.Context), error) {
	conn, err := a.pool.Acquire(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("orphan-mirror sweep: acquire conn for singleton lock: %w", err)
	}
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, orphanMirrorSingletonLockKey).Scan(&ok); err != nil {
		conn.Release()
		return false, nil, fmt.Errorf("orphan-mirror sweep: pg_try_advisory_lock: %w", err)
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
		if _, err := conn.Exec(uctx, `SELECT pg_advisory_unlock($1)`, orphanMirrorSingletonLockKey); err != nil {
			a.logger.WarnContext(uctx, "orphan-mirror sweep: singleton advisory-unlock failed (released on conn recycle)",
				slog.Any("err", err))
		}
		conn.Release()
	}
	return true, release, nil
}

// CountMirrorRows — знаменатель переписи.
func (a *OrphanMirrorAdapter) CountMirrorRows(ctx context.Context) (int, error) {
	var n int
	if err := a.pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.resource_mirror`).Scan(&n); err != nil {
		return 0, fmt.Errorf("orphan-mirror sweep: count mirror rows: %w", err)
	}
	return n, nil
}

// ListOrphanMirrorRows — строки, у которых пусты ВСЕ ТРИ носителя родителя.
//
// Порядок детерминирован (тип, затем идентификатор), чтобы потолок прогона
// отрезал одно и то же место, а не случайное.
func (a *OrphanMirrorAdapter) ListOrphanMirrorRows(ctx context.Context, limit int) ([]seed.OrphanMirrorRow, error) {
	rows, err := a.pool.Query(ctx,
		`SELECT m.object_type,
		        m.object_id,
		        EXISTS (SELECT 1 FROM kaname.resource_parent_edge e
		                 WHERE e.object_type = m.object_type
		                   AND e.object_id   = m.object_id) AS repairable
		   FROM kaname.resource_mirror m
		  WHERE m.parent_project_id = ''
		    -- Второй носитель. Джойна на projects здесь НЕТ намеренно: при пустом
		    -- проекте резолвить аккаунт не через что, и выражение с COALESCE
		    -- сводилось бы к этому же сравнению (см. разбор в шапке файла).
		    AND m.parent_account_id = ''
		    -- Третий носитель: цепь предков. Её наличие означает, что строка
		    -- видна пути решения о доступе и ПОЧИНИМА той же базой, — но пустые
		    -- колонки всё равно делают её невидимой материализации, поэтому она
		    -- возвращается с признаком, а не отсеивается.
		  ORDER BY m.object_type ASC, m.object_id ASC
		  LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("orphan-mirror sweep: list orphan rows: %w", err)
	}
	defer rows.Close()

	var out []seed.OrphanMirrorRow
	for rows.Next() {
		var r seed.OrphanMirrorRow
		if err := rows.Scan(&r.ObjectType, &r.ObjectID, &r.RepairableFromChain); err != nil {
			return nil, fmt.Errorf("orphan-mirror sweep: scan orphan row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("orphan-mirror sweep: iterate orphan rows: %w", err)
	}
	return out, nil
}

// RepairMirrorParentFromChain выводит колонки родителя из цепи предков и
// записывает их ОДНИМ оператором.
//
// ОДИН оператор, а не «прочитать цепь → записать колонки»: пара чтение-запись
// есть software check-then-act (запрет #10), и между её половинами снятие
// регистрации успело бы убрать цепь — колонки записались бы от предка, которого
// уже нет.
//
// Идемпотентность держит `WHERE`, а не вызывающий: строка, у которой колонки уже
// непусты, оператором не затрагивается, и повтор меняет ноль строк.
//
// Из цепи берётся БЛИЖАЙШИЙ предок каждого вида (`depth` по возрастанию):
// цепь идёт от ближайшего к дальнему, и проект ресурса — тот, что ближе, а не
// тот, что первым лёг в таблицу.
func (a *OrphanMirrorAdapter) RepairMirrorParentFromChain(ctx context.Context, objectType, objectID string) (bool, error) {
	tag, err := a.pool.Exec(ctx,
		`WITH chain AS (
		     SELECT
		       (SELECT e.parent_id FROM kaname.resource_parent_edge e
		         WHERE e.object_type = $1 AND e.object_id = $2
		           AND e.parent_type = 'project'
		         ORDER BY e.depth ASC LIMIT 1) AS project_id,
		       (SELECT e.parent_id FROM kaname.resource_parent_edge e
		         WHERE e.object_type = $1 AND e.object_id = $2
		           AND e.parent_type = 'account'
		         ORDER BY e.depth ASC LIMIT 1) AS account_id
		 )
		 UPDATE kaname.resource_mirror m
		    SET parent_project_id = COALESCE((SELECT project_id FROM chain), ''),
		        parent_account_id = COALESCE((SELECT account_id FROM chain), ''),
		        updated_at        = now()
		  FROM chain
		  WHERE m.object_type = $1
		    AND m.object_id   = $2
		    -- Идемпотентность: починенную строку оператор не трогает.
		    AND m.parent_project_id = ''
		    AND m.parent_account_id = ''
		    -- Выводить должно быть ИЗ ЧЕГО: цепь без предков вида project/account
		    -- родителя не даёт, и запись пустых колонок поверх пустых была бы
		    -- ложным «починено».
		    AND (chain.project_id IS NOT NULL OR chain.account_id IS NOT NULL)`,
		objectType, objectID,
	)
	if err != nil {
		return false, fmt.Errorf("orphan-mirror sweep: repair parent from chain: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
