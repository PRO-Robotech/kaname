// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// expired_credential_reclaimer.go — долговечная половина снятия истёкших
// удостоверений (задача #1264, приёмка `expired-credential-reclaim.md`).
//
// # ЧТО ЭТО ДЕЛАЕТ
//
// Снимает строку удостоверения, чей срок истёк более чем на её собственную
// отсрочку назад, — ТЕМ ЖЕ оператором, каким её снимает отзыв. Место под
// потолком возвращает существующий триггер списания (`kacho_quota_count`,
// ветвь `TG_OP = 'DELETE'`: `used = GREATEST(used - 1, 0)`), и возвращает в ТОЙ
// ЖЕ транзакции. Арифметика списания здесь не трогается вовсе — она уже
// выражает нужное, и это несущий довод в пользу уборки против «не считать
// истёкшие на пути списания».
//
// # ЧАСЫ — БАЗЫ, А НЕ ПРОЦЕССА
//
// Порог судит `now()` СУБД. Это не мелочь реализации: тем же `now()` судит
// отбор резолва секрета (`expires_at > now()`), то есть ЧИТАТЕЛЬ, решающий,
// действует ли строка. Уборщик, получающий момент аргументом, тождествен этому
// читателю только при синхронности часов; ушедший вперёд процесс снял бы строку,
// которую резолв ещё считает живой. Поэтому наружу отсюда уезжают ДЛИТЕЛЬНОСТИ,
// а момент вычисляет база.
//
// # ОТБОР РАСКЛАДЫВАЕТСЯ НА ИНДЕКСИРУЕМОЕ И ФИЛЬТР
//
// Действующая отсрочка строки зависит от ДВУХ её колонок
// (`expires_at`, `created_at`), поэтому выражение целиком по индексу не идёт —
// планировщик диапазона по нему не строит. Отбор поэтому несёт НЕОБХОДИМОЕ
// условие `expires_at <= now() - minDelay` (по нему работает частичный индекс), а
// точная отсрочка применяется фильтром ПОВЕРХ отобранного. Необходимое оно
// потому, что отсрочка НИКОГДА не меньше нижней границы.
//
// # РЕПЛИКИ
//
// Партия берётся клеймом (`FOR UPDATE SKIP LOCKED`), поэтому две реплики не
// спорят за одни строки и не снимают одну дважды. Партия упорядочена ПО
// НОСИТЕЛЮ: побочная правка строки учёта идёт под клеймом, и порядок замков на
// строках учёта клеймом не задаётся — две реплики, взявшие пересекающиеся
// наборы принципалов, брали бы их в произвольном порядке, и цикл возможен.
// Детерминированный порядок это закрывает.
package pg

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/service"
)

// ExpiredCredentialReclaimSpec — границы одного прогона. ДЛИТЕЛЬНОСТИ, а не
// моменты: момент вычисляет база своими часами (см. шапку файла).
type ExpiredCredentialReclaimSpec struct {
	// MinDelay — технический пол отсрочки и он же индексируемая необходимая
	// граница отбора.
	MinDelay time.Duration
	// Grace — верхняя отсрочка; действующая связана со сроком самой строки.
	Grace time.Duration
	// BatchSize — строк на таблицу за прогон.
	BatchSize int
	// DryRun — показ без снятия.
	DryRun bool
}

// ExpiredCredentialReclaimResult — перепись прогона: ДВА числа плюс разбивка.
type ExpiredCredentialReclaimResult struct {
	Found     int
	Reclaimed int
	ByKind    map[string]int
}

// ExpiredCredentialReclaimer снимает удостоверения обеих таблиц.
type ExpiredCredentialReclaimer struct {
	pool   *pgxpool.Pool
	schema string
}

// NewExpiredCredentialReclaimer — конструктор композиционного корня.
func NewExpiredCredentialReclaimer(pool *pgxpool.Pool, schema string) *ExpiredCredentialReclaimer {
	if schema == "" {
		schema = "kaname"
	}
	return &ExpiredCredentialReclaimer{pool: pool, schema: schema}
}

// reclaimTarget — одна таблица удостоверений и всё, чем она отличается от
// соседней.
//
// Перечень ВЫПИСАН, и это осознанно: таблиц удостоверений в схеме две, у каждой
// свой носитель, свой вид учёта и свой тип события аудита. Вывести их из дерева
// нечем — вид учёта живёт в объявлении триггера строкой, — поэтому расхождение
// с деревом закрывает не форма перечня, а проба, читающая обе таблицы.
type reclaimTarget struct {
	// Table — имя таблицы удостоверений.
	Table string
	// CarrierCol — колонка, несущая принципала: по ней упорядочена партия.
	CarrierCol string
	// Kind — вид учёта, под которым принципалу считается потолок.
	Kind string
	// AuditEvent — СВОЙ тип события, а не тип ручного отзыва: смешать их значило
	// бы утратить ответственность — аудит обязан писать, КТО снял.
	AuditEvent string
	// CascadeCount — подзапрос, считающий записи, которые уйдут каскадом вместе
	// со строкой. Пустой — каскада нет.
	CascadeCount string
	// ResourceType — как ресурс называется в теле события.
	ResourceType string
}

// reclaimTargets — обе таблицы удостоверений.
func reclaimTargets() []reclaimTarget {
	return []reclaimTarget{
		{
			Table:        "user_oauth_clients",
			CarrierCol:   "user_id",
			Kind:         "iam.user.credential",
			AuditEvent:   "iam.user_token.expired_reclaimed",
			ResourceType: "user_token",
		},
		{
			Table:      "service_account_oauth_clients",
			CarrierCol: "sva_id",
			Kind:       "iam.serviceAccount.credential",
			AuditEvent: "iam.sa_key.expired_reclaimed",
			// Снятие строки машины УНОСИТ привязанные к ней записи доверия
			// внешним издателям (`ON DELETE CASCADE`). Каскад намеренный —
			// доверие, привязанное к мёртвому ключу, и само мертво, — но при
			// автоснятии действует ПЛАТФОРМА, и настройка, восстановление
			// которой требует участия внешней стороны, исчезает без участия
			// арендатора. Поэтому событие аудита обязано назвать ЧИСЛО снятых
			// записей: иначе оно исчезает молча.
			CascadeCount: `(SELECT count(*) FROM %[1]s.federated_trusted_issuers f
			                 WHERE f.sa_oauth_client_id = c.id)`,
			ResourceType: "sa_key",
		},
	}
}

// reclaimedRow — то, что известно о снятой строке. Тело события шире образца
// ручного отзыва намеренно: строки больше нет, и отличить «сняли законно» от
// «уборщик посчитал не так» можно только по её содержимому.
type reclaimedRow struct {
	ID        string
	Carrier   string
	Kind      string
	ExpiresAt time.Time
	Cascaded  int64
}

// ReclaimExpiredCredentials делает один прогон по обеим таблицам.
//
// Транзакция — СВОЯ на таблицу: отказ на одной не обязан уносить работу,
// сделанную по другой. Внутри транзакции клейм, снятие и запись аудита
// атомарны — без атомарности возможны снятия без следа, то есть ровно
// «пропало, и следа нет».
func (r *ExpiredCredentialReclaimer) ReclaimExpiredCredentials(
	ctx context.Context, spec ExpiredCredentialReclaimSpec,
) (ExpiredCredentialReclaimResult, error) {
	res := ExpiredCredentialReclaimResult{ByKind: map[string]int{}}
	if spec.BatchSize <= 0 {
		return res, fmt.Errorf("снятие истёкших удостоверений: размер партии обязан быть положителен, дано %d", spec.BatchSize)
	}
	if spec.MinDelay <= 0 {
		return res, fmt.Errorf("снятие истёкших удостоверений: технический пол отсрочки обязан быть положителен, дано %v", spec.MinDelay)
	}
	if spec.Grace < spec.MinDelay {
		// Настройка ниже пола не превращается здесь в снятие живого: страж
		// старта такую отвергает, а прогон отказывает громко, а не тихо
		// подтягивает величину до безопасной.
		return res, fmt.Errorf("снятие истёкших удостоверений: отсрочка %v ниже технического пола %v — "+
			"до пола ещё живут отчеканенные токены", spec.Grace, spec.MinDelay)
	}

	for _, tgt := range reclaimTargets() {
		found, rows, err := r.sweepOneTable(ctx, tgt, spec)
		if err != nil {
			return res, fmt.Errorf("снятие истёкших удостоверений (%s): %w", tgt.Table, err)
		}
		res.Found += found
		res.Reclaimed += len(rows)
		if found > 0 || len(rows) > 0 {
			res.ByKind[tgt.Kind] = len(rows)
		}
	}
	return res, nil
}

// sweepOneTable — клейм, снятие и аудит одной таблицы в одной транзакции.
func (r *ExpiredCredentialReclaimer) sweepOneTable(
	ctx context.Context, tgt reclaimTarget, spec ExpiredCredentialReclaimSpec,
) (int, []reclaimedRow, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("открыть транзакцию: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	claimed, err := r.claim(ctx, tx, tgt, spec)
	if err != nil {
		return 0, nil, err
	}
	if len(claimed) == 0 || spec.DryRun {
		// Показ без снятия ничего не удаляет и ничего не пишет; транзакция
		// откатывается вместе с клеймом, поэтому чужой прогон не заперт.
		return len(claimed), nil, nil
	}

	removed, err := r.remove(ctx, tx, tgt, claimed)
	if err != nil {
		return len(claimed), nil, err
	}
	for _, row := range removed {
		ev := service.AuditEvent{
			EventType: tgt.AuditEvent,
			Payload: map[string]any{
				// Актор — ПЛАТФОРМА. Тип события отдельный, и актор отдельный:
				// «арендатор отозвал» и «платформа сняла» обязаны быть
				// различимы, иначе теряется ответственность.
				"actor":           "kaname:expired-credential-reclaim",
				"resource_type":   tgt.ResourceType,
				"resource_id":     row.ID,
				"principal_id":    row.Carrier,
				"credential_kind": row.Kind,
				"expired_at":      row.ExpiresAt.UTC().Format(time.RFC3339),
				"grace_applied":   spec.Grace.String(),
				// Число записей, ушедших каскадом: их восстановление требует
				// участия внешней стороны, и молча исчезать они не вправе.
				"cascaded_trusted_issuers": row.Cascaded,
			},
		}
		if err := insertAuditEventTx(ctx, tx, ev); err != nil {
			return len(claimed), nil, fmt.Errorf("аудит снятия %s: %w", row.ID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return len(claimed), nil, fmt.Errorf("зафиксировать снятие: %w", err)
	}
	return len(claimed), removed, nil
}

// claim берёт партию подлежащих снятию.
//
// `FOR UPDATE SKIP LOCKED` — клейм: строку, взятую соседней репликой, эта
// пропускает, а не ждёт. Порядок — по носителю, затем по идентификатору: он
// задаёт порядок замков на строках УЧЁТА, которые правит триггер снятия.
func (r *ExpiredCredentialReclaimer) claim(
	ctx context.Context, tx pgx.Tx, tgt reclaimTarget, spec ExpiredCredentialReclaimSpec,
) ([]reclaimedRow, error) {
	cascade := "0::bigint"
	if tgt.CascadeCount != "" {
		cascade = fmt.Sprintf(tgt.CascadeCount, r.schema)
	}
	q := fmt.Sprintf(`
SELECT c.id, c.%[2]s, c.credential_kind, c.expires_at, %[3]s
  FROM %[1]s.%[4]s c
 WHERE c.expires_at IS NOT NULL
   -- НЕОБХОДИМОЕ условие: отсрочка никогда не меньше пола, поэтому строка,
   -- не прошедшая его, не пройдёт и точного фильтра. По нему идёт индекс.
   AND c.expires_at <= now() - $1::interval
   -- Точная отсрочка: min(верхняя, max(пол, срок самой строки)). Окно памяти о
   -- вещи не должно быть дольше жизни самой вещи.
   AND c.expires_at + LEAST($2::interval,
         GREATEST($1::interval, c.expires_at - c.created_at)) <= now()
 ORDER BY c.%[2]s, c.id
 LIMIT $3
 FOR UPDATE SKIP LOCKED`, r.schema, tgt.CarrierCol, cascade, tgt.Table)

	rows, err := tx.Query(ctx, q, spec.MinDelay, spec.Grace, spec.BatchSize)
	if err != nil {
		return nil, fmt.Errorf("клейм партии: %w", err)
	}
	defer rows.Close()

	var out []reclaimedRow
	for rows.Next() {
		var row reclaimedRow
		if err := rows.Scan(&row.ID, &row.Carrier, &row.Kind, &row.ExpiresAt, &row.Cascaded); err != nil {
			return nil, fmt.Errorf("чтение партии: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("обход партии: %w", err)
	}
	return out, nil
}

// remove снимает заклеймённые строки ТЕМ ЖЕ оператором, каким их снимает отзыв.
//
// Возврат места делает триггер списания на этом же `DELETE`, в этой же
// транзакции: «спросить, потом списать» здесь не появляется by construction.
func (r *ExpiredCredentialReclaimer) remove(
	ctx context.Context, tx pgx.Tx, tgt reclaimTarget, claimed []reclaimedRow,
) ([]reclaimedRow, error) {
	byID := make(map[string]reclaimedRow, len(claimed))
	ids := make([]string, 0, len(claimed))
	for _, c := range claimed {
		byID[c.ID] = c
		ids = append(ids, c.ID)
	}

	q := fmt.Sprintf(`DELETE FROM %s.%s WHERE id = ANY($1) RETURNING id`, r.schema, tgt.Table)
	rows, err := tx.Query(ctx, q, ids)
	if err != nil {
		return nil, fmt.Errorf("снятие партии: %w", err)
	}
	defer rows.Close()

	var out []reclaimedRow
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("чтение снятого: %w", err)
		}
		out = append(out, byID[id])
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("обход снятого: %w", err)
	}
	return out, nil
}
