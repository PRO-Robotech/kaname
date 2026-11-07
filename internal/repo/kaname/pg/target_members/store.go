// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package target_members — хранилище kaname.access_binding_target_members,
// материализованного членства желаемого состояния цели привязки.
//
// Работник согласования вычисляет желаемый набор участников по resource_mirror,
// делает UPSERT каждого с verification_status и DELETE выбывших
// внутри транзакции записи вызывающего, атомарно с
// записью кортежей fga_outbox (запрет №10). Чтения обслуживают разницу (текущий набор) и
// проекцию чтения/интерфейса (членство со статусом каждого участника).
//
// Идемпотентность: UPSERT по первичному ключу (binding_id, object_type, object_id) делает
// повторную материализацию эквивалентной отсутствию изменений и сериализует параллельные проходы
// согласования блокировкой строки (детерминированная последняя запись).
package target_members

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Member — один материализованный участник цели со статусом проверки. RoleID и
// RuleFP связывают участника с породившей его парой (роль, правило) модели правил
// RBAC; входят в первичный ключ (binding, role, rule_fp, object).
type Member struct {
	BindingID          string
	RoleID             string
	RuleFP             string
	ObjectType         string
	ObjectID           string
	VerificationStatus domain.VerificationStatus
}

// UpsertTx вставляет или обновляет строку членства до status по полной координате
// правила (binding, role, rule_fp, object) в транзакции вызывающего. Идемпотентен по
// первичному ключу; при конфликте статус заменяется (повторная проверка
// PENDING→ACTIVE/REJECTED). updated_at продвигается при записи.
func UpsertTx(ctx context.Context, tx pgx.Tx, m Member) error {
	if _, err := tx.Exec(ctx,
		`INSERT INTO kaname.access_binding_target_members
		   (binding_id, role_id, rule_fp, object_type, object_id, verification_status, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, now(), now())
		 ON CONFLICT (binding_id, role_id, rule_fp, object_type, object_id) DO UPDATE
		    SET verification_status = EXCLUDED.verification_status,
		        updated_at          = now()`,
		m.BindingID, m.RoleID, m.RuleFP, m.ObjectType, m.ObjectID, string(m.VerificationStatus),
	); err != nil {
		return fmt.Errorf("target_members: upsert: %w", err)
	}
	return nil
}

// upsertBatchRows ограничивает один SQL, не размер атомарного прохода.
const upsertBatchRows = 4096

// UpsertManyTx — тот же UPSERT, что UpsertTx, ограниченными наборами в той же tx.
//
// ЗАЧЕМ. Аддитивный проход материализации пишет по строке члена на КАЖДУЮ выдачу,
// совпавшую с одним объектом, а совпавших столько, сколько выдач покрывает область
// объекта (по дереву выдач: p50 = 9, хвост 227). Поштучная вставка делала стоимость
// прохода линейной по числу выдач соседей, хотя изменился ровно один объект.
//
// Семантика дословно та же: тот же ключ конфликта, то же перезаписывание статуса,
// то же advance updated_at. Дубли по ключу внутри одного набора схлопываются здесь —
// `ON CONFLICT … DO UPDATE` не вправе задеть одну строку дважды в одном стейтменте, и
// набор с дублем Postgres отверг бы целиком (поштучная вставка этого не требовала,
// потому что каждая строка ехала своим стейтментом). Пустой набор — no-op.
func UpsertManyTx(ctx context.Context, tx pgx.Tx, members []Member) error {
	if len(members) == 0 {
		return nil
	}
	n := min(len(members), upsertBatchRows)
	bindings := make([]string, 0, n)
	roles := make([]string, 0, n)
	fps := make([]string, 0, n)
	objTypes := make([]string, 0, n)
	objIDs := make([]string, 0, n)
	statuses := make([]string, 0, n)
	flush := func() error {
		if len(bindings) == 0 {
			return nil
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO kaname.access_binding_target_members
			   (binding_id, role_id, rule_fp, object_type, object_id, verification_status, created_at, updated_at)
			 SELECT b, r, f, ot, oi, vs, now(), now()
			   FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[])
			        AS t(b, r, f, ot, oi, vs)
			 ON CONFLICT (binding_id, role_id, rule_fp, object_type, object_id) DO UPDATE
			    SET verification_status = EXCLUDED.verification_status,
			        updated_at          = now()`,
			bindings, roles, fps, objTypes, objIDs, statuses,
		); err != nil {
			return fmt.Errorf("target_members: upsert many (%d): %w", len(bindings), err)
		}
		return nil
	}
	seen := make(map[[5]string]struct{}, len(members))
	// Дедупликация общая для всех SQL: поздний дубль не меняет первый статус.
	for _, m := range members {
		k := [5]string{m.BindingID, m.RoleID, m.RuleFP, m.ObjectType, m.ObjectID}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		bindings = append(bindings, m.BindingID)
		roles = append(roles, m.RoleID)
		fps = append(fps, m.RuleFP)
		objTypes = append(objTypes, m.ObjectType)
		objIDs = append(objIDs, m.ObjectID)
		statuses = append(statuses, string(m.VerificationStatus))
		if len(bindings) == upsertBatchRows {
			if err := flush(); err != nil {
				return err
			}
			bindings, roles, fps = bindings[:0], roles[:0], fps[:0]
			objTypes, objIDs, statuses = objTypes[:0], objIDs[:0], statuses[:0]
		}
	}
	return flush()
}

// DeleteTx удаляет строку членства по полной координате правила (binding, role,
// rule_fp, object) в транзакции вызывающего. Нужен при выпадении участника ACTIVE из
// подходящего набора (сняли метку или правило): работник
// немедленно отзывает кортеж FGA И удаляет строку той же транзакцией. Нет строки →
// без действия (идемпотентно). DELETE ограничен rule_fp, поэтому удаление участника
// одного правила никогда не снимает участника того же объекта другого правила.
func DeleteTx(ctx context.Context, tx pgx.Tx, bindingID, ruleFP, objectType, objectID string) error {
	if _, err := tx.Exec(ctx,
		`DELETE FROM kaname.access_binding_target_members
		  WHERE binding_id = $1 AND rule_fp = $2 AND object_type = $3 AND object_id = $4`,
		bindingID, ruleFP, objectType, objectID,
	); err != nil {
		return fmt.Errorf("target_members: delete: %w", err)
	}
	return nil
}

// ListByBindingTx возвращает всех материализованных участников привязки в порядке для
// стабильного чтения и сравнения. Работает в транзакции вызывающего: разница согласования читает текущий
// набор в той же транзакции, где производится запись.
func ListByBindingTx(ctx context.Context, tx pgx.Tx, bindingID string) ([]Member, error) {
	return queryMembers(ctx, tx,
		`SELECT binding_id, role_id, rule_fp, object_type, object_id, verification_status
		   FROM kaname.access_binding_target_members
		  WHERE binding_id = $1
		  ORDER BY rule_fp ASC, object_type ASC, object_id ASC`,
		bindingID)
}

// ListByBindingObjectTx возвращает материализованных участников ОДНОЙ привязки на ОДНОМ объекте:
// УЗКУЮ базу сравнения согласования по событию объекта (UPSERT/DELETE зеркала или
// UPDATE метки меняет ровно один объект, поэтому измениться могут только его участники).
//
// Предикат начинается с (object_type, object_id), поэтому обслуживается индексом
// по объекту: у объекта лишь несколько строк участников (в среднем 3,2 привязки на
// измеренном стенде, 66 в хвосте), а первый столбец первичного ключа — binding_id,
// под которым самые горячие привязки держат 10 140 строк. Фильтрация объекта из всей
// привязки вернула бы то самое чтение O(mirror), ради устранения которого нужна узкая база.
func ListByBindingObjectTx(ctx context.Context, tx pgx.Tx, bindingID, objectType, objectID string) ([]Member, error) {
	return queryMembers(ctx, tx,
		`SELECT binding_id, role_id, rule_fp, object_type, object_id, verification_status
		   FROM kaname.access_binding_target_members
		  WHERE object_type = $2 AND object_id = $3 AND binding_id = $1
		  ORDER BY rule_fp ASC`,
		bindingID, objectType, objectID)
}

// BindingsForObjectTx возвращает различные идентификаторы привязок с материализованным
// участником, ссылающимся на (objectType, objectID). Работник использует это при
// событии изменения зеркала, чтобы найти привязки с селектором/byName,
// которые нужно заново оценить для объекта. Чтение обслуживает
// индекс по объекту.
func BindingsForObjectTx(ctx context.Context, tx pgx.Tx, objectType, objectID string) ([]string, error) {
	// ORDER BY binding_id ASC: работник берёт pg_advisory_xact_lock каждой привязки
	// в порядке обхода, поэтому запрос ОБЯЗАН возвращать детерминированный порядок,
	// чтобы параллельные проходы ReconcileObject не образовывали взаимных блокировок. Сценарий
	// заново сортирует объединение двух источников обхода, но детерминированный порядок SQL сохраняет
	// честность контракта и стабильность EXPLAIN.
	rows, err := tx.Query(ctx,
		`SELECT DISTINCT binding_id
		   FROM kaname.access_binding_target_members
		  WHERE object_type = $1 AND object_id = $2
		  ORDER BY binding_id ASC`,
		objectType, objectID)
	if err != nil {
		return nil, fmt.Errorf("target_members: bindings for object: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("target_members: scan binding id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func queryMembers(ctx context.Context, tx pgx.Tx, sql string, args ...any) ([]Member, error) {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("target_members: query: %w", err)
	}
	defer rows.Close()
	return scanMembers(rows)
}

func scanMembers(rows pgx.Rows) ([]Member, error) {
	var out []Member
	for rows.Next() {
		var (
			m  Member
			st string
		)
		if err := rows.Scan(&m.BindingID, &m.RoleID, &m.RuleFP, &m.ObjectType, &m.ObjectID, &st); err != nil {
			return nil, fmt.Errorf("target_members: scan: %w", err)
		}
		m.VerificationStatus = domain.VerificationStatus(st)
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("target_members: rows: %w", err)
	}
	return out, nil
}
