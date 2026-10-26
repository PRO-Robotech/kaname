// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resource_mirror

// descendants.go — потомки снимаемого объекта по цепи предков (kaname#1002).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПОТОМКОВ НАХОДИТ KANAME, А НЕ РЕГИСТРАТОР
//
// Снятие регистрации родителя называет ОДИН объект. Регистратор модуля
// перечислить его потомков не может: чтения зеркала kaname у него нет, а
// потомки, заведённые вне его учёта, ему не видны вовсе. Цепь предков каждого
// зарегистрированного объекта хранит `kaname.resource_parent_edge` — ребро на
// КАЖДОГО предка, с глубиной (замыкание, а не только ближайший родитель). Поэтому
// «все потомки на любой глубине» — один выбор по стороне предка, и его
// обслуживает индекс `resource_parent_edge_by_parent (parent_type, parent_id)`.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПОТОМОК СНИМАЕТСЯ БЕЗ НАДГРОБИЯ
//
// Версия регистрации потомка — его собственная, и с надгробием родителя она не
// сравнима. Предмет здесь другой: родитель снят (вызывающий зовёт это только
// тогда, когда снятие родителя удалило его строку зеркала), значит у потомка
// живого родителя больше нет, какой бы версии ни была его регистрация.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Descendant — объект, в цепи предков которого стоит снимаемый родитель.
// `ModelType` — имя словаря МОДЕЛИ прав (им названа сторона объекта ребра).
type Descendant struct {
	ModelType string
	ID        string
}

// DescendantsTx возвращает каждый объект, в цепи предков которого на любой
// глубине стоит (parentType, parentID). `parentType` — имя любого из двух
// словарей: сторона предка ребра названа словарём модели, и перевод берётся тот
// же единственный, которым цепь пишется (`modelTypeName`).
//
// Порядок — по ключу объекта: два снятия разных родителей с общим потомком
// берут замки его строк в одном порядке.
func DescendantsTx(ctx context.Context, tx pgx.Tx, parentType, parentID string) ([]Descendant, error) {
	if tx == nil {
		return nil, fmt.Errorf("resource_mirror: tx must not be nil")
	}
	modelType, err := modelTypeName(ctx, tx, parentType)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx,
		`SELECT DISTINCT object_type, object_id
		   FROM kaname.resource_parent_edge
		  WHERE parent_type = $1 AND parent_id = $2
		  ORDER BY object_type, object_id`,
		modelType, parentID)
	if err != nil {
		return nil, fmt.Errorf("resource_parent_edge: descendants: %w", err)
	}
	defer rows.Close()
	var out []Descendant
	for rows.Next() {
		var d Descendant
		if err := rows.Scan(&d.ModelType, &d.ID); err != nil {
			return nil, fmt.Errorf("resource_parent_edge: descendants: scan: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("resource_parent_edge: descendants: %w", err)
	}
	return out, nil
}

// DropRegistrationTx снимает регистрацию потомка целиком и безусловно: строку
// зеркала (словарь каталога, `catalogType`) и всю его цепь предков (словарь
// модели, `modelType`). deleted — строка зеркала была и снята: только такое
// снятие есть снятие регистрации и отзывает выдачи объекта (kaname#963, Д1).
//
// version — версия снятой регистрации (kaname#969): кортежи потомка записаны
// версиями его регистраций, и снять их ВСЕ можно лишь надгробием не старше
// последней из них. Нулевая — строки не было либо регистрация без версии
// ('-infinity'): тогда надгробие выбирает вызывающий.
func DropRegistrationTx(ctx context.Context, tx pgx.Tx, catalogType, modelType, objectID string) (bool, time.Time, error) {
	if tx == nil {
		return false, time.Time{}, fmt.Errorf("resource_mirror: tx must not be nil")
	}
	var (
		version pgtype.Timestamptz
		deleted bool
	)
	err := tx.QueryRow(ctx,
		`DELETE FROM kaname.resource_mirror WHERE object_type = $1 AND object_id = $2
		 RETURNING source_version`,
		catalogType, objectID).Scan(&version)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return false, time.Time{}, fmt.Errorf("resource_mirror: drop descendant: %w", err)
	default:
		deleted = true
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM kaname.resource_parent_edge WHERE object_type = $1 AND object_id = $2`,
		modelType, objectID); err != nil {
		return false, time.Time{}, fmt.Errorf("resource_parent_edge: drop descendant: %w", err)
	}
	if !version.Valid || version.InfinityModifier != pgtype.Finite {
		return deleted, time.Time{}, nil
	}
	return deleted, version.Time, nil
}
