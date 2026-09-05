// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// residual_tuples.go — что ЕЩЁ стоит на объекте, когда его снимают.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ ЭТО ЧИТАЮТ
//
// Снятие обязано забрать КАЖДОЕ отношение, которое посредник мог поставить на
// объект, а не только то, которое сумел назвать потребитель. Потребитель называет
// указатель области — это всё, чем он располагает; собственное `owner` создателя
// записано от личности, которую после этого никто не хранит. Значит назвать её
// может только сторона, у которой лежат сами строки.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИЗМЕНИЛОСЬ ПРИ СНЯТИИ ВНЕШНЕГО ДВИЖКА
//
// Раньше эти строки лежали в чужом хранилище, и читать их приходилось СИЛЬНЫМ
// чтением: набор используется для решения, что УДАЛИТЬ, а отставшая копия
// недосказывает — и недосказанное здесь не «повторится и сойдётся», а отношение,
// пережившее снятие своего объекта и продолжающее отвечать «доступ есть».
//
// Теперь строки лежат в СВОЕЙ базе (`kacho_iam.relation_fact` — проекция журнала
// намерений), и вопрос об отставании отпадает by construction: читается ведущая
// база тем же соединением, которым идёт остальная работа. Просьбы к чужому
// транспорту «ответь не с реплики» больше нет, потому что нет чужого транспорта.
//
// Постраничность оставлена: объект несёт горсть отношений, и одна страница
// отвечает на практике, — но «на практике» не гарантия, а молча усечённое чтение
// недоудалило бы ровно то, ради чего этот читатель заведён.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЗДЕСЬ НЕТ ПО ПОСТРОЕНИЮ — И ЭТО ВЕРНО
//
// Отношений-ГЛАГОЛОВ (`v_*`) в проекции нет: глагол ВЫВОДИТСЯ формой из выдачи
// (роль → тип × глагол → область) и строкой не хранится. Прежний читатель у
// чужого хранилища возвращал и их — там глагол был кортежем, — и снятие обязано
// было забирать их поимённо.
//
// Забирать больше нечего: снялась выдача — глагол перестал выводиться. Поэтому
// сужение проекции здесь не потеря полноты, а её условие: попытка «снять глагол»
// адресовалась бы строке, которой не существует.

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho-iam/internal/outboxtypes"
)

// errResidualListingUnbounded — перечисление объекта не сошлось за отведённые
// страницы. Возвращается ошибкой, а не глотается: снятие тогда отказывается и
// доставляется заново, вместо того чтобы закоммитить частичное удаление.
var errResidualListingUnbounded = errors.New("relation_fact: перечисление отношений объекта не сошлось")

const (
	residualReadPageSize = 100
	residualReadPageCap  = 50
)

// ResidualTupleReader называет отношения, стоящие на объекте.
//
// Отбор «какие из них принадлежат посреднику» — работа use-case'а: политика у
// него, поэтому адаптер отдаёт строки как есть и не решает ничего.
type ResidualTupleReader struct {
	pool *pgxpool.Pool
}

// NewResidualTupleReader собирает адаптер. nil-пул даёт nil — композиционный
// корень сборки без базы получает путь «только очередь», а не панику.
func NewResidualTupleReader(pool *pgxpool.Pool) *ResidualTupleReader {
	if pool == nil {
		return nil
	}
	return &ResidualTupleReader{pool: pool}
}

// ObjectTuples перечисляет отношения, стоящие на `object` («тип:идентификатор»).
func (r *ResidualTupleReader) ObjectTuples(ctx context.Context, object string) ([]outboxtypes.RelationTuple, error) {
	if r == nil || r.pool == nil || object == "" {
		return nil, nil
	}
	objectType, objectID, ok := splitObjectRef(object)
	if !ok {
		return nil, fmt.Errorf("relation_fact: объект %q не разбирается как «тип:идентификатор»", object)
	}

	var (
		out       []outboxtypes.RelationTuple
		afterRel  string
		afterSubj string
	)
	for page := 0; page < residualReadPageCap; page++ {
		rows, err := r.pool.Query(ctx, `
			SELECT f.relation, f.subject
			  FROM kacho_iam.relation_fact f
			 WHERE f.object_type = $1
			   AND f.object_id   = $2
			   AND (f.relation, f.subject) > ($3, $4)
			 ORDER BY f.relation, f.subject
			 LIMIT $5`, objectType, objectID, afterRel, afterSubj, residualReadPageSize)
		if err != nil {
			return nil, fmt.Errorf("relation_fact: чтение отношений объекта: %w", err)
		}
		n := 0
		for rows.Next() {
			var relation, subject string
			if serr := rows.Scan(&relation, &subject); serr != nil {
				rows.Close()
				return nil, fmt.Errorf("relation_fact: разбор отношения объекта: %w", serr)
			}
			out = append(out, outboxtypes.RelationTuple{
				User:     subject,
				Relation: relation,
				Object:   object,
			})
			afterRel, afterSubj = relation, subject
			n++
		}
		rows.Close()
		if rerr := rows.Err(); rerr != nil {
			return nil, fmt.Errorf("relation_fact: чтение отношений объекта: %w", rerr)
		}
		if n < residualReadPageSize {
			return out, nil
		}
	}
	return nil, errResidualListingUnbounded
}

// splitObjectRef — «тип:идентификатор» надвое.
func splitObjectRef(s string) (objectType, objectID string, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			if i == 0 || i == len(s)-1 {
				return "", "", false
			}
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}
