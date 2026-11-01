// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzfilter

import (
	"context"
	"sort"
	"strings"
)

// HeldOn — подмножество объектов `objects` (форма «тип:идентификатор», типы
// смешаны), на которых субъект держит отношение `relation`, множеством полных
// имён объектов.
//
// # Зачем, рядом с VisibleSet
//
// VisibleSet спрашивает предикат ЧТЕНИЯ одного типа — тот, которым гейтится
// одиночное чтение. Проверке права выдавать на областях действующих выдач
// (`access_binding.ScopeGrantAuthority`) нужен другой вопрос: одно отношение
// (`admin`) о наборе областей, где типы смешаны (`account`, `project`,
// `cluster`). Набор растёт с тем, что уже выдано, и ничем не ограничен до
// проверки, поэтому вопрос на область делал бы цену запроса равной числу
// областей. Здесь цена — по партии на тип области: ceil(n_t /
// MaxBatchChecksPerRequest) запросов на тип, партии одного типа — параллельно,
// как у VisibleSet (BatchParallelism).
//
// Партийная дверь отвечает об объектах ОДНОГО типа (партия двух типов —
// ошибка двери), поэтому набор разбивается по типу; типы спрашиваются по
// порядку имени, так что последовательность запросов детерминирована.
//
// # Исходы
//
// Закрыто по умолчанию: нет двери, нет субъекта, нет отношения, объект без типа
// либо без идентификатора — объект не держится, хранилище не спрашивается.
// Первая ошибка двери проваливает весь ответ (nil и ошибка): частичный набор не
// возвращается, потому что «не спросили» неотличимо в нём от «нет права».
// Ответ двери не той длины — ошибка (batchRelationRound).
func HeldOn(ctx context.Context, bc BatchObjectChecker, subject, relation string, objects []string) (map[string]bool, error) {
	out := make(map[string]bool, len(objects))
	if bc == nil || subject == "" || relation == "" || len(objects) == 0 {
		return out, nil
	}

	byType := map[string][]string{}
	seen := make(map[string]struct{}, len(objects))
	for _, o := range objects {
		typ, id, ok := strings.Cut(o, ":")
		if !ok || typ == "" || id == "" {
			continue
		}
		if _, dup := seen[o]; dup {
			continue
		}
		seen[o] = struct{}{}
		byType[typ] = append(byType[typ], id)
	}
	types := make([]string, 0, len(byType))
	for typ := range byType {
		types = append(types, typ)
	}
	sort.Strings(types)

	for _, typ := range types {
		heldIDs := make(map[string]bool, len(byType[typ]))
		if _, err := batchRelationRound(ctx, bc, subject, typ, relation, byType[typ], heldIDs); err != nil {
			return nil, err
		}
		for id := range heldIDs {
			out[typ+":"+id] = true
		}
	}
	// Как у VisibleSet: истёкший запрос без записанной ошибки — «перестали
	// спрашивать», а не «права нет».
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
