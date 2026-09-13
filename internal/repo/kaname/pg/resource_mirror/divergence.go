// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resource_mirror

// divergence.go — РАЗНОСТЬ ЗЕРКАЛА И КАТАЛОГА, У КОТОРОЙ ПОЯВИЛСЯ ЧИТАТЕЛЬ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (kacho#1828)
//
// Условие приёма сузили ВПЕРЁД: строка зеркала принимается только при живой
// строке каталога с таким `dotted` (`emitter.go`, ветвь `!typeLive`). У того,
// что записано ДО сужения, производителя отзыва нет — ключ судит строку
// зеркала, а право живёт в реляционной форме, и ключ его не касается by
// construction.
//
// Разность при этом НИКТО НЕ ЧИТАЛ: ни одной функцией, ни одним запросом. То
// есть величина, от которой зависит решение владельца об отзыве, не была
// измерена ни разу — не «оказалась нулём», а не спрашивалась.
//
// ─────────────────────────────────────────────────────────────────────────────
// РАЗНОСТЬ РАСПАДАЕТСЯ НА ТРИ СОСТОЯНИЯ, И СХЛОПЫВАТЬ ИХ НЕЛЬЗЯ
//
//	живой тип                  нормой является; в разность не входит
//	снятый С ПРЕЕМНИКОМ        строка ПЕРЕЖИВАЕТ снятие ОСОЗНАННО (см. ниже), и
//	                           `superseded_by` называет, куда её переселять;
//	                           это ПРЕДМЕТ РЕШЕНИЯ ВЛАДЕЛЬЦА, а не дефект
//	снятый БЕЗ ПРЕЕМНИКА       строку переселять НЕКУДА и назвать нечем
//	типа нет в каталоге ВОВСЕ  ни живого, ни снятого: адресата у отзыва нет
//
// Схлопнуть их в одно число значило бы либо объявить дефектом то, что дерево
// делает НАМЕРЕННО (проба
// `TestResourceMirror_RetiredTypeKeepsItsAlreadyRegisteredRows` держит
// переживание снятия как СВОЙСТВО), либо промолчать о состоянии, которое
// разрешить нечем.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТО ЧТЕНИЕ, А НЕ КЛЮЧ СХЕМЫ
//
// Ключ на `(dotted, live)` выразил бы сверку постоянным инвариантом — и тем
// самым ЗАПРЕТИЛ БЫ СНЯТИЕ типа, пока у арендатора есть хоть один ресурс этого
// типа, а каскад унёс бы чужие данные. Довод записан у самого оператора вставки
// (`emitter.go`), и здесь он не пересматривается: условие приёма и постоянный
// инвариант — разные утверждения.
//
// Значит держателем может быть только ЧТЕНИЕ. Оно и заводится.

import (
	"context"
	"fmt"
)

// CatalogState — чем каталог отвечает на тип, который несёт зеркало.
type CatalogState string

const (
	// CatalogLive — живая строка каталога. Норма.
	CatalogLive CatalogState = "живой"
	// CatalogRetiredSucceeded — строка снята, преемник назван.
	CatalogRetiredSucceeded CatalogState = "снят, преемник назван"
	// CatalogRetiredOrphan — строка снята, преемник НЕ назван.
	CatalogRetiredOrphan CatalogState = "снят без преемника"
	// CatalogAbsent — строки нет вовсе, ни живой, ни снятой.
	CatalogAbsent CatalogState = "в каталоге нет"
)

// DivergenceRow — один тип, который несёт зеркало, вместе с ответом каталога.
type DivergenceRow struct {
	// ObjectType — значение `resource_mirror.object_type`, словарь КАТАЛОГА.
	ObjectType string
	// Rows — сколько строк зеркала этого типа.
	Rows int64
	// State — чем каталог отвечает на этот тип.
	State CatalogState
	// SupersededBy — живой тип-преемник, когда каталог его назвал.
	SupersededBy string
}

// Divergence — ЧТО НЕСЁТ ЗЕРКАЛО СВЕРХ ЖИВОГО КАТАЛОГА.
//
// Возвращает строку на каждый тип зеркала, чей ответ каталога НЕ `живой`, — то
// есть ровно разность. Живые типы опускаются: их в разности нет by construction,
// и перечислять их значило бы утопить предмет в норме.
//
// Пустой ответ означает «разности нет», и это отличимо от «не спрашивали»:
// вызывающий получает ещё и `Scanned` — сколько РАЗЛИЧНЫХ типов зеркало несёт
// всего. Ноль осмотренных типов — пустое зеркало, а не чистая разность.
func Divergence(ctx context.Context, q querier) (rows []DivergenceRow, scanned int, err error) {
	const stmt = `
		SELECT m.object_type,
		       count(*)                                    AS rows,
		       c.dotted IS NOT NULL                        AS known,
		       coalesce(c.live, false)                     AS live,
		       coalesce(c.superseded_by, '')               AS superseded_by
		  FROM kaname.resource_mirror m
		  LEFT JOIN kaname.catalog_resource c
		         ON c.dotted = m.object_type
		 GROUP BY m.object_type, c.dotted, c.live, c.superseded_by
		 ORDER BY m.object_type`

	res, qerr := q.Query(ctx, stmt)
	if qerr != nil {
		return nil, 0, fmt.Errorf("resource_mirror: divergence: %w", qerr)
	}
	defer res.Close()

	for res.Next() {
		var (
			objectType   string
			count        int64
			known, live  bool
			supersededBy string
		)
		if serr := res.Scan(&objectType, &count, &known, &live, &supersededBy); serr != nil {
			return nil, 0, fmt.Errorf("resource_mirror: divergence scan: %w", serr)
		}
		scanned++
		switch {
		case known && live:
			// Норма: в разность не входит.
		case !known:
			rows = append(rows, DivergenceRow{ObjectType: objectType, Rows: count, State: CatalogAbsent})
		case supersededBy == "":
			rows = append(rows, DivergenceRow{ObjectType: objectType, Rows: count, State: CatalogRetiredOrphan})
		default:
			rows = append(rows, DivergenceRow{
				ObjectType: objectType, Rows: count,
				State: CatalogRetiredSucceeded, SupersededBy: supersededBy,
			})
		}
	}
	if rerr := res.Err(); rerr != nil {
		return nil, 0, fmt.Errorf("resource_mirror: divergence rows: %w", rerr)
	}
	return rows, scanned, nil
}

// UnresolvableDivergence — те строки разности, у которых ИСХОДА НЕТ.
//
// Тип, которого каталог не знает вовсе, и тип, снятый без преемника, объединены
// не по происхождению, а по тому, что с ними можно СДЕЛАТЬ: ничего. Переселять
// некуда — живого преемника не назвал никто; отозвать молча — решение, которое
// ОТНИМАЕТ доступ и потому принимается владельцем, а не проверкой.
//
// Снятое с преемником сюда НЕ входит: у него исход назван самой строкой
// каталога, и переживание снятия — объявленное свойство дерева, а не дефект.
func UnresolvableDivergence(rows []DivergenceRow) []DivergenceRow {
	var out []DivergenceRow
	for _, r := range rows {
		if r.State == CatalogAbsent || r.State == CatalogRetiredOrphan {
			out = append(out, r)
		}
	}
	return out
}
