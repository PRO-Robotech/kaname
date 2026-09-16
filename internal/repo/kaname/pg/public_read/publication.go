// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package public_read — публикация объекта для АНОНИМНОГО ЧТЕНИЯ (`user:* #v_get`),
// упорядоченная версией владельца (kaname#107).
//
// # Предмет
//
// Публикацию объявляет владелец ресурса (сегодня — реестр для репозитория), и
// доставляет её дважды: синхронно после своей фиксации и надёжной очередью, с
// ОДНОЙ версией из своей writer-транзакции. Снятие публикации приезжает только
// очередью. Значит служба получает намерения об одном объекте в произвольном
// порядке, с повторами, и обязана прийти к состоянию намерения со СТАРШЕЙ
// версией — какая бы доставка ни пришла последней.
//
// # Почему надгробие, а не только прямой факт
//
// Прямой факт снятием удаляется, и после этого запоздавшее открытие старшей
// версии нашло бы пустое место и легло бы заново: сравнивать было бы не с чем.
// Строка `kaname.public_read_publication` переживает снятие и помнит его версию —
// это и есть то, с чем сравнивается каждая следующая доставка.
//
// # Почему одним оператором
//
// «Прочитать версию, сравнить, записать» — чтение-и-действие (запрет #10): две
// доставки одного объекта прочли бы одну и ту же старую версию и применились бы
// обе. Здесь сравнение стоит в `WHERE` ветки `ON CONFLICT … DO UPDATE`: вторая
// доставка ждёт блокировку строки, после фиксации первой перечитывает условие
// против зафиксированной строки и не применяется, если не новее.
//
// Строка журнала кладётся ТОЙ ЖЕ транзакцией и ТОЛЬКО применившимся намерением,
// пока блокировка строки ещё держится, — поэтому порядок строк одного объекта в
// журнале совпадает с порядком версий владельца.
package public_read

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
)

// Publication — одно намерение владельца об анонимном чтении одного объекта.
type Publication struct {
	// ObjectType — тип в словаре МОДЕЛИ ПРАВ (`registry_repository`), как в
	// кортеже публикации: этим же именем назван прямой факт, который она ставит.
	ObjectType string
	ObjectID   string
	// Published — открывает намерение (true) или снимает (false).
	Published bool
	// Version — версия владельца. Нулевая — доставка без маркера: порядка она не
	// доказывает и хранится как '-infinity' (см. ApplyTx).
	Version time.Time
}

// Outcome — вердикт одного применения.
type Outcome struct {
	// Applied — намерение изменило состояние публикации и положило строку журнала.
	// false — доставка устарела либо повторяет применённое: делать нечего.
	Applied bool
}

// applySQL — сравнение и запись ОДНИМ оператором.
//
// # Правило применения
//
// Намерение с версией применяется, когда оно СТРОГО новее хранимого: повтор той же
// доставки (синхронная и очередная несут одно значение) не новее и ничего не
// меняет, запоздавшая старшая — тем более.
//
// Намерение БЕЗ версии ('-infinity') порядка не доказывает, и потому различается по
// направлению, в сторону отказа:
//
//   - СНЯТИЕ без версии применяется всегда: проглоченное за недоказанностью, оно
//     было бы стоящим лишним доступом. Версия хранимого при этом НЕ ОТСТУПАЕТ
//     (`greatest`): запоздавшая доставка того же открытия, что стояло, по-прежнему
//     не новее и ничего не открывает;
//   - ОТКРЫТИЕ без версии не перекрывает ничего, упорядоченного версией: оно
//     ложится только туда, где хранимое тоже без версии, либо где ничего нет.
//
// # Что возвращается
//
// Версия и направление ПОСЛЕ применения. Строка журнала обязана нести именно эту
// версию: у снятия без версии она равна хранимой, и только с ней проекция снимет
// факт, поставленный под этой версией.
const applySQL = `
INSERT INTO kaname.public_read_publication AS p
       (object_type, object_id, source_version, published, updated_at)
VALUES ($1, $2, $3::timestamptz, $4, now())
ON CONFLICT (object_type, object_id) DO UPDATE
   SET source_version = greatest(p.source_version, EXCLUDED.source_version),
       published      = EXCLUDED.published,
       updated_at     = now()
 WHERE p.source_version < EXCLUDED.source_version
    OR (EXCLUDED.source_version = '-infinity'
        AND (NOT EXCLUDED.published OR p.source_version = '-infinity'))
RETURNING p.source_version, p.published`

// ApplyTx применяет намерение владельца в транзакции вызывающего: сравнение версий
// и, если намерение новее, строку журнала публикации, из которой проекция
// складывает (или снимает) прямой факт `user:* #v_get` в той же фиксации.
//
// Отказ вызывающего откатывает и то и другое: состояние публикации и строка
// журнала фиксируются только вместе.
func ApplyTx(ctx context.Context, tx pgx.Tx, p Publication) (Outcome, error) {
	if tx == nil {
		return Outcome{}, fmt.Errorf("public_read: tx must not be nil")
	}
	if p.ObjectType == "" || p.ObjectID == "" {
		return Outcome{}, fmt.Errorf("public_read: publication without an object (%q, %q)", p.ObjectType, p.ObjectID)
	}
	var (
		version   pgtype.Timestamptz
		published bool
	)
	err := tx.QueryRow(ctx, applySQL, p.ObjectType, p.ObjectID, versionOf(p.Version), p.Published).
		Scan(&version, &published)
	if errors.Is(err, pgx.ErrNoRows) {
		// Условие применения не выполнилось: доставка не новее хранимого. Это
		// штатный исход повторной и запоздавшей доставки, а не отказ.
		return Outcome{}, nil
	}
	if err != nil {
		return Outcome{}, fmt.Errorf("public_read: apply publication: %w", err)
	}
	if err := fga_outbox.EmitPublicationTx(ctx, tx, published, p.ObjectType+":"+p.ObjectID, version); err != nil {
		return Outcome{}, err
	}
	return Outcome{Applied: true}, nil
}

// versionOf — нулевая версия уезжает как '-infinity', иначе — сама версия в UTC.
func versionOf(v time.Time) pgtype.Timestamptz {
	if v.IsZero() {
		return pgtype.Timestamptz{InfinityModifier: pgtype.NegativeInfinity, Valid: true}
	}
	return pgtype.Timestamptz{Time: v.UTC(), Valid: true}
}
