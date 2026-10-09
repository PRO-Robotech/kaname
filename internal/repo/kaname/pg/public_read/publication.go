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
//
// # Публикация ложится только на ТЕКУЩЕЕ воплощение объекта
//
// Идентификатор репозитория — его имя внутри реестра, и объект с тем же id
// создаётся заново после снятия прежнего. Версия публикации порядок двух
// воплощений не различает: запоздавшая публикация прежнего репозитория легла бы
// на новый. Поэтому намерение несёт поколение воплощения (`ObjectGeneration`), а
// применение судит его по голове объекта (`kaname.object_head`) в том же
// операторе (приёмка NTF-3, Р30 «Публикация для анонимного чтения»):
//
//   - голова — надгробие: применяется, если поколение воплощения строго новее
//     надгробия (публикация следующего воплощения, пришедшая раньше его
//     регистрации); снятое воплощение не публикуется ни при какой версии;
//   - голова живая: применяется, если поколение воплощения не старше границы
//     воплощения — поколения регистрации, начавшей его;
//   - головы нет: применяется (публикация раньше первой регистрации объекта).
//
// Строку головы оператор берёт замком `FOR SHARE`: снятие либо регистрация,
// меняющие голову, ждут фиксации публикации и видят её строку, а публикация,
// ждущая их, перечитывает голову после их фиксации.
//
// Снятие объекта уносит его публикацию целиком (`WithdrawTx`), а регистрация,
// начавшая воплощение, снимает публикацию прежнего воплощения
// (`DropStaleIncarnationTx`): после снятия порядок прежнего воплощения держит
// голова, а не строка публикации.
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
	// HeadType — тип того же объекта в словаре КАТАЛОГА (`registry.repositories`):
	// им ключуется голова объекта (`kaname.object_head`), с которой судится
	// воплощение.
	HeadType string
	// Published — открывает намерение (true) или снимает (false).
	Published bool
	// Version — версия владельца. Обязательна: намерение без версии порядка не
	// доказывает, и приём его не допускает.
	Version time.Time
	// ObjectGeneration — поколение объекта по счётчику владельца в транзакции
	// намерения: признак воплощения, на которое ложится публикация. Обязательно.
	ObjectGeneration int64
}

// Outcome — вердикт одного применения.
type Outcome struct {
	// Applied — намерение изменило состояние публикации и положило строку журнала.
	// false — REJECTED_STALE: доставка устарела, повторяет применённое либо
	// относится не к текущему воплощению объекта; делать нечего.
	Applied bool
}

// applySQL — суд воплощения, сравнение версий и запись ОДНИМ оператором.
//
// Версия применяется, когда она СТРОГО новее хранимой: повтор той же доставки
// (синхронная и очередная несут одно значение) не новее и ничего не меняет,
// запоздавшая старшая — тем более. Воплощение судится по голове (см. шапку
// пакета); строка, легшая на воплощение, помнит его поколение.
//
// Возвращаются версия и направление ПОСЛЕ применения: строка журнала обязана
// нести именно эту версию.
const applySQL = `
WITH head AS (
  SELECT h.generation, h.withdrawn, h.incarnation
    FROM kaname.object_head h
   WHERE h.object_type = $3 AND h.object_id = $2
     FOR SHARE
)
INSERT INTO kaname.public_read_publication AS p
       (object_type, object_id, source_version, published, object_generation, updated_at)
SELECT $1, $2, $4::timestamptz, $5, $6, now()
 WHERE NOT EXISTS (SELECT 1 FROM head)
    OR EXISTS (SELECT 1 FROM head
                WHERE (head.withdrawn AND $6 > head.generation)
                   OR (NOT head.withdrawn AND $6 >= head.incarnation))
ON CONFLICT (object_type, object_id) DO UPDATE
   SET source_version    = EXCLUDED.source_version,
       published         = EXCLUDED.published,
       object_generation = EXCLUDED.object_generation,
       updated_at        = now()
 WHERE p.source_version < EXCLUDED.source_version
RETURNING p.source_version, p.published`

// ApplyTx применяет намерение владельца в транзакции вызывающего: суд воплощения,
// сравнение версий и, если намерение применилось, строку журнала публикации, из
// которой проекция складывает (или снимает) прямой факт `user:* #v_get` в той же
// фиксации.
//
// Отказ вызывающего откатывает и то и другое: состояние публикации и строка
// журнала фиксируются только вместе.
func ApplyTx(ctx context.Context, tx pgx.Tx, p Publication) (Outcome, error) {
	if tx == nil {
		return Outcome{}, fmt.Errorf("public_read: tx must not be nil")
	}
	if p.ObjectType == "" || p.ObjectID == "" || p.HeadType == "" {
		return Outcome{}, fmt.Errorf("public_read: publication without an object (%q, %q, %q)", p.ObjectType, p.ObjectID, p.HeadType)
	}
	if p.Version.IsZero() {
		return Outcome{}, fmt.Errorf("public_read: publication of %s:%s without an owner version", p.ObjectType, p.ObjectID)
	}
	if p.ObjectGeneration <= 0 {
		return Outcome{}, fmt.Errorf("public_read: publication of %s:%s without an incarnation generation", p.ObjectType, p.ObjectID)
	}
	var (
		version   pgtype.Timestamptz
		published bool
	)
	err := tx.QueryRow(ctx, applySQL, p.ObjectType, p.ObjectID, p.HeadType,
		pgtype.Timestamptz{Time: p.Version.UTC(), Valid: true}, p.Published, p.ObjectGeneration).
		Scan(&version, &published)
	if errors.Is(err, pgx.ErrNoRows) {
		// Условие применения не выполнилось: доставка не новее хранимого либо не
		// к текущему воплощению. Это штатный исход REJECTED_STALE, а не отказ.
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

// withdrawSQL — снятие строки публикации объекта целиком; возвращает то, что
// стояло, чтобы журнал снял прямой факт под его версией.
const withdrawSQL = `
DELETE FROM kaname.public_read_publication
 WHERE object_type = $1 AND object_id = $2
RETURNING source_version, published`

// dropStaleSQL — снятие публикации прежнего воплощения: строки с поколением
// воплощения меньше границы текущего живого воплощения объекта.
const dropStaleSQL = `
DELETE FROM kaname.public_read_publication p
 USING kaname.object_head h
 WHERE p.object_type = $1 AND p.object_id = $2
   AND h.object_type = $3 AND h.object_id = $2
   AND NOT h.withdrawn AND p.object_generation < h.incarnation
RETURNING p.source_version, p.published`

// WithdrawTx снимает публикацию объекта вместе с объектом: строку публикации и,
// если она открывала, прямой факт `user:* #v_get` строкой журнала под её версией.
// Вызывается только применившимся снятием объекта, в его транзакции.
func WithdrawTx(ctx context.Context, tx pgx.Tx, objectType, objectID string) error {
	if tx == nil {
		return fmt.Errorf("public_read: tx must not be nil")
	}
	return dropRows(ctx, tx, objectType, objectID, withdrawSQL, objectType, objectID)
}

// DropStaleIncarnationTx снимает публикацию прежнего воплощения объекта: новое
// воплощение её не наследует. Вызывается применившейся регистрацией, в её
// транзакции, после приёма поколения; на живом воплощении без такой строки
// ничего не делает.
func DropStaleIncarnationTx(ctx context.Context, tx pgx.Tx, objectType, objectID, headType string) error {
	if tx == nil {
		return fmt.Errorf("public_read: tx must not be nil")
	}
	return dropRows(ctx, tx, objectType, objectID, dropStaleSQL, objectType, objectID, headType)
}

// dropRows исполняет снятие строк публикации и кладёт строку журнала снятия
// прямого факта для каждой снятой строки, которая открывала объект.
func dropRows(ctx context.Context, tx pgx.Tx, objectType, objectID, stmt string, args ...any) error {
	var (
		version   pgtype.Timestamptz
		published bool
	)
	err := tx.QueryRow(ctx, stmt, args...).Scan(&version, &published)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("public_read: withdraw publication of %s:%s: %w", objectType, objectID, err)
	}
	if !published {
		return nil
	}
	return fga_outbox.EmitPublicationTx(ctx, tx, false, objectType+":"+objectID, version)
}
