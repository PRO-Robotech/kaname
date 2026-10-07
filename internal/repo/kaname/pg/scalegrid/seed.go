// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
)

// ПОСЕВЩИК ПРИБОРА ПОРЯДКОВ — КОНВЕЙЕРИЗОВАННАЯ ПОДАЧА ТОГО ЖЕ ПРИЁМА
//
// # Почему пачкой, а не по объекту
//
// Производитель (`resource_mirror.UpsertTx`) идёт по объекту за раз, обменом с
// БД на намерение. Критерий владельца назван МИЛЛИОНОМ объектов, и миллион
// обменов — свойство не машины, а кода. Поэтому посевщик подаёт ТО ЖЕ намерение
// пачками по [BatchObjects]: сценарий R7-1-01 утверждает число ОБМЕНОВ, а не
// время.
//
// # СТЕЙТМЕНТ НА ОБЪЕКТ — ОДИН, И ОН ПРОИЗВОДИТЕЛЯ
//
// Проекцию объекта (зеркало, цепь предков, голову) пишет один производитель —
// триггер `resource_event` базы службы доступа на вставке в приём
// `kaname.resource_event_intake` (приёмка NTF-3, Р30 «Поколение и проекция —
// один производитель»). Посевщик подаёт в пачку ту же вставку приёма
// (`resource_mirror.StmtIntake`) — объявленную ОДИН раз у производителя, а не
// её копию (#1890): копия текста расходилась бы молча. Перевод имён типов в
// словарь модели, условие приёма по живому каталогу и запись рёбер делает
// триггер — тот же для обоих путей, то есть расхождения в ПОТОКЕ УПРАВЛЕНИЯ
// между посевщиком и производителем больше нет.
//
// # ИСХОД КАЖДОГО ОБЪЕКТА ЧИТАЕТСЯ
//
// Вставка приёма возвращает исход, и [Seeder.Flush] читает его у КАЖДОГО
// объекта пачки: не `APPLIED` — отказ посадки, называющий объект и исход. Тип
// вне живого каталога либо непонятое звено цепи поэтому не дают «тихо
// посаженного нуля»: посадка отказывает, а не меряет другую популяцию.
//
// # ЦЕНА НАЗВАНА
//
// Посевщик годится ТОЛЬКО для посева свежих объектов поколением, которое он
// получает от вызывающего: повторная подача того же поколения — REJECTED_STALE
// и, значит, отказ посадки. ПЕРЕПИСЬ по каждой таблице (census.go) остаётся
// свидетельством того, что условие замера создано.

// BatchObjects — сколько объектов уходит в БД одним обменом.
//
// 2000 — не круглое число ради красоты: при нём стоимость на объект уже вышла
// на полку (0.105 мс), а размер пачки ещё не заставляет драйвер держать в
// памяти ответы на десятки тысяч стейтментов. Величина названа здесь, потому
// что от неё зависит утверждение сценария R7-1-01 о числе обменов.
const BatchObjects = 2000

// MirrorRow — объект зеркала вместе с его цепью предков.
//
// Форма повторяет `resource_mirror.Row` намеренно: посевщик обязан принимать
// ровно то, что принимает производитель.
type MirrorRow struct {
	// ObjectType — тип в словаре КАТАЛОГА (`registry.repositories`): им назван
	// `resource_mirror.object_type`.
	ObjectType string
	ObjectID   string
	// ParentProjectID/ParentAccountID — две колонки зеркала.
	ParentProjectID string
	ParentAccountID string
	Labels          map[string]string
	// ParentChain — цепь предков формой `"<type>:<id>"`, ближайший первым.
	// Типы приезжают уже словарём МОДЕЛИ, как их шлёт владелец ресурса.
	ParentChain []string
	// Generation — поколение объекта у владельца. Обязательно (`> 0`): приёма
	// без поколения нет.
	Generation int64
}

// Seeder — конвейеризованная посадка. Считает СВОЮ работу: обмены и стейтменты.
//
// Считает затем, что сценарий R7-1-01 утверждает ОБМЕН, а не время: «посадка
// миллиона за 15 минут» — свойство машины и на другой машине ложно, а «посадка
// миллиона не делает миллион обменов» — свойство кода и верно везде.
type Seeder struct {
	tx        pgx.Tx
	batch     *pgx.Batch
	batchSize int
	// intakes — для каждого стейтмента пачки: вставка ли это приёма (её исход
	// читается) либо сырой стейтмент [Seeder.QueueRaw] (читается только отказ).
	// objectRefs — объект каждой вставки приёма, для текста отказа.
	intakes    []bool
	objectRefs []string

	// exchanges — обменов с БД (отправок пачки), statements — стейтментов в них.
	exchanges  int64
	statements int64
	// objects — объектов зеркала, поданных этим посевщиком.
	objects int64
	// pendingObjects — объектов, накопленных в НЕотправленной пачке.
	//
	// Считаются ОБЪЕКТЫ, а не стейтменты, и это не педантизм: у объектов цепи
	// разной длины (лист несёт три предка, его дед — одного), поэтому порог,
	// выраженный в стейтментах, срабатывает на РАЗНОМ числе объектов и на
	// коротких цепях не срабатывает вовсе. Первая редакция считала стейтменты и
	// отправила миллион одним обменом — то есть накопила бы в памяти драйвера
	// ответы на шесть миллионов стейтментов.
	pendingObjects int
}

// NewSeeder — посевщик поверх открытой транзакции.
func NewSeeder(tx pgx.Tx) *Seeder {
	return &Seeder{tx: tx, batch: &pgx.Batch{}, batchSize: BatchObjects}
}

// Exchanges — обменов с БД. Свойство КОДА, ради которого сценарий и написан.
func (s *Seeder) Exchanges() int64 { return s.exchanges }

// Statements — стейтментов подано.
func (s *Seeder) Statements() int64 { return s.statements }

// Objects — объектов зеркала подано.
func (s *Seeder) Objects() int64 { return s.objects }

// Queue — поставить объект зеркала в очередь: ОДНУ вставку приёма
// производителя (`resource_mirror.StmtIntake`) с той же формой параметров,
// какой её зовёт `resource_mirror.UpsertTx`.
func (s *Seeder) Queue(ctx context.Context, row MirrorRow) error {
	if row.Generation <= 0 {
		return fmt.Errorf("scalegrid: поколение %d объекта %s:%s не положительно — приёма без поколения нет",
			row.Generation, row.ObjectType, row.ObjectID)
	}
	labels := row.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	payload, err := json.Marshal(labels)
	if err != nil {
		return fmt.Errorf("scalegrid: сериализация меток: %w", err)
	}
	chain := row.ParentChain
	if chain == nil {
		chain = []string{}
	}
	s.batch.Queue(resource_mirror.StmtIntake,
		resource_mirror.ChangeRegister, row.ObjectType, row.ObjectID, row.Generation,
		row.ParentProjectID, row.ParentAccountID, payload, chain)
	s.intakes = append(s.intakes, true)
	s.objectRefs = append(s.objectRefs, row.ObjectType+":"+row.ObjectID)

	s.objects++
	s.pendingObjects++
	if s.pendingObjects >= s.batchSize {
		return s.Flush(ctx)
	}
	return nil
}

// QueueRaw — произвольный стейтмент в ту же пачку.
//
// Нужен для того, что производителя зеркала не касается вовсе: выдачи, роли,
// членства, факты. Для НИХ форму задаёт схема, а не производитель, поэтому
// сверка (2) на них не распространяется — и это сказано здесь, а не
// подразумевается.
func (s *Seeder) QueueRaw(ctx context.Context, sql string, args ...any) error {
	s.batch.Queue(sql, args...)
	s.intakes = append(s.intakes, false)
	s.objectRefs = append(s.objectRefs, "")
	if s.batch.Len() >= s.batchSize {
		return s.Flush(ctx)
	}
	return nil
}

// Flush — отправить накопленное ОДНИМ обменом.
func (s *Seeder) Flush(ctx context.Context) error {
	n := s.batch.Len()
	if n == 0 {
		return nil
	}
	br := s.tx.SendBatch(ctx, s.batch)
	s.exchanges++
	s.statements += int64(n)
	var firstErr error
	for i := 0; i < n; i++ {
		if !s.intakes[i] {
			if _, err := br.Exec(); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("scalegrid: стейтмент %d из пачки: %w", i+1, err)
			}
			continue
		}
		var outcome, refused string
		var unchanged bool
		if err := br.QueryRow().Scan(&outcome, &unchanged, &refused); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("scalegrid: приём %s (стейтмент %d из пачки): %w", s.objectRefs[i], i+1, err)
			}
			continue
		}
		if outcome != resource_mirror.OutcomeApplied && firstErr == nil {
			firstErr = fmt.Errorf("scalegrid: приём %s не применён: исход %s %s — посадка не создала условия замера",
				s.objectRefs[i], outcome, refused)
		}
	}
	if err := br.Close(); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("scalegrid: закрытие пачки: %w", err)
	}
	s.batch = &pgx.Batch{}
	s.intakes = s.intakes[:0]
	s.objectRefs = s.objectRefs[:0]
	s.pendingObjects = 0
	return firstErr
}
