// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

// dangling_project_mirror_sweep.go — обнаружение строк зеркала ресурса, чей
// проект НАЗВАН и не резолвится (стадия S2 приёмки
// `non-empty-project-is-not-deleted.md`; задача продукта PRO-Robotech/kacho#1231).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ — ОСТАТОК, КОТОРЫЙ ОТКАЗ ПО НЕПУСТОТЕ НЕ ЗАКРЫВАЕТ ПО ПОСТРОЕНИЮ
//
// Удаление непустого проекта отвергается по строкам зеркала (S1). Но строка
// приходит к службе ПОСЛЕ коммита владельца — распределённой транзакции между
// двумя базами нет, — и у окна доставки две стороны: регистрация, обогнавшая
// удаление, ложится с родителем, которого уже нет; создание в только что
// удалённом проекте у владельца проходит из положительного кэша существования.
// В обоих случаях в зеркале остаётся строка с непустым `parent_project_id`,
// которому не отвечает ни одна строка `kaname.projects`.
//
// Такую строку не видит ни одна выдача (область не резолвится) и не назовёт
// ни один отказ (проекта, который она удерживала бы, нет). Без прохода она
// невидима — этот проход делает её ВИДИМОЙ: называет видом и идентификатором и
// печатает перепись на каждом старте.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ НЕ ПЕРЕСЕКАЕТСЯ С ДЕЙСТВУЮЩИМ ПРОХОДОМ ЗЕРКАЛА
//
// `orphan_mirror_sweep.go` берёт строки, у которых родитель не назван ВОВСЕ
// (обе колонки пусты), и чинит их из цепи предков. Здесь родитель назван —
// чинить нечего и нечем: правильного родителя знает только владелец.
// Предикаты взаимно исключающи по первому условию (`parent_project_id = ''`
// против `<> ''`), поэтому одну строку не назовут оба.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРОХОД НИЧЕГО НЕ УДАЛЯЕТ И РОДИТЕЛЯ НЕ ВЫДУМЫВАЕТ
//
// Родителя чужого ресурса знает владелец, а спросить его служба не может — она
// лист графа вызовов. Проход, «починивший» такую строку из цепи предков, раздал
// бы доступ по выдуманной вложенности; проход, снявший её, стёр бы единственное
// свидетельство того, что ресурс у владельца, возможно, жив. Оба исхода хуже
// строки, названной вслух. Решение по строке — за владельцем вида.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОТОЛОК: ПРИЗНАК ТОЛЬКО ПРИ ОСТАТКЕ, ЧИСЛО СИРОТ — ОТДЕЛЬНЫМ СЧЁТОМ
//
// Форма соседа здесь НЕ берётся: у него признак «потолок достигнут» стоит уже
// НА потолке при нулевом остатке, а «сирот» равно длине выборки (приёмка §0.2в,
// Н19). Здесь число сирот производит отдельный счёт тем же предикатом в том же
// снимке (`count(*) OVER ()`), а признак стоит только когда сирот больше, чем
// названо. От соседа берутся провязка, свой ключ замка и величина потолка.

import (
	"context"
	"fmt"
	"log/slog"
)

// DanglingProjectMirrorDefaultMaxRows — потолок прогона по умолчанию; та же
// величина, что у соседнего прохода зеркала.
const DanglingProjectMirrorDefaultMaxRows = OrphanMirrorDefaultMaxRows

// DanglingProjectMirrorRow — строка зеркала, чей проект назван и не резолвится.
type DanglingProjectMirrorRow struct {
	ObjectType      string
	ObjectID        string
	ParentProjectID string
}

// String — координата строки для текста находки.
func (r DanglingProjectMirrorRow) String() string { return r.ObjectType + ":" + r.ObjectID }

// DanglingProjectMirrorStore — узкий порт прохода. Реализуется pg-адаптером.
type DanglingProjectMirrorStore interface {
	// TryAcquireSingletonDanglingProjectMirrorLock берёт СЕССИОННЫЙ неблокирующий
	// pg_advisory_lock по СВОЕМУ известному ключу — отличному от ключей других
	// проходов старта: два разных прохода не вправе исключать друг друга.
	// ok=false ⇒ проход ведёт другой процесс ⇒ этот прогон пропускается.
	// Замыкание освобождения обязано быть вызвано.
	TryAcquireSingletonDanglingProjectMirrorLock(ctx context.Context) (ok bool, release func(context.Context), err error)

	// CountMirrorRows — сколько строк в зеркале ВСЕГО: знаменатель переписи.
	CountMirrorRows(ctx context.Context) (int, error)

	// ListDanglingProjectMirrorRows возвращает до `limit` строк с названным и
	// нерезолвящимся проектом И ТОЧНОЕ число таких строк в том же снимке.
	// Второе — не длина выборки: при потолке ниже числа сирот они различаются.
	ListDanglingProjectMirrorRows(ctx context.Context, limit int) (rows []DanglingProjectMirrorRow, total int, err error)
}

// DanglingProjectMirrorConfig — настройки прохода.
type DanglingProjectMirrorConfig struct {
	// MaxRowsPerRun ограничивает, сколько строк НАЗЫВАЕТСЯ за прогон.
	// ≤0 → DanglingProjectMirrorDefaultMaxRows. Счёт сирот потолком не ограничен.
	MaxRowsPerRun int
	// Logger — необязателен; nil → slog.Default().
	Logger *slog.Logger
}

// DanglingProjectMirrorResult — исход прогона. Перепись печатается ВСЕГДА,
// включая чистый прогон: «сирот ноль» обязано быть отличимо от «проход не
// состоялся».
type DanglingProjectMirrorResult struct {
	// Executed — этот ли прогон взял общий замок и вёл проход.
	Executed bool
	// MirrorRows — строк в зеркале ВСЕГО (знаменатель).
	MirrorRows int
	// Orphans — ТОЧНОЕ число строк с названным и нерезолвящимся проектом.
	Orphans int
	// Named — названные строки: не больше потолка прогона.
	Named []DanglingProjectMirrorRow
	// Truncated — сирот больше, чем названо: остаток берёт следующий прогон.
	Truncated bool
}

// Census — перепись одной строкой: обе величины и признак потолка.
func (r DanglingProjectMirrorResult) Census() string {
	s := fmt.Sprintf(
		"перепись зеркала по родителю-проекту: строк осмотрено %d · осиротевших %d · названо %d",
		r.MirrorRows, r.Orphans, len(r.Named))
	if r.Truncated {
		s += " · потолок достигнут, остаток берёт следующий прогон"
	}
	return s
}

// DanglingProjectMirrorSweeper — проход по строкам зеркала с несуществующим
// проектом.
type DanglingProjectMirrorSweeper struct {
	store   DanglingProjectMirrorStore
	maxRows int
	logger  *slog.Logger
}

// NewDanglingProjectMirrorSweeper собирает проход.
func NewDanglingProjectMirrorSweeper(store DanglingProjectMirrorStore, cfg DanglingProjectMirrorConfig) *DanglingProjectMirrorSweeper {
	maxRows := cfg.MaxRowsPerRun
	if maxRows <= 0 {
		maxRows = DanglingProjectMirrorDefaultMaxRows
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &DanglingProjectMirrorSweeper{store: store, maxRows: maxRows, logger: logger}
}

// RunOnce исполняет проход ровно один раз на кластер: читает, называет,
// печатает. Ничего не пишет, поэтому повтор безопасен by construction.
func (s *DanglingProjectMirrorSweeper) RunOnce(ctx context.Context) (DanglingProjectMirrorResult, error) {
	ok, release, err := s.store.TryAcquireSingletonDanglingProjectMirrorLock(ctx)
	if err != nil {
		return DanglingProjectMirrorResult{}, fmt.Errorf("dangling-project-mirror sweep: acquire singleton lock: %w", err)
	}
	if !ok {
		s.logger.InfoContext(ctx, "dangling-project-mirror sweep: singleton lock held by another process — skipping")
		return DanglingProjectMirrorResult{Executed: false}, nil
	}
	defer release(ctx)

	res := DanglingProjectMirrorResult{Executed: true}
	total, err := s.store.CountMirrorRows(ctx)
	if err != nil {
		return res, fmt.Errorf("dangling-project-mirror sweep: count mirror rows: %w", err)
	}
	res.MirrorRows = total

	rows, orphans, err := s.store.ListDanglingProjectMirrorRows(ctx, s.maxRows)
	if err != nil {
		return res, fmt.Errorf("dangling-project-mirror sweep: list dangling rows: %w", err)
	}
	res.Named = rows
	res.Orphans = orphans
	res.Truncated = orphans > len(rows)

	s.logger.InfoContext(ctx, "dangling-project-mirror sweep: "+res.Census())
	for _, row := range rows {
		s.logger.WarnContext(ctx,
			"dangling-project-mirror sweep: строка зеркала называет проект, которого нет, — "+
				"ресурс владельца пережил удаление проекта либо регистрация обогнала его; "+
				"решение по строке принимает ВЛАДЕЛЕЦ вида (снятие регистрации), служба ничего не удаляет",
			slog.String("object_type", row.ObjectType),
			slog.String("object_id", row.ObjectID),
			slog.String("parent_project_id", row.ParentProjectID))
	}
	return res, nil
}
