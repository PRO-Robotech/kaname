// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

// orphan_mirror_sweep.go — обнаружение строк зеркала ресурса, оставшихся БЕЗ
// РОДИТЕЛЯ (задача `PRO-Robotech/kacho#2051`).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Строка `kaname.resource_mirror` с пустым родителем не матчится НИ ОДНОЙ
// выдачей: реконсайлер разворачивает выдачи по родителю и по меткам, а при
// пустом родителе область не совпадает ни с проектной, ни с аккаунтной. Ресурс
// остаётся с одним иерархическим кортежем, который в плоской модели сам по себе
// доступа не даёт, — **владелец своего ресурса не видит**. Наблюдалось на живом
// стенде: владелец сети не видел таблиц маршрутизации, от которых зависят все
// его подсети.
//
// Класс шире исторических данных: приём регистрации непустого родителя НЕ
// ТРЕБУЕТ (колонки объявлены `DEFAULT ''::text NOT NULL`), поэтому производитель,
// приславший пустого родителя, заводит такую строку и сегодня.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПРИЁМ НЕ НАЧИНАЕТ ОТВЕРГАТЬ ПУСТОГО РОДИТЕЛЯ
//
// Задача называла это первым исходом: отвергнуть — и класс невозможен by
// construction. Исход НЕ выбран, и причина не в цене: **контракт объявляет
// пустой родитель законным**, а кластерная область матчит такую строку
// безусловно. Отвергать значило бы сломать регистрацию ресурса, чей родитель —
// кластер. Поэтому берутся обнаружение и проба.
//
// ─────────────────────────────────────────────────────────────────────────────
// СИРОТСТВО — ПО ТРЁМ НОСИТЕЛЯМ СРАЗУ, а не по одной колонке
//
// Родителя несут ТРИ разных места, и у каждого свой потребитель:
//
//	parent_project_id      колонка зеркала   → вложенность проектной выдачи
//	parent_account_id      колонка зеркала   → вложенность аккаунтной выдачи
//	                                            (с резолвом project→account)
//	resource_parent_edge   таблица цепи      → представление решения о доступе
//
// Пустой ОДИН из них законен: ресурс, лежащий прямо в аккаунте, проектного
// родителя не имеет, и это не дефект. Сиротой строка становится, когда пусты
// ВСЕ ТРИ: тогда её не видит ни путь материализации, ни путь решения.
//
// Предикат по одной колонке дал бы находки на законных строках — и был бы снят
// первым же читателем как ложно срабатывающий.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПРОХОД НИЧЕГО НЕ ЧИНИТ — И ГДЕ ТЕПЕРЬ ЧИНИТСЯ ПОЧИНИМОЕ
//
// Зеркало держит ресурсы ЧУЖИХ владельцев (compute / vpc / loadbalancer), и
// родителя чужого ресурса знает ВЛАДЕЛЕЦ. Спросить его служба не может — она
// ЛИСТ графа вызовов, обратный вызов замкнул бы граф.
//
// Починимым случаем был один: колонки пусты, а цепь предков владелец прислал.
// Прежде его чинил ЭТОТ проход — вторым писателем зеркала. Проекцию объекта
// теперь пишет один производитель — триггер `resource_event` базы службы доступа
// (приёмка NTF-3, Р30 «Поколение и проекция — один производитель»; гейт
// `TestObjectProjectionHasOneProducer`), и вывод колонок из цепи живёт в нём:
// регистрация с пустыми колонками и непустой цепью получает ближайшего предка
// вида `project` и ближайшего вида `account` при приёме. Значит новая строка
// «с цепью, без колонок» не возникает, а лежащая до перевода приводится к факту
// СЛЕДУЮЩЕЙ регистрацией владельцем — тем же путём, что и строка вовсе без цепи.
//
// Поэтому проход только НАЗЫВАЕТ: каждую сироту — координатой, с признаком
// «цепь есть» отдельным числом. Проход, «починивший» строку записью мимо
// производителя, был бы вторым местом об одном предмете; проход, выдумавший
// родителя строке без цепи, раздал бы доступ по выдуманной вложенности.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПЕРЕПИСЬ ПЕЧАТАЕТ ТРИ ЧИСЛА, А НЕ ОДНО
//
//	строк зеркала N · без родителя M · из них с цепью предков C
//
// Без знаменателя «сирот ноль» неотличимо от пустого зеркала; без C не видно,
// сколько сирот приведёт к факту первая же регистрация, а сколько ждёт владельца
// вовсе без цепи.

import (
	"context"
	"fmt"
	"log/slog"
)

// OrphanMirrorDefaultMaxRows — потолок прогона по умолчанию.
const OrphanMirrorDefaultMaxRows = 1000

// OrphanMirrorRow — одна строка зеркала без родителя.
type OrphanMirrorRow struct {
	ObjectType string
	ObjectID   string
	// HasChain — цепь предков у строки ЕСТЬ: родителя из неё выведет следующая
	// регистрация владельцем. Ложь — цепи нет, и родителя приносит только он.
	HasChain bool
}

// String — координата строки для текста находки.
func (r OrphanMirrorRow) String() string { return r.ObjectType + ":" + r.ObjectID }

// OrphanMirrorStore — узкий порт прохода. Реализуется pg-адаптером.
type OrphanMirrorStore interface {
	// TryAcquireSingletonOrphanMirrorLock берёт СЕССИОННЫЙ неблокирующий
	// pg_advisory_lock по известному ключу. ok=false ⇒ проход ведёт другой
	// процесс ⇒ этот прогон пропускается. Замыкание освобождения обязано быть
	// вызвано.
	TryAcquireSingletonOrphanMirrorLock(ctx context.Context) (ok bool, release func(context.Context), err error)

	// CountMirrorRows — сколько строк в зеркале ВСЕГО.
	//
	// Знаменатель переписи. Без него «сирот ноль» неотличимо от «зеркало
	// пусто», а это разные ответы: первый — здоровье, второй — что registrar
	// не доехал ни разу.
	CountMirrorRows(ctx context.Context) (int, error)

	// ListOrphanMirrorRows возвращает до `limit` строк зеркала, у которых пусты
	// обе колонки родителя, с признаком наличия цепи предков.
	ListOrphanMirrorRows(ctx context.Context, limit int) ([]OrphanMirrorRow, error)
}

// OrphanMirrorConfig — настройки прохода.
type OrphanMirrorConfig struct {
	// MaxRowsPerRun ограничивает прогон. ≤0 → OrphanMirrorDefaultMaxRows.
	MaxRowsPerRun int
	// Logger — необязателен; nil → slog.Default().
	Logger *slog.Logger
}

// OrphanMirrorResult — исход прогона.
//
// Все четыре величины печатаются ВСЕГДА и по отдельности: «ноль починенного»
// неотличимо от «ноль осмотренного» и от «чинить было нечем», а это три разных
// ответа, требующих трёх разных действий.
type OrphanMirrorResult struct {
	// Executed — этот ли прогон взял общий замок и вёл проход.
	Executed bool
	// MirrorRows — строк в зеркале ВСЕГО (знаменатель).
	MirrorRows int
	// Orphans — из них без родителя (обе колонки пусты).
	Orphans int
	// WithChain — из сирот с цепью предков: родителя выведет следующая
	// регистрация владельцем.
	WithChain int
	// LeftToOwner — каждая сирота координатой: к факту строку приводит повторная
	// регистрация ВЛАДЕЛЬЦЕМ, внутри службы родителя записать некому.
	LeftToOwner []OrphanMirrorRow
	// Truncated — упёрлись в потолок прогона, остаток берёт следующий.
	Truncated bool
}

// Census — перепись одной строкой. Печатается всегда, включая чистый прогон.
func (r OrphanMirrorResult) Census() string {
	return fmt.Sprintf(
		"перепись зеркала: строк %d, из них без родителя %d, из них с цепью предков %d, "+
			"осталось владельцу %d",
		r.MirrorRows, r.Orphans, r.WithChain, len(r.LeftToOwner))
}

// OrphanMirrorSweeper — проход по зеркалу.
type OrphanMirrorSweeper struct {
	store   OrphanMirrorStore
	maxRows int
	logger  *slog.Logger
}

// NewOrphanMirrorSweeper собирает проход.
func NewOrphanMirrorSweeper(store OrphanMirrorStore, cfg OrphanMirrorConfig) *OrphanMirrorSweeper {
	maxRows := cfg.MaxRowsPerRun
	if maxRows <= 0 {
		maxRows = OrphanMirrorDefaultMaxRows
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &OrphanMirrorSweeper{store: store, maxRows: maxRows, logger: logger}
}

// RunOnce исполняет проход ровно один раз на кластер.
//
// Повтор безопасен: проход ничего не пишет, и сирота попадает в перепись снова
// и снова — это не шум, а единственное место, где видно, что владелец ещё не
// перерегистрировал ресурс.
func (s *OrphanMirrorSweeper) RunOnce(ctx context.Context) (OrphanMirrorResult, error) {
	ok, release, err := s.store.TryAcquireSingletonOrphanMirrorLock(ctx)
	if err != nil {
		return OrphanMirrorResult{}, fmt.Errorf("orphan-mirror sweep: acquire singleton lock: %w", err)
	}
	if !ok {
		s.logger.InfoContext(ctx, "orphan-mirror sweep: singleton lock held by another process — skipping")
		return OrphanMirrorResult{Executed: false}, nil
	}
	defer release(ctx)

	res := OrphanMirrorResult{Executed: true}

	// Знаменатель берётся ПЕРВЫМ и печатается даже при нуле сирот: без него
	// «сирот ноль» не отличить от пустого зеркала.
	total, err := s.store.CountMirrorRows(ctx)
	if err != nil {
		return res, fmt.Errorf("orphan-mirror sweep: count mirror rows: %w", err)
	}
	res.MirrorRows = total

	rows, err := s.store.ListOrphanMirrorRows(ctx, s.maxRows)
	if err != nil {
		return res, fmt.Errorf("orphan-mirror sweep: list orphan rows: %w", err)
	}
	res.Orphans = len(rows)
	res.Truncated = len(rows) >= s.maxRows
	for _, row := range rows {
		if row.HasChain {
			res.WithChain++
		}
		res.LeftToOwner = append(res.LeftToOwner, row)
	}

	s.logger.InfoContext(ctx, "orphan-mirror sweep: "+res.Census())
	for _, row := range res.LeftToOwner {
		s.logger.WarnContext(ctx,
			"orphan-mirror sweep: строка зеркала без родителя — внутри службы родителя "+
				"записать некому (она лист графа, проекцию пишет только приём); строку "+
				"приводит к факту повторная регистрация ВЛАДЕЛЬЦЕМ",
			slog.String("object_type", row.ObjectType),
			slog.String("object_id", row.ObjectID),
			slog.Bool("has_chain", row.HasChain))
	}
	if res.Truncated {
		s.logger.InfoContext(ctx, "orphan-mirror sweep: упёрлись в потолок прогона, остаток берёт следующий",
			slog.Int("max_rows", s.maxRows))
	}
	return res, nil
}
