// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

// orphan_mirror_sweep.go — обнаружение и починка строк зеркала ресурса,
// оставшихся БЕЗ РОДИТЕЛЯ (задача `PRO-Robotech/kacho#2051`).
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
// кластер. Поэтому берутся пункты 2–4 предиката: обнаружение, починка, проба.
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
// ЧТО ПОЧИНИМО ИЗНУТРИ СЛУЖБЫ, А ЧТО НЕТ — ГРАНИЦА НАЗВАНА, А НЕ ОБОЙДЕНА
//
// Зеркало держит ресурсы ЧУЖИХ владельцев (compute / vpc / loadbalancer): свои
// типы служба читает из собственных таблиц и в зеркало не кладёт. Значит
// родителя чужого ресурса знает ВЛАДЕЛЕЦ, а спросить его служба не может —
// она ЛИСТ графа вызовов: её зовут, она не зовёт никого из доменов, и обратный
// вызов замкнул бы граф. Ацикличность — несущее свойство, а не соглашение.
//
// Отсюда два РАЗНЫХ исхода, и смешивать их нельзя:
//
//	ПОЧИНИМО      цепь предков есть, колонки пусты → родитель выводится
//	              ТОЙ ЖЕ базой из `resource_parent_edge`. Это не догадка: цепь
//	              прислал сам владелец при регистрации;
//	НЕ ПОЧИНИМО   нет ни колонок, ни цепи → внутри службы родителя взять
//	              НЕОТКУДА. Такая строка НАЗЫВАЕТСЯ числом и координатой;
//	              приводит её к факту повторная регистрация владельцем.
//
// Проход, который «починил» бы вторую группу, выдумав родителя, был бы хуже
// отсутствующего: он раздал бы доступ по выдуманной вложенности.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПЕРЕПИСЬ ПЕЧАТАЕТ ЧЕТЫРЕ ЧИСЛА, А НЕ ОДНО
//
// Задача требовала двух: «строк зеркала N, из них без родителя M». Одно число
// скрывает ровно тот случай, ради которого проход заведён. Но и двух мало:
// «без родителя M» не отличает починенное от того, что служба починить не
// вправе, — а это разные действия оператора. Поэтому печатаются четыре:
//
//	строк зеркала N · без родителя M · починено цепью R · осталось владельцу M−R
//
// Ноль в третьем при ненулевом втором — законное состояние, а не поломка: оно
// означает, что все сироты пришли вовсе без цепи.

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
	// RepairableFromChain — цепь предков у строки ЕСТЬ, значит родителя можно
	// вывести той же базой. Ложь означает, что внутри службы его взять неоткуда.
	RepairableFromChain bool
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
	// ВСЕ ТРИ носителя родителя, с признаком починимости по цепи предков.
	ListOrphanMirrorRows(ctx context.Context, limit int) ([]OrphanMirrorRow, error)

	// RepairMirrorParentFromChain выводит колонки родителя из цепи предков ОДНОЙ
	// строки и записывает их. Идемпотентна: повтор на уже починенной строке
	// меняет ноль строк и возвращает repaired=false.
	//
	// Возвращает repaired=false и БЕЗ ошибки, когда выводить не из чего, — это
	// штатный исход для строки, пришедшей без цепи, а не отказ.
	RepairMirrorParentFromChain(ctx context.Context, objectType, objectID string) (repaired bool, err error)
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
	// Orphans — из них без родителя по всем трём носителям.
	Orphans int
	// Repaired — сколько починено выводом из цепи предков.
	Repaired int
	// LeftToOwner — сколько осталось владельцу: ни колонок, ни цепи, внутри
	// службы родителя взять неоткуда.
	LeftToOwner []OrphanMirrorRow
	// Truncated — упёрлись в потолок прогона, остаток берёт следующий.
	Truncated bool
}

// Census — перепись одной строкой. Печатается всегда, включая чистый прогон.
func (r OrphanMirrorResult) Census() string {
	return fmt.Sprintf(
		"перепись зеркала: строк %d, из них без родителя %d, починено цепью предков %d, "+
			"осталось владельцу %d",
		r.MirrorRows, r.Orphans, r.Repaired, len(r.LeftToOwner))
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
// Повтор безопасен: починенная строка в следующую перепись не попадает (у неё
// появился родитель), а непочинимая попадает снова и снова НАЗЫВАЕТСЯ — это не
// шум, а единственное место, где видно, что владелец ещё не перерегистрировал
// ресурс.
//
// Отказ починки ОДНОЙ строки не роняет остальные: он считается, называется и
// возвращается ошибкой в конце. Иначе одна неподатливая строка блокировала бы
// все последующие на каждом прогоне.
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

	var failures []string
	for _, row := range rows {
		if !row.RepairableFromChain {
			// Внутри службы родителя взять неоткуда — она лист графа. Строка
			// НАЗЫВАЕТСЯ, а не чинится выдуманным родителем.
			res.LeftToOwner = append(res.LeftToOwner, row)
			continue
		}
		repaired, rerr := s.store.RepairMirrorParentFromChain(ctx, row.ObjectType, row.ObjectID)
		if rerr != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", row, rerr))
			continue
		}
		if !repaired {
			// Цепь была на момент переписи и исчезла к моменту починки — гонка
			// со снятием регистрации. Строка уходит владельцу, а не считается
			// починенной: засчитать её значило бы соврать переписи.
			res.LeftToOwner = append(res.LeftToOwner, row)
			continue
		}
		res.Repaired++
	}

	s.logger.InfoContext(ctx, "orphan-mirror sweep: "+res.Census())
	for _, row := range res.LeftToOwner {
		s.logger.WarnContext(ctx,
			"orphan-mirror sweep: строка зеркала без родителя и без цепи предков — "+
				"внутри службы родителя взять неоткуда (она лист графа); строку приводит "+
				"к факту повторная регистрация ВЛАДЕЛЬЦЕМ",
			slog.String("object_type", row.ObjectType),
			slog.String("object_id", row.ObjectID))
	}
	if res.Truncated {
		s.logger.InfoContext(ctx, "orphan-mirror sweep: упёрлись в потолок прогона, остаток берёт следующий",
			slog.Int("max_rows", s.maxRows))
	}

	if len(failures) > 0 {
		return res, fmt.Errorf("orphan-mirror sweep: починка не удалась по %d строкам: %v",
			len(failures), failures)
	}
	return res, nil
}
