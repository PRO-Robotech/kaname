// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// subject_change_repo.go — pgxpool adapter implementing service.SubjectChangeReader.
// Drains kacho_iam.subject_change_outbox for the InternalIAMService.PollSubjectChanges
// use-case. Read-only; no mutation.
//
// # Позиция ДОЕЗЖАЕТ по границе устоявшегося, а не по голому номеру (kacho#1374)
//
// Номер строки выдаёт счётчик на ВСТАВКЕ (умолчание колонки), а видимой она
// становится на ФИКСАЦИИ. Выдачу здесь ничто не сериализует — в отличие от
// `kacho_iam.limits`, где ревизию штампует триггер под транзакционной
// блокировкой, держащейся до коммита, — поэтому порядок номеров и порядок
// фиксаций НЕЗАВИСИМЫ.
//
// Потребитель (`pkg/subjectchange`.Watcher) хранит курсор между проходами и
// двигает его по прочитанным строкам. Отдай ему чтение строку с бо́льшим
// номером, пока меньший в полёте, — и меньшая не вернётся НИКОГДА: перечитывание
// идёт строго «больше курсора», пропуска в нумерации потребитель не видит, и
// сходиться тут нечему. Цена названа предметом журнала: это оповещение о том,
// что вердикты по субъекту пора считать заново, значит недоехавшая строка
// означает доступ, оставшийся действующим до следующего события по ТОМУ ЖЕ
// субъекту, — а его может не быть.
//
// Гарантия и её ЦЕНА объявлены один раз —
// `docs/architecture/journal-position-settled-watermark.md`; наблюдатель в дереве
// ОДИН и лежит в фундаменте ([subscription.Watermark]), поэтому здесь он берётся,
// а не пишется заново: два наблюдения одного класса разошлись бы молча.
package pg

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/pkg/subscription"

	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// Имена журнала — КОНСТАНТЫ этого пакета, а не строки, пришедшие снаружи:
// наблюдение подставляет их в текст запроса и не экранирует.
const (
	subjectChangeTable    = "kacho_iam.subject_change_outbox"
	subjectChangePosition = "id"
)

// SubjectChangeRepo — pgxpool adapter for service.SubjectChangeReader.
type SubjectChangeRepo struct {
	pool *pgxpool.Pool

	// settled — наблюдатель границы устоявшегося, ОДИН на процесс: граница есть
	// свойство ЖУРНАЛА, а не читателя, поэтому параллельные проходы не заводят
	// параллельных наблюдений, а складываются в одно — и подтверждают его чаще.
	settled *subscription.Watermark
}

// NewSubjectChangeRepo constructs a SubjectChangeRepo backed by pool.
//
// Журнал процесса НАЗЫВАЕТСЯ вызывающим, а не берётся умолчанием: удержание
// границы незавершившимся писателем — единственное состояние, в котором чтение
// молчит при живых событиях, и без жалобы оно неотличимо от «событий нет».
// Ноль резолвится в [slog.Default].
func NewSubjectChangeRepo(pool *pgxpool.Pool, log *slog.Logger) *SubjectChangeRepo {
	return &SubjectChangeRepo{
		pool:    pool,
		settled: subscription.NewWatermark(subjectChangeTable, subjectChangePosition, log),
	}
}

// Compile-time guard: SubjectChangeRepo must implement service.SubjectChangeReader.
var _ service.SubjectChangeReader = (*SubjectChangeRepo)(nil)

// PollSubjectChanges returns rows of the window `(sinceID, settled]` in ascending
// order, at most limit rows, plus the position the caller may adopt.
//
// # Позиция — ГРАНИЦА УСТОЯВШЕГОСЯ, урезанная до последней строки полной страницы
//
// Прежде отдавался `MAX(id)` по всей таблице, и это была потеря ДВУМЯ полосами
// сразу: курсор перепрыгивал и через номер писателя в полёте, и — при полной
// странице — через непрочитанный хвост окна. Теперь отдаётся то, за что прыгать
// безопасно by construction: каждый номер ≤ позиции либо уже видим, либо не
// появится никогда, и ни одна строка окна за ней не осталась непрочитанной.
//
// # Холодный старт отвечает ОТКАЗОМ, а не нулём
//
// Ноль границы означает «позиции ещё нет», и от «журнал пуст» он неотличим
// ([subscription.Watermark.Established] разделяет их, само значение — нет).
// Отдай мы такой ноль позицией — потребитель, усваивающий её на первом проходе
// вместо истории, сел бы в НАЧАЛО журнала и погасил бы кэш по всякому субъекту,
// когда-либо менявшемуся. Поэтому неустоявшаяся граница — явный отказ
// [service.ErrSubjectChangeNotSettled]; вызывающий переспросит на следующем такте.
//
// Признак МОНОТОНЕН: подтвердившись однажды, он не отзывается, — значит отказ
// есть состояние холодного старта, а не режим работы. Ровно так же отвечает
// вторая полоса того же механизма — поток подписки (`subscription.Server.serve`),
// и это не совпадение: полосы одного механизма обязаны сходиться между собой.
func (r *SubjectChangeRepo) PollSubjectChanges(ctx context.Context, sinceID int64, limit int32) ([]service.SubjectChange, int64, error) {
	// Наблюдение идёт ДО чтения: окно обязано быть закрыто сверху уже к моменту
	// запроса строк, иначе в него попадёт номер, за которым появится меньший.
	if err := r.settled.Advance(ctx, r.pool); err != nil {
		return nil, 0, fmt.Errorf("settled watermark of subject_change_outbox: %w", err)
	}
	if !r.settled.Established() {
		return nil, 0, service.ErrSubjectChangeNotSettled
	}
	settled := r.settled.Settled()
	if settled <= sinceID {
		// Отдавать нечего, и позиция НЕ двигается: назвать здесь границу значило
		// бы откатить курсор потребителя назад, когда он ушёл вперёд нас.
		return nil, sinceID, nil
	}

	// Тип субъекта живёт в `payload`, а не колонкой: полосе сброса кэша он был не
	// нужен, и колонки под него не завели. Достаётся он тем же чтением, чтобы у
	// перепроса и у толчка имя субъекта собиралось из ОДНОГО источника — иначе
	// две полосы об одном предмете разошлись бы молча.
	rows, err := r.pool.Query(ctx,
		`SELECT id, subject_id, op, COALESCE(payload->>'subject_type', '')
		   FROM kacho_iam.subject_change_outbox
		  WHERE id > $1 AND id <= $2
		  ORDER BY id ASC
		  LIMIT $3`,
		sinceID, settled, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("poll subject_change_outbox: %w", err)
	}
	defer rows.Close()

	var changes []service.SubjectChange
	for rows.Next() {
		var c service.SubjectChange
		if err := rows.Scan(&c.ID, &c.SubjectID, &c.Op, &c.SubjectType); err != nil {
			return nil, 0, fmt.Errorf("scan subject_change: %w", err)
		}
		changes = append(changes, c)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate subject_change: %w", err)
	}

	// Позиция УРЕЗАЕТСЯ до последней строки ПОЛНОЙ страницы.
	//
	// Неполная страница означает, что окно `(sinceID, settled]` вычитано целиком,
	// и отдать границу безопасно. Полная — что чтение упёрлось в предел, и за её
	// последней строкой в том же окне остались НЕПРОЧИТАННЫЕ; назвать тогда
	// границу значило бы перепрыгнуть через них.
	headID := settled
	if limit > 0 && len(changes) >= int(limit) {
		headID = changes[len(changes)-1].ID
	}

	return changes, headID, nil
}
