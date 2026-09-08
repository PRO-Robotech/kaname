// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// subject_change_service.go — read-side of subject_change_outbox.
// Exposes the outbox by ascending-id cursor for api-gateway authz-cache
// invalidation. Read-only; no mutation.
package service

import (
	"context"
	"errors"
	"fmt"
)

// SubjectChange — a row of kaname.subject_change_outbox, plain Go (no proto).
type SubjectChange struct {
	ID        int64
	SubjectID string
	Op        string
	// SubjectType — тип субъекта в словаре модели прав (`user` |
	// `service_account` | `group`). Пусто у строк, записанных до того, как
	// производители начали его проставлять.
	//
	// Едет наружу, потому что идентификатор БЕЗ типа субъекта не называет: пара
	// собирается только вместе, и вызывающий, получивший половину, не может ни
	// закрыть поток названного субъекта, ни сбросить его записи поимённо.
	SubjectType string
}

// ErrSubjectChangeNotSettled — граница журнала ЕЩЁ НЕ УСТОЯЛАСЬ: позиции нет.
//
// Не ошибка хранилища и не пустой журнал. Номер строки выдаётся счётчиком на
// вставке, а видимой она становится на фиксации, поэтому позицию можно назвать
// только за писателями, которые уже доистекли. Пока наблюдение их лишь
// ЗАПОМНИЛО, называть позицию нечем — а ноль вызывающий, усваивающий позицию на
// первом проходе, прочёл бы как «журнал кончается здесь» и сел бы в его начало.
//
// Состояние ХОЛОДНОГО СТАРТА, а не режим работы: признак подтверждённости
// монотонен и однажды подтвердившись не отзывается. Вызывающий переспрашивает на
// следующем такте; вечное молчание закрывает его собственный fail-closed.
var ErrSubjectChangeNotSettled = errors.New("subject change journal position is not settled yet")

// SubjectChangePositionLostError — КУРСОР НИЖЕ ПОЛА ЖУРНАЛА (задача #1712).
//
// Строки между курсором вызывающего и полом СНЯТЫ, и он их уже не получит.
//
// # Почему это отказ, а не тишина
//
// Чтение идёт окном `id > since AND id <= settled`: снятая строка в него просто
// не попадает, курсор переезжает через неё по последней прочитанной позиции, и
// «строк не было» становится НЕОТЛИЧИМО от «строки убрали». Полоса при этом
// fail-open by design — пропущенная строка означает непогашенный кэш вердиктов
// края, то есть неприменённый отзыв доступа, молча.
//
// Пока такого отказа не существовало, уборка журнала была невозможна не по
// предпочтению, а by construction: любой уборщик уносил бы отзывы у читателя
// из-под курсора. Этот отказ — недостававший предикат обнаружения пропуска.
//
// # Почему тип, а не значение-часовой
//
// Возобновимая позиция здесь НЕСУЩАЯ: без неё вызывающему некуда сесть — принять
// ноль значило бы проиграть журнал с начала, остаться на месте — получать тот же
// отказ вечно. Значение-часовой позиции не носит by construction.
//
// Не путать с [ErrSubjectChangeNotSettled]: тот говорит «переспроси на следующем
// такте», этот — «повтор не пройдёт никогда, пересядь». Советы противоположные.
type SubjectChangePositionLostError struct {
	// EarliestResumable — нижняя позиция, с которой возобновление ещё ничего не
	// теряет: «самая ранняя удержанная строка минус один», а у вычищенного
	// целиком журнала — сама граница устоявшегося.
	EarliestResumable int64
}

func (e *SubjectChangePositionLostError) Error() string {
	return fmt.Sprintf("subject change position is no longer resumable; earliest resumable position is %d",
		e.EarliestResumable)
}

// SubjectChangeReader — port: read side of subject_change_outbox.
type SubjectChangeReader interface {
	// PollSubjectChanges returns rows of the window `(sinceID, settled]` in
	// ascending order, at most limit rows, plus the position the caller may adopt
	// as its cursor — the settled boundary, narrowed to the last delivered row
	// when the page was cut by limit.
	//
	// Never "everything above the cursor" and never `MAX(id)`: a position issued
	// past a number still in flight loses that row silently and forever.
	// [ErrSubjectChangeNotSettled] when there is no settled position yet.
	// [SubjectChangePositionLostError] when sinceID sits BELOW the journal floor:
	// the rows between them have been removed and will never be delivered, so a
	// silent empty page would read as "nothing changed" — i.e. an unapplied
	// revocation, silently.
	PollSubjectChanges(ctx context.Context, sinceID int64, limit int32) (changes []SubjectChange, headID int64, err error)
}

// SubjectChangeService — read-only use-case that drains subject_change_outbox
// by ascending-id cursor. Used by InternalIAMService.PollSubjectChanges.
type SubjectChangeService struct{ reader SubjectChangeReader }

// NewSubjectChangeService constructs a SubjectChangeService backed by the
// given SubjectChangeReader port.
func NewSubjectChangeService(reader SubjectChangeReader) *SubjectChangeService {
	return &SubjectChangeService{reader: reader}
}

// PollSubjectChanges returns up to `limit` rows of the window `(sinceID, settled]`,
// ordered ascending. limit is clamped to [1, 1000]; zero or negative defaults to
// 256. Also returns the position a freshly started caller may seed its cursor
// with — the settled boundary, never `MAX(id)`.
func (s *SubjectChangeService) PollSubjectChanges(ctx context.Context, sinceID int64, limit int32) ([]SubjectChange, int64, error) {
	if limit <= 0 {
		limit = 256
	}
	if limit > 1000 {
		limit = 1000
	}
	return s.reader.PollSubjectChanges(ctx, sinceID, limit)
}
