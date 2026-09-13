// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

// positionlostanswer_test.go — ЧИТАТЕЛЬ ОТВЕЧАЕТ на «позиция утрачена».
//
// # Почему без ответа отказ бесполезен, а полоса — хуже прежней
//
// Отказ, произведённый владельцем и не разобранный читателем, попадает в общую
// ветвь: «пожаловаться и повторить С ТОЙ ЖЕ ПОЗИЦИИ». На утраченной позиции этот
// повтор не пройдёт НИКОГДА — сколько бы ни ждать, ответ один и тот же, — то
// есть петля отзыва встаёт навсегда, и встаёт она молча для клиента: кэш
// вердиктов продолжает отвечать по правам, которых уже нет.
//
// Ответ края дёшев и безопасен, и он уже написан для двух других состояний
// (холодный старт и просроченное чтение): погасить кэш ЦЕЛИКОМ, закрыть ВСЕ
// открытые потоки, принять названную позицию за курсор. Радиус широкий потому,
// что имена пропущенных строк приезжали как раз тем чтением, которого не было.
//
// # Различающий признак пробы
//
// Срок неподтверждённого чтения здесь заведомо не истекает (`StaleAfter` — минута,
// часы не двигаются), поэтому сплошное закрытие потоков НЕ МОЖЕТ прийти из
// ветви просроченного чтения. Наблюдаемое закрытие — только из разбираемой
// ветви, и утверждение о нём не двусмысленно.
//
// Положительный контроль стоит рядом и в том же файле: ОБЫЧНЫЙ отказ на том же
// такте кэша не гасит, потоков не закрывает и курсора не двигает. Без него
// утверждение зеленело бы на читателе, гасящем всё на всякий отказ, — то есть на
// поведении, снимающем ровно ту границу, ради которой ветвь заводится.
package subjectchange_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/pkg/subjectchange"
)

// answerScript собирает читателя над сценарным источником и отдаёт средства
// наблюдения: сам источник, счётчик гашений кэша, реестр потоков и один такт.
func answerScript(t *testing.T, batches [][]subjectchange.SubjectChange, errs []error,
) (*subjectPoller, *int, *closerStub, func()) {
	t.Helper()
	p := &subjectPoller{batches: batches, errs: errs}
	c := &closerStub{}
	var flushes int
	w, err := subjectchange.New(subjectchange.Config{
		Poller: p, Flush: func() { flushes++ }, Interval: time.Second,
		Logger: slog.Default(), Closer: c, StaleAfter: time.Minute,
	})
	if err != nil {
		t.Fatalf("сборка читателя: %v", err)
	}
	return p, &flushes, c, func() { w.Poll(context.Background()) }
}

// TestPositionLostFlushesEverythingAndAdoptsTheNamedPosition — разбираемая ветвь.
func TestPositionLostFlushesEverythingAndAdoptsTheNamedPosition(t *testing.T) {
	p, flushes, closer, tick := answerScript(t,
		[][]subjectchange.SubjectChange{
			{},                     // такт 0 — праймящий: курсор := 0
			{{ID: 5, Subject: ""}}, // такт 1 — обычная порция: курсор := 5
			nil,                    // такт 2 — отказ ниже
			{},                     // такт 3 — наблюдаем усвоенный курсор
		},
		[]error{nil, nil, subjectchange.PositionLost(599), nil},
	)

	tick() // праймящий
	tick() // порция: гашение #1

	if *flushes != 1 {
		t.Fatalf("до отказа гашений %d, ожидалось 1 — сценарий не доехал до разбираемой ветви", *flushes)
	}
	_, sweepsBefore := closer.snapshot()
	if sweepsBefore != 0 {
		t.Fatalf("до отказа сплошных закрытий %d, ожидалось 0", sweepsBefore)
	}

	tick() // «позиция утрачена»

	if *flushes != 2 {
		t.Errorf("кэш вердиктов не погашен на утраченной позиции: гашений %d, ожидалось 2. "+
			"Пропущенные строки называли субъектов, которых читатель не узнает уже никогда, "+
			"поэтому радиус обязан быть сплошным", *flushes)
	}
	if _, sweeps := closer.snapshot(); sweeps != 1 {
		t.Errorf("открытые потоки не закрыты на утраченной позиции: сплошных закрытий %d, ожидалось 1. "+
			"Кэш отвечает на СЛЕДУЮЩИЙ запрос, а длинное соединение следующего запроса не делает", sweeps)
	}

	tick() // следующий перепрос обязан идти с НАЗВАННОЙ позиции

	if got := p.sinceAt(3); got != 599 {
		t.Errorf("перепрос после утраченной позиции пошёл с %d, ожидалось 599 — "+
			"повтор с прежнего курсора не прошёл бы НИКОГДА, и петля отзыва встала бы навсегда", got)
	}
}

// TestOrdinaryRefusalNeitherFlushesNorClosesNorMovesTheCursor — положительный
// контроль к пробе выше.
//
// Обычный отказ (владелец недоступен, границы ещё нет) означает «повтори позже»:
// прочитанного не потеряно, гасить нечего, а сдвиг курсора уничтожил бы задел,
// накопленный за время недоступности.
func TestOrdinaryRefusalNeitherFlushesNorClosesNorMovesTheCursor(t *testing.T) {
	p, flushes, closer, tick := answerScript(t,
		[][]subjectchange.SubjectChange{
			{},
			{{ID: 5, Subject: ""}},
			nil,
			{},
		},
		[]error{nil, nil, errors.New("connection refused"), nil},
	)

	tick() // праймящий
	tick() // порция: гашение #1
	tick() // обычный отказ

	if *flushes != 1 {
		t.Errorf("обычный отказ погасил кэш: гашений %d, ожидалось 1", *flushes)
	}
	if _, sweeps := closer.snapshot(); sweeps != 0 {
		t.Errorf("обычный отказ закрыл потоки сплошь: закрытий %d, ожидалось 0 — "+
			"срок неподтверждённого чтения не истёк", sweeps)
	}

	tick()

	if got := p.sinceAt(3); got != 5 {
		t.Errorf("обычный отказ сдвинул курсор: перепрос пошёл с %d, ожидалось 5 — "+
			"задел, накопленный за недоступность, обязан быть перечитан", got)
	}
}
