// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

// repoerrlog.go — запись ПРИЧИНЫ отказа хранилища в журнал сервера.
//
// # Зачем отдельный глагол рядом с MapRepoErr
//
// Соседний файл обещает: «Detail stays in the error chain for logs». Обещание
// держится, только если у цепочки есть ЧИТАТЕЛЬ. Читателя не было: логгера нет
// ни у хранилища, ни у use-case пределов, а журнала доступа gRPC у сервиса нет
// вовсе — исход попадал в счётчик и больше никуда. Отказ на каждом подъёме
// каждого домена приходилось разбирать без единой строки о причине (kacho#666).
//
// Решение живёт ЗДЕСЬ, а не копией у каждого вызывающего, потому что это
// решение, а не механика: какие исходы называть журналу — вопрос, у которого
// обязан быть один ответ, иначе домены разойдутся в том, что считается заметным.

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"runtime"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// LogMappedErr называет журналу причину отказа, чей текст на проводе её НЕ
// несёт, и возвращает переданный статус без изменений.
//
// # Почему перевод приходит СНАРУЖИ, а решение остаётся ЗДЕСЬ
//
// Переводчик у домена бывает свой: `sa_keys` отвечает «internal SA key error»,
// `user_tokens` — «internal user token error», и эти тексты часть контракта, а
// не стиль. Подменить их общим переводом значило бы сменить контракт двадцати
// пяти мест мимо приёмки. А вот ВОПРОС «какие исходы называть журналу» ответа
// на домен не имеет: разойдясь в нём, домены разойдутся в том, что считается
// заметным, — поэтому он решается тут и только тут.
//
// # Какие исходы пишутся и почему не все
//
// Пишутся ровно те, чьё сообщение на проводе причины НЕ несёт:
//
//   - `INTERNAL` — текст фиксирован by construction, иначе наружу уехал бы
//     текст драйвера;
//   - `UNAVAILABLE` — текст тоже фиксирован, по той же причине: цепочка ведёт к
//     драйверу. Подсистему текст не называет: признак ставит и база, и сосед, и
//     гейт прав.
//
// Остальные отказы называют свою причину САМИ и адресованы вызывающему: «Project
// %s not found», «Illegal argument …». Дублировать их в журнале значило бы
// писать строку на каждое обычное обращение арендатора — и та единственная,
// ради которой журнал и читают, утонула бы среди них. Заметность, введённая
// таким способом, уничтожается тем же средством, которым вводится.
//
// # Что пишется
//
// Полоса (`op`), полная цепочка ошибки (там же код состояния, который мост
// SQLSTATE оставляет намеренно) и КОНКРЕТНЫЙ ТИП ошибки. Тип назван отдельно,
// потому что отказ, не несущий строки состояния вовсе (не дозвонились до базы),
// цепочкой не отличим от прочих, а типом — отличим сразу.
//
// Сообщение подсистемы НЕ называет — её называет `op`. Прежде здесь стояло
// «limit read failed»: единственным вызывающим был домен пределов, и текст был
// верен. Став общим, он лгал бы про всякого следующего — тот же класс, который
// соседний файл называет у текста `UNAVAILABLE`.
//
// Журнал — серверный, на провод из него не идёт ничего: возвращаемый статус
// собирает вызывающий, и он остаётся единственным местом перевода.
func LogMappedErr(ctx context.Context, logger *slog.Logger, op string, err, gerr error) error {
	if err == nil || logger == nil {
		return gerr
	}
	switch status.Code(gerr) {
	case codes.Internal:
		logger.ErrorContext(ctx, "repository call failed",
			slog.String("op", op),
			slog.String("err", err.Error()),
			slog.String("err_type", fmt.Sprintf("%T", err)))
	case codes.Unavailable:
		logger.WarnContext(ctx, "repository call unavailable",
			slog.String("op", op),
			slog.String("err", err.Error()),
			slog.String("err_type", fmt.Sprintf("%T", err)))
	}
	return gerr
}

// unclassifiedMsg — сообщение записи о неразобранном отказе хранилища.
// Постоянное, чтобы запись находилась поиском по журналу одной строкой.
const unclassifiedMsg = "repository error is not classified"

// chainDepthLimit — сколько звеньев цепочки называет запись. Цепочка строится
// обёртками вызывающих и на деле короче десятка; предел нужен лишь затем, чтобы
// чужой тип с самоссылающимся `Unwrap` не превратил запись в бесконечный обход.
const chainDepthLimit = 32

// journalUnclassified называет журналу СТРУКТУРУ отказа, который не опознала
// ни одна ветка [MapRepoErr] (kaname#662).
//
// # Почему здесь, а не у восьмидесяти четырёх вызывающих
//
// Неразобранный отказ на проводе — `internal error`, и других читателей у него
// нет: логгера нет ни у хранилища, ни у большинства use-case. До этой записи
// 500 на стенде разбирали без единой строки о причине. Вопрос «писать ли»
// ответа на домен не имеет, поэтому решается в переводчике, а не копией у
// каждого вызывающего — как и у [LogMappedErr].
//
// # Что пишется — и почему не текст
//
// Текст цепочки — это текст драйвера и обёрток вызывающего, а они несут
// значения арендатора: адрес почты в обёртке, введённое значение в «invalid
// input syntax», идентификаторы. Журнал читает оператор, и такой текст в нём —
// утечка данных арендатора в чужую зону доступа. Поэтому запись несёт только
// то, что задаёт КОД, а не данные:
//
//   - `site`, `at` — функция и файл:строка вызывающего переводчик;
//   - `err_type` — конкретный тип ошибки;
//   - `err_chain` — типы всех звеньев цепочки по порядку обёртки (ветвление
//     `errors.Join` — в квадратных скобках): «не дозвонились», «не просканировали»
//     и «отказала база» различаются типом сразу;
//   - `sqlstate` — код состояния, если звено его несёт (метод `SQLState()`,
//     форма `pgconn.PgError`; пакет драйвера здесь не импортируется — слой
//     переводчика от драйвера свободен). Поле пишется, только когда код есть:
//     пустое значение читалось бы как «код есть и он пуст».
//
// Уровень — ERROR: неразобранный отказ — всегда дефект службы, не арендатора.
// Журнал — общий для процесса (`slog.Default`, задан композиционным корнем),
// берётся в момент записи, а не при сборке пакета. Контекста вызова у записи
// нет: у [MapRepoErr] его нет в подписи, а обработчик журнала службы (JSON
// фундамента) из контекста ничего не читает.
//
// # Когда запись молчит
//
// Отказ, поданный в обёртке [contextEnded], пришёл после конца контекста
// вызова: [MapRepoErrAt] отвечает на него недоступностью, это конец срока, а не
// поломка, и записи уровня ERROR о нём нет.
func journalUnclassified(err error) {
	var ended *contextEnded
	if stderrors.As(err, &ended) {
		return
	}
	attrs := make([]any, 0, 5)
	if site, at, ok := mapperCaller(); ok {
		attrs = append(attrs, slog.String("site", site), slog.String("at", at))
	}
	attrs = append(attrs,
		slog.String("err_type", fmt.Sprintf("%T", err)),
		slog.String("err_chain", errChainShape(err, 0)))
	var coded interface{ SQLState() string }
	if stderrors.As(err, &coded) {
		if state := coded.SQLState(); state != "" {
			attrs = append(attrs, slog.String("sqlstate", state))
		}
	}
	slog.Default().Error(unclassifiedMsg, attrs...)
}

// mapperCaller — первая рамка стека вне переводчика: тот, кто позвал
// [MapRepoErr] либо [MapRepoErrAt]. Рамки отсеиваются по имени функции, а не
// числом пропуска: число пропуска ломается встраиванием и любой новой
// промежуточной функцией молча.
//
// Путь пакета не выписан литералом, а берётся из собственной рамки: литерал
// пережил бы переезд пакета и перестал бы отсеивать что-либо, не покраснев.
func mapperCaller() (site, at string, ok bool) {
	var pcs [8]uintptr
	n := runtime.Callers(1, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	self, more := frames.Next()
	pkg := strings.TrimSuffix(self.Function, "mapperCaller")
	for more {
		var f runtime.Frame
		f, more = frames.Next()
		if f.Function == "" {
			return "", "", false
		}
		if !isMapperFrame(pkg, f.Function) {
			return f.Function, fmt.Sprintf("%s:%d", filepath.Base(f.File), f.Line), true
		}
	}
	return "", "", false
}

// mapperFrames — функции переводчика, чьи рамки лежат между записью и её
// вызывающим.
var mapperFrames = [...]string{"MapRepoErr", "MapRepoErrAt", "journalUnclassified"}

// isMapperFrame — принадлежит ли рамка переводчику; pkg — путь пакета с
// завершающей точкой.
func isMapperFrame(pkg, fn string) bool {
	for _, name := range mapperFrames {
		if fn == pkg+name {
			return true
		}
	}
	return false
}

// errChainShape — типы звеньев цепочки по порядку обёртки. Текст звеньев не
// читается вовсе: ни `Error()`, ни поля.
func errChainShape(err error, depth int) string {
	if err == nil {
		return "<nil>"
	}
	if depth >= chainDepthLimit {
		return "…"
	}
	name := fmt.Sprintf("%T", err)
	switch u := err.(type) {
	case interface{ Unwrap() []error }:
		inner := u.Unwrap()
		parts := make([]string, 0, len(inner))
		for _, e := range inner {
			parts = append(parts, errChainShape(e, depth+1))
		}
		return name + " > [" + strings.Join(parts, " | ") + "]"
	case interface{ Unwrap() error }:
		if next := u.Unwrap(); next != nil {
			return name + " > " + errChainShape(next, depth+1)
		}
	}
	return name
}
