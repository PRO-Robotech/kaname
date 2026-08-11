// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package shadowverdict — форма E спрашивается РЯДОМ с движком и только
// сравнивается.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЭТО ДЕЛАЕТ И ЧЕГО НЕ ДЕЛАЕТ
//
// Делает: задаёт форме E тот же вопрос, что ушёл движку, сравнивает ответы и
// считает пару чисел — сколько сравнений и сколько расхождений.
//
// НЕ делает: не влияет на ответ вызывающему. Ни один исход теневого вызова — ни
// разрешение, ни отказ, ни ошибка, ни истёкший срок — не меняет того, что
// вернёт Check. Это и есть смысл фазы: ошибка формы E сегодня стоит записи в
// журнале, а не чужого доступа.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СОБСТВЕННЫЙ СРОК, А НЕ СРОК ЗАПРОСА
//
// Теневой вызов идёт на пути ЖИВОГО запроса. Отдать ему срок вызывающего значит
// разрешить сравнению задержать ответ, который от него не зависит: медленный
// теневой запрос превратился бы в медленный Check, то есть наблюдение изменило
// бы наблюдаемое. Срок здесь короткий и свой; его исчерпание — исход
// «не выполнилось», а не расхождение.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ОШИБКА — НЕ РАСХОЖДЕНИЕ И НЕ СОГЛАСИЕ
//
// Ошибка формы E означает, что ответа не получено. Засчитать её согласием —
// объявить сравнение состоявшимся там, где его не было, и «ноль расхождений»
// перестанет отличаться от «ничего не сравнили». Засчитать расхождением —
// утопить настоящие расхождения в шуме недоступной БД. Поэтому у исхода три
// корзины, и «не выполнилось» считается ОТДЕЛЬНО.
package shadowverdict

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// DefaultTimeout — срок одного теневого вызова.
//
// Величина выбрана из назначения, а не из вкуса: сравнение обязано быть дешевле
// самого решения, иначе оно меняет то, что измеряет. Ответ формы E на прямом
// вопросе — единичные миллисекунды (индексы по всем четырём источникам), и срок
// на порядок больше даёт запас, оставаясь незаметным для вызывающего.
const DefaultTimeout = 50 * time.Millisecond

// Asker — форма E. Узкий порт: сравнителю нужен ровно один вопрос.
//
// condCtx — доводы для условий на записях («сейчас», уровень уверенности
// подтверждения личности). Приезжают ОТ ВЫЗЫВАЮЩЕГО уже очищенными от значений,
// присланных клиентом: собрать их здесь второй раз значило бы завести второе
// место, знающее, чему можно верить, — и разойтись с первым в сторону лишнего
// доступа. Путь, у которого доводов нет, передаёт nil: условие тогда не
// выполнено, а не проигнорировано.
type Asker interface {
	Allowed(ctx context.Context, subject, objectType, objectID, relation string, condCtx map[string]any) (allowed bool, err error)
}

// Counters — то, что сравнение обязано уметь предъявить.
//
// «Ноль расхождений» без числа сравнений — утверждение ни о чём: оно одинаково
// верно и для согласия, и для выключенного сравнения.
type Counters struct {
	compared   atomic.Int64
	diverged   atomic.Int64
	unfinished atomic.Int64
}

// Snapshot — мгновенный слепок счётчиков.
type Snapshot struct {
	Compared   int64
	Diverged   int64
	Unfinished int64
}

// Read отдаёт слепок.
func (c *Counters) Read() Snapshot {
	return Snapshot{
		Compared:   c.compared.Load(),
		Diverged:   c.diverged.Load(),
		Unfinished: c.unfinished.Load(),
	}
}

// Comparator задаёт форме E вопрос, ушедший движку, и считает исход.
type Comparator struct {
	form    Asker
	timeout time.Duration
	logger  *slog.Logger
	counts  Counters
}

// New собирает сравнитель. nil-форма — законный вход: сравнение выключено, и
// вызовы становятся дешёвыми no-op.
func New(form Asker, logger *slog.Logger) *Comparator {
	if logger == nil {
		logger = slog.Default()
	}
	return &Comparator{form: form, timeout: DefaultTimeout, logger: logger}
}

// WithTimeout меняет срок теневого вызова (для проб).
func (c *Comparator) WithTimeout(d time.Duration) *Comparator {
	if d > 0 {
		c.timeout = d
	}
	return c
}

// Counters отдаёт счётчики.
func (c *Comparator) Counters() Snapshot { return c.counts.Read() }

// Compare задаёт вопрос форме E и сравнивает с вердиктом движка.
//
// Ничего не возвращает НАМЕРЕННО: у вызывающего не должно быть соблазна прочесть
// теневой исход и на него опереться. Пока движок жив, единственный законный
// потребитель этого сравнения — счётчики и журнал.
func (c *Comparator) Compare(ctx context.Context, engineAllowed bool, subject, objectType, objectID, relation string, condCtx map[string]any) {
	if c == nil || c.form == nil {
		return
	}
	// Срок СВОЙ: контекст вызывающего берётся только ради его отмены, но время
	// теневому вызову отпускается отдельное.
	sctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	formAllowed, err := c.form.Allowed(sctx, subject, objectType, objectID, relation, condCtx)
	if err != nil {
		// Ответа не получено — отдельная корзина. Ни согласие, ни расхождение.
		c.counts.unfinished.Add(1)
		c.logger.Warn("shadow verdict: не выполнилось",
			"err", err, "object_type", objectType, "relation", relation)
		return
	}
	c.counts.compared.Add(1)
	if formAllowed == engineAllowed {
		return
	}
	c.counts.diverged.Add(1)
	// Расхождение называется ПОИМЁННО: счётчик говорит «сколько», а разобрать
	// можно только зная, на каком вопросе.
	c.logger.Error("shadow verdict: РАСХОЖДЕНИЕ формы E с движком",
		"engine", engineAllowed, "form_e", formAllowed,
		"subject", subject, "object_type", objectType, "object_id", objectID, "relation", relation)
}
