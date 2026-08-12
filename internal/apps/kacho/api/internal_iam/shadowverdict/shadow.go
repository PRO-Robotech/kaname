// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package shadowverdict — форма E спрашивается РЯДОМ с движком и только
// сравнивается.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЭТО ДЕЛАЕТ И ЧЕГО НЕ ДЕЛАЕТ
//
// Делает: задаёт форме E те же вопросы, что уходят движку — прямой вердикт,
// перечисление объектов, перечисление субъектов, разворот отношений, — сравнивает
// ответы и считает четыре числа: сколько решений, сколько сравнений, сколько
// расхождений, сколько «не выполнилось». Первое из них — знаменатель: без него
// «сравнений тысяча» не отвечает, какая это доля.
//
// Вопрос уходит форме E ДО того, как ответил движок. Сравнение, начатое после
// ответа, происходит ровно там, где ответ пришёл, — и молчит там, где движок
// ответил из кэша или не ответил вовсе, то есть на самом частом пути.
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
	"sort"
	"strings"
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

// CompareSetLimit — потолок множества, которое сравнение берётся сверить ЦЕЛИКОМ.
//
// Перечисление сравнимо только как множество: две страницы, снятые разными
// курсорами, совпадать не обязаны, и сверять их поэлементно значило бы объявлять
// расхождением разный порядок обхода. Значит либо обе стороны помещаются целиком,
// либо сравнения не было — и тогда исход идёт в корзину «не выполнилось», а не в
// согласие. Величина принадлежит СРАВНЕНИЮ, а не ответу: она ограничивает, сколько
// теневой путь готов прочитать за один живой запрос, и на ответ вызывающему не
// влияет никак.
const CompareSetLimit = 200

// Asker — форма E. Узкий порт: ровно те вопросы, которые форма умеет отвечать.
//
// condCtx — доводы для условий на записях («сейчас», уровень уверенности
// подтверждения личности). Приезжают ОТ ВЫЗЫВАЮЩЕГО уже очищенными от значений,
// присланных клиентом: собрать их здесь второй раз значило бы завести второе
// место, знающее, чему можно верить, — и разойтись с первым в сторону лишнего
// доступа. Путь, у которого доводов нет, передаёт nil: условие тогда не
// выполнено, а не проигнорировано.
//
// `complete` у перечислений — НЕ украшение: неполный ответ сравнивать нельзя
// (см. CompareSetLimit), и форма обязана сказать, поместилась ли она, а не
// оставлять вызывающего гадать по длине.
type Asker interface {
	Allowed(ctx context.Context, subject, objectType, objectID, relation string, condCtx map[string]any) (allowed bool, err error)
	// Objects — какие объекты этого типа доступны субъекту. relations — набор,
	// а не одно имя: движок отвечает на читающее действие ОБЪЕДИНЕНИЕМ двух
	// отношений, и спросить форму об одном из них значило бы сравнить два разных
	// вопроса.
	Objects(ctx context.Context, subject, objectType string, relations []string, limit int) (ids []string, complete bool, err error)
	// Subjects — кто имеет это отношение на этом объекте.
	Subjects(ctx context.Context, objectType, objectID, relation string, limit int) (subjects []string, complete bool, err error)
	// Sources — из чего складывается право на объекте; возвращает СУБЪЕКТОВ,
	// названных основаниями. Форма ответа у двух сторон разная (у движка дерево,
	// у формы E плоский перечень оснований), и единственное, что обе называют
	// одинаково, — кто в итоге получает право.
	Sources(ctx context.Context, objectType, objectID, relation string) (subjects []string, err error)
}

// Counters — то, что сравнение обязано уметь предъявить.
//
// «Ноль расхождений» без числа сравнений — утверждение ни о чём: оно одинаково
// верно и для согласия, и для выключенного сравнения.
//
// И числа сравнений НЕДОСТАТОЧНО: «сравнили тысячу» не отвечает на вопрос
// «сколько это от всех решений». Знаменатель — `decisions`: каждое решение о
// доступе, к которому теневой путь был позван, считается им независимо от того,
// удалось ли спросить форму E. Без знаменателя доля сравнённого неизвестна, и
// мерой сходимости пользоваться нельзя.
type Counters struct {
	decisions  atomic.Int64
	compared   atomic.Int64
	diverged   atomic.Int64
	unfinished atomic.Int64
}

// Snapshot — мгновенный слепок счётчиков.
type Snapshot struct {
	Decisions  int64
	Compared   int64
	Diverged   int64
	Unfinished int64
}

// ComparedShare — доля сравнённых решений от всех, к которым теневой путь позван.
//
// Ноль решений даёт ноль, а не деление на ноль: «ничего не решали» и «ничего не
// сравнили» читатель различит по самому знаменателю, который слепок несёт рядом.
func (s Snapshot) ComparedShare() float64 {
	if s.Decisions == 0 {
		return 0
	}
	return float64(s.Compared) / float64(s.Decisions)
}

// Read отдаёт слепок.
func (c *Counters) Read() Snapshot {
	return Snapshot{
		Decisions:  c.decisions.Load(),
		Compared:   c.compared.Load(),
		Diverged:   c.diverged.Load(),
		Unfinished: c.unfinished.Load(),
	}
}

// Comparator задаёт форме E вопросы, ушедшие движку, и считает исход.
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

// Unaskable отмечает решение, которое форме E задать НЕЛЬЗЯ.
//
// Существует ради знаменателя. Решение, о котором форму не спросили, обязано
// попасть в число решений — иначе доля сравнённого считается от того подмножества,
// где сравнение и так удавалось, и растёт от каждого нового пропуска. Молчаливый
// пропуск здесь запрещён ровно потому, что он делает меру лучше, ничего не улучшив.
func (c *Comparator) Unaskable(reason, objectType, relation string) {
	if c == nil || c.form == nil {
		return
	}
	c.counts.decisions.Add(1)
	c.counts.unfinished.Add(1)
	c.logger.Warn("shadow verdict: вопрос форме E не задан", append([]any{
		"reason", reason, "object_type", objectType, "relation", relation,
	}, c.coverage()...)...)
}

// Ask задаёт форме E прямой вопрос СЕЙЧАС и отдаёт сведение исхода.
//
// # Почему вопрос уходит ДО того, как ответил движок
//
// Сравнение, начатое после ответа движка, происходит ровно там, где движок
// ответил: путь, на котором его ответ пришёл из кэша, укоротился или не состоялся
// вовсе, сравнения не получает — и доля сравнённого становится неизвестной,
// потому что знаменатель считает не те решения. Вопрос форме E задаётся первым и
// не зависит ни от одного исхода движка; сведение — отдельным шагом, когда исход
// известен.
//
// # Почему возвращается функция, а не значение
//
// У вызывающего не должно быть соблазна прочесть теневой ответ и на него
// опереться: сведение ничего не возвращает by construction. Вызывать его ОБЯЗАН
// каждый путь — отсюда `defer` на стороне вызывающего: несведённый вопрос оставил
// бы висеть горутину и её срок.
//
// engineAnswered=false означает «движок вердикта не дал» (ошибка, недоступность):
// сравнивать не с чем, и исход идёт в «не выполнилось», а не в согласие.
func (c *Comparator) Ask(ctx context.Context, subject, objectType, objectID, relation string,
	condCtx map[string]any) func(engineAllowed, engineAnswered bool) {
	if c == nil || c.form == nil {
		return func(bool, bool) {}
	}
	c.counts.decisions.Add(1)
	// Срок СВОЙ: контекст вызывающего берётся только ради его отмены, но время
	// теневому вызову отпускается отдельное.
	sctx, cancel := context.WithTimeout(ctx, c.timeout)
	type answer struct {
		allowed bool
		err     error
	}
	// Буфер на единицу: горутина никогда не блокируется на записи, даже если
	// вызывающий по какой-то причине не сведёт исход.
	ch := make(chan answer, 1)
	go func() {
		allowed, err := c.form.Allowed(sctx, subject, objectType, objectID, relation, condCtx)
		ch <- answer{allowed, err}
	}()
	return func(engineAllowed, engineAnswered bool) {
		defer cancel()
		a := <-ch
		if !engineAnswered {
			c.unfinishedAt("прямой вердикт", "движок вердикта не дал", objectType, relation)
			return
		}
		if a.err != nil {
			c.unfinishedAt("прямой вердикт", a.err.Error(), objectType, relation)
			return
		}
		c.counts.compared.Add(1)
		if a.allowed == engineAllowed {
			return
		}
		c.counts.diverged.Add(1)
		// Расхождение называется ПОИМЁННО: счётчик говорит «сколько», а разобрать
		// можно только зная, на каком вопросе. Доля едет рядом (см. coverage).
		c.logger.Error("shadow verdict: РАСХОЖДЕНИЕ формы E с движком", append([]any{
			"question", "прямой вердикт", "engine", engineAllowed, "form_e", a.allowed,
			"subject", subject, "object_type", objectType, "object_id", objectID, "relation", relation,
		}, c.coverage()...)...)
	}
}

// AskObjects задаёт форме E вопрос «что доступно субъекту» и отдаёт сведение.
func (c *Comparator) AskObjects(ctx context.Context, subject, objectType string,
	relations []string) func(engineIDs []string, engineComplete, engineAnswered bool) {
	return c.askSet(ctx, "перечисление объектов",
		logFields{"subject": subject, "object_type": objectType, "relations": strings.Join(relations, ",")},
		false,
		func(sctx context.Context) ([]string, bool, error) {
			return c.form.Objects(sctx, subject, objectType, relations, CompareSetLimit+1)
		})
}

// AskSubjects задаёт форме E вопрос «кто имеет право на объекте» и отдаёт сведение.
func (c *Comparator) AskSubjects(ctx context.Context, objectType, objectID,
	relation string) func(engineSubjects []string, engineComplete, engineAnswered bool) {
	return c.askSet(ctx, "перечисление субъектов",
		logFields{"object_type": objectType, "object_id": objectID, "relation": relation},
		false,
		func(sctx context.Context) ([]string, bool, error) {
			return c.form.Subjects(sctx, objectType, objectID, relation, CompareSetLimit+1)
		})
}

// AskSources задаёт форме E вопрос «из чего складывается право» и отдаёт сведение.
//
// Сверка ОДНОСТОРОННЯЯ, и это свойство предмета, а не послабление: движок называет
// основание тем, кому оно выдано (набор субъектов — `group:g#member`), а форма E
// называет и его, и тех, кто внутри. Значит «у формы E названо больше» — ожидаемая
// форма ответа, а не расхождение; расхождением остаётся обратное: движок назвал
// основание, которого форма E не знает.
func (c *Comparator) AskSources(ctx context.Context, objectType, objectID,
	relation string) func(engineGrounds []string, engineComplete, engineAnswered bool) {
	return c.askSet(ctx, "разворот отношений",
		logFields{"object_type": objectType, "object_id": objectID, "relation": relation},
		true,
		func(sctx context.Context) ([]string, bool, error) {
			subjects, err := c.form.Sources(sctx, objectType, objectID, relation)
			// Плоский перечень оснований страницами не режется: он либо прочитан
			// целиком, либо не прочитан.
			return subjects, err == nil, err
		})
}

// logFields — поля, называющие вопрос в журнале.
type logFields map[string]string

// askSet — общая механика трёх перечислительных вопросов: спросить форму E СЕЙЧАС,
// свести исход, когда движок ответил.
//
// oneWay=true оставляет расхождением только «движок назвал то, чего форма E не
// знает» (см. AskSources).
func (c *Comparator) askSet(ctx context.Context, question string, fields logFields, oneWay bool,
	ask func(context.Context) ([]string, bool, error)) func([]string, bool, bool) {
	if c == nil || c.form == nil {
		return func([]string, bool, bool) {}
	}
	c.counts.decisions.Add(1)
	sctx, cancel := context.WithTimeout(ctx, c.timeout)
	type answer struct {
		set      []string
		complete bool
		err      error
	}
	ch := make(chan answer, 1)
	go func() {
		set, complete, err := ask(sctx)
		ch <- answer{set, complete, err}
	}()
	return func(engineSet []string, engineComplete, engineAnswered bool) {
		defer cancel()
		a := <-ch
		switch {
		case !engineAnswered:
			c.unfinishedSet(question, "движок ответа не дал", fields)
			return
		case a.err != nil:
			c.unfinishedSet(question, a.err.Error(), fields)
			return
		case len(a.set) > CompareSetLimit || !a.complete || !engineComplete:
			// Неполный ответ хотя бы одной стороны: сравнивать нечего. Засчитать
			// согласием значило бы объявить сравнение состоявшимся там, где сверялись
			// два разных подмножества.
			c.unfinishedSet(question, "ответ не помещается целиком", fields)
			return
		}
		c.counts.compared.Add(1)
		missing, extra := setDiff(engineSet, a.set)
		if oneWay {
			extra = nil
		}
		if len(missing) == 0 && len(extra) == 0 {
			return
		}
		c.counts.diverged.Add(1)
		args := []any{"question", question,
			"engine_only", strings.Join(missing, ","), "form_e_only", strings.Join(extra, ",")}
		for k, v := range fields {
			args = append(args, k, v)
		}
		c.logger.Error("shadow verdict: РАСХОЖДЕНИЕ формы E с движком", append(args, c.coverage()...)...)
	}
}

func (c *Comparator) unfinishedAt(question, reason, objectType, relation string) {
	c.counts.unfinished.Add(1)
	c.logger.Warn("shadow verdict: не выполнилось", append([]any{
		"question", question, "reason", reason,
		"object_type", objectType, "relation", relation,
	}, c.coverage()...)...)
}

func (c *Comparator) unfinishedSet(question, reason string, fields logFields) {
	c.counts.unfinished.Add(1)
	args := []any{"question", question, "reason", reason}
	for k, v := range fields {
		args = append(args, k, v)
	}
	c.logger.Warn("shadow verdict: не выполнилось", append(args, c.coverage()...)...)
}

// coverage — ДОЛЯ сравнённого, которую несёт КАЖДАЯ запись теневого пути.
//
// Без неё вывод отвечает «сколько разошлось» и молчит про «от скольких»: и
// «расхождений нет», и «сравнений не было» выглядят одинаково — ровно то, ради
// чего у счётчиков появился знаменатель. Поэтому доля едет с каждой записью, а не
// ждёт, пока её кто-нибудь спросит: запись без неё читается шире, чем измерено.
func (c *Comparator) coverage() []any {
	s := c.counts.Read()
	return []any{
		"decisions", s.Decisions,
		"compared", s.Compared,
		"compared_share", s.ComparedShare(),
	}
}

// setDiff отдаёт то, что назвал только движок, и то, что назвала только форма E.
//
// Множества, а не последовательности: порядок обхода у двух форм свой, и сверять
// его значило бы объявить расхождением разный курсор.
func setDiff(engine, formE []string) (engineOnly, formEOnly []string) {
	inForm := make(map[string]struct{}, len(formE))
	for _, s := range formE {
		inForm[s] = struct{}{}
	}
	inEngine := make(map[string]struct{}, len(engine))
	for _, s := range engine {
		inEngine[s] = struct{}{}
		if _, ok := inForm[s]; !ok {
			engineOnly = append(engineOnly, s)
		}
	}
	for _, s := range formE {
		if _, ok := inEngine[s]; !ok {
			formEOnly = append(formEOnly, s)
		}
	}
	sort.Strings(engineOnly)
	sort.Strings(formEOnly)
	return engineOnly, formEOnly
}
