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
// НЕ делает: не влияет на ответ вызывающему — ни ЗНАЧЕНИЕМ, ни ЗАДЕРЖКОЙ. Ни
// один исход теневого вызова — ни разрешение, ни отказ, ни ошибка, ни истёкший
// срок — не меняет ни того, что вернёт Check, ни того, КОГДА он это вернёт. Это
// и есть смысл фазы: ошибка формы E сегодня стоит записи в журнале, а не чужого
// доступа.
//
// > [!warning] Вторая половина этого утверждения появилась ПОЗЖЕ первой, и до
// > неё абзац был наполовину ложным
// >
// > Прежняя редакция говорила «не влияет на ответ» и имела в виду ЗНАЧЕНИЕ.
// > Про значение это было верно всегда. Про задержку — неверно: сведение исхода
// > делало безусловное блокирующее чтение ответа формы E, и вызывающий ждал его
// > столько, сколько отпущено теневому вызову. Замер пропускной способности
// > нашёл это как медиану, севшую ровно на срок сверки.
// >
// > Так и работает этот класс: утверждение о безопасности, верное в одном
// > измерении, читается как верное во всех. Комментарий, не назвавший, ЧЕГО
// > именно он не касается, следующий читатель принимает за общий.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СОБСТВЕННЫЙ СРОК, А НЕ СРОК ЗАПРОСА
//
// Теневой вызов идёт РЯДОМ с живым запросом. Отдать ему срок вызывающего значит
// связать сравнение с жизнью запроса, который от него не зависит; отдать ему
// ожидание на стороне ответа — сделать срок сверки верхней границей задержки
// вызывающего. Ни того, ни другого здесь нет: срок свой, отмена своя, а сведение
// исхода живого пути не держит (см. offPath). Исчерпание срока — исход
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
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultTimeout — срок одного теневого вызова.
//
// Величина выбрана из назначения, а не из вкуса: сравнение обязано быть дешевле
// самого решения, иначе оно меняет то, что измеряет. Ответ формы E на прямом
// вопросе — единичные миллисекунды (индексы по всем четырём источникам), и срок
// втрое-впятеро больше даёт запас, оставаясь малой долей бюджета.
//
// Прежде здесь стояло 50 мс — БОЛЬШЕ всего бюджета чтения (см. ReadBudget).
// Обоснование было верным по форме («на порядок больше единичных миллисекунд»)
// и неверным по опоре: запас отсчитывался от ответа формы E, а не от бюджета
// операции, в который этот запас обязан поместиться. Пока форма укладывалась,
// расхождение было незаметно; на сорванной ступени замера медиана села ровно на
// срок сверки.
//
// Сегодня срок ограничивает не задержку вызывающего (сведение исхода его больше
// не ждёт), а то, СКОЛЬКО теневой вопрос держит соединение к базе. Обе величины —
// срок и потолок одновременных вопросов — вместе задают верхнюю границу
// теневого следа в пуле, и она перестала зависеть от нагрузки.
const DefaultTimeout = 10 * time.Millisecond

// ReadBudget — бюджет чтения, названный владельцем: столько отпущено ВСЕЙ
// операции, ради которой теневая сверка существует.
//
// Стоит здесь потому, что здесь единственное место, где эту величину с чем-то
// сравнивают: срок сверки обязан быть строго меньше — механизм, который решений
// НЕ ПРИНИМАЕТ, не вправе задержать ответ дольше, чем весь бюджет решения.
const ReadBudget = 30 * time.Millisecond

// DefaultMaxInFlight — потолок теневых вопросов, идущих одновременно.
//
// Потолок появился вместе со снятием ожидания и является его ЦЕНОЙ. Пока сведение
// исхода ждало форму E, число теневых вопросов в полёте ограничивал сам живой
// путь: запрос не уходил, пока его сверка не закончилась. Без ожидания этой
// границы нет, и теневая работа растёт вместе с нагрузкой — то есть обрыв по
// задержке сменился бы обрывом по соединениям, а лекарство сохранило бы свой
// отказ.
//
// Величина выбрана из назначения: теневой путь делит пул с живым и обязан
// оставаться его малой долей, а не соперником. Восьми хватает, чтобы сверка шла
// непрерывно (при сроке в единицы миллисекунд это сотни сравнений в секунду —
// доля сравнённого измеряется, а не обнуляется), и мало настолько, что даже
// целиком занятый теневой путь не отбирает у живого заметной части пула.
//
// Отброшенный вопрос идёт в корзину «не выполнилось» СВОЕЙ причиной: сброс,
// невидимый снаружи, сделал бы долю сравнённого лучше, ничего не улучшив.
const DefaultMaxInFlight = 8

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

// LabelArmObserver — необязательное расширение формы E: сколько раз меточная
// ветвь дала основание НА ПРЯМОМ ВЕРДИКТЕ, по осям. Границу счёта объявляет
// сама форма (см. relverdict.Asker) — здесь числа только печатаются.
//
// Отдельным интерфейсом, а не полем порта `Asker`, намеренно: отвечать на
// вопросы и вести наблюдение — разные обязанности, и форма, которая наблюдения
// не ведёт, обязана оставаться пригодной без заглушки. Реализуется источником
// (`relverdict.Asker`), читается ЗДЕСЬ — числа едут в каждую запись теневого
// пути.
//
// Зачем это вообще: ветвь меток отвечает на ДВУХ осях (зеркало чужих ресурсов и
// собственные таблицы iam), и «расхождений нет» при нуле оснований на одной из
// них означает не согласие, а то, что ось не спрашивали. Одно число на обе оси
// эту разницу скрыло бы — потому их два.
type LabelArmObserver interface {
	// Третье число — вердиктов, ответивших ДО того, как набор источников
	// дочитан (ранний выход на первом безусловном основании). Без него ноль
	// оснований меточной ветви одинаково читается и как «ветвь молчала», и как
	// «до неё не дочитали»; печатать первые два и умолчать о третьем значило бы
	// выдать неопределённость за наблюдение.
	LabelArmGrounds() (mirror, iamDirect, earlyStops int64)
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

// DefaultSummaryEvery — как часто сравнение печатает сводку.
//
// Сводка существует ради ОДНОГО различия: «расхождений 0 из N сравнённых» против
// «сравнено 0». Пока наружу выходили только записи о расхождениях, согласие форм
// и выключенное сравнение выглядели одинаково — тишиной. Значение выбрано так,
// чтобы след оставался у любого прогона (сквозная проба идёт минуты), и при этом
// сводка не становилась сама источником шума.
const DefaultSummaryEvery = 30 * time.Second

// Comparator задаёт форме E вопросы, ушедшие движку, и считает исход.
type Comparator struct {
	form    Asker
	timeout time.Duration
	logger  *slog.Logger
	counts  Counters

	// sem — потолок теневых вопросов в полёте (см. DefaultMaxInFlight). Занятый
	// слот держится ровно столько, сколько живёт теневой вопрос; свободного нет —
	// вопрос ОТБРАСЫВАЕТСЯ со своей причиной, а не встаёт в очередь. Очередь
	// вернула бы ту же беду с другой стороны: неограниченный рост работы,
	// которая ни на что не влияет.
	sem chan struct{}

	// wg — учёт незавершённых сравнений. Нужен тому, кто обязан знать, что
	// теневая работа кончилась: пробам — чтобы читать счётчики после сведения,
	// а не до него, и остановке процесса — чтобы не рвать вопросы на полуслове.
	wg sync.WaitGroup

	// now — часы. Параметром ради проб: сводка привязана ко времени, и проба,
	// ждущая настоящих секунд, проверяла бы планировщик, а не свойство.
	now          func() time.Time
	summaryEvery time.Duration

	// mu защищает перечень классов и отметку последней сводки.
	//
	// РАЗБОР ВЕДЁТСЯ ПО КЛАССУ, А НЕ ПО СЛУЧАЮ. Один и тот же дефект даёт тысячи
	// одинаковых записей — за один прогон их было 3215, — и уровень записи от
	// этого перестаёт значить что-либо: настоящая ошибка тонет by construction.
	// Поэтому КАЖДЫЙ класс называется поимённо ровно один раз, а повторы копятся
	// счётчиком и выходят сводкой.
	//
	// Это НЕ ослабление сравнения: ни один счётчик и ни одна клетка метрики от
	// этого не меняются, и ни один класс не пропадает — пропадает только
	// дословный повтор уже названного. Ослаблением было бы перестать СЧИТАТЬ.
	mu          sync.Mutex
	classes     map[string]int64
	lastSummary time.Time
	summaries   int64
}

// New собирает сравнитель. nil-форма — законный вход: сравнение выключено, и
// вызовы становятся дешёвыми no-op.
func New(form Asker, logger *slog.Logger) *Comparator {
	if logger == nil {
		logger = slog.Default()
	}
	return &Comparator{
		form:         form,
		timeout:      DefaultTimeout,
		logger:       logger,
		now:          time.Now,
		summaryEvery: DefaultSummaryEvery,
		classes:      make(map[string]int64),
		sem:          make(chan struct{}, DefaultMaxInFlight),
	}
}

// WithTimeout меняет срок теневого вызова (для проб).
//
// Величина С БЮДЖЕТОМ ЧТЕНИЯ ИЛИ ВЫШЕ не принимается: ограничение обязано
// держаться механизмом, а не комментарием рядом с константой. Отвергнутая
// величина оставляет срок прежним — тихо расширить его отсюда нельзя.
func (c *Comparator) WithTimeout(d time.Duration) *Comparator {
	if d > 0 && d < ReadBudget {
		c.timeout = d
	}
	return c
}

// Wait ждёт, пока сведутся все начатые сравнения.
//
// Сведение исхода ушло с пути живого запроса, поэтому «вопрос задан» и
// «сравнение состоялось» перестали быть одним мгновением. Тому, кто читает
// счётчики (проба) или гасит процесс, нужна точка, после которой теневой работы
// не осталось.
func (c *Comparator) Wait() {
	if c == nil {
		return
	}
	c.wg.Wait()
}

// acquire занимает слот в потолке; false — свободного нет.
func (c *Comparator) acquire() bool {
	select {
	case c.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (c *Comparator) release() { <-c.sem }

// reasonSaturated / reasonNotSettled — причины в корзине «не выполнилось».
//
// Названы отдельно от ошибок формы E намеренно: «сравнения не было, потому что
// теневой путь занят» и «форма E не ответила» требуют разных действий, а одна
// причина на оба случая сделала бы их неотличимыми.
const (
	reasonSaturated  = "теневой путь занят — вопрос отброшен"
	reasonNotSettled = "исход не сведён вызывающим"
)

// settleGrace — сколько теневой вопрос ждёт исхода движка, если вызывающий его
// так и не свёл.
//
// Штатно исход приходит `defer`-ом, то есть раньше, чем контекст вызывающего
// будет отменён, и ожидание кончается на первом же признаке. Запас существует
// ради вызывающего с неотменяемым контекстом: без него слот потолка не
// освободился бы никогда, и теневой путь встал бы целиком.
const settleGrace = 5 * time.Second

// offPath задаёт вопрос форме E РЯДОМ с живым запросом и сводит исход ВНЕ его пути.
//
// # Почему сведение не ждёт форму E
//
// Сравнение решений НЕ ПРИНИМАЕТ. Ожидание его ответа делает верхнюю границу
// задержки вызывающего равной сроку сверки — и эта граница приходит СКАЧКОМ:
// пока форма укладывается, ожидание незаметно, а как только перестаёт, полный
// срок платит каждый запрос. Наблюдение, меняющее наблюдаемое ровно в тот момент,
// когда наблюдаемое становится интересным, не измеряет ничего.
//
// # Почему у теневого вопроса СВОЯ отмена, а не только свой срок
//
// gRPC отменяет контекст обработчика ровно тогда, когда обработчик вернулся, —
// то есть сразу после сведения. Теневой вопрос, унаследовавший эту отмену, стал
// бы «не выполнилось» на КАЖДОМ решении: живой путь перестал бы ждать, но и
// сравнения не осталось бы. Поэтому вопрос идёт по контексту БЕЗ отмены (значения
// сохраняются — они называют вызывающего), а исходный контекст остаётся ровно
// одним: признаком того, что вызывающий ушёл.
func offPath[A any, E any](c *Comparator, ctx context.Context,
	ask func(context.Context) A,
	unfinished func(reason string),
	reconcile func(A, E),
) func(E) {
	if !c.acquire() {
		unfinished(reasonSaturated)
		return func(E) {}
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.timeout)
	// Буфер на единицу: сведение исхода не блокируется НИКОГДА, даже если
	// теневой вопрос к этому мгновению уже сдался по сроку.
	engine := make(chan E, 1)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer c.release()
		defer cancel()
		a := ask(sctx)
		e, ok := awaitEngine(ctx, engine)
		if !ok {
			unfinished(reasonNotSettled)
			return
		}
		reconcile(a, e)
	}()
	return func(e E) {
		select {
		case engine <- e:
		default:
		}
	}
}

// awaitEngine забирает исход движка, не завися от того, кто пришёл первым.
func awaitEngine[E any](ctx context.Context, engine <-chan E) (E, bool) {
	// Сначала — БЕЗ ожидания: штатно исход уже лежит в буфере (сведение идёт
	// `defer`-ом, до отмены контекста). `select` из двух готовых веток выбрал бы
	// случайно, и сравнение терялось бы на ровном месте примерно в половине
	// случаев.
	select {
	case e := <-engine:
		return e, true
	default:
	}
	timer := time.NewTimer(settleGrace)
	defer timer.Stop()
	select {
	case e := <-engine:
		return e, true
	case <-ctx.Done():
		// Та же гонка на выходе: исход мог лечь в буфер ровно в это мгновение.
		select {
		case e := <-engine:
			return e, true
		default:
		}
	case <-timer.C:
	}
	var zero E
	return zero, false
}

// WithClock подменяет часы сводки (для проб).
func (c *Comparator) WithClock(now func() time.Time) *Comparator {
	if now != nil {
		c.now = now
	}
	return c
}

// WithSummaryEvery меняет период сводки. Ноль и отрицательное — отказ от
// изменения, а не «печатать всегда»: последнее превратило бы сводку в шум.
func (c *Comparator) WithSummaryEvery(d time.Duration) *Comparator {
	if d > 0 {
		c.summaryEvery = d
	}
	return c
}

// firstOfClass отвечает, впервые ли встречен этот класс, и сколько их всего.
func (c *Comparator) firstOfClass(key string) (first bool, seen int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.classes[key]++
	return c.classes[key] == 1, c.classes[key]
}

// Summarise печатает сводку безусловно — числа и перечень классов.
//
// Печатается ВСЕГДА, даже когда расхождений нет: строка «расхождений 0 из N
// сравнённых» — единственное, что отличает согласие форм от невыполненного
// сравнения в журнале (метрика отвечает на тот же вопрос, но её на прогоне со
// стенда никто не снимает).
func (c *Comparator) Summarise() {
	if c == nil || c.form == nil {
		return
	}
	c.mu.Lock()
	now := c.now()
	c.lastSummary = now
	c.mu.Unlock()
	c.summarise(now)
}

// summarise печатает сводку, считая слот УЖЕ занятым вызывающим.
func (c *Comparator) summarise(at time.Time) {
	s := c.counts.Read()
	c.mu.Lock()
	classes := make([]string, 0, len(c.classes))
	for k, n := range c.classes {
		classes = append(classes, fmt.Sprintf("%s×%d", k, n))
	}
	c.summaries++
	c.lastSummary = at
	c.mu.Unlock()
	sort.Strings(classes)

	c.logger.Info("shadow verdict: сводка",
		"decisions", s.Decisions, "compared", s.Compared,
		"diverged", s.Diverged, "unfinished", s.Unfinished,
		"compared_share", s.ComparedShare(),
		"classes", len(classes), "class_breakdown", strings.Join(classes, " "))
}

// maybeSummarise печатает сводку не чаще, чем раз в период.
//
// Первая печатается на первом же сведённом исходе: присутствие строки отвечает
// «сравнение живо», а её числа — «до чего оно дошло». Отсутствие отвечало бы на
// оба вопроса сразу и не отвечало бы ни на один.
// Слот СВОДКИ ЗАНИМАЕТСЯ ТЕМ ЖЕ ЗАМКОМ, КОТОРЫЙ РЕШИЛ, ЧТО ОНА НУЖНА.
//
// Прежде решение и занятие стояли по разные стороны замка: «пора» вычислялось
// под ним, а отметка времени ставилась уже внутри Summarise, после его снятия.
// Пока сведение исходов шло на пути живого запроса, вызывающих было по одному на
// запрос и промежуток между двумя действиями ничем не заполнялся. Как только
// сведение ушло РЯДОМ с запросом, вызывающих стало несколько сразу — и оба
// проходили проверку до того, как первый успевал отметиться, то есть период
// переставал ограничивать что-либо.
//
// Это тот же вид ошибки, что «прочитал → проверил → записал» в базе, только в
// памяти: между решением и действием состояние успевает измениться. Лечится так
// же — решением и занятием под ОДНИМ замком.
func (c *Comparator) maybeSummarise() {
	c.mu.Lock()
	now := c.now()
	if !c.lastSummary.IsZero() && now.Sub(c.lastSummary) < c.summaryEvery {
		c.mu.Unlock()
		return
	}
	c.lastSummary = now
	c.mu.Unlock()
	c.summarise(now)
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
	class := fmt.Sprintf("не задан|%s|%s|%s", objectType, relation, reason)
	if first, seen := c.firstOfClass(class); first {
		c.logger.Warn("shadow verdict: вопрос форме E не задан", append([]any{
			"reason", reason, "object_type", objectType, "relation", relation,
			"class", class, "class_seen", seen,
		}, c.coverage()...)...)
	}
	c.maybeSummarise()
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

	const question = "прямой вердикт"
	unfinished := func(reason string) { c.unfinishedAt(question, reason, objectType, relation) }
	type formAnswer struct {
		allowed bool
		err     error
	}
	type engineVerdict struct{ allowed, answered bool }

	deposit := offPath(c, ctx,
		func(sctx context.Context) formAnswer {
			allowed, err := c.form.Allowed(sctx, subject, objectType, objectID, relation, condCtx)
			return formAnswer{allowed, err}
		},
		unfinished,
		func(a formAnswer, e engineVerdict) {
			engineAllowed := e.allowed
			if !e.answered {
				unfinished("движок вердикта не дал")
				return
			}
			if a.err != nil {
				unfinished(a.err.Error())
				return
			}
			c.counts.compared.Add(1)
			if a.allowed == engineAllowed {
				c.maybeSummarise()
				return
			}
			c.counts.diverged.Add(1)
			// Расхождение называется ПОИМЁННО: счётчик говорит «сколько», а разобрать
			// можно только зная, на каком вопросе. Доля едет рядом (см. coverage).
			//
			// Поимённо — ОДИН РАЗ НА КЛАСС. Повторы копятся счётчиком класса и выходят
			// сводкой; разбирают их всё равно по классу, а не по случаю (см. mu).
			class := fmt.Sprintf("%s|%s|%s|движок=%v", question, objectType, relation, engineAllowed)
			if first, seen := c.firstOfClass(class); first {
				c.logger.Error("shadow verdict: РАСХОЖДЕНИЕ формы E с движком", append([]any{
					"question", question, "engine", engineAllowed, "form_e", a.allowed,
					"subject", subject, "object_type", objectType, "object_id", objectID, "relation", relation,
					"class", class, "class_seen", seen,
				}, c.coverage()...)...)
			}
			c.maybeSummarise()
		})
	return func(engineAllowed, engineAnswered bool) {
		deposit(engineVerdict{allowed: engineAllowed, answered: engineAnswered})
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

// class — устойчивая часть вопроса: всё, кроме идентификатора объекта и субъекта.
//
// Оба исключены намеренно: они меняются на каждом ресурсе и на каждом вызывающем,
// и класс, включивший их, перестал бы быть классом — перечень «уже названного»
// рос бы вместе с трафиком, а разбор всё равно ведётся по типу и отношению.
// Координаты первого случая при этом называются полностью — они в самой записи.
func (f logFields) class() string {
	keys := make([]string, 0, len(f))
	for k := range f {
		if k == "object_id" || k == "subject" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+f[k])
	}
	return strings.Join(parts, ",")
}

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

	unfinished := func(reason string) { c.unfinishedSet(question, reason, fields) }
	type formAnswer struct {
		set      []string
		complete bool
		err      error
	}
	type engineAnswer struct {
		set      []string
		complete bool
		answered bool
	}

	deposit := offPath(c, ctx,
		func(sctx context.Context) formAnswer {
			set, complete, err := ask(sctx)
			return formAnswer{set, complete, err}
		},
		unfinished,
		func(a formAnswer, e engineAnswer) {
			switch {
			case !e.answered:
				unfinished("движок ответа не дал")
				return
			case a.err != nil:
				unfinished(a.err.Error())
				return
			case len(a.set) > CompareSetLimit || !a.complete || !e.complete:
				// Неполный ответ хотя бы одной стороны: сравнивать нечего. Засчитать
				// согласием значило бы объявить сравнение состоявшимся там, где сверялись
				// два разных подмножества.
				unfinished("ответ не помещается целиком")
				return
			}
			c.counts.compared.Add(1)
			missing, extra := setDiff(e.set, a.set)
			if oneWay {
				extra = nil
			}
			if len(missing) == 0 && len(extra) == 0 {
				c.maybeSummarise()
				return
			}
			c.counts.diverged.Add(1)
			class := question + "|" + fields.class()
			if first, seen := c.firstOfClass(class); first {
				args := []any{"question", question,
					"engine_only", strings.Join(missing, ","), "form_e_only", strings.Join(extra, ","),
					"class", class, "class_seen", seen}
				for k, v := range fields {
					args = append(args, k, v)
				}
				c.logger.Error("shadow verdict: РАСХОЖДЕНИЕ формы E с движком", append(args, c.coverage()...)...)
			}
			c.maybeSummarise()
		})
	return func(engineSet []string, engineComplete, engineAnswered bool) {
		deposit(engineAnswer{set: engineSet, complete: engineComplete, answered: engineAnswered})
	}
}

// unfinishedAt / unfinishedSet — то же правило класса, что у расхождения.
//
// «Не выполнилось» повторяется ещё чаще расхождения (за один прогон таких записей
// было 914 при 4 различных причинах), и повтор одной и той же причины по одному и
// тому же вопросу нового действия не требует. Счётчик исходов при этом не
// меняется: он считает СЛУЧАИ, а перечень классов — ВИДЫ.
func (c *Comparator) unfinishedAt(question, reason, objectType, relation string) {
	c.counts.unfinished.Add(1)
	class := fmt.Sprintf("не выполнилось|%s|%s|%s|%s", question, objectType, relation, reason)
	if first, seen := c.firstOfClass(class); first {
		c.logger.Warn("shadow verdict: не выполнилось", append([]any{
			"question", question, "reason", reason,
			"object_type", objectType, "relation", relation,
			"class", class, "class_seen", seen,
		}, c.coverage()...)...)
	}
	c.maybeSummarise()
}

func (c *Comparator) unfinishedSet(question, reason string, fields logFields) {
	c.counts.unfinished.Add(1)
	class := "не выполнилось|" + question + "|" + fields.class() + "|" + reason
	if first, seen := c.firstOfClass(class); first {
		args := []any{"question", question, "reason", reason, "class", class, "class_seen", seen}
		for k, v := range fields {
			args = append(args, k, v)
		}
		c.logger.Warn("shadow verdict: не выполнилось", append(args, c.coverage()...)...)
	}
	c.maybeSummarise()
}

// coverage — ДОЛЯ сравнённого, которую несёт КАЖДАЯ запись теневого пути.
//
// Без неё вывод отвечает «сколько разошлось» и молчит про «от скольких»: и
// «расхождений нет», и «сравнений не было» выглядят одинаково — ровно то, ради
// чего у счётчиков появился знаменатель. Поэтому доля едет с каждой записью, а не
// ждёт, пока её кто-нибудь спросит: запись без неё читается шире, чем измерено.
func (c *Comparator) coverage() []any {
	s := c.counts.Read()
	out := []any{
		"decisions", s.Decisions,
		"compared", s.Compared,
		"compared_share", s.ComparedShare(),
	}
	// Основания меточной ветви — ПО ОСЯМ. Без них запись отвечает «сколько
	// сравнили» и молчит о том, спрашивали ли вообще ту ветвь, на которой
	// конъюнкт однажды оказался тождественно ложным: ноль там читался бы как
	// согласие форм.
	if o, ok := c.form.(LabelArmObserver); ok {
		mirror, iamDirect, earlyStops := o.LabelArmGrounds()
		out = append(out, "label_grounds_mirror", mirror,
			"label_grounds_iam_direct", iamDirect,
			"verdicts_short_circuited", earlyStops)
	}
	return out
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
