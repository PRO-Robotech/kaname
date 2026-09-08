// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzformbench

// labelcost.go — ПУТЬ МЕТОК: чего стоит доступ, выданный правилом с отбором по
// меткам, у формы с материализацией и у формы без неё.
//
// # Почему это отдельный предмет, а не колонка в матрице XC-10
//
// Матрица XC-10 меряет выдачу, переразметку и отзыв как ЗАПИСЬ КОРТЕЖЕЙ: сколько
// строк, сколько обращений, сколько миллисекунд. Она не спрашивает того
// единственного, ради чего путь меток вообще заведён, — ЧЕРЕЗ СКОЛЬКО ОТВЕТ
// СТАНОВИТСЯ ВЕРНЫМ. Форма, которая пишет вдвое меньше строк, но отвечает
// неверно ещё секунду после того, как право снято, не дешевле: она опаснее.
//
// Поэтому здесь у каждой операции ДВЕ величины, и вторая никогда не сворачивается
// в первую: работа (мс, стейтменты, строки) и ОКНО НЕВЕРНОГО ОТВЕТА.
//
// # Что здесь НЕ измеряется и почему — сказано в самом приборе, а не только в отчёте
//
// Очередь доставки. Прибор её не поднимает — он держит Postgres, а не сервис, —
// поэтому то, что стоит у продукта между изменением и его видимостью, называется
// рядом отдельной величиной, прочитанной из дерева предикатом, и НЕ складывается с
// измеренным: сложить значило бы напечатать под именем измеренного то, что измерено
// наполовину.
//
// Формы, чьё окно этой очередью и определялось, здесь больше нет. Реляционная
// форма между изменением метки и вердиктом очереди не имеет вовсе — её окно
// измерено целиком, и раздел остаётся не ради неё, а ради честности отчёта: он
// говорит, чего в числах НЕТ, до того как их прочитают.

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ── ПРАВИЛО ОТНЕСЕНИЯ ─────────────────────────────────────────────────────────

// AttributionRule — правило отнесения стоимости, объявленное ДО прогона.
//
// Оно живёт В КОДЕ прибора, а не в прозе отчёта, ровно по одной причине: отчёт
// пишется после прогона, и правило, впервые появившееся в нём, неотличимо от
// правила, подобранного под полученные числа. Здесь оно приезжает своим
// коммитом, раньше первой измеренной величины, и печатается в отчёт ДОСЛОВНО
// отсюда — так, что расхождение между объявленным и напечатанным невозможно.
const AttributionRule = `
ПРАВИЛО ОТНЕСЕНИЯ (объявлено до прогона; отчёт печатает его дословно из кода)

0. СТОРОНА ОДНА. Правило писалось для СРАВНЕНИЯ двух форм — реляционной и
   материализованной во внешнем движке отношений. Движок снят целиком, и второй
   стороны больше нет. Пункты ниже сохранены и переписаны под то, что осталось,
   а не выброшены: они объявляют, ЧТО именно попадает в измеряемую величину, и
   без второй стороны этот вопрос не становится проще — он становится
   единственным. Числа сравнивать не с чем; числа остаются.

1. ЕДИНИЦЫ. Три, и ни одна не складывается с другой:
     мс             — время стены, p50/p95/min/max по повторам; нулевой повтор
                      прогревочный и в выборку не входит;
     стейтментов    — SQL-стейтментов на Postgres формы; считаются трассировщиком
                      с контролем в обе стороны;
     строк          — строк намерения, которых операция коснулась.
   Четвёртой единицей были круговые обращения к движку по HTTP. Она СНЯТА, а не
   оставлена нулём: величина без производителя печатается неотличимо от
   измеренной.

2. ОБЩЕЕ НЕ ПРИПИСЫВАЕТСЯ ФОРМЕ. Зеркало объектов и цепь их предков существуют
   независимо от того, выдано ли кому-нибудь право: их наполняют владельцы
   объектов. Поэтому запись зеркала и ребра предка исключена из стоимости формы и
   выполняется до старта секундомера. Пункт пережил вторую сторону и остался
   несущим: без него «выдать» у формы E выглядело бы дороже ровно на ту работу,
   которую она не делает.

3. ФОРМЕ ПРИПИСЫВАЕТСЯ ВЫЧИСЛЕНИЕ ВЕРДИКТА НА ПУТИ ЗАПРОСА и запись самого
   правила. Её работа по событию метки может оказаться нулевой — и этот ноль
   ИЗМЕРЯЕТСЯ теми же счётчиками, а не объявляется: ноль, взятый из рассуждения,
   неотличим от несработавшего счётчика.

4. ОКНО НЕВЕРНОГО ОТВЕТА — отдельная величина, никогда не сворачиваемая в «мс».
   Отсчёт начинается в момент КОММИТА общего изменения (метка изменена, объект
   создан, правило отозвано) и кончается на ПЕРВОМ вопросе, ответ на который
   соответствует новому состоянию. Опрос идёт с шагом 200 мкс и своим бюджетом;
   исчерпание бюджета — «не выполнилось» с причиной, а не ноль.

5. ОКНО ОТЗЫВА НАЗЫВАЕТСЯ ОТДЕЛЬНО ОТ ОСТАЛЬНЫХ. Это величина про безопасность:
   сколько времени доступ остаётся у того, кто его уже потерял. Она не
   усредняется с окнами выдачи и не входит ни в какую сводную «скорость».

6. НЕИЗМЕРЕННАЯ ЧАСТЬ НАЗЫВАЕТСЯ, А НЕ ПРИБАВЛЯЕТСЯ И НЕ ОБЪЯВЛЯЕТСЯ «ПОЛОМ».
   Что стоит между коммитом изменения и тем, как его увидит продуктовый путь,
   читается из дерева предикатом и печатается ТЕКСТОМ, отдельным разделом.

7. ИСХОДОВ ТРИ: измерено · не выполнилось · неизмеряемое, названное текстом.
   Их было четыре, пока сторон было две: «отказ» был фактом о движке, а
   «неприменимо by construction» — самым содержательным результатом таблицы (у
   движка не могло быть общей транзакции с БД предмета выдачи). У формы E эта
   операция ВЫРАЗИМА, поэтому она измеряется. «Не выполнилось» по-прежнему
   никогда не вычитается ни в чью пользу и печатается своей строкой с причиной.

8. КОНТРОЛИ ДО ЗАМЕРА, ИНАЧЕ ЗАМЕР НЕ НАЧИНАЕТСЯ. Перед первой величиной форма
   отвечает на два вопроса: посторонний на объекте набора — ОТКАЗ, субъект
   правила на нём же — РАЗРЕШЕНО. Форма, отвечающая «нет» всем, иначе выиграла бы
   все читающие колонки, не тронув ни одного индекса; форма, отвечающая «да»
   всем, выиграла бы все окна. С уходом второй стороны эти контроли стали
   ЕДИНСТВЕННЫМ, что отличает измеренную скорость от скорости неверного ответа.

9. КРИВАЯ, А НЕ ТОЧКА. Каждая величина снимается на всех N перечня. Одно число
   без наклона не отличает O(1) от O(N) — и теперь, когда сравнивать не с чем,
   наклон остался единственным содержательным утверждением замера.
`

// QueuePredicate — предикат, которым читается неизмеренная часть окна.
//
// Предикатом, а не числом: число из памяти устаревает молча, команда — нет.
//
// И НИКАКОГО «пола» из этих величин не строится. Обе очереди продукта
// пробуждаются УВЕДОМЛЕНИЕМ, а перечисленные периоды — запасной путь на
// пропущенное уведомление. Объявить период опроса нижней границей окна значило бы
// назвать числом то, что на штатном пути не выполняется, — придуманная величина
// в отчёте, чей предмет как раз в том, чтобы величины были измеренными.
const QueuePredicate = `grep -rn 'KANAME_RECONCILE_DRAIN_INTERVAL_MS|PollFallback|pg_notify' ` +
	`services/iam/cmd/kaname/serve.go services/iam/cmd/kaname/fga_outbox_drainer.go ` +
	`services/iam/internal/repo/kaname/pg/reconcile_notify.go`

// ── словарь операций ──────────────────────────────────────────────────────────

// LabelOp — операция пути меток.
type LabelOp string

const (
	// LopFirstAnswer — чего стоит ПЕРВЫЙ верный ответ, считая от момента, когда
	// правило написано. У формы E это запись правила и один вопрос; у формы,
	// материализующей состав, это была развёртка правила в кортежи —
	// материализация всего набора и один вопрос. Это и есть развилка N.
	LopFirstAnswer LabelOp = "L1-первый-ответ"
	// LopCheck — прямой вердикт в установившемся состоянии.
	LopCheck LabelOp = "D1-вердикт-1"
	// LopPage — страница договора (1000), суженная тем же правилом.
	LopPage LabelOp = "D2-страница-1000"
	// LopRelabelIn — метка одного объекта введена: он попадает под правило.
	LopRelabelIn LabelOp = "L2-метка-введена"
	// LopCreateInSet — объект создан и сразу попадает под существующее правило.
	LopCreateInSet LabelOp = "L3-создан-под-правилом"
	// LopRelabelOut — ОТЗЫВ: метка снята, объект выходит из-под правила.
	LopRelabelOut LabelOp = "L4-метка-снята-ОТЗЫВ"
	// LopRevokeRule — ОТЗЫВ: правило отозвано целиком, набор выходит разом.
	LopRevokeRule LabelOp = "L5-правило-отозвано-ОТЗЫВ"
)

// labelOpsOrder — единственное место, где объявлен порядок операций в отчёте.
var labelOpsOrder = []LabelOp{
	LopFirstAnswer, LopCheck, LopPage,
	LopRelabelIn, LopCreateInSet, LopRelabelOut, LopRevokeRule,
}

// revocationOps — операции, чьё окно есть величина ПРО БЕЗОПАСНОСТЬ.
var revocationOps = map[LabelOp]bool{LopRelabelOut: true, LopRevokeRule: true}

// IsRevocation — операция ли это отзыва. Перечень один, и он здесь.
func IsRevocation(op LabelOp) bool { return revocationOps[op] }

// ── событие пути меток ────────────────────────────────────────────────────────

// LabelEventKind — что именно случилось с набором.
type LabelEventKind string

const (
	// EventEntered — объект, уже существовавший, получил метку правила.
	EventEntered LabelEventKind = "метка введена"
	// EventCreated — объект заведён и сразу несёт метку правила.
	EventCreated LabelEventKind = "объект создан под правилом"
	// EventLeft — объект потерял метку и вышел из-под правила.
	EventLeft LabelEventKind = "метка снята"
	// EventRuleRevoked — правило отозвано; набор выходит целиком.
	EventRuleRevoked LabelEventKind = "правило отозвано"
)

// LabelEvent — одно событие пути меток.
type LabelEvent struct {
	Kind LabelEventKind
	// ObjectID — объект события. Пусто для отзыва правила: он про весь набор.
	ObjectID string
	// Expect — вердикт, который новое состояние ПОДРАЗУМЕВАЕТ. Окно кончается на
	// первом ответе, равном ему.
	Expect bool
}

// opOf — операция, которой принадлежит событие.
func opOf(k LabelEventKind) LabelOp {
	switch k {
	case EventEntered:
		return LopRelabelIn
	case EventCreated:
		return LopCreateInSet
	case EventLeft:
		return LopRelabelOut
	case EventRuleRevoked:
		return LopRevokeRule
	}
	return LabelOp("неизвестное событие " + string(k))
}

// ── сценарий ──────────────────────────────────────────────────────────────────

// LabelScenario — набор, правило и его размерности.
type LabelScenario struct {
	N          int      // объектов под правилом
	Verbs      []string // M — глаголы роли, в канонической форме без приставки
	Subjects   []string // S — субъекты выдачи, в форме "user:usr-…"
	ObjectType string
	ProjectID  string
	AccountID  string
	LabelKey   string
	LabelValue string

	PageSize    int // страница договора
	Partition   int // объектов в одном обращении BatchCheck
	Parallelism int // частей страницы в полёте
}

// Object — идентификатор i-го объекта набора. Форма фиксирована: сравниваются
// формы, а разница в идентификаторах была бы разницей в данных.
func (sc LabelScenario) Object(i int) string { return fmt.Sprintf("net-%07d", i) }

// SpareEnter / SpareCreate — объекты СОБЫТИЙ, лежащие за пределами набора.
//
// Отдельные, а не «возьмём любой из набора»: событие, поставленное на объект
// набора, меняло бы сам набор от повтора к повтору, и вторая итерация мерила бы
// уже другой мир.
func (sc LabelScenario) SpareEnter() string  { return "net-spare-enter" }
func (sc LabelScenario) SpareCreate() string { return "net-spare-create" }

// Ref — объект строкой «тип:идентификатор».
func (sc LabelScenario) Ref(objectID string) string { return sc.ObjectType + ":" + objectID }

// Verb — модельное имя глагола (с приставкой) по канонической форме.
func Verb(v string) string { return VerbPrefix + v }

// Objects — весь набор.
func (sc LabelScenario) Objects() []string {
	out := make([]string, 0, sc.N)
	for i := 0; i < sc.N; i++ {
		out = append(out, sc.Object(i))
	}
	return out
}

// ── границы ───────────────────────────────────────────────────────────────────

// LabelWorld — ОБЩАЯ часть обеих форм: зеркало объектов и цепь предков.
//
// Реализуется тем, кто держит обе стороны сравнения. Границей она заведена не
// ради красоты: без неё общее изменение выполнял бы каждый по-своему, и правило
// отнесения п.2 («общее не приписывается никому») стало бы обещанием вместо
// свойства прогона.
type LabelWorld interface {
	// Commit применяет общее изменение и возвращает МОМЕНТ его коммита — точку,
	// от которой отсчитывается окно неверного ответа у КАЖДОЙ формы.
	Commit(ctx context.Context, ev LabelEvent) (time.Time, error)
	// Revert возвращает общее состояние к тому, каким оно было до события.
	Revert(ctx context.Context, ev LabelEvent) error
}

// LabelForm — форма, измеряемая на пути меток.
type LabelForm interface {
	Name() string
	// Place — откуда сняты ячейки этой формы. Отчёт из двух мест без этого
	// признака выдаёт за один прогон два.
	Place() string
	// StmtProducer — чем и где считаются стейтменты этой формы и прошёл ли
	// производитель контроль в обе стороны.
	StmtProducer() ProducerStatus

	// ApplyRule записывает правило В ТОЙ ФОРМЕ, В КАКОЙ ОНО У НЕЁ СУЩЕСТВУЕТ:
	// у формы E — строки правила и выдачи.
	// Это и есть предмет L1.
	ApplyRule(ctx context.Context) (Counters, int, error)
	// DropRule снимает правило, не трогая общее. Нужен, чтобы повтор L1 мерил
	// первый ответ, а не идемпотентный повтор.
	DropRule(ctx context.Context) error

	// Settle — что форма ОБЯЗАНА сделать после уже закоммиченного общего
	// изменения, чтобы её ответ стал верным. У формы E ожидается ноль — и он
	// измеряется, а не объявляется.
	Settle(ctx context.Context, ev LabelEvent) (Counters, int, error)

	Check(ctx context.Context, subject, relation, objectID string) (bool, Counters, error)
	// Page сужает страницу кандидатов; возвращает число разрешённых и на сколько
	// частей страница была разложена.
	Page(ctx context.Context, subject, relation string, ids []string) (allowed, parts int, c Counters, err error)

	Teardown(ctx context.Context) error
}

// ── ячейка ────────────────────────────────────────────────────────────────────

// LabelCell — одна ячейка (форма, N, операция).
type LabelCell struct {
	Form    string
	Place   string
	N       int
	Op      LabelOp
	Outcome Outcome
	Reason  string

	Repeats            int
	P50, P95, Min, Max float64 // мс работы

	StmtSQL  int
	StmtNote string // непусто ⇒ величина НЕ измерена, здесь причина
	Rows     int
	Parts    int

	// Окно неверного ответа. Заполняется только у операций-событий.
	HasWindow  bool
	WindowP50  float64
	WindowP95  float64
	WindowMax  float64
	WindowMin  float64
	Polls      int
	Revocation bool
}

// ── прогон ────────────────────────────────────────────────────────────────────

// LabelConfig — повторы и бюджеты. Величины, у которых нет прод-аналога,
// заданы минимумом, которого требует методика, а не удобным числом.
type LabelConfig struct {
	WriteRepeats int
	ReadRepeats  int
	EventRepeats int
	// WindowBudget — сколько ждать верного ответа, прежде чем признать «не
	// выполнилось». Исчерпание бюджета НЕ печатается нулём.
	WindowBudget time.Duration
	// PollEvery — шаг опроса окна.
	PollEvery time.Duration
}

// DefaultLabelConfig — повторов ровно столько, сколько нужно для p95 на выборке,
// которую не стыдно назвать выборкой.
func DefaultLabelConfig() LabelConfig {
	return LabelConfig{
		WriteRepeats: 3,
		ReadRepeats:  10,
		EventRepeats: 5,
		WindowBudget: 60 * time.Second,
		PollEvery:    200 * time.Microsecond,
	}
}

// RunLabelPath снимает все операции пути меток для ОДНОЙ формы на ОДНОМ N.
//
// Порядок несущий: контроли → L1 (первый ответ) → установившееся чтение → события.
// Контроли идут первыми, потому что все остальные величины опираются на то, что
// форма отвечает правильно; замер, начатый без них, мерил бы скорость неверного
// ответа.
func RunLabelPath(ctx context.Context, w LabelWorld, f LabelForm, sc LabelScenario,
	cfg LabelConfig) []LabelCell {
	var out []LabelCell
	newCell := func(op LabelOp) *LabelCell {
		c := &LabelCell{Form: f.Name(), Place: f.Place(), N: sc.N, Op: op, Outcome: Measured,
			Revocation: IsRevocation(op)}
		if p := f.StmtProducer(); !p.OK {
			c.StmtNote = "производитель не прошёл контроль: " + p.Note
		}
		return c
	}
	failAll := func(reason string, ops ...LabelOp) {
		for _, op := range ops {
			c := newCell(op)
			c.Outcome, c.Reason = NotRun, reason
			out = append(out, *c)
		}
	}

	// L1 — ПЕРВЫЙ ОТВЕТ. Каждый повтор начинается со снятия правила: повтор по
	// уже написанному правилу мерил бы идемпотентную запись, а это другая
	// операция под тем же именем.
	first := newCell(LopFirstAnswer)
	var firstMs []float64
	for rep := 0; rep <= cfg.WriteRepeats; rep++ {
		if err := f.DropRule(ctx); err != nil {
			first.Outcome, first.Reason = classify(err)
			break
		}
		t0 := time.Now()
		cnt, rows, err := f.ApplyRule(ctx)
		if err != nil {
			first.Outcome, first.Reason = classify(err)
			break
		}
		ok, c2, err := f.Check(ctx, sc.Subjects[0], Verb(sc.Verbs[0]), sc.Object(sc.N/2))
		d := float64(time.Since(t0).Microseconds()) / 1000.0
		if err != nil {
			first.Outcome, first.Reason = classify(err)
			break
		}
		if !ok {
			first.Outcome = NotRun
			first.Reason = "первый ответ по написанному правилу — ОТКАЗ; форма не отвечает то, " +
				"что правило подразумевает, и её время было бы временем неверного ответа"
			break
		}
		if rep > 0 {
			firstMs = append(firstMs, d)
			first.StmtSQL = cnt.StmtSQL + c2.StmtSQL
			first.Rows = rows
		}
	}
	if first.Outcome == Measured {
		statsInto(first, firstMs)
	}
	out = append(out, *first)
	if first.Outcome != Measured {
		failAll("правило не написано: "+first.Reason,
			LopCheck, LopPage, LopRelabelIn, LopCreateInSet, LopRelabelOut, LopRevokeRule)
		return out
	}

	// КОНТРОЛИ. Обе стороны ответа, до первой читающей величины.
	if reason := labelControls(ctx, f, sc); reason != "" {
		failAll(reason, LopCheck, LopPage, LopRelabelIn, LopCreateInSet, LopRelabelOut, LopRevokeRule)
		return out
	}

	// D1 — вердикт в установившемся состоянии. Объекты берутся с большим простым
	// шагом, а не с начала: начало набора — самая тёплая часть индекса, и
	// дешевизна принадлежала бы выборке, а не форме.
	chk := newCell(LopCheck)
	var chkMs []float64
	for rep := 0; rep <= cfg.ReadRepeats; rep++ {
		obj := sc.Object((rep * 7919) % sc.N)
		t0 := time.Now()
		ok, c, err := f.Check(ctx, sc.Subjects[len(sc.Subjects)-1], Verb(sc.Verbs[0]), obj)
		d := float64(time.Since(t0).Microseconds()) / 1000.0
		if err != nil {
			chk.Outcome, chk.Reason = classify(err)
			break
		}
		if !ok {
			chk.Outcome, chk.Reason = NotRun, "объект набора получил ОТКАЗ — форма засеяна не тем, "+
				"что заявляет правило, и её время было бы временем отказа"
			break
		}
		if rep > 0 {
			chkMs = append(chkMs, d)
			chk.StmtSQL = c.StmtSQL
		}
	}
	if chk.Outcome == Measured {
		statsInto(chk, chkMs)
	}
	out = append(out, *chk)

	// D2 — страница договора, суженная тем же правилом.
	page := newCell(LopPage)
	ids := sc.Objects()
	if len(ids) > sc.PageSize {
		ids = ids[:sc.PageSize]
	}
	var pageMs []float64
	for rep := 0; rep <= cfg.ReadRepeats; rep++ {
		t0 := time.Now()
		allowed, parts, c, err := f.Page(ctx, sc.Subjects[len(sc.Subjects)-1], Verb(sc.Verbs[0]), ids)
		d := float64(time.Since(t0).Microseconds()) / 1000.0
		if err != nil {
			page.Outcome, page.Reason = classify(err)
			break
		}
		if allowed != len(ids) {
			page.Outcome = NotRun
			page.Reason = fmt.Sprintf("страница из %d объектов набора дала %d разрешений — "+
				"форма отвечает не то, что подразумевает правило, и её время было бы "+
				"временем неполного ответа", len(ids), allowed)
			break
		}
		if rep > 0 {
			pageMs = append(pageMs, d)
			page.StmtSQL, page.Parts, page.Rows = c.StmtSQL, parts, len(ids)
		}
	}
	if page.Outcome == Measured {
		statsInto(page, pageMs)
	}
	out = append(out, *page)

	// СОБЫТИЯ. Каждое — своим циклом: окно отсчитывается от коммита ОБЩЕГО
	// изменения, поэтому вторая форма не может мерить хвост работы первой.
	for _, ev := range []LabelEvent{
		{Kind: EventEntered, ObjectID: sc.SpareEnter(), Expect: true},
		{Kind: EventCreated, ObjectID: sc.SpareCreate(), Expect: true},
		{Kind: EventLeft, ObjectID: sc.SpareEnter(), Expect: false},
		{Kind: EventRuleRevoked, Expect: false},
	} {
		out = append(out, runLabelEvent(ctx, w, f, sc, cfg, ev, newCell))
	}
	return out
}

// runLabelEvent меряет одно событие: работу формы и окно неверного ответа.
func runLabelEvent(ctx context.Context, w LabelWorld, f LabelForm, sc LabelScenario,
	cfg LabelConfig, ev LabelEvent, newCell func(LabelOp) *LabelCell) LabelCell {
	c := newCell(opOf(ev.Kind))
	var work, window []float64
	subj := sc.Subjects[0]
	// Объект наблюдения: у отзыва правила это объект НАБОРА (правило снимается со
	// всех), у остальных — объект самого события.
	watch := ev.ObjectID
	if ev.Kind == EventRuleRevoked {
		watch = sc.Object(sc.N / 2)
	}

	for rep := 0; rep <= cfg.EventRepeats; rep++ {
		// Приведение к состоянию ДО события. Ошибка приведения — «не выполнилось»,
		// а не тихий пропуск повтора: замер на неприведённом мире мерил бы другой мир.
		if err := w.Revert(ctx, ev); err != nil {
			c.Outcome, c.Reason = NotRun, "приведение общего состояния: "+err.Error()
			return *c
		}
		if err := restoreForm(ctx, f, ev); err != nil {
			c.Outcome, c.Reason = NotRun, "приведение формы: "+err.Error()
			return *c
		}
		// Предусловие: до события ответ ПРОТИВОПОЛОЖЕН ожидаемому. Без него окно
		// «стало верно сразу» неотличимо от «было верно всегда».
		before, _, err := f.Check(ctx, subj, Verb(sc.Verbs[0]), watch)
		if err != nil {
			c.Outcome, c.Reason = classify(err)
			return *c
		}
		if before == ev.Expect {
			c.Outcome = NotRun
			c.Reason = fmt.Sprintf("до события ответ уже равен ожидаемому (%v) — окно этого события "+
				"неотличимо от нулевого при любой форме, и измерять было бы нечего", ev.Expect)
			return *c
		}

		t0, err := w.Commit(ctx, ev)
		if err != nil {
			c.Outcome, c.Reason = NotRun, "коммит общего изменения: "+err.Error()
			return *c
		}
		cnt, rows, err := f.Settle(ctx, ev)
		if err != nil {
			c.Outcome, c.Reason = classify(err)
			return *c
		}
		workMs := float64(time.Since(t0).Microseconds()) / 1000.0

		polls, winMs, err := awaitCorrect(ctx, f, sc, subj, watch, ev.Expect, t0, cfg)
		if err != nil {
			c.Outcome, c.Reason = NotRun, err.Error()
			return *c
		}
		if rep > 0 {
			work = append(work, workMs)
			window = append(window, winMs)
			c.StmtSQL, c.Rows = cnt.StmtSQL, rows
			c.Polls = polls
		}
	}

	statsInto(c, work)
	if len(window) > 0 {
		sort.Float64s(window)
		c.HasWindow = true
		c.WindowMin, c.WindowMax = window[0], window[len(window)-1]
		c.WindowP50, c.WindowP95 = pct(window, 0.50), pct(window, 0.95)
	}
	// Мир возвращается в исходное состояние, иначе следующее событие мерило бы
	// последствия предыдущего.
	if err := w.Revert(ctx, ev); err != nil && c.Outcome == Measured {
		c.Outcome, c.Reason = NotRun, "возврат общего состояния после замера: "+err.Error()
	}
	if err := restoreForm(ctx, f, ev); err != nil && c.Outcome == Measured {
		c.Outcome, c.Reason = NotRun, "возврат формы после замера: "+err.Error()
	}
	return *c
}

// restoreForm приводит форму к состоянию, которое событие ОТМЕНЯЕТ.
//
// Состояние «до» у каждого события своё, и подменять его одним общим значило бы
// мерить не то событие: у введения метки объект обязан быть ВНЕ набора, у её
// снятия — ВНУТРИ, у отзыва правила — правило обязано действовать.
func restoreForm(ctx context.Context, f LabelForm, ev LabelEvent) error {
	switch ev.Kind {
	case EventRuleRevoked:
		if err := f.DropRule(ctx); err != nil {
			return err
		}
		_, _, err := f.ApplyRule(ctx)
		return err
	case EventLeft:
		_, _, err := f.Settle(ctx, LabelEvent{Kind: EventEntered, ObjectID: ev.ObjectID, Expect: true})
		return err
	default:
		_, _, err := f.Settle(ctx, LabelEvent{Kind: EventLeft, ObjectID: ev.ObjectID, Expect: false})
		return err
	}
}

// awaitCorrect опрашивает форму до первого ответа, равного ожидаемому, и
// возвращает окно от t0.
//
// Исчерпание бюджета — ошибка с причиной, а не «окно равно бюджету»: величина,
// упёршаяся в собственный предел, о предмете не говорит ничего.
func awaitCorrect(ctx context.Context, f LabelForm, sc LabelScenario, subj, obj string,
	expect bool, t0 time.Time, cfg LabelConfig) (int, float64, error) {
	deadline := t0.Add(cfg.WindowBudget)
	polls := 0
	for {
		polls++
		got, _, err := f.Check(ctx, subj, Verb(sc.Verbs[0]), obj)
		if err != nil {
			return polls, 0, fmt.Errorf("опрос окна: %w", err)
		}
		if got == expect {
			return polls, float64(time.Since(t0).Microseconds()) / 1000.0, nil
		}
		if time.Now().After(deadline) {
			return polls, 0, fmt.Errorf("за %s ответ так и не стал верным (%d опросов) — "+
				"окно не измерено, и печатать вместо него бюджет значило бы выдать предел "+
				"прибора за свойство формы", cfg.WindowBudget, polls)
		}
		time.Sleep(cfg.PollEvery)
	}
}

// labelControls — два контроля до первой читающей величины. Пустая строка —
// оба пройдены.
func labelControls(ctx context.Context, f LabelForm, sc LabelScenario) string {
	stranger := "user:usr-stranger-not-in-any-binding"
	denied, _, err := f.Check(ctx, stranger, Verb(sc.Verbs[0]), sc.Object(0))
	if err != nil {
		return "контроль отказа не задан: " + err.Error()
	}
	if denied {
		return "отрицательный контроль не сработал: посторонний получил доступ к объекту набора — " +
			"«разрешено субъекту правила» здесь неотличимо от «разрешено всем»"
	}
	allowed, _, err := f.Check(ctx, sc.Subjects[0], Verb(sc.Verbs[0]), sc.Object(0))
	if err != nil {
		return "положительный контроль не задан: " + err.Error()
	}
	if !allowed {
		return "положительный контроль не сработал: субъект правила получил отказ на объекте набора — " +
			"форма отвечает «нет» и выиграла бы всякую читающую колонку, не тронув индекса"
	}
	return ""
}

func statsInto(c *LabelCell, ms []float64) {
	if len(ms) == 0 {
		if c.Outcome == Measured {
			c.Outcome, c.Reason = NotRun, "ни один повтор не дошёл до выборки"
		}
		return
	}
	s := append([]float64(nil), ms...)
	sort.Float64s(s)
	c.Repeats = len(s)
	c.Min, c.Max = s[0], s[len(s)-1]
	c.P50, c.P95 = pct(s, 0.50), pct(s, 0.95)
}

// ── производитель `StmtSQL` для формы, живущей в Postgres ─────────────────────

// SQLStmtCounter — счётчик стейтментов на СВОЁМ пуле pgx.
//
// Экспортируется потому, что сторона формы E живёт там, где достижимы её
// таблицы, а прибор — здесь. Своего счётчика там заводить нельзя: два счётчика
// одного предмета расходятся молча, и расходятся они как раз в ту сторону, где
// расхождение не видно.
type SQLStmtCounter struct{ tr *stmtTracer }

// NewSQLStmtCounter заводит счётчик.
func NewSQLStmtCounter() *SQLStmtCounter { return &SQLStmtCounter{tr: &stmtTracer{}} }

// Tracer — то, что вешается на конфигурацию пула.
func (c *SQLStmtCounter) Tracer() pgx.QueryTracer { return c.tr }

// StmtWindow — окно счёта.
type StmtWindow struct{ w stmtWindow }

// Open открывает окно.
func (c *SQLStmtCounter) Open() StmtWindow { return StmtWindow{w: c.tr.open()} }

// Close закрывает окно и возвращает число стейтментов.
func (s StmtWindow) Close() int { return s.w.close() }

// Verify прогоняет контроль в ОБЕ стороны на живом пуле и возвращает состояние
// производителя. Пока контроль не пройден, величина не печатается вовсе — ноль
// от несработавшего счётчика неотличим от измеренного нуля.
func (c *SQLStmtCounter) Verify(ctx context.Context, pool *pgxpool.Pool, place string) ProducerStatus {
	producer := "счётчик стейтментов на pgx.Tracer собственного пула"
	idle := c.Open()
	if n := idle.Close(); n != 0 {
		return ProducerStatus{Place: place, Producer: producer,
			Note: fmt.Sprintf("холостая дельта %d вместо 0 — счётчик мерит фон, а не операцию", n)}
	}
	one := c.Open()
	var x int
	if err := pool.QueryRow(ctx, `SELECT 1`).Scan(&x); err != nil {
		return ProducerStatus{Place: place, Producer: producer, Note: err.Error()}
	}
	if n := one.Close(); n != 1 {
		return ProducerStatus{Place: place, Producer: producer,
			Note: fmt.Sprintf("один стейтмент дал дельту %d вместо 1 — счётчик мерит не стейтменты", n)}
	}
	return ProducerStatus{Place: place, Producer: producer, OK: true,
		Note: "холостая дельта 0, один стейтмент дал 1"}
}

// ── отчёт ─────────────────────────────────────────────────────────────────────

// LabelReportInput — всё, что нужно отчёту, кроме самих ячеек.
type LabelReportInput struct {
	Prov     Provenance
	Scenario LabelScenario
	Config   LabelConfig
	Ns       []int
	// QueueNote — что стоит между коммитом метки и началом пересчёта у продукта,
	// прочитанное из дерева. ТЕКСТ, а не число: складывать его с измеренным окном
	// запрещено правилом отнесения п.7.
	QueueNote string
	// RunCommand — чем прогон воспроизводится. Замер без него не свидетельство.
	RunCommand string
	// RepeatSchedule — сколько повторов снято на каждом N. Печатается строкой, а
	// не одним числом: расписание, уменьшающееся с ростом N, обязано быть видно,
	// иначе p95 на одном образце читается как p95 на пяти.
	RepeatSchedule string
	Unmeasured     []string
}

// ReportLabelPath печатает отчёт пути меток.
//
// Порядок разделов: правило отнесения → провенанс → величины → окна → окна
// отзыва отдельно → неизмеренное. Правило первым потому, что число, прочитанное
// раньше правила, читатель отнесёт по своему.
func ReportLabelPath(w io.Writer, in LabelReportInput, cells []LabelCell) {
	// Первый отказ записи ОСТАНАВЛИВАЕТ вывод: иначе прибор, потерявший середину
	// отчёта, отдал бы усечённый текст, выглядящий полным. Саму ошибку эта функция
	// не возвращает — её сигнатура не позволяет, и это названо здесь, а не выдано
	// за обработку: вызывающий узнаёт об обрыве по неполноте отчёта, не по коду.
	var werr error
	p := func(f string, a ...any) {
		if werr != nil {
			return
		}
		_, werr = fmt.Fprintf(w, f, a...)
	}

	p("XC-12, Ф5: ПЕРЕЗАМЕР СТОИМОСТИ ПОЛНОМОДЕЛЬНОЙ ФОРМЫ — ПУТЬ МЕТОК\n")
	p("================================================================\n\n")
	p("%s\n", strings.TrimSpace(AttributionRule))
	p("\n\nПРОВЕНАНС\n---------\n")
	p("дата                %s\n", in.Prov.When)
	p("ревизия дерева      %s\n", in.Prov.TreeRev)
	p("машина              %s\n", in.Prov.Machine)
	p("Postgres            %s\n", in.Prov.Postgres)
	p("модель              %s (sha256/16 %s)\n", in.Prov.ModelPath, in.Prov.ModelDigest)
	// ОТПЕЧАТОК ПРИБОРА берётся ЗДЕСЬ, внутри писателя, а не передаётся
	// вызывающим: вызывающий этого отчёта живёт в чужом каталоге, и требование
	// «не забудь передать» держалось бы памятью, а не построением.
	p("%s", FingerprintHeader())
	// Здесь печатались образ движка отношений, образ его командной строки и
	// ИЗМЕРЕННЫЙ потолок его пакетной проверки. Все три сняты вместе с движком.
	// Потолок печатался только когда он в этом прогоне измерялся: прежняя редакция
	// печатала ноль с подписью «измерен у движка» — утверждение о замере, которого
	// не было, и притом самое правдоподобное на вид. Строки нет вовсе — это вернее,
	// чем прочерк: прочерк сообщал бы, что величину спрашивали.
	for _, ps := range in.Prov.StmtProducers {
		p("производитель       %s\n", ps.String())
	}
	p("\nсценарий            тип %s · N ∈ %v · глаголов M=%d %v · субъектов S=%d\n",
		in.Scenario.ObjectType, in.Ns, len(in.Scenario.Verbs), in.Scenario.Verbs, len(in.Scenario.Subjects))
	p("правило             отбор по метке {%s: %s} на область project:%s\n",
		in.Scenario.LabelKey, in.Scenario.LabelValue, in.Scenario.ProjectID)
	p("страница договора   %d · часть %d · частей в полёте %d\n",
		in.Scenario.PageSize, in.Scenario.Partition, in.Scenario.Parallelism)
	p("                    фактическая страница = min(N, %d); её размер стоит в колонке «строк»,\n",
		in.Scenario.PageSize)
	p("                    поэтому на N меньше страницы величина D2 относится к N объектам, а не к %d\n",
		in.Scenario.PageSize)
	p("повторов            %s (нулевой повтор прогревочный и в выборку не входит)\n", in.RepeatSchedule)
	p("бюджет окна         %s, шаг опроса %s\n", in.Config.WindowBudget, in.Config.PollEvery)
	p("воспроизведение     %s\n", in.RunCommand)
	p("\nРевизия выше — та, на которой прогон ИСПОЛНЯЛСЯ: правило отнесения и прибор\n")
	p("приехали своим коммитом РАНЬШЕ, а этот отчёт — отдельным коммитом ПОЗЖЕ. Порядок\n")
	p("виден по истории, и в этом его смысл: правило, впервые появившееся вместе с\n")
	p("числами, неотличимо от правила, подобранного под них.\n")

	p("\n\nРАБОТА: мс (p50 / p95), стейтментов SQL, строк намерения\n")
	p("---------------------------------------------------------------------------\n")
	p("%-28s %-30s %7s %6s %11s %11s %8s %9s\n",
		"операция", "форма", "N", "повт.", "p50 мс", "p95 мс", "стейтм.", "строк")
	for _, op := range labelOpsOrder {
		for _, c := range sortedCells(cells, op, in.Ns) {
			if c.Outcome != Measured {
				continue
			}
			p("%-28s %-30s %7d %6d %11.3f %11.3f %8s %9d\n",
				string(c.Op), shortForm(c.Form), c.N, c.Repeats, c.P50, c.P95, stmtCol(c), c.Rows)
		}
	}

	p("\n\nОКНО НЕВЕРНОГО ОТВЕТА: мс от коммита общего изменения до первого верного ответа\n")
	p("------------------------------------------------------------------------------\n")
	p("%-28s %-30s %7s %6s %11s %11s %11s %8s\n",
		"операция", "форма", "N", "повт.", "окно p50", "окно p95", "окно max", "опросов")
	for _, op := range labelOpsOrder {
		if IsRevocation(op) {
			continue
		}
		for _, c := range sortedCells(cells, op, in.Ns) {
			if c.Outcome != Measured || !c.HasWindow {
				continue
			}
			p("%-28s %-30s %7d %6d %11.3f %11.3f %11.3f %8d\n",
				string(c.Op), shortForm(c.Form), c.N, c.Repeats, c.WindowP50, c.WindowP95, c.WindowMax, c.Polls)
		}
	}

	p("\n\nОКНО ОТЗЫВА — ВЕЛИЧИНА ПРО БЕЗОПАСНОСТЬ, А НЕ ПРО СКОРОСТЬ\n")
	p("-----------------------------------------------------------\n")
	p("Сколько времени доступ остаётся у того, кто его уже потерял. Не усредняется\n")
	p("с окнами выдачи и не входит ни в какую сводную величину.\n\n")
	p("%-28s %-30s %7s %6s %11s %11s %11s\n",
		"операция", "форма", "N", "повт.", "окно p50", "окно p95", "окно max")
	for _, op := range labelOpsOrder {
		if !IsRevocation(op) {
			continue
		}
		for _, c := range sortedCells(cells, op, in.Ns) {
			if c.Outcome != Measured || !c.HasWindow {
				continue
			}
			p("%-28s %-30s %7d %6d %11.3f %11.3f %11.3f\n",
				string(c.Op), shortForm(c.Form), c.N, c.Repeats, c.WindowP50, c.WindowP95, c.WindowMax)
		}
	}
	p("\nЧЕГО ИЗМЕРЕННОЕ ОКНО ДВИЖКА НЕ СОДЕРЖИТ\n")
	p("%s\n", strings.TrimSpace(in.QueueNote))
	p("предикат: %s\n", QueuePredicate)

	// Категории исхода. Сумма обязана сходиться с числом ячеек — отчёт, полный по
	// собственному счёту, молчал бы о самых дорогих вопросах.
	byOutcome := map[Outcome]int{}
	for _, c := range cells {
		byOutcome[c.Outcome]++
	}
	p("\n\nИСХОДЫ ЯЧЕЕК\n------------\n")
	total := 0
	for _, o := range []Outcome{Measured, NotRun} {
		p("%-18s %d\n", string(o), byOutcome[o])
		total += byOutcome[o]
	}
	p("%-18s %d (обязана равняться числу ячеек: %d)\n", "сумма", total, len(cells))
	if byOutcome[NotRun] > 0 {
		p("\nячейки не-измеренных исходов, поимённо:\n")
		for _, c := range cells {
			if c.Outcome == Measured {
				continue
			}
			p("  %-28s %-30s N=%-7d %s: %s\n", string(c.Op), shortForm(c.Form), c.N, string(c.Outcome), c.Reason)
		}
	}

	if len(in.Unmeasured) > 0 {
		p("\n\nЧТО ОСТАЛОСЬ НЕИЗМЕРЕННЫМ И ПОЧЕМУ\n----------------------------------\n")
		for i, u := range in.Unmeasured {
			p("%d. %s\n", i+1, u)
		}
	}
}

func sortedCells(cells []LabelCell, op LabelOp, ns []int) []LabelCell {
	var out []LabelCell
	for _, n := range ns {
		for _, c := range cells {
			if c.Op == op && c.N == n {
				out = append(out, c)
			}
		}
	}
	return out
}

// shortForm подрезает имя формы по РУНАМ, а не по байтам: имена русские, и рез
// по байту разломал бы букву пополам — отчёт стал бы нечитаем ровно в колонке,
// по которой его читают.
func shortForm(form string) string {
	r := []rune(form)
	if len(r) <= 30 {
		return form
	}
	return string(r[:29]) + "…"
}

// stmtCol — колонка стейтментов. У формы, чей производитель контроль не прошёл,
// печатается причина, а не ноль: ноль от несработавшего счётчика неотличим от
// измеренного.
func stmtCol(c LabelCell) string {
	if c.StmtNote != "" {
		return "н/д"
	}
	return fmt.Sprintf("%d", c.StmtSQL)
}
