// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package shadowverdict

// offpath_test.go — пробы на то, что сравнение НЕ СТОИТ на пути живого запроса.
//
// Здесь уже была проба с этим предметом в заголовке —
// `TestCompare_OwnDeadlineDoesNotHoldTheCaller`, — и она закрепляла не то, что
// обещала. Её тело утверждало «вызывающего держали не дольше 150 мс» при сроке
// сверки 20 мс: такое утверждение остаётся зелёным при ЛЮБОМ сроке ниже порога,
// включая боевые 50 мс, то есть ровно на том дефекте, ради которого писалось.
// Класс назван в корпусе: проба закрепляет ОТВЕТ проверки, а не её МЕСТО.
//
// Пробы ниже утверждают место, и утверждают его ЛОГИЧЕСКИ, а не по часам:
// «сведение исхода вернулось РАНЬШЕ, чем форма E ответила». Такое утверждение не
// зависит ни от загрузки машины, ни от выбранной величины срока.

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// gatedAsker — форма E, которая не отвечает, пока проба её не отпустит, и НЕ
// СМОТРИТ на срок.
//
// Безразличие к сроку — не выдумка ради жёсткости пробы, а наблюдавшееся
// поведение: путь, снимающий транзакцию уже истёкшим контекстом, задерживается
// ровно так. Живой путь не вправе зависеть от того, соблюдает ли форма E свой
// срок, — иначе верхняя граница задержки назначена не нами.
type gatedAsker struct {
	gate  chan struct{}
	allow bool
	calls atomic.Int64
	// respectCtx — отвечать ошибкой, если срок вышел К МОМЕНТУ ответа. Нужен
	// пробе про уход вызывающего: форма, безразличная к контексту, отмену
	// вызывающего не заметила бы, и проба зеленела бы на сломанном.
	respectCtx bool
}

func (g *gatedAsker) wait(ctx context.Context) error {
	g.calls.Add(1)
	<-g.gate
	if g.respectCtx {
		return ctx.Err()
	}
	return nil
}

func (g *gatedAsker) Allowed(ctx context.Context, _, _, _, _ string, _ map[string]any) (bool, error) {
	if err := g.wait(ctx); err != nil {
		return false, err
	}
	return g.allow, nil
}

func (g *gatedAsker) Objects(ctx context.Context, _, _ string, _ []string, _ int) ([]string, bool, error) {
	if err := g.wait(ctx); err != nil {
		return nil, false, err
	}
	return nil, true, nil
}

func (g *gatedAsker) Subjects(ctx context.Context, _, _, _ string, _ int) ([]string, bool, error) {
	if err := g.wait(ctx); err != nil {
		return nil, false, err
	}
	return nil, true, nil
}

func (g *gatedAsker) Sources(ctx context.Context, _, _, _ string) ([]string, error) {
	if err := g.wait(ctx); err != nil {
		return nil, err
	}
	return nil, nil
}

// mustReturnPromptly требует, чтобы сведение исхода вернулось, НЕ дожидаясь
// формы E. Предел здесь не измеряет задержку — он лишь отделяет «вернулось» от
// «не вернулось никогда»: форма отпускается только в t.Cleanup.
func mustReturnPromptly(t *testing.T, what string, call func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { call(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s ждало ответа формы E — сравнение стоит НА ПУТИ живого запроса. "+
			"Форма вердикта, которая решений не принимает, не вправе задерживать ответ, "+
			"который от неё не зависит: пока она укладывается в свой срок, это незаметно, "+
			"а как только перестаёт — полный срок платит каждый запрос", what)
	}
}

// waitFor ждёт условия, а не времени.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("не дождались: %s", what)
}

// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДИКАТ 1 ЗАДАЧИ: срок сверки строго меньше бюджета чтения.

func TestShadowDeadlineStaysStrictlyUnderTheReadBudget(t *testing.T) {
	if DefaultTimeout >= ReadBudget {
		t.Fatalf("срок теневой сверки %v при бюджете чтения %v — механизм, который решений "+
			"НЕ ПРИНИМАЕТ, вправе задержать ответ дольше, чем весь бюджет операции, "+
			"ради которой он существует", DefaultTimeout, ReadBudget)
	}
}

// Срок держится МЕХАНИЗМОМ, а не намерением (ban #10): значение с бюджетом или
// выше не принимается вовсе. Рядом — положительный контроль: законная величина
// принимается, иначе «отвергнуто» было бы неотличимо от «ручка не работает».
func TestShadowDeadlineAtOrAboveTheBudgetIsRefused(t *testing.T) {
	refused := New(&stubAsker{}, quiet()).WithTimeout(ReadBudget)
	if refused.timeout != DefaultTimeout {
		t.Errorf("срок %v принят при бюджете %v — ограничение держится комментарием, а не механизмом",
			refused.timeout, ReadBudget)
	}
	legal := ReadBudget / 3
	accepted := New(&stubAsker{}, quiet()).WithTimeout(legal)
	if accepted.timeout != legal {
		t.Errorf("законная величина %v не принята (стало %v) — проверка ловит форму, а не существо",
			legal, accepted.timeout)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ ЗАДАЧИ: сведение исхода не ждёт форму E — и сравнение всё равно
// состоится.
//
// Два утверждения в одной пробе намеренно: «не ждём» достигается и отменой
// сверки, и это была бы починка, уничтожившая предмет. Второе утверждение
// закрывает такой исход.

func TestSettleLeavesTheLivePathAndTheComparisonStillHappens(t *testing.T) {
	gate := make(chan struct{})
	form := &gatedAsker{gate: gate, allow: true}
	c := New(form, quiet())

	settle := c.Ask(context.Background(), "user:usr-1", "vpc_network", "net-1", "v_get", nil)
	mustReturnPromptly(t, "сведение прямого вердикта", func() { settle(true, true) })

	// Форма E отвечает уже ПОСЛЕ того, как живой путь ушёл.
	close(gate)
	waitFor(t, "сравнение состоялось вне живого пути", func() bool {
		return c.Counters().Compared == 1
	})
	if got := c.Counters(); got.Diverged != 0 {
		t.Errorf("согласие записано расхождением: %+v", got)
	}
}

// То же для перечислительных вопросов: у них своя механика (`askSet`), и класс
// не закрывается починкой одного прямого вердикта.
func TestSettleLeavesTheLivePathForSetQuestionsToo(t *testing.T) {
	for _, tc := range []struct {
		name string
		ask  func(*Comparator, context.Context) func([]string, bool, bool)
	}{
		{"перечисление объектов", func(c *Comparator, ctx context.Context) func([]string, bool, bool) {
			return c.AskObjects(ctx, "user:usr-1", "vpc_network", []string{"v_list"})
		}},
		{"перечисление субъектов", func(c *Comparator, ctx context.Context) func([]string, bool, bool) {
			return c.AskSubjects(ctx, "vpc_network", "net-1", "v_get")
		}},
		{"разворот отношений", func(c *Comparator, ctx context.Context) func([]string, bool, bool) {
			return c.AskSources(ctx, "vpc_network", "net-1", "v_get")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate := make(chan struct{})
			form := &gatedAsker{gate: gate}
			c := New(form, quiet())
			settle := tc.ask(c, context.Background())
			mustReturnPromptly(t, "сведение «"+tc.name+"»", func() { settle(nil, true, true) })
			close(gate)
			waitFor(t, "сравнение «"+tc.name+"» состоялось вне живого пути", func() bool {
				return c.Counters().Compared == 1
			})
		})
	}
}

// Уход вызывающего НЕ отменяет сравнение.
//
// gRPC отменяет контекст обработчика ровно тогда, когда обработчик вернулся, —
// то есть сразу после сведения. Теневой запрос, унаследовавший эту отмену, стал
// бы «не выполнилось» на КАЖДОМ решении, и «не ждём живой путь» было бы куплено
// тем, что сравнения не стало. Срок у теневого вызова свой И отмена своя.
func TestComparisonSurvivesTheCallerGoingAway(t *testing.T) {
	gate := make(chan struct{})
	form := &gatedAsker{gate: gate, allow: true, respectCtx: true}
	c := New(form, quiet())

	ctx, cancel := context.WithCancel(context.Background())
	settle := c.Ask(ctx, "user:usr-1", "vpc_network", "net-1", "v_get", nil)
	mustReturnPromptly(t, "сведение прямого вердикта", func() { settle(true, true) })
	cancel() // обработчик вернулся

	close(gate)
	waitFor(t, "сравнение пережило уход вызывающего", func() bool {
		return c.Counters().Compared == 1
	})
	if got := c.Counters(); got.Unfinished != 0 {
		t.Errorf("уход вызывающего засчитан «не выполнилось»: %+v — тогда «сравнение не "+
			"держит живой путь» означало бы «сравнения больше нет»", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ЦЕНА СНЯТИЯ ОЖИДАНИЯ: без ожидания живой путь перестаёт быть тормозом для
// теневого, и теневая работа растёт вместе с нагрузкой. Значит нужен потолок —
// иначе обрыв по задержке меняется на обрыв по соединениям, и лекарство
// сохраняет свой отказ.

func TestSaturatedComparisonShedsInsteadOfGrowingWithoutBound(t *testing.T) {
	gate := make(chan struct{})
	t.Cleanup(func() { close(gate) })
	form := &gatedAsker{gate: gate, allow: true}
	c := New(form, quiet())

	for i := 0; i < DefaultMaxInFlight; i++ {
		c.Ask(context.Background(), "user:usr-1", "vpc_network", "net-1", "v_get", nil)
	}
	waitFor(t, "все слоты заняты", func() bool {
		return form.calls.Load() == int64(DefaultMaxInFlight)
	})

	// Следующий вопрос обязан быть ОТБРОШЕН, а не встать в очередь.
	settle := c.Ask(context.Background(), "user:usr-1", "vpc_network", "net-2", "v_get", nil)
	mustReturnPromptly(t, "сведение сверх потолка", func() { settle(true, true) })

	got := c.Counters()
	if got.Unfinished != 1 {
		t.Errorf("отброшенное сравнение не попало в корзину «не выполнилось»: %+v — "+
			"невидимый сброс делает долю сравнённого лучше, ничего не улучшив", got)
	}
	if got.Decisions != int64(DefaultMaxInFlight)+1 {
		t.Errorf("отброшенное решение выпало из знаменателя: %+v", got)
	}
	if n := form.calls.Load(); n != int64(DefaultMaxInFlight) {
		t.Errorf("форму E спросили %d раз при потолке %d — потолка нет", n, DefaultMaxInFlight)
	}
}
