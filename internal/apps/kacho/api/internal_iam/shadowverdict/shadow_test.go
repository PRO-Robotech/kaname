// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package shadowverdict

// shadow_test.go — сравнение считает три исхода раздельно и не влияет на ответ.
//
// # Почему инъекция ПОДЛОЖНЫМ расхождением обязательна
//
// Сравнитель, который всегда молчит, выглядит ровно как сравнитель, у которого
// нет расхождений. Отличить их можно единственным способом: подсунуть форму,
// заведомо отвечающую иначе, и увидеть, что счётчик расхождений вырос, а запись
// в журнале назвала вопрос. Без этого «ноль расхождений» — утверждение о тишине,
// а не о согласии.

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"
)

// stubAsker — форма E с заданным ответом.
type stubAsker struct {
	allow bool
	err   error
	delay time.Duration
	calls int
}

func (s *stubAsker) Allowed(ctx context.Context, _, _, _, _ string) (bool, error) {
	s.calls++
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	return s.allow, s.err
}

func quiet() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// Согласие: счётчик сравнений растёт, расхождений — нет.
func TestCompare_AgreementCountsAsComparedOnly(t *testing.T) {
	c := New(&stubAsker{allow: true}, quiet())
	c.Compare(context.Background(), true, "user:usr-1", "vpc_network", "net-1", "get")

	got := c.Counters()
	if got.Compared != 1 || got.Diverged != 0 || got.Unfinished != 0 {
		t.Fatalf("счётчики = %+v, ожидалось сравнений 1, расхождений 0, невыполненных 0", got)
	}
}

// ИНЪЕКЦИЯ: форма отвечает иначе — расхождение обязано быть посчитано.
//
// Это направление и доказывает, что сравнитель вообще способен покраснеть.
func TestCompare_InjectedDivergenceIsCounted(t *testing.T) {
	c := New(&stubAsker{allow: false}, quiet())
	c.Compare(context.Background(), true, "user:usr-1", "vpc_network", "net-1", "get")

	got := c.Counters()
	if got.Diverged != 1 {
		t.Fatalf("подложное расхождение не посчитано: %+v — сравнитель, который всегда "+
			"молчит, неотличим от сравнителя без расхождений", got)
	}
	if got.Compared != 1 {
		t.Errorf("расхождение обязано считаться и как СРАВНЕНИЕ: %+v — иначе доля "+
			"расхождений не вычислима", got)
	}
}

// Ошибка формы — третья корзина, ни согласие, ни расхождение.
func TestCompare_ErrorIsItsOwnBucket(t *testing.T) {
	c := New(&stubAsker{err: errors.New("БД недоступна")}, quiet())
	c.Compare(context.Background(), true, "user:usr-1", "vpc_network", "net-1", "get")

	got := c.Counters()
	if got.Unfinished != 1 {
		t.Fatalf("ошибка не попала в свою корзину: %+v", got)
	}
	if got.Compared != 0 || got.Diverged != 0 {
		t.Errorf("ошибка засчитана сравнением или расхождением: %+v — первое объявляет "+
			"сравнение состоявшимся там, где его не было; второе топит настоящие "+
			"расхождения в шуме недоступной БД", got)
	}
}

// Срок СВОЙ: медленная форма не задерживает вызывающего дольше срока сравнения.
func TestCompare_OwnDeadlineDoesNotHoldTheCaller(t *testing.T) {
	form := &stubAsker{allow: true, delay: 200 * time.Millisecond}
	c := New(form, quiet()).WithTimeout(20 * time.Millisecond)

	start := time.Now()
	c.Compare(context.Background(), true, "user:usr-1", "vpc_network", "net-1", "get")
	elapsed := time.Since(start)

	if elapsed > 150*time.Millisecond {
		t.Fatalf("сравнение держало вызывающего %v — теневой вызов обязан иметь СВОЙ срок, "+
			"иначе наблюдение меняет наблюдаемое: медленный теневой запрос превращается в "+
			"медленный Check", elapsed)
	}
	if got := c.Counters(); got.Unfinished != 1 {
		t.Errorf("исчерпание срока не попало в корзину «не выполнилось»: %+v", got)
	}
}

// Выключенное сравнение — дешёвый no-op, а не паника и не ложные счётчики.
func TestCompare_DisabledIsANoOp(t *testing.T) {
	c := New(nil, quiet())
	c.Compare(context.Background(), true, "user:usr-1", "vpc_network", "net-1", "get")
	if got := c.Counters(); got != (Snapshot{}) {
		t.Fatalf("выключенное сравнение что-то посчитало: %+v — «ноль расхождений» тогда "+
			"означало бы «сравнение не работает»", got)
	}
	// И на nil-приёмнике: сборка без сравнителя ведёт себя как прежняя.
	var nilComparator *Comparator
	nilComparator.Compare(context.Background(), true, "s", "t", "i", "v")
}
