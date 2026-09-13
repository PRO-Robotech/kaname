// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package subjectchange_test

// revocation_closes_streams_test.go — чтение отзыва закрывает поток (kacho#1022).
//
// Перепрос — ЕДИНСТВЕННЫЙ путь, которым отзыв доезжает до открытых соединений:
// толчок от владельца прав снят вместе с обратным ребром (kacho#1024), и других
// имён реплика не получает ниоткуда. Читатель, имена субъектов выбрасывающий,
// закрыть поток не может ни при каких условиях — то есть отзыв не имеет действия
// на длинных соединениях вовсе.

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/pkg/subjectchange"
)

// closerStub — реестр открытых потоков на стенде.
type closerStub struct {
	mu       sync.Mutex
	closed   []string
	sweeps   int
	perClose int
}

func (c *closerStub) CloseSubject(subject string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = append(c.closed, subject)
	return c.perClose
}

func (c *closerStub) CloseAll() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweeps++
	return c.perClose
}

func (c *closerStub) snapshot() ([]string, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.closed...), c.sweeps
}

// subjectPoller отдаёт заготовленные порции ИМЕНОВАННЫХ изменений.
type subjectPoller struct {
	mu      sync.Mutex
	batches [][]subjectchange.SubjectChange
	errs    []error
	calls   int
	limits  []int32
	// sinces — курсор, НАБЛЮДЁННЫЙ на каждом перепросе. Записывается затем, что
	// «читатель пересел» иначе неотличимо от «читатель остался»: обе полосы
	// зовут источник, и различает их только поданная позиция.
	sinces []int64
}

func (p *subjectPoller) PollSubjectChanges(
	_ context.Context, since int64, limit int32,
) ([]subjectchange.SubjectChange, int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.limits = append(p.limits, limit)
	p.sinces = append(p.sinces, since)
	i := p.calls
	p.calls++
	if i < len(p.errs) && p.errs[i] != nil {
		return nil, 0, p.errs[i]
	}
	var b []subjectchange.SubjectChange
	if i < len(p.batches) {
		b = p.batches[i]
	}
	var head int64
	for _, c := range b {
		if c.ID > head {
			head = c.ID
		}
	}
	return b, head, nil
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// TestPolledRevocationClosesExactlyTheNamedSubjects — радиус полосы перепроса.
//
// Положительный контроль и отрицание стоят в одной пробе: названный субъект
// закрыт, неназванный не тронут. Одно отрицание зеленело бы на устройстве,
// которое не закрывает никого.
func TestPolledRevocationClosesExactlyTheNamedSubjects(t *testing.T) {
	p := &subjectPoller{batches: [][]subjectchange.SubjectChange{
		{{ID: 7, Subject: "user:usr-a"}},
		{{ID: 9, Subject: "user:usr-b"}, {ID: 10, Subject: "service_account:sva-c"}},
	}}
	closer := &closerStub{perClose: 1}
	var flushes int
	w := newWatcher(t, p, func() { flushes++ }, closer)

	w.Poll(context.Background()) // праймящий: курсор принимается, отзывом не является
	if closed, _ := closer.snapshot(); len(closed) != 0 {
		t.Fatalf("праймящий перепрос закрыл потоки %v — принятие курсора отзывом не является", closed)
	}

	w.Poll(context.Background())
	closed, _ := closer.snapshot()
	if len(closed) != 2 || closed[0] != "user:usr-b" || closed[1] != "service_account:sva-c" {
		t.Fatalf("закрыты %v, ожидались ровно названные порцией субъекты", closed)
	}
	if flushes != 1 {
		t.Errorf("сбросов кэша %d, ожидался 1 — закрытие потоков не отменяет сброса кэша", flushes)
	}
}

// TestPolledRevocationNamesEachSubjectOnce — повтор имени в одной порции не
// умножает закрытий: закрытие идемпотентно, но лишний обход реестра под замком
// стоит ровно столько же, сколько нужный.
func TestPolledRevocationNamesEachSubjectOnce(t *testing.T) {
	p := &subjectPoller{batches: [][]subjectchange.SubjectChange{
		{{ID: 1, Subject: "user:usr-a"}},
		{
			{ID: 2, Subject: "user:usr-a"},
			{ID: 3, Subject: "user:usr-a"},
			{ID: 4, Subject: ""},
		},
	}}
	closer := &closerStub{}
	w := newWatcher(t, p, func() {}, closer)
	w.Poll(context.Background())
	w.Poll(context.Background())

	closed, _ := closer.snapshot()
	if len(closed) != 1 || closed[0] != "user:usr-a" {
		t.Fatalf("закрыты %v, ожидалось одно закрытие «user:usr-a» (пустое имя отсекается безусловно)", closed)
	}
}

// TestUnreadableRevocationClosesEverything — FAIL-CLOSED.
//
// Неполученный ответ авторитета отзыва НЕ есть «прав не отзывали». Реплика,
// потерявшая читателя дольше объявленного срока, не вправе держать потоки: она
// больше не может утверждать, что чьи-то права целы.
func TestUnreadableRevocationClosesEverything(t *testing.T) {
	down := errors.New("iam недоступен")
	p := &subjectPoller{
		batches: [][]subjectchange.SubjectChange{{{ID: 1, Subject: "user:usr-a"}}},
		errs:    []error{nil, down, down, down, down},
	}
	closer := &closerStub{perClose: 2}
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	w := newWatcherAt(t, p, func() {}, closer, 10*time.Second, clock.Now)

	w.Poll(context.Background()) // праймящий успех: читатель подтверждён
	if _, sweeps := closer.snapshot(); sweeps != 0 {
		t.Fatalf("подтверждённый читатель дал %d сплошных закрытий, ожидался 0", sweeps)
	}

	// Отказ в пределах срока — ещё не утверждение о потере читателя.
	clock.advance(4 * time.Second)
	w.Poll(context.Background())
	if _, sweeps := closer.snapshot(); sweeps != 0 {
		t.Fatalf("отказ внутри объявленного срока дал %d сплошных закрытий, ожидался 0", sweeps)
	}

	// Срок исчерпан — потоки закрываются, и закрываются на КАЖДОМ последующем
	// отказе: клиент, переоткрывшийся в середине аварии, обязан закрыться тоже.
	clock.advance(7 * time.Second)
	w.Poll(context.Background())
	w.Poll(context.Background())
	if _, sweeps := closer.snapshot(); sweeps != 2 {
		t.Fatalf("сплошных закрытий %d, ожидалось 2 — по одному на каждый отказ за сроком", sweeps)
	}

	if closed, _ := closer.snapshot(); len(closed) != 0 {
		t.Errorf("сплошное закрытие тронуло поимённые %v — у него нет имён, оно закрывает всех", closed)
	}
}

// TestRecoveredReaderStopsSweeping — срок отсчитывается от ПОСЛЕДНЕГО удачного
// чтения, а не от старта: восстановившийся читатель снимает fail-closed.
func TestRecoveredReaderStopsSweeping(t *testing.T) {
	down := errors.New("iam недоступен")
	p := &subjectPoller{
		batches: [][]subjectchange.SubjectChange{{{ID: 1, Subject: "user:usr-a"}}, nil, nil, nil},
		errs:    []error{nil, down, nil, nil},
	}
	closer := &closerStub{perClose: 1}
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	w := newWatcherAt(t, p, func() {}, closer, 10*time.Second, clock.Now)

	w.Poll(context.Background()) // праймящий успех
	clock.advance(20 * time.Second)
	w.Poll(context.Background()) // отказ за сроком → сплошное закрытие
	if _, sweeps := closer.snapshot(); sweeps != 1 {
		t.Fatalf("сплошных закрытий %d, ожидалось 1", sweeps)
	}

	w.Poll(context.Background()) // успех: читатель подтверждён заново
	clock.advance(5 * time.Second)
	w.Poll(context.Background()) // отказа нет, срок не исчерпан
	if _, sweeps := closer.snapshot(); sweeps != 1 {
		t.Fatalf("сплошных закрытий %d после восстановления читателя, ожидалось 1", sweeps)
	}
}

// TestMissingCloserIsRefusedAtStartup — провязка закрывателя не бывает
// необязательной.
//
// Инъекция показала, ПОЧЕМУ: передай в точке сборки ноль — и весь корпус проб
// края остаётся зелёным, код собирается, а отзыв перестаёт доезжать до потоков
// совсем. Несделанная провязка была бы неотличима от сделанной — и неотличима
// именно тем механизмом, ради которого задача заведена.
func TestMissingCloserIsRefusedAtStartup(t *testing.T) {
	_, err := subjectchange.New(subjectchange.Config{
		Poller: &subjectPoller{}, Flush: func() {}, Interval: time.Second,
		Closer: nil, StaleAfter: 30 * time.Second, Logger: quietLogger(),
	})
	if err == nil {
		t.Fatal("наблюдатель без реестра открытых потоков собрался — отзыв не доезжал бы до них вовсе")
	}
}

// TestWiredCloserIsVisibleInTheSelfReport — самоотчёт ОБЯЗАН быть наблюдением.
//
// Литерал `true` продолжал бы утверждать «закрывает потоки» при отключённом
// закрывателе, то есть был бы ровно тем классом, ради которого задача заведена.
func TestWiredCloserIsVisibleInTheSelfReport(t *testing.T) {
	w := newWatcherAt(t, &subjectPoller{}, func() {}, &closerStub{}, 30*time.Second, time.Now)
	if !w.ClosesStreams() {
		t.Fatal("провязанный закрыватель не виден в самоотчёте")
	}
	if got := w.StaleAfter(); got != 30*time.Second {
		t.Fatalf("срок в самоотчёте %v, объявлено 30s", got)
	}
}

// TestStaleBudgetIsRefusedAtStartup — величина, при которой fail-closed не
// наступает никогда, отвергается на сборке, а не первым отказом в бою.
func TestStaleBudgetIsRefusedAtStartup(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  subjectchange.Config
	}{
		{
			name: "закрыватель без объявленного срока",
			cfg: subjectchange.Config{
				Poller: &subjectPoller{}, Flush: func() {}, Interval: time.Second,
				Closer: &closerStub{}, StaleAfter: 0, Logger: quietLogger(),
			},
		},
		{
			name: "срок не превосходит перепроса",
			cfg: subjectchange.Config{
				Poller: &subjectPoller{}, Flush: func() {}, Interval: 10 * time.Second,
				Closer: &closerStub{}, StaleAfter: 10 * time.Second, Logger: quietLogger(),
			},
		},
		{
			name: "нет источника",
			cfg: subjectchange.Config{
				Poller: nil, Flush: func() {}, Interval: time.Second, Logger: quietLogger(),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := subjectchange.New(tc.cfg); err == nil {
				t.Fatal("негодное объявление принято сборкой")
			}
		})
	}
}

// testClock — управляемые часы: срок fail-closed измеряется решением, а не тем,
// сколько успела проработать проба на занятой машине.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newWatcher(
	t *testing.T, p subjectchange.Poller, flush func(), closer subjectchange.StreamCloser,
) *subjectchange.Watcher {
	t.Helper()
	return newWatcherAt(t, p, flush, closer, 30*time.Second, time.Now)
}

func newWatcherAt(
	t *testing.T, p subjectchange.Poller, flush func(), closer subjectchange.StreamCloser,
	staleAfter time.Duration, now func() time.Time,
) *subjectchange.Watcher {
	t.Helper()
	w, err := subjectchange.New(subjectchange.Config{
		Poller:     p,
		Flush:      flush,
		Interval:   time.Second,
		Closer:     closer,
		StaleAfter: staleAfter,
		Now:        now,
		Logger:     quietLogger(),
	})
	if err != nil {
		t.Fatalf("сборка наблюдателя: %v", err)
	}
	return w
}

// TestTruncatedBatchDoesNotSkipUnreadRevocations — B1.
//
// # Что здесь ловится
//
// Курсор поднимался до общего максимума ТАБЛИЦЫ (`headID`) и поднимался
// безусловно. При заделе больше порции он перепрыгивал через непрочитанные
// строки, и субъекты этих строк не назывались бы НИКОГДА. Для сплошного сброса
// кэша это было безвредно; для поимённого закрытия потоков это потеря отзыва —
// и срабатывает она ровно при массовом отзыве, то есть в том случае, ради
// которого механизм заведён.
//
// Стенд отдаёт ПОЛНУЮ порцию (по объявленному пределу), а `headID` называет
// строку далеко за ней. Утверждается исход: субъект непрочитанной строки закрыт.
func TestTruncatedBatchDoesNotSkipUnreadRevocations(t *testing.T) {
	full := func(base int64, n int) []subjectchange.SubjectChange {
		out := make([]subjectchange.SubjectChange, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, subjectchange.SubjectChange{ID: base + int64(i), Subject: "user:usr-bulk"})
		}
		return out
	}
	p := &truncatingPoller{
		first:  full(1, 1000),
		second: []subjectchange.SubjectChange{{ID: 1001, Subject: "user:usr-tail"}},
		head:   1001,
	}
	closer := &closerStub{perClose: 1}
	w := newWatcher(t, p, func() {}, closer)

	w.Poll(context.Background()) // праймящий
	w.Poll(context.Background()) // полная порция + добор хвоста

	closed, _ := closer.snapshot()
	var sawTail bool
	for _, s := range closed {
		if s == "user:usr-tail" {
			sawTail = true
		}
	}
	if !sawTail {
		t.Fatalf("закрыты %v — субъект строки ЗА пределом порции не назван: "+
			"курсор перепрыгнул через непрочитанное, и его отзыв потерян навсегда", closed)
	}
	if p.limits[0] != 1000 {
		t.Errorf("предел порции запрошен как %d — решение об усечении принимается по нему", p.limits[0])
	}
}

// truncatingPoller — первая порция ПОЛНАЯ (по пределу), вторая короткая.
type truncatingPoller struct {
	mu     sync.Mutex
	first  []subjectchange.SubjectChange
	second []subjectchange.SubjectChange
	head   int64
	calls  int
	limits []int32
}

func (p *truncatingPoller) PollSubjectChanges(
	_ context.Context, since int64, limit int32,
) ([]subjectchange.SubjectChange, int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.limits = append(p.limits, limit)
	i := p.calls
	p.calls++
	if i == 0 {
		// Праймящий идёт по ПУСТОЙ таблице: строки появляются после него.
		// Отдай здесь голову — курсор принял бы её, и проба мерила бы приём
		// курсора, а не потерю непрочитанного.
		return nil, 0, nil
	}
	switch {
	case since < 1000:
		return p.first, p.head, nil
	case since < p.head:
		return p.second, p.head, nil
	default:
		return nil, p.head, nil
	}
}

// sinceAt — курсор, поданный на (считая с нуля) n-м перепросе; -1, если такого
// перепроса не было.
func (p *subjectPoller) sinceAt(n int) int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n < 0 || n >= len(p.sinces) {
		return -1
	}
	return p.sinces[n]
}
