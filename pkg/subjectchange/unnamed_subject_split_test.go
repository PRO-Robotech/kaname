// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package subjectchange_test

// unnamed_subject_split_test.go — норма и дефект считаются РАЗДЕЛЬНО (kacho#1463).
//
// # Что здесь утверждается и почему одного числа было мало
//
// Строка, чьего субъекта назвать не удалось, приходит по двум несравнимым
// причинам: субъект выдан ГРУППЕ (норма — потоков по множеству участников не
// заводится) либо производитель имя ПОТЕРЯЛ (дефект — отзыв не доедет до
// потока). Под одним счётчиком величина ненулевая в штатной работе, поэтому
// тревогу на неё повесить нельзя и дефект остаётся в шуме нормы.
//
// Обе стороны утверждаются одной порцией намеренно: проба, подающая только
// группу, зеленела бы на устройстве, которое не считает ничего, — а проба,
// подающая только безымянную строку, зеленела бы на устройстве, которое всё
// зовёт дефектом.

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/authz"
	"github.com/PRO-Robotech/kaname/pkg/subjectchange"
)

// recordingHandler — журнал процесса, запоминающий записи с их полями.
//
// Наблюдаемое здесь — ЗАПИСЬ ЖУРНАЛА, а не возвращаемое значение: величина,
// которую оператор не может прочитать, наблюдением не является.
type recordingHandler struct {
	mu      sync.Mutex
	records []loggedRecord
}

type loggedRecord struct {
	level slog.Level
	msg   string
	attrs map[string]int64
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	rec := loggedRecord{level: r.Level, msg: r.Message, attrs: map[string]int64{}}
	r.Attrs(func(a slog.Attr) bool {
		if v, ok := a.Value.Any().(int); ok {
			rec.attrs[a.Key] = int64(v)
			return true
		}
		if a.Value.Kind() == slog.KindInt64 {
			rec.attrs[a.Key] = a.Value.Int64()
		}
		return true
	})
	h.mu.Lock()
	h.records = append(h.records, rec)
	h.mu.Unlock()
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingHandler) find(msg string) (loggedRecord, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var found loggedRecord
	n := 0
	for _, r := range h.records {
		if r.msg == msg {
			found = r
			n++
		}
	}
	return found, n
}

// scriptedPoller отдаёт заготовленные порции ЦЕЛИКОМ, вместе с именами.
//
// Существующий `fakePoller` строит строки по одному номеру и имени не несёт —
// он писался про курсор. Здесь предмет именно имя, поэтому порция задаётся
// дословно.
type scriptedPoller struct {
	mu      sync.Mutex
	batches [][]subjectchange.SubjectChange
	calls   int
}

func (p *scriptedPoller) PollSubjectChanges(
	_ context.Context, _ int64, _ int32,
) ([]subjectchange.SubjectChange, int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	i := p.calls
	p.calls++
	if i >= len(p.batches) {
		return nil, 0, nil
	}
	b := p.batches[i]
	var head int64
	for _, c := range b {
		if c.ID > head {
			head = c.ID
		}
	}
	return b, head, nil
}

// TestUnnamedSubjectsAreCountedApartFromUsersetKinds — две величины вместо одной.
func TestUnnamedSubjectsAreCountedApartFromUsersetKinds(t *testing.T) {
	handler := &recordingHandler{}
	poller := &scriptedPoller{batches: [][]subjectchange.SubjectChange{
		// Праймящий проход: курсор принимается, сброса нет.
		{{ID: 1, Subject: "user:usr00000000000000009", Naming: authz.SubjectNamed}},
		{
			{ID: 2, Subject: "user:usr00000000000000001", Naming: authz.SubjectNamed},
			// НОРМА: выдача группе; потоков по ней не заводится.
			{ID: 3, Subject: "", Naming: authz.SubjectUserset},
			// ДЕФЕКТ: производитель не назвал тип, имя потеряно.
			{ID: 4, Subject: "", Naming: authz.SubjectUnnameable},
		},
	}}
	closer := &closerStub{perClose: 1}

	w, err := subjectchange.New(subjectchange.Config{
		Poller:     poller,
		Flush:      func() {},
		Closer:     closer,
		Interval:   time.Second,
		StaleAfter: time.Minute,
		Logger:     slog.New(handler),
	})
	if err != nil {
		t.Fatalf("сборка читателя: %v", err)
	}

	w.Poll(context.Background()) // праймящий
	w.Poll(context.Background()) // разбираемая порция

	rec, n := handler.find("authz decision-cache flushed by subject-change poll")
	if n != 1 {
		t.Fatalf("записей о сбросе %d, ожидалась 1", n)
	}

	usersets, hasUsersets := rec.attrs["usersets_skipped"]
	unnamed, hasUnnamed := rec.attrs["subjects_unnamed"]
	if !hasUsersets || !hasUnnamed {
		t.Fatalf("запись несёт поля %v — норма и дефект обязаны называться РАЗДЕЛЬНО, "+
			"иначе тревогу повесить не на что", rec.attrs)
	}
	if usersets != 1 {
		t.Errorf("usersets_skipped=%d, ожидалась 1 (строка, выданная группе)", usersets)
	}
	if unnamed != 1 {
		t.Errorf("subjects_unnamed=%d, ожидалась 1 (строка, чьё имя потерял производитель)", unnamed)
	}
	if closed := rec.attrs["streams_closed"]; closed != 1 {
		t.Errorf("streams_closed=%d, ожидалась 1 — названный субъект обязан закрываться по-прежнему", closed)
	}
}

// TestUsersetKindAloneRaisesNoAlarm — законный близнец: на одной норме тревоги нет.
//
// Без него жалоба на дефект зеленела бы на устройстве, которое жалуется всегда,
// — то есть на пороге, срабатывающем в штатной работе. Ровно та беда, ради
// которой счётчик и разделён.
func TestUsersetKindAloneRaisesNoAlarm(t *testing.T) {
	handler := &recordingHandler{}
	poller := &scriptedPoller{batches: [][]subjectchange.SubjectChange{
		{{ID: 1, Subject: "user:usr00000000000000009", Naming: authz.SubjectNamed}},
		{{ID: 2, Subject: "", Naming: authz.SubjectUserset}},
	}}
	w, err := subjectchange.New(subjectchange.Config{
		Poller: poller, Flush: func() {}, Closer: &closerStub{},
		Interval: time.Second, StaleAfter: time.Minute, Logger: slog.New(handler),
	})
	if err != nil {
		t.Fatalf("сборка читателя: %v", err)
	}
	w.Poll(context.Background())
	w.Poll(context.Background())

	if _, n := handler.find("subject-change row carries no subject name"); n != 0 {
		t.Errorf("жалоба на потерянное имя поднята %d раз(а) на строке, выданной ГРУППЕ — "+
			"это норма, и тревога на ней перестанет читаться", n)
	}
}

// TestUnnamedSubjectRaisesTheAlarm — вторая сторона: дефект слышен.
func TestUnnamedSubjectRaisesTheAlarm(t *testing.T) {
	handler := &recordingHandler{}
	poller := &scriptedPoller{batches: [][]subjectchange.SubjectChange{
		{{ID: 1, Subject: "user:usr00000000000000009", Naming: authz.SubjectNamed}},
		{{ID: 2, Subject: "", Naming: authz.SubjectUnnameable}},
	}}
	w, err := subjectchange.New(subjectchange.Config{
		Poller: poller, Flush: func() {}, Closer: &closerStub{},
		Interval: time.Second, StaleAfter: time.Minute, Logger: slog.New(handler),
	})
	if err != nil {
		t.Fatalf("сборка читателя: %v", err)
	}
	w.Poll(context.Background())
	w.Poll(context.Background())

	rec, n := handler.find("subject-change row carries no subject name")
	if n != 1 {
		t.Fatalf("жалоб на потерянное имя %d, ожидалась 1 — иначе дефект производителя нем", n)
	}
	if rec.level != slog.LevelWarn {
		t.Errorf("уровень записи %v, ожидался WARN", rec.level)
	}
	if rec.attrs["subjects_unnamed"] != 1 {
		t.Errorf("жалоба не называет число: %v", rec.attrs)
	}
}
