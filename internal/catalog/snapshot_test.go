// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog_test

// snapshot_test.go — сценарии IAM-CT-2-03 · -04 (kacho#1816).
//
// Предмет — НАБЛЮДАЕМОСТЬ обновления снимка, а не его содержание: содержание
// утверждает `facts_test.go`.

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
)

// countingObserver — счётчики исходов обновления. Их ДВА, и одного не хватает
// ни на один из двух вопросов: ноль отказов даёт и исправный процесс, и ни разу
// не ходивший обновляться; растущий ноль удавшихся не говорит, отказывало ли
// обновление или его не запускали.
type countingObserver struct {
	mu       sync.Mutex
	outcomes map[string]int
}

func newCountingObserver() *countingObserver {
	return &countingObserver{outcomes: map[string]int{}}
}

func (o *countingObserver) IncCatalogSnapshotRefresh(outcome string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.outcomes[outcome]++
}

func (o *countingObserver) get(outcome string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.outcomes[outcome]
}

// stubSource — источник строк с управляемым исходом.
type stubSource struct {
	mu   sync.Mutex
	rows catalog.Rows
	err  error
}

func (s *stubSource) ReadLiveCatalog(context.Context) (catalog.Rows, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return catalog.Rows{}, s.err
	}
	return s.rows, nil
}

func (s *stubSource) set(rows catalog.Rows, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows, s.err = rows, err
}

// logSink — журнал в память: проба утверждает УРОВЕНЬ и ПРЕДМЕТ записи, а не
// только факт её существования.
type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (s *logSink) Enabled(context.Context, slog.Level) bool { return true }
func (s *logSink) WithAttrs([]slog.Attr) slog.Handler       { return s }
func (s *logSink) WithGroup(string) slog.Handler            { return s }
func (s *logSink) Handle(_ context.Context, r slog.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, r.Level.String()+" "+r.Message)
	return nil
}
func (s *logSink) text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.lines, "\n")
}

// TestIAMCT2_03_RefreshFailureIsNeitherFatalNorSilent — `-03`.
func TestIAMCT2_03_RefreshFailureIsNeitherFatalNorSilent(t *testing.T) {
	rows := seed.LiteralRows()
	src := &stubSource{rows: rows}
	obs := newCountingObserver()
	sink := &logSink{}

	snap, err := catalog.NewSnapshot(rows, src, slog.New(sink), obs)
	if err != nil {
		t.Fatalf("снимок на старте: %v", err)
	}
	before := snap.Facts()
	if before == nil || len(before.AllVerbVocabulary()) == 0 {
		t.Fatalf("снимок на старте пуст — проба ниже стала бы вакуумной")
	}

	src.set(catalog.Rows{}, errors.New("база не отвечает"))
	if rerr := snap.Refresh(context.Background()); rerr == nil {
		t.Fatalf("отказ обновления не сообщён вызывающему")
	}

	// Служба продолжает работать на ПРЕЖНЕМ снимке.
	if got := snap.Facts(); got != before {
		t.Errorf("снимок подменён на отказе обновления — ограниченное отставание "+
			"обменяли на полный отказ (было %p, стало %p)", before, got)
	}
	if n := obs.get("failed"); n != 1 {
		t.Errorf("счётчик отказов обновления %d, ожидался 1 — отказ виден только в журнале, "+
			"то есть не измеряется", n)
	}
	if n := obs.get("refreshed"); n != 0 {
		t.Errorf("счётчик удавшихся обновлений %d при отказе", n)
	}
	logged := sink.text()
	if !strings.Contains(logged, "ERROR") || !strings.Contains(logged, "снимок каталога не обновлён") {
		t.Errorf("запись журнала не называет предмет уровнем ERROR, получено:\n%s", logged)
	}

	// ПУСТОЙ ответ без ошибки — тоже отказ обновления, а не новый снимок:
	// пустой снимок отверг бы все правила разом.
	src.set(catalog.Rows{}, nil)
	if rerr := snap.Refresh(context.Background()); rerr == nil {
		t.Errorf("пустое множество принято как новый снимок")
	}
	if got := snap.Facts(); got != before {
		t.Errorf("снимок подменён пустым множеством")
	}
}

// TestIAMCT2_04_SuccessfulRefreshesAreCounted — `-04`: «ноль обновлений за жизнь
// процесса» отличимо от исправной работы.
func TestIAMCT2_04_SuccessfulRefreshesAreCounted(t *testing.T) {
	rows := seed.LiteralRows()
	src := &stubSource{rows: rows}
	obs := newCountingObserver()

	snap, err := catalog.NewSnapshot(rows, src, slog.New(&logSink{}), obs)
	if err != nil {
		t.Fatalf("снимок на старте: %v", err)
	}
	// Заполнение на старте обновлением НЕ считается: считается то, что происходит
	// после, иначе «ноль обновлений за жизнь процесса» неотличимо от одного.
	if n := obs.get("refreshed"); n != 0 {
		t.Fatalf("заполнение на старте зачтено обновлением (%d) — тогда счётчик "+
			"не отвечает на вопрос, ради которого заведён", n)
	}
	if rerr := snap.Refresh(context.Background()); rerr != nil {
		t.Fatalf("обновление: %v", rerr)
	}
	if n := obs.get("refreshed"); n != 1 {
		t.Errorf("счётчик удавшихся обновлений %d, ожидался 1", n)
	}
	if n := obs.get("failed"); n != 0 {
		t.Errorf("счётчик отказов %d при удавшемся обновлении", n)
	}
}

// TestIAMCT2_04_RunRefreshesOnItsPeriod — величина отставания НАЗНАЧЕНА, а не
// получилась: цикл обновления ходит с заданным периодом и завершается по
// отмене.
func TestIAMCT2_04_RunRefreshesOnItsPeriod(t *testing.T) {
	rows := seed.LiteralRows()
	src := &stubSource{rows: rows}
	obs := newCountingObserver()
	snap, err := catalog.NewSnapshot(rows, src, slog.New(&logSink{}), obs)
	if err != nil {
		t.Fatalf("снимок на старте: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { snap.Run(ctx, time.Millisecond); close(done) }()

	deadline := time.Now().Add(5 * time.Second)
	for obs.get("refreshed") == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("цикл обновления не завершился по отмене")
	}
	if n := obs.get("refreshed"); n == 0 {
		t.Errorf("за период обновления не случилось ни одного — снимок отстаёт бессрочно")
	}
}
