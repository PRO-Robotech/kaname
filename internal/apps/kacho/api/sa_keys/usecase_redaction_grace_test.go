// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package sa_keys

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// recordingRedactor фиксирует время и путь каждого redact-вызова — так тест
// проверяет, что затирание private_key_pem откладывается на grace-окно, а не
// происходит сразу после того как Operation стал Done.
type recordingRedactor struct {
	mu    sync.Mutex
	calls []recordedRedact
}

type recordedRedact struct {
	at    time.Time
	field string
}

func (r *recordingRedactor) RedactResponseField(_ context.Context, _ string, fieldPath []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, recordedRedact{at: time.Now(), field: strings.Join(fieldPath, ".")})
	return nil
}

func (r *recordingRedactor) snapshot() []recordedRedact {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedRedact(nil), r.calls...)
}

// TestScheduleSecretRedact_WaitsGraceBeforeRedacting — центральный тест фикса.
// Одноразовый private_key_pem отдается только в op.response; клиент (docker/CI/UI)
// поллит Operation.Get, чтобы его забрать. Затирание обязано подождать grace-окно,
// иначе клиент гарантированно проигрывает гонку и получает "<redacted>".
//
// Проверяется: первый redact-вызов случился НЕ раньше чем через grace после старта
// (клиент успевал опросить op), и в итоге затерты оба поля — private_key_pem и
// legacy client_secret.
func TestScheduleSecretRedact_WaitsGraceBeforeRedacting(t *testing.T) {
	const grace = 120 * time.Millisecond
	rec := &recordingRedactor{}
	uc := &IssueSAKeyUseCase{
		opsRepo:     &stubOpsRepo{done: true},
		redactor:    rec,
		redactGrace: grace,
	}

	start := time.Now()
	// scheduleSecretRedact синхронен: дожидается done, выдерживает grace, затирает.
	uc.scheduleSecretRedact(context.Background(), "iop_x")

	calls := rec.snapshot()
	require.NotEmpty(t, calls, "redact must eventually run")
	require.GreaterOrEqual(t, calls[0].at.Sub(start), grace,
		"private_key_pem must NOT be redacted until the grace window elapses (client poll-retrieval window)")

	fields := map[string]bool{}
	for _, c := range calls {
		fields[c.field] = true
	}
	require.True(t, fields["private_key_pem"], "private_key_pem must be redacted after grace")
	require.True(t, fields["client_secret"], "legacy client_secret must be redacted after grace")
}

// TestScheduleSecretRedact_PemPresentDuringGraceWindow — пока grace-окно не
// истекло, ключ ОСТАЁТСЯ в op.response (redact ещё не случился), поэтому
// параллельный клиентский поллинг успевает его прочитать.
//
// Deterministic: the grace expiry is driven by an injected timer channel (not a
// wall-clock Sleep race) — the test releases the window only AFTER asserting the
// key is still present, so it can never flake on a slow/loaded runner.
func TestScheduleSecretRedact_PemPresentDuringGraceWindow(t *testing.T) {
	rec := &recordingRedactor{}

	graceCh := make(chan time.Time)
	graceRequested := make(chan struct{})
	uc := &IssueSAKeyUseCase{
		opsRepo:     &stubOpsRepo{done: true},
		redactor:    rec,
		redactGrace: 300 * time.Millisecond, // >0 so the grace branch is taken
		graceTimer: func(time.Duration) <-chan time.Time {
			close(graceRequested) // signal: worker reached the grace wait
			return graceCh
		},
	}

	done := make(chan struct{})
	go func() {
		uc.scheduleSecretRedact(context.Background(), "iop_x")
		close(done)
	}()

	// Barrier: block until the worker has passed awaitOpDone and is parked on the
	// (not-yet-fired) grace timer. At that point redaction provably has NOT run.
	<-graceRequested
	require.Empty(t, rec.snapshot(),
		"private_key_pem must remain retrievable mid grace window")

	// Release the grace window deterministically → redaction proceeds.
	close(graceCh)
	<-done
	require.NotEmpty(t, rec.snapshot(),
		"private_key_pem must be redacted once the grace window has elapsed")
}

// TestScheduleSecretRedact_ZeroGraceRedactsImmediately — при нулевом grace
// (тест/legacy-wiring без WithRedactGrace) затирание происходит сразу: prod-дефолт
// живёт в конфиге, а нулевое значение use-case трактует как «без окна».
func TestScheduleSecretRedact_ZeroGraceRedactsImmediately(t *testing.T) {
	rec := &recordingRedactor{}
	uc := &IssueSAKeyUseCase{
		opsRepo:  &stubOpsRepo{done: true},
		redactor: rec,
	}

	start := time.Now()
	uc.scheduleSecretRedact(context.Background(), "iop_x")

	require.NotEmpty(t, rec.snapshot(), "zero grace must still redact")
	require.Less(t, time.Since(start), 100*time.Millisecond,
		"zero grace → redact runs immediately (no wait)")
}

// TestWithRedactGrace_SetsField — опция wire-time проставляет grace-окно
// (композиционный корень передаёт значение из конфига).
func TestWithRedactGrace_SetsField(t *testing.T) {
	uc := &IssueSAKeyUseCase{}
	require.Same(t, uc, uc.WithRedactGrace(90*time.Second), "option must be chainable")
	require.Equal(t, 90*time.Second, uc.redactGrace)
}
