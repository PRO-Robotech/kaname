// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package installruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// ReadinessStatus проверяет настоящий диагностический маршрут готовности с теми же
// проверенными CA/клиентским TLS фикстуры. Рукопожатие TLS или один JWKS не означают готовность.
func (w *Wire) ReadinessStatus(ctx context.Context) (int, error) {
	code, _, _, err := w.request(ctx, http.MethodGet, fmt.Sprintf("https://localhost:%d/readyz", w.ports.Metrics), nil, nil)
	return code, err
}
func (w *Wire) ProductionReady(ctx context.Context) error {
	if err := w.ListenersReady(ctx); err != nil {
		return err
	}
	code, _, raw, err := w.request(ctx, http.MethodGet, fmt.Sprintf("https://localhost:%d/readyz", w.ports.Metrics), nil, nil)
	if err != nil {
		return err
	}
	var body struct {
		Status string `json:"status"`
	}
	if code != http.StatusOK || json.Unmarshal(raw, &body) != nil || body.Status != "ready" {
		return fmt.Errorf("production readiness unavailable: HTTP %d", code)
	}
	return nil
}

type ReadinessSample struct {
	StartedAt, FinishedAt time.Time
	HTTPStatus            int
	TransportFailed       bool
}
type ReadinessWatch struct {
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
	samples []ReadinessSample // публикуются только после закрытия done
}

// StartReadinessWatch активирует наблюдателя до запуска serve вызывающим.
// Возвращается только после завершения ПЕРВОГО настоящего запроса. Каждый следующий
// запрос начинается сразу после интервала планирования 1ms и имеет ограниченный
// срок 250ms. Вызывающий должен сохранять наблюдателя до завершения процесса.
func (w *Wire) StartReadinessWatch(ctx context.Context) *ReadinessWatch {
	watch := &ReadinessWatch{stop: make(chan struct{}), done: make(chan struct{})}
	armed := make(chan struct{})
	go func() {
		defer close(watch.done)
		first := true
		for {
			sample := ReadinessSample{StartedAt: time.Now().UTC()}
			attempt, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
			code, err := w.ReadinessStatus(attempt)
			cancel()
			sample.FinishedAt = time.Now().UTC()
			sample.HTTPStatus = code
			sample.TransportFailed = err != nil
			watch.samples = append(watch.samples, sample)
			if first {
				close(armed)
				first = false
			}
			// Stop не отменяет текущий запрос: 200, совпавший с выходом процесса,
			// всё равно относится к доказательству и не должен исчезать при отмене.
			timer := time.NewTimer(time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-watch.stop:
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	<-armed
	return watch
}
func (w *ReadinessWatch) Stop() []ReadinessSample {
	w.once.Do(func() { close(w.stop) })
	<-w.done
	return append([]ReadinessSample(nil), w.samples...)
}
