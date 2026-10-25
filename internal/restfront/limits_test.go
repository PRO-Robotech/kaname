// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package restfront

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// Пробы потолков публичного REST-фронта (kaname#990).

// countingBody — тело запроса, которое считает прочитанное и производит байты
// по требованию, не держа их в памяти: проба меряет память ФРОНТА, а не свою.
type countingBody struct {
	left int64
	read atomic.Int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > b.left {
		n = b.left
	}
	for i := range p[:n] {
		p[i] = 'a'
	}
	b.left -= n
	b.read.Add(n)
	return int(n), nil
}

func (b *countingBody) Close() error { return nil }

// echoLen — обработчик за потолком: отвечает 200 и длиной прочитанного тела.
func echoLen(calls *atomic.Int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		n, _ := io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, strings.Repeat("x", int(n%7)))
	})
}

type refusal struct {
	Code    int               `json:"code"`
	Message string            `json:"message"`
	Details []json.RawMessage `json:"details"`
}

func requireRefusal(t *testing.T, rec *httptest.ResponseRecorder, status int, msg string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("статус %d, ожидался %d; тело %q", rec.Code, status, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type %q, ожидался application/json", ct)
	}
	var got refusal
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("тело отказа не JSON формы фронта: %v (%q)", err, rec.Body.String())
	}
	if got.Code != 8 || got.Message != msg || got.Details == nil {
		t.Fatalf("отказ %+v, ожидался {code:8, message:%q, details:[]}", got, msg)
	}
}

// Тело с объявленной длиной сверх потолка — 413, и тело НЕ читается вовсе.
func TestLimits_DeclaredOversizedBodyIsRefusedUnread(t *testing.T) {
	var calls atomic.Int64
	h := WithLimits(echoLen(&calls), Limits{MaxBodyBytes: 1024, MaxInFlight: 4})
	body := &countingBody{left: 64 << 20}
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/authorize:check", body)
	req.ContentLength = 64 << 20

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	requireRefusal(t, rec, http.StatusRequestEntityTooLarge, TextBodyTooLarge)
	if got := body.read.Load(); got != 0 {
		t.Errorf("прочитано %d байт тела, объявленного сверх потолка; ожидалось 0", got)
	}
	if calls.Load() != 0 {
		t.Error("обработчик за потолком вызван для отвергнутого запроса")
	}
}

// Тело без объявленной длины сверх потолка — 413; в память попадает не больше
// потолка, рост выделенной памяти ограничен порогом (замер).
func TestLimits_StreamedOversizedBodyIsRefusedWithBoundedMemory(t *testing.T) {
	const ceiling = 64 << 10
	const sent = 32 << 20
	const threshold = 4 << 20 // порог роста: потолок плюс накладные, много меньше отправленного

	var calls atomic.Int64
	h := WithLimits(echoLen(&calls), Limits{MaxBodyBytes: ceiling, MaxInFlight: 4})
	body := &countingBody{left: sent}
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/authorize:check", body)
	req.ContentLength = -1
	rec := httptest.NewRecorder()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	h.ServeHTTP(rec, req)
	runtime.ReadMemStats(&after)

	requireRefusal(t, rec, http.StatusRequestEntityTooLarge, TextBodyTooLarge)
	grown := after.TotalAlloc - before.TotalAlloc
	t.Logf("отправлено %d байт, прочитано фронтом %d, выделено %d байт (порог %d)",
		sent, body.read.Load(), grown, threshold)
	if grown > threshold {
		t.Errorf("выделено %d байт при потолке тела %d — тело читается в память сверх потолка", grown, ceiling)
	}
	if got := body.read.Load(); got > ceiling+1 {
		t.Errorf("прочитано %d байт при потолке %d", got, ceiling)
	}
	if calls.Load() != 0 {
		t.Error("обработчик за потолком вызван для отвергнутого запроса")
	}
}

// Законный близнец: тело в пределах потолка доезжает до обработчика целиком.
func TestLimits_BodyWithinCeilingReachesTheHandler(t *testing.T) {
	for _, declared := range []bool{true, false} {
		var calls atomic.Int64
		var seen int64
		h := WithLimits(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			seen, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
		}), Limits{MaxBodyBytes: 1024, MaxInFlight: 4})
		req := httptest.NewRequest(http.MethodPost, "/iam/v1/authorize:check", &countingBody{left: 1024})
		if declared {
			req.ContentLength = 1024
		} else {
			req.ContentLength = -1
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || calls.Load() != 1 || seen != 1024 {
			t.Fatalf("declared=%v: статус %d, вызовов %d, тела доехало %d байт; ожидалось 200, 1, 1024",
				declared, rec.Code, calls.Load(), seen)
		}
	}
}

// Одновременных сверх потолка — 429 сразу, без очереди и без чтения тела;
// освободившийся слот снова принимает.
func TestLimits_InFlightAboveCeilingIsRefusedNotQueued(t *testing.T) {
	const ceiling = 2
	entered := make(chan struct{}, ceiling)
	release := make(chan struct{})
	var calls atomic.Int64
	h := WithLimits(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}), Limits{MaxBodyBytes: 1024, MaxInFlight: ceiling})

	var wg sync.WaitGroup
	codes := make([]int, ceiling)
	for i := 0; i < ceiling; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/iam/v1/whoami", nil))
			codes[i] = rec.Code
		}(i)
	}
	for i := 0; i < ceiling; i++ {
		<-entered
	}

	extra := &countingBody{left: 1 << 20}
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/authorize:check", extra)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	requireRefusal(t, rec, http.StatusTooManyRequests, TextTooManyConcurrent)
	if extra.read.Load() != 0 {
		t.Errorf("тело лишнего запроса прочитано (%d байт) — отказ обязан наступать до чтения", extra.read.Load())
	}

	close(release)
	wg.Wait()
	for i, c := range codes {
		if c != http.StatusOK {
			t.Errorf("запрос %d в пределах потолка получил %d", i, c)
		}
	}
	if calls.Load() != ceiling {
		t.Fatalf("обработчик вызван %d раз, ожидалось %d", calls.Load(), ceiling)
	}

	// Близнец: слоты освобождены — следующий запрос принят.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/iam/v1/whoami", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("запрос после освобождения получил %d", rec.Code)
	}
}

// Слот одновременности возвращается и на отказе по телу: иначе каждый 413
// навсегда занимал бы слот, и потолок превращался бы в счётчик отказов.
func TestLimits_BodyRefusalReturnsTheSlot(t *testing.T) {
	var calls atomic.Int64
	h := WithLimits(echoLen(&calls), Limits{MaxBodyBytes: 8, MaxInFlight: 1})
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/x", &countingBody{left: 1 << 10})
		req.ContentLength = -1
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("попытка %d: статус %d, ожидался 413", i+1, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("после отказов по телу слот не вернулся: статус %d", rec.Code)
	}
}
