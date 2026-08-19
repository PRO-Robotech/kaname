// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Предмет: #720 — ОДИН отказ недоступности из 736 запросов посреди здорового
// прогона, на чтении, которого ветка не касалась.
//
// Что происходило. Набор «отказ в закрытую» сворачивает хранилище прав до нуля
// реплик и поднимает обратно — то есть под ПЕРЕСОЗДАЁТСЯ, адрес назначения
// меняется. Соединения, которые процесс держал в пуле, указывают на экземпляр,
// которого больше нет; ответа по ним не будет никогда. Первый же запрос,
// которому досталось такое соединение, упирается в собственный срок и отдаёт
// арендатору 503 — при том что хранилище живо и отвечает соседним запросам за
// миллисекунды (замер по журналу: 249 мс против 5–9 мс у соседей).
//
// Повтор здесь — не смягчение симптома, а единственный корректный ответ:
// свежее соединение доказывает, что адресат жив, переиспользованное не
// доказывает ничего.

// poolTrapStore — хранилище прав, у которого КАЖДОЕ соединение обслуживает
// ровно один запрос, а на втором молча умирает.
//
// Молча — принципиально: сервер читает запрос ЦЕЛИКОМ и только потом закрывает
// сокет. Транспорт Go переигрывает сам лишь те попытки, по которым ничего не
// было записано; POST без ключа идемпотентности после записи он не
// переигрывает — значит отказ доходит до вызывающего, ровно как в проде.
type poolTrapStore struct {
	ln net.Listener

	mu    sync.Mutex
	conns int
	drops int
}

func newPoolTrapStore(t *testing.T) *poolTrapStore {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := &poolTrapStore{ln: ln}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *poolTrapStore) addr() string { return s.ln.Addr().String() }

func (s *poolTrapStore) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns++
		s.mu.Unlock()
		go s.handle(conn)
	}
}

func (s *poolTrapStore) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)
	served := 0
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
		if served > 0 {
			// Соединение уже обслуживало запрос — значит оно взято из пула.
			s.mu.Lock()
			s.drops++
			s.mu.Unlock()
			return
		}
		served++
		writeAllowedReply(conn)
	}
}

func (s *poolTrapStore) counts() (conns, drops int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns, s.drops
}

func writeAllowedReply(w io.Writer) {
	const body = `{"allowed":true}`
	_, _ = fmt.Fprintf(w,
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body)
}

// attemptLog — журнал наблюдателя попыток.
type attemptLog struct {
	mu   sync.Mutex
	seen []FGAAttempt
}

func (l *attemptLog) observer() func(FGAAttempt) {
	return func(a FGAAttempt) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.seen = append(l.seen, a)
	}
}

func (l *attemptLog) all() []FGAAttempt {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]FGAAttempt, len(l.seen))
	copy(out, l.seen)
	return out
}

func (l *attemptLog) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen = nil
}

func (l *attemptLog) sawOutcome(o FGACallOutcome) bool {
	for _, a := range l.all() {
		if a.Outcome == o {
			return true
		}
	}
	return false
}

func (l *attemptLog) outcomes() []FGACallOutcome {
	all := l.all()
	out := make([]FGACallOutcome, 0, len(all))
	for _, a := range all {
		out = append(out, a.Outcome)
	}
	return out
}

// TestCheck_DeadPooledConnectionIsRetriedOnAFreshOne — ПРЕДМЕТ #720.
//
// Красная до фикса: попытка, ушедшая в мёртвое соединение из пула, доезжала до
// вызывающего ошибкой, а use-case превращал её в `unavailable` → 503.
func TestCheck_DeadPooledConnectionIsRetriedOnAFreshOne(t *testing.T) {
	t.Parallel()
	store := newPoolTrapStore(t)
	log := &attemptLog{}
	c := &OpenFGAHTTPClient{
		Endpoint:     store.addr(),
		StoreID:      "store-720",
		CheckTimeout: 2 * time.Second,
		Observe:      log.observer(),
	}
	ctx := context.Background()

	// Прогрев: открыть соединение, получить ответ, вернуть соединение в пул.
	allowed, err := c.Check(ctx, "user:u1", "v_get", "account:acc1")
	require.NoError(t, err, "предпосылка: здоровое хранилище обязано отвечать")
	require.True(t, allowed, "предпосылка: подставное хранилище отвечает разрешением")

	// Дальше транспорт обязан взять соединение ИЗ ПУЛА. Ждём УСЛОВИЕ
	// (переиспользование), а не время: парковка соединения происходит в
	// читающей горутине транспорта, и «поспать» здесь означало бы утверждать о
	// расписании, а не о свойстве.
	log.reset()
	var (
		lastErr     error
		lastAllowed bool
		reuseSeen   bool
	)
	for i := 0; i < 20 && !reuseSeen; i++ {
		lastAllowed, lastErr = c.Check(ctx, "user:u1", "v_get", "account:acc1")
		for _, a := range log.all() {
			if a.Reused {
				reuseSeen = true
			}
		}
	}

	// Предпосылка отдельным утверждением: без переиспользования проба не
	// утверждает НИЧЕГО и зеленела бы на любом коде.
	require.True(t, reuseSeen,
		"предпосылка НЕ создана: ни одна попытка не пошла по соединению из пула — "+
			"проба про повтор ничего не проверила; исходы: %v", log.outcomes())
	_, drops := store.counts()
	require.Positive(t, drops,
		"предпосылка НЕ создана: хранилище ни разу не уронило переиспользованное соединение")

	require.NoError(t, lastErr,
		"чтение прав, чья попытка ушла в мёртвое соединение из пула, обязано быть "+
			"повторено на свежем: без повтора один такой запрос отдаёт арендатору 503 "+
			"посреди здорового прогона (#720). Исходы попыток: %v", log.outcomes())
	require.True(t, lastAllowed,
		"повтор обязан вернуть НАСТОЯЩИЙ ответ хранилища, а не «разрешено по умолчанию»")

	require.True(t, log.sawOutcome(FGAOutcomePooledConnDropped),
		"причина обязана быть НАЗВАНА: «оборвалось соединение из пула» — то самое "+
			"различие, которого не было (#720). Исходы: %v", log.outcomes())
	require.True(t, log.sawOutcome(FGAOutcomeOK),
		"после повтора обязан быть успешный исход")
}

// TestCheckWithContext_DeadPooledConnectionIsRetriedOnAFreshOne — тот же
// горячий страж чтения, вторая его дверь. Отдельная проба, а не параметр:
// у CheckWithContext своё тело запроса и свой путь разбора, и «починили там,
// где нашли» закрыло бы находку, оставив класс.
func TestCheckWithContext_DeadPooledConnectionIsRetriedOnAFreshOne(t *testing.T) {
	t.Parallel()
	store := newPoolTrapStore(t)
	log := &attemptLog{}
	c := &OpenFGAHTTPClient{
		Endpoint:     store.addr(),
		StoreID:      "store-720",
		CheckTimeout: 2 * time.Second,
		Observe:      log.observer(),
	}
	ctx := context.Background()

	allowed, err := c.CheckWithContext(ctx, "user:u1", "v_get", "account:acc1", nil)
	require.NoError(t, err, "предпосылка: здоровое хранилище обязано отвечать")
	require.True(t, allowed)

	log.reset()
	var (
		lastErr     error
		lastAllowed bool
		reuseSeen   bool
	)
	for i := 0; i < 20 && !reuseSeen; i++ {
		lastAllowed, lastErr = c.CheckWithContext(ctx, "user:u1", "v_get", "account:acc1", nil)
		for _, a := range log.all() {
			if a.Reused {
				reuseSeen = true
			}
		}
	}
	require.True(t, reuseSeen,
		"предпосылка НЕ создана: соединение из пула не переиспользовано; исходы: %v", log.outcomes())
	require.NoError(t, lastErr,
		"вторая дверь горячего стража обязана держать тот же класс; исходы: %v", log.outcomes())
	require.True(t, lastAllowed)
}

// ── ЗАКОННЫЕ БЛИЗНЕЦЫ: повтора быть НЕ ДОЛЖНО ───────────────────────────────
//
// Они не копия пробы выше с другим ожиданием, а ДРУГИЕ конструкции отказа.
// Без них «повторяем на недоступности» выродилось бы в «повторяем всегда»:
// закрытый отказ перестал бы укладываться в объявленный бюджет ровно тогда,
// когда хранилищу плохо.

// TestCheck_UnreachableStoreIsNotRetried — хранилища нет на том конце.
// Соединение не установлено, повтор в том же окне ничего не изменит.
func TestCheck_UnreachableStoreIsNotRetried(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close(), "порт закрыт намеренно: так выглядит лежащее хранилище")

	log := &attemptLog{}
	c := &OpenFGAHTTPClient{
		Endpoint:     addr,
		StoreID:      "store-720",
		CheckTimeout: 2 * time.Second,
		Observe:      log.observer(),
	}
	_, err = c.Check(context.Background(), "user:u1", "v_get", "account:acc1")
	require.Error(t, err, "недоступное хранилище обязано отказывать в закрытую")

	seen := log.all()
	require.Len(t, seen, 1,
		"повтора быть не должно: соединение не установлено, условие не изменится; исходы: %v",
		log.outcomes())
	require.Equal(t, FGAOutcomeStoreUnreachable, seen[0].Outcome,
		"причина обязана называться «до хранилища не дозвонились», а не «оборвалось соединение»")
	require.False(t, seen[0].Reused, "соединения не было — переиспользовать нечего")
}

// TestCheck_SilentStoreIsNotRetried — соединение СВЕЖЕЕ, хранилище приняло его
// и молчит. Повтор утроил бы время удержания запроса именно под той нагрузкой,
// при которой это и случается.
func TestCheck_SilentStoreIsNotRetried(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	// Принятые соединения УДЕРЖИВАЮТСЯ ссылкой. Без этого их закрывает
	// финализатор сборщика мусора, отказ приходит обрывом за 0 мс, и проба
	// про «хранилище молчит» проверяет другой класс — она это и показала
	// на первом же прогоне (исход conn_dropped вместо store_timeout).
	var held struct {
		mu    sync.Mutex
		conns []net.Conn
	}
	t.Cleanup(func() {
		_ = ln.Close()
		held.mu.Lock()
		defer held.mu.Unlock()
		for _, c := range held.conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Принимаем и не отвечаем НИКОГДА: отказ обязан прийти ПО СРОКУ.
			held.mu.Lock()
			held.conns = append(held.conns, conn)
			held.mu.Unlock()
		}
	}()

	log := &attemptLog{}
	budget := 150 * time.Millisecond
	c := &OpenFGAHTTPClient{
		Endpoint:     ln.Addr().String(),
		StoreID:      "store-720",
		CheckTimeout: budget,
		Observe:      log.observer(),
	}
	start := time.Now()
	_, err = c.Check(context.Background(), "user:u1", "v_get", "account:acc1")
	elapsed := time.Since(start)
	require.Error(t, err, "молчащее хранилище обязано отказывать в закрытую по сроку")

	seen := log.all()
	require.Len(t, seen, 1,
		"повтора быть не должно: хранилище молчит, и второй срок — это удвоенное "+
			"удержание запроса под той же нагрузкой; исходы: %v", log.outcomes())
	require.Equal(t, FGAOutcomeStoreTimeout, seen[0].Outcome,
		"причина обязана называться «хранилище молчит», а не «оборвалось соединение из пула»")
	require.Less(t, elapsed, 2*budget,
		"закрытый отказ обязан укладываться в ОДИН объявленный бюджет")
}

// TestCheck_RejectedQuestionIsADenyNotAnOutage — 400 от хранилища есть чистое
// «нет»: повторять нечего, и наружу это обязано идти отказом в доступе, а не
// недоступностью.
func TestCheck_RejectedQuestionIsADenyNotAnOutage(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"code":"validation_error"}`)
	}))
	t.Cleanup(srv.Close)

	log := &attemptLog{}
	c := &OpenFGAHTTPClient{
		Endpoint:     srv.Listener.Addr().String(),
		StoreID:      "store-720",
		CheckTimeout: 2 * time.Second,
		Observe:      log.observer(),
	}
	allowed, err := c.Check(context.Background(), "user:u1", "v_get", "account:acc1")
	require.NoError(t, err, "400 — терминальный отказ вопроса, а не сбой: ложный 503 запрещён")
	require.False(t, allowed)

	seen := log.all()
	require.Len(t, seen, 1, "терминальный отказ не повторяется; исходы: %v", log.outcomes())
	require.Equal(t, FGAOutcomeStoreRejected, seen[0].Outcome)
}

// TestCheck_ServerErrorIsRetried — 5xx повторяется (это и было поведение
// девяти соседних вызовов через retryClient; горячий страж его не имел вовсе).
func TestCheck_ServerErrorIsRetried(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		n := hits
		mu.Unlock()
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"allowed":true}`)
	}))
	t.Cleanup(srv.Close)

	log := &attemptLog{}
	c := &OpenFGAHTTPClient{
		Endpoint:     srv.Listener.Addr().String(),
		StoreID:      "store-720",
		CheckTimeout: 2 * time.Second,
		Observe:      log.observer(),
	}
	allowed, err := c.Check(context.Background(), "user:u1", "v_get", "account:acc1")
	require.NoError(t, err, "5xx обязан повторяться; исходы: %v", log.outcomes())
	require.True(t, allowed)
	require.Equal(t, []FGACallOutcome{FGAOutcomeStoreError, FGAOutcomeOK}, log.outcomes())
}

// TestFGAOutcome_RetryablePartitionsTheVocabulary — словарь исходов закрыт, и
// решение о повторе принимается ПО НЕМУ, а не по тексту ошибки.
func TestFGAOutcome_RetryablePartitionsTheVocabulary(t *testing.T) {
	t.Parallel()
	retryable := map[FGACallOutcome]bool{
		FGAOutcomeOK:                false,
		FGAOutcomeStoreRejected:     false,
		FGAOutcomeStoreUnreachable:  false,
		FGAOutcomeStoreTimeout:      false,
		FGAOutcomeDecodeFailed:      false,
		FGAOutcomeStoreError:        true,
		FGAOutcomePooledConnDropped: true,
		FGAOutcomeConnDropped:       true,
	}
	require.Len(t, retryable, 8, "перепись: словарь исходов обязан быть перечислен ЦЕЛИКОМ")
	for o, want := range retryable {
		require.Equal(t, want, o.Retryable(), "исход %q", o)
	}
}
