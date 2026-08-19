// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// openfga_attempt.go — ОДНА попытка обращения к хранилищу прав: со своим
// сроком, с разбором того, ЧТО именно не получилось, и с объявлением исхода
// наблюдателю.
//
// Зачем это отдельным примитивом. До него все обращения к хранилищу прав
// отвечали вызывающему одним и тем же — ошибкой. Снаружи «хранилище
// перезапускали», «хранилище не отвечает» и «соединение, взятое из пула,
// оказалось мёртвым» выглядели ОДИНАКОВО, и различить их можно было только
// чтением журнала построчно — уже после того как отказ истолкован. Поэтому
// причина здесь не пишется в текст ошибки (текст — часть контракта и разбору
// не подлежит), а объявляется ОТДЕЛЬНЫМ значением: оно и решает, имеет ли
// смысл повтор, и уезжает наблюдателю отдельной серией счётчика.
package clients

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"time"
)

// FGACallOutcome — исход ОДНОЙ попытки обращения к хранилищу прав.
//
// Значения — метка серии счётчика, поэтому словарь ЗАКРЫТ и мощность его
// ограничена: неизвестного исхода не бывает, у каждого отказа есть имя.
type FGACallOutcome string

const (
	// FGAOutcomeOK — ответ получен и разобран.
	FGAOutcomeOK FGACallOutcome = "ok"

	// FGAOutcomeStoreRejected — хранилище отвергло сам вопрос (400): такого
	// отношения у типа нет, объект — типизированный подстановочный знак и т.п.
	// Это ТЕРМИНАЛЬНЫЙ отказ, а не сбой: повтор не пройдёт никогда, и вызывающий
	// обязан прочитать его как чистое «нет», а не как недоступность.
	FGAOutcomeStoreRejected FGACallOutcome = "store_rejected"

	// FGAOutcomeStoreError — хранилище ответило 5xx.
	FGAOutcomeStoreError FGACallOutcome = "store_error"

	// FGAOutcomeStoreUnreachable — соединение установить НЕ УДАЛОСЬ (отказ в
	// подключении, имя не разрешилось, маршрута нет). Хранилище лежит или
	// перезапускается: повтор в пределах того же бюджета ничего не изменит.
	FGAOutcomeStoreUnreachable FGACallOutcome = "store_unreachable"

	// FGAOutcomePooledConnDropped — соединение было взято ИЗ ПУЛА и не дало ни
	// одного байта ответа.
	//
	// Это ровно тот класс, ради которого примитив написан. Соединение,
	// переиспользованное из пула, могло быть открыто к экземпляру хранилища,
	// которого больше нет (пересоздание пода меняет адрес назначения, а
	// установленное соединение об этом не узнаёт). Пакеты уходят в никуда,
	// ответа нет, и попытка упирается в собственный срок — то есть отказ по
	// ФОРМЕ неотличим от «хранилище не отвечает», хотя само хранилище здорово и
	// отвечает соседним запросам за миллисекунды.
	//
	// Различает их ровно один признак: соединение взято из пула. Свежее
	// соединение доказывает, что адресат жив; переиспользованное — не
	// доказывает ничего. Поэтому единственный верный ответ здесь — повторить на
	// СВЕЖЕМ соединении, и только здесь.
	FGAOutcomePooledConnDropped FGACallOutcome = "pooled_conn_dropped"

	// FGAOutcomeConnDropped — соединение было СВЕЖИМ, запрос ушёл, ответа нет:
	// соединение оборвалось. Быстрый отказ, повтор дёшев.
	FGAOutcomeConnDropped FGACallOutcome = "conn_dropped"

	// FGAOutcomeStoreTimeout — соединение свежее, срок попытки истёк, ответа
	// нет. Хранилище живо на уровне соединения и молчит на уровне запроса
	// (пауза сборщика, перегрузка). Повтор НЕ делается: он утроил бы время
	// удержания запроса ровно под той нагрузкой, при которой это и происходит,
	// а закрытый отказ обязан укладываться в объявленный бюджет.
	FGAOutcomeStoreTimeout FGACallOutcome = "store_timeout"

	// FGAOutcomeDecodeFailed — ответ 200, но тело не разбирается.
	FGAOutcomeDecodeFailed FGACallOutcome = "decode_failed"
)

// Retryable — стоит ли повторять попытку с таким исходом.
//
// Повторяются ТОЛЬКО те исходы, у которых повтор меняет условие: мёртвое
// соединение сменится живым, оборванное — новым, 5xx может не повториться.
// «Хранилища нет» и «хранилище молчит» не повторяются: условие то же, а цена —
// удвоенное время удержания запроса именно тогда, когда хранилищу и так плохо.
func (o FGACallOutcome) Retryable() bool {
	switch o {
	case FGAOutcomePooledConnDropped, FGAOutcomeConnDropped, FGAOutcomeStoreError:
		return true
	default:
		return false
	}
}

// FGAAttempt — наблюдение об одной попытке. Уезжает в счётчик композиционным
// корнем; сам адаптер про prometheus не знает (dependency-rule).
type FGAAttempt struct {
	// Op — операция хранилища: check / write / read / list-objects / …
	Op string
	// Attempt — номер попытки, начиная с 1.
	Attempt int
	// Reused — соединение взято из пула (а не открыто заново).
	Reused bool
	// Outcome — исход этой попытки.
	Outcome FGACallOutcome
	// Duration — сколько попытка заняла.
	Duration time.Duration
}

// observeAttempt — сообщить наблюдателю. Nil-безопасно: наблюдатель
// необязателен, и его отсутствие не меняет поведения.
func (c *OpenFGAHTTPClient) observeAttempt(a FGAAttempt) {
	if c == nil || c.Observe == nil {
		return
	}
	c.Observe(a)
}

// fgaConnTrace — что удалось узнать о соединении этой попытки.
//
// Под мьютексом: GotFirstResponseByte вызывается из читающей горутины
// транспорта, и без синхронизации гонку нашёл бы -race, а не человек.
type fgaConnTrace struct {
	mu        sync.Mutex
	gotConn   bool
	reused    bool
	firstByte bool
}

func (t *fgaConnTrace) hook() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GotConn: func(i httptrace.GotConnInfo) {
			t.mu.Lock()
			defer t.mu.Unlock()
			t.gotConn = true
			t.reused = i.Reused
		},
		GotFirstResponseByte: func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			t.firstByte = true
		},
	}
}

func (t *fgaConnTrace) read() (gotConn, reused, firstByte bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.gotConn, t.reused, t.firstByte
}

// classifyFGAAttempt — исход попытки по тому, что о ней известно.
//
// status == 0 означает «ответа не было вовсе»; err == nil означает, что ответ
// пришёл, и тогда решает его код.
func classifyFGAAttempt(tr *fgaConnTrace, status int, err error) FGACallOutcome {
	if err == nil {
		switch {
		case status == http.StatusBadRequest:
			return FGAOutcomeStoreRejected
		case status >= 500:
			return FGAOutcomeStoreError
		case status == http.StatusOK:
			return FGAOutcomeOK
		default:
			// Любой прочий код — тоже ответ хранилища, а не сбой связи.
			return FGAOutcomeStoreError
		}
	}
	gotConn, reused, firstByte := tr.read()
	switch {
	case !gotConn:
		// До соединения не дошло: отказ в подключении, имя, маршрут, срок на
		// самом подключении. Хранилища на том конце нет.
		return FGAOutcomeStoreUnreachable
	case reused && !firstByte:
		// Соединение из пула не дало ни байта — оно и есть подозреваемое.
		// Сюда попадает И обрыв, И истёкший срок: срок на переиспользованном
		// соединении ничего не говорит о здоровье хранилища.
		return FGAOutcomePooledConnDropped
	case errors.Is(err, context.DeadlineExceeded):
		return FGAOutcomeStoreTimeout
	default:
		return FGAOutcomeConnDropped
	}
}

// fgaOpFromURL — имя операции для наблюдателя: последний сегмент пути
// (check / write / read / list-objects / list-users / expand / stores).
//
// Выводится из адреса, а не передаётся девятью вызывающими: рукописный
// параметр в девяти местах разошёлся бы с адресом молча, а метка счётчика —
// это то, по чему потом ищут.
func fgaOpFromURL(url string) string {
	if i := strings.IndexByte(url, '?'); i >= 0 {
		url = url[:i]
	}
	url = strings.TrimSuffix(url, "/")
	if i := strings.LastIndexByte(url, '/'); i >= 0 {
		if seg := url[i+1:]; seg != "" {
			return seg
		}
	}
	return "unknown"
}

// fgaCheckMaxAttempts — сколько попыток допускает ЧТЕНИЕ хранилища прав.
//
// Две, а не три: у каждой попытки СВОЙ срок (см. fgaRead), поэтому число
// попыток напрямую умножает худшее время удержания запроса на горячем пути.
// Двух достаточно ровно для того класса, ради которого повтор и заведён, —
// первая попытка отбраковывает мёртвое соединение из пула, вторая идёт по
// свежему. Третья добавила бы ещё один полный срок и не закрыла бы ни одного
// нового случая: исходы, где повтор бесполезен, не повторяются вовсе.
const fgaCheckMaxAttempts = 2

// fgaReadRetryBackoff — пауза перед повтором ПОСЛЕ ответа хранилища (5xx).
//
// Обрыв соединения повторяется без паузы: смысл повтора там — взять другое
// соединение, а не переждать. Пауза нужна лишь тогда, когда хранилище ответило
// и ответ был отказом.
const fgaReadRetryBackoff = 20 * time.Millisecond

// fgaRead — идемпотентное чтение хранилища прав с повтором по причине отказа.
//
// perAttempt — срок КАЖДОЙ попытки, не общий на все. Это несущее решение, а не
// деталь: при общем сроке попытка, повисшая на мёртвом соединении из пула,
// съедает бюджет целиком, и повтор рождается мёртвым — что и наблюдалось (#720:
// один отказ из 736 запросов, длительность ответа равна сроку проверки, при
// соседних ответах в 5 мс).
//
// Худшее время ограничено: fgaCheckMaxAttempts × perAttempt, и удваивается оно
// ТОЛЬКО на исходах из Retryable(). При настоящей недоступности хранилища пул
// пуст, соединение свежее, исход — store_unreachable/store_timeout, повтора нет
// и время остаётся прежним.
//
// Возвращает rejected=true, когда хранилище отвергло сам вопрос (400): это
// чистое «нет», а не сбой, и вызывающий обязан прочитать его как отказ в
// доступе, а не как недоступность.
func (c *OpenFGAHTTPClient) fgaRead(
	ctx context.Context,
	url string,
	body []byte,
	perAttempt time.Duration,
	maxAttempts int,
	onOK func(*http.Response) error,
) (rejected bool, err error) {
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	op := fgaOpFromURL(url)
	var last error
	for n := 1; n <= maxAttempts; n++ {
		rejected, outcome, err := c.fgaReadOnce(ctx, op, url, body, perAttempt, n, onOK)
		if err == nil || !outcome.Retryable() || n == maxAttempts {
			return rejected, err
		}
		last = err
		if outcome == FGAOutcomeStoreError {
			select {
			case <-time.After(fgaReadRetryBackoff):
			case <-ctx.Done():
				return false, last
			}
		}
	}
	return false, last
}

// fgaReadOnce — одна попытка: свой срок, своя трасса соединения, свой исход.
func (c *OpenFGAHTTPClient) fgaReadOnce(
	ctx context.Context,
	op, url string,
	body []byte,
	perAttempt time.Duration,
	attempt int,
	onOK func(*http.Response) error,
) (rejected bool, outcome FGACallOutcome, err error) {
	start := time.Now()
	tr := &fgaConnTrace{}
	actx, cancel := context.WithTimeout(httptrace.WithClientTrace(ctx, tr.hook()), perAttempt)
	defer cancel()

	defer func() {
		_, reused, _ := tr.read()
		c.observeAttempt(FGAAttempt{
			Op: op, Attempt: attempt, Reused: reused,
			Outcome: outcome, Duration: time.Since(start),
		})
	}()

	req, reqErr := newFGAJSONRequest(actx, url, body)
	if reqErr != nil {
		return false, FGAOutcomeStoreUnreachable, reqErr
	}
	resp, doErr := fgaHTTPClient.Do(req)
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	outcome = classifyFGAAttempt(tr, status, doErr)
	if doErr != nil {
		return false, outcome, fmt.Errorf("openfga check: %w", doErr)
	}
	defer resp.Body.Close()

	switch outcome {
	case FGAOutcomeStoreRejected:
		// Тело сливается (с потолком) до закрытия, чтобы соединение вернулось в
		// пул, а не рвалось: деградировавшее хранилище, сыплющее 400, не должно
		// вдобавок жечь дескрипторы и рукопожатия на горячем пути.
		drainFGABody(resp)
		return true, outcome, nil
	case FGAOutcomeOK:
		if decErr := onOK(resp); decErr != nil {
			outcome = FGAOutcomeDecodeFailed
			return false, outcome, fmt.Errorf("openfga check decode: %w", decErr)
		}
		return false, outcome, nil
	default:
		drainFGABody(resp)
		return false, outcome, fmt.Errorf("openfga check: status %d", status)
	}
}

// newFGAJSONRequest — POST с JSON-телом и перезаписываемым телом для повтора.
//
// GetBody обязателен: без него транспорт не переиграет даже те попытки, которые
// он умеет переигрывать сам, а наш повтор не сможет отдать тело второй раз.
func newFGAJSONRequest(ctx context.Context, url string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	b := body
	req.GetBody = func() (io.ReadCloser, error) {
		return &nopCloser{Reader: bytes.NewReader(b)}, nil
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// drainFGABody — слить (с потолком) тело неуспешного ответа, чтобы соединение
// вернулось в пул. Деградировавшее хранилище не должно вдобавок жечь
// рукопожатия.
func drainFGABody(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBodyBytes))
}
