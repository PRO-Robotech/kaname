// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package restfront

// limits.go — потолки размера тела и одновременности публичного фронта
// (kaname#990).
//
// # Зачем они у фронта, а не у края
//
// Пока служба стоит за краем платформы, тело и число запросов ограничивает
// край. Опубликованная клиентам напрямую, края она не имеет by construction, и
// держать потолок больше некому: тело любого размера читалось бы в память
// процесса целиком (разбор JSON берёт его всё), а число запросов в работе было
// бы ограничено только числом соединений, которые откроет вызывающий.
//
// # Почему потолок одновременности — на процесс, а не на вызывающего
//
// На вызывающего его уже держит ограничитель допуска слушателя (admission.go
// корня). Он стоит ПОСЛЕ разбора тела и после звеньев личности, то есть
// защищает базу, но не память фронта: сто анонимных запросов с телом в
// потолок занимают память до того, как ограничитель о них узнает. Потолок
// здесь — граница памяти процесса: не больше MaxInFlight запросов в работе, и
// у каждого в памяти не больше MaxBodyBytes тела.
//
// # Почему отказ сразу, а не очередь
//
// Очередь ожидающих растёт вместе с нагрузкой и держит соединения и горутины
// тех, кого всё равно не обслужат вовремя: неограниченная очередь — тот же
// неограниченный ресурс, перенесённый на шаг раньше. Лишний запрос получает
// 429 немедленно и тело его не читается.
//
// # Порядок: слот, затем тело
//
// Слот берётся ДО чтения тела: иначе тела ждущих слота уже лежали бы в памяти,
// и потолок одновременности не ограничивал бы её. Слот возвращается на
// КАЖДОМ пути, включая отказ по телу.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"google.golang.org/grpc/codes"

	"github.com/PRO-Robotech/corelib/grpcsrv"
)

// Limits — потолки публичного фронта.
//
// Ноль у оси означает «потолок снят». Допустим он только вне боевой посадки:
// значения приходят из настройки, и её страж отвергает снятие в боевой
// (`config.RESTLimitsConfig.Validate`).
type Limits struct {
	// MaxBodyBytes — наибольший размер тела запроса в байтах.
	MaxBodyBytes int64
	// MaxInFlight — наибольшее число запросов в работе на процесс.
	MaxInFlight int
}

// Тексты отказов — часть контракта, меняются осознанно.
//
// Код в теле — RESOURCE_EXHAUSTED (8) у обоих: им же слушатель отвечает на
// сообщение сверх своего потолка приёма и на исчерпанный потолок допуска;
// текст одновременности — дословно текст ограничителя допуска, чтобы клиент
// читал один класс отказа одинаково, где бы его ни остановили.
const (
	TextBodyTooLarge      = "Request body too large"
	TextTooManyConcurrent = grpcsrv.MsgInFlightExceeded
	// TextBodyUnreadable — тело оборвалось на чтении (код INVALID_ARGUMENT, 400).
	TextBodyUnreadable = "Request body could not be read"
)

// WithLimits оборачивает обработчик потолками l.
func WithLimits(next http.Handler, l Limits) http.Handler {
	var slots chan struct{}
	if l.MaxInFlight > 0 {
		slots = make(chan struct{}, l.MaxInFlight)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if slots != nil {
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			default:
				writeRefusal(w, http.StatusTooManyRequests, TextTooManyConcurrent)
				return
			}
		}
		if l.MaxBodyBytes > 0 && r.Body != nil && r.Body != http.NoBody {
			if r.ContentLength > l.MaxBodyBytes {
				writeRefusal(w, http.StatusRequestEntityTooLarge, TextBodyTooLarge)
				return
			}
			// Читается не больше потолка плюс один байт: лишний байт и есть
			// признак превышения, а остаток тела в память не попадает вовсе.
			body, err := io.ReadAll(io.LimitReader(r.Body, l.MaxBodyBytes+1))
			_ = r.Body.Close()
			if int64(len(body)) > l.MaxBodyBytes {
				writeRefusal(w, http.StatusRequestEntityTooLarge, TextBodyTooLarge)
				return
			}
			if err != nil {
				// Тело оборвалось на чтении — запрос не дочитан, и отдавать
				// обработчику его часть значило бы разобрать не то, что прислано.
				writeRefusal(w, http.StatusBadRequest, TextBodyUnreadable)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		}
		next.ServeHTTP(w, r)
	})
}

// refusal — тело отказа формой фронта; `details` — пустой список, а не
// отсутствие поля: так отвечает и маршрутизатор фронта.
type refusal struct {
	Code    codes.Code `json:"code"`
	Message string     `json:"message"`
	Details []struct{} `json:"details"`
}

// writeRefusal пишет отказ формой фронта: `{"code","message","details":[]}`.
func writeRefusal(w http.ResponseWriter, status int, message string) {
	code := codes.ResourceExhausted
	if status == http.StatusBadRequest {
		code = codes.InvalidArgument
	}
	body, err := json.Marshal(refusal{Code: code, Message: message, Details: []struct{}{}})
	if err != nil {
		// Сериализация структуры из трёх полей простых типов не отказывает;
		// ветка — ради того, чтобы отказ кодирования не стал пустым 200.
		http.Error(w, message, status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
