// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package restfront

import (
	"context"
	"net/http"
)

// challenge.go — подсказка аутентификации на публичной HTTP-поверхности
// (задача продукта #2103, находка Н1 приёмки KAN-REST-1).
//
// # Предмет
//
// Статус `401` приезжает сам: слушатель отвечает `UNAUTHENTICATED`, а
// отображение кода в HTTP-статус делает библиотека. Подсказку — ЧЕМ назваться —
// производил КРАЙ платформы; у отдельно поставленной службы края нет by
// construction, и вместе с ним исчез единственный её производитель. Без неё
// клиент, получивший `401`, знает, что его не пустили, и не знает, что сделать.
//
// # Почему обёртка ОТВЕТА, а не свой обработчик ошибок
//
// Обработчик ошибок, ЗАМЕНЯЮЩИЙ умолчание, сменил бы множество производимых
// статусов, и таблица статусов приёмки перестала бы описывать поведение — шапка
// пакета говорит это прямо. Обработчик фронта (stepup.go) умолчания не
// заменяет: он рендерит одно указание повысить уровень и кладёт его вызов в
// место запроса, а всё прочее отдаёт библиотеке. Подсказку на всяком `401`
// ставит эта обёртка — ОДИН заголовок, ни кода, ни тела: множество статусов
// остаётся тем, что задаёт библиотека.
//
// # Почему только на ПУБЛИЧНОМ фронте
//
// Внутренний фронт обслуживает модули, и называются они клиентским
// сертификатом, а не удостоверением. Подсказка `Bearer` там советовала бы
// действие, которого у вызывающего нет, — то есть была бы тем же дефектом, что
// и молчание, только с другой стороны. Это решение, а не пропуск: полоса без
// подсказки при полосе с подсказкой названа здесь, а не оставлена умолчанием.

// challengeHeader — заголовок вызова аутентификации (RFC 7235 §4.1).
const challengeHeader = "WWW-Authenticate"

// AuthenticationChallenge — ЕДИНСТВЕННОЕ значение подсказки.
//
// Голая схема, без кода ошибки: RFC 6750 §3.1 прямо говорит, что запросу БЕЗ
// сведений об аутентификации код ошибки прилагать не следует. Отсюда и второе,
// более важное свойство — подсказка одинакова на ОБЕИХ полосах отказа
// аутентификации, поэтому по ней нельзя отличить «не предъявлял» от
// «предъявил негодное», и оракулом она не является.
//
// Экспортировано затем, чтобы проба утверждала ЕГО, а не свою копию.
const AuthenticationChallenge = "Bearer"

// challengeHandler — обработчик, прикладывающий подсказку к ответу `401`.
type challengeHandler struct{ next http.Handler }

// stepUpSlot — место, куда обработчик ошибок фронта кладёт вызов УКАЗАНИЯ
// повысить уровень (Р11, kaname#511) для этого запроса. Подсказка `Bearer`
// ставится в момент выбора статуса и иначе перекрыла бы вызов с параметрами
// уровня; место заводит обёртка, и только она его читает.
type stepUpSlot struct{ challenge string }

// stepUpSlotKey — ключ места в контексте запроса. Тип не экспортирован:
// завести место может только этот пакет, снаружи запрос его не несёт.
type stepUpSlotKey struct{}

func stepUpSlotFrom(ctx context.Context) (*stepUpSlot, bool) {
	slot, ok := ctx.Value(stepUpSlotKey{}).(*stepUpSlot)
	return slot, ok
}

// withAuthenticationChallenge оборачивает обработчик фронта.
func withAuthenticationChallenge(next http.Handler) http.Handler {
	return &challengeHandler{next: next}
}

func (h *challengeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	slot := &stepUpSlot{}
	h.next.ServeHTTP(&challengeWriter{ResponseWriter: w, slot: slot},
		r.WithContext(context.WithValue(r.Context(), stepUpSlotKey{}, slot)))
}

// challengeWriter ставит заголовок В МОМЕНТ выбора статуса, а не после.
//
// Позже нельзя: заголовки уходят на провод вместе со статусом, и запись после
// `WriteHeader` не доезжает до клиента вовсе — молча, потому что ошибки у неё
// нет.
type challengeWriter struct {
	http.ResponseWriter
	wroteHeader bool
	slot        *stepUpSlot
}

// WriteHeader — на `401` ставит вызов указания, если обработчик ошибок его
// положил, иначе — голую подсказку. Указание отказом аутентификации не является
// (Р11), поэтому решение KAN-REST-1 — подсказка одна на обе полосы ОТКАЗА — им
// не задето: на всяком ином `401` подсказка прежняя.
func (w *challengeWriter) WriteHeader(status int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		if status == http.StatusUnauthorized {
			challenge := AuthenticationChallenge
			if w.slot != nil && w.slot.challenge != "" {
				challenge = w.slot.challenge
			}
			w.Header().Set(challengeHeader, challenge)
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

// Write — обработчик, не назвавший статуса явно, отвечает `200`: подсказке там
// не место, и отдельной ветви для этого не нужно. Метод объявлен затем, чтобы
// признак «статус уже выбран» был верен и на этом пути.
func (w *challengeWriter) Write(b []byte) (int, error) {
	w.wroteHeader = true
	return w.ResponseWriter.Write(b)
}

// Flush — потоковые ответы библиотеки (server-stream в REST) ходят через
// сбрасыватель. Обёртка, его потерявшая, превратила бы поток в ответ, который
// клиент увидит целиком и в конце.
func (w *challengeWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap отдаёт обёрнутого писателя [http.ResponseController].
//
// Без него всякая возможность, которую обёртка не перечислила поимённо (сроки
// чтения и записи, сброс потока новым путём), терялась бы МОЛЧА: контроллер не
// нашёл бы её у обёртки и вернул отказ, а обработчик прочитал бы это как
// «сервер так не умеет». Перечислять возможности поимённо — тот же перечень
// запрещённого, который стареет; здесь он не заводится.
func (w *challengeWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
