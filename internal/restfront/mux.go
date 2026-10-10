// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package restfront

import (
	"context"
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newMux собирает мультиплексор REST-фронта.
//
// Один конструктор на оба фронта: два места об одном предмете разошлись бы
// молча, и разошлись бы именно в той части, где расхождение не видно снаружи.
//
// Обработчик ошибок вызова — stepUpErrorHandler (stepup.go): он рендерит ОДИН
// ответ — указание повысить уровень (Р11, kaname#511) — и всё прочее отдаёт
// умолчанию библиотеки. Отображение кодов в статусы он не трогает ни одним
// значением: указание и так `UNAUTHENTICATED`, то есть `401` у умолчания.
//
// Обработчик ошибок МАРШРУТИЗАЦИИ — другой предмет и заводится отдельно
// (см. routingErrorHandler): он судит промах глагола, а не исход вызова, и
// отображение кодов отказа в статусы не трогает ни одним значением.
//
// Промежуточный слой routeProbeMiddleware обязан стоять на каждом маршруте:
// без него выяснение перечня допустимых методов исполняло бы обработчики.
// Библиотека навешивает слой при регистрации маршрута, поэтому он объявлен
// здесь, до первой регистрации, а не снаружи.
func newMux() *runtime.ServeMux {
	return runtime.NewServeMux(
		narrowingHeaderMatcherOption(),
		runtime.WithRoutingErrorHandler(routingErrorHandler),
		runtime.WithErrorHandler(stepUpErrorHandler),
		runtime.WithMiddlewares(routeProbeMiddleware),
	)
}

// TextMethodNotAllowed — текст отказа на неверный метод: дословно тот, которым
// отвечает полоса входа службы (задача #261, решение R36 п. 3).
const TextMethodNotAllowed = "method not allowed"

// routingErrorHandler отвечает на промах ГЛАГОЛА формой, одной у обеих
// HTTP-поверхностей службы (задачи #2493, #261; решение R36 п. 3): `405`,
// `{"code":12,"message":"method not allowed","details":[]}` и заголовок
// `Allow` с методами, которые маршрутизатор на этом пути обслуживает.
//
// # Почему статус 405, а не умолчание
//
// Умолчание библиотеки переводит промах глагола в `Unimplemented`, а тот
// отображается в 501. «Не реализовано» означает для клиента отсутствующую
// возможность, и он идёт заводить задачу вместо того, чтобы сменить глагол.
//
// # Почему код 12 и этот текст
//
// Код — тот, что производит маршрутизатор (`Unimplemented`), и тот же отдаёт
// полоса входа: клиент, ключующийся на `code`, читает один класс отказа
// одинаково по любому адресу службы. Текст — дословно текст полосы.
//
// # Откуда перечень методов
//
// Его отвечает сам маршрутизатор: allowedMethods спрашивает мультиплексор о
// каждом методе HTTP, не исполняя обработчиков. Выписанный перечень был бы
// ложью — пути службы обслуживаются под разными наборами методов, — а
// выведенный из маршрутизатора совпадает с тем, что он обслужит, по построению.
func routingErrorHandler(ctx context.Context, mux *runtime.ServeMux, m runtime.Marshaler,
	w http.ResponseWriter, r *http.Request, httpStatus int,
) {
	if isRouteProbe(ctx) {
		// Выяснение перечня методов: промах здесь — ответ «метод не обслужен»,
		// и писать в ответ выяснения нечего.
		return
	}
	if httpStatus != http.StatusMethodNotAllowed {
		runtime.DefaultRoutingErrorHandler(ctx, mux, m, w, r, httpStatus)
		return
	}
	if allow := allowedMethods(mux, r); allow != "" {
		w.Header().Set("Allow", allow)
	}
	runtime.HTTPError(ctx, mux, m, w, r, &runtime.HTTPStatusError{
		HTTPStatus: http.StatusMethodNotAllowed,
		Err:        status.Error(codes.Unimplemented, TextMethodNotAllowed),
	})
}

// candidateMethods — методы HTTP, о которых спрашивается маршрутизатор, в
// порядке, в котором они перечисляются в `Allow`. Это стандартные методы
// `net/http`: правило `google.api.http` объявляет маршрут одним из них.
var candidateMethods = []string{
	http.MethodGet,
	http.MethodHead,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
	http.MethodConnect,
	http.MethodOptions,
	http.MethodTrace,
}

// routeProbeKey — ключ контекста выяснения. Тип не экспортирован: пометить
// запрос выяснением может только этот пакет, снаружи запрос пометки не несёт.
type routeProbeKey struct{}

// routeProbe — исход выяснения одного метода: маршрут найден или нет.
type routeProbe struct{ matched bool }

func isRouteProbe(ctx context.Context) bool {
	_, ok := ctx.Value(routeProbeKey{}).(*routeProbe)
	return ok
}

// routeProbeMiddleware отмечает, что маршрут найден, и НЕ зовёт обработчик,
// если запрос — выяснение перечня методов. Прочие запросы проходят как были.
func routeProbeMiddleware(next runtime.HandlerFunc) runtime.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
		if p, ok := r.Context().Value(routeProbeKey{}).(*routeProbe); ok {
			p.matched = true
			return
		}
		next(w, r, pathParams)
	}
}

// allowedMethods спрашивает мультиплексор, какие методы он обслужил бы на пути
// запроса r, и возвращает их через запятую.
//
// Каждый вопрос — копия запроса без заголовков и тела: заголовки снимаются,
// чтобы ни подмена метода заголовком, ни запасной путь формы (POST как GET)
// не переписали метод вопроса, тело — чтобы его не прочли. Ответ вопроса идёт
// в discardWriter и клиенту не достаётся.
func allowedMethods(mux *runtime.ServeMux, r *http.Request) string {
	var allowed []string
	for _, m := range candidateMethods {
		p := &routeProbe{}
		q := r.Clone(context.WithValue(r.Context(), routeProbeKey{}, p))
		q.Method = m
		q.Header = http.Header{}
		q.Body = http.NoBody
		q.ContentLength = 0
		mux.ServeHTTP(discardWriter{}, q)
		if p.matched {
			allowed = append(allowed, m)
		}
	}
	return strings.Join(allowed, ", ")
}

// discardWriter — ответ выяснения: всё написанное отбрасывается.
type discardWriter struct{}

func (discardWriter) Header() http.Header         { return http.Header{} }
func (discardWriter) Write(b []byte) (int, error) { return len(b), nil }
func (discardWriter) WriteHeader(int)             {}

// narrowingHeaderMatcherOption отдаёт мультиплексору сужающий сопоставитель
// входящих заголовков.
//
// Объявление ОДНО на пакет: второе разошлось бы с первым молча, и разошлось бы
// именно там, где это не видно снаружи. Гейт требует, чтобы каждый собираемый
// мультиплексор получал его (headermatcher_test.go).
func narrowingHeaderMatcherOption() runtime.ServeMuxOption {
	return runtime.WithIncomingHeaderMatcher(narrowingHeaderMatcher)
}

// narrowingHeaderMatcher не пропускает внутрь НИ ОДНОГО заголовка запроса.
//
// # Почему «ни одного», а не «всё, кроме имени личности»
//
// Перечень запрещённого стареет: платформа заведёт следующий заголовок
// личности, а сопоставитель о нём не узнает и пропустит. Перечень разрешённого
// такого класса не имеет by construction — новый заголовок не проходит, пока
// его не назвали. Разрешать же здесь нечего: единственное, что фронт обязан
// донести до слушателя, — предъявленное удостоверение, а его библиотека
// переносит САМА, особым случаем, до обращения к сопоставителю.
//
// # Почему удостоверение НЕ пропускается явно — это измерено, а не выведено
//
// Соблазн вернуть здесь («authorization», true) для заголовка удостоверения
// велик: так объявление выглядит полным и не зависит от чужого особого случая.
// Такой сопоставитель делает фронт НЕИСПОЛНИМЫМ на каждом запросе.
//
// Замер вызовом `runtime.AnnotateContext` на трёх сопоставителях:
//
//	умолчание библиотеки  → authorization=[Bearer T] и ОБА ключа личности
//	явный пропуск         → authorization=[Bearer T, Bearer T]  ← удвоение
//	отвергающий всё       → authorization=[Bearer T]
//
// Удвоение возникает потому, что библиотека переносит удостоверение своим
// особым случаем И ЕЩЁ РАЗ по вердикту сопоставителя. А проверяющий на
// слушателе читает два непустых предъявления как неоднозначность о том, кто
// звонит, — и отвергает запрос, не сравнивая значения. То есть «более полное»
// объявление отказывало бы КАЖДОМУ арендатору с годным удостоверением.
//
// Предпосылка — свойство чужой библиотеки, поэтому она не подразумевается, а
// проверяется: проба рядом падает, если умолчание перестанет пропускать имя
// личности, и вторая — если удостоверение перестанет доезжать ровно одним
// значением. Смена поведения библиотеки роняет проверку, а не обесценивает её
// молча.
func narrowingHeaderMatcher(string) (string, bool) { return "", false }
