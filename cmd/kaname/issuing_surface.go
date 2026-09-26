// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/PRO-Robotech/corelib/servicecontract"

	"github.com/PRO-Robotech/kaname/internal/handler/ceremonyhttp"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

// issuingSurfaceAuthOf — объявление аутентификации внешней поверхности выдачи,
// ВЫВЕДЕННОЕ из обработчика, который она обслуживает (kaname#423, опыт 423F2
// проверяющего сборки 425).
//
// Прежде объявление собиралось из флага, который композиционный корень ставил
// рядом с монтажом церемонии: флаг и монтаж — два места об одном факте, и снятая
// строка флага оставляла объявление прежним при смонтированной церемонии. Здесь
// источник один — маршрутизатор: объявление называет пути церемонии ровно тогда,
// когда маршрутизатор их РАЗРЕШАЕТ. Провязку «ось Auth выведена из того же
// обработчика, что поле Handler» держит гейт
// `TestIssuingSurfaceAuthIsDerivedFromItsMountedHandler`.
//
// Исходов три, и третий — не «не смонтировано»:
//
//   - обработчика нет (поверхность не поднимается) либо церемонии на нём нет —
//     объявление машинных полос;
//   - оба пути церемонии разрешаются — объявление с церемонией;
//   - прочесть монтаж нельзя (обработчик не умеет назвать маршрут) либо
//     смонтирована половина церемонии — ось НЕ ОБЪЯВЛЕНА, и профиль поверхности
//     отказывает старту (`servicecontract.Surface`, ось Auth): объявить
//     «церемонии нет» о том, чего не прочли, значило бы объявить наугад.
func issuingSurfaceAuthOf(h http.Handler) servicecontract.Axis[servicecontract.SurfaceAuthMech] {
	if h == nil {
		return issuingSurfaceAuth(false)
	}
	routes, readable := h.(interface {
		Handler(*http.Request) (http.Handler, string)
	})
	if !readable {
		return servicecontract.Axis[servicecontract.SurfaceAuthMech]{}
	}
	authorize, aok := routedPath(routes, ceremonyhttp.AuthorizePath)
	discovery, dok := routedPath(routes, ceremonyhttp.DiscoveryPath)
	if !aok || !dok || authorize != discovery {
		return servicecontract.Axis[servicecontract.SurfaceAuthMech]{}
	}
	return issuingSurfaceAuth(authorize)
}

// routedPath — разрешает ли маршрутизатор путь СОБСТВЕННЫМ шаблоном: шаблон
// равен пути (с приставкой метода либо без). Шаблон-приёмник вроде «/» пути не
// монтирует. Второе значение — удалось ли спросить: путь, не разбираемый как
// адрес, — не «не смонтировано».
//
// Запрос собирается описанием, а не конструктором с контекстом: он не
// исполняется и никуда не уходит — маршрутизатор лишь называет шаблон, и
// контекста, который было бы чем отменять, у этого вопроса нет.
func routedPath(routes interface {
	Handler(*http.Request) (http.Handler, string)
}, path string) (mounted, asked bool) {
	u, err := url.ParseRequestURI(path)
	if err != nil {
		return false, false
	}
	_, pattern := routes.Handler(&http.Request{Method: http.MethodGet, URL: u, Header: http.Header{}})
	return pattern == path || strings.HasSuffix(pattern, " "+path), true
}

// issuingSurfaceAuth — решение об аутентификации внешней поверхности выдачи по
// тому, смонтирована ли на ней церемония. Зовёт его ТОЛЬКО issuingSurfaceAuthOf:
// флаг, поставленный рядом с монтажом, — форма, которую держит гейт.
//
// Значение оси называет, ЧЕМ аутентифицируется запрос, — и называет КАЖДЫЙ
// способ, а исключение без аутентификации — с причиной (ось Auth профиля
// поверхности, `servicecontract`). Самоотчёт старта и дескриптор посадки читают
// это объявление; путь, о котором оно молчит, для них не смонтирован.
//
// Церемония (ceremonyMounted) добавляет два пути: эндпоинт авторизации — его
// запрос аутентифицирует сессия НАШЕГО входа по печенью полосы входа, — и
// метаданные обнаружения: публичное чтение БЕЗ аутентификации. Исключение
// законно по той же причине, что у набора ключей: документ RFC 8414 несёт только
// публичный материал — координаты и словари, ни секретов, ни данных арендатора.
// Полосы обмена церемонии живут на токен-эндпоинте и аутентифицируют клиента
// так, как объявляет его регистрация.
func issuingSurfaceAuth(ceremonyMounted bool) servicecontract.Axis[servicecontract.SurfaceAuthMech] {
	const machine = "подпись ключом служебной учётки на пути docker-токена и подписанное утверждение клиента, " +
		"сверяемое открытым ключом из нашего реестра, на пути выдачи по учётным данным клиента; второй " +
		"выпускает НАШ подписант"
	if !ceremonyMounted {
		return servicecontract.Value[servicecontract.SurfaceAuthMech](
			"два вида предъявления, у каждого своя проверка на каждом запросе: " + machine)
	}
	return servicecontract.Value[servicecontract.SurfaceAuthMech](
		"у каждого пути своя проверка на каждом запросе: " + machine +
			"; церемония OAuth — эндпоинт авторизации " + ceremonyhttp.AuthorizePath +
			" аутентифицирует сессия нашего входа (печенье " + loginlanehttp.CookieSession +
			"), полосы обмена на токен-эндпоинте — клиента способом его регистрации; исключение: метаданные " +
			"обнаружения " + ceremonyhttp.DiscoveryPath + " читаются без аутентификации — публичный документ " +
			"RFC 8414 (координаты и словари, ни секретов, ни данных арендатора), как набор ключей")
}
