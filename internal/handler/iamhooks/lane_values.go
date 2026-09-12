// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lane_values.go — исход КАЖДОГО обращения поставщика личности становится
// величиной (задача продукта #2495).
//
// # Предмет
//
// Полоса хуков — живой путь входа человека: выдача утверждений токена,
// продление, заведение по первому входу, завершение восстановления доступа.
// Наблюдения у неё было ровно два вида — предупреждающая строка и строка
// доступа, — и оба видны только тому, кто читает журнал построчно.
//
// Два состояния одного отказа давали при этом несравнимые, но одинаково
// ненаблюдаемые картины:
//
//	полоса отказывает            растёт число строк журнала с отказом;
//	поставщик не зовёт хук вовсе строк журнала НЕТ. Провязку на своей стороне
//	                            делает оператор, и её отсутствие невидимо
//	                            by construction: тишина тревогой не бывает.
//
// # Почему исходов ТРИ
//
// У каждого свой владелец починки, и смешать их значило бы отдать чужую работу:
//
//	ok       хук сделал работу;
//	refused  обращение отвергнуто до работы — общий секрет, форма тела, метод.
//	         Провязка на стороне поставщика не создана либо неверна, и чинит её
//	         ОПЕРАТОР, а не мы;
//	failed   ответить не смогли. Сломан продукт, и чиним мы.
//
// Корзины «прочее» у набора нет. Ответ вне трёх диапазонов на этих маршрутах не
// возникает (обработчики отвечают телом JSON либо отказом), а перенаправление
// есть решение самого обработчика — оно попадает в `ok` вместе с остальными
// доведёнными ответами, а не заводит четвёртое значение, которое присутствовало
// бы нулём и выглядело исправным наблюдением.
//
// # Почему имена маршрутов объявлены ЗДЕСЬ
//
// Их знает мультиплексор — он один держит соответствие пути и обработчика.
// Второй перечень (у приёмника величин) разошёлся бы с этим молча, и разошёлся
// бы он в сторону «маршрут без клетки», то есть в сторону невидимости.
package iamhooks

import "net/http"

// Имена маршрутов полосы. Метка величины, а не путь: путь несёт версию и
// префикс, и его смена переименовала бы ряд, ничего не изменив по существу.
const (
	// RouteToken — выдача утверждений токена.
	RouteToken = "token"
	// RouteRefresh — продление.
	RouteRefresh = "refresh"
	// RouteProvision — заведение по первому входу.
	RouteProvision = "provision"
	// RouteRecovery — завершение восстановления доступа.
	RouteRecovery = "recovery"
)

// Routes — закрытый набор маршрутов полосы в порядке объявления.
//
// ВЫВОДИТСЯ отсюда всяким, кому нужен перечень: заведение клеток величины,
// проба переписи. Вторая копия разошлась бы молча.
func Routes() []string {
	return []string{RouteToken, RouteRefresh, RouteProvision, RouteRecovery}
}

// Исходы одного обращения. Набор ЗАКРЫТ.
const (
	// LaneOutcomeOK — хук сделал работу.
	LaneOutcomeOK = "ok"
	// LaneOutcomeRefused — обращение отвергнуто до работы: провязка на стороне
	// поставщика не создана либо неверна.
	LaneOutcomeRefused = "refused"
	// LaneOutcomeFailed — ответить не смогли: сломан продукт.
	LaneOutcomeFailed = "failed"
)

// LaneOutcomes — закрытый набор исходов в порядке объявления.
func LaneOutcomes() []string {
	return []string{LaneOutcomeOK, LaneOutcomeRefused, LaneOutcomeFailed}
}

// LaneOutcomeForStatus переводит состояние ответа в объявленный исход.
//
// Функция ПОЛНАЯ: у неё нет входа, на котором она вернула бы значение вне
// [LaneOutcomes], — и именно это делает набор закрытым by construction, а не по
// договорённости.
func LaneOutcomeForStatus(status int) string {
	switch {
	case status >= http.StatusInternalServerError:
		return LaneOutcomeFailed
	case status >= http.StatusBadRequest:
		return LaneOutcomeRefused
	default:
		return LaneOutcomeOK
	}
}

// LaneObserver — приёмник исходов полосы. Порт, а не готовый счётчик: слой
// транспорта не знает ни реестра величин, ни prometheus.
type LaneObserver interface {
	// HookServed принимает исход ОДНОГО обращения: route из [Routes], outcome из
	// [LaneOutcomes].
	HookServed(route, outcome string)
}

// observeRoute надевает на обработчик съём исхода.
//
// Нулевой приёмник возвращает обработчик как есть: полоса обязана обслуживать
// вход человека и там, где величин не собирают (проба пакета, отдельная сборка),
// — наблюдение, роняющее наблюдаемое, хуже отсутствующего.
func observeRoute(route string, h http.Handler, obs LaneObserver) http.Handler {
	if h == nil || obs == nil {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(sw, r)
		obs.HookServed(route, LaneOutcomeForStatus(sw.status))
	})
}
