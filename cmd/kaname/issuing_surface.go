// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"github.com/PRO-Robotech/corelib/servicecontract"

	"github.com/PRO-Robotech/kaname/internal/handler/ceremonyhttp"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

// issuingSurfaceAuth — решение об аутентификации внешней поверхности выдачи,
// объявленное по тому, что на ней смонтировано.
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
