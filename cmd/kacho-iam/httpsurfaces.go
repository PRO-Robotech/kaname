// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// httpsurfaces.go — ОБЩАЯ ЧАСТЬ объявлений четырёх не-gRPC поверхностей iam.
//
// # Что здесь общее, а что нет — и почему граница именно такая
//
// Общее — СРОКИ и имя процесса: они одинаковы у всех четырёх и были выписаны по
// месту четыре раза, то есть держались тем, что автор написал те же числа.
// Разъехавшиеся числа читались бы как осознанная разница, которой нет.
//
// НЕ общее — имя поверхности, адрес, досягаемость, решение об аутентификации и
// транспорт. Их сводить нельзя: именно ими четыре поверхности и отличаются, и
// пара «досягаемость × аутентификация» — единственное, что профиль судит по
// существу. Помощник, подставляющий сюда умолчание, вернул бы решение о доступе,
// принятое никем.
package main

import (
	"time"

	"github.com/PRO-Robotech/kacho/pkg/servicecontract"
)

// Сроки не-gRPC поверхностей iam. Величины взяты у прежних четырёх серверов
// один-в-один, кроме одной: срок гашения раньше жил не в объявлении, а в общем
// триггере остановки — четырьмя копиями по пять секунд.
const (
	// iamSurfaceReadHeaderBudget — потолок чтения заголовка.
	iamSurfaceReadHeaderBudget = 10 * time.Second
	// iamSurfaceRequestBudget — потолок чтения и записи запроса целиком. Все
	// четыре поверхности запрос-ответные и короткие: вебхук провайдера, выдача
	// токена, отдача ключей проверки, скрейп. Потоковых среди них нет.
	iamSurfaceRequestBudget = 30 * time.Second
	// iamSurfaceIdleBudget — потолок простоя keep-alive соединения.
	iamSurfaceIdleBudget = 90 * time.Second
	// iamSurfaceShutdownBudget — срок гашения.
	iamSurfaceShutdownBudget = 5 * time.Second
)

// iamHTTPSurface достраивает объявление ОБЩЕЙ частью и отдаёт его конструктору.
//
// Аргумент — уже наполовину заполненная [servicecontract.Surface], а не набор
// параметров: так видно, что именно вызывающий обязан сказать сам, и добавление
// новой оси в профиль не проходит здесь молча.
func iamHTTPSurface(s servicecontract.Surface) (servicecontract.SurfaceDescriptor, error) {
	s.Service = "kacho-iam"
	s.ReadHeaderBudget = iamSurfaceReadHeaderBudget
	s.RequestBudget = servicecontract.Value(iamSurfaceRequestBudget)
	s.IdleBudget = iamSurfaceIdleBudget
	s.ShutdownBudget = iamSurfaceShutdownBudget
	return servicecontract.NewSurface(s)
}

// addrAxis превращает «адрес из конфигурации» в ОСЬ с тремя состояниями.
//
// Пустая строка перестаёт быть молчаливым выключением: она становится
// объявленным выключением с причиной, и причина попадает в журнал при старте.
// Причина требуется АРГУМЕНТОМ, а не берётся из общего шаблона — у четырёх
// поверхностей iam цена выключения РАЗНАЯ: у скрейпа это отсутствие
// наблюдаемости, у зеркала ключей — закрытая верификация всей плоскости данных
// реестра.
func addrAxis(addr, becauseEmpty string) servicecontract.Axis[string] {
	if addr == "" {
		return servicecontract.NotApplicable[string](becauseEmpty)
	}
	return servicecontract.Value(addr)
}
