// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package methodrefusal — ОДНА форма отказа на неверный метод HTTP для путей
// службы, обслуживаемых собственными обработчиками (решение R36 п. 3, задача
// PRO-Robotech/kaname#261; распространено на слушатель выдачи решением Р12
// приёмки темпа церемонии, задача PRO-Robotech/kaname#524).
//
// # Предмет
//
// Путь есть, метод не тот. Слушатель выдачи отвечал на это формами протокола
// (`{"error":"invalid_request"}`) и голым текстом (`{"error":"method_not_allowed"}`
// под `text/plain`), а полоса входа и REST-фронт — `405` с кодом `12`. Код `3`
// и `invalid_request` клиент читает как «исправь тело» и правит тело вместо
// метода; общий обработчик `405` не написать, пока у пути своя форма.
//
// # Форма
//
// `405`, `Content-Type: application/json`, `Allow` с методами пути и тело
// побайтово `{"code":12,"message":"method not allowed","details":[]}` — то же,
// что печатает полоса входа (`loginlanehttp`). Код `12` (`UNIMPLEMENTED`) —
// тот, что производит маршрутизатор REST-фронта: клиент, ключующийся на
// `code`, читает один класс отказа одинаково по любому адресу службы.
//
// # Почему тело литералом
//
// Побайтовое равенство с полосой входа — часть контракта (KN-PACE-46): тело
// пишется готовыми байтами, а не кодировщиком, у которого свой перевод строки
// и свои пробелы.
package methodrefusal

import (
	"net/http"
	"strings"
)

// Text — текст отказа, дословно текст полосы входа и REST-фронта.
const Text = "method not allowed"

// Body — тело отказа побайтово.
const Body = `{"code":12,"message":"` + Text + `","details":[]}`

// Write отвечает формой отказа на неверный метод. allowed — методы, которые
// путь обслуживает; их порядок — порядок заголовка `Allow`.
func Write(w http.ResponseWriter, allowed ...string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusMethodNotAllowed)
	_, _ = w.Write([]byte(Body))
}
