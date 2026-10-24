// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap

// export_test.go — порождённая таблица для внешнего пакета проб `authzmap_test`.
// Внешний пакет нужен пробе, спрашивающей живой каталог (`catalogfixture`):
// фикстура через посев импортирует `authzmap`, и проба внутри пакета замкнула
// бы кольцо импорта.

// ObjectTypes — порождённая таблица «точечное имя каталога → имя типа модели».
var ObjectTypes = objectTypes
