// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// export_test.go — помощники проб пакета, открытые внешнему пакету проб
// `domain_test`. Внешний пакет нужен пробам, которым требуется живой каталог
// (`catalogfixture`): `catalog` импортирует `domain`, и проба внутри пакета
// `domain` замкнула бы кольцо импорта.

// SnakeResource — `snakeResource` для внешнего пакета проб: им механически
// производятся близнецы-перенаписания живого словаря.
var SnakeResource = snakeResource
