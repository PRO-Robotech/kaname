// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// export_test.go — мост для проб пакета, намеренно УЗКИЙ: только величины,
// которые проба не вправе назвать своей рукой.

// ForceLogoutLockWait — предел одного ожидания замка в транзакции выхода
// (`forceLogoutLockWait`). Сцены конкуренции держат замки не дольше его доли
// (`holdSceneBudget`): выписанное пробой число разошлось бы с пределом молча,
// когда тот сдвинется, и ждущий выход начал бы отказывать по пределу — исходом
// продукта, вызванным самой сценой.
const ForceLogoutLockWait = forceLogoutLockWait
