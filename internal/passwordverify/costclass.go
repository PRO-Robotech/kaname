// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package passwordverify

// costclass.go — ЧИТАТЕЛЬ ПРЕФИКСА КЛАССА: строка «значение без соли и тела»,
// какой её отдаёт перепись хранилища (`LoginMethodRepo.PasswordCostClasses`),
// разбирается в класс стоимости (решение kaname#188 по Ф3-31).
//
// Материала здесь нет by construction: перепись выносит из колонки только
// сегменты признака, версии и параметров, а соль и тело остаются в базе.
// Разметка каждого формата — та же, что у проверяющего (`verifier.go`), и
// разбор параметров объявленного формата зовёт ТОТ ЖЕ `parseArgon2idParams`:
// второй разбор разошёлся бы с первым молча. Производитель префикса (SQL) и
// этот читатель сходятся интеграционной пробой адаптера, а не соглашением.

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ParseCostClassPrefix — класс стоимости из префикса переписи.
//
// Наследуемый формат: `$2a$<две цифры>`; объявленный:
// `$argon2id$v=19$m=<КиБ>,t=<проходы>,p=<параллельность>`. Всё прочее — отказ:
// пустой префикс (признак вне перечня), чужая версия разметки, лишний сегмент
// (соль, которой здесь быть не должно), негодное число.
func ParseCostClassPrefix(prefix string) (domain.PasswordCostClass, error) {
	switch {
	case prefix == "":
		return domain.PasswordCostClass{}, fmt.Errorf("password_cost_class: признак формата вне перечня")
	case strings.HasPrefix(prefix, bcryptMarkerPrefix):
		return parseBcryptClassPrefix(prefix)
	case strings.HasPrefix(prefix, argon2idMarkerPrefix):
		return parseArgon2idClassPrefix(prefix)
	default:
		return domain.PasswordCostClass{}, fmt.Errorf("password_cost_class: признак формата вне перечня")
	}
}

func parseBcryptClassPrefix(prefix string) (domain.PasswordCostClass, error) {
	digits := prefix[len(bcryptMarkerPrefix):]
	if len(digits) != bcryptCostDigits {
		return domain.PasswordCostClass{}, fmt.Errorf("password_cost_class %q: стоимость bcrypt — ровно %d цифры", prefix, bcryptCostDigits)
	}
	cost, err := strconv.ParseUint(digits, 10, 32)
	if err != nil {
		return domain.PasswordCostClass{}, fmt.Errorf("password_cost_class %q: стоимость bcrypt не число", prefix)
	}
	return domain.PasswordCostClass{Format: domain.PasswordHashFormatBcrypt,
		Params: map[domain.PasswordHashCostParam]uint32{domain.CostParamBcryptCost: uint32(cost)}}, nil
}

func parseArgon2idClassPrefix(prefix string) (domain.PasswordCostClass, error) {
	rest := prefix[len(argon2idMarkerPrefix):]
	if !strings.HasPrefix(rest, argon2idVersionPrefix) {
		return domain.PasswordCostClass{}, fmt.Errorf("password_cost_class %q: версия разметки argon2id не 19", prefix)
	}
	paramsPart := rest[len(argon2idVersionPrefix):]
	if strings.Contains(paramsPart, "$") {
		return domain.PasswordCostClass{}, fmt.Errorf("password_cost_class %q: префикс несёт сегмент сверх параметров", prefix)
	}
	memory, iterations, parallelism, ok := parseArgon2idParams(paramsPart)
	if !ok {
		return domain.PasswordCostClass{}, fmt.Errorf("password_cost_class %q: параметры argon2id не разбираются", prefix)
	}
	return domain.PasswordCostClass{Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory:      memory,
			domain.CostParamArgon2Iterations:  iterations,
			domain.CostParamArgon2Parallelism: parallelism,
		}}, nil
}
