// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// credsecretmint — печатает базовое удостоверение, ОТЧЕКАНЕННОЕ КОДОМ ПРОДУКТА.
//
// # Зачем отдельная программа
//
// Самопроверка сквозного кейса (`scripts/selftest_basic_access_token.py`) гоняет
// НАСТОЯЩИЙ newman по НАСТОЯЩЕЙ коллекции, а ответы даёт подставным сервером.
// Секрет в этом ответе обязан быть ТЕМ, что производит продукт, — иначе
// утверждение о форме проверялось бы против значения, выписанного руками, то
// есть против второй копии предиката. Копия эта уже расходилась (#1253), и
// расходилась молча.
//
// Вычислить такое значение на стороне пробы нельзя: в нём контрольная сумма,
// а её вычисление — часть формы. Своя реализация суммы стала бы третьей копией
// того же предиката. Поэтому здесь — вызов, а не повторение: `ids.NewID` даёт
// идентификатор той же формы, что на пути выдачи, `credsecret.Mint` чеканит.
//
// # Что печатает
//
// Одну строку JSON: идентификатор удостоверения и секрет. Хеш НЕ печатается —
// он хранимая величина, и подставному стенду не нужен; печатать его значило бы
// выносить наружу больше, чем требует предмет.
//
// Использование:
//
//	go run -C services/iam ./tests/newman/scripts/credsecretmint            # вид uoc
//	go run -C services/iam ./tests/newman/scripts/credsecretmint -prefix soc
//
// `-C` не украшение: служба несёт СВОЙ модуль, и путь от корня монорепо
// отказывает — «main module … does not contain package …».
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/PRO-Robotech/kacho/pkg/credsecret"
	"github.com/PRO-Robotech/kacho/pkg/ids"
)

func main() {
	prefix := flag.String("prefix", "uoc", "вид удостоверения: uoc — персональный токен, soc — ключ служебной учётки")
	flag.Parse()

	if len(*prefix) != 3 {
		fmt.Fprintf(os.Stderr, "credsecretmint: вид удостоверения — ровно три знака, получено %q\n", *prefix)
		os.Exit(2)
	}

	credentialID := ids.NewID(*prefix)
	secret, _, err := credsecret.Mint(credentialID)
	if err != nil {
		// Отказ, а не строка предсказуемого вида: подставной стенд, получивший
		// угадываемое значение, доказывал бы форму, которой продукт не чеканит.
		fmt.Fprintf(os.Stderr, "credsecretmint: чеканка отказана: %v\n", err)
		os.Exit(1)
	}

	out, err := json.Marshal(map[string]string{
		"credentialId": credentialID,
		"secret":       secret,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "credsecretmint: ответ не сериализуется: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}
