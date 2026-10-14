// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// storedvaluemint — строит ХРАНИМОЕ ЗНАЧЕНИЕ пароля СТОРОННЕЙ БИБЛИОТЕКОЙ, а не
// продуктом: «Дано» сквозных позиций PWV-01 и PWV-02 (ID-PW-1 редакции 5, Д-01).
//
// # Зачем отдельная программа
//
// «Дано» обеих позиций — человек, чьё проверочное значение положено ПОСЕВОМ и
// несёт признак формата A (bcrypt `2a`) либо формата B (argon2id). Значения
// формата A продукт не пишет вовсе, у формата B пишет только параметры ручки
// «что писать» (ID-PW-1 Р2, PWV-16). Поэтому значение строит библиотека
// (`golang.org/x/crypto`), и ни один вызов продукта здесь не стоит: хешер
// продукта, построивший «Дано», доказывал бы, что продукт читает то, что сам
// написал, — а предмет позиций в обратном.
//
// Пароль приходит СТАНДАРТНЫМ ВВОДОМ, а не аргументом: аргументы видны в
// перечне процессов машины. Печатается одна строка — значение; пароль не
// печатается никогда.
//
// # Формы
//
//	-format 2a        `$2a$<стоимость>$…` — стоимость `-cost` (умолчание 12 —
//	                  стоимость, которой писал прежний поставщик, ID-PW-1 §1.6)
//	-format argon2id  `$argon2id$v=19$m=<КиБ>,t=<проходы>,p=<потоки>$<соль>$<тело>`
//	                  — соль 16 и тело 32 байта, base64 без выравнивания
//	                  (разметка PHC, которую читает проверяющий,
//	                  `internal/passwordverify/verifier.go`)
//
// Использование (`-C` — служба несёт СВОЙ модуль):
//
//	printf %s "$PW" | go -C <корень> run ./tests/newman/scripts/storedvaluemint -format 2a
//	printf %s "$PW" | go -C <корень> run ./tests/newman/scripts/storedvaluemint -format argon2id -t 4
//
// Что значение, построенное здесь, ЧИТАЕТСЯ проверяющим продукта, держит
// `mint_test.go` рядом: каждый формат совпадает с верным паролем и не совпадает
// с неверным, и признак формата назван тем, что ждёт перечень продукта.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Длины соли и тела формата B — те, что у проверяющего формата B продукта и у
// значений §1.2 ID-PW-1 («соль 16 · ключ 32»).
const (
	argon2SaltLen = 16
	argon2KeyLen  = 32
)

// params — параметры одного построения.
type params struct {
	format      string
	cost        int
	memory      uint32
	iterations  uint32
	parallelism uint8
}

// mint строит значение; ошибка — отказ построить, а не значение предсказуемого
// вида: посев, получивший угадываемое значение, клал бы в хранилище не то, что
// названо его «Дано».
func mint(p params, password []byte, entropy io.Reader) (string, error) {
	if len(password) == 0 {
		return "", errors.New("пароль пуст — значение от пустого пароля «Дано» позиции не строит")
	}
	switch p.format {
	case "2a":
		if p.cost < bcrypt.MinCost || p.cost > bcrypt.MaxCost {
			return "", fmt.Errorf("стоимость bcrypt %d вне [%d, %d]", p.cost, bcrypt.MinCost, bcrypt.MaxCost)
		}
		// Библиотека пишет признак `2a` — тот, что перечень продукта называет
		// форматом A (`domain.PasswordHashFormatBcrypt`).
		out, err := bcrypt.GenerateFromPassword(password, p.cost)
		if err != nil {
			return "", fmt.Errorf("bcrypt: %w", err)
		}
		return string(out), nil
	case "argon2id":
		if p.memory == 0 || p.iterations == 0 || p.parallelism == 0 {
			return "", errors.New("параметры argon2id обязаны быть положительны")
		}
		salt := make([]byte, argon2SaltLen)
		if _, err := io.ReadFull(entropy, salt); err != nil {
			return "", fmt.Errorf("соль не набрана: %w", err)
		}
		body := argon2.IDKey(password, salt, p.iterations, p.memory, p.parallelism, argon2KeyLen)
		return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version,
			p.memory, p.iterations, p.parallelism,
			base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(body)), nil
	default:
		return "", fmt.Errorf("формат %q не известен: 2a либо argon2id", p.format)
	}
}

func main() {
	var p params
	var mem, iter, par uint
	flag.StringVar(&p.format, "format", "", "формат значения: 2a (A) либо argon2id (B)")
	flag.IntVar(&p.cost, "cost", 12, "стоимость bcrypt (формат 2a)")
	flag.UintVar(&mem, "m", 65536, "память argon2id, КиБ")
	flag.UintVar(&iter, "t", 3, "проходы argon2id")
	flag.UintVar(&par, "p", 4, "потоки argon2id")
	flag.Parse()
	if mem > 1<<32-1 || iter > 1<<32-1 || par > 255 {
		fmt.Fprintln(os.Stderr, "storedvaluemint: параметр argon2id вне своего типа")
		os.Exit(2)
	}
	p.memory, p.iterations, p.parallelism = uint32(mem), uint32(iter), uint8(par)

	password, err := io.ReadAll(bufio.NewReader(os.Stdin))
	if err != nil {
		fmt.Fprintf(os.Stderr, "storedvaluemint: пароль не прочитан: %v\n", err)
		os.Exit(1)
	}
	out, err := mint(p, password, rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "storedvaluemint: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(out)
}
