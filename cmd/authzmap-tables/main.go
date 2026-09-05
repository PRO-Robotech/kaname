// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Команда authzmap-tables пишет порождённые таблицы типов пакета `authzmap`.
//
// Она — ТОНКАЯ: весь вывод живёт в `services/iam/internal/authzmapgen`, потому
// что тот же вывод зовёт гейт свежести. Копия вывода внутри команды разошлась бы
// с гейтом молча, и гейт сверял бы файл с другим производителем.
//
// Исходов три, и они различимы кодом возврата:
//
//	0  файл записан (либо уже совпадает)
//	1  обход дал находки либо порождать нечего — предпосылка исчезла
//	2  не записалось: путь недоступен
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmapgen"
)

func main() {
	root := flag.String("root", ".", "корень репозитория: отсюда обходятся манифесты модулей")
	out := flag.String("out", "", "куда писать; пусто — штатная координата под корнем")
	flag.Parse()

	tables, err := authzmapgen.Collect(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "authzmap-tables: %v\n", err)
		os.Exit(1)
	}
	body, err := authzmapgen.Render(tables)
	if err != nil {
		fmt.Fprintf(os.Stderr, "authzmap-tables: %v\n", err)
		os.Exit(1)
	}

	target := *out
	if target == "" {
		target = filepath.Join(*root, authzmapgen.GeneratedRelPath)
	}
	if err := os.WriteFile(target, body, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "authzmap-tables: %s не записан: %v\n", target, err)
		os.Exit(2)
	}
	// Перепись печатается ВСЕГДА: без неё «файл записан» не отличается от
	// «записан файл, собранный из части манифестов».
	fmt.Printf("authzmap-tables: %s — %s\n", target, tables.Census.Summary())
}
