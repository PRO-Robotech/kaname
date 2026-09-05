// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Команда scope-source-census-sql печатает запрос переписи источников звена
// цепи областей — либо перечень типов, о которых перепись обязана высказаться.
//
// Существует затем, чтобы перепись, живущая скриптом над `psql`, брала перечень
// типов и предикаты У ВЛАДЕЛЬЦЕВ, а не выписывала их у себя. Выписанный перечень
// не сдвинулся бы от нового типа и продолжал бы сторожить прежние.
//
// Ошибка печатается в поток ошибок и возвращает КОД 1: скрипт обязан отличить
// «перечень пуст» от «перечень не получен», иначе перепись объявит «типов ноль»
// вместо «читать нечем».
package main

import (
	"fmt"
	"os"

	"github.com/PRO-Robotech/kacho-iam/internal/scopesourcecensus"
)

func main() {
	mode := "sql"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "sql":
		q, err := scopesourcecensus.SQL()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Print(q)
	case "types":
		plans, err := scopesourcecensus.Plans()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for _, p := range plans {
			fmt.Printf("%s\t%s\t%s\n", p.ModelType, p.CatalogType, p.Table)
		}
	default:
		fmt.Fprintf(os.Stderr, "неизвестный режим %q: ожидается sql либо types\n", mode)
		os.Exit(2)
	}
}
