// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command clagate — судья подписи по ведомости `cla-ledger.yaml`.
//
//	clagate push-range --remote <имя|адрес> [--root <корень>] [--ledger cla-ledger.yaml] < строки pre-push
//
// Режим один: `push-range` судит коммиты, которые отправка ОПУБЛИКУЕТ, — автора,
// коммиттера и соавторов каждого — по той же ведомости, что гейт дерева
// (`make cla-check`, пакет tools/clagate). Зовёт его хук `scripts/hooks/pre-push`
// до наборов проверок.
//
// Коды: 0 — ЗЕЛЁНОЕ, 1 — КРАСНОЕ, 2 — УСЛОВИЕ НЕ СОЗДАНО. Хук читает всякий
// ненулевой как отказ отправки: «судить было нечем» — не проход.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/PRO-Robotech/corelib/gitenv"

	"github.com/PRO-Robotech/kaname/tools/clagate"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stderr))
}

func run(args []string, in io.Reader, out io.Writer) int {
	// Отказ записи в поток диагностики вердикта не меняет: исход несёт код.
	say := func(format string, a ...any) { _, _ = fmt.Fprintf(out, format, a...) }
	if len(args) == 0 || args[0] != "push-range" {
		say("clagate: УСЛОВИЕ НЕ СОЗДАНО — режим не назван либо неизвестен; режим один: push-range\n")
		return clagate.ExitUnmet
	}
	fs := flag.NewFlagSet("push-range", flag.ContinueOnError)
	fs.SetOutput(out)
	remote := fs.String("remote", "", "remote отправки — первый довод хука pre-push (имя либо адрес)")
	root := fs.String("root", "", "корень судимого дерева; по умолчанию — рабочая копия текущего каталога")
	ledger := fs.String("ledger", "cla-ledger.yaml", "ведомость относительно корня дерева")
	if err := fs.Parse(args[1:]); err != nil {
		return clagate.ExitUnmet
	}
	if fs.NArg() > 0 {
		say("clagate push-range: УСЛОВИЕ НЕ СОЗДАНО — лишние доводы %q: строки отправки читаются со stdin\n", fs.Args())
		return clagate.ExitUnmet
	}
	if *remote == "" {
		say("clagate push-range: УСЛОВИЕ НЕ СОЗДАНО — remote не назван (--remote): вычитать опубликованное не из чего\n")
		return clagate.ExitUnmet
	}
	if *root == "" {
		top, err := gitenv.Command(".", "rev-parse", "--show-toplevel").Output()
		if err != nil {
			say("clagate push-range: УСЛОВИЕ НЕ СОЗДАНО — текущий каталог не рабочая копия git: %v\n", err)
			return clagate.ExitUnmet
		}
		*root = strings.TrimSpace(string(top))
	}
	return clagate.RunPushRange(*root, *ledger, *remote, in, out)
}
