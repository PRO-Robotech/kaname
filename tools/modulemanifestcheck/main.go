// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Команда module-manifest-check — прод-потребитель загрузчика манифестов: обходит
// дерево, читает каждый `manifest.yaml` модуля и судит его тем же Load, которым
// его прочтёт посев iam (приёмка
// services/iam/docs/engineering/acceptance/module-manifest-seed-contract.md,
// §5.5, сценарии MOD-MF-17 · 18 · 19).
//
// Тонкая обёртка: ЧТО проверяется и почему исходов три, документировано на
// пакете services/iam/internal/manifest (check.go). Здесь живёт только вызов и
// перевод отчёта в код возврата.
//
// # Коды возврата
//
//	0  годно  — каждый найденный манифест прочитан, разобран и связен;
//	1  находка — манифест негоден либо путь не прочитан;
//	2  VOID   — манифестов не найдено ни одного: проверять нечего;
//	3  проверка НЕ ИСПОЛНЯЛАСЬ — вызов разобрать не удалось.
//
// Третий код отделён от нулевого потому, что «ноль находок» обязано быть
// отличимо от «ноль прочитанного»; четвёртый — потому, что «не выполнилось» не
// вычитается из вердикта и не зачитывается в успех (`testing.md` §«Чтение
// вердикта»). Разбор аргументов у flag.ExitOnError выходит кодом 2 — то есть
// СОВПАЛ БЫ с VOID и объявил бы пустым деревом опечатку в вызове; поэтому здесь
// свой набор флагов с ContinueOnError и свой код.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

// exitNotRun — проверка не исполнялась: вызов разобран не был.
const exitNotRun = 3

func main() {
	root, err := parseArgs(os.Args[0], os.Args[1:])
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(os.Stderr, "проверка НЕ ИСПОЛНЯЛАСЬ: %v\n", err)
		}
		os.Exit(exitNotRun)
	}

	report := manifest.CheckTree(root)

	// Перепись печатается ВСЕГДА и первой: без неё зелёный вердикт неотличим от
	// вердикта обхода, не прочитавшего ничего.
	fmt.Printf("корень обхода: %s\n", root)
	fmt.Printf("перепись: %s\n", report.Summary())
	for _, p := range report.Paths {
		fmt.Printf("  прочитан: %s\n", p)
	}
	for _, f := range report.Findings {
		fmt.Fprintf(os.Stderr, "НАХОДКА: %s\n", f)
	}

	code := report.ExitCode()
	if code == manifest.CheckVoid {
		// Словами, а не только кодом: код читает оболочка, а строку — человек,
		// и она не вправе выглядеть успехом.
		fmt.Fprintln(os.Stderr,
			"манифестов в дереве нет ни одного — это НЕ успех, а «проверять нечего»: "+
				"предмет у проверки появится вместе с первым манифестом модуля")
	}
	os.Exit(code)
}

// parseArgs — свой набор флагов, чтобы отказ разбора не выходил кодом VOID.
func parseArgs(prog string, args []string) (string, error) {
	fs := flag.NewFlagSet(prog, flag.ContinueOnError)
	root := fs.String("root", ".", "корень дерева, в котором ищутся манифесты модулей")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if rest := fs.Args(); len(rest) > 0 {
		return "", fmt.Errorf("лишние аргументы: %v — корень задаётся флагом -root", rest)
	}
	if *root == "" {
		return "", errors.New("-root пуст: корень обхода не назван")
	}
	return *root, nil
}
