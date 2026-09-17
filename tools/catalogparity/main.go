// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalogparity — сверка копии каталога прав службы с копией края.
//
// Вход у сверки ДВА ФАЙЛА, а не дерево: путь копии края собирает вызывающий
// (рецепт `check-permission-catalog`), он же и отвечает за третий исход «дерева
// платформы нет». Здесь третий исход остаётся ровно один — файл не разбирается
// той формой, которую эта сверка знает; тогда о совпадении копий не известно
// НИЧЕГО, и говорить «совпали» нельзя.
//
// Коды возврата: 0 — копии сходятся · 1 — находка · 2 — сверка НЕ ИСПОЛНЯЛАСЬ.
// Текст третьего исхода несёт слова «УСЛОВИЕ НЕ СОЗДАНО» дословно: по ним
// конвейер отличает его от находки, и менять их нельзя без правки шага.
//
// ЧЕЙ ЗДЕСЬ ПУТЬ — ОПЕРАТОРА, И ЭТО СВОЙСТВО, А НЕ УДОБСТВО. Двоичный файл не
// поставляется: в образах его нет, звать его умеет только рецепт
// (`go run ./tools/catalogparity` из цели `check-permission-catalog`). Оба пути
// собирает ТОТ ЖЕ рецепт: `-own` — литеральная константа `IAM_CATALOG_EMBED`,
// `-edge` — `$(EDGE_TREE)` плюс литеральная константа `EDGE_CATALOG_REL`. Корень
// `EDGE_TREE` называет человек, который цель и позвал, — тот самый, кто этот файл
// прочёл бы и `cat`-ом. Ни арендатора, ни запроса, ни сети на входе нет, права
// процесса — ровно права позвавшего, и границы привилегии он не пересекает.
//
// ПОЭТОМУ СВЕСТИ ЧТЕНИЕ ПОД ФИКСИРОВАННЫЙ КОРЕНЬ (`os.Root`, автоподсказка
// gosec) ЗДЕСЬ НЕЛЬЗЯ: второе дерево лежит СНАРУЖИ этого намеренно — предмет
// сверки в том и состоит, чтобы сличить свою копию с копией чужого чекаута.
// Корня, под который это сводится, не существует, и сведение отняло бы у
// инструмента его работу.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const (
	exitFinding = 1
	exitNotRun  = 2
)

func main() {
	edgePath, ownPath, err := parseArgs(os.Args[0], os.Args[1:])
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Printf("УСЛОВИЕ НЕ СОЗДАНО: вызов разобран не был: %v\n", err)
			fmt.Println("Сверка НЕ ИСПОЛНЯЛАСЬ — вердикта о совпадении копий НЕТ.")
		}
		os.Exit(exitNotRun)
	}

	// #nosec G304,G703 -- путь копии края назвал оператор: рецепт складывает его из
	// своего `EDGE_TREE` и литеральной константы (см. шапку пакета «ЧЕЙ ЗДЕСЬ ПУТЬ»).
	// Названы ОБА правила, и это не перестраховка: замерено пином v2.28.0 —
	// `#nosec G304` в одиночку оставляет G703 живым, и наоборот. `filepath.Clean`
	// гасит оба БЕЗ директивы и потому здесь отвергнут: он нормализует строку, не
	// сужая того, что программа вправе прочесть, — то есть убрал бы вердикт, не
	// тронув свойства, и не оставил бы предмета, которому истекать.
	edgeRaw, err := os.ReadFile(edgePath)
	if err != nil {
		fmt.Printf("УСЛОВИЕ НЕ СОЗДАНО: копия края не читается: %v\n", err)
		fmt.Println("Сверка НЕ ИСПОЛНЯЛАСЬ — вердикта о совпадении копий НЕТ.")
		os.Exit(exitNotRun)
	}
	// #nosec G304,G703 -- своя копия: рецепт подаёт литеральную константу
	// `IAM_CATALOG_EMBED`, вариантов у этого пути нет ни одного. Довод и замер —
	// у чтения копии края выше.
	ownRaw, err := os.ReadFile(ownPath)
	if err != nil {
		fmt.Printf("УСЛОВИЕ НЕ СОЗДАНО: своя копия не читается: %v\n", err)
		fmt.Println("Сверка НЕ ИСПОЛНЯЛАСЬ — сверять нечего.")
		os.Exit(exitNotRun)
	}

	findings, census, err := check.CompareCatalogCopies(string(edgeRaw), string(ownRaw))
	if err != nil {
		fmt.Printf("УСЛОВИЕ НЕ СОЗДАНО: %v\n", err)
		fmt.Println("Сверка НЕ ИСПОЛНЯЛАСЬ — вердикта о совпадении копий НЕТ.")
		os.Exit(exitNotRun)
	}

	fmt.Println(census.String())
	fmt.Printf("  край: %s\n", edgePath)
	fmt.Printf("  своя: %s\n", ownPath)
	printDeclaredRenames(census)
	printPendingEntries(census)

	if len(findings) == 0 {
		if census.BytesEqual {
			fmt.Println("ЗЕЛЁНЫЙ: копии каталога прав совпадают ПОБАЙТОВО.")
			return
		}
		fmt.Println("ЗЕЛЁНЫЙ: копии — один порождённый артефакт; всё расхождение объяснено " +
			"объявленными окнами — переименованиями фундамента и записями, ждущими края " +
			"(см. перечни выше).")
		return
	}

	printFindings(findings)
	os.Exit(exitFinding)
}

// printFindings — находки печатаются ПО ВИДУ, а не одним заголовком.
//
// Заголовок «копии разошлись» на находке ведомости лгал бы: при наступившем
// предикате снятия копии как раз СОВПАДАЮТ, а править надо перечень. Находка,
// называющая симптом вместо причины, посылает читателя искать не там — и это
// ровно тот класс, ради которого эта сверка и переписана.
func printFindings(findings []check.CatalogParityFinding) {
	var ledger, copies []check.CatalogParityFinding
	for _, f := range findings {
		if f.Kind == check.CatalogFindingLedger {
			ledger = append(ledger, f)
			continue
		}
		copies = append(copies, f)
	}

	if len(ledger) > 0 {
		fmt.Println("НАХОДКА: ведомость объявленных окон пережила свой предмет.")
		for _, f := range ledger {
			fmt.Printf("  · %s\n", f.Text)
		}
		fmt.Println("Правится ЗДЕСЬ: снимите запись тем же изменением, которым наступил её предикат.")
	}

	if len(copies) > 0 {
		fmt.Println("НАХОДКА: копия каталога прав РАЗОШЛАСЬ с копией края.")
		for _, f := range copies {
			fmt.Printf("  · %s\n", f.Text)
		}
		fmt.Println("Разошлось НЕ объявленным окном (переименованием фундамента либо записью, ждущей края). Исходов два, третьего нет:")
		fmt.Println("  · наша копия отстала → позвать в полном чекауте монорепо: make sync-permission-catalog;")
		fmt.Println("  · отстала копия края → предмет у платформы, а не здесь: синхронизация ЗАПРЕЩЕНА,")
		fmt.Println("    она вписала бы сюда имя метода, которого этот двоичный файл не служит.")
	}
}

// printDeclaredRenames — ведомость печатается ВСЕГДА, а не только при
// расхождении: послабление, которого не видно в журнале зелёного прогона,
// перестают замечать, и снять его оказывается некому.
func printDeclaredRenames(census check.CatalogParityCensus) {
	renames := check.CatalogFoundationRenames()
	if len(renames) == 0 {
		fmt.Println("  объявленных переименований фундамента нет — требуется побайтовое совпадение")
		return
	}
	fmt.Printf("  объявленные переименования фундамента (%d, применено %d):\n",
		len(renames), census.RenamesApplied)
	for _, r := range renames {
		fmt.Printf("    · %s → %s\n", r.EdgeFQN, r.OwnFQN)
		fmt.Printf("      почему: %s\n", r.Why)
		fmt.Printf("      снятие: %s\n", r.Removal)
		fmt.Printf("      предмет: %s\n", r.Refs)
	}
}

// printPendingEntries — вторая ведомость печатается по той же причине, что и
// первая: окно, которого не видно в журнале зелёного прогона, не снимет никто.
func printPendingEntries(census check.CatalogParityCensus) {
	pending := check.CatalogPendingEntries()
	if len(pending) == 0 {
		fmt.Println("  записей службы, ждущих края, нет")
		return
	}
	fmt.Printf("  записи службы, ждущие края (%d, применено %d):\n",
		len(pending), census.PendingApplied)
	for _, e := range pending {
		fmt.Printf("    · %s\n", e.OwnFQN)
		fmt.Printf("      почему: %s\n", e.Why)
		fmt.Printf("      снятие: %s\n", e.Removal)
		fmt.Printf("      предмет: %s\n", e.Refs)
	}
}

func parseArgs(prog string, args []string) (edgePath, ownPath string, err error) {
	fs := flag.NewFlagSet(prog, flag.ContinueOnError)
	edge := fs.String("edge", "", "копия каталога прав у края (файл)")
	own := fs.String("own", "", "своя копия каталога прав (файл)")
	if err := fs.Parse(args); err != nil {
		return "", "", err
	}
	if *edge == "" || *own == "" {
		return "", "", fmt.Errorf("обязательны оба пути: -edge и -own")
	}
	if fs.NArg() != 0 {
		return "", "", fmt.Errorf("лишние аргументы: %v", fs.Args())
	}
	return *edge, *own, nil
}
