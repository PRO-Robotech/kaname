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
// # Здесь же — КОМПОЗИЦИОННЫЙ КОРЕНЬ второй проверки (задача #1090)
//
// Форму манифеста судит загрузчик; ПРОИЗВОДИМОСТЬ права роли — пакет
// `manifest/roleexport`, и каталог прав он берёт ПОРТОМ, а не встраивает у себя:
// встроенная копия каталога одна, она у посева, и второй её встраиватель был бы
// вторым объявлением одного предмета. Сводит их здесь: команда — единственное
// место, которому позволено знать про оба.
//
// Манифест читается ВТОРОЙ раз намеренно. Это второе чтение ФАЙЛА, а не второй
// разбор его формы: судит по-прежнему один загрузчик, и расходиться тут нечему.
//
// # Стадий у второй проверки ДВЕ, и порядок между ними — не свойство команды
//
// Сначала судится КЛАСС каждого действия раздела `resources` (удовлетворяет ли
// он гейт этого действия), и только потом — правила ролей. Пока первая стадия
// красна, вопрос «полон ли перечень» не имеет определённого множества, по
// которому считается. Порядок и замыкание объявлены в `roleexport.Check`;
// команда зовёт её и не воспроизводит у себя ни того, ни другого.
//
// # Пометка — НЕ находка, и печатаются они в разные потоки
//
// Действие, чей гейт непроизводим правилом роли ни при каком классе, и
// действие, которого каталог не знает, вердикта не меняют: раздел `resources`
// порождается из аннотаций, и автор манифеста за их состояние не отвечает.
// Молчать о них нельзя — иначе они выходят из-под всех трёх проверок не
// нарушением, а невидимостью.
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
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/catalog"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest/roleexport"
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

	rightsCode := checkRights(root, report.Paths)

	code := report.ExitCode()
	if code == manifest.CheckOK && rightsCode != manifest.CheckOK {
		code = rightsCode
	}
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

// checkRights — производимость прав ролей каждого прочитанного манифеста.
//
// Возвращает КОД, а не ошибку: у проверки те же три исхода, что у обхода, и
// «каталог не прочитан» не вправе выглядеть ни находкой о манифесте, ни успехом.
//
// Обход манифестов НЕ повторяется: пути приходят от единственного обходчика.
// Повторяется только чтение файла — судит его по-прежнему один загрузчик.
func checkRights(root string, paths []string) int {
	if len(paths) == 0 {
		// Манифестов нет — предмета у этой проверки нет тоже, и молчать об этом
		// нельзя: «ноль находок» обязано быть отличимо от «ноль прочитанного».
		fmt.Println("права ролей: манифестов не прочитано ни одного — проверять нечего")
		return manifest.CheckOK
	}

	reg, err := seed.LoadPermissionRegistry(context.Background(),
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	if err != nil {
		fmt.Fprintf(os.Stderr, "проверка прав НЕ ИСПОЛНЯЛАСЬ: каталог прав не прочитан: %v\n", err)
		return exitNotRun
	}
	// Каталожный факт берётся СНИМКОМ, а не у литерала: читатель на литерале
	// продолжил бы считать снятый тип живым (kacho#1816). Снимок собирается из
	// того же перечня, которым миграция посеяла строки, поэтому вердикт
	// команды остаётся воспроизводимым из ДЕРЕВА и базы не требует — иначе
	// сборочная проверка стала бы функцией состояния чужой базы.
	facts, ferr := catalog.NewFacts(seed.LiteralRows())
	if ferr != nil {
		fmt.Fprintf(os.Stderr,
			"проверка прав НЕ ИСПОЛНЯЛАСЬ: каталожный факт не собран: %v\n", ferr)
		return exitNotRun
	}

	rows := reg.All()
	entries := make([]roleexport.CatalogEntry, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, roleexport.CatalogEntry{
			FQN:              r.FQN,
			RequiredRelation: r.RequiredRelation,
			ScopeObjectType:  r.ScopeExtractor.ObjectType,
		})
	}
	actions, outside := roleexport.Attribute(entries)
	// Записи вне формы модуля НАЗЫВАЮТСЯ: платформенные службы ресурсом модуля
	// не являются, и отбросить их молча значило бы сделать перепись неверной.
	fmt.Printf("каталог прав: записей %d · привязано действий %d · вне формы модуля %d\n",
		len(entries), len(actions), len(outside))
	if len(actions) == 0 {
		fmt.Fprintln(os.Stderr,
			"проверка прав НЕ ИСПОЛНЯЛАСЬ: привязано ноль действий — судить нечем")
		return exitNotRun
	}

	// Второе чтение идёт ПОД КОРНЕМ и тем же читателем, что и обход. Путь сюда
	// принёс обход, а между записью каталога и этим открытием лежит окно: в нём
	// любой сегмент подменяется ссылкой наружу, и чтение ПО ИМЕНИ уходит за
	// корень, не заметив этого. Через os.Root каждый сегмент разрешает ядро
	// относительно корня, поэтому свойство держится построением, а не тем, что
	// вызывающий о нём помнит. Читатель один на всех: вторая реализация
	// разошлась бы с первой молча — и разошлась бы именно там, где расхождение
	// не видно, потому что обе дают «прочитано» на честном дереве.
	treeRoot, err := os.OpenRoot(root)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"проверка прав НЕ ИСПОЛНЯЛАСЬ: корень обхода не открыт: %v\n", err)
		return exitNotRun
	}
	defer func() { _ = treeRoot.Close() }()

	code := manifest.CheckOK
	for _, rel := range paths {
		data, err := manifest.ReadUnderRoot(treeRoot, rel)
		if err != nil {
			fmt.Fprintf(os.Stderr, "НАХОДКА: %s: повторное чтение: %v\n", rel, err)
			code = manifest.CheckFailed
			continue
		}
		m, err := manifest.Load(data)
		if err != nil {
			// Форму уже осудил обход, и его код возврата это учёл; здесь просто
			// нечего судить дальше.
			continue
		}
		// Обе стадии зовутся ОДНОЙ функцией: порядок «класс → правила» и
		// замыкание на красной первой живут в ней, а не здесь. Проверка
		// порядка, написанная в команде, не защищала бы второго вызывающего той
		// же связки.
		rep := roleexport.Check(facts, m, actions)
		fmt.Printf("  права ролей %s: %s\n", rel, rep.Summary())
		// Пометки печатаются в ВЫВОД, а не в поток ошибок, и вердикта не
		// меняют: состояние, за которое автор манифеста не отвечает, обязано
		// быть названо и обязано быть отличимо от находки.
		for _, n := range rep.Notes {
			fmt.Printf("  пометка (%s): %s: %s\n", n.Kind, rel, n.Detail)
		}
		for _, f := range rep.Faults {
			fmt.Fprintf(os.Stderr, "НАХОДКА: %s: %s\n", rel, f)
			code = manifest.CheckFailed
		}
	}
	return code
}
