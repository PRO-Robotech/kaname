// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// terminal_refusal_wrapping_test.go — гейты приёмки #2439: KN-RTX-06 и KN-RTX-08.
//
// Что предикат устанавливает и чего НЕ устанавливает — в шапке
// `terminal_refusal_wrapping.go`; здесь это не пересказывается.
//
// Способность упасть доказана `terminal_refusal_wrapping_injection_test.go`.
package check_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestTerminalRefusalRepoIsTheOnlyOperationsRepo — KN-RTX-06: репозиторий
// операций, попадающий в use-case, — только обёрнутый.
//
// Заголовок называет РОВНО то, что предикат устанавливает. Всеобщности вида
// «всякий терминальный исход проходит надстройку» здесь НЕТ: четвёртый писатель
// (реконсайлер осиротевших операций) идёт мимо контракта репозитория и вынесен
// исключением приёмки §2.3 с внешним предикатом истечения.
func TestTerminalRefusalRepoIsTheOnlyOperationsRepo(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}

	sites, census, err := check.ScanRawOperationsRepo(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: обход дерева не состоялся: %v", err)
	}
	t.Logf("%s", census)

	if census.Read == 0 || census.Parsed == 0 {
		t.Fatal("не прочитано ни одного файла Go — вердикт беспредметен")
	}
	// Предмет обязан быть НЕ НОЛЬ: ноль вызовов означает либо снятый репозиторий
	// операций (тогда снимается и гейт), либо разбор, переставший видеть предмет,
	// — и второе выглядит точно так же, как чистое дерево.
	if census.Ctors == 0 {
		t.Fatalf("вызовов сырого конструктора осмотрено НОЛЬ при %d разобранных файлах — "+
			"репозиторий операций снят либо разбор перестал видеть предмет", census.Parsed)
	}

	for _, s := range sites {
		if s.Wrapped {
			continue
		}
		t.Errorf("сырой репозиторий операций %s не обёрнут надстройкой ПРЯМО НА МЕСТЕ.\n"+
			"Терминальный исход, записанный через него, унесёт СИНХРОННЫЙ текст отказа "+
			"(«повтори запрос») в строку операции — то есть совет тому, кого нет: тело "+
			"мутации исполняется один раз, и повтора внутри платформы не происходит. "+
			"Заметить это можно только у арендатора.", s.Where)
	}
}

// TestRefusalTextsHaveASingleDeclaration — KN-RTX-08: у каждого текста ровно
// одно объявление.
//
// Второй литерал заводит копию, которая разойдётся с первой МОЛЧА: на всяком
// входе, кроме сериализационного конфликта, обе стороны отвечают одинаково.
func TestRefusalTextsHaveASingleDeclaration(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}

	texts := []string{
		iamerr.SerializationConflictSyncText,
		iamerr.SerializationConflictTerminalText,
	}
	// Тексты обязаны РАЗЛИЧАТЬСЯ: совпади они — обе полосы говорили бы одно, и
	// гейт считал бы объявления одного текста дважды, ничего не утверждая.
	if texts[0] == texts[1] {
		t.Fatal("тексты полос совпали — разведения не произошло, и гейт беспредметен")
	}

	found, census, err := check.ScanRefusalTextLiterals(root, texts)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: обход дерева не состоялся: %v", err)
	}
	t.Logf("перепись: файлов Go прочитано %d, разобрано %d; литералов обоих текстов "+
		"найдено %d", census.Read, census.Parsed, census.Ctors)

	if census.Read == 0 {
		t.Fatal("не прочитано ни одного файла Go — вердикт беспредметен")
	}
	for _, text := range texts {
		decls := found[text]
		switch {
		case len(decls) == 0:
			t.Errorf("текст %q не объявлен НИ РАЗУ — объявление снято, а потребители "+
				"остались: они возьмут его из константы, которой нет", text)
		case len(decls) > 1:
			var where []string
			for _, d := range decls {
				where = append(where, d.Where)
			}
			t.Errorf("текст %q объявлен %d раз: %v.\n"+
				"Две копии разойдутся при первой же правке, и разойдутся МОЛЧА — на "+
				"всяком входе, кроме сериализационного конфликта, обе стороны отвечают "+
				"одинаково. Объявление обязано быть одно, а потребители — импортировать его.",
				text, len(decls), where)
		}
	}
}
