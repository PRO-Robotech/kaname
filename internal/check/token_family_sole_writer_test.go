// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_family_sole_writer_test.go — гейт на РЕАЛЬНОМ дереве: семейство
// выданного заводит ровно один писатель, и он несёт условие живости сессии.
//
// Предмет и границы — в шапке `token_family_sole_writer.go`. Способность
// упасть доказана инъекцией — `token_family_sole_writer_injection_test.go`.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// TestTokenFamilyIsWrittenByASingleGuardedProducer — непредставимость «живое
// семейство в снятой сессии» держится ЭТИМ писателем, а не построением, и вот
// предикат на границу.
func TestTokenFamilyIsWrittenByASingleGuardedProducer(t *testing.T) {
	t.Parallel()

	root := moduleRoot(t)

	// Осматривается прод-код службы. Пробы исключены намеренно: они законно
	// строят сцену прямой вставкой, и запрет им означал бы запрет на сцену.
	var dirs []string
	for _, d := range []string{"internal", "cmd"} {
		dirs = append(dirs, filepath.Join(root, d))
	}

	files := map[string]string{}
	for _, dir := range dirs {
		paths, err := treecorpus.UnderWithSuffix(dir, ".go")
		if err != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: обход %s: %v", dir, err)
		}
		for _, p := range paths {
			if strings.HasSuffix(p, "_test.go") {
				continue
			}
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: чтение %s: %v", p, err)
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				rel = p
			}
			files[rel] = string(b)
		}
	}
	if len(files) == 0 {
		t.Fatal("проверка НЕ ИСПОЛНЯЛАСЬ: обход дал ноль непроверочных файлов")
	}

	census, err := check.OAuthFamilyWriters(files)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}

	t.Logf("перепись: файлов разобрано %d · литералов осмотрено %d · писателей %d "+
		"(охраняемых %d, без условия живости %d)",
		census.FilesParsed, census.LiteralsSeen, len(census.Writers),
		census.GuardedCount, census.BareCount)

	// ПУСТОЙ ОБХОД — КРАСНЫЙ. Ноль охраняемых писателей означает, что гейт
	// потерял предмет, а не что дерево чисто.
	if census.GuardedCount == 0 {
		t.Fatal("охраняемых писателей НОЛЬ: гейт потерял предмет — оператор вставки " +
			"семейства переименован, собран из кусков либо таблица переназвана. " +
			"Это не «чисто», это «не смотрели»")
	}

	for _, w := range census.Writers {
		if w.Kind == check.OAuthFamilyWriterBare {
			t.Errorf("%s:%d — вставка в таблицу семейств БЕЗ условия живости сессии.\n"+
				"  Второй писатель обходит условие МОЛЧА: он компилируется, проходит пробы\n"+
				"  церемонии и заводит живое семейство в снятой либо истёкшей сессии.\n"+
				"  Исход один — вести заведение через `insertFamilyOnLiveSessionSQL`\n"+
				"  (`internal/repo/kaname/pg/oauth_ceremony_repo.go`), а не заводить второй\n"+
				"  оператор: истечение сессии ключом невыразимо, и база этого не поймает",
				w.File, w.Line)
		}
	}

	if census.GuardedCount > 1 {
		t.Errorf("охраняемых писателей %d, а должен быть ОДИН: два написания одного "+
			"условия расходятся молча — и разойдётся то, которое правили последним",
			census.GuardedCount)
		for _, w := range census.Writers {
			t.Logf("  %s:%d — %s", w.File, w.Line, w.Kind)
		}
	}
}
